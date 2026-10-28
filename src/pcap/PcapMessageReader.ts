import { realpath } from "node:fs/promises";

import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ArtifactAnalysisResources } from "../process/ArtifactAnalysisResources.js";
import { readLinuxResourceLimits } from "../process/LinuxResourceLimits.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import type { Result } from "../domain/result.js";
import { err, ok } from "../domain/result.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { ProtocolMessageReadResult } from "../domain/protolearn/protocolMessageSource.js";
import { PROTOLEARN_LIMITS } from "../domain/protolearn/protolearnLimits.js";
import {
  PcapConfigurationFailure,
  assertWiresharkExecutableIdentity,
  locateWiresharkTool,
  pcapToolUnavailable,
  resolvePcapTools,
  wiresharkExecutableIdentity,
  type PcapToolSelection,
  type WiresharkExecutableIdentity,
} from "./PcapConfiguration.js";
import {
  runPcapCommand,
  type PcapCommandCleanup,
  type PcapCommandLauncher,
  type PcapCommandOutput,
} from "./PcapCommand.js";
import { parseCapinfosOutput } from "./PcapOutput.js";
import {
  PCAP_MESSAGE_FIELDS,
  parsePcapMessageRows,
  pcapCaptureFormat,
} from "./PcapMessageRows.js";
import { preparePcapNativeBound } from "./PcapNativeBound.js";
import { PcapSnapshot } from "./PcapSnapshot.js";
import { TSHARK_JSON_MAX_BYTES } from "./TsharkJson.js";

const OPERATION = "learn_protocol_model";
const MAX_TOOL_IDENTITY_BYTES = 64 * 1024 * 1024;

export interface PcapMessageReaderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly launcher?: PcapCommandLauncher;
  readonly artifactReader?: typeof readStableArtifact;
}

interface RetainedCommand {
  readonly owner: ProviderProcessSupervisor;
  readonly resources: readonly string[];
  readonly reason: string;
}

/**
 * Read one saved capture's messages through the packet-capture lane's own
 * snapshot, tool selection, native bound, and command supervision.
 *
 * One capture is in flight at a time, and anything the reader could not release
 * stays owned: the next read refuses until `close` retries it.
 */
export class PcapMessageReader {
  readonly #resources: ArtifactAnalysisResources;
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #launcher: PcapCommandLauncher | undefined;
  readonly #snapshots = new Set<PcapSnapshot>();
  readonly #commands = new Map<ProviderProcessSupervisor, RetainedCommand>();
  readonly #unreleasedSnapshots = new Map<string, AnalysisError>();
  #nativeBound: Parameters<typeof runPcapCommand>[0]["nativeBound"];
  #nativeLimitations: readonly string[] = [];

  constructor(options: PcapMessageReaderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#launcher = options.launcher;
    this.#resources = new ArtifactAnalysisResources(
      "pcap",
      OPERATION,
      options.artifactReader ?? readStableArtifact,
      readLinuxResourceLimits,
      {
        message:
          "A protocol-learning read is already active; retry after it completes.",
        details: { max_concurrent_reads: 1 },
      },
    );
  }

  async read(
    path: string,
    options?: { readonly signal?: AbortSignal; readonly timeoutMs?: number },
  ): Promise<Result<ProtocolMessageReadResult, AnalysisError>> {
    const signal = options?.signal;
    return this.#resources.run(async () => {
      const pending = this.#pendingCleanup();
      if (pending !== undefined) return err(pending);
      if (signal?.aborted)
        return err(
          new AnalysisCancelledError(OPERATION, { cause: signal.reason }),
        );
      try {
        return ok(await this.#readCapture(path, signal, options?.timeoutMs));
      } catch (cause: unknown) {
        return err(this.#classify(cause));
      }
    }, signal);
  }

  async close(): Promise<void> {
    const failures: AnalysisError[] = [];
    for (const [owner, command] of this.#commands) {
      const stopped = await owner
        .stop({ terminationGraceMs: PROTOLEARN_LIMITS.stopGraceMs })
        .catch((cause: unknown) => ({
          status: "incomplete" as const,
          reason: cause instanceof Error ? cause.message : String(cause),
        }));
      if (stopped.status === "incomplete")
        failures.push(
          new ProviderCleanupError(
            "pcap",
            command.resources,
            { reason: command.reason },
            { operation: OPERATION },
          ),
        );
      else this.#commands.delete(owner);
    }
    for (const snapshot of this.#snapshots) {
      const failure = await this.#discard(snapshot);
      if (failure !== undefined) failures.push(failure);
    }
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (cause instanceof AnalysisError) failures.push(cause);
    }
    if (failures.length > 0)
      throw new ProviderCleanupError(
        "pcap",
        [
          ...[...this.#commands.values()].flatMap(({ resources }) => resources),
          ...this.#unreleasedSnapshots.keys(),
        ],
        {
          reason: "Protocol-learning read cleanup failed",
          operation: OPERATION,
        },
      ).bindCleanupDependencies(failures);
  }

  #classify(cause: unknown): AnalysisError {
    if (cause instanceof AnalysisError) return cause;
    if (cause instanceof ArtifactReaderFailure)
      return this.#resources.cleanupFailure(
        cause,
        (failure) =>
          new AnalysisProtocolError(
            `Reading the selected capture failed: ${failure instanceof Error ? failure.message : String(failure)}`,
            { cause: failure },
          ),
        undefined,
        OPERATION,
      );
    if (cause instanceof PcapConfigurationFailure)
      return pcapToolUnavailable(OPERATION, cause.message, { cause });
    return new AnalysisProtocolError(
      `Protocol learning could not read the capture: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }

  #pendingCleanup(): ProviderCleanupError | undefined {
    const resources = [
      ...[...this.#commands.values()].flatMap(({ resources }) => resources),
      ...this.#unreleasedSnapshots.keys(),
    ];
    if (resources.length === 0) return undefined;
    return new ProviderCleanupError(
      "pcap",
      [...new Set(resources)],
      { reason: "A previous protocol-learning read still owns resources." },
      { operation: OPERATION },
    );
  }

  async #readCapture(
    path: string,
    signal: AbortSignal | undefined,
    timeoutMs: number | undefined,
  ): Promise<ProtocolMessageReadResult> {
    const selection = resolvePcapTools(this.#environment);
    const tools = await this.#toolIdentities(selection, signal);
    const prepared = await preparePcapNativeBound(
      this.#environment,
      this.#resources,
    );
    this.#nativeBound = prepared.nativeBound;
    this.#nativeLimitations = prepared.limitations;
    const snapshot = await PcapSnapshot.create();
    this.#snapshots.add(snapshot);
    let failure: unknown;
    let result: ProtocolMessageReadResult | undefined;
    try {
      result = await this.#inspect(
        snapshot,
        selection,
        path,
        signal,
        timeoutMs,
      );
    } catch (cause: unknown) {
      failure = cause;
    }
    const cleanup = await this.#discard(snapshot);
    if (cleanup !== undefined) {
      throw failure === undefined
        ? cleanup
        : new ProviderCleanupError(
            "pcap",
            [snapshot.path],
            {
              reason: "Owned capture cleanup failed after the read",
              previous_error:
                failure instanceof Error ? failure.message : String(failure),
            },
            { operation: OPERATION, cause: failure },
          ).bindCleanupDependencies([cleanup]);
    }
    if (failure !== undefined) throw failure;
    if (result === undefined)
      throw new AnalysisProtocolError(
        "Protocol learning produced no capture result",
      );
    for (const tool of [tools.tshark, tools.capinfos]) {
      const after = await this.#resources.read(
        tool.path,
        MAX_TOOL_IDENTITY_BYTES,
      );
      assertWiresharkExecutableIdentity(
        OPERATION,
        tool.path,
        tool.identity,
        wiresharkExecutableIdentity(after),
      );
    }
    return result;
  }

  async #inspect(
    snapshot: PcapSnapshot,
    selection: PcapToolSelection,
    path: string,
    signal: AbortSignal | undefined,
    timeoutMs: number | undefined,
  ): Promise<ProtocolMessageReadResult> {
    const identity = await snapshot.capture(path, signal);
    const info = await this.#run(
      "capinfos",
      selection.capinfos.command,
      ["-M", "-S", "--", snapshot.path],
      { timeoutMs: 60_000, maxOutputBytes: 64 * 1024 },
      signal,
      snapshot,
      path,
    );
    const metadata = parseCapinfosOutput(info.stdout);
    if (metadata.sha256 !== null && metadata.sha256 !== identity.sha256)
      throw new AnalysisProtocolError(
        "capinfos SHA256 disagrees with the owned capture snapshot",
      );
    const dissected = await this.#run(
      "tshark",
      selection.tshark.command,
      [
        "-n",
        "-r",
        snapshot.path,
        "-T",
        "json",
        "--no-duplicate-keys",
        `--temp-dir=${snapshot.configurationPath}`,
        ...PCAP_MESSAGE_FIELDS.flatMap((field) => ["-e", field]),
      ],
      {
        timeoutMs: timeoutMs ?? 300_000,
        maxOutputBytes: TSHARK_JSON_MAX_BYTES,
      },
      signal,
      snapshot,
      path,
    );
    const stream = await parsePcapMessageRows(dissected.stdout, {
      format: pcapCaptureFormat(metadata.fileType),
      ...(signal === undefined ? {} : { signal }),
    });
    if (
      metadata.packetCount !== null &&
      stream.packets !== metadata.packetCount
    )
      throw new AnalysisProtocolError(
        `capinfos counted ${String(metadata.packetCount)} packets but tshark returned ${String(stream.packets)}`,
      );
    await snapshot.verify(identity, path, signal);
    return {
      sessions: stream.sessions,
      format: stream.format,
      packets: stream.packets,
      sha256: identity.sha256,
      bytes: identity.bytes,
      limitations: [
        ...this.#nativeLimitations,
        "Both tools read one owned snapshot; the capture identity comes from its admitted source descriptor",
        "Only bytes present in the saved capture are examined; encryption and capture truncation can hide message boundaries",
        "Direction is attributed from the first frame each flow shows, so a server-speaks-first protocol is labelled from its greeting",
        ...(stream.framesWithoutPayload > 0
          ? [
              `${String(stream.framesWithoutPayload)} frame(s) carried no dissected payload and are not messages`,
            ]
          : []),
        ...(stream.messagesOmitted > 0
          ? [
              `Messages retained at most ${String(PROTOLEARN_LIMITS.maxMessages)}; the rest are counted as omitted`,
            ]
          : []),
      ],
    };
  }

  async #run(
    stage: "capinfos" | "tshark",
    command: string,
    args: readonly string[],
    limits: { readonly timeoutMs: number; readonly maxOutputBytes: number },
    signal: AbortSignal | undefined,
    snapshot: PcapSnapshot,
    inputPath: string,
  ): Promise<PcapCommandOutput> {
    let retained: RetainedCommand | undefined;
    const output = await runPcapCommand({
      operation: OPERATION,
      command,
      arguments: args,
      limits,
      signal,
      environment: {
        ...this.#environment,
        WIRESHARK_CONFIG_DIR: snapshot.configurationPath,
      },
      inputPath,
      ...(this.#nativeBound === undefined
        ? {}
        : { nativeBound: this.#nativeBound }),
      ...(this.#launcher === undefined ? {} : { launcher: this.#launcher }),
      retain: (owner, resources, reason) => {
        retained = { owner, resources, reason };
        this.#commands.set(owner, retained);
      },
    });
    if (output.cleanup !== undefined)
      throw this.#commandCleanupError(stage, output.cleanup);
    return output;
  }

  #commandCleanupError(
    stage: string,
    cleanup: PcapCommandCleanup,
  ): ProviderCleanupError {
    return new ProviderCleanupError(
      "pcap",
      cleanup.resources,
      {
        reason: cleanup.reason,
        stage,
        captured_output: {
          stdout: cleanup.capturedOutput.stdout,
          stderr: cleanup.capturedOutput.stderr,
          truncated: cleanup.capturedOutput.truncated,
        },
      },
      { operation: OPERATION },
    );
  }

  async #toolIdentities(
    selection: PcapToolSelection,
    signal: AbortSignal | undefined,
  ): Promise<{
    readonly tshark: { path: string; identity: WiresharkExecutableIdentity };
    readonly capinfos: { path: string; identity: WiresharkExecutableIdentity };
  }> {
    const read = async (
      name: "tshark" | "capinfos",
    ): Promise<{ path: string; identity: WiresharkExecutableIdentity }> => {
      const selected = selection[name];
      const located = locateWiresharkTool(selected, this.#environment);
      if (located === undefined)
        throw pcapToolUnavailable(
          OPERATION,
          `The selected ${name} executable ${selected.command} could not be located`,
        );
      const path = await realpath(located);
      const snapshot = await this.#resources.read(
        path,
        MAX_TOOL_IDENTITY_BYTES,
        signal,
      );
      return { path, identity: wiresharkExecutableIdentity(snapshot) };
    };
    return { tshark: await read("tshark"), capinfos: await read("capinfos") };
  }

  async #discard(snapshot: PcapSnapshot): Promise<AnalysisError | undefined> {
    try {
      await snapshot.close();
      this.#snapshots.delete(snapshot);
      this.#unreleasedSnapshots.delete(snapshot.path);
      return undefined;
    } catch (cause: unknown) {
      const failure = new ProviderCleanupError(
        "pcap",
        [snapshot.path],
        { reason: String(cause) },
        { operation: OPERATION, cause },
      );
      this.#unreleasedSnapshots.set(snapshot.path, failure);
      return failure;
    }
  }
}
