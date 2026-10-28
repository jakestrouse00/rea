import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  binaryDeepReportSchema,
  inspectBinaryDeepInputSchema,
  type BinaryDeepReport,
} from "../domain/lief/binaryDeep.js";
import {
  liefArtifactSchema,
  type LiefFormat,
} from "../domain/lief/liefArtifact.js";
import {
  parseLiefFrame,
  type LiefBridgeAdvertisement,
  type LiefBridgeErrorFrame,
  type LiefBridgeReportFrame,
} from "../domain/lief/liefBridgeFrames.js";
import {
  extractPdbDwarfInfoInputSchema,
  pdbDwarfInfoReportSchema,
  type LiefLookupQuery,
  type PdbDwarfInfoReport,
} from "../domain/lief/pdbDwarfInfo.js";
import {
  LIEF_COMMAND_REMEDIATION,
  LIEF_IMPORT_REMEDIATION,
  LIEF_LIMITS,
  LIEF_PARSE_REMEDIATION,
  LIEF_PROTOCOL_REMEDIATION,
  LIEF_PROVIDER_ID,
} from "../domain/lief/liefLimits.js";
import {
  LIEF_SUPPORTED_RANGE,
  liefVersionSupported,
} from "../domain/lief/liefVersion.js";
import { resolveLiefConfiguration } from "./LiefConfiguration.js";
import {
  LiefBridgeRunError,
  runLiefBridge,
  type LiefBridgeRunInput,
} from "./LiefBridgeClient.js";
import { liefDelegatedFacts } from "./LiefDelegatedFacts.js";

/** Bundled adapter identity; the LIEF release is caller-owned. */
export const LIEF_PROVIDER_IDENTITY = {
  id: LIEF_PROVIDER_ID,
  name: "REA LIEF deep-parse bridge",
  version: "1",
} as const;

const DEEP_PARSE_OPERATION = "inspect_binary_deep";
const PDB_DWARF_OPERATION = "extract_pdb_dwarf_info";

/** Replaceable run seam; production spawns the caller's interpreter once. */
export type LiefBridgeRunner = (
  input: LiefBridgeRunInput,
) => Promise<Awaited<ReturnType<typeof runLiefBridge>>>;

/** One artifact digest computed before the bridge is asked to parse it. */
interface SelectedArtifact {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

/** What a successful run established before the operation's own validation. */
interface BridgeObservation {
  readonly artifact: SelectedArtifact;
  readonly bridge: LiefBridgeAdvertisement;
  readonly report: unknown;
}

const hashArtifact = async (
  operation: string,
  path: string,
  signal: AbortSignal | undefined,
): Promise<{ sha256: string; bytes: number }> => {
  const hash = createHash("sha256");
  let bytes = 0;
  const stream = createReadStream(path);
  for await (const chunk of stream) {
    if (signal?.aborted === true)
      throw new AnalysisCancelledError(operation, {
        cause: signal.reason,
      });
    bytes += (chunk as Buffer).length;
    hash.update(chunk as Buffer);
  }
  return { sha256: hash.digest("hex"), bytes };
};

const fileFailure = (
  operation: string,
  cause: unknown,
  path: string,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof Error && "code" in cause) {
    const code = String(cause.code);
    if (code === "EACCES" || code === "EPERM")
      return new AnalysisAccessDeniedError(operation, path, code, { cause });
    if (["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(code))
      return new AnalysisInputError(operation, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${code}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(LIEF_PROVIDER_ID, operation, { cause });
};

const unavailable = (
  operation: string,
  reason: string,
  remediation: string,
): AnalysisCapabilityUnavailableError =>
  new AnalysisCapabilityUnavailableError(LIEF_PROVIDER_ID, operation, reason, {
    userMessage: reason,
    remediationAction: remediation,
  });

/** Project one bounded run failure onto the provider-neutral error algebra. */
const runFailure = (
  operation: string,
  cause: LiefBridgeRunError,
): AnalysisError => {
  const detail =
    cause.diagnostics.stderr.length === 0
      ? cause.message
      : `${cause.message} Bridge stderr: ${cause.diagnostics.stderr.slice(0, 512)}`;
  switch (cause.reason) {
    case "cancelled":
      return new AnalysisCancelledError(operation, { cause });
    case "timeout":
      return new AnalysisTimeoutError(
        operation,
        LIEF_LIMITS.defaultDeadlineMs,
        {
          cause,
          userMessage: cause.message,
          remediationAction: `One LIEF bridge run has a fixed ${String(LIEF_LIMITS.defaultDeadlineMs)} ms deadline in this release. Reduce the selected artifact or answer fewer queries; raising the host tool-call deadline does not extend it.`,
        },
      );
    case "spawn":
      return unavailable(operation, detail, LIEF_COMMAND_REMEDIATION);
    case "output-limit":
      return new AnalysisResourceConstraintError(
        operation,
        "memory",
        detail,
        { maximum_response_bytes: LIEF_LIMITS.maxResponseBytes },
        { cause, remediationAction: LIEF_PROTOCOL_REMEDIATION },
      );
    case "protocol":
    case "process":
      return new AnalysisOutputError(operation, detail, {
        cause,
        userMessage: detail,
        remediationAction: LIEF_PROTOCOL_REMEDIATION,
      });
  }
};

/** Project one bridge refusal frame onto the provider-neutral error algebra. */
const refusal = (
  operation: string,
  path: string,
  frame: LiefBridgeErrorFrame,
): AnalysisError => {
  switch (frame.code) {
    case "lief_missing":
      return unavailable(operation, frame.message, LIEF_IMPORT_REMEDIATION);
    case "unsupported_format":
      return new AnalysisUnsupportedTargetError(
        operation,
        path,
        frame.message,
        { remediationAction: LIEF_PARSE_REMEDIATION },
      );
    case "artifact_unreadable":
      return new AnalysisInputError(operation, undefined, [
        { path: ["path"], reason: "invalid_value", message: frame.message },
      ]);
    case "artifact_mismatch":
      return new AnalysisArtifactChangedError(operation, path, frame.message);
    case "parse_failed":
      return new AnalysisOutputError(operation, frame.message, {
        userMessage: frame.message,
        remediationAction: LIEF_PARSE_REMEDIATION,
      });
    case "empty_request":
    case "oversized_request":
    case "malformed_request":
    case "unsupported_protocol":
    case "unsupported_operation":
      return new AnalysisOutputError(
        operation,
        `The bundled bridge refused the request it was handed (${frame.code}): ${frame.message}`,
        {
          userMessage: frame.message,
          remediationAction: LIEF_PROTOCOL_REMEDIATION,
        },
      );
    case "internal_error":
      return new ProviderAdapterError(LIEF_PROVIDER_ID, operation, {
        diagnostics: { bridge_message: frame.message.slice(0, 512) },
      });
  }
};

/** Offline LIEF adapter: bounded bridge runs, caller-owned LIEF, no target execution. */
export class LiefDeepProvider {
  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv>,
    readonly runner: LiefBridgeRunner = runLiefBridge,
  ) {}

  get identity(): {
    readonly id: string;
    readonly name: string;
    readonly version: string;
  } {
    return LIEF_PROVIDER_IDENTITY;
  }

  /** Report one binary's LIEF-unique cross-format structure. */
  async inspectBinaryDeep(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<BinaryDeepReport, AnalysisError>> {
    const operation = DEEP_PARSE_OPERATION;
    const input = inspectBinaryDeepInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        new AnalysisInputError(operation, { cause: input.error }, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: "Expected an absolute ELF, PE or Mach-O path.",
          },
        ]),
      );
    const observation = await this.#observe(
      operation,
      input.data.path,
      undefined,
      options?.signal,
    );
    if (!observation.ok) return observation;
    const { artifact, bridge, report } = observation.value;
    const parsed = binaryDeepReportSchema.safeParse({
      artifact,
      bridge,
      ...(typeof report === "object" && report !== null ? report : {}),
      delegated_facts: liefDelegatedFacts(
        (report as { format?: LiefFormat } | null)?.format ?? "unknown",
      ),
    });
    if (!parsed.success)
      return err(
        new AnalysisOutputError(
          operation,
          "The bridge report does not satisfy the deep-structure contract.",
          { cause: parsed.error, remediationAction: LIEF_PROTOCOL_REMEDIATION },
        ),
      );
    if (parsed.data.format === "pdb")
      return err(
        new AnalysisUnsupportedTargetError(
          operation,
          artifact.path,
          "A PDB is read by extract_pdb_dwarf_info, which owns its symbol surface.",
          {
            remediationAction:
              "Run extract_pdb_dwarf_info on the selected PDB.",
          },
        ),
      );
    return ok(parsed.data);
  }

  /** Report one artifact's PDB and DWARF debug surfaces and bounded lookups. */
  async extractPdbDwarfInfo(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<PdbDwarfInfoReport, AnalysisError>> {
    const operation = PDB_DWARF_OPERATION;
    const input = extractPdbDwarfInfoInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        new AnalysisInputError(operation, { cause: input.error }, [
          {
            path: ["queries"],
            reason: "invalid_value",
            message: `Expected at most ${String(LIEF_LIMITS.maxQueries)} symbol or address lookups.`,
          },
        ]),
      );
    const observation = await this.#observe(
      operation,
      input.data.path,
      input.data.queries,
      options?.signal,
    );
    if (!observation.ok) return observation;
    const { artifact, bridge, report } = observation.value;
    const parsed = pdbDwarfInfoReportSchema.safeParse({
      artifact,
      bridge,
      ...(typeof report === "object" && report !== null ? report : {}),
    });
    if (!parsed.success)
      return err(
        new AnalysisOutputError(
          operation,
          "The bridge report does not satisfy the debug-info contract.",
          { cause: parsed.error, remediationAction: LIEF_PROTOCOL_REMEDIATION },
        ),
      );
    return ok(parsed.data);
  }

  /** Hash the selected artifact, run the bridge once and validate its frame. */
  async #observe(
    operation: string,
    path: string,
    queries: readonly LiefLookupQuery[] | undefined,
    signal: AbortSignal | undefined,
  ): Promise<Result<BridgeObservation, AnalysisError>> {
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    const configuration = resolveLiefConfiguration(this.environment);
    if (!configuration.ok)
      return err(
        unavailable(
          operation,
          `${configuration.error.reason} The LIEF deep-parse lane needs a caller-supplied interpreter and bridge script.`,
          configuration.error.remediation,
        ),
      );
    let artifact: SelectedArtifact;
    try {
      const stats = await stat(path);
      if (!stats.isFile())
        return err(
          new AnalysisInputError(operation, undefined, [
            {
              path: ["path"],
              reason: "invalid_value",
              message: `Selected artifact is not a regular file: ${path}`,
            },
          ]),
        );
      artifact = { path, ...(await hashArtifact(operation, path, signal)) };
      const identity = liefArtifactSchema.safeParse(artifact);
      if (!identity.success) throw identity.error;
    } catch (cause: unknown) {
      return err(fileFailure(operation, cause, path));
    }
    const request = JSON.stringify({
      protocol: configuration.value.protocolVersion,
      operation,
      path: artifact.path,
      artifact: { sha256: artifact.sha256, bytes: artifact.bytes },
      ...(queries === undefined ? {} : { queries }),
    });
    let run: Awaited<ReturnType<LiefBridgeRunner>>;
    try {
      run = await this.runner({
        command: configuration.value.command,
        bridgePath: configuration.value.bridgePath,
        request,
        hostEnvironment: this.environment,
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause: unknown) {
      return err(
        cause instanceof LiefBridgeRunError
          ? runFailure(operation, cause)
          : new ProviderAdapterError(LIEF_PROVIDER_ID, operation, { cause }),
      );
    }
    if (run.line === undefined)
      return err(
        new AnalysisOutputError(operation, "The bridge emitted no frame.", {
          remediationAction: LIEF_PROTOCOL_REMEDIATION,
        }),
      );
    const frame = parseLiefFrame(run.line);
    if (frame.kind === "invalid")
      return err(
        new AnalysisOutputError(operation, frame.reason, {
          remediationAction: LIEF_PROTOCOL_REMEDIATION,
        }),
      );
    if (frame.kind === "protocol-mismatch")
      return err(
        new AnalysisOutputError(
          operation,
          `The bridge speaks protocol ${String(frame.protocol)}; this REA build speaks ${String(configuration.value.protocolVersion)}.`,
          { remediationAction: LIEF_PROTOCOL_REMEDIATION },
        ),
      );
    if (frame.kind === "error")
      return err(refusal(operation, path, frame.frame));
    return this.#accept(operation, artifact, frame.frame);
  }

  /** Bind one report frame to the selected artifact's digest and LIEF release. */
  #accept(
    operation: string,
    artifact: SelectedArtifact,
    frame: LiefBridgeReportFrame,
  ): Result<BridgeObservation, AnalysisError> {
    const bridge = frame.bridge;
    if (frame.operation !== operation)
      return err(
        new AnalysisOutputError(
          operation,
          `The bridge answered ${frame.operation} for an ${operation} request.`,
          { remediationAction: LIEF_PROTOCOL_REMEDIATION },
        ),
      );
    if (!liefVersionSupported(bridge.lief_version))
      return err(
        unavailable(
          operation,
          `The selected interpreter reports LIEF ${bridge.lief_version}; this bridge targets ${LIEF_SUPPORTED_RANGE}.`,
          LIEF_IMPORT_REMEDIATION,
        ),
      );
    const echoed = (frame.report as { artifact?: unknown }).artifact;
    if (echoed !== undefined) {
      const digest = liefArtifactSchema.safeParse(echoed);
      if (!digest.success || digest.data.sha256 !== artifact.sha256)
        return err(
          new AnalysisArtifactChangedError(
            operation,
            artifact.path,
            "the bridge parsed a different artifact than the one that was hashed",
          ),
        );
    }
    const limitations = boundedLimitations([
      ...(Array.isArray((frame.report as { limitations?: unknown }).limitations)
        ? ((frame.report as { limitations: string[] }).limitations ?? [])
        : []),
      "LIEF-derived facts are the caller-selected release's interpretation; REA does not re-derive them.",
      "Debug-info coverage is bounded: absent DWARF sections or PDB symbol tables are reported as absence, not as proof no debug data exists in another container.",
    ]);
    return ok({
      artifact,
      bridge,
      report: { ...(frame.report as Record<string, unknown>), limitations },
    });
  }
}

/** Retain at most the fixed limitation budget, preserving first-seen order. */
const boundedLimitations = (values: readonly string[]): readonly string[] =>
  [...new Set(values.filter((value) => value.length > 0))].slice(
    0,
    LIEF_LIMITS.maxLimitations,
  );
