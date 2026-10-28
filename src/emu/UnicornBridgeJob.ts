import { randomUUID } from "node:crypto";

import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  EMU_DIAGNOSTIC_EXCERPT_BYTES,
  EMU_LIMITS,
  EMU_PROTOCOL_VERSION,
  EMU_PROVIDER_ID,
} from "../domain/emu/emuLimits.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
  type ProviderProcessStopResult,
} from "../process/ProviderProcess.js";
import type { EmuConfiguration } from "./EmuConfiguration.js";

const MAX_LATE_OUTPUT_BYTES = 64 * 1024;

export interface UnicornBridgeJobInput {
  readonly configuration: EmuConfiguration;
  readonly operation: string;
  /** One protocol request without the envelope REA adds. */
  readonly body: Readonly<Record<string, unknown>>;
  readonly timeoutMs: number;
  readonly hostEnvironment: Readonly<Record<string, string | undefined>>;
  readonly signal?: AbortSignal;
}

/** A sidecar frame that violated the declared protocol. */
export class UnicornBridgeProtocolFailure extends Error {
  constructor(
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
  ) {
    super(message);
    this.name = "UnicornBridgeProtocolFailure";
  }
}

const excerpt = (value: string): string =>
  Buffer.from(value, "utf8")
    .subarray(0, EMU_DIAGNOSTIC_EXCERPT_BYTES)
    .toString("utf8");

const failureOf = (
  cause: unknown,
  operation: string,
  signal: AbortSignal | undefined,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof UnicornBridgeProtocolFailure)
    return new AnalysisProtocolError(`${cause.message} for ${operation}`, {
      cause,
      diagnostics: cause.diagnostics,
    });
  if (signal?.aborted === true)
    return new AnalysisCancelledError(operation, { cause: signal.reason });
  return new AnalysisCapabilityUnavailableError(
    EMU_PROVIDER_ID,
    operation,
    cause instanceof Error
      ? cause.message
      : "The Unicorn bridge failed without a reason",
    { cause },
  );
};

/** Run one bounded job through its own supervised sidecar process. */
export const runUnicornBridgeJob = async (
  input: UnicornBridgeJobInput,
): Promise<unknown> => {
  input.signal?.throwIfAborted();
  const jobId = randomUUID();
  const spawned = await spawnOwnedProviderProcess({
    command: input.configuration.python,
    // -I ignores PYTHON* variables and user-site packages so the caller's
    // selected environment is the only one that supplies Unicorn; -B keeps the
    // bridge from writing bytecode caches beside caller-selected sources.
    arguments: ["-I", "-B", input.configuration.bridgeScript],
    runId: randomUUID(),
    expectedCommand: null,
    stdin: "pipe",
    hostEnvironment: input.hostEnvironment as NodeJS.ProcessEnv,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  const supervisor = new ProviderProcessSupervisor(
    {
      process: spawned.process,
      ownsProcessLifetime: true,
      ownership: spawned.ownership,
    },
    { captureStdout: false, maxDiagnosticBytes: MAX_LATE_OUTPUT_BYTES },
  );
  let frame: unknown;
  let failure: AnalysisError | undefined;
  try {
    frame = await exchange(supervisor, input, jobId);
  } catch (cause: unknown) {
    failure = failureOf(cause, input.operation, input.signal);
  }
  // A finished job closes its own stdin and exits; give it a bounded moment
  // before the owner escalates to a signal it does not need.
  if (failure === undefined) await supervisor.waitForExit(250);
  const stopped: ProviderProcessStopResult = await supervisor
    .stop({ terminationGraceMs: EMU_LIMITS.stopGraceMs })
    .catch((cause: unknown): ProviderProcessStopResult => ({
      status: "incomplete",
      reason: cause instanceof Error ? cause.message : String(cause),
    }));
  if (stopped.status === "incomplete") {
    const cleanupError = new ProviderCleanupError(
      EMU_PROVIDER_ID,
      [`emu-bridge-job:${jobId}`],
      {
        reason: stopped.reason,
        job_id: jobId,
        operation: input.operation,
      },
      { operation: input.operation },
    );
    throw failure === undefined
      ? cleanupError
      : analysisErrorWithCleanupFailure(failure, cleanupError, input.operation);
  }
  if (failure !== undefined) throw failure;
  return frame;
};

const exchange = (
  supervisor: ProviderProcessSupervisor,
  input: UnicornBridgeJobInput,
  jobId: string,
): Promise<unknown> =>
  new Promise((resolve, reject) => {
    const process = supervisor.launch.process;
    const deadline = Date.now() + input.timeoutMs + EMU_LIMITS.stopGraceMs;
    let buffered: Buffer = Buffer.alloc(0);
    let settled = false;
    const settle = (complete: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      input.signal?.removeEventListener("abort", onAbort);
      process.stdout?.off("data", onData);
      process.off("close", onClose);
      // The child owns one job; closing stdin ends an idle sidecar.
      process.stdin?.end();
      complete();
    };
    const fail = (error: Error): void => settle(() => reject(error));
    const timer = setTimeout(
      () =>
        fail(
          new AnalysisOutputError(
            input.operation,
            `The Unicorn bridge did not finish within ${String(input.timeoutMs)} ms plus ${String(EMU_LIMITS.stopGraceMs)} ms of stop grace and was stopped.`,
            {
              diagnostics: {
                job_id: jobId,
                timeout_ms: input.timeoutMs,
                stop_grace_ms: EMU_LIMITS.stopGraceMs,
              },
            },
          ),
        ),
      Math.max(0, deadline - Date.now()),
    );
    const onAbort = (): void =>
      fail(
        new AnalysisCancelledError(input.operation, {
          cause: input.signal?.reason,
        }),
      );
    const onClose = (): void => {
      if (settled) return;
      const snapshot = supervisor.snapshot();
      const stderrExcerpt = excerpt(snapshot.stderr.text);
      fail(
        new AnalysisCapabilityUnavailableError(
          EMU_PROVIDER_ID,
          input.operation,
          `The Unicorn bridge exited with code ${String(snapshot.exitCode)} before returning one frame${stderrExcerpt === "" ? "" : `: ${stderrExcerpt}`}`,
          {
            diagnostics: {
              job_id: jobId,
              exit_code: snapshot.exitCode ?? null,
              exit_signal: snapshot.signal ?? null,
              stderr_excerpt: stderrExcerpt,
            },
          },
        ),
      );
    };
    const onData = (chunk: Buffer | string): void => {
      if (settled) return;
      buffered = Buffer.concat([
        buffered,
        Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
      ]);
      const boundary = buffered.indexOf(10);
      if (boundary < 0) {
        if (buffered.byteLength <= EMU_LIMITS.maxBridgeLineBytes) return;
        fail(
          new UnicornBridgeProtocolFailure(
            "The bridge emitted a frame above the transport budget",
            {
              job_id: jobId,
              max_frame_bytes: EMU_LIMITS.maxBridgeLineBytes,
            },
          ),
        );
        return;
      }
      const frame = buffered.subarray(0, boundary);
      buffered = buffered.subarray(boundary + 1);
      if (frame.byteLength > EMU_LIMITS.maxBridgeLineBytes) {
        fail(
          new UnicornBridgeProtocolFailure(
            "The bridge emitted a frame above the transport budget",
            {
              job_id: jobId,
              frame_bytes: frame.byteLength,
              max_frame_bytes: EMU_LIMITS.maxBridgeLineBytes,
            },
          ),
        );
        return;
      }
      const line = frame.toString("utf8").replace(/\r$/u, "");
      let decoded: unknown;
      try {
        decoded = JSON.parse(line);
      } catch {
        fail(
          new UnicornBridgeProtocolFailure(
            "The bridge's answer was not one JSON frame",
            { job_id: jobId, frame_excerpt: excerpt(line) },
          ),
        );
        return;
      }
      settle(() => resolve(decoded));
    };
    input.signal?.addEventListener("abort", onAbort, { once: true });
    if (input.signal?.aborted === true) {
      onAbort();
      return;
    }
    process.stdout?.on("data", onData);
    process.once("close", onClose);
    const request = JSON.stringify({
      protocol: EMU_PROTOCOL_VERSION,
      job_id: jobId,
      ...input.body,
    });
    if (Buffer.byteLength(request) + 1 > EMU_LIMITS.maxBridgeLineBytes) {
      fail(
        new UnicornBridgeProtocolFailure(
          "The request exceeds the transport budget",
          { job_id: jobId, max_frame_bytes: EMU_LIMITS.maxBridgeLineBytes },
        ),
      );
      return;
    }
    process.stdin?.on("error", () => undefined);
    process.stdin?.write(`${request}\n`);
  });
