import { lstat } from "node:fs/promises";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import {
  CRASH_MINIMIZE_DIAGNOSTIC_EXCERPT_BYTES,
  CRASH_MINIMIZE_MAX_OUTPUT_BYTES,
  CRASH_MINIMIZE_MAX_TIMEOUT_MS,
  CRASH_MINIMIZE_MAX_TOTAL_SECONDS,
  crashMinimizeArguments,
  crashMinimizationObservationSchema,
  parseCrashMinimizeOutput,
  type CrashMinimizationObservation,
  type CrashMinimizeEngine,
  type CrashMinimizeExitType,
} from "../domain/crashTriage/crashMinimization.js";
import { CRASH_TRIAGE_PROVIDER } from "../domain/crashTriage/crashReport.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  ExecFileOutputCancelledError,
  execFileBytes,
  execFileFailureCapturedOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import {
  CrashMinimizeConfigurationFailure,
  resolveCrashMinimizeConfiguration,
} from "./MinimizationConfiguration.js";
import {
  digestCampaignArtifact,
  observeWrittenFile,
} from "./CrashTriageArtifacts.js";

const operation = "minimize_crash";

/** One minimization attempt over a caller-owned crash input and output path. */
export interface CrashMinimizeRequest {
  readonly engine: CrashMinimizeEngine;
  readonly inputPath: string;
  readonly outputPath: string;
  readonly targetPath?: string;
  readonly timeoutMs: number;
  readonly maxTotalSeconds: number;
}

const SPAWN_FAILURE_CODES = new Set([
  "ENOENT",
  "EACCES",
  "EPERM",
  "ENOTDIR",
  "ENOEXEC",
]);

const spawnFailureCode = (cause: unknown): string | undefined => {
  if (!(cause instanceof Error) || !("code" in cause)) return undefined;
  const code = cause.code;
  return typeof code === "string" && SPAWN_FAILURE_CODES.has(code)
    ? code
    : undefined;
};

const exitTypeOf = (
  failure: NonNullable<ReturnType<typeof execFileOutputFailure>>,
): CrashMinimizeExitType => {
  if (failure.outputTruncated) return "output_truncated";
  if (typeof failure.code === "number")
    return failure.killed ? "timeout" : "exited";
  return failure.killed ? "timeout" : "signalled";
};

const excerpt = (text: string): string => {
  const trimmed = text.trim();
  return trimmed.length <= CRASH_MINIMIZE_DIAGNOSTIC_EXCERPT_BYTES
    ? trimmed
    : `…${trimmed.slice(-CRASH_MINIMIZE_DIAGNOSTIC_EXCERPT_BYTES)}`;
};

export class CrashMinimizer {
  constructor(
    private readonly environment: Readonly<Record<string, string | undefined>>,
  ) {}

  /**
   * Run one engine's minimizer over one crash input.
   *
   * Output bytes are never published: the caller receives the observed input
   * and output sizes and digests, the engine's own counters, and how the call
   * ended. Both engine logs stay bounded and only a 512-byte tail can reach a
   * failure message.
   */
  async minimize(
    request: CrashMinimizeRequest,
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<Result<CrashMinimizationObservation, AnalysisError>> {
    if (options.signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    if (
      !Number.isInteger(request.timeoutMs) ||
      request.timeoutMs < 1 ||
      request.timeoutMs > CRASH_MINIMIZE_MAX_TIMEOUT_MS
    )
      return err(
        new AnalysisInputError(operation, {
          userMessage: `timeout_ms must be an integer from 1 to ${String(CRASH_MINIMIZE_MAX_TIMEOUT_MS)}`,
        }),
      );
    if (
      !Number.isInteger(request.maxTotalSeconds) ||
      request.maxTotalSeconds < 1 ||
      request.maxTotalSeconds > CRASH_MINIMIZE_MAX_TOTAL_SECONDS
    )
      return err(
        new AnalysisInputError(operation, {
          userMessage: `max_total_seconds must be an integer from 1 to ${String(CRASH_MINIMIZE_MAX_TOTAL_SECONDS)}`,
        }),
      );
    let configuration;
    try {
      configuration = resolveCrashMinimizeConfiguration(
        this.environment,
        request.engine,
      );
    } catch (cause: unknown) {
      if (!(cause instanceof CrashMinimizeConfigurationFailure)) throw cause;
      return err(
        new AnalysisCapabilityUnavailableError(
          CRASH_TRIAGE_PROVIDER.id,
          operation,
          cause.message,
          {
            cause,
            userMessage: cause.message,
            remediationAction: cause.remediation,
            diagnostics: { setting: cause.setting, ...cause.diagnostics },
          },
        ),
      );
    }
    const input = await digestCampaignArtifact(request.inputPath, operation, {
      label: "seed",
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (!input.ok) return input;
    const existing = await lstat(request.outputPath).catch(() => null);
    if (existing !== null)
      return err(
        new AnalysisInputError(operation, {
          userMessage: `The minimization output path already exists; REA never overwrites a caller-selected file: ${request.outputPath}`,
        }),
      );
    const startedAt = Date.now();
    try {
      const { stdout } = await execFileBytes(
        configuration.command,
        crashMinimizeArguments({
          engine: request.engine,
          inputPath: request.inputPath,
          outputPath: request.outputPath,
          maxTotalSeconds: request.maxTotalSeconds,
          ...(request.targetPath === undefined
            ? {}
            : { targetPath: request.targetPath }),
        }),
        {
          timeout: request.timeoutMs,
          maxBuffer: CRASH_MINIMIZE_MAX_OUTPUT_BYTES,
          stopSignal: "SIGTERM",
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        },
      );
      return this.#completed(
        request,
        input.value,
        stdout.toString("utf8"),
        Date.now() - startedAt,
        options.signal,
      );
    } catch (cause: unknown) {
      if (cause instanceof ExecFileOutputCancelledError)
        return err(
          new AnalysisCancelledError(operation, { cause: cause.cause }),
        );
      const spawnCode = spawnFailureCode(cause);
      if (spawnCode !== undefined)
        return err(
          new AnalysisCapabilityUnavailableError(
            CRASH_TRIAGE_PROVIDER.id,
            operation,
            `The selected minimizer could not be started (${spawnCode}): ${configuration.command}`,
            {
              cause,
              diagnostics: {
                boundary: "provider-launch",
                selected_binary: configuration.command,
                system_code: spawnCode,
              },
            },
          ),
        );
      return this.#failed(request, input.value, cause, options.signal);
    }
  }

  async #completed(
    request: CrashMinimizeRequest,
    input: { readonly bytes: number; readonly sha256: string },
    stdout: string,
    durationMs: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<CrashMinimizationObservation, AnalysisError>> {
    const written = await observeWrittenFile(
      request.outputPath,
      operation,
      signal,
    );
    if (written === null)
      return err(
        new AnalysisOutputError(
          operation,
          "the minimizer exited cleanly without writing its artifact",
          {
            userMessage: `No readable regular file was observed at ${request.outputPath} after a clean exit (absent, not a regular file, or above the artifact digest budget); the minimized artifact is unknown`,
            diagnostics: {
              engine: request.engine,
              output_path: request.outputPath,
              exit_code: 0,
              duration_ms: durationMs,
            },
          },
        ),
      );
    const counters = parseCrashMinimizeOutput(request.engine, stdout);
    return ok(
      crashMinimizationObservationSchema.parse({
        engine: request.engine,
        exit_type: "exited",
        exit_code: 0,
        duration_ms: durationMs,
        timeout_ms: request.timeoutMs,
        max_total_seconds: request.maxTotalSeconds,
        input: { path: request.inputPath, ...input },
        output: { path: request.outputPath, ...written },
        byte_reduction: input.bytes - written.bytes,
        executions: counters.executions,
        stability_percent: counters.stabilityPercent,
        output_truncated: false,
        output_reported_bytes: counters.reportedBytes,
      }),
    );
  }

  async #failed(
    request: CrashMinimizeRequest,
    input: { readonly bytes: number; readonly sha256: string },
    cause: unknown,
    signal: AbortSignal | undefined,
  ): Promise<Result<CrashMinimizationObservation, AnalysisError>> {
    const failure = execFileOutputFailure(cause);
    if (failure === undefined)
      return err(
        new ProviderAdapterError(CRASH_TRIAGE_PROVIDER.id, operation, {
          cause,
          userMessage: `Cannot run the ${request.engine} minimizer: ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
        }),
      );
    const capturedOutput = execFileFailureCapturedOutput(failure);
    const exitCode = typeof failure.code === "number" ? failure.code : null;
    const exitType = exitTypeOf(failure);
    const tail = excerpt(failure.stderr);
    const written = await observeWrittenFile(
      request.outputPath,
      operation,
      signal,
    );
    const diagnostics = {
      engine: request.engine,
      exit_type: exitType,
      exit_code: exitCode,
      input_bytes: input.bytes,
      output_bytes: written?.bytes ?? null,
      output_written: written !== null,
      ...(tail === "" ? {} : { stderr_excerpt: tail }),
    };
    if (exitType === "output_truncated")
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `The minimizer exceeded the ${String(CRASH_MINIMIZE_MAX_OUTPUT_BYTES)}-byte retained output budget`,
          {
            max_output_bytes: CRASH_MINIMIZE_MAX_OUTPUT_BYTES,
            stdout_bytes: failure.stdoutBytes ?? failure.stdout.length,
            stderr_bytes: failure.stderrBytes ?? failure.stderr.length,
          },
          {
            cause,
            capturedOutput,
            retryable: true,
            diagnostics,
            remediationAction:
              "Rerun with a smaller input; the retained-output budget has no runtime override.",
          },
        ),
      );
    if (exitType === "timeout")
      return err(
        new AnalysisTimeoutError(operation, request.timeoutMs, {
          cause,
          capturedOutput,
          diagnostics,
        }),
      );
    return err(
      new ProviderAdapterError(CRASH_TRIAGE_PROVIDER.id, operation, {
        cause,
        capturedOutput,
        diagnostics,
        userMessage: `The ${request.engine} minimizer ${
          exitType === "signalled"
            ? `ended on ${failure.signal ?? "a signal"}`
            : `exited with status ${String(exitCode)}`
        }${tail === "" ? "" : `: ${tail}`}`,
      }),
    );
  }
}
