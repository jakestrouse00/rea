import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  execFileBytes,
  ExecFileOutputCancelledError,
  execFileOutputFailure,
  type ExecFileOutputFailure,
} from "../process/ExecFileOutput.js";
import { IDEVICE_PROVIDER_ID } from "./IdeviceRelease.js";

/** Bounded stdout budget for one pmd3 device command. */
export const IDEVICE_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/**
 * Injection seam over the owned child launcher. Production runs the
 * caller-supplied executable directly with bounded output and a stop signal;
 * the current suites exercise that executable path with scripted launcher
 * scripts, so no test injects this seam today.
 */
export type IdeviceProcessLauncher = (request: {
  readonly executable: string;
  readonly arguments: readonly string[];
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly signal: AbortSignal | undefined;
}) => Promise<{ readonly stdout: string; readonly stderr: string }>;

/** Run one bounded pmd3 command, keeping its exact failure shape. */
export const runIdeviceCommand = async (
  operation: string,
  executable: string,
  args: readonly string[],
  limits: { readonly timeoutMs: number },
  signal: AbortSignal | undefined,
  launcher?: IdeviceProcessLauncher,
): Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  try {
    if (launcher !== undefined) {
      const ran = await launcher({
        executable,
        arguments: args,
        timeoutMs: limits.timeoutMs,
        maxOutputBytes: IDEVICE_MAX_OUTPUT_BYTES,
        signal,
      });
      return ok({
        stdout: ran.stdout,
        stderr: ran.stderr,
        stdoutBytes: Buffer.byteLength(ran.stdout),
      });
    }
    const { stdout, stderr } = await execFileBytes(executable, args, {
      timeout: limits.timeoutMs,
      maxBuffer: IDEVICE_MAX_OUTPUT_BYTES,
      stopSignal: "SIGTERM",
      ...(signal === undefined ? {} : { signal }),
    });
    return ok({
      stdout: stdout.toString("utf8"),
      stderr: stderr.toString("utf8"),
      stdoutBytes: stdout.byteLength,
    });
  } catch (cause) {
    const failure = execFileOutputFailure(cause);
    if (cause instanceof ExecFileOutputCancelledError)
      return err(
        new AnalysisCancelledError(operation, {
          cause: cause.cause,
          ...(failure === undefined
            ? {}
            : { capturedOutput: ideviceCapturedOutput(failure) }),
        }),
      );
    if (failure === undefined)
      return err(
        new ProviderAdapterError(IDEVICE_PROVIDER_ID, operation, {
          cause,
          userMessage: `Cannot run ${executable} for ${operation}: ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
        }),
      );
    if (failure.outputTruncated)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `pymobiledevice3 output exceeded the ${String(IDEVICE_MAX_OUTPUT_BYTES)}-byte capture budget`,
          { max_output_bytes: IDEVICE_MAX_OUTPUT_BYTES },
          { cause },
        ),
      );
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, { cause }),
      );
    return err(
      new ProviderAdapterError(IDEVICE_PROVIDER_ID, operation, {
        cause,
        capturedOutput: ideviceCapturedOutput(failure),
        userMessage: `pymobiledevice3 ${args[0] ?? ""} failed for ${operation}: ${
          failure.stderr.trim().split("\n").at(-1) ||
          `exit code ${String(failure.code)}`
        }`,
      }),
    );
  }
};

/** Reuse the shared captured-output shape for pmd3 diagnostics. */
const ideviceCapturedOutput = (failure: ExecFileOutputFailure) => ({
  stdout: failure.stdout,
  stderr: failure.stderr,
  truncated: failure.outputTruncated,
  ...(typeof failure.stdoutBytes === "number"
    ? { stdout_bytes: failure.stdoutBytes }
    : {}),
  ...(typeof failure.stderrBytes === "number"
    ? { stderr_bytes: failure.stderrBytes }
    : {}),
  exit_code: typeof failure.code === "number" ? failure.code : null,
  signal: failure.signal,
});
