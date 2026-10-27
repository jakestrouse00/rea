import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
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
import { DISCOVERY_PROVIDER_ID } from "./DiscoveryRelease.js";

/** Bounded stdout budget for one host tool. */
export const DISCOVERY_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/**
 * Injection seam over the owned child launcher. Production runs the
 * resolved host tool directly with bounded output and a stop signal.
 */
export type DiscoveryProcessLauncher = (request: {
  readonly executable: string;
  readonly arguments: readonly string[];
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly signal: AbortSignal | undefined;
}) => Promise<{ readonly stdout: string; readonly stderr: string }>;

/** Run one bounded host-tool command, keeping its exact failure shape. */
export const runDiscoveryCommand = async (
  operation: string,
  executable: string,
  args: readonly string[],
  limits: { readonly timeoutMs: number },
  signal: AbortSignal | undefined,
  launcher?: DiscoveryProcessLauncher,
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
        maxOutputBytes: DISCOVERY_MAX_OUTPUT_BYTES,
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
      maxBuffer: DISCOVERY_MAX_OUTPUT_BYTES,
      stopSignal: "SIGTERM",
      ...(signal === undefined ? {} : { signal }),
    });
    return ok({
      stdout: stdout.toString("utf8"),
      stderr: stderr.toString("utf8"),
      stdoutBytes: stdout.byteLength,
    });
  } catch (cause) {
    return err(discoveryCommandFailure(operation, executable, args, cause));
  }
};

/**
 * Run one process whose nonzero exit is observed data rather than a
 * failure, as with an unanswered ping. A deadline kill becomes a
 * structured non-response; cancellation still cancels.
 */
export const runDiscoveryObservation = async (
  operation: string,
  executable: string,
  args: readonly string[],
  limits: { readonly timeoutMs: number },
  signal: AbortSignal | undefined,
  launcher?: DiscoveryProcessLauncher,
): Promise<
  Result<
    {
      stdout: string;
      stderr: string;
      exit_code: number | null;
      timed_out: boolean;
    },
    AnalysisError
  >
> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  try {
    if (launcher !== undefined) {
      const ran = await launcher({
        executable,
        arguments: args,
        timeoutMs: limits.timeoutMs,
        maxOutputBytes: DISCOVERY_MAX_OUTPUT_BYTES,
        signal,
      });
      return ok({
        stdout: ran.stdout,
        stderr: ran.stderr,
        exit_code: 0,
        timed_out: false,
      });
    }
    const { stdout, stderr } = await execFileBytes(executable, args, {
      timeout: limits.timeoutMs,
      maxBuffer: DISCOVERY_MAX_OUTPUT_BYTES,
      stopSignal: "SIGTERM",
      ...(signal === undefined ? {} : { signal }),
    });
    return ok({
      stdout: stdout.toString("utf8"),
      stderr: stderr.toString("utf8"),
      exit_code: 0,
      timed_out: false,
    });
  } catch (cause) {
    if (cause instanceof ExecFileOutputCancelledError)
      return err(new AnalysisCancelledError(operation, { cause: cause.cause }));
    const output = execFileOutputFailure(cause);
    if (output === undefined)
      return err(
        new ProviderAdapterError(DISCOVERY_PROVIDER_ID, operation, {
          cause,
          userMessage: `Cannot run ${executable} for ${operation}: ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
        }),
      );
    // A deadline kill is the host not answering within the window, which is
    // the observation this operation exists to make; nonzero exits likewise.
    if (output.killed)
      return ok({
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: typeof output.code === "number" ? output.code : null,
        timed_out: true,
      });
    return ok({
      stdout: output.stdout,
      stderr: output.stderr,
      exit_code: typeof output.code === "number" ? output.code : null,
      timed_out: false,
    });
  }
};

/** Shared failure mapping for tool reads where nonzero exits are failures. */
const discoveryCommandFailure = (
  operation: string,
  executable: string,
  args: readonly string[],
  cause: unknown,
): AnalysisError => {
  const failure = execFileOutputFailure(cause);
  if (cause instanceof ExecFileOutputCancelledError)
    return new AnalysisCancelledError(operation, { cause: cause.cause });
  if (failure === undefined)
    return new ProviderAdapterError(DISCOVERY_PROVIDER_ID, operation, {
      cause,
      userMessage: `Cannot run ${executable} for ${operation}: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    });
  if (failure.outputTruncated)
    return new AnalysisResourceConstraintError(
      operation,
      "memory",
      `host tool output exceeded the ${String(DISCOVERY_MAX_OUTPUT_BYTES)}-byte capture budget`,
      { max_output_bytes: DISCOVERY_MAX_OUTPUT_BYTES },
      { cause },
    );
  return new ProviderAdapterError(DISCOVERY_PROVIDER_ID, operation, {
    cause,
    capturedOutput: discoveryCapturedOutput(failure),
    userMessage: `${executable} failed for ${operation}: ${
      failure.stderr.trim().split("\n").at(-1) ||
      `exit code ${String(failure.code)}`
    }`,
  });
};

/** Reuse the shared captured-output shape for host-tool diagnostics. */
const discoveryCapturedOutput = (failure: ExecFileOutputFailure) => ({
  stdout: failure.stdout,
  stderr: failure.stderr,
  truncated: failure.outputTruncated,
  exit_code: typeof failure.code === "number" ? failure.code : null,
  signal: failure.signal,
});
