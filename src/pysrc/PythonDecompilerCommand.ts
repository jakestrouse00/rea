import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  ExecFileOutputCancelledError,
  execFileBytes,
  execFileFailureCapturedOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import { PYTHON_DECOMPILER_PROVIDER_ID } from "./PythonDecompilerRelease.js";

/** Bounded stdout budget for one recovered source document. */
export const PYTHON_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

/** The decompiler argv shape this lane assumes: recovered source on stdout. */
export const pythonDecompilerArguments = {
  decompile: (path: string): readonly string[] => [path],
} as const;

/** Run one bounded Python decompiler command, keeping its exact failure shape. */
export const runPythonDecompilerCommand = async (
  operation: string,
  executable: string,
  args: readonly string[],
  limits: { readonly timeoutMs: number },
  signal: AbortSignal | undefined,
): Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  try {
    const { stdout, stderr } = await execFileBytes(executable, args, {
      timeout: limits.timeoutMs,
      maxBuffer: PYTHON_MAX_OUTPUT_BYTES,
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
    const capturedOutput =
      failure === undefined
        ? undefined
        : execFileFailureCapturedOutput(failure);
    if (cause instanceof ExecFileOutputCancelledError)
      return err(
        new AnalysisCancelledError(operation, {
          cause: cause.cause,
          ...(capturedOutput === undefined ? {} : { capturedOutput }),
        }),
      );
    if (failure === undefined)
      return err(
        new ProviderAdapterError(PYTHON_DECOMPILER_PROVIDER_ID, operation, {
          cause,
          userMessage: `Cannot run ${executable} for ${operation}: ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
        }),
      );
    const outputOptions = {
      cause,
      ...(capturedOutput === undefined ? {} : { capturedOutput }),
    };
    if (failure.outputTruncated)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `Python decompiler output exceeded the ${String(PYTHON_MAX_OUTPUT_BYTES)}-byte capture budget`,
          { max_output_bytes: PYTHON_MAX_OUTPUT_BYTES },
          outputOptions,
        ),
      );
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, outputOptions),
      );
    return err(
      new ProviderAdapterError(PYTHON_DECOMPILER_PROVIDER_ID, operation, {
        ...outputOptions,
        userMessage: `Python decompiler failed for ${operation}: ${
          failure.stderr.trim().split("\n").at(-1) ||
          `exit code ${String(failure.code)}`
        }`,
      }),
    );
  }
};
