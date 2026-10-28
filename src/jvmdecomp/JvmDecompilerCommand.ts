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
import type { JvmDecompilerConfiguration } from "./JvmDecompilerConfiguration.js";
import { JVM_DECOMPILER_PROVIDER_ID } from "./JvmDecompilerRelease.js";

/** Bounded stdout/stderr budget for one Vineflower run. */
export const JVM_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

/** The Vineflower argv shape this lane assumes. */
export const jvmDecompilerArguments = {
  decompile: (
    jar: string,
    input: string,
    outputDirectory: string,
    className: string | null,
  ): readonly string[] => [
    "-jar",
    jar,
    ...(className === null ? [] : [`-only=${className}`]),
    input,
    outputDirectory,
  ],
} as const;

/** Run one bounded Vineflower invocation, keeping its exact failure shape. */
export const runJvmDecompilerCommand = async (
  operation: string,
  configuration: JvmDecompilerConfiguration,
  input: string,
  outputDirectory: string,
  className: string | null,
  signal: AbortSignal | undefined,
): Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  try {
    const { stdout, stderr } = await execFileBytes(
      configuration.java,
      jvmDecompilerArguments.decompile(
        configuration.jar,
        input,
        outputDirectory,
        className,
      ),
      {
        timeout: configuration.operationTimeoutMs,
        maxBuffer: JVM_MAX_OUTPUT_BYTES,
        stopSignal: "SIGTERM",
        ...(signal === undefined ? {} : { signal }),
      },
    );
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
        new ProviderAdapterError(JVM_DECOMPILER_PROVIDER_ID, operation, {
          cause,
          userMessage: `Cannot run ${configuration.java} for ${operation}: ${
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
          `Vineflower output exceeded the ${String(JVM_MAX_OUTPUT_BYTES)}-byte capture budget`,
          { max_output_bytes: JVM_MAX_OUTPUT_BYTES },
          outputOptions,
        ),
      );
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(
          operation,
          configuration.operationTimeoutMs,
          outputOptions,
        ),
      );
    return err(
      new ProviderAdapterError(JVM_DECOMPILER_PROVIDER_ID, operation, {
        ...outputOptions,
        userMessage: `Vineflower failed for ${operation}: ${
          failure.stderr.trim().split("\n").at(-1) ||
          `exit code ${String(failure.code)}`
        }`,
      }),
    );
  }
};
