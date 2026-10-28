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
import type { SymbolTool } from "./SymbolRecoveryConfiguration.js";
import { SYMBOL_PROVIDER_ID } from "./SymbolRecoveryRelease.js";

/** Bounded stdout budget for one symbol tool document. */
export const SYMBOL_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

/** One bounded symbol-recovery invocation. */
const OPERATION_TIMEOUT_MS: Readonly<Record<SymbolTool, number>> = {
  recover_go_symbols: 300_000,
  demangle_rust_name: 60_000,
  generate_symbol_table: 300_000,
};

export const symbolOperationTimeoutMs = (tool: SymbolTool): number =>
  OPERATION_TIMEOUT_MS[tool];

/** The producer argv shapes this lane assumes. */
export const symbolArguments = {
  recover_go_symbols: (path: string): readonly string[] => [path],
  demangle_rust_name: (names: readonly string[]): readonly string[] => [
    ...names,
  ],
  generate_symbol_table: (path: string): readonly string[] => [path],
} as const;

/** Run one bounded symbol tool, keeping its exact failure shape. */
export const runSymbolCommand = async (
  operation: string,
  tool: SymbolTool,
  executable: string,
  args: readonly string[],
  signal: AbortSignal | undefined,
): Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  try {
    const { stdout, stderr } = await execFileBytes(executable, args, {
      timeout: symbolOperationTimeoutMs(tool),
      maxBuffer: SYMBOL_MAX_OUTPUT_BYTES,
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
        new ProviderAdapterError(SYMBOL_PROVIDER_ID, operation, {
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
          `Symbol tool output exceeded the ${String(SYMBOL_MAX_OUTPUT_BYTES)}-byte capture budget`,
          { max_output_bytes: SYMBOL_MAX_OUTPUT_BYTES },
          outputOptions,
        ),
      );
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(
          operation,
          symbolOperationTimeoutMs(tool),
          outputOptions,
        ),
      );
    return err(
      new ProviderAdapterError(SYMBOL_PROVIDER_ID, operation, {
        ...outputOptions,
        userMessage: `Symbol tool failed for ${operation}: ${
          failure.stderr.trim().split("\n").at(-1) ||
          `exit code ${String(failure.code)}`
        }`,
      }),
    );
  }
};
