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
import type { ProtoRecoveryTool } from "./ProtobufRecoveryConfiguration.js";
import { PROTOBUF_RECOVERY_PROVIDER_ID } from "./ProtobufRecoveryRelease.js";

/** Bounded stdout budget for one recovery or reflection invocation. */
export const PROTOBUF_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

/** The recovery-tool argv shapes this lane assumes. */
export const protoRecoveryArguments = {
  pbtk: (path: string, outputDirectory: string): readonly string[] => [
    "recover",
    "-o",
    outputDirectory,
    path,
  ],
  protodump: (path: string, outputDirectory: string): readonly string[] => [
    "-o",
    outputDirectory,
    path,
  ],
} as const;

/** The grpcurl argv shapes this lane assumes. */
export const grpcReflectionArguments = {
  list: (endpoint: string, plaintext: boolean): readonly string[] => [
    ...(plaintext ? ["-plaintext"] : []),
    endpoint,
    "list",
  ],
  describe: (
    endpoint: string,
    plaintext: boolean,
    service: string,
  ): readonly string[] => [
    ...(plaintext ? ["-plaintext"] : []),
    endpoint,
    "describe",
    service,
  ],
} as const;

export const recoveryArgumentsFor = (
  tool: ProtoRecoveryTool,
  path: string,
  outputDirectory: string,
): readonly string[] =>
  tool === "pbtk"
    ? protoRecoveryArguments.pbtk(path, outputDirectory)
    : protoRecoveryArguments.protodump(path, outputDirectory);

/** Run one bounded protobuf tool, keeping its exact failure shape. */
export const runProtobufCommand = async (
  operation: string,
  executable: string,
  args: readonly string[],
  limits: { readonly timeoutMs: number },
  signal: AbortSignal | undefined,
  tool: "pbtk" | "protodump" | "grpcurl",
): Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  try {
    const { stdout, stderr } = await execFileBytes(executable, args, {
      timeout: limits.timeoutMs,
      maxBuffer: PROTOBUF_MAX_OUTPUT_BYTES,
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
        new ProviderAdapterError(PROTOBUF_RECOVERY_PROVIDER_ID, operation, {
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
          `${tool} output exceeded the ${String(PROTOBUF_MAX_OUTPUT_BYTES)}-byte capture budget`,
          { max_output_bytes: PROTOBUF_MAX_OUTPUT_BYTES },
          outputOptions,
        ),
      );
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, outputOptions),
      );
    return err(
      new ProviderAdapterError(PROTOBUF_RECOVERY_PROVIDER_ID, operation, {
        ...outputOptions,
        userMessage: `${tool} failed for ${operation}: ${
          failure.stderr.trim().split("\n").at(-1) ||
          `exit code ${String(failure.code)}`
        }`,
      }),
    );
  }
};
