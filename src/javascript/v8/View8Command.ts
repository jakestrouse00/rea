import { createHash } from "node:crypto";
import type {
  AnalysisCapturedOutput,
  AnalysisError,
} from "../../domain/analysisErrorBase.js";
import type { ExecFileOutputFailure } from "../../process/ExecFileOutput.js";
import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  ExecFileOutputCancelledError,
  execFileBytes,
  execFileFailureCapturedOutput,
  execFileOutputFailure,
} from "../../process/ExecFileOutput.js";
import { VIEW8_MAX_OUTPUT_BYTES, VIEW8_PROVIDER_ID } from "./View8Release.js";

/** The View8 argv shape this lane assumes: one cached-data path, disassembly on stdout. */
export const view8Arguments = (path: string): readonly string[] => [path];

/** Bounded disassembly observation; the text itself never leaves this command. */
export interface View8DisassemblyRun {
  readonly stdoutBytes: number;
  readonly stdoutSha256: string;
  readonly lines: number;
}

/**
 * Keep stderr and exit facts for diagnosis while withholding the launcher's
 * stdout, which is the disassembly this lane never republishes.
 */
const view8CapturedOutput = (
  failure: ExecFileOutputFailure,
): AnalysisCapturedOutput => {
  const captured = execFileFailureCapturedOutput(failure);
  return {
    ...captured,
    stdout: "<view8 disassembly withheld>",
    ...(captured.stdout_bytes === undefined
      ? {}
      : { stdout_bytes: captured.stdout_bytes }),
  };
};

/** Run one bounded View8 command and keep its exact failure shape. */
export const runView8Command = async (
  operation: string,
  executable: string,
  args: readonly string[],
  limits: { readonly timeoutMs: number },
  signal: AbortSignal | undefined,
): Promise<Result<View8DisassemblyRun, AnalysisError>> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  const digest = createHash("sha256");
  let lines = 0;
  let lastByte = 0x0a;
  try {
    const { stdout } = await execFileBytes(executable, args, {
      timeout: limits.timeoutMs,
      maxBuffer: VIEW8_MAX_OUTPUT_BYTES,
      stopSignal: "SIGTERM",
      ...(signal === undefined ? {} : { signal }),
    });
    digest.update(stdout);
    for (const byte of stdout) {
      if (byte === 0x0a) lines += 1;
      lastByte = byte;
    }
    return ok({
      stdoutBytes: stdout.byteLength,
      stdoutSha256: digest.digest("hex"),
      lines: lines + (stdout.byteLength > 0 && lastByte !== 0x0a ? 1 : 0),
    });
  } catch (cause) {
    const failure = execFileOutputFailure(cause);
    const capturedOutput =
      failure === undefined ? undefined : view8CapturedOutput(failure);
    if (cause instanceof ExecFileOutputCancelledError)
      return err(
        new AnalysisCancelledError(operation, {
          cause: cause.cause,
          ...(capturedOutput === undefined ? {} : { capturedOutput }),
        }),
      );
    if (failure === undefined)
      return err(
        new ProviderAdapterError(VIEW8_PROVIDER_ID, operation, {
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
          `View8 disassembly exceeded the ${String(VIEW8_MAX_OUTPUT_BYTES)}-byte capture budget`,
          { max_output_bytes: VIEW8_MAX_OUTPUT_BYTES },
          outputOptions,
        ),
      );
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, outputOptions),
      );
    return err(
      new ProviderAdapterError(VIEW8_PROVIDER_ID, operation, {
        ...outputOptions,
        userMessage: `View8 failed for ${operation}: ${
          failure.stderr.trim().split("\n").at(-1) ||
          `exit code ${String(failure.code)}`
        }`,
      }),
    );
  }
};
