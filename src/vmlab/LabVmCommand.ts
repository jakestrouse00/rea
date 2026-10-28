import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import type { LabVmExitType } from "../domain/vmlab/labVm.js";
import {
  LAB_VM_DIAGNOSTIC_EXCERPT_BYTES,
  LAB_VM_PROVIDER,
} from "../domain/vmlab/labVm.js";
import {
  ExecFileOutputCancelledError,
  execFileBytes,
  execFileFailureCapturedOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";

/** The limactl argv shapes this lane assumes. */
export const labVmArguments = {
  start: (vmName: string, templatePath: string): readonly string[] => [
    "start",
    "--tty=false",
    "--name",
    vmName,
    templatePath,
  ],
  shell: (
    vmName: string,
    guestWorkdir: string,
    command: string,
  ): readonly string[] => [
    "shell",
    "--workdir",
    guestWorkdir,
    vmName,
    "--",
    "/bin/sh",
    "-lc",
    command,
  ],
  stop: (vmName: string): readonly string[] => ["stop", vmName],
  delete: (vmName: string): readonly string[] => ["delete", "--force", vmName],
} as const;

/** One limactl observation before output is reduced to structural facts. */
export interface LabVmCommandObservation {
  readonly exitType: Exclude<LabVmExitType, "cancelled">;
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly outputTruncated: boolean;
  readonly durationMs: number;
}

const classify = (
  failure: NonNullable<ReturnType<typeof execFileOutputFailure>>,
): {
  readonly exitType: "exited" | "signalled" | "timeout";
  readonly exitCode: number | null;
} =>
  typeof failure.code === "number"
    ? {
        exitType: failure.killed ? "timeout" : "exited",
        exitCode: failure.code,
      }
    : failure.killed
      ? { exitType: "timeout", exitCode: null }
      : { exitType: "signalled", exitCode: null };

/** Retain a bounded diagnostic tail without publishing the command's output. */
const labVmDiagnosticExcerpt = (
  text: string,
  limit = LAB_VM_DIAGNOSTIC_EXCERPT_BYTES,
): string => {
  const trimmed = text.trim();
  return trimmed.length <= limit ? trimmed : `…${trimmed.slice(-limit)}`;
};

export const runLabVmCommand = async (
  operation: string,
  executable: string,
  args: readonly string[],
  limits: { readonly timeoutMs: number; readonly maxOutputBytes: number },
  signal: AbortSignal | undefined,
): Promise<Result<LabVmCommandObservation, AnalysisError>> => {
  if (signal?.aborted === true)
    return err(new AnalysisCancelledError(operation, { cause: signal.reason }));
  const startedAt = Date.now();
  try {
    const { stdout, stderr } = await execFileBytes(executable, args, {
      timeout: limits.timeoutMs,
      maxBuffer: limits.maxOutputBytes,
      stopSignal: "SIGTERM",
      ...(signal === undefined ? {} : { signal }),
    });
    return ok({
      exitType: "exited",
      exitCode: 0,
      stdout: stdout.toString("utf8"),
      stderr: stderr.toString("utf8"),
      stdoutBytes: stdout.byteLength,
      stderrBytes: stderr.byteLength,
      outputTruncated: false,
      durationMs: Date.now() - startedAt,
    });
  } catch (cause) {
    if (cause instanceof ExecFileOutputCancelledError)
      return err(new AnalysisCancelledError(operation, { cause: cause.cause }));
    const failure = execFileOutputFailure(cause);
    if (failure === undefined)
      return err(
        new ProviderAdapterError(LAB_VM_PROVIDER.id, operation, {
          cause,
          userMessage: `Cannot run ${executable} for ${operation}: ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
        }),
      );
    const capturedOutput = execFileFailureCapturedOutput(failure);
    const observed: LabVmCommandObservation = {
      ...classify(failure),
      stdout: failure.stdout,
      stderr: failure.stderr,
      stdoutBytes: failure.stdoutBytes ?? failure.stdout.length,
      stderrBytes: failure.stderrBytes ?? failure.stderr.length,
      outputTruncated: failure.outputTruncated,
      durationMs: Date.now() - startedAt,
    };
    if (observed.exitType === "timeout")
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, {
          cause,
          capturedOutput,
          diagnostics: {
            timeout_ms: limits.timeoutMs,
            stderr_excerpt: labVmDiagnosticExcerpt(failure.stderr),
          },
        }),
      );
    if (observed.exitType === "signalled")
      return err(
        new ProviderAdapterError(LAB_VM_PROVIDER.id, operation, {
          cause,
          capturedOutput,
          userMessage: `limactl ended on ${failure.signal ?? "a signal"} during ${operation}${
            failure.stderr.trim() === ""
              ? ""
              : `: ${labVmDiagnosticExcerpt(failure.stderr)}`
          }`,
        }),
      );
    return err(
      new ProviderAdapterError(LAB_VM_PROVIDER.id, operation, {
        cause,
        capturedOutput,
        userMessage: `limactl exited with status ${String(failure.code)} during ${operation}${
          failure.stderr.trim() === ""
            ? ""
            : `: ${labVmDiagnosticExcerpt(failure.stderr)}`
        }`,
        ...(failure.outputTruncated
          ? {
              diagnostics: {
                max_output_bytes: limits.maxOutputBytes,
                output_truncated: true,
              },
            }
          : {}),
      }),
    );
  }
};
