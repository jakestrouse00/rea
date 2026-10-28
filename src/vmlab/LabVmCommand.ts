import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisResourceConstraintError,
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
  list: (): readonly string[] => ["list", "--json"],
} as const;

/** One limactl observation before output is reduced to structural facts. */
export interface LabVmCommandObservation {
  readonly exitType: Exclude<LabVmExitType, "cancelled" | "not_started">;
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly outputTruncated: boolean;
  readonly durationMs: number;
}

type TerminalFailure = NonNullable<ReturnType<typeof execFileOutputFailure>>;

const classify = (
  failure: TerminalFailure,
): {
  readonly exitType: LabVmCommandObservation["exitType"];
  readonly exitCode: number | null;
} => {
  const exitCode = typeof failure.code === "number" ? failure.code : null;
  // Exceeding the retained-output budget stops the process, so `killed` alone
  // does not distinguish that outcome from a deadline or a signal.
  if (failure.outputTruncated)
    return { exitType: "output_truncated", exitCode };
  if (typeof failure.code === "number")
    return {
      exitType: failure.killed ? "timeout" : "exited",
      exitCode,
    };
  return failure.killed
    ? { exitType: "timeout", exitCode }
    : { exitType: "signalled", exitCode };
};

/** Spawn errors describe a missing or unusable executable, not a run. */
const SPAWN_FAILURE_CODES = new Set([
  "ENOENT",
  "EACCES",
  "EPERM",
  "ENOTDIR",
  "ENOEXEC",
]);

/** A spawn error code on the rejection means no process ever existed. */
const spawnFailureCode = (cause: unknown): string | undefined => {
  if (!(cause instanceof Error) || !("code" in cause)) return undefined;
  const code = cause.code;
  return typeof code === "string" && SPAWN_FAILURE_CODES.has(code)
    ? code
    : undefined;
};

const spawnFailure = (
  operation: string,
  executable: string,
  code: string,
  cause: unknown,
): AnalysisError =>
  new AnalysisCapabilityUnavailableError(
    LAB_VM_PROVIDER.id,
    operation,
    `The selected limactl binary could not be started (${code}): ${executable}`,
    {
      cause,
      diagnostics: {
        boundary: "provider-launch",
        selected_binary: executable,
        system_code: code,
      },
    },
  );

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
    const spawnCode = spawnFailureCode(cause);
    if (spawnCode !== undefined)
      return err(spawnFailure(operation, executable, spawnCode, cause));
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
    const exitCode = typeof failure.code === "number" ? failure.code : null;
    const excerpt = labVmDiagnosticExcerpt(failure.stderr);
    const observed = classify(failure);
    if (observed.exitType === "output_truncated")
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `limactl output exceeded the ${String(limits.maxOutputBytes)}-byte retained budget during ${operation}`,
          {
            max_output_bytes: limits.maxOutputBytes,
            stdout_bytes: failure.stdoutBytes ?? failure.stdout.length,
            stderr_bytes: failure.stderrBytes ?? failure.stderr.length,
          },
          {
            cause,
            capturedOutput,
            retryable: true,
            remediationAction:
              "Rerun the command with quieter output; the retained-output budget has no runtime override.",
            ...(excerpt === ""
              ? {}
              : { diagnostics: { stderr_excerpt: excerpt } }),
          },
        ),
      );
    if (observed.exitType === "timeout")
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, {
          cause,
          capturedOutput,
          diagnostics: {
            timeout_ms: limits.timeoutMs,
            ...(excerpt === "" ? {} : { stderr_excerpt: excerpt }),
          },
        }),
      );
    if (observed.exitType === "signalled")
      return err(
        new ProviderAdapterError(LAB_VM_PROVIDER.id, operation, {
          cause,
          capturedOutput,
          userMessage: `limactl ended on ${failure.signal ?? "a signal"} during ${operation}${
            excerpt === "" ? "" : `: ${excerpt}`
          }`,
        }),
      );
    return err(
      new ProviderAdapterError(LAB_VM_PROVIDER.id, operation, {
        cause,
        capturedOutput,
        userMessage: `limactl exited with status ${String(failure.code)} during ${operation}${
          excerpt === "" ? "" : `: ${excerpt}`
        }`,
      }),
    );
  }
};
