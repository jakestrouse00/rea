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
  execFileOutputFailure,
  type ExecFileOutputFailure,
} from "../process/ExecFileOutput.js";
import { IPSW_PROVIDER_ID } from "./IpswRelease.js";

/** Bounded stdout budget for one ipsw command. */
export const IPSW_MAX_OUTPUT_BYTES = 32 * 1024 * 1024;

/**
 * The upstream CLI shapes this lane assumes. No verified ipsw release is
 * pinned, so the table stays explicit and documented as unverified in
 * docs/ipsw-analysis.md.
 */
export const ipswArguments = {
  inspect_ipsw: (path: string): readonly string[] => ["info", path, "--json"],
  dyld_info: (cache: string): readonly string[] => [
    "dyld",
    "info",
    cache,
    "--json",
  ],
  dyld_extract: (
    cache: string,
    destination: string,
    images: readonly string[],
  ): readonly string[] => [
    "dyld",
    "extract",
    cache,
    destination,
    ...images,
    "--json",
  ],
  dump_ios_class_metadata: (
    path: string,
    family: "objc" | "swift",
  ): readonly string[] =>
    family === "objc"
      ? ["macho", "class-dump", path, "--json"]
      : ["swift", "dump", path, "--json"],
  symbolicate_ios_crash: (crash: string, cache: string): readonly string[] => [
    "symbolicate",
    crash,
    "--dsc",
    cache,
    "--json",
  ],
  inspect_macho_entitlements: (path: string): readonly string[] => [
    "macho",
    "info",
    path,
    "--json",
    "--entitlements",
  ],
} as const;

/** Run one bounded ipsw command, keeping its exact failure shape. */
export const runIpswCommand = async (
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
      maxBuffer: IPSW_MAX_OUTPUT_BYTES,
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
            : { capturedOutput: ipswCapturedOutput(failure) }),
        }),
      );
    if (failure === undefined)
      return err(
        new ProviderAdapterError(IPSW_PROVIDER_ID, operation, {
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
          `ipsw output exceeded the ${String(IPSW_MAX_OUTPUT_BYTES)}-byte capture budget`,
          { max_output_bytes: IPSW_MAX_OUTPUT_BYTES },
          { cause },
        ),
      );
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, { cause }),
      );
    return err(
      new ProviderAdapterError(IPSW_PROVIDER_ID, operation, {
        cause,
        capturedOutput: ipswCapturedOutput(failure),
        userMessage: `ipsw ${args.slice(0, 2).join(" ")} failed for ${operation}: ${
          failure.stderr.trim().split("\n").at(-1) ||
          `exit code ${String(failure.code)}`
        }`,
      }),
    );
  }
};

const ipswCapturedOutput = (failure: ExecFileOutputFailure) => ({
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
