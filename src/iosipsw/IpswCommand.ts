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

/**
 * Run one bounded ipsw command, keeping its exact failure shape.
 *
 * `withholdOutput` drops raw stdout/stderr from every failure path. The
 * `macho info` document can embed entitlement values, so its failures report
 * only an exit code, never the bytes that failed to parse.
 */
export const runIpswCommand = async (
  operation: string,
  executable: string,
  args: readonly string[],
  limits: { readonly timeoutMs: number },
  signal: AbortSignal | undefined,
  options: { readonly withholdOutput?: boolean } = {},
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
    const withheld = options.withholdOutput === true;
    const capturedOutput =
      withheld || failure === undefined
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
        new ProviderAdapterError(IPSW_PROVIDER_ID, operation, {
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
          `ipsw output exceeded the ${String(IPSW_MAX_OUTPUT_BYTES)}-byte capture budget`,
          {
            max_output_bytes: IPSW_MAX_OUTPUT_BYTES,
            ...(withheld ? { output_withheld: true } : {}),
          },
          outputOptions,
        ),
      );
    if (failure.killed)
      return err(
        new AnalysisTimeoutError(operation, limits.timeoutMs, outputOptions),
      );
    return err(
      new ProviderAdapterError(IPSW_PROVIDER_ID, operation, {
        ...outputOptions,
        userMessage: withheld
          ? `ipsw ${args.slice(0, 2).join(" ")} failed for ${operation}: exit code ${
              typeof failure.code === "number"
                ? String(failure.code)
                : "unknown"
            }. Raw output is withheld because this document can embed entitlement values`
          : `ipsw ${args.slice(0, 2).join(" ")} failed for ${operation}: ${
              failure.stderr.trim().split("\n").at(-1) ||
              `exit code ${String(failure.code)}`
            }`,
      }),
    );
  }
};
