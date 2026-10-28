import { z } from "zod";

import { digestSchema } from "../digests.js";

/** Engines whose crash minimizers REA can drive through one subprocess each. */
export const CRASH_MINIMIZE_ENGINES = ["libfuzzer", "afl-tmin"] as const;

export const crashMinimizeEngineSchema = z.enum(CRASH_MINIMIZE_ENGINES);
export type CrashMinimizeEngine = z.infer<typeof crashMinimizeEngineSchema>;

/**
 * Caller-supplied libFuzzer-instrumented target used with `-minimize_crash=1`.
 * The minimizer is the fuzz target itself, not a separate utility.
 */
export const CRASH_MINIMIZE_LFZ_COMMAND_ENV = "REA_LFZ_MINIMIZE_COMMAND";

/** Caller-supplied `afl-tmin` binary. */
export const CRASH_MINIMIZE_AFLTMIN_COMMAND_ENV = "REA_AFLTMIN_COMMAND";

export const CRASH_MINIMIZE_LFZ_REMEDIATION = `Set ${CRASH_MINIMIZE_LFZ_COMMAND_ENV} to the absolute path of a libFuzzer-instrumented target binary that accepts -minimize_crash=1. REA does not build, download, or install fuzz targets.`;

export const CRASH_MINIMIZE_AFLTMIN_REMEDIATION = `Set ${CRASH_MINIMIZE_AFLTMIN_COMMAND_ENV} to the absolute path of a caller-supplied afl-tmin binary. REA does not install or upgrade AFL++ tooling.`;

/** Wall clock for one minimizer run when the caller omits `timeout_ms`. */
export const CRASH_MINIMIZE_DEFAULT_TIMEOUT_MS = 600_000;

/** Largest delay Node honors as a timer rather than clamping to 1 ms. */
export const CRASH_MINIMIZE_MAX_TIMEOUT_MS = 2_147_483_647;

/** libFuzzer's own `-max_total_time` default for minimization. */
export const CRASH_MINIMIZE_DEFAULT_MAX_TOTAL_SECONDS = 300;

/** Longest minimizer search window a caller may request (four hours). */
export const CRASH_MINIMIZE_MAX_TOTAL_SECONDS = 14_400;

/** Per-execution timeout passed to `afl-tmin -t`, in milliseconds. */
export const CRASH_MINIMIZE_AFLTMIN_EXEC_TIMEOUT_MS = 5_000;

/** Retained stdout, and separately stderr, from one minimizer run. */
export const CRASH_MINIMIZE_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/** Retained byte tail for one failure diagnostic from a minimizer. */
export const CRASH_MINIMIZE_DIAGNOSTIC_EXCERPT_BYTES = 512;

/** Input file the minimizer reads, and the caller-owned output path. */
export interface CrashMinimizeInvocation {
  readonly engine: CrashMinimizeEngine;
  readonly inputPath: string;
  readonly outputPath: string;
  /** libFuzzer's search budget; ignored by `afl-tmin`, which uses `timeoutMs`. */
  readonly maxTotalSeconds: number;
  /** libFuzzer target for `afl-tmin`; the seed is always `@@`. */
  readonly targetPath?: string;
}

/**
 * Build the minimizer argv for one crash input.
 *
 * Both engines read one input file and write one minimized artifact, so REA
 * can compare the observed sizes without interpreting either engine's
 * progress log. `afl-tmin` runs the caller-declared target with `@@` replaced
 * by the current test case; libFuzzer minimizes inside the target binary
 * itself, which is why that engine needs no separate target path.
 */
export const crashMinimizeArguments = (
  invocation: CrashMinimizeInvocation,
): readonly string[] => {
  switch (invocation.engine) {
    case "libfuzzer":
      return [
        "-minimize_crash=1",
        `-exact_artifact_path=${invocation.outputPath}`,
        `-max_total_time=${String(invocation.maxTotalSeconds)}`,
        invocation.inputPath,
      ];
    case "afl-tmin":
      return [
        "-i",
        invocation.inputPath,
        "-o",
        invocation.outputPath,
        "-t",
        String(CRASH_MINIMIZE_AFLTMIN_EXEC_TIMEOUT_MS),
        "--",
        invocation.targetPath ?? invocation.inputPath,
        "@@",
      ];
  }
};

/** Counters a minimizer reported about its own search. */
export interface CrashMinimizeCounters {
  /** Final artifact size the engine reported, when it reported one. */
  readonly reportedBytes: number | null;
  readonly executions: number | null;
  readonly stabilityPercent: number | null;
}

const lastMatch = (text: string, pattern: RegExp): RegExpExecArray | null => {
  let found: RegExpExecArray | null = null;
  const global = new RegExp(pattern.source, `${pattern.flags}g`);
  for (const match of text.matchAll(global)) found = match as RegExpExecArray;
  return found;
};

/**
 * Read the minimizer's own counters from its stdout.
 *
 * Both engines print free-form progress; only the final size and the execution
 * count are stable across releases, and a missing counter stays null rather
 * than being guessed from the retained size.
 */
export const parseCrashMinimizeOutput = (
  engine: CrashMinimizeEngine,
  stdout: string,
): CrashMinimizeCounters => {
  switch (engine) {
    case "libfuzzer": {
      const bytes = lastMatch(stdout, /CRASH_MIN:\s*(\d+)\s*bytes/u);
      const executions = lastMatch(
        stdout,
        /stat::number_of_executed_units:\s*(\d+)/u,
      );
      return {
        reportedBytes:
          bytes === null ? null : Number.parseInt(bytes[1] ?? "0", 10),
        executions:
          executions === null
            ? null
            : Number.parseInt(executions[1] ?? "0", 10),
        stabilityPercent: null,
      };
    }
    case "afl-tmin": {
      const bytes = lastMatch(
        stdout,
        /\[\+\]\s*Final result:\s*(\d+)\s*bytes/u,
      );
      const executions = lastMatch(stdout, /Execution count:\s*(\d+)/u);
      const stability = lastMatch(stdout, /Stability:\s*([\d.]+)%/u);
      return {
        reportedBytes:
          bytes === null ? null : Number.parseInt(bytes[1] ?? "0", 10),
        executions:
          executions === null
            ? null
            : Number.parseInt(executions[1] ?? "0", 10),
        stabilityPercent:
          stability === null ? null : Number.parseFloat(stability[1] ?? "0"),
      };
    }
  }
};

/** How one minimizer call ended. */
export const crashMinimizeExitTypeSchema = z.enum([
  "exited",
  "signalled",
  "timeout",
  "cancelled",
  "output_truncated",
  "not_started",
]);

export type CrashMinimizeExitType = z.infer<typeof crashMinimizeExitTypeSchema>;

/** Observed artifact identity, either the input or the written output. */
export const minimizeArtifactSchema = z.strictObject({
  path: z.string().min(1),
  bytes: z.int().min(0),
  sha256: digestSchema.nullable(),
});

/**
 * Structural result of one minimization attempt.
 *
 * The minimized artifact is the caller's file: REA reports its observed size
 * and digest and never publishes its bytes or the engine's progress log.
 */
export const crashMinimizationObservationSchema = z.strictObject({
  engine: crashMinimizeEngineSchema,
  exit_type: crashMinimizeExitTypeSchema,
  exit_code: z.int().nullable(),
  duration_ms: z.int().min(0),
  timeout_ms: z.int().min(1),
  max_total_seconds: z.int().min(1),
  input: minimizeArtifactSchema,
  output: minimizeArtifactSchema.nullable(),
  byte_reduction: z
    .int()
    .nullable()
    .describe(
      "Input bytes minus output bytes, only when both sizes were observed and the output exists.",
    ),
  executions: z.int().min(0).nullable(),
  stability_percent: z.number().min(0).max(100).nullable(),
  output_truncated: z
    .boolean()
    .describe("The retained-output budget stopped the minimizer."),
  output_reported_bytes: z
    .int()
    .min(0)
    .nullable()
    .describe(
      "Final size the engine reported for itself, which can differ from the observed file.",
    ),
});

export type CrashMinimizationObservation = z.infer<
  typeof crashMinimizationObservationSchema
>;
