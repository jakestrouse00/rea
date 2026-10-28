import { describe, expect, it } from "vitest";

import {
  CRASH_MINIMIZE_AFLTMIN_EXEC_TIMEOUT_MS,
  crashMinimizationObservationSchema,
  crashMinimizeArguments,
  parseCrashMinimizeOutput,
} from "./crashMinimization.js";

const LIBFUZZER_LOG = `INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3123456789
CRASH_MIN: minimizing crash input: 'crash-9f8e7d6c'
CRASH_MIN: 512 bytes
CRASH_MIN: executing: ./fuzz -minimize_crash=1 crash-9f8e7d6c
#1000  DONE cov: 42 ft: 90 corp: 1/1b lim: 4 exec/s: 500 rss: 24Mb
CRASH_MIN: 128 bytes
#2000  DONE cov: 42 ft: 90 corp: 1/1b lim: 4 exec/s: 520 rss: 24Mb
CRASH_MIN: 24 bytes
stat::number_of_executed_units: 2048
stat::average_exec_per_sec:     512
Done 2048 runs in 4 second(s)
`;

const AFL_TMIN_LOG = `afl-tmin 4.21c by Michal Zalewski
[+] Read 512 bytes from '/tmp/crash-9f8e7d6c'
[+] Setting up the test case, as per the current AFL++ settings
[+] Executing the test case
[+] Minimizing input, stage 1/2
[+] Minimizing input, stage 2/2
[+] Final result: 37 bytes
[+] Execution count: 4211
[+] Stability: 100.00%
[+] The test case appears to be stable
`;

describe("minimizer argv", () => {
  it("builds the libFuzzer minimize invocation", () => {
    const argv = crashMinimizeArguments({
      engine: "libfuzzer",
      inputPath: "/tmp/crash-abc",
      outputPath: "/tmp/minimized",
      maxTotalSeconds: 120,
    });
    expect(argv).toEqual([
      "-minimize_crash=1",
      "-exact_artifact_path=/tmp/minimized",
      "-max_total_time=120",
      "/tmp/crash-abc",
    ]);
  });

  it("builds the afl-tmin invocation over an explicit target", () => {
    const argv = crashMinimizeArguments({
      engine: "afl-tmin",
      inputPath: "/tmp/crash-abc",
      outputPath: "/tmp/minimized",
      targetPath: "/artifacts/fuzz_target",
      maxTotalSeconds: 120,
    });
    expect(argv).toEqual([
      "-i",
      "/tmp/crash-abc",
      "-o",
      "/tmp/minimized",
      "-t",
      String(CRASH_MINIMIZE_AFLTMIN_EXEC_TIMEOUT_MS),
      "--",
      "/artifacts/fuzz_target",
      "@@",
    ]);
  });
});

describe("minimizer counters", () => {
  it("takes the last libFuzzer artifact size it reported", () => {
    expect(parseCrashMinimizeOutput("libfuzzer", LIBFUZZER_LOG)).toEqual({
      reportedBytes: 24,
      executions: 2048,
      stabilityPercent: null,
    });
  });

  it("reads afl-tmin's final size, execution count, and stability", () => {
    expect(parseCrashMinimizeOutput("afl-tmin", AFL_TMIN_LOG)).toEqual({
      reportedBytes: 37,
      executions: 4211,
      stabilityPercent: 100,
    });
  });

  it("leaves an unreported counter null instead of guessing", () => {
    expect(parseCrashMinimizeOutput("libfuzzer", "no counters here")).toEqual({
      reportedBytes: null,
      executions: null,
      stabilityPercent: null,
    });
  });
});

const observation = {
  engine: "afl-tmin" as const,
  exit_type: "exited" as const,
  exit_code: 0,
  duration_ms: 1200,
  timeout_ms: 600000,
  max_total_seconds: 300,
  input: { path: "/tmp/crash", bytes: 512, sha256: "a".repeat(64) },
  output: { path: "/tmp/minimized", bytes: 37, sha256: "b".repeat(64) },
  byte_reduction: 475,
  executions: 4211,
  stability_percent: 100,
  output_truncated: false,
  output_reported_bytes: 37,
};

describe("minimization observation", () => {
  it("accepts an observed artifact reduction", () => {
    expect(crashMinimizationObservationSchema.parse(observation)).toEqual(
      observation,
    );
  });

  it("keeps an unobserved output and an unknown digest representable", () => {
    const parsed = crashMinimizationObservationSchema.parse({
      ...observation,
      exit_type: "timeout",
      exit_code: null,
      output: null,
      byte_reduction: null,
      input: { ...observation.input, sha256: null },
      stability_percent: null,
    });
    expect(parsed.output).toBeNull();
    expect(parsed.input.sha256).toBeNull();
  });

  it("rejects an out-of-range stability and an unknown engine", () => {
    expect(
      crashMinimizationObservationSchema.safeParse({
        ...observation,
        stability_percent: 101,
      }).success,
    ).toBe(false);
    expect(
      crashMinimizationObservationSchema.safeParse({
        ...observation,
        engine: "honggfuzz",
      }).success,
    ).toBe(false);
  });
});
