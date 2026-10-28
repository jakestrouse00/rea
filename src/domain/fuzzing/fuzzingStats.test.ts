import { describe, expect, it } from "vitest";

import { FUZZING_MAX_STATS_SAMPLES } from "./fuzzingEngine.js";
import {
  FuzzingStatSeries,
  parseAflFuzzerStats,
  parseJackalopeStatLine,
  parseLibFuzzerStatLine,
} from "./fuzzingStats.js";

const sample = (executions: number) => ({
  at_ms: executions,
  executions,
  executions_per_second: 10,
  edges: 3,
  corpus_entries: 1,
  observed_crashes: 0,
});

describe("libFuzzer stat lines", () => {
  it("reads executions and counters from a pulse line", () => {
    expect(
      parseLibFuzzerStatLine(
        "#1234\tpulse  cov: 45 ft: 12 corp: 30/300b lim: 4096 exec/s: 1000 rss: 20Mb",
      ),
    ).toEqual({
      executions: 1234,
      executionsPerSecond: 1000,
      edges: 45,
      corpusEntries: 30,
    });
  });

  it("reads the action-word lines libFuzzer interleaves with pulses", () => {
    expect(
      parseLibFuzzerStatLine(
        "#7\tNEW    cov: 9 ft: 9 corp: 2/20b exec/s: 7 rss: 12Mb",
      ),
    ).toMatchObject({ executions: 7, edges: 9, corpusEntries: 2 });
    expect(
      parseLibFuzzerStatLine("#99\tDONE   cov: 90 ft: 40 corp: 12/120b"),
    ).toMatchObject({ executions: 99, edges: 90, executionsPerSecond: null });
  });

  it("ignores lines that carry no execution counter", () => {
    expect(
      parseLibFuzzerStatLine(
        "INFO: seed corpus: files: 3 min: 1b max: 4b total: 8b rss: 20Mb",
      ),
    ).toBeNull();
    expect(parseLibFuzzerStatLine("")).toBeNull();
    expect(parseLibFuzzerStatLine("#4 not-a-word cov: 1")).toBeNull();
  });
});

describe("Jackalope stat lines", () => {
  it("reads the elapsed-bracket and iteration-counter prefixes", () => {
    expect(
      parseJackalopeStatLine("[ 12 sec ] exec/s: 500 cov: 21 corpus: 4"),
    ).toEqual({
      executions: null,
      executionsPerSecond: 500,
      edges: 21,
      corpusEntries: 4,
    });
    expect(
      parseJackalopeStatLine("#88 iterations: 88 exec/s: 40 cov: 12"),
    ).toMatchObject({ executions: 88, edges: 12 });
  });

  it("refuses a bracketed line that names no counter", () => {
    expect(parseJackalopeStatLine("[ 1 sec ] starting")).toBeNull();
    expect(parseJackalopeStatLine("fuzzer ready")).toBeNull();
  });
});

describe("AFL++ fuzzer_stats", () => {
  it("reads the counters afl-fuzz writes", () => {
    expect(
      parseAflFuzzerStats(
        [
          "start_time        : 1700000000",
          "execs_done        : 4321",
          "execs_per_sec     : 210.55",
          "paths_total       : 17",
          "bitmap_cvg        : 12.5%",
          "edges_found       : 640",
          "unique_crashes    : 1",
        ].join("\n"),
      ),
    ).toEqual({
      executions: 4321,
      executionsPerSecond: 210,
      edges: 640,
      corpusEntries: 17,
    });
  });

  it("leaves an unreported counter null instead of guessing", () => {
    expect(parseAflFuzzerStats("paths_total : 4\nbitmap_cvg : 3%\n")).toEqual({
      executions: null,
      executionsPerSecond: null,
      edges: null,
      corpusEntries: 4,
    });
    expect(parseAflFuzzerStats("not a stats file")).toBeNull();
    expect(parseAflFuzzerStats("")).toBeNull();
  });
});

describe("bounded stat series", () => {
  it("keeps one sample until the budget is full", () => {
    const series = new FuzzingStatSeries();
    series.append(sample(1));
    expect(series.samples).toHaveLength(1);
    expect(series.strideMs).toBe(500);
    expect(series.first).toEqual(sample(1));
    expect(series.last).toEqual(sample(1));
    expect(series.peakExecutionsPerSecond).toBe(10);
  });

  it("compacts to half and doubles the stride instead of growing", () => {
    const series = new FuzzingStatSeries();
    for (let index = 0; index < FUZZING_MAX_STATS_SAMPLES; index += 1)
      series.append(sample(index));
    series.append(sample(FUZZING_MAX_STATS_SAMPLES));
    expect(series.samples).toHaveLength(FUZZING_MAX_STATS_SAMPLES / 2 + 1);
    expect(series.strideMs).toBe(1_000);
    expect(series.first?.executions).toBe(0);
    expect(series.last?.executions).toBe(FUZZING_MAX_STATS_SAMPLES);
  });
});
