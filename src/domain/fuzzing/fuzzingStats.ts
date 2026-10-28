import { z } from "zod";

import {
  FUZZING_MAX_STATS_SAMPLES,
  FUZZING_STATS_INTERVAL_MS,
} from "./fuzzingEngine.js";

/** One observation of the engine's own progress counters. */
export const fuzzingStatsSampleSchema = z.strictObject({
  at_ms: z
    .int()
    .min(0)
    .describe("Milliseconds from campaign start when this sample was read."),
  executions: z
    .int()
    .min(0)
    .nullable()
    .describe(
      "Executions the engine reported, or null when the stream did not.",
    ),
  executions_per_second: z.int().min(0).nullable(),
  edges: z
    .int()
    .min(0)
    .nullable()
    .describe(
      "Coverage counter the engine reported: libFuzzer/Jackalope `cov` or AFL++ edges found.",
    ),
  corpus_entries: z.int().min(0).nullable(),
  observed_crashes: z
    .int()
    .min(0)
    .describe(
      "Crash artifacts REA observed in the engine's artifact directory.",
    ),
});

export type FuzzingStatsSample = z.infer<typeof fuzzingStatsSampleSchema>;

/** Counters one engine line or stats file established. */
export interface FuzzingStatReading {
  readonly executions: number | null;
  readonly executionsPerSecond: number | null;
  readonly edges: number | null;
  readonly corpusEntries: number | null;
}

const escaped = (value: string): string =>
  value.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&");

const fieldOf = (line: string, name: string): number | null => {
  const match = new RegExp(
    `(?:^|\\s)${escaped(name)}\\s*:\\s*(\\d+)`,
    "u",
  ).exec(line);
  return match === null ? null : Number(match[1]);
};

const LIB_FUZZER_LINE =
  /^#(\d+)\s+(?:pulse|NEW|REDUCE|DONE|INITED|RELOAD|TIMEOUT|ERROR)\b/u;

/**
 * Read one libFuzzer console counter line.
 *
 * libFuzzer prints `#<executions>` followed by an action word and its counters
 * (`cov`, `ft`, `corp`, `exec/s`, `rss`). Any other line, including seed-corpus
 * and dictionary notices, is not a counter line.
 */
export const parseLibFuzzerStatLine = (
  line: string,
): FuzzingStatReading | null => {
  const match = LIB_FUZZER_LINE.exec(line);
  if (match === null) return null;
  return {
    executions: Number(match[1]),
    executionsPerSecond: fieldOf(line, "exec/s"),
    edges: fieldOf(line, "cov"),
    corpusEntries: fieldOf(line, "corp"),
  };
};

const JACKALOPE_LINE = /^(?:\[\s*(\d+)(?:\s+sec(?:ond)?s?)?\s*\]|#(\d+))\s+/u;

/**
 * Read one Jackalope console counter line.
 *
 * Jackalope reports its progress with a bracket-elapsed prefix or a
 * `#<iterations>` prefix and the same `key: value` counters. The bracket is
 * elapsed time, so it never becomes an execution count; a line that carries no
 * recognized counter is ignored rather than reported as progress.
 */
export const parseJackalopeStatLine = (
  line: string,
): FuzzingStatReading | null => {
  const match = JACKALOPE_LINE.exec(line);
  if (match === null) return null;
  const reading: FuzzingStatReading = {
    executions:
      fieldOf(line, "iterations") ??
      fieldOf(line, "execs") ??
      (match[2] === undefined ? null : Number(match[2])),
    executionsPerSecond:
      fieldOf(line, "exec/s") ?? fieldOf(line, "execs_per_sec"),
    edges: fieldOf(line, "cov") ?? fieldOf(line, "edges"),
    corpusEntries: fieldOf(line, "corp") ?? fieldOf(line, "corpus"),
  };
  return reading.executions === null &&
    reading.executionsPerSecond === null &&
    reading.edges === null &&
    reading.corpusEntries === null
    ? null
    : reading;
};

const aflCount = (value: string | undefined): number | null => {
  if (value === undefined) return null;
  const parsed = Number(value.trim());
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
};

/** afl-fuzz reports `execs_per_sec` as a decimal rate. */
const aflRate = (value: string | undefined): number | null => {
  if (value === undefined) return null;
  const parsed = Math.floor(Number(value.trim()));
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
};

/**
 * Read AFL++'s `fuzzer_stats` file.
 *
 * afl-fuzz writes `key: value` lines that describe the running instance.
 * `bitmap_cvg` is a percentage, so edges are only reported when the build
 * writes an absolute `edges_found` count.
 */
export const parseAflFuzzerStats = (
  text: string,
): FuzzingStatReading | null => {
  const values = new Map<string, string>();
  for (const line of text.split("\n")) {
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    values.set(line.slice(0, separator).trim(), line.slice(separator + 1));
  }
  const reading: FuzzingStatReading = {
    executions: aflCount(values.get("execs_done")),
    executionsPerSecond: aflRate(values.get("execs_per_sec")),
    edges: aflCount(values.get("edges_found")),
    corpusEntries:
      aflCount(values.get("paths_total")) ??
      aflCount(values.get("corpus_count")),
  };
  return reading.executions === null &&
    reading.executionsPerSecond === null &&
    reading.edges === null &&
    reading.corpusEntries === null
    ? null
    : reading;
};

/**
 * Bounded time series of engine counters.
 *
 * A campaign can run for hours and report every half second, so the series
 * keeps a fixed number of samples. When it is full, every second retained
 * sample survives and the stride doubles, so early progress stays visible and
 * the reported sample interval widens instead of the series growing.
 */
export class FuzzingStatSeries {
  #retained: FuzzingStatsSample[] = [];
  #stride = 1;

  append(sample: FuzzingStatsSample): void {
    if (this.#retained.length >= FUZZING_MAX_STATS_SAMPLES) {
      this.#retained = this.#retained.filter((_, index) => index % 2 === 0);
      this.#stride *= 2;
    }
    this.#retained.push(sample);
  }

  get samples(): readonly FuzzingStatsSample[] {
    return this.#retained;
  }

  /** Milliseconds between retained samples after compaction. */
  get strideMs(): number {
    return this.#stride * FUZZING_STATS_INTERVAL_MS;
  }

  get first(): FuzzingStatsSample | null {
    return this.#retained[0] ?? null;
  }

  get last(): FuzzingStatsSample | null {
    return this.#retained[this.#retained.length - 1] ?? null;
  }

  get peakExecutionsPerSecond(): number | null {
    return this.#retained.reduce<number | null>(
      (peak, sample) =>
        sample.executions_per_second === null
          ? peak
          : peak === null
            ? sample.executions_per_second
            : Math.max(peak, sample.executions_per_second),
      null,
    );
  }
}
