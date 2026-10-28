import type { CrashMinimizeEngine } from "../domain/crashTriage/crashMinimization.js";
import type { FuzzingEngine } from "../domain/fuzzing/fuzzingEngine.js";
import type { FuzzingEngineConfiguration } from "./FuzzingEngineConfiguration.js";

/** Directories one campaign owns inside its private runtime root. */
export interface FuzzingCampaignWorkspace {
  readonly root: string;
  readonly corpusDirectory: string;
  readonly artifactDirectory: string;
  readonly outputDirectory: string;
}

/** Stop conditions the adapter reflects in its own argv where it can. */
export interface FuzzingLaunchBudget {
  readonly maxRuns: number | null;
  readonly maxSeconds: number | null;
}

/** Everything an engine needs to start one campaign run. */
export interface FuzzingLaunchContext {
  readonly targetPath: string;
  readonly configuration: FuzzingEngineConfiguration;
  readonly workspace: FuzzingCampaignWorkspace;
  readonly budget: FuzzingLaunchBudget;
}

/** Everything an engine needs to reproduce one candidate crash. */
export interface FuzzingReproduceContext {
  readonly targetPath: string;
  readonly configuration: FuzzingEngineConfiguration;
  readonly inputPath: string;
  readonly workspace: FuzzingCampaignWorkspace;
  /** Corpus directory holding exactly the reproduction input. */
  readonly singleInputCorpus: string;
  /** Directory the reproduction may write into. */
  readonly outputDirectory: string;
}

/** Where the adapter's progress counters can be read. */
export interface FuzzingStatsSource {
  readonly kind: "stdout" | "file";
  /** Absolute stats file for the `file` kind, else null. */
  readonly path: string | null;
}

/** One engine command line, plus the paths a sandbox must admit. */
export interface FuzzingLaunchPlan {
  readonly executable: string;
  readonly arguments: readonly string[];
  readonly artifactDirectory: string;
  readonly statsSource: FuzzingStatsSource;
  readonly writablePaths: readonly string[];
  readonly readablePaths: readonly string[];
}

export type FuzzingReproducePlan = Pick<
  FuzzingLaunchPlan,
  "executable" | "arguments" | "writablePaths" | "readablePaths"
>;

/**
 * One fuzzing engine behind the campaign contract.
 *
 * Every adapter answers the same four questions: which file in the artifact
 * directory is a crash candidate, what argv starts a campaign, what argv
 * reproduces one input, and which crash-triage minimizer (if any) can minimize
 * an accepted crash. Stats stay a separate owner: the adapter declares where
 * its counters live and the domain parsers read them.
 */
export interface FuzzingEngineAdapter {
  readonly engine: FuzzingEngine;
  /** Minimizer engine for accepted crashes, or null when unsupported. */
  readonly minimizerEngine: CrashMinimizeEngine | null;
  isCrashArtifact(name: string): boolean;
  launch(context: FuzzingLaunchContext): FuzzingLaunchPlan;
  reproduce(context: FuzzingReproduceContext): FuzzingReproducePlan;
}
