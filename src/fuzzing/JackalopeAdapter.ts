import { dirname } from "node:path";

import type {
  FuzzingEngineAdapter,
  FuzzingLaunchContext,
  FuzzingLaunchPlan,
  FuzzingReproduceContext,
  FuzzingReproducePlan,
} from "./FuzzingEngineAdapter.js";

/** The one non-input file an artifact directory may carry. */
const README = "README.txt";

/** REA's own bookkeeping file inside a campaign artifact directory. */
const ENGINE_LOG = "engine.log";

/**
 * Drive a caller-built Jackalope/TinyInst fuzzer.
 *
 * The build directory supplies the `fuzzer` executable and the
 * `instrumentation` module. The registered target is `-t`, the corpus copy is
 * `-i`, and every crashing input lands in `-o`; `-n` is the iteration budget.
 * Jackalope has no wall-clock flag, so REA enforces the time budget by stopping
 * the owned process.
 */
export class JackalopeAdapter implements FuzzingEngineAdapter {
  readonly engine = "jackalope" as const;
  /** No crash-triage minimizer adapter is documented for this build. */
  readonly minimizerEngine = null;

  isCrashArtifact(name: string): boolean {
    return name !== README && name !== ENGINE_LOG && !name.startsWith(".");
  }

  launch(context: FuzzingLaunchContext): FuzzingLaunchPlan {
    const { configuration, workspace, budget, targetPath } = context;
    return {
      executable: configuration.command,
      arguments: [
        "-i",
        workspace.corpusDirectory,
        "-o",
        workspace.artifactDirectory,
        "-t",
        targetPath,
        ...(budget.maxRuns === null ? [] : ["-n", String(budget.maxRuns)]),
      ],
      artifactDirectory: workspace.artifactDirectory,
      statsSource: { kind: "stdout", path: null },
      writablePaths: [workspace.root],
      readablePaths: [
        dirname(targetPath),
        dirname(configuration.command),
        ...(configuration.supportDirectory === null
          ? []
          : [configuration.supportDirectory]),
      ],
    };
  }

  reproduce(context: FuzzingReproduceContext): FuzzingReproducePlan {
    return {
      executable: context.configuration.command,
      arguments: [
        "-i",
        context.singleInputCorpus,
        "-o",
        context.outputDirectory,
        "-t",
        context.targetPath,
        "-n",
        "1",
      ],
      writablePaths: [context.outputDirectory, context.workspace.root],
      readablePaths: [dirname(context.targetPath), context.workspace.root],
    };
  }
}
