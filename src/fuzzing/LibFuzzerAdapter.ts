import { dirname } from "node:path";

import type {
  FuzzingEngineAdapter,
  FuzzingLaunchContext,
  FuzzingLaunchPlan,
  FuzzingReproduceContext,
  FuzzingReproducePlan,
} from "./FuzzingEngineAdapter.js";

/** libFuzzer artifact names: a crashing, leaking, hanging, or slow input. */
const ARTIFACT = /^(?:crash|leak|oom|timeout|slow-unit)-/u;

/**
 * Drive a caller-supplied libFuzzer-instrumented target.
 *
 * The campaign's corpus copy is the only positional argument, so libFuzzer
 * mutates it in place; `-artifact_prefix` keeps every crashing input inside the
 * campaign root, and the declared budget becomes `-runs`/`-max_total_time`.
 */
export class LibFuzzerAdapter implements FuzzingEngineAdapter {
  readonly engine = "libfuzzer" as const;
  readonly minimizerEngine = "libfuzzer" as const;

  isCrashArtifact(name: string): boolean {
    return ARTIFACT.test(name);
  }

  launch(context: FuzzingLaunchContext): FuzzingLaunchPlan {
    const { configuration, workspace, budget, targetPath } = context;
    return {
      executable: configuration.command,
      arguments: [
        workspace.corpusDirectory,
        `-artifact_prefix=${workspace.artifactDirectory}/`,
        "-print_final_stats=1",
        ...(budget.maxRuns === null ? [] : [`-runs=${String(budget.maxRuns)}`]),
        ...(budget.maxSeconds === null
          ? []
          : [`-max_total_time=${String(budget.maxSeconds)}`]),
      ],
      artifactDirectory: workspace.artifactDirectory,
      statsSource: { kind: "stdout", path: null },
      writablePaths: [workspace.root],
      readablePaths: [dirname(targetPath), workspace.root],
    };
  }

  reproduce(context: FuzzingReproduceContext): FuzzingReproducePlan {
    return {
      executable: context.configuration.command,
      arguments: [context.inputPath],
      writablePaths: [context.workspace.root],
      readablePaths: [context.workspace.root],
    };
  }
}
