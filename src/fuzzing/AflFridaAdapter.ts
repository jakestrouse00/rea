import { dirname, join } from "node:path";

import type {
  FuzzingEngineAdapter,
  FuzzingLaunchContext,
  FuzzingLaunchPlan,
  FuzzingReproduceContext,
  FuzzingReproducePlan,
} from "./FuzzingEngineAdapter.js";

/** AFL++ names every crashing input `id:<seq>,sig:<n>,src:<seq>,time:<n>`. */
const ARTIFACT = /^id:\d+/u;

/** The one non-input file afl-fuzz leaves in its crashes directory. */
const README = "README.txt";

/**
 * Drive afl-fuzz in FRIDA mode (`-O`) on a macOS arm64 host.
 *
 * The corpus copy is `-i`, the campaign root is `-o`, and the registered
 * target receives the input path through `@@`. afl-fuzz maintains
 * `<output>/default/fuzzer_stats`, so the adapter reads counters from that
 * file rather than parsing the console.
 */
export class AflFridaAdapter implements FuzzingEngineAdapter {
  readonly engine = "aflpp_frida" as const;
  /** afl-tmin reads the same instrumented target. */
  readonly minimizerEngine = "afl-tmin" as const;

  isCrashArtifact(name: string): boolean {
    return name !== README && ARTIFACT.test(name);
  }

  statisticsPath(outputDirectory: string): string {
    return join(outputDirectory, "default", "fuzzer_stats");
  }

  launch(context: FuzzingLaunchContext): FuzzingLaunchPlan {
    const { configuration, workspace, budget, targetPath } = context;
    return {
      executable: configuration.command,
      arguments: [
        "-O",
        "-i",
        workspace.corpusDirectory,
        "-o",
        workspace.outputDirectory,
        ...(budget.maxSeconds === null
          ? []
          : ["-V", String(budget.maxSeconds)]),
        "--",
        targetPath,
        "@@",
      ],
      artifactDirectory: join(workspace.outputDirectory, "default", "crashes"),
      statsSource: {
        kind: "file",
        path: this.statisticsPath(workspace.outputDirectory),
      },
      writablePaths: [workspace.root],
      readablePaths: [dirname(targetPath), dirname(configuration.command)],
    };
  }

  reproduce(context: FuzzingReproduceContext): FuzzingReproducePlan {
    return {
      executable: context.targetPath,
      arguments: [context.inputPath],
      writablePaths: [context.outputDirectory],
      readablePaths: [dirname(context.targetPath), context.outputDirectory],
    };
  }
}
