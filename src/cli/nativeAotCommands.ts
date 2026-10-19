import { z } from "incur";
import { createNativeAotArtifactService } from "../composition/nativeAot.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";

/** Canonical NativeAOT inspection command name from the shared registry. */
export const NATIVE_AOT_CLI_COMMAND = CLI_COMMANDS.inspectNativeAotTypes;

/** Inspect NativeAOT/ReadyToRun structures through the shared workflow. */
export const registerNativeAotCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(NATIVE_AOT_CLI_COMMAND, {
    description:
      "Inspect NativeAOT/ReadyToRun structural metadata in a PE artifact without target execution",
    args: z.object({
      path: z.string().describe("Local PE image (NativeAOT or ReadyToRun)"),
      offset: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("First recovered row to return"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .optional()
        .describe("Maximum recovered rows to return"),
    }),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createNativeAotArtifactService();
        return await logCliCommand(logger, NATIVE_AOT_CLI_COMMAND, async () =>
          finishAnalysisCommand(
            () =>
              service.inspect(
                {
                  path: absoluteCallerPath(args.path),
                  ...(args.offset === undefined ? {} : { offset: args.offset }),
                  ...(args.limit === undefined ? {} : { limit: args.limit }),
                },
                { signal },
              ),
            service,
            "nativeaot-types",
            "inspect_nativeaot_types",
            signal,
          ),
        );
      }),
  });
};
