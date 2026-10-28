import { z } from "incur";
import { createLiefService } from "../composition/lief.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { logCliCommand } from "../cliLogging.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { LIEF_LIMITS } from "../domain/lief/liefLimits.js";

const pathArgs = (description: string) =>
  z.object({ path: z.string().describe(description) });

/** Parse the lookup list once; a malformed document stays invalid for the schema. */
const parseQueries = (value: string): unknown => {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
};

/** Report LIEF structure and debug-info facts through the caller's own LIEF. */
export const registerLiefCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): void => {
  cli.command(CLI_COMMANDS.inspectBinaryDeep, {
    description:
      "Report an ELF, PE or Mach-O dynamic, load-command and debug surface through the caller-supplied LIEF bridge; layout and symbol detail stay with their owning tools",
    args: pathArgs("Absolute filesystem path to the selected binary"),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createLiefService(environment);
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectBinaryDeep,
          async () =>
            finishAnalysisCommand(
              () =>
                service.inspectBinaryDeep(
                  { path: absoluteCallerPath(args.path) },
                  { signal },
                ),
              service,
              "lief",
              "inspect_binary_deep",
              signal,
            ),
        );
      }),
  });
  cli.command(CLI_COMMANDS.extractPdbDwarfInfo, {
    description:
      "Report PDB and DWARF debug surfaces and answer symbol or address lookups through the caller-supplied LIEF bridge",
    args: pathArgs(
      "Absolute filesystem path to the selected PDB, ELF, PE or Mach-O",
    ),
    options: z.object({
      "queries-json": z
        .string()
        .optional()
        .describe(
          `JSON array of at most ${String(LIEF_LIMITS.maxQueries)} lookups, e.g. [{"kind":"symbol","name":"main"}]`,
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        const service = createLiefService(environment);
        const raw = options["queries-json"];
        return await logCliCommand(
          logger,
          CLI_COMMANDS.extractPdbDwarfInfo,
          async () =>
            finishAnalysisCommand(
              () =>
                service.extractPdbDwarfInfo(
                  {
                    path: absoluteCallerPath(args.path),
                    ...(raw === undefined
                      ? {}
                      : { queries: parseQueries(raw) }),
                  },
                  { signal },
                ),
              service,
              "lief",
              "extract_pdb_dwarf_info",
              signal,
            ),
        );
      }),
  });
};
