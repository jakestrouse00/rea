import { z } from "incur";
import { createGameDataService } from "../composition/gamedata.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import type { GamedataOperation } from "../domain/gamedata/gamedataRequests.js";

const COMMANDS = CLI_COMMANDS;

const pageArgs = {
  entries_start: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("First entry index to return in paged inventories (default 0)"),
  entries_limit: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .describe("Maximum entries to return per page (default 200)"),
};

/** Inspect game-container structure: indexes, chunk maps and detection headers. */
export const registerGamedataCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const execute = (
    name: string,
    operation: GamedataOperation,
    input: Record<string, unknown>,
  ) =>
    withCommandCancellation(async (signal) => {
      const service = createGameDataService();
      return await logCliCommand(logger, name, async () =>
        finishAnalysisCommand(
          () => service.execute(operation, input, { signal }),
          service,
          "game-data-structure",
          operation,
          signal,
        ),
      );
    });

  cli.command(COMMANDS.inspectGodotPck, {
    description:
      "Inspect a Godot PCK directory index (v1/v2): entry paths, offsets, sizes, MD5, flags; optional bounded single-entry extraction",
    args: z.object({
      path: z
        .string()
        .min(1)
        .describe("Local .pck file or embedded executable"),
      ...pageArgs,
      extract_entry_path: z
        .string()
        .min(1)
        .optional()
        .describe("Directory entry path to extract verbatim with sha256"),
      output_directory: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Existing absolute directory for the extraction (never overwritten)",
        ),
    }),
    run: ({ args }) =>
      execute(COMMANDS.inspectGodotPck, "inspect_godot_pck", {
        path: absoluteCallerPath(args.path),
        ...(args.entries_start === undefined
          ? {}
          : { entries_start: args.entries_start }),
        ...(args.entries_limit === undefined
          ? {}
          : { entries_limit: args.entries_limit }),
        ...(args.extract_entry_path === undefined ||
        args.output_directory === undefined
          ? {}
          : {
              extract: {
                entry_path: args.extract_entry_path,
                output_directory: absoluteCallerPath(args.output_directory),
              },
            }),
      }),
  });

  cli.command(COMMANDS.inspectVpkArchive, {
    description:
      "Inspect a Source VPK directory: header, sections, and the full file tree with CRCs and archive indices",
    args: z.object({
      path: z
        .string()
        .min(1)
        .describe("Local _dir.vpk (or single-file) directory"),
      ...pageArgs,
    }),
    run: ({ args }) =>
      execute(COMMANDS.inspectVpkArchive, "inspect_vpk_archive", {
        path: absoluteCallerPath(args.path),
        ...(args.entries_start === undefined
          ? {}
          : { entries_start: args.entries_start }),
        ...(args.entries_limit === undefined
          ? {}
          : { entries_limit: args.entries_limit }),
      }),
  });

  cli.command(COMMANDS.inspectGamemakerData, {
    description:
      "Inspect a GameMaker data.win/game.unx: FORM chunk map, GEN8 header fields, and CODE/STRG/TXOR/SOND presence",
    args: z.object({
      path: z.string().min(1).describe("Local GameMaker data file"),
    }),
    run: ({ args }) =>
      execute(COMMANDS.inspectGamemakerData, "inspect_gamemaker_data", {
        path: absoluteCallerPath(args.path),
      }),
  });

  cli.command(COMMANDS.inspectRpaArchive, {
    description:
      "Inspect a Ren'Py RPA archive: header, index key, and the deobfuscated name/offset/length table",
    args: z.object({
      path: z.string().min(1).describe("Local .rpa archive"),
      ...pageArgs,
    }),
    run: ({ args }) =>
      execute(COMMANDS.inspectRpaArchive, "inspect_rpa_archive", {
        path: absoluteCallerPath(args.path),
        ...(args.entries_start === undefined
          ? {}
          : { entries_start: args.entries_start }),
        ...(args.entries_limit === undefined
          ? {}
          : { entries_limit: args.entries_limit }),
      }),
  });

  cli.command(COMMANDS.inspectRpgmakerAssetPrefixes, {
    description:
      "Detect RPG Maker MV/MZ 16-byte RPGMV fake headers across a directory of PNG/OGG/OGA/M4A files (detect only, never strips)",
    args: z.object({
      directory: z.string().min(1).describe("Absolute directory to scan"),
      extensions: z
        .array(z.enum(["png", "ogg", "oga", "m4a"]))
        .optional()
        .describe("Candidate extensions (default all)"),
      ...pageArgs,
    }),
    run: ({ args }) =>
      execute(
        COMMANDS.inspectRpgmakerAssetPrefixes,
        "inspect_rpgmaker_asset_prefixes",
        {
          directory: absoluteCallerPath(args.directory),
          ...(args.extensions === undefined
            ? {}
            : { extensions: args.extensions }),
          ...(args.entries_start === undefined
            ? {}
            : { entries_start: args.entries_start }),
          ...(args.entries_limit === undefined
            ? {}
            : { entries_limit: args.entries_limit }),
        },
      ),
  });
};
