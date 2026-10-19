import { z } from "incur";
import { createWindowsArtifactsService } from "../composition/windowsArtifacts.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { logCliCommand } from "../cliLogging.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";

const pathArgs = (description: string) =>
  z.object({ path: z.string().describe(description) });

/** Inspect minidumps, WER reports and PDB symbol tables without target execution. */
export const registerWindowsArtifactsCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): void => {
  cli.command(CLI_COMMANDS.inspectWindowsMinidump, {
    description:
      "Inspect one Windows minidump's streams, modules, threads, exception and memory inventory without executing anything",
    args: pathArgs("Absolute filesystem path to the selected Windows minidump"),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createWindowsArtifactsService(environment);
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectWindowsMinidump,
          async () =>
            finishAnalysisCommand(
              () =>
                service.inspectMinidump(
                  { path: absoluteCallerPath(args.path) },
                  { signal },
                ),
              service,
              "windows-minidump",
              "inspect_windows_minidump",
              signal,
            ),
        );
      }),
  });
  cli.command(CLI_COMMANDS.inspectWerReport, {
    description:
      "Parse one WER report's exact UTF-16LE key/value fields and module signatures with no redaction or inference",
    args: pathArgs("Absolute filesystem path to the selected WER report"),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createWindowsArtifactsService(environment);
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectWerReport,
          async () =>
            finishAnalysisCommand(
              () =>
                service.inspectWerReport(
                  { path: absoluteCallerPath(args.path) },
                  { signal },
                ),
              service,
              "windows-wer-report",
              "inspect_wer_report",
              signal,
            ),
        );
      }),
  });
  cli.command(CLI_COMMANDS.inspectPdbSymbols, {
    description:
      "Dump modules, named streams and symbol records from one PDB through the caller-configured llvm-pdbutil; source-server streams stay inert",
    args: pathArgs("Absolute filesystem path to the selected PDB file"),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createWindowsArtifactsService(environment);
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectPdbSymbols,
          async () =>
            finishAnalysisCommand(
              () =>
                service.inspectPdbSymbols(
                  { path: absoluteCallerPath(args.path) },
                  { signal },
                ),
              service,
              "llvm-pdbutil",
              "inspect_pdb_symbols",
              signal,
            ),
        );
      }),
  });
};
