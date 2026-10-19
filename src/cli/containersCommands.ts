import { z } from "incur";
import { createContainerInspectionService } from "../composition/containers.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";

/** Canonical one-shot container command names from the shared registry. */
export const CONTAINERS_CLI_COMMANDS = CLI_COMMANDS;

const containerPathArg = {
  path: z
    .string()
    .describe(
      "Absolute path to the selected container (CRX3 extension, XPI package, or PyInstaller executable/archive)",
    ),
};

/** Inspect static container metadata through the shared workflow. */
export const registerContainersCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CONTAINERS_CLI_COMMANDS.inspectCrxExtension, {
    description:
      "Inspect a CRX3 browser extension header and manifest surface without target execution",
    args: z.object(containerPathArg),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createContainerInspectionService();
        return await logCliCommand(
          logger,
          CONTAINERS_CLI_COMMANDS.inspectCrxExtension,
          async () =>
            finishAnalysisCommand(
              () =>
                service.execute(
                  "inspect_crx_extension",
                  { path: absoluteCallerPath(args.path) },
                  { signal },
                ),
              service,
              "containers",
              "inspect_crx_extension",
              signal,
            ),
        );
      }),
  });
  cli.command(CONTAINERS_CLI_COMMANDS.inspectXpiExtension, {
    description:
      "Inspect a Firefox XPI package's META-INF digest facts and manifest surface without target execution",
    args: z.object(containerPathArg),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createContainerInspectionService();
        return await logCliCommand(
          logger,
          CONTAINERS_CLI_COMMANDS.inspectXpiExtension,
          async () =>
            finishAnalysisCommand(
              () =>
                service.execute(
                  "inspect_xpi_extension",
                  { path: absoluteCallerPath(args.path) },
                  { signal },
                ),
              service,
              "containers",
              "inspect_xpi_extension",
              signal,
            ),
        );
      }),
  });
  cli.command(CONTAINERS_CLI_COMMANDS.inspectPyInstallerArchive, {
    description:
      "Inventory a PyInstaller CArchive and its embedded PYZ and pyc facts without target execution",
    args: z.object(containerPathArg),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createContainerInspectionService();
        return await logCliCommand(
          logger,
          CONTAINERS_CLI_COMMANDS.inspectPyInstallerArchive,
          async () =>
            finishAnalysisCommand(
              () =>
                service.execute(
                  "inspect_pyinstaller_archive",
                  { path: absoluteCallerPath(args.path) },
                  { signal },
                ),
              service,
              "containers",
              "inspect_pyinstaller_archive",
              signal,
            ),
        );
      }),
  });
};
