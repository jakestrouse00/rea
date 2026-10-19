import { z } from "incur";

import { IdeviceAnalysisService } from "../application/idevice/IdeviceAnalysisService.js";
import type { IdeviceAnalysisPort } from "../application/idevice/IdevicePort.js";
import { createIdeviceAnalysisProvider } from "../composition/idevice.js";
import type { IdeviceOperation } from "../domain/idevice/ideviceDeviceAnalysis.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";

const IDEVICE_CLI_COMMANDS = CLI_COMMANDS;

/** Expose the read-only iOS device-plane operations through the CLI. */
export const registerIdeviceCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
  provider: IdeviceAnalysisPort = createIdeviceAnalysisProvider(environment),
): void => {
  const service = new IdeviceAnalysisService(provider);
  const execute = (name: string, operation: IdeviceOperation, input: unknown) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, () =>
        finishAnalysisCommand(
          () => service.execute(operation, input, { signal }),
          { close: () => provider.close() },
          "idevice",
          operation,
          signal,
        ),
      ),
    );

  const udid = z
    .string()
    .min(1)
    .regex(
      /^[0-9a-fA-F-]+$/u,
      "A UDID contains hexadecimal digits and dashes only",
    )
    .describe("Device UDID");
  const outputDirectory = z
    .string()
    .min(1)
    .describe("Local directory for the pulled artifact");

  cli.command(IDEVICE_CLI_COMMANDS.listIosDevices, {
    description:
      "List devices visible through caller-supplied pymobiledevice3; an unpaired host is an empty inventory",
    args: z.object({}),
    run: () =>
      execute(IDEVICE_CLI_COMMANDS.listIosDevices, "list_ios_devices", {}),
  });
  cli.command(IDEVICE_CLI_COMMANDS.inspectIosDevice, {
    description:
      "Inspect one device's model, iOS version, and connection type via lockdown",
    args: z.object({ udid }),
    run: ({ args }) =>
      execute(
        IDEVICE_CLI_COMMANDS.inspectIosDevice,
        "inspect_ios_device",
        args,
      ),
  });
  cli.command(IDEVICE_CLI_COMMANDS.readIosSyslog, {
    description: "Read a bounded one-shot dump of the device syslog stream",
    args: z.object({ udid }),
    options: z.object({
      timeout: z
        .number()
        .int()
        .min(1)
        .max(120)
        .default(10)
        .describe("Capture window in seconds"),
      "process-filter": z
        .string()
        .min(1)
        .optional()
        .describe("Keep only lines containing this case-insensitive substring"),
    }),
    run: ({ args, options }) =>
      execute(IDEVICE_CLI_COMMANDS.readIosSyslog, "read_ios_syslog", {
        udid: args.udid,
        timeout_seconds: options.timeout,
        ...(options["process-filter"] === undefined
          ? {}
          : { process_filter: options["process-filter"] }),
      }),
  });
  cli.command(IDEVICE_CLI_COMMANDS.captureIosScreenshot, {
    description: "Capture one screen frame as a digested PNG",
    args: z.object({ udid }),
    options: z.object({ "output-directory": outputDirectory }),
    run: ({ args, options }) =>
      execute(
        IDEVICE_CLI_COMMANDS.captureIosScreenshot,
        "capture_ios_screenshot",
        {
          udid: args.udid,
          output_directory: options["output-directory"],
        },
      ),
  });
  cli.command(IDEVICE_CLI_COMMANDS.listIosCrashReports, {
    description: "List the device's retained crash reports",
    args: z.object({ udid }),
    run: ({ args }) =>
      execute(
        IDEVICE_CLI_COMMANDS.listIosCrashReports,
        "list_ios_crash_reports",
        args,
      ),
  });
  cli.command(IDEVICE_CLI_COMMANDS.inspectIosCrash, {
    description: "Pull one crash report as a digested local artifact",
    args: z.object({
      udid,
      report: z
        .string()
        .min(1)
        .describe(
          "Crash report name exactly as list-ios-crash-reports reports it",
        ),
    }),
    options: z.object({ "output-directory": outputDirectory }),
    run: ({ args, options }) =>
      execute(IDEVICE_CLI_COMMANDS.inspectIosCrash, "inspect_ios_crash", {
        udid: args.udid,
        report: args.report,
        output_directory: options["output-directory"],
      }),
  });
  cli.command(IDEVICE_CLI_COMMANDS.listIosApps, {
    description: "List installed app bundles on the device (read-only)",
    args: z.object({ udid }),
    run: ({ args }) =>
      execute(IDEVICE_CLI_COMMANDS.listIosApps, "list_ios_apps", args),
  });
  cli.command(IDEVICE_CLI_COMMANDS.inspectIosProvisioning, {
    description:
      "Display provisioning and signing metadata the launcher reports for one installed app",
    args: z.object({
      udid,
      "bundle-id": z.string().min(1).describe("Installed app bundle id"),
    }),
    run: ({ args }) =>
      execute(
        IDEVICE_CLI_COMMANDS.inspectIosProvisioning,
        "inspect_ios_provisioning",
        {
          udid: args.udid,
          bundle_id: args["bundle-id"],
        },
      ),
  });
};
