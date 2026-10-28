import { z } from "incur";

import { IpswAnalysisService } from "../application/iosipsw/IpswAnalysisService.js";
import type { IpswAnalysisPort } from "../application/iosipsw/IpswAnalysisPort.js";
import { createIpswAnalysisProvider } from "../composition/iosipsw.js";
import type { IpswOperation } from "../domain/iosipsw/ipswAnalysis.js";
import {
  MAX_IPSW_CLASSES,
  MAX_IPSW_DSC_IMAGES,
} from "../domain/iosipsw/ipswAnalysis.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";

/** Expose the same ipsw static-image requests through one-shot CLI commands. */
export const registerIpswCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
  provider: IpswAnalysisPort = createIpswAnalysisProvider(environment),
): void => {
  const service = new IpswAnalysisService(provider);
  const execute = (name: string, operation: IpswOperation, input: unknown) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, () =>
        finishAnalysisCommand(
          () => service.execute(operation, input, { signal }),
          { close: () => provider.close() },
          "ipsw",
          operation,
          signal,
        ),
      ),
    );

  const path = (description: string) => z.string().min(1).describe(description);

  cli.command(CLI_COMMANDS.inspectIpsw, {
    description:
      "Inventory a local IPSW or OTA archive: build identity, devices, and partitions",
    args: z.object({
      path: path("Absolute path to the IPSW or OTA archive"),
    }),
    run: ({ args }) =>
      execute(CLI_COMMANDS.inspectIpsw, "inspect_ipsw", { path: args.path }),
  });
  cli.command(CLI_COMMANDS.extractDyldSharedCacheImages, {
    description:
      "List a dyld shared cache and extract the selected images into a new output subdirectory",
    args: z.object({
      "output-directory": path(
        "Local directory that receives one new subdirectory of extracted images",
      ),
    }),
    options: z.object({
      cache: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Absolute shared-cache file or directory; defaults to REA_IPSW_DSC_PATH, then to the macOS cryptex directory",
        ),
      image: z
        .array(z.string().min(1))
        .max(MAX_IPSW_DSC_IMAGES)
        .default([])
        .describe("Image name or path to extract, repeatable"),
      "max-images": z
        .number()
        .int()
        .min(1)
        .max(MAX_IPSW_DSC_IMAGES)
        .default(32)
        .describe("Upper bound on images extracted and published"),
    }),
    run: ({ args, options }) =>
      execute(
        CLI_COMMANDS.extractDyldSharedCacheImages,
        "extract_dyld_shared_cache_images",
        {
          ...(options.cache === undefined ? {} : { cache: options.cache }),
          output_directory: args["output-directory"],
          ...(options.image.length === 0 ? {} : { images: options.image }),
          max_images: options["max-images"],
        },
      ),
  });
  cli.command(CLI_COMMANDS.dumpIosClassMetadata, {
    description:
      "Dump Objective-C or Swift type tables from one Mach-O image as structure",
    args: z.object({
      path: path("Absolute path to a Mach-O image"),
    }),
    options: z.object({
      family: z
        .enum(["objc", "swift"])
        .default("objc")
        .describe("Metadata family"),
      "max-classes": z
        .number()
        .int()
        .min(1)
        .max(MAX_IPSW_CLASSES)
        .default(500)
        .describe("Upper bound on reported classes or types"),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.dumpIosClassMetadata, "dump_ios_class_metadata", {
        path: args.path,
        family: options.family,
        max_classes: options["max-classes"],
      }),
  });
  cli.command(CLI_COMMANDS.symbolicateIosCrash, {
    description: "Symbolicate a collected crash report against a shared cache",
    args: z.object({
      crash: path("Absolute path to the crash report"),
    }),
    options: z.object({
      cache: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Absolute shared-cache path; defaults to REA_IPSW_DSC_PATH, then to the macOS cryptex directory",
        ),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.symbolicateIosCrash, "symbolicate_ios_crash", {
        crash: args.crash,
        ...(options.cache === undefined ? {} : { cache: options.cache }),
      }),
  });
  cli.command(CLI_COMMANDS.inspectMachoEntitlements, {
    description: "Read one Mach-O image's entitlement keys and load commands",
    args: z.object({
      path: path("Absolute path to a Mach-O image"),
    }),
    run: ({ args }) =>
      execute(
        CLI_COMMANDS.inspectMachoEntitlements,
        "inspect_macho_entitlements",
        {
          path: args.path,
        },
      ),
  });
};
