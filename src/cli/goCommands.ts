import { z } from "incur";
import { createGoBinaryService } from "../composition/go.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import {
  analysisEvidenceDeliveryOptions,
  deliverCliAnalysisEvidence,
} from "./analysisEvidenceDelivery.js";
import { localPathStringSchema } from "../domain/localPath.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { machoSliceArchitectureSchema } from "../domain/apple/machoTargetSelection.js";

/** Resolve caller paths and inspect static build metadata through the shared workflow. */
export const registerGoCommands = (cli: CliInstance, logger: Logger): void => {
  cli.command(CLI_COMMANDS.inspectGoBinary, {
    description:
      "Inspect embedded Go compiler, modules and build settings without target execution",
    args: z.object({
      path: localPathStringSchema.describe(
        "Local ELF, PE, thin Mach-O or universal Mach-O image",
      ),
    }),
    options: z.object({
      ...analysisEvidenceDeliveryOptions,
      architecture: machoSliceArchitectureSchema
        .optional()
        .describe(
          "CPU family of the slice to read from a universal Mach-O; required for universal files",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        const service = createGoBinaryService();
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectGoBinary,
          async () =>
            deliverCliAnalysisEvidence({
              run: () =>
                service.inspect(
                  {
                    path: absoluteCallerPath(args.path),
                    ...(options.architecture === undefined
                      ? {}
                      : { architecture: options.architecture }),
                  },
                  { signal },
                ),
              service,
              providerId: "go-build-info",
              operation: "inspect_go_binary",
              signal,
              detail: options.detail,
              evidenceOutput: options.evidence_output,
            }),
        );
      }),
  });
  cli.command(CLI_COMMANDS.inspectGoProcedureTable, {
    description:
      "Page embedded Go procedure names, entries and table facts without target execution",
    args: z.object({
      path: z.string().describe("Local ELF, PE or thin Mach-O image"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("Zero-based procedure-table row index where the page starts"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(500)
        .default(50)
        .describe("Maximum procedures returned in one page"),
    }),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const service = createGoBinaryService();
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectGoProcedureTable,
          async () =>
            finishAnalysisCommand(
              () =>
                service.procedureTable(
                  {
                    path: absoluteCallerPath(args.path),
                    offset: args.offset,
                    limit: args.limit,
                  },
                  { signal },
                ),
              service,
              "go-build-info",
              "inspect_go_procedure_table",
              signal,
            ),
        );
      }),
  });
};
