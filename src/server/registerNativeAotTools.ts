import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { NativeAotArtifactService } from "../application/nativeAot/NativeAotArtifactService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { NATIVE_AOT_TOOL_CONTRACTS } from "../contracts/managed/nativeAotToolContracts.js";
import type { Logger } from "pino";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/**
 * Bind the NativeAOT structural contracts to the shared read workflow by
 * contract name; every contract in the list must have a registered operation
 * or registration fails closed.
 */
export const registerNativeAotTools = (
  server: EvidenceMcpServer,
  service: NativeAotArtifactService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const operations: Readonly<
    Record<
      string,
      (
        input: unknown,
        options?: ExecutionOptions,
      ) => ReturnType<typeof service.inspect>
    >
  > = {
    inspect_nativeaot_types: (input, options) =>
      service.inspect(input, options),
  };
  for (const contract of NATIVE_AOT_TOOL_CONTRACTS) {
    const operation = operations[contract.name];
    if (operation === undefined)
      throw new Error(
        `NativeAOT tool ${contract.name} has no registered operation`,
      );
    const handler = createEvidenceToolHandler(
      server,
      operation,
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    );
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
