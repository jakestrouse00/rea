import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { IdeviceAnalysisService } from "../application/idevice/IdeviceAnalysisService.js";
import { IDEVICE_TOOL_CONTRACTS } from "../contracts/idevice/ideviceToolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/**
 * Bind the iOS device plane to its exact named contracts. These contracts
 * participate in the central TOOL_CONTRACTS inventory (toolContracts.ts
 * spreads IDEVICE_TOOL_CONTRACTS); handlers still bind by exact name, never
 * by catalog ordering.
 */
export const registerIdeviceTools = (
  server: EvidenceMcpServer,
  service: IdeviceAnalysisService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    service,
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  for (const contract of IDEVICE_TOOL_CONTRACTS) {
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
