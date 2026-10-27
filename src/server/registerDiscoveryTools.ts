import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { DiscoveryAnalysisService } from "../application/discovery/DiscoveryAnalysisService.js";
import { DISCOVERY_TOOL_CONTRACTS } from "../contracts/discovery/discoveryToolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/**
 * Bind the discovery lane to its exact named contracts. These contracts
 * participate in the central TOOL_CONTRACTS inventory (toolContracts.ts
 * spreads DISCOVERY_TOOL_CONTRACTS); handlers still bind by exact name,
 * never by catalog ordering.
 */
export const registerDiscoveryTools = (
  server: EvidenceMcpServer,
  service: DiscoveryAnalysisService,
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
  for (const contract of DISCOVERY_TOOL_CONTRACTS) {
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
