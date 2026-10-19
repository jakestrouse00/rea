import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { ContainerInspectionService } from "../application/containers/ContainerInspectionService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { CONTAINER_TOOL_CONTRACTS } from "../contracts/containers/containersToolContracts.js";

/** Bind container handlers to their exact named schemas from the owned contract set. */
export const registerContainersTools = (
  server: EvidenceMcpServer,
  service: ContainerInspectionService,
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
  for (const contract of CONTAINER_TOOL_CONTRACTS) {
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
