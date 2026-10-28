import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { MobileToolchainService } from "../application/mobile/MobileToolchainService.js";
import { MOBILE_TOOLCHAIN_TOOL_CONTRACTS } from "../contracts/mobile/mobileToolchainToolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Bind the mobile toolchain family to its exact named contracts. */
export const registerMobileToolchainTools = (
  server: EvidenceMcpServer,
  service: MobileToolchainService,
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
  for (const contract of MOBILE_TOOLCHAIN_TOOL_CONTRACTS) {
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
