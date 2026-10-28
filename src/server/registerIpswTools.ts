import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { IpswAnalysisService } from "../application/iosipsw/IpswAnalysisService.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Bind ipsw handlers to their exact named contracts through the shared workflow. */
export const registerIpswTools = (
  server: EvidenceMcpServer,
  service: IpswAnalysisService,
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
  // Names come from the central TOOL_CONTRACTS inventory; catalog ordering
  // never selects an operation.
  for (const contract of [
    toolContract("inspect_ipsw"),
    toolContract("extract_dyld_shared_cache_images"),
    toolContract("dump_ios_class_metadata"),
    toolContract("symbolicate_ios_crash"),
    toolContract("inspect_macho_entitlements"),
  ])
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
