import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { AsarIntegrityService } from "../application/electron/AsarIntegrityService.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { applicationToolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Bind the ASAR integrity reader to its exact named contract. */
export const registerAsarIntegrityTool = (
  server: EvidenceMcpServer,
  service: AsarIntegrityService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("inspect_asar_integrity");
  server.registerTool(
    contract.name,
    applicationToolRegistrationOptions(contract),
    createEvidenceToolHandler(
      server,
      (input, execution) => service.inspect(input, execution),
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    )(contract),
  );
};
