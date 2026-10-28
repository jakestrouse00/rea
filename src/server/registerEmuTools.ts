import type { EmuAnalysisPort } from "../application/emu/EmuAnalysisPort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { EmuAnalysisService } from "../application/emu/EmuAnalysisService.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

/** Bind emulation handlers to their exact named contracts through the shared workflow. */
export const registerEmuTools = (
  server: EvidenceMcpServer,
  emu: EmuAnalysisPort,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    new EmuAnalysisService(emu),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  for (const contract of [
    toolContract("emulate_function_isolated"),
    toolContract("assemble_bytes"),
  ])
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
