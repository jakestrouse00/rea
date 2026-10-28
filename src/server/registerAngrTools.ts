import type { AngrAnalysisPort } from "../application/angr/AngrAnalysisPort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { AngrAnalysisService } from "../application/angr/AngrAnalysisService.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

/** Bind symbolic-execution handlers to their exact named contracts. */
export const registerAngrTools = (
  server: EvidenceMcpServer,
  angr: AngrAnalysisPort,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    new AngrAnalysisService(angr),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  for (const contract of [
    toolContract("find_paths_to_target"),
    toolContract("run_symbolic_function_exploration"),
    toolContract("recover_control_flow_angr"),
  ])
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
