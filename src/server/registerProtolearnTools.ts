import type { ProtocolLearningPort } from "../application/protolearn/ProtocolLearningPort.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { ProtocolLearningService } from "../application/protolearn/ProtocolLearningService.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

/** Bind protocol-learning handlers to their exact named contracts. */
export const registerProtolearnTools = (
  server: EvidenceMcpServer,
  protocolLearning: ProtocolLearningPort,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    new ProtocolLearningService(protocolLearning),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  for (const contract of [
    toolContract("learn_protocol_model"),
    toolContract("probe_learned_model"),
    toolContract("export_protocol_grammar"),
  ])
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
