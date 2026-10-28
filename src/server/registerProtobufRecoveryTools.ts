import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { ProtobufRecoveryService } from "../application/protobufrecovery/ProtobufRecoveryService.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Bind protobuf-recovery handlers to their exact named contracts. */
export const registerProtobufRecoveryTools = (
  server: EvidenceMcpServer,
  service: ProtobufRecoveryService,
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
  for (const contract of [
    toolContract("recover_proto_definitions"),
    toolContract("enumerate_grpc_reflection"),
  ])
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
