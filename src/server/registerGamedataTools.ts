import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { GAME_DATA_TOOL_CONTRACTS } from "../contracts/gamedata/gamedataToolContracts.js";
import type { GameDataService } from "../gamedata/GameDataService.js";

/**
 * Bind the structure-only game-data contracts to their shared workflow and
 * owning session Evidence ledger.
 */
export const registerGamedataTools = (
  server: EvidenceMcpServer,
  service: GameDataService,
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
  for (const contract of GAME_DATA_TOOL_CONTRACTS) {
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
