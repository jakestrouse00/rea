import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { LiefService } from "../application/lief/LiefService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { LIEF_TOOL_CONTRACTS } from "../contracts/lief/liefToolContracts.js";
import type { Logger } from "pino";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/**
 * Bind the LIEF contracts to their shared workflow by contract name; every
 * contract must have a registered operation or registration fails closed.
 */
export const registerLiefTools = (
  server: EvidenceMcpServer,
  service: LiefService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const operations: Readonly<
    Record<
      string,
      (
        input: unknown,
        options?: ExecutionOptions,
      ) => ReturnType<typeof service.inspectBinaryDeep>
    >
  > = {
    inspect_binary_deep: (input, options) =>
      service.inspectBinaryDeep(input, options),
    extract_pdb_dwarf_info: (input, options) =>
      service.extractPdbDwarfInfo(input, options),
  };
  for (const contract of LIEF_TOOL_CONTRACTS) {
    const operation = operations[contract.name];
    if (operation === undefined)
      throw new Error(`LIEF tool ${contract.name} has no registered operation`);
    const handler = createEvidenceToolHandler(
      server,
      operation,
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    );
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
