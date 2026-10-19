import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { WindowsArtifactsService } from "../application/windowsArtifacts/WindowsArtifactsService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { WINDOWS_ARTIFACTS_TOOL_CONTRACTS } from "../contracts/windowsArtifacts/windowsArtifactsToolContracts.js";
import type { Logger } from "pino";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/**
 * Bind the Windows-artifact contracts to their shared workflow and the
 * owning session's Evidence ledger by contract name; every contract in the
 * list must have a registered operation or registration fails closed.
 */
export const registerWindowsArtifactsTools = (
  server: EvidenceMcpServer,
  service: WindowsArtifactsService,
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
      ) => ReturnType<typeof service.inspectMinidump>
    >
  > = {
    inspect_windows_minidump: (input, options) =>
      service.inspectMinidump(input, options),
    inspect_wer_report: (input, options) =>
      service.inspectWerReport(input, options),
    inspect_pdb_symbols: (input, options) =>
      service.inspectPdbSymbols(input, options),
  };
  for (const contract of WINDOWS_ARTIFACTS_TOOL_CONTRACTS) {
    const operation = operations[contract.name];
    if (operation === undefined)
      throw new Error(
        `Windows-artifact tool ${contract.name} has no registered operation`,
      );
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
