import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceLookup } from "../application/EvidenceInputResolver.js";
import type { RustBinaryService } from "../application/rust/RustBinaryService.js";
import type { RustSymbolsService } from "../application/rust/RustSymbolsService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { applicationToolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the exact Rust contracts to their shared workflows and owning session Evidence ledger. */
export const registerRustTools = (
  server: EvidenceMcpServer,
  service: RustBinaryService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
  symbolsService?: RustSymbolsService,
  evidenceById?: EvidenceLookup,
): void => {
  const contract = toolContract("inspect_rust_binary");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) =>
      service.inspect(input, options, { recordEvidence, evidenceById }),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    applicationToolRegistrationOptions(contract),
    handler(contract),
  );
  const symbolsContract = toolContract("inspect_rust_symbols");
  server.registerTool(
    symbolsContract.name,
    toolRegistrationOptions(symbolsContract),
    createEvidenceToolHandler(
      server,
      (input, options) => {
        if (symbolsService === undefined)
          throw new Error(
            "inspect_rust_symbols requires the rust symbols service",
          );
        return symbolsService.symbols(input, options);
      },
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    )(symbolsContract),
  );
};
