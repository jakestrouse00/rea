import type { SymbolRecoveryPort } from "./SymbolRecoveryPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { symbolRecoveryRequestSchema } from "../../domain/symbols/symbolRecovery.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for symbol recovery. */
export class SymbolRecoveryService {
  constructor(readonly provider: SymbolRecoveryPort) {}

  /** Run one caller-selected symbol-recovery request and retain its provenance. */
  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      symbolRecoveryRequestSchema,
      this.provider,
      "observed",
    );
  }
}
