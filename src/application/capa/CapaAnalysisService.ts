import type { CapaAnalysisPort } from "./CapaAnalysisPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { analyzeBinaryCapabilitiesRequestSchema } from "../../domain/capa/capaAnalysis.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for capa. */
export class CapaAnalysisService {
  constructor(readonly provider: CapaAnalysisPort) {}

  /** Run one caller-selected capability match and retain its structural provenance. */
  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      analyzeBinaryCapabilitiesRequestSchema,
      this.provider,
      "observed",
    );
  }
}
