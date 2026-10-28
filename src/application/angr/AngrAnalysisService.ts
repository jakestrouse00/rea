import type { AngrAnalysisPort } from "./AngrAnalysisPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { angrRequestSchema } from "../../domain/angr/angrEvidence.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for angr. */
export class AngrAnalysisService {
  constructor(readonly provider: AngrAnalysisPort) {}

  /** Run one bounded symbolic job and retain its provenance. */
  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      angrRequestSchema,
      this.provider,
      "observed",
    );
  }
}
