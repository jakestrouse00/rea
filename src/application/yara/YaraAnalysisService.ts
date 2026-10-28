import type { YaraAnalysisPort } from "./YaraAnalysisPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { yaraScanRequestSchema } from "../../domain/yara/yaraScan.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for YARA-X. */
export class YaraAnalysisService {
  constructor(readonly provider: YaraAnalysisPort) {}

  /** Run one caller-selected YARA-X scan and retain its structural provenance. */
  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      yaraScanRequestSchema,
      this.provider,
      "observed",
    );
  }
}
