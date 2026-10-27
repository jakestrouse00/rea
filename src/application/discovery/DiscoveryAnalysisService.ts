import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  discoveryRequestSchema,
  type DiscoveryOperation,
} from "../../domain/discovery/discoveryAnalysis.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import type { DiscoveryAnalysisPort } from "./DiscoveryPort.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for the discovery lane. */
export class DiscoveryAnalysisService {
  constructor(readonly provider: DiscoveryAnalysisPort) {}

  /** Run one caller-selected discovery request. */
  async execute(
    operation: DiscoveryOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      discoveryRequestSchema,
      this.provider,
      "observed",
    );
  }
}
