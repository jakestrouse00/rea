import type { IpswAnalysisPort } from "./IpswAnalysisPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { ipswRequestSchema } from "../../domain/iosipsw/ipswAnalysis.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for ipsw. */
export class IpswAnalysisService {
  constructor(readonly provider: IpswAnalysisPort) {}

  /** Run one caller-selected ipsw request and retain the static-image provenance inline. */
  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      ipswRequestSchema,
      this.provider,
      "observed",
    );
  }
}
