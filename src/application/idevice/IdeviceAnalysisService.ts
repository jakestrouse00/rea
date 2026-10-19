import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  ideviceRequestSchema,
  type IdeviceOperation,
} from "../../domain/idevice/ideviceDeviceAnalysis.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import type { IdeviceAnalysisPort } from "./IdevicePort.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for the iOS device plane. */
export class IdeviceAnalysisService {
  constructor(readonly provider: IdeviceAnalysisPort) {}

  /** Run one caller-selected read-only iOS device request. */
  async execute(
    operation: IdeviceOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      ideviceRequestSchema,
      this.provider,
      "observed",
    );
  }
}
