import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { MobileToolchainPort } from "./MobileToolchainPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import type { MobileToolchainOperation } from "../../domain/mobile/mobileToolchain.js";
import { mobileToolchainRequestSchema } from "../../domain/mobile/mobileToolchain.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for the mobile lane. */
export class MobileToolchainService {
  constructor(readonly provider: MobileToolchainPort) {}

  /** Run one caller-selected mobile toolchain operation. */
  async execute(
    operation: MobileToolchainOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      mobileToolchainRequestSchema,
      this.provider,
      "observed",
    );
  }
}
