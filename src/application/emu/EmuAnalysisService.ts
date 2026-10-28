import type { EmuAnalysisPort } from "./EmuAnalysisPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { emuRequestSchema } from "../../domain/emu/emuEmulation.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP admission, execution, and Evidence composition for emulation. */
export class EmuAnalysisService {
  constructor(readonly provider: EmuAnalysisPort) {}

  /** Run one bounded emulation or assembly request and retain its provenance. */
  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      emuRequestSchema,
      this.provider,
      "observed",
    );
  }
}
