import type { V8BytecodePort } from "./V8BytecodePort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { v8BytecodeRequestSchema } from "../../domain/javascript/v8Bytecode.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared admission, execution, and Evidence composition for V8 disassembly. */
export class V8BytecodeService {
  constructor(readonly provider: V8BytecodePort) {}

  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      v8BytecodeRequestSchema,
      this.provider,
      "observed",
    );
  }
}
