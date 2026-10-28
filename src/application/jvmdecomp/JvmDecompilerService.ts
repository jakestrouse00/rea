import type { JvmDecompilerPort } from "./JvmDecompilerPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { jvmDecompilerRequestSchema } from "../../domain/jvmdecomp/jvmDecompilation.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared admission, execution, and Evidence composition for JVM classes. */
export class JvmDecompilerService {
  constructor(readonly provider: JvmDecompilerPort) {}

  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      jvmDecompilerRequestSchema,
      this.provider,
      "observed",
    );
  }
}
