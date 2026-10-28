import type { PythonDecompilerPort } from "./PythonDecompilerPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { pythonDecompilerRequestSchema } from "../../domain/pysrc/pythonSourceRecovery.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared admission, execution, and Evidence composition for Python recovery. */
export class PythonDecompilerService {
  constructor(readonly provider: PythonDecompilerPort) {}

  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      pythonDecompilerRequestSchema,
      this.provider,
      "observed",
    );
  }
}
