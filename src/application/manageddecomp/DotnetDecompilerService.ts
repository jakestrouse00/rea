import type { DotnetDecompilerPort } from "./DotnetDecompilerPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { dotnetDecompilerRequestSchema } from "../../domain/manageddecomp/dotnetDecompilation.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared admission, execution, and Evidence composition for .NET decompilation. */
export class DotnetDecompilerService {
  constructor(readonly provider: DotnetDecompilerPort) {}

  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      dotnetDecompilerRequestSchema,
      this.provider,
      "observed",
    );
  }
}
