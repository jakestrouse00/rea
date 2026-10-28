import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { DotnetDecompilerRequest } from "../../domain/manageddecomp/dotnetDecompilation.js";
import type { Result } from "../../domain/result.js";

/** .NET decompilation over a caller-selected ilspycmd binary. */
export interface DotnetDecompilerPort {
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  close(): Promise<void>;
  execute(
    request: DotnetDecompilerRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
