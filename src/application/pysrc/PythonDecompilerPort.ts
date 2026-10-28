import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { PythonDecompilerRequest } from "../../domain/pysrc/pythonSourceRecovery.js";
import type { Result } from "../../domain/result.js";

/** Python source recovery over a caller-selected decompiler binary. */
export interface PythonDecompilerPort {
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  close(): Promise<void>;
  execute(
    request: PythonDecompilerRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
