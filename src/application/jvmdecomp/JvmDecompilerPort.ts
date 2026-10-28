import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { JvmDecompilerRequest } from "../../domain/jvmdecomp/jvmDecompilation.js";
import type { Result } from "../../domain/result.js";

/** JVM class decompilation over a caller-selected Vineflower JAR. */
export interface JvmDecompilerPort {
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  close(): Promise<void>;
  execute(
    request: JvmDecompilerRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
