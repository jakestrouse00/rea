import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { V8BytecodeRequest } from "../../domain/javascript/v8Bytecode.js";
import type { Result } from "../../domain/result.js";

/** V8 bytecode disassembly over a caller-selected View8 build. */
export interface V8BytecodePort {
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  close(): Promise<void>;
  execute(
    request: V8BytecodeRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
