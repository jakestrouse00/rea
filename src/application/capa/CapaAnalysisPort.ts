import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { AnalyzeBinaryCapabilitiesRequest } from "../../domain/capa/capaAnalysis.js";
import type { Result } from "../../domain/result.js";

/**
 * Capability matching over a caller-selected capa binary. Implementation
 * details belong to the provider adapter.
 */
export interface CapaAnalysisPort {
  /** Probe the selected binary without reading a target. */
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  /** Terminally stop admission, drain work, and release retained descriptors. */
  close(): Promise<void>;
  execute(
    request: AnalyzeBinaryCapabilitiesRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
