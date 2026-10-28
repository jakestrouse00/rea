import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { YaraScanRequest } from "../../domain/yara/yaraScan.js";
import type { Result } from "../../domain/result.js";

/**
 * Rule scanning over a caller-selected YARA-X binary. Implementation details
 * belong to the provider adapter.
 */
export interface YaraAnalysisPort {
  /** Probe the selected binary without scanning a target. */
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  /** Terminally stop admission, drain work, and release retained descriptors. */
  close(): Promise<void>;
  execute(
    request: YaraScanRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
