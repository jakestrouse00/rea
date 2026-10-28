import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { AngrRequest } from "../../domain/angr/angrEvidence.js";
import type { Result } from "../../domain/result.js";

/**
 * Bounded symbolic execution and CFG recovery through the caller-managed angr
 * sidecar. Each request owns one queued job and process; implementation
 * details belong to the provider adapter.
 */
export interface AngrAnalysisPort {
  /** Report the caller's selection without starting the sidecar. */
  inspectAvailability(): ProviderAvailability;
  /** Stop admission, cancel queued and running jobs, and drain them. */
  close(): Promise<void>;
  execute(
    request: AngrRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
