import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { DiscoveryRequest } from "../../domain/discovery/discoveryAnalysis.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";

/**
 * Local network/device discovery boundary over macOS host-provided tools.
 * Passive sources read this host's observation state; the only operation
 * that emits packets is the explicitly authorized subnet sweep. An empty
 * table or tree is an observation, not an error.
 */
export interface DiscoveryAnalysisPort {
  /** Probe tool resolution without reading host tables or devices. */
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  /** Terminally stop admission and release owned resources. */
  close(): Promise<void>;
  execute(
    request: DiscoveryRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
