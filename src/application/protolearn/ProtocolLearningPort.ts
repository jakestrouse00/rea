import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { ProtolearnRequest } from "../../domain/protolearn/protocolLearningInputs.js";
import type { Result } from "../../domain/result.js";

/**
 * Protocol learning over one saved capture, active differential probes against
 * one allowlisted lab socket, and structure-aware seed export. Implementation
 * details belong to the provider adapter.
 */
export interface ProtocolLearningPort {
  /** Report the probe lane's selection without opening a socket. */
  inspectProbeAvailability(): Promise<ProviderAvailability>;
  /** Release the packet-capture reader and refuse new work. */
  close(): Promise<void>;
  execute(
    request: ProtolearnRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
