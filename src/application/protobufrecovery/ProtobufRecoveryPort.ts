import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { ProtobufRecoveryRequestInput } from "../../domain/protobufrecovery/protobufRecovery.js";
import type { Result } from "../../domain/result.js";

/** Protobuf recovery and reflection over caller-selected tools. */
export interface ProtobufRecoveryPort {
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  inspectRecoveryAvailability?(
    signal?: AbortSignal,
  ): ProviderAvailability | Promise<ProviderAvailability>;
  inspectReflectionAvailability?(
    signal?: AbortSignal,
  ): ProviderAvailability | Promise<ProviderAvailability>;
  close(): Promise<void>;
  execute(
    request: ProtobufRecoveryRequestInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
