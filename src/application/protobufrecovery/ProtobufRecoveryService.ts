import type { ProtobufRecoveryPort } from "./ProtobufRecoveryPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { protobufRecoveryRequestSchema } from "../../domain/protobufrecovery/protobufRecovery.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";

/** Shared admission, execution, and Evidence composition for protobuf recovery. */
export class ProtobufRecoveryService {
  constructor(readonly provider: ProtobufRecoveryPort) {}

  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      protobufRecoveryRequestSchema,
      this.provider,
      "observed",
    );
  }
}
