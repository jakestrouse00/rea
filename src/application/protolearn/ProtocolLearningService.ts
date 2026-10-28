import type { ExecutionOptions } from "../AnalysisProvider.js";
import { protolearnRequestSchema } from "../../domain/protolearn/protocolLearningInputs.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";
import type { ProtocolLearningPort } from "./ProtocolLearningPort.js";

/** A learned model is derived; a lab reply is observed. */
const confidenceOf = (operation: string): "observed" | "derived" =>
  operation === "probe_learned_model" ? "observed" : "derived";

/** Shared CLI/MCP admission, execution, and Evidence composition. */
export class ProtocolLearningService {
  constructor(readonly provider: ProtocolLearningPort) {}

  /** Run one learning, probing, or export request and retain its provenance. */
  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      protolearnRequestSchema,
      this.provider,
      confidenceOf(operation),
    );
  }
}
