import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  AsarIntegrityReport,
  InspectAsarIntegrityRequest,
} from "../../domain/electron/asarIntegrity.js";
import type { Result } from "../../domain/result.js";

/** Replaceable read-only ASAR integrity reader with no target-execution authority. */
export interface AsarIntegrityPort {
  readonly identity: ProviderIdentity;
  /** Release owned read resources; legacy read-only ports may own none. */
  close?(): Promise<void>;
  inspect(
    input: InspectAsarIntegrityRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AsarIntegrityReport, AnalysisError>>;
}
