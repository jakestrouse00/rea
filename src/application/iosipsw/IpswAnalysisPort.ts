import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { IpswRequest } from "../../domain/iosipsw/ipswAnalysis.js";
import type { Result } from "../../domain/result.js";

/**
 * iOS static-image boundary over a caller-selected blacktop/ipsw binary.
 * Implementation details belong to the provider adapter.
 */
export interface IpswAnalysisPort {
  /** Probe the selected binary without reading an archive or cache. */
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  /** Terminally stop admission, drain work, and retry retained staging roots. */
  close(): Promise<void>;
  execute(
    request: IpswRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
