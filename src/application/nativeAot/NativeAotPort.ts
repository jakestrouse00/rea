import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectNativeAotTypesInput } from "../../domain/managed/nativeAotArtifact.js";
import type { NativeAotArtifactInspection } from "../../domain/managed/nativeAotArtifact.js";
import type { Result } from "../../domain/result.js";

/** Replaceable read-only NativeAOT structural reader with no target-execution authority. */
export interface NativeAotPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectNativeAotTypesInput,
    options?: ExecutionOptions,
  ): Promise<Result<NativeAotArtifactInspection, AnalysisError>>;
}
