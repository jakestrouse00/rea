import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { GamedataRequest } from "../domain/gamedata/gamedataRequests.js";
import type { Result } from "../domain/result.js";

/**
 * Replaceable structure-only game-container reader with no content-decrypting
 * or asset-decoding authority.
 */
export interface GameDataPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  execute(
    request: GamedataRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
