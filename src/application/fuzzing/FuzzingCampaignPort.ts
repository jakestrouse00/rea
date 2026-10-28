import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { SanitizerClass } from "../../domain/crashTriage/crashReport.js";
import type { FuzzingEngine } from "../../domain/fuzzing/fuzzingEngine.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";

/** One launch of a registered campaign through one engine adapter. */
export interface StartFuzzingCampaignRequest {
  readonly campaignId: string;
  readonly engine: FuzzingEngine;
  readonly povRepeats: number;
  readonly expectedSanitizer: SanitizerClass | undefined;
  readonly minimizeCrashes: boolean;
  readonly labVm: {
    readonly sessionId: string;
    readonly workspacePath: string;
  } | null;
}

/**
 * The fuzz loop: launch a caller-selected engine over a registered campaign,
 * report the stats it observed, and hand validated crashes to crash triage.
 *
 * The port reports one Evidence observation per campaign run. It starts no
 * engine until a campaign is registered, never rewrites a caller file, and
 * removes only the private campaign roots it owns.
 */
export interface FuzzingCampaignPort {
  startCampaign(
    request: StartFuzzingCampaignRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  /** Remove every retained campaign root; a failed removal reports the path. */
  closeAll(): Promise<Result<null, AnalysisError>>;
}
