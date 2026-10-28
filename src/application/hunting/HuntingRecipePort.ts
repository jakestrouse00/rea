import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { SanitizerClass } from "../../domain/crashTriage/crashReport.js";
import type { Evidence } from "../../domain/evidence.js";
import type { FuzzingEngine } from "../../domain/fuzzing/fuzzingEngine.js";
import type { HuntingReanalysisOperation } from "../../domain/hunting/huntingRecipes.js";
import type { Result } from "../../domain/result.js";

/** One re-analysis unit: repeat an inspection over the admitted target. */
export interface HuntingReanalysisRequest {
  readonly targetPath: string;
  readonly operation: HuntingReanalysisOperation;
}

/** One probe step as the queue carries it. */
export interface HuntingProbeStep {
  readonly templateHex: string;
  readonly waitForResponse: boolean;
}

/** One labelled probe connection set. */
export interface HuntingProbeConnection {
  readonly label: string;
  readonly steps: readonly HuntingProbeStep[];
}

/** One probe unit against one operator-allowlisted lab socket. */
export interface HuntingProbeRequest {
  readonly endpoint: { readonly host: string; readonly port: number };
  readonly modelPath: string;
  readonly connections: readonly HuntingProbeConnection[];
  readonly repeats: number;
}

/** One replay unit over a plane that already owns a session. */
export interface HuntingReplayRequest {
  readonly session:
    | {
        readonly kind: "replay";
        readonly sessionId: string;
        readonly entryOrdinal: number | null;
      }
    | {
        readonly kind: "mitm";
        readonly sessionId: string;
        readonly sequence: number;
      };
  readonly timeoutMs: number | undefined;
  readonly followRedirects: boolean;
}

/** One fuzz-campaign unit over an already-registered campaign. */
export interface HuntingFuzzRequest {
  readonly campaignId: string;
  readonly engine: FuzzingEngine;
  readonly povRepeats: number | undefined;
  readonly expectedSanitizer: SanitizerClass | undefined;
  readonly minimizeCrashes: boolean;
}

/** The one seam a recipe runner exposes. */
export interface HuntingRecipeRunner<Request> {
  run(
    request: Request,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
}

/** Runners composed into this server; null when a recipe kind is not wired. */
export interface HuntingRecipeRunners {
  readonly "re-analysis": HuntingRecipeRunner<HuntingReanalysisRequest> | null;
  readonly "fuzz-campaign": HuntingRecipeRunner<HuntingFuzzRequest> | null;
  readonly probe: HuntingRecipeRunner<HuntingProbeRequest> | null;
  readonly replay: HuntingRecipeRunner<HuntingReplayRequest> | null;
}
