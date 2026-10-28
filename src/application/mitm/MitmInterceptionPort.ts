import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { MitmTargetApp } from "../../domain/mitm/mitmLimits.js";
import type {
  MitmRuleAction,
  MitmRuleMatch,
} from "../../domain/mitm/mitmRule.js";
import type { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import type { ReplayDumpTarget } from "../../domain/replay/replayObservation.js";
import type { ReplayMutation } from "../../domain/replay/replayRequest.js";
import type { Result } from "../../domain/result.js";

/** One per-application interception session over the loopback proxy. */
export interface StartMitmSessionRequest {
  readonly targetApp: MitmTargetApp;
  readonly appIdentifier: string | undefined;
  readonly listenPort: number;
  readonly targetOrigins: readonly string[];
  readonly startTimeoutMs: number;
}

export interface ReadMitmInventoryRequest {
  readonly sessionId: string;
  readonly offset: number;
  readonly limit: number;
}

export interface ExportMitmInventoryRequest {
  readonly sessionId: string;
  readonly path: string | undefined;
  readonly overwrite: boolean;
}

export interface SetMitmRuleRequest {
  readonly sessionId: string;
  readonly ruleId: string | undefined;
  readonly match: MitmRuleMatch;
  readonly action: MitmRuleAction;
  readonly ttlMs: number;
}

export interface ClearMitmRuleRequest {
  readonly sessionId: string;
  readonly ruleId: string;
}

export interface MitmReplayRequest {
  readonly sessionId: string;
  readonly sequence: number;
  readonly mutation: ReplayMutation;
  readonly timeoutMs: number;
  readonly followRedirects: boolean;
  readonly dump: ReplayDumpTarget | undefined;
}

/**
 * The interception lane's application seam.
 *
 * A session owns one supervised proxy, a bounded value-free inventory, its
 * armed rewrite rules, and the owner-only capture directory the addon writes
 * bodies into. Replay is a thin projection over the shared send core.
 */
export interface MitmInterceptionPort {
  start(
    request: StartMitmSessionRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  readInventory(
    request: ReadMitmInventoryRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  exportInventory(
    request: ExportMitmInventoryRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  setRule(
    request: SetMitmRuleRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  clearRule(
    request: ClearMitmRuleRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  replay(
    request: MitmReplayRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  stop(
    request: { readonly sessionId: string },
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  closeAll(): Promise<Result<void, ProviderCleanupError>>;
}
