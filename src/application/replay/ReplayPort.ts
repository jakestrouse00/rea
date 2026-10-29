import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { ReplayDumpTarget } from "../../domain/replay/replayObservation.js";
import type {
  ReplayMutation,
  ReplayRequest,
} from "../../domain/replay/replayRequest.js";
import type { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import type { Result } from "../../domain/result.js";

/** Select a capture entry or supply a drafted request for one session. */
export type ReplaySessionSource =
  | {
      readonly kind: "har";
      readonly path: string;
      readonly entryOrdinal: number | undefined;
    }
  | { readonly kind: "draft"; readonly request: ReplayRequest };

export interface StartReplaySessionRequest {
  readonly source: ReplaySessionSource;
  /** Origins this session may dispatch to; each must be operator-approved.
   * Omit only when the operator list is open (the "*" wildcard marker). */
  readonly targetOrigins: readonly string[] | undefined;
}

export interface SendReplayRequest {
  readonly sessionId: string;
  readonly entryOrdinal: number | undefined;
  readonly mutation: ReplayMutation;
  readonly timeoutMs: number;
  readonly followRedirects: boolean;
  readonly dump: ReplayDumpTarget | undefined;
}

export interface ReplaySessionStatusRequest {
  readonly sessionId: string;
}

export interface CloseReplaySessionRequest {
  readonly sessionId: string;
}

/**
 * The active request plane's application seam.
 *
 * A session owns its declared origins and its selected request; a send is one
 * dispatch with no retry, and its Evidence carries classes and names rather
 * than bodies or credential values.
 */
export interface ReplayPort {
  startSession(
    request: StartReplaySessionRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  send(
    request: SendReplayRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  sessionStatus(
    request: ReplaySessionStatusRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  closeSession(
    request: CloseReplaySessionRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  closeAll(): Promise<Result<void, ProviderCleanupError>>;
}
