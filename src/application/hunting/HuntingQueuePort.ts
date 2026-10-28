import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { HuntingQueueReadResult } from "../../domain/hunting/huntingObservation.js";
import type {
  HuntingReanalysisOperation,
  HuntingRecipe,
  HuntingTarget,
} from "../../domain/hunting/huntingRecipes.js";
import type { HuntingWatchSource } from "../../domain/hunting/huntingWatch.js";
import type { Result } from "../../domain/result.js";

/** One batch to queue: a target list, a recipe list, and its budget. */
export interface ScheduleHuntingBatchRequest {
  readonly targets: readonly HuntingTarget[];
  readonly recipes: readonly HuntingRecipe[];
  /** Omitted means one budget slot per queued unit. */
  readonly maxUnits: number | undefined;
  /** Omitted means the hunting.max_batch_seconds setting. */
  readonly maxSeconds: number | undefined;
}

/** Admitting the next unit of one batch, or of the oldest runnable batch. */
export interface RunScheduledBatchRequest {
  readonly batchId: string | undefined;
  readonly maxUnitSeconds: number | undefined;
}

/** One page of the durable queue. */
export interface ReadHuntingQueueRequest {
  readonly batchId: string | undefined;
  readonly offset: number;
  readonly limit: number;
}

export interface CancelHuntingBatchRequest {
  readonly batchId: string;
}

/** Start observing one source and enqueue re-analysis for one target. */
export interface StartHuntingWatchRequest {
  readonly source: HuntingWatchSource;
  readonly target: HuntingTarget;
  readonly operation: HuntingReanalysisOperation;
  readonly intervalMs: number;
  readonly maxTriggers: number;
  readonly maxUnits: number | undefined;
  readonly maxSeconds: number | undefined;
}

export interface StopHuntingWatchRequest {
  readonly sessionId: string;
}

/**
 * The orchestration seam: a durable queue of analysis units, one admitted at a
 * time, and watch sessions that enqueue work instead of running it.
 *
 * Every unit delegates to the capability that owns the work; this port owns
 * only the queue state, the budgets, and the lifecycle of the watch timers it
 * started.
 */
export interface HuntingQueuePort {
  schedule(
    request: ScheduleHuntingBatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  runNext(
    request: RunScheduledBatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  /** Read-only: returns the durable queue without recording Evidence. */
  read(
    request: ReadHuntingQueueRequest,
    options?: ExecutionOptions,
  ): Promise<Result<HuntingQueueReadResult, AnalysisError>>;
  cancel(
    request: CancelHuntingBatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  startWatch(
    request: StartHuntingWatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  stopWatch(
    request: StopHuntingWatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  /** Release every timer and wait for owned work; the durable queue stays. */
  closeAll(): Promise<Result<null, AnalysisError>>;
}
