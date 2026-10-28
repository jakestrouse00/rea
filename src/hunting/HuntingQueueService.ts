import { randomUUID } from "node:crypto";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  CancelHuntingBatchRequest,
  HuntingQueuePort,
  ReadHuntingQueueRequest,
  RunScheduledBatchRequest,
  ScheduleHuntingBatchRequest,
  StartHuntingWatchRequest,
  StopHuntingWatchRequest,
} from "../application/hunting/HuntingQueuePort.js";
import type { HuntingRecipeRunners } from "../application/hunting/HuntingRecipePort.js";
import { workflowUnknownInput } from "../application/investigation/WorkflowUnknown.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
  type AnalysisInputIssue,
} from "../domain/analysisErrorCore.js";
import type { Evidence } from "../domain/evidence.js";
import {
  HUNTING_DEFAULT_BATCH_SECONDS,
  HUNTING_DEFAULT_UNIT_SECONDS,
  HUNTING_LIMITS,
  HUNTING_OPERATIONS,
  HUNTING_PROVIDER,
  HUNTING_SANDBOX,
  HUNTING_UNKNOWN_NOTE,
} from "../domain/hunting/huntingLimits.js";
import type {
  HuntingBatchState,
  HuntingQueueCounts,
  HuntingQueueReadResult,
  HuntingRunResult,
  HuntingScheduleResult,
  HuntingStop,
  HuntingUnitFact,
  HuntingUnitState,
  HuntingWatchStartResult,
  HuntingWatchStopResult,
} from "../domain/hunting/huntingObservation.js";
import {
  huntingBatchBudgetSchema,
  huntingQueueCountsSchema,
  huntingRunResultSchema,
  huntingUnitFactSchema,
} from "../domain/hunting/huntingObservation.js";
import { huntingPriority } from "../domain/hunting/huntingPriority.js";
import {
  huntingUnitId,
  type HuntingRecipe,
  type HuntingTarget,
} from "../domain/hunting/huntingRecipes.js";
import {
  huntingWatchChanges,
  type HuntingWatchSnapshot,
  type HuntingWatchSource,
} from "../domain/hunting/huntingWatch.js";
import type {
  RecordUnknownInput,
  ResidualUnknown,
} from "../domain/residualUnknown.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  sandboxDisableState,
  type SandboxDisableState,
} from "../domain/sandboxProfiles.js";
import {
  createHuntingCancelEvidence,
  createHuntingRunEvidence,
  createHuntingScheduleEvidence,
  createHuntingWatchStartEvidence,
  createHuntingWatchStopEvidence,
  huntingObservationFacts,
} from "./HuntingEvidence.js";
import { readHuntingWatchSnapshot } from "./HuntingDirectoryWatch.js";
import {
  huntingQueueDirectory,
  HuntingQueueStore,
  type StoredHuntingBatch,
  type StoredHuntingUnit,
} from "./HuntingQueueStore.js";

/** Timer seam; production uses the platform interval timers. */
export interface HuntingTimers {
  set(callback: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

/** Directory observer seam; production walks the tree with `lstat`. */
export interface HuntingWatchObserver {
  snapshot(
    root: string,
    recursive: boolean,
    signal: AbortSignal,
  ): Promise<HuntingWatchSnapshot>;
}

/** Evidence writes this lane performs for the composed observations it retains. */
export interface HuntingEvidenceWriter {
  recordEvidence(evidence: Evidence): unknown;
}

/** Residual-unknown owner this lane reads and appends to. */
export interface HuntingUnknownRegistry {
  list(): readonly ResidualUnknown[];
  record(input: RecordUnknownInput): Result<ResidualUnknown, AnalysisError>;
}

export interface HuntingQueueServiceOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly platform?: NodeJS.Platform;
  readonly settings?: AnalysisSettingsReader;
  readonly runners: HuntingRecipeRunners;
  readonly unknowns?: HuntingUnknownRegistry;
  readonly writer?: HuntingEvidenceWriter;
  readonly createStore?: () => HuntingQueueStore;
  readonly timers?: HuntingTimers;
  readonly observer?: HuntingWatchObserver;
  readonly maxWatchEntries?: number;
  readonly now?: () => string;
  readonly elapsed?: () => number;
  readonly sandboxState?: (
    environment: Readonly<Record<string, string | undefined>>,
  ) => SandboxDisableState;
}

interface WatchSession {
  readonly id: string;
  readonly source: Extract<HuntingWatchSource, { readonly kind: "directory" }>;
  readonly targetPath: string;
  readonly operation: StartHuntingWatchRequest["operation"];
  readonly intervalMs: number;
  readonly triggersLimit: number;
  readonly maxUnits: number;
  readonly maxSeconds: number;
  readonly priority: HuntingUnitFact["priority"];
  readonly controller: AbortController;
  readonly pending: Set<Promise<unknown>>;
  previous: HuntingWatchSnapshot;
  handle: unknown;
  inFlight: Promise<void> | null;
  state: "watching" | "stopped";
  triggers: number;
  queuedUnits: number;
  batchId: string | null;
  lastReadError: string | null;
  limitations: string[];
}

interface BudgetApplied {
  readonly unitMs: number;
  readonly source: "request" | "setting";
}

const defaultTimers: HuntingTimers = {
  set: (callback, ms) => setInterval(callback, ms),
  clear: (handle) => clearInterval(handle as ReturnType<typeof setInterval>),
};

const operationOf = (error: AnalysisError): string | null =>
  "operation" in error && typeof error.operation === "string"
    ? error.operation
    : null;

const errorTag = (cause: unknown): string =>
  typeof cause === "object" &&
  cause !== null &&
  "_tag" in cause &&
  typeof (cause as { readonly _tag?: unknown })._tag === "string"
    ? (cause as { readonly _tag: string })._tag
    : "unexpected";

/**
 * Owns the durable hunting queue and the watch sessions this process started.
 *
 * A call admits at most one unit, so a long batch never runs unattended inside
 * one tool call. The queue, its budget, and every unit outcome are written to
 * the owner-only queue file before the reply, so a restarted process resumes
 * the same units. Watch sessions only enqueue; they hold no analysis work.
 */
export class HuntingQueueService implements HuntingQueuePort {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #settings: AnalysisSettingsReader | undefined;
  readonly #runners: HuntingRecipeRunners;
  readonly #unknowns: HuntingUnknownRegistry | undefined;
  readonly #writer: HuntingEvidenceWriter | undefined;
  readonly #store: HuntingQueueStore;
  readonly #timers: HuntingTimers;
  readonly #observer: HuntingWatchObserver;
  readonly #now: () => string;
  readonly #elapsed: () => number;
  readonly #sandboxState: (
    environment: Readonly<Record<string, string | undefined>>,
  ) => SandboxDisableState;
  readonly #watches = new Map<string, WatchSession>();
  readonly #running = new Set<string>();
  readonly #pending = new Set<Promise<unknown>>();
  #activeUnit: string | null = null;
  #closing = false;

  constructor(options: HuntingQueueServiceOptions) {
    this.#environment = options.environment ?? process.env;
    this.#settings = options.settings;
    this.#runners = options.runners;
    this.#unknowns = options.unknowns;
    this.#writer = options.writer;
    this.#store =
      options.createStore?.() ??
      new HuntingQueueStore(
        huntingQueueDirectory(this.#environment, options.platform),
        options.platform ?? process.platform,
      );
    this.#timers = options.timers ?? defaultTimers;
    this.#observer = options.observer ?? {
      snapshot: (root, recursive, signal) =>
        readHuntingWatchSnapshot(
          root,
          recursive,
          signal,
          options.maxWatchEntries === undefined
            ? {}
            : { maxEntries: options.maxWatchEntries },
        ),
    };
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#elapsed = options.elapsed ?? (() => Date.now());
    this.#sandboxState = options.sandboxState ?? sandboxDisableState;
  }

  async schedule(
    request: ScheduleHuntingBatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = HUNTING_OPERATIONS.schedule;
    if (options?.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    if (this.#closing) return err(this.#closingRefusal(operation));
    if (request.targets.length === 0 || request.recipes.length === 0)
      return err(
        this.#inputError(operation, [
          {
            path: request.targets.length === 0 ? ["targets"] : ["recipes"],
            reason: "missing_argument",
            message:
              "Schedule at least one target and one recipe; an empty batch would queue nothing.",
          },
        ]),
      );
    const unitCount = request.targets.length * request.recipes.length;
    if (unitCount > HUNTING_LIMITS.maxUnitsPerBatch)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "capacity",
          `This batch would queue ${String(unitCount)} units; one batch holds at most ${String(HUNTING_LIMITS.maxUnitsPerBatch)}.`,
          {
            requested_units: unitCount,
            max_units_per_batch: HUNTING_LIMITS.maxUnitsPerBatch,
          },
          {
            retryable: false,
            remediationAction:
              "Split the batch by target or recipe, or schedule the remainder as a second batch.",
          },
        ),
      );
    return this.#withStore(operation, async (store) => {
      const priorities = this.#resolveTargets(request.targets, operation);
      if (!priorities.ok) return priorities;
      const batchId = randomUUID();
      const createdAt = this.#now();
      const maxUnits = Math.min(
        request.maxUnits ?? unitCount,
        HUNTING_LIMITS.maxUnitsPerBatch,
      );
      const maxSeconds = Math.min(
        request.maxSeconds ?? this.#settingBatchSeconds(),
        this.#settingBatchSeconds(),
      );
      const recipeCount = request.recipes.length;
      const writes = request.targets.flatMap((target, targetIndex) =>
        request.recipes.map((recipe, recipeIndex) => {
          const position = targetIndex * recipeCount + recipeIndex;
          return {
            unitId: huntingUnitId(batchId, position, target.path, recipe),
            position,
            targetPath: target.path,
            recipe,
            priority: priorities.value[targetIndex]!,
          };
        }),
      );
      store.createBatch({ batchId, createdAt, maxUnits, maxSeconds }, writes);
      const batch = store.batch(batchId);
      if (batch === null)
        return err(
          new AnalysisOutputError(operation, "queue-unreadable", {
            userMessage: "The scheduled batch could not be read back.",
          }),
        );
      const result: HuntingScheduleResult = {
        batch_id: batchId,
        created_at: batch.createdAt,
        state: batch.state,
        budget: huntingBatchBudgetSchema.parse({
          max_units: batch.maxUnits,
          max_seconds: batch.maxSeconds,
          units_started: batch.unitsStarted,
          spent_ms: batch.spentMs,
        }),
        units: store
          .units(batchId, HUNTING_LIMITS.maxUnitsPerBatch, 0)
          .map((unit) => this.#unitFact(unit)),
        limitations: [
          `This batch queued ${String(writes.length)} units from ${String(request.targets.length)} target(s) and ${String(recipeCount)} recipe(s), ordered by each target's coverage ledger and residual unknowns.`,
          `Composed recipe kinds this server can execute: ${this.#composedRecipeKinds().join(", ") || "none"}. A unit whose kind is not composed reports a typed precondition stop.`,
          ...this.#sandboxLimitations(),
        ],
      };
      return ok(createHuntingScheduleEvidence(result));
    });
  }

  async runNext(
    request: RunScheduledBatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = HUNTING_OPERATIONS.run;
    if (this.#closing) return err(this.#closingRefusal(operation));
    const signal = options?.signal;
    return this.#withStore(operation, async (store) => {
      const batch =
        request.batchId === undefined
          ? store.nextOpenBatch()
          : store.batch(request.batchId);
      if (request.batchId !== undefined && batch === null)
        return err(
          this.#inputError(operation, [
            {
              path: ["batch_id"],
              reason: "invalid_value",
              message:
                "No batch with that identity is recorded in this queue. Read the queue for the identities it holds.",
            },
          ]),
        );
      if (batch === null)
        return ok(
          this.#runEvidence({
            batchId: null,
            batchState: null,
            unit: null,
            state: null,
            stop: null,
            observation: null,
            budget: null,
            elapsedMs: 0,
            counts: this.#emptyCounts(),
            limitations: [
              "No open batch holds a queued or blocked unit, so this call admitted nothing.",
            ],
          }),
        );
      const remaining = this.#remainingBudget(batch);
      if (remaining.units <= 0 || remaining.seconds <= 0) {
        const settling = this.#settleBatch(store, batch, batch.state);
        return ok(
          this.#runEvidence({
            batchId: batch.batchId,
            batchState: settling,
            unit: null,
            state: null,
            stop: { kind: "batch_budget", error_tag: null, operation: null },
            observation: null,
            budget: this.#unitBudget(
              { unitMs: this.#settingUnitSeconds() * 1_000, source: "setting" },
              batch,
            ),
            elapsedMs: 0,
            counts: this.#counts(store, batch.batchId),
            limitations: [
              `This batch already started ${String(batch.unitsStarted)} of ${String(batch.maxUnits)} units and spent ${String(batch.spentMs)} ms of ${String(batch.maxSeconds * 1_000)} ms. Its remaining units stay queued; schedule a new batch to continue.`,
            ],
          }),
        );
      }
      if (batch.state === "cancelled")
        return ok(
          this.#runEvidence({
            batchId: batch.batchId,
            batchState: "cancelled",
            unit: null,
            state: null,
            stop: { kind: "cancelled", error_tag: null, operation: null },
            observation: null,
            budget: null,
            elapsedMs: 0,
            counts: this.#counts(store, batch.batchId),
            limitations: [
              "This batch was cancelled; every unit it had not started stays cancelled.",
            ],
          }),
        );
      const unit = store.nextUnit(batch.batchId);
      if (unit === null) {
        const settling = this.#settleBatch(store, batch, batch.state);
        return ok(
          this.#runEvidence({
            batchId: batch.batchId,
            batchState: settling,
            unit: null,
            state: null,
            stop: null,
            observation: null,
            budget: null,
            elapsedMs: 0,
            counts: this.#counts(store, batch.batchId),
            limitations: [
              "Every unit in this batch reached a terminal state, so this call admitted nothing.",
            ],
          }),
        );
      }
      if (signal?.aborted === true)
        return err(this.#cancelled(operation, signal));
      try {
        return ok(await this.#executeUnit(store, batch, unit, request, signal));
      } catch (cause: unknown) {
        return err(
          new AnalysisOutputError(operation, "queue-unwritable", {
            cause,
            userMessage:
              "REA could not record this unit's outcome in the durable queue, so the unit is not reported as executed.",
            diagnostics: { unit_id: unit.unitId },
          }),
        );
      }
    });
  }

  async read(
    request: ReadHuntingQueueRequest,
    options?: ExecutionOptions,
  ): Promise<Result<HuntingQueueReadResult, AnalysisError>> {
    const operation = HUNTING_OPERATIONS.read;
    if (options?.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    return this.#withStore(operation, async (store) => {
      if (
        request.batchId !== undefined &&
        store.batch(request.batchId) === null
      )
        return err(
          this.#inputError(operation, [
            {
              path: ["batch_id"],
              reason: "invalid_value",
              message: "No batch with that identity is recorded in this queue.",
            },
          ]),
        );
      const batches = store.batches(HUNTING_LIMITS.maxQueuePage, 0);
      const matching = store.unitCount(request.batchId ?? null);
      const page = store.units(
        request.batchId ?? null,
        request.limit,
        request.offset,
      );
      const next = request.offset + page.length;
      return ok({
        batches: batches.map((batch) => ({
          batch_id: batch.batchId,
          created_at: batch.createdAt,
          state: batch.state,
          budget: huntingBatchBudgetSchema.parse({
            max_units: batch.maxUnits,
            max_seconds: batch.maxSeconds,
            units_started: batch.unitsStarted,
            spent_ms: batch.spentMs,
          }),
        })),
        units: page.map((unit) => this.#unitFact(unit)),
        totals: {
          batches: store.batchCount(),
          units: store.unitCount(null),
          matching_units: matching,
        },
        offset: request.offset,
        limit: request.limit,
        next_offset: next < matching ? next : null,
        limitations: [
          request.batchId === undefined
            ? "This page reports units across every batch in queue order."
            : "This page reports one batch's units in queue order.",
          HUNTING_UNKNOWN_NOTE,
          ...this.#sandboxLimitations(),
        ],
      });
    });
  }

  async cancel(
    request: CancelHuntingBatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = HUNTING_OPERATIONS.cancel;
    if (options?.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    return this.#withStore(operation, async (store) => {
      const batch = store.batch(request.batchId);
      if (batch === null)
        return err(
          this.#inputError(operation, [
            {
              path: ["batch_id"],
              reason: "invalid_value",
              message: "No batch with that identity is recorded in this queue.",
            },
          ]),
        );
      const inFlight = this.#running.has(batch.batchId) ? 1 : 0;
      const released =
        batch.state === "cancelled"
          ? { cancelled: 0 }
          : store.cancelBatch(batch.batchId, this.#now());
      return ok(
        createHuntingCancelEvidence({
          batch_id: batch.batchId,
          state: "cancelled",
          cancelled_units: released.cancelled,
          units_in_flight: inFlight,
          limitations: [
            batch.state === "cancelled"
              ? "This batch was already cancelled, so no unit changed state."
              : `This call cancelled ${String(released.cancelled)} unit(s) that had not started.`,
          ],
        }),
      );
    });
  }

  async startWatch(
    request: StartHuntingWatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = HUNTING_OPERATIONS.watchStart;
    const signal = options?.signal;
    const aborted = (): boolean => signal?.aborted === true;
    const source = request.source;
    const target = request.target;
    if (aborted()) return err(this.#cancelled(operation, signal!));
    if (this.#closing) return err(this.#closingRefusal(operation));
    if (source.kind !== "directory")
      return err(
        new AnalysisCapabilityUnavailableError(
          HUNTING_PROVIDER.id,
          operation,
          HUNTING_SANDBOX.unwatchedSource,
        ),
      );
    if (this.#watches.size >= HUNTING_LIMITS.maxLiveWatches)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "capacity",
          `This server already owns ${String(this.#watches.size)} watch session(s); at most ${String(HUNTING_LIMITS.maxLiveWatches)} stay live.`,
          {
            live_watch_sessions: this.#watches.size,
            max_live_watch_sessions: HUNTING_LIMITS.maxLiveWatches,
          },
          {
            retryable: true,
            remediationAction:
              "Stop a watch session with stop_watch_session before starting another.",
          },
        ),
      );
    return this.#withStore(operation, async (store) => {
      const priorities = this.#resolveTargets([target], operation);
      if (!priorities.ok) return priorities;
      if (aborted()) return err(this.#cancelled(operation, signal!));
      const baselineController = new AbortController();
      const onAbort = () => baselineController.abort(signal?.reason);
      signal?.addEventListener("abort", onAbort, { once: true });
      let baseline: HuntingWatchSnapshot;
      try {
        baseline = await this.#observer.snapshot(
          source.path,
          source.recursive,
          baselineController.signal,
        );
      } catch (cause: unknown) {
        if (aborted()) return err(this.#cancelled(operation, signal!));
        if (cause instanceof Error && "_tag" in cause)
          return err(cause as AnalysisError);
        return err(
          new AnalysisOutputError(operation, "watch-source-unreadable", {
            cause,
            userMessage: `The watch source ${source.path} could not be observed.`,
          }),
        );
      } finally {
        signal?.removeEventListener("abort", onAbort);
      }
      if (aborted()) return err(this.#cancelled(operation, signal!));
      void store;
      const session: WatchSession = {
        id: randomUUID(),
        source,
        targetPath: target.path,
        operation: request.operation,
        intervalMs: request.intervalMs,
        triggersLimit: Math.min(
          request.maxTriggers,
          HUNTING_LIMITS.maxWatchTriggers,
        ),
        maxUnits: Math.min(
          request.maxUnits ?? request.maxTriggers,
          HUNTING_LIMITS.maxUnitsPerBatch,
        ),
        maxSeconds: Math.min(
          request.maxSeconds ?? this.#settingBatchSeconds(),
          this.#settingBatchSeconds(),
        ),
        priority: priorities.value[0]!,
        controller: new AbortController(),
        pending: new Set(),
        previous: baseline,
        handle: undefined,
        inFlight: null,
        state: "watching",
        triggers: 0,
        queuedUnits: 0,
        batchId: null,
        lastReadError: null,
        limitations: [
          ...(baseline.truncated
            ? [
                "The baseline observation reached its entry budget, so an unchanged path missing from it is unknown rather than removed.",
              ]
            : []),
          ...(baseline.unreadable.length === 0
            ? []
            : [
                `${String(baseline.unreadable.length)} directory path(s) in the tree could not be read; changes under them are unobserved.`,
              ]),
        ],
      };
      session.handle = this.#timers.set(
        () => this.#tick(session),
        session.intervalMs,
      );
      this.#watches.set(session.id, session);
      if (aborted()) {
        const released = await this.#releaseWatch(session);
        const evidence = createHuntingWatchStopEvidence(
          this.#watchStopFacts(session, released),
        );
        return err(
          this.#cancelled(operation, signal!).retainPartialObservation(
            evidence,
          ),
        );
      }
      const result: HuntingWatchStartResult = {
        session_id: session.id,
        source: {
          kind: "directory",
          path: session.source.path,
          recursive: session.source.recursive,
        },
        interval_ms: session.intervalMs,
        state: session.state,
        triggers: session.triggers,
        triggers_limit: session.triggersLimit,
        queued_units: session.queuedUnits,
        batch_id: session.batchId,
        limitations: [
          ...session.limitations,
          `This observation is a bounded snapshot of ${String(baseline.entries.length)} entry(ies); content is never read.`,
          `Each observed change enqueues one re-analysis unit for ${session.targetPath} into a batch this session owns.`,
          ...this.#sandboxLimitations(),
        ],
      };
      return ok(createHuntingWatchStartEvidence(result));
    });
  }

  async stopWatch(
    request: StopHuntingWatchRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = HUNTING_OPERATIONS.watchStop;
    const session = this.#watches.get(request.sessionId);
    if (session === undefined)
      return err(
        this.#inputError(operation, [
          {
            path: ["session_id"],
            reason: "invalid_value",
            message:
              "This REA server owns no watch session with that identity. Watch identity lasts for this server's lifetime, and a session that reached its trigger budget has already stopped and released it.",
          },
        ]),
      );
    const aborted = options?.signal?.aborted === true;
    const released = await this.#releaseWatch(session);
    const evidence = createHuntingWatchStopEvidence(
      this.#watchStopFacts(session, released),
    );
    if (!released.released)
      return err(
        new AnalysisCapabilityUnavailableError(
          HUNTING_PROVIDER.id,
          operation,
          "The watch session's owned timer or in-flight read is still unreleased.",
          {
            userMessage: "Call stop_watch_session again to retry the release.",
          },
        ).retainPartialObservation(evidence),
      );
    if (aborted)
      return err(
        this.#cancelled(operation, options!.signal!).retainPartialObservation(
          evidence,
        ),
      );
    return ok(evidence);
  }

  async closeAll(): Promise<Result<null, AnalysisError>> {
    this.#closing = true;
    const failures: string[] = [];
    for (const session of this.#watches.values()) {
      const released = await this.#releaseWatch(session);
      if (!released.released) failures.push(session.id);
    }
    // A composed runner that ignored its cancellation signal may still run; the
    // durable queue already recorded the stop, so shutdown does not wait on it.
    this.#pending.clear();
    try {
      await this.#store.close();
    } catch {
      failures.push("hunting-queue-store");
    }
    return failures.length === 0
      ? ok(null)
      : err(
          new AnalysisOutputError("stop_watch_session", "cleanup-incomplete", {
            userMessage: `REA could not release ${failures.join(", ")}.`,
            diagnostics: { retained: failures.join(",") },
          }),
        );
  }

  async #executeUnit(
    store: HuntingQueueStore,
    batch: StoredHuntingBatch,
    unit: StoredHuntingUnit,
    request: RunScheduledBatchRequest,
    signal: AbortSignal | undefined,
  ): Promise<Evidence> {
    const operation = HUNTING_OPERATIONS.run;
    const sandbox = this.#sandboxState(this.#environment);
    if (sandbox.kind === "invalid")
      return this.#persistedOutcome(store, batch, unit, {
        state: "blocked",
        stop: {
          kind: "precondition",
          error_tag: "SandboxStateInvalid",
          operation,
        },
        observation: null,
        elapsedMs: 0,
        admitted: false,
        chargedUnit: false,
        budget: {
          unitMs: this.#settingUnitSeconds() * 1_000,
          source: "setting",
        },
        limitation: HUNTING_SANDBOX.invalid,
      });
    if (!this.#recipeComposed(unit.recipe.kind))
      return this.#persistedOutcome(store, batch, unit, {
        state: "blocked",
        stop: {
          kind: "precondition",
          error_tag: "RecipeNotComposed",
          operation,
        },
        observation: null,
        elapsedMs: 0,
        admitted: false,
        chargedUnit: false,
        budget: {
          unitMs: this.#settingUnitSeconds() * 1_000,
          source: "setting",
        },
        limitation: `No ${unit.recipe.kind} runner is composed in this server, so the unit stays in the queue as blocked.`,
      });
    // Admission is synchronous from here to `beginUnit`, so a second call in
    // the same process cannot observe the same queued unit as runnable.
    if (this.#activeUnit !== null)
      return this.#persistedOutcome(store, batch, unit, {
        state: "blocked",
        stop: { kind: "precondition", error_tag: "UnitInFlight", operation },
        observation: null,
        elapsedMs: 0,
        admitted: false,
        chargedUnit: false,
        budget: {
          unitMs: this.#settingUnitSeconds() * 1_000,
          source: "setting",
        },
        limitation:
          "Another unit is already admitted in this server; a blocked unit is retried after it finishes.",
      });
    this.#activeUnit = unit.unitId;
    const settingMs = this.#settingUnitSeconds() * 1_000;
    const requestedMs =
      request.maxUnitSeconds === undefined
        ? undefined
        : request.maxUnitSeconds * 1_000;
    const budget: BudgetApplied =
      requestedMs !== undefined && requestedMs < settingMs
        ? { unitMs: requestedMs, source: "request" }
        : { unitMs: settingMs, source: "setting" };
    store.beginUnit(unit.unitId, this.#now());
    this.#running.add(batch.batchId);
    const startedAt = this.#elapsed();
    const controller = new AbortController();
    let budgetExpired = false;
    let resolveDeadline: (() => void) | undefined;
    const deadline = new Promise<{ readonly kind: "deadline" }>((resolve) => {
      resolveDeadline = () => resolve({ kind: "deadline" });
    });
    const handle = this.#timers.set(() => {
      budgetExpired = true;
      controller.abort(new AnalysisTimeoutError(operation, budget.unitMs));
      resolveDeadline?.();
    }, budget.unitMs);
    const onAbort = () => controller.abort(signal?.reason);
    signal?.addEventListener("abort", onAbort, { once: true });
    const work = Promise.resolve()
      .then(() => this.#runRecipe(unit, controller.signal))
      .then(
        (value) => ({ kind: "result" as const, value }),
        (cause: unknown) => ({ kind: "threw" as const, cause }),
      );
    let raced: Awaited<typeof work> | { kind: "deadline" };
    try {
      raced = await Promise.race([work, deadline]);
    } finally {
      this.#timers.clear(handle);
      signal?.removeEventListener("abort", onAbort);
      this.#running.delete(batch.batchId);
      if (this.#activeUnit === unit.unitId) this.#activeUnit = null;
    }
    if (raced.kind === "deadline") {
      // The composed runner ignored its cancellation signal; REA stops waiting
      // but keeps the promise owned so a late settlement cannot be lost.
      const late = work.then(() => undefined);
      this.#pending.add(late);
      void late.finally(() => this.#pending.delete(late));
    }
    const elapsedMs = Math.max(0, Math.trunc(this.#elapsed() - startedAt));
    const outcome = this.#outcomeOf(raced, {
      budgetExpired,
      cancelled: signal?.aborted === true,
    });
    return this.#persistedOutcome(store, batch, unit, {
      ...outcome,
      elapsedMs,
      admitted: true,
      chargedUnit: outcome.state === "succeeded" || outcome.state === "failed",
      budget,
      ...(sandbox.kind === "disabled"
        ? { limitation: sandbox.limitation }
        : {}),
    });
  }

  #outcomeOf(
    raced:
      | {
          readonly kind: "result";
          readonly value: Result<Evidence, AnalysisError>;
        }
      | { readonly kind: "threw"; readonly cause: unknown }
      | { readonly kind: "deadline" },
    facts: { readonly budgetExpired: boolean; readonly cancelled: boolean },
  ): {
    readonly state: HuntingUnitState;
    readonly stop: HuntingStop | null;
    readonly observation: Evidence | null;
  } {
    if (raced.kind === "deadline")
      return {
        state: "stopped",
        stop: {
          kind: "unit_budget",
          error_tag: "AnalysisTimeoutError",
          operation: null,
        },
        observation: null,
      };
    if (raced.kind === "threw")
      return {
        state: "failed",
        stop: {
          kind: "runner_failure",
          error_tag: errorTag(raced.cause),
          operation: null,
        },
        observation: null,
      };
    if (raced.value.ok)
      return { state: "succeeded", stop: null, observation: raced.value.value };
    const error = raced.value.error;
    if (facts.budgetExpired)
      return {
        state: "stopped",
        stop: {
          kind: "unit_budget",
          error_tag: errorTag(error),
          operation: operationOf(error),
        },
        observation: null,
      };
    if (facts.cancelled || error instanceof AnalysisCancelledError)
      return {
        state: "stopped",
        stop: {
          kind: "cancelled",
          error_tag: errorTag(error),
          operation: operationOf(error),
        },
        observation: null,
      };
    if (error instanceof AnalysisCapabilityUnavailableError)
      return {
        state: "blocked",
        stop: {
          kind: "precondition",
          error_tag: errorTag(error),
          operation: operationOf(error),
        },
        observation: null,
      };
    return {
      state: "failed",
      stop: {
        kind: "runner_failure",
        error_tag: errorTag(error),
        operation: operationOf(error),
      },
      observation: null,
    };
  }

  /** Persist one unit outcome, its Evidence, and its unknown, then project it. */
  #persistedOutcome(
    store: HuntingQueueStore,
    batch: StoredHuntingBatch,
    unit: StoredHuntingUnit,
    outcome: {
      readonly state: HuntingUnitState;
      readonly stop: HuntingStop | null;
      readonly observation: Evidence | null;
      readonly elapsedMs: number;
      /** Whether the recipe was admitted at all. */
      readonly admitted: boolean;
      /** Whether this call consumed one slot of the batch's unit budget. */
      readonly chargedUnit: boolean;
      readonly budget: BudgetApplied;
      readonly limitation?: string;
    },
  ): Evidence {
    const observation =
      outcome.observation === null
        ? null
        : huntingObservationFacts(outcome.observation);
    // A unit that stopped for a budget or a cancellation keeps its queued work:
    // the queue stores it as queued, while this call reports what it observed.
    const storedState: HuntingUnitState =
      outcome.state === "stopped" ? "queued" : outcome.state;
    store.finishUnit({
      unitId: unit.unitId,
      state: storedState,
      at: this.#now(),
      stop: outcome.stop,
      observation,
    });
    const unitsStarted = batch.unitsStarted + (outcome.chargedUnit ? 1 : 0);
    const spentMs = batch.spentMs + (outcome.admitted ? outcome.elapsedMs : 0);
    const counts = this.#counts(store, batch.batchId);
    const batchState = outcome.admitted
      ? this.#settleBatch(
          store,
          batch,
          this.#nextBatchState(batch, { unitsStarted, spentMs, counts }),
          { unitsStarted, spentMs },
        )
      : batch.state === "open" &&
          counts.queued + counts.running + counts.blocked === 0
        ? this.#settleBatch(store, batch, "complete")
        : batch.state;
    const stored = store.unit(unit.unitId) ?? unit;
    const limitations = [
      ...(outcome.limitation === undefined ? [] : [outcome.limitation]),
      ...(observation === null
        ? []
        : [
            `The composed observation is retained as Evidence ${observation.evidence_id}; read it with get_evidence_bundle.`,
          ]),
      ...(outcome.state === "blocked" ? [HUNTING_UNKNOWN_NOTE] : []),
    ];
    const evidence = this.#runEvidence({
      batchId: batch.batchId,
      batchState,
      unit: this.#unitFact(stored),
      state: outcome.state,
      stop: outcome.stop,
      observation,
      budget: this.#unitBudget(outcome.budget, batch),
      elapsedMs: outcome.elapsedMs,
      counts,
      limitations,
    });
    if (outcome.observation !== null)
      try {
        this.#writer?.recordEvidence(outcome.observation);
      } catch {
        // Evidence recording is the session's concern; the queue outcome stands.
      }
    try {
      this.#writer?.recordEvidence(evidence);
    } catch {
      // Same as above: a registry failure must not rewrite the queue.
    }
    if (outcome.state !== "succeeded")
      this.#recordUnknown(evidence, outcome.state);
    return evidence;
  }

  #settleBatch(
    store: HuntingQueueStore,
    batch: StoredHuntingBatch,
    state: HuntingBatchState,
    budget?: { readonly unitsStarted: number; readonly spentMs: number },
  ): HuntingBatchState {
    store.updateBatch({
      batchId: batch.batchId,
      state,
      unitsStarted: budget?.unitsStarted ?? batch.unitsStarted,
      spentMs: budget?.spentMs ?? batch.spentMs,
    });
    return state;
  }

  #nextBatchState(
    batch: StoredHuntingBatch,
    facts: {
      readonly unitsStarted: number;
      readonly spentMs: number;
      readonly counts: HuntingQueueCounts;
    },
  ): HuntingBatchState {
    if (batch.state === "cancelled") return "cancelled";
    if (facts.counts.queued + facts.counts.running + facts.counts.blocked === 0)
      return "complete";
    if (
      facts.unitsStarted >= batch.maxUnits ||
      facts.spentMs >= batch.maxSeconds * 1_000
    )
      return "exhausted";
    return "open";
  }

  #recordUnknown(evidence: Evidence, state: HuntingUnitState): void {
    if (this.#unknowns === undefined) return;
    const input = workflowUnknownInput(evidence.evidence_id, {
      question: `A scheduled hunting unit ended as ${state}; the claim it would have established is still unverified.`,
      severity: state === "failed" ? "medium" : "low",
      domain: "hunting",
      required_authority: "shipped-artifact",
      required_confidence: "observed",
      required_environment: null,
      recommended_probes: [
        {
          operation: HUNTING_OPERATIONS.run,
          rationale:
            "Read the queue and admit the unit again once its precondition, budget, or composed runner allows it.",
        },
      ],
      relationships: [],
    });
    if (!input.ok) return;
    try {
      this.#unknowns.record(input.value);
    } catch {
      // The unit's own Evidence already names the unfinished claim.
    }
  }

  #runEvidence(input: {
    readonly batchId: string | null;
    readonly batchState: HuntingBatchState | null;
    readonly unit: HuntingUnitFact | null;
    readonly state: HuntingUnitState | null;
    readonly stop: HuntingStop | null;
    readonly observation: HuntingRunResult["observation"];
    readonly budget: HuntingRunResult["budget"];
    readonly elapsedMs: number;
    readonly counts: HuntingQueueCounts;
    readonly limitations: readonly string[];
  }): Evidence {
    const sandbox = this.#sandboxState(this.#environment);
    const result: HuntingRunResult = huntingRunResultSchema.parse({
      batch_id: input.batchId,
      batch_state: input.batchState,
      unit: input.unit,
      state: input.state,
      stop: input.stop,
      observation: input.observation,
      budget: input.budget,
      elapsed_ms: input.elapsedMs,
      sandbox: sandbox.kind === "disabled" ? "disabled" : "enabled",
      queue: input.counts,
      limitations: [
        ...input.limitations,
        ...(sandbox.kind === "disabled" ? [sandbox.limitation] : []),
        ...(sandbox.kind === "invalid" ? [HUNTING_SANDBOX.invalid] : []),
      ],
    });
    return createHuntingRunEvidence(result);
  }

  #unitFact(unit: StoredHuntingUnit): HuntingUnitFact {
    return huntingUnitFactSchema.parse({
      unit_id: unit.unitId,
      batch_id: unit.batchId,
      recipe_kind: unit.recipe.kind,
      target_path: unit.targetPath,
      operation:
        unit.recipe.kind === "re-analysis" ? unit.recipe.operation : null,
      state: unit.state,
      attempt: unit.attempt,
      priority: {
        score: unit.priority.score,
        reasons: unit.priority.reasons.map((reason) => ({ ...reason })),
      },
      updated_at: unit.updatedAt,
    });
  }

  #counts(store: HuntingQueueStore, batchId: string): HuntingQueueCounts {
    const states = store.unitStates(batchId);
    return huntingQueueCountsSchema.parse({
      ...states,
      total:
        states.queued +
        states.running +
        states.blocked +
        states.succeeded +
        states.failed +
        states.stopped +
        states.cancelled,
      next_unit_id: store.nextUnit(batchId)?.unitId ?? null,
    });
  }

  #emptyCounts(): HuntingQueueCounts {
    return huntingQueueCountsSchema.parse({
      queued: 0,
      running: 0,
      blocked: 0,
      succeeded: 0,
      failed: 0,
      stopped: 0,
      cancelled: 0,
      total: 0,
      next_unit_id: null,
    });
  }

  #remainingBudget(batch: StoredHuntingBatch): {
    readonly units: number;
    readonly seconds: number;
  } {
    return {
      units: batch.maxUnits - batch.unitsStarted,
      seconds: Math.max(0, batch.maxSeconds - Math.ceil(batch.spentMs / 1_000)),
    };
  }

  #unitBudget(
    budget: BudgetApplied,
    batch: StoredHuntingBatch,
  ): HuntingRunResult["budget"] {
    const remaining = this.#remainingBudget(batch);
    return {
      unit_ms: budget.unitMs,
      source: budget.source,
      batch_remaining_seconds: remaining.seconds,
      batch_remaining_units: remaining.units,
    };
  }

  #resolveTargets(
    targets: readonly HuntingTarget[],
    operation: string,
  ): Result<readonly HuntingUnitFact["priority"][], AnalysisError> {
    const requested = new Set(
      targets.flatMap((target) => [...target.unknown_ids]),
    );
    if (requested.size > 0 && this.#unknowns === undefined)
      return err(
        this.#inputError(
          operation,
          targets.map((_target, index) => ({
            path: ["targets", index, "unknown_ids"],
            reason: "invalid_value" as const,
            message:
              "This server has no investigation session, so it cannot resolve residual-unknown identities. Schedule the unit without unknown_ids.",
          })),
          "This server has no investigation session, so unknown_ids cannot be resolved.",
        ),
      );
    const registry = new Map(
      (this.#unknowns?.list() ?? []).map((unknown) => [
        unknown.unknown_id,
        unknown,
      ]),
    );
    const missing: AnalysisInputIssue[] = [];
    const priorities: HuntingUnitFact["priority"][] = [];
    for (const [index, target] of targets.entries()) {
      const heads: ResidualUnknown[] = [];
      for (const [position, id] of target.unknown_ids.entries()) {
        const head = registry.get(id);
        if (head === undefined) {
          missing.push({
            path: ["targets", index, "unknown_ids", position],
            reason: "invalid_value",
            message:
              "No residual unknown in this session's registry has that identity.",
          });
          continue;
        }
        heads.push(head);
      }
      const priority = huntingPriority({
        coverage: target.coverage,
        unknowns: heads,
      });
      priorities.push({
        score: priority.score,
        reasons: [...priority.reasons],
      });
    }
    if (missing.length > 0)
      return err(
        this.#inputError(
          operation,
          missing,
          "The batch names unknown identities this session's registry does not hold; record them first or schedule without them.",
        ),
      );
    return ok(priorities);
  }

  #recipeComposed(kind: HuntingRecipe["kind"]): boolean {
    switch (kind) {
      case "re-analysis":
        return this.#runners["re-analysis"] !== null;
      case "fuzz-campaign":
        return this.#runners["fuzz-campaign"] !== null;
      case "probe":
        return this.#runners.probe !== null;
      case "replay":
        return this.#runners.replay !== null;
    }
  }

  #runRecipe(
    unit: StoredHuntingUnit,
    signal: AbortSignal | undefined,
  ): Promise<Result<Evidence, AnalysisError>> {
    const recipe = unit.recipe;
    const options: ExecutionOptions = signal === undefined ? {} : { signal };
    switch (recipe.kind) {
      case "re-analysis": {
        const runner = this.#runners["re-analysis"];
        if (runner === null)
          return Promise.resolve(err(this.#notComposed(unit)));
        return runner.run(
          { targetPath: unit.targetPath, operation: recipe.operation },
          options,
        );
      }
      case "fuzz-campaign": {
        const runner = this.#runners["fuzz-campaign"];
        if (runner === null)
          return Promise.resolve(err(this.#notComposed(unit)));
        return runner.run(
          {
            campaignId: recipe.campaign_id,
            engine: recipe.engine,
            povRepeats: recipe.pov_repeats,
            expectedSanitizer: recipe.expected_sanitizer,
            minimizeCrashes: recipe.minimize_crashes,
          },
          options,
        );
      }
      case "probe": {
        const runner = this.#runners.probe;
        if (runner === null)
          return Promise.resolve(err(this.#notComposed(unit)));
        return runner.run(
          {
            endpoint: recipe.endpoint,
            modelPath: recipe.model_path,
            repeats: recipe.repeats,
            connections: recipe.probes.map((probe) => ({
              label: probe.label,
              steps: probe.steps.map((step) => ({
                templateHex: step.template_hex,
                waitForResponse: step.wait_for_response,
              })),
            })),
          },
          options,
        );
      }
      case "replay": {
        const runner = this.#runners.replay;
        if (runner === null)
          return Promise.resolve(err(this.#notComposed(unit)));
        return runner.run(
          {
            session:
              recipe.session.kind === "replay"
                ? {
                    kind: "replay" as const,
                    sessionId: recipe.session.session_id,
                    entryOrdinal: recipe.session.entry_ordinal,
                  }
                : {
                    kind: "mitm" as const,
                    sessionId: recipe.session.session_id,
                    sequence: recipe.session.sequence,
                  },
            timeoutMs: recipe.timeout_ms,
            followRedirects: recipe.follow_redirects,
          },
          options,
        );
      }
    }
  }

  #notComposed(unit: StoredHuntingUnit): AnalysisCapabilityUnavailableError {
    return new AnalysisCapabilityUnavailableError(
      HUNTING_PROVIDER.id,
      unit.recipe.kind,
      `No ${unit.recipe.kind} runner is composed in this server.`,
    );
  }

  #tick(session: WatchSession): void {
    if (session.state !== "watching" || this.#closing) return;
    if (session.inFlight !== null) return;
    const run = this.#tickOnce(session).catch(() => undefined);
    session.inFlight = run;
    session.pending.add(run);
    void run.finally(() => {
      if (session.inFlight === run) session.inFlight = null;
      session.pending.delete(run);
    });
  }

  async #tickOnce(session: WatchSession): Promise<void> {
    let snapshot: HuntingWatchSnapshot;
    try {
      snapshot = await this.#observer.snapshot(
        session.source.path,
        session.source.recursive,
        session.controller.signal,
      );
    } catch (cause: unknown) {
      if (session.controller.signal.aborted) return;
      session.lastReadError = errorTag(cause);
      return;
    }
    if (session.state !== "watching") return;
    const diff = huntingWatchChanges(
      session.previous,
      snapshot,
      HUNTING_LIMITS.maxWatchPathsPerTick,
    );
    session.previous = snapshot;
    if (diff.changes.length === 0) return;
    const remaining = session.triggersLimit - session.triggers;
    const taken = Math.min(diff.changes.length, Math.max(0, remaining));
    if (taken === 0) return;
    try {
      await this.#store.ensure();
      this.#enqueueTriggers(session, taken);
    } catch (cause: unknown) {
      session.lastReadError = errorTag(cause);
      return;
    }
    session.triggers += taken;
    if (diff.truncated)
      session.limitations.push(
        "A change list reached its bound, so this interval may have changed more paths than were queued.",
      );
    if (session.triggers >= session.triggersLimit)
      this.#retireWatch(session, "trigger-budget");
  }

  #enqueueTriggers(session: WatchSession, count: number): void {
    const at = this.#now();
    const recipe: HuntingRecipe = {
      kind: "re-analysis",
      operation: session.operation,
    };
    for (let index = 0; index < count; index += 1) {
      const position = session.queuedUnits + index;
      const unit = {
        unitId: huntingUnitId(session.id, position, session.targetPath, recipe),
        position,
        targetPath: session.targetPath,
        recipe,
        priority: session.priority,
      };
      if (session.batchId === null) {
        const batchId = randomUUID();
        this.#store.createBatch(
          {
            batchId,
            createdAt: at,
            maxUnits: Math.max(
              1,
              Math.min(session.triggersLimit, session.maxUnits),
            ),
            maxSeconds: session.maxSeconds,
          },
          [unit],
        );
        session.batchId = batchId;
      } else this.#store.insertUnit(session.batchId, unit, at);
    }
    session.queuedUnits += count;
  }

  #retireWatch(session: WatchSession, reason: string): void {
    if (session.state !== "watching") return;
    session.state = "stopped";
    try {
      this.#timers.clear(session.handle);
    } catch {
      session.limitations.push(
        "The owned watch timer could not be cleared after the trigger budget was reached; this session identity is retained.",
      );
      return;
    }
    this.#watches.delete(session.id);
    session.limitations.push(
      `This watch session stopped after ${String(session.triggers)} trigger(s) (${reason}); its queued units stay in batch ${session.batchId ?? "none"}.`,
    );
  }

  async #releaseWatch(session: WatchSession): Promise<{
    readonly released: boolean;
    readonly stop: HuntingStop | null;
  }> {
    session.state = "stopped";
    let released = true;
    try {
      this.#timers.clear(session.handle);
    } catch {
      released = false;
    }
    session.controller.abort("watch-session-stopped");
    if (session.inFlight !== null)
      await session.inFlight.catch(() => undefined);
    const settled = await Promise.allSettled(session.pending);
    session.inFlight = null;
    if (settled.some((result) => result.status === "rejected"))
      released = false;
    if (released && this.#watches.get(session.id) === session)
      this.#watches.delete(session.id);
    return {
      released,
      stop: released
        ? null
        : {
            kind: "runner_failure",
            error_tag: "WatchReleaseIncomplete",
            operation: null,
          },
    };
  }

  #watchStopFacts(
    session: WatchSession,
    released: { readonly released: boolean; readonly stop: HuntingStop | null },
  ): HuntingWatchStopResult {
    return {
      session_id: session.id,
      state: "stopped",
      triggers: session.triggers,
      queued_units: session.queuedUnits,
      batch_id: session.batchId,
      released: released.released,
      stop: released.stop,
      limitations: [
        ...session.limitations,
        "The units this session already queued stay in their batch; cancelling that batch is a separate call.",
        ...(session.lastReadError === null
          ? []
          : [
              `The last observation failed with ${session.lastReadError}; changes in that interval are unknown.`,
            ]),
        ...(released.released
          ? []
          : [
              "The owned timer or an in-flight directory read could not be released, so this session identity is retained for a retry.",
            ]),
      ],
    };
  }

  #settingUnitSeconds(): number {
    return Math.min(
      this.#settings?.().overrides["hunting.max_unit_seconds"] ??
        HUNTING_DEFAULT_UNIT_SECONDS,
      HUNTING_LIMITS.maxUnitSeconds,
    );
  }

  #settingBatchSeconds(): number {
    return Math.min(
      this.#settings?.().overrides["hunting.max_batch_seconds"] ??
        HUNTING_DEFAULT_BATCH_SECONDS,
      HUNTING_LIMITS.maxBatchSeconds,
    );
  }

  #composedRecipeKinds(): readonly string[] {
    const kinds: string[] = [];
    if (this.#runners["re-analysis"] !== null) kinds.push("re-analysis");
    if (this.#runners["fuzz-campaign"] !== null) kinds.push("fuzz-campaign");
    if (this.#runners.probe !== null) kinds.push("probe");
    if (this.#runners.replay !== null) kinds.push("replay");
    return kinds;
  }

  #sandboxLimitations(): readonly string[] {
    const state = this.#sandboxState(this.#environment);
    return state.kind === "disabled"
      ? [state.limitation]
      : state.kind === "invalid"
        ? [HUNTING_SANDBOX.invalid]
        : [];
  }

  async #withStore<Value>(
    operation: string,
    run: (store: HuntingQueueStore) => Promise<Result<Value, AnalysisError>>,
  ): Promise<Result<Value, AnalysisError>> {
    try {
      await this.#store.ensure();
    } catch (cause: unknown) {
      return err(
        new AnalysisCapabilityUnavailableError(
          HUNTING_PROVIDER.id,
          operation,
          cause instanceof Error ? cause.message : String(cause),
          {
            cause,
            userMessage:
              "The durable hunting queue could not be opened; the caller's REA home state directory may be unreadable.",
            remediationAction:
              "Check that the REA home state directory is writable, or remove a foreign queue file, then retry.",
          },
        ),
      );
    }
    return run(this.#store);
  }

  #cancelled(operation: string, signal: AbortSignal): AnalysisCancelledError {
    return new AnalysisCancelledError(operation, { cause: signal.reason });
  }

  #closingRefusal(operation: string): AnalysisError {
    return new AnalysisCapabilityUnavailableError(
      HUNTING_PROVIDER.id,
      operation,
      "The REA server is shutting down and admits no further hunting work.",
    );
  }

  #inputError(
    operation: string,
    issues: readonly AnalysisInputIssue[],
    userMessage?: string,
  ): AnalysisInputError {
    return new AnalysisInputError(
      operation,
      userMessage === undefined ? undefined : { userMessage },
      issues,
    );
  }
}
