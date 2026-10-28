import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import type {
  HuntingQueuePort,
  RunScheduledBatchRequest,
  ScheduleHuntingBatchRequest,
  StartHuntingWatchRequest,
} from "../application/hunting/HuntingQueuePort.js";
import type {
  HuntingRecipeRunner,
  HuntingRecipeRunners,
  HuntingReanalysisRequest,
} from "../application/hunting/HuntingRecipePort.js";
import type { AnalysisSettingsSnapshot } from "../domain/analysisSettings.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { createEvidenceCompletionLedger } from "../domain/evidenceCompletionLedger.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import {
  HUNTING_LIMITS,
  HUNTING_PROVIDER,
} from "../domain/hunting/huntingLimits.js";
import type { HuntingUnitFact } from "../domain/hunting/huntingObservation.js";
import {
  huntingRunResultSchema,
  huntingWatchStartResultSchema,
} from "../domain/hunting/huntingObservation.js";
import type {
  HuntingRecipe,
  HuntingTarget,
} from "../domain/hunting/huntingRecipes.js";
import type { HuntingWatchSnapshot } from "../domain/hunting/huntingWatch.js";
import {
  createResidualUnknown,
  recordUnknownInputSchema,
  type RecordUnknownInput,
  type ResidualUnknown,
} from "../domain/residualUnknown.js";
import { err, ok, type Result } from "../domain/result.js";
import type { SandboxDisableState } from "../domain/sandboxProfiles.js";
import {
  HuntingQueueService,
  type HuntingTimers,
  type HuntingUnknownRegistry,
  type HuntingWatchObserver,
} from "./HuntingQueueService.js";
import { HuntingQueueStore } from "./HuntingQueueStore.js";

const TARGET = "/cases/api/target.bin";
const OTHER_TARGET = "/cases/api/other.bin";

const observation = (operation: string): Evidence =>
  createEvidence(undefined, HUNTING_PROVIDER, {
    operation,
    parameters: {},
    result: { observed: operation },
    confidence: "observed",
    authority: "controlled-replay",
    subjectUnavailableReason: "Scripted test observation.",
  });

/** Manual interval/interval seam so a budget or watch tick is explicit. */
class ManualTimers implements HuntingTimers {
  #next = 1;
  readonly handles = new Map<
    number,
    { callback: () => void; cleared: boolean }
  >();
  #clearFailure: Error | null = null;

  set(callback: () => void): unknown {
    const id = this.#next;
    this.#next += 1;
    this.handles.set(id, { callback, cleared: false });
    return id;
  }

  clear(handle: unknown): void {
    if (this.#clearFailure !== null) {
      const failure = this.#clearFailure;
      this.#clearFailure = null;
      throw failure;
    }
    const entry = this.handles.get(handle as number);
    if (entry !== undefined) entry.cleared = true;
  }

  /** Fire every live timer once; returns how many callbacks ran. */
  fire(): number {
    const live = [...this.handles.entries()].filter(
      ([, entry]) => !entry.cleared,
    );
    for (const [id, entry] of live) {
      this.handles.delete(id);
      entry.callback();
    }
    return live.length;
  }

  failNextClear(): void {
    this.#clearFailure = new Error("timer clear denied");
  }
}

const runner = (
  impl: HuntingRecipeRunner<HuntingReanalysisRequest>["run"],
): HuntingRecipeRunner<HuntingReanalysisRequest> => ({ run: impl });

const runners = (
  reanalysis: HuntingRecipeRunner<HuntingReanalysisRequest> | null,
): HuntingRecipeRunners => ({
  "re-analysis": reanalysis,
  "fuzz-campaign": null,
  probe: null,
  replay: null,
});

const target = (
  path: string,
  overrides: Partial<HuntingTarget> = {},
): HuntingTarget => ({
  path,
  coverage: null,
  unknown_ids: [],
  ...overrides,
});

const reanalysis: HuntingRecipe = {
  kind: "re-analysis",
  operation: "binary_overview",
};

const unknownHead = (
  question: string,
  severity: ResidualUnknown["severity"],
): ResidualUnknown =>
  createResidualUnknown(
    recordUnknownInputSchema.parse({
      question,
      severity,
      domain: "hunting",
      required_authority: "shipped-artifact",
      required_confidence: "observed",
      required_environment: null,
      recommended_probes: [],
      relationships: [],
    }),
    `ev_${"a".repeat(64)}`,
    null,
  );

class FakeUnknowns implements HuntingUnknownRegistry {
  readonly recorded: RecordUnknownInput[] = [];
  constructor(private readonly heads: readonly ResidualUnknown[] = []) {}
  list(): readonly ResidualUnknown[] {
    return this.heads;
  }
  record(input: RecordUnknownInput): Result<ResidualUnknown, never> {
    this.recorded.push(input);
    return ok(unknownHead(input.question, input.severity));
  }
}

interface HarnessOptions {
  readonly recipeRunners?: HuntingRecipeRunners;
  readonly settings?: AnalysisSettingsSnapshot;
  readonly observer?: HuntingWatchObserver;
  readonly sandboxState?: () => SandboxDisableState;
  readonly unknowns?: FakeUnknowns;
  readonly directoryName?: string;
}

const harness = async (options: HarnessOptions = {}) => {
  const root = await createTestTempDirectory("hunting-");
  const directory = join(root, options.directoryName ?? "state");
  const timers = new ManualTimers();
  const unknowns = options.unknowns ?? new FakeUnknowns();
  const recorded: Evidence[] = [];
  const service = new HuntingQueueService({
    environment: {},
    platform: "darwin",
    runners: options.recipeRunners ?? runners(null),
    unknowns,
    writer: {
      recordEvidence: (evidence) => {
        recorded.push(evidence);
        return ok("added");
      },
    },
    createStore: () => new HuntingQueueStore(directory, "darwin"),
    timers,
    ...(options.settings === undefined
      ? {}
      : { settings: () => options.settings! }),
    ...(options.observer === undefined ? {} : { observer: options.observer }),
    sandboxState: options.sandboxState ?? (() => ({ kind: "enabled" })),
    now: () => "2026-10-28T00:00:00.000Z",
  });
  return { root, directory, timers, unknowns, recorded, service };
};

const schedule = (
  service: HuntingQueuePort,
  request: Partial<ScheduleHuntingBatchRequest> &
    Pick<ScheduleHuntingBatchRequest, "targets" | "recipes">,
) =>
  service.schedule({
    targets: request.targets,
    recipes: request.recipes,
    maxUnits: request.maxUnits,
    maxSeconds: request.maxSeconds,
  });

const run = (
  service: HuntingQueuePort,
  request: Partial<RunScheduledBatchRequest> = {},
) =>
  service.runNext({
    batchId: request.batchId,
    maxUnitSeconds: request.maxUnitSeconds,
  });

const resultOf = (
  evidence: Evidence,
): ReturnType<typeof huntingRunResultSchema.parse> =>
  huntingRunResultSchema.parse(evidence.normalized_result);

const batchIdOf = (evidence: Evidence): string =>
  (evidence.normalized_result as { readonly batch_id: string }).batch_id;

const snapshot = (
  entries: readonly { path: string; bytes: number; mtime_ms: number }[],
  truncated = false,
): HuntingWatchSnapshot => ({
  entries: [...entries],
  truncated,
  unreadable: [],
});

const waitFor = async (
  predicate: () => Promise<boolean> | boolean,
): Promise<void> => {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timed out waiting for the expected observation");
};

describe("hunting queue scheduling", () => {
  it("orders units by the target's coverage ledger and residual unknowns", async () => {
    const coverage = createEvidenceCompletionLedger([
      {
        claim_id: "claim-parser",
        status: "fail",
        evidence_ids: [`ev_${"b".repeat(64)}`],
      },
      {
        claim_id: "claim-strings",
        status: "truncated",
        evidence_ids: [`ev_${"c".repeat(64)}`],
      },
    ]);
    const { service } = await harness();
    const scheduled = await schedule(service, {
      targets: [target(OTHER_TARGET), target(TARGET, { coverage })],
      recipes: [reanalysis],
    });
    expect(scheduled.ok).toBe(true);
    if (!scheduled.ok) return;
    const units = (
      scheduled.value.normalized_result as unknown as {
        readonly units: readonly HuntingUnitFact[];
      }
    ).units;
    expect(units).toHaveLength(2);
    expect(units[0]?.target_path).toBe(TARGET);
    expect(units[0]?.priority.reasons).toEqual([
      { kind: "coverage_fail", count: 1, weight: 40 },
      { kind: "coverage_truncated", count: 1, weight: 20 },
    ]);
    expect(units[1]?.target_path).toBe(OTHER_TARGET);
    expect(units[1]?.priority.reasons).toEqual([
      { kind: "coverage_missing", count: 1, weight: 5 },
    ]);
  });

  it("raises a unit for unresolved unknowns and refuses an unknown it cannot resolve", async () => {
    const head = unknownHead("Is the parser boundary covered?", "critical");
    const unknowns = new FakeUnknowns([head]);
    const { service } = await harness({ unknowns });
    const scheduled = await schedule(service, {
      targets: [
        target(OTHER_TARGET),
        target(TARGET, { unknown_ids: [head.unknown_id] }),
      ],
      recipes: [reanalysis],
    });
    expect(scheduled.ok).toBe(true);
    if (!scheduled.ok) return;
    const units = (
      scheduled.value.normalized_result as unknown as {
        readonly units: readonly HuntingUnitFact[];
      }
    ).units;
    expect(units[0]?.target_path).toBe(TARGET);
    expect(units[0]?.priority.reasons).toContainEqual({
      kind: "unresolved_unknown",
      count: 1,
      weight: 80,
    });

    const refused = await schedule(service, {
      targets: [target(TARGET, { unknown_ids: [`unk_${"c".repeat(64)}`] })],
      recipes: [reanalysis],
    });
    expect(refused.ok).toBe(false);
    if (refused.ok) return;
    expect(refused.error).toBeInstanceOf(AnalysisInputError);
  });

  it("refuses a batch that would exceed the fixed unit allowance", async () => {
    const { service } = await harness();
    const targets = Array.from(
      { length: HUNTING_LIMITS.maxTargets },
      (_unused, index) => target(`/cases/api/${String(index)}.bin`),
    );
    const recipes = Array.from({ length: 12 }, () => reanalysis);
    const refused = await schedule(service, { targets, recipes });
    expect(refused.ok).toBe(false);
    if (refused.ok) return;
    expect(refused.error._tag).toBe("AnalysisResourceConstraintError");
  });
});

describe("hunting queue execution", () => {
  it("admits the next queued unit and records its observation as Evidence", async () => {
    const calls: HuntingReanalysisRequest[] = [];
    const first = await harness({
      recipeRunners: runners(
        runner(async (request) => {
          calls.push(request);
          return ok(observation("binary_overview"));
        }),
      ),
    });
    const scheduled = await schedule(first.service, {
      targets: [target(TARGET)],
      recipes: [reanalysis],
    });
    expect(scheduled.ok).toBe(true);
    if (!scheduled.ok) return;
    const executed = await run(first.service);
    expect(executed.ok).toBe(true);
    if (!executed.ok) return;
    const result = resultOf(executed.value);
    expect(result.state).toBe("succeeded");
    expect(result.unit?.recipe_kind).toBe("re-analysis");
    expect(result.observation?.operation).toBe("binary_overview");
    expect(result.queue.succeeded).toBe(1);
    expect(result.queue.queued).toBe(0);
    expect(result.batch_state).toBe("complete");
    expect(calls).toEqual([
      { targetPath: TARGET, operation: "binary_overview" },
    ]);
    expect(first.recorded).toHaveLength(2);
    expect(first.recorded.map((evidence) => evidence.operation)).toContain(
      "run_scheduled_batch",
    );
    await first.service.closeAll();
  });
});

describe("hunting queue budgets", () => {
  it("stops a unit at its deadline and leaves it queued", async () => {
    const { service, timers } = await harness({
      recipeRunners: runners(
        runner(
          (_request, options) =>
            new Promise((resolve) => {
              options?.signal?.addEventListener("abort", () => {
                resolve(err(new AnalysisTimeoutError("re-analysis", 1_000)));
              });
            }),
        ),
      ),
      settings: { revision: 1, overrides: { "hunting.max_unit_seconds": 1 } },
    });
    const scheduled = await schedule(service, {
      targets: [target(TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    const pending = run(service, { batchId: batchIdOf(scheduled.value) });
    await waitFor(() => timers.handles.size === 1);
    timers.fire();
    const executed = await pending;
    expect(executed.ok).toBe(true);
    if (!executed.ok) return;
    const result = resultOf(executed.value);
    expect(result.state).toBe("stopped");
    expect(result.stop?.kind).toBe("unit_budget");
    expect(result.queue.queued).toBe(1);
    expect(result.budget?.source).toBe("setting");
    expect(result.budget?.unit_ms).toBe(1_000);
    await service.closeAll();
  });

  it("stops a unit whose runner ignores its cancellation signal", async () => {
    const { service, timers, recorded } = await harness({
      recipeRunners: runners(runner(() => new Promise<never>(() => undefined))),
    });
    const scheduled = await schedule(service, {
      targets: [target(TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    const pending = run(service, {
      batchId: batchIdOf(scheduled.value),
      maxUnitSeconds: 30,
    });
    await waitFor(() => timers.handles.size === 1);
    timers.fire();
    const executed = await pending;
    expect(executed.ok).toBe(true);
    if (!executed.ok) return;
    const result = resultOf(executed.value);
    expect(result.state).toBe("stopped");
    expect(result.stop).toEqual({
      kind: "unit_budget",
      error_tag: "AnalysisTimeoutError",
      operation: null,
    });
    expect(result.budget?.source).toBe("request");
    expect(
      recorded.some((evidence) => evidence.operation === "run_scheduled_batch"),
    ).toBe(true);
    await service.closeAll();
  });

  it("exhausts a batch at its unit budget and keeps the remaining units queued", async () => {
    const { service } = await harness({
      recipeRunners: runners(
        runner(async () => ok(observation("binary_overview"))),
      ),
    });
    const scheduled = await schedule(service, {
      targets: [target(TARGET), target(OTHER_TARGET)],
      recipes: [reanalysis],
      maxUnits: 1,
    });
    if (!scheduled.ok) return;
    const batchId = batchIdOf(scheduled.value);
    const first = await run(service, { batchId });
    expect(first.ok && resultOf(first.value).state).toBe("succeeded");
    expect(first.ok && resultOf(first.value).batch_state).toBe("exhausted");
    const second = await run(service, { batchId });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    const result = resultOf(second.value);
    expect(result.unit).toBeNull();
    expect(result.batch_state).toBe("exhausted");
    expect(result.stop?.kind).toBe("batch_budget");
    expect(result.queue.total).toBe(2);
    expect(result.queue.queued).toBe(1);
    await service.closeAll();
  });
});

describe("hunting queue preconditions", () => {
  it("keeps a unit queued when the composed recipe is not composed", async () => {
    const { service } = await harness({ recipeRunners: runners(null) });
    const scheduled = await schedule(service, {
      targets: [target(TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    const executed = await run(service, {
      batchId: batchIdOf(scheduled.value),
    });
    expect(executed.ok).toBe(true);
    if (!executed.ok) return;
    const result = resultOf(executed.value);
    expect(result.state).toBe("blocked");
    expect(result.stop?.kind).toBe("precondition");
    expect(result.stop?.error_tag).toBe("RecipeNotComposed");
    expect(result.queue.blocked).toBe(1);
    expect(result.queue.next_unit_id).not.toBeNull();
    await service.closeAll();
  });

  it("admits one unit at a time and blocks a second concurrent call", async () => {
    let startedRun: (() => void) | undefined;
    const startedRunPromise = new Promise<void>((resolve) => {
      startedRun = resolve;
    });
    const { service, timers } = await harness({
      recipeRunners: runners(
        runner(() => {
          startedRun?.();
          return new Promise<never>(() => undefined);
        }),
      ),
    });
    const scheduled = await schedule(service, {
      targets: [target(TARGET), target(OTHER_TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    const batchId = batchIdOf(scheduled.value);
    const admitted = run(service, { batchId });
    await startedRunPromise;
    const second = await run(service, { batchId });
    if (!second.ok) throw second.error;
    expect(resultOf(second.value).state).toBe("blocked");
    expect(resultOf(second.value).stop?.error_tag).toBe("UnitInFlight");
    expect(resultOf(second.value).queue.blocked).toBe(1);
    timers.fire();
    const completed = await admitted;
    expect(completed.ok && resultOf(completed.value).state).toBe("stopped");
    await service.closeAll();
  });

  it("refuses to admit a unit when REA_DISABLE_SANDBOX is uninterpretable", async () => {
    const { service } = await harness({
      recipeRunners: runners(
        runner(async () => ok(observation("binary_overview"))),
      ),
      sandboxState: () => ({
        kind: "invalid",
        reason: "REA_DISABLE_SANDBOX=maybe",
      }),
    });
    const scheduled = await schedule(service, {
      targets: [target(TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    const executed = await run(service, {
      batchId: batchIdOf(scheduled.value),
    });
    if (!executed.ok) return;
    const result = resultOf(executed.value);
    expect(result.state).toBe("blocked");
    expect(result.stop?.error_tag).toBe("SandboxStateInvalid");
    await service.closeAll();
  });

  it("reports typed cancellation during a unit and keeps the unit queued", async () => {
    const controller = new AbortController();
    let startedRun: (() => void) | undefined;
    const running = new Promise<void>((resolve) => {
      startedRun = resolve;
    });
    const { service } = await harness({
      recipeRunners: runners(
        runner(
          (_request, options) =>
            new Promise((resolve) => {
              startedRun?.();
              options?.signal?.addEventListener("abort", () => {
                resolve(
                  err(
                    new AnalysisCancelledError("re-analysis", {
                      cause: "test",
                    }),
                  ),
                );
              });
            }),
        ),
      ),
    });
    const scheduled = await schedule(service, {
      targets: [target(TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    const batchId = batchIdOf(scheduled.value);
    const pending = service.runNext(
      { batchId, maxUnitSeconds: undefined },
      { signal: controller.signal },
    );
    await running;
    controller.abort("caller stopped");
    const executed = await pending;
    expect(executed.ok).toBe(true);
    if (!executed.ok) return;
    const result = resultOf(executed.value);
    expect(result.state).toBe("stopped");
    expect(result.stop?.kind).toBe("cancelled");
    expect(result.queue.queued).toBe(1);
    const queued = await service.read({ batchId, offset: 0, limit: 10 });
    expect(queued.ok && queued.value.units[0]?.state).toBe("queued");
    expect(queued.ok && queued.value.units[0]?.attempt).toBe(1);
    await service.closeAll();
  });
});

describe("hunting queue cancellation and unknowns", () => {
  it("records one residual unknown for a unit that did not complete", async () => {
    const unknowns = new FakeUnknowns();
    const { service } = await harness({
      recipeRunners: runners(
        runner(async () =>
          err(
            new AnalysisCapabilityUnavailableError(
              HUNTING_PROVIDER.id,
              "binary_overview",
              "no admitted target",
            ),
          ),
        ),
      ),
      unknowns,
    });
    const scheduled = await schedule(service, {
      targets: [target(TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    await run(service, { batchId: batchIdOf(scheduled.value) });
    expect(unknowns.recorded).toHaveLength(1);
    expect(unknowns.recorded[0]?.domain).toBe("hunting");
    expect(unknowns.recorded[0]?.supporting_evidence_ids).toHaveLength(1);
    await service.closeAll();
  });

  it("cancels every unit a batch had not started", async () => {
    const { service } = await harness({
      recipeRunners: runners(
        runner(async () => ok(observation("binary_overview"))),
      ),
    });
    const scheduled = await schedule(service, {
      targets: [target(TARGET), target(OTHER_TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    const batchId = batchIdOf(scheduled.value);
    const cancelled = await service.cancel({ batchId });
    expect(cancelled.ok).toBe(true);
    if (!cancelled.ok) return;
    expect(
      (
        cancelled.value.normalized_result as {
          readonly cancelled_units: number;
        }
      ).cancelled_units,
    ).toBe(2);
    const executed = await run(service, { batchId });
    if (!executed.ok) return;
    expect(resultOf(executed.value).batch_state).toBe("cancelled");
    const repeated = await service.cancel({ batchId });
    expect(
      repeated.ok &&
        (
          repeated.value.normalized_result as {
            readonly cancelled_units: number;
          }
        ).cancelled_units,
    ).toBe(0);
    await service.closeAll();
  });
});

describe("hunting queue durability", () => {
  it("resumes the same queue after a restart", async () => {
    const directory = await createTestTempDirectory("hunting-resume-");
    const stateDirectory = join(directory, "state");
    const first = new HuntingQueueService({
      environment: {},
      runners: runners(runner(async () => ok(observation("binary_overview")))),
      createStore: () => new HuntingQueueStore(stateDirectory, "darwin"),
      timers: new ManualTimers(),
      sandboxState: () => ({ kind: "enabled" }),
      now: () => "2026-10-28T00:00:00.000Z",
    });
    const scheduled = await schedule(first, {
      targets: [target(TARGET), target(OTHER_TARGET)],
      recipes: [reanalysis],
    });
    if (!scheduled.ok) return;
    const batchId = batchIdOf(scheduled.value);
    const executed = await run(first, { batchId });
    expect(executed.ok && resultOf(executed.value).state).toBe("succeeded");
    expect((await first.closeAll()).ok).toBe(true);

    const second = new HuntingQueueService({
      environment: {},
      runners: runners(runner(async () => ok(observation("list_procedures")))),
      createStore: () => new HuntingQueueStore(stateDirectory, "darwin"),
      timers: new ManualTimers(),
      sandboxState: () => ({ kind: "enabled" }),
      now: () => "2026-10-28T00:01:00.000Z",
    });
    const read = await second.read({ batchId, offset: 0, limit: 10 });
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    expect(read.value.totals.units).toBe(2);
    expect(
      read.value.units.filter((unit) => unit.state === "queued"),
    ).toHaveLength(1);
    const resumed = await run(second, { batchId });
    expect(resumed.ok && resultOf(resumed.value).state).toBe("succeeded");
    expect(resumed.ok && resultOf(resumed.value).queue.succeeded).toBe(2);
    await second.closeAll();

    const file = join(stateDirectory, "queue.sqlite");
    expect((await stat(file)).size).toBeGreaterThan(0);
    expect((await readFile(file)).byteLength).toBeGreaterThan(0);
  });

  it("returns a running unit to the queue as interrupted when the process stopped", async () => {
    const directory = await createTestTempDirectory("hunting-interrupted-");
    const store = new HuntingQueueStore(directory, "darwin");
    await store.ensure();
    store.createBatch(
      {
        batchId: "2f1c9d4e-0b6a-4c8f-9e37-5a1f0d2b7c33",
        createdAt: "2026-10-28T00:00:00.000Z",
        maxUnits: 4,
        maxSeconds: 60,
      },
      [
        {
          unitId: `hunt_${"d".repeat(64)}`,
          position: 0,
          targetPath: TARGET,
          recipe: reanalysis,
          priority: { score: 5, reasons: [] },
        },
      ],
    );
    store.beginUnit(`hunt_${"d".repeat(64)}`, "2026-10-28T00:00:01.000Z");
    await store.close();

    const reopened = new HuntingQueueStore(directory, "darwin");
    await reopened.ensure();
    const unit = reopened.unit(`hunt_${"d".repeat(64)}`);
    expect(unit?.state).toBe("queued");
    expect(unit?.stop).toEqual({
      kind: "interrupted",
      error_tag: null,
      operation: null,
    });
    await reopened.close();
  });
});

describe("hunting watch sessions", () => {
  it("enqueues one re-analysis unit per observed change without analyzing inside the watch", async () => {
    const snapshots = [
      snapshot([{ path: "target.bin", bytes: 4, mtime_ms: 1 }]),
      snapshot([{ path: "target.bin", bytes: 8, mtime_ms: 2 }]),
    ];
    let call = 0;
    const { service, timers } = await harness({
      observer: {
        snapshot: async () => {
          const value = snapshots[Math.min(call, snapshots.length - 1)]!;
          call += 1;
          return value;
        },
      },
    });
    const request: StartHuntingWatchRequest = {
      source: { kind: "directory", path: "/cases/api/build", recursive: true },
      target: target(TARGET),
      operation: "binary_overview",
      intervalMs: 1_000,
      maxTriggers: 4,
      maxUnits: undefined,
      maxSeconds: undefined,
    };
    const started = await service.startWatch(request);
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const session = huntingWatchStartResultSchema.parse(
      started.value.normalized_result,
    );
    expect(session.triggers).toBe(0);
    expect(session.batch_id).toBeNull();
    timers.fire();
    await waitFor(async () => {
      const read = await service.read({
        batchId: undefined,
        offset: 0,
        limit: 10,
      });
      return read.ok && read.value.totals.units === 1;
    });
    const read = await service.read({
      batchId: undefined,
      offset: 0,
      limit: 10,
    });
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    expect(read.value.units[0]?.recipe_kind).toBe("re-analysis");
    expect(read.value.units[0]?.target_path).toBe(TARGET);

    const stopped = await service.stopWatch({ sessionId: session.session_id });
    expect(stopped.ok).toBe(true);
    if (!stopped.ok) return;
    const facts = stopped.value.normalized_result as {
      readonly triggers: number;
      readonly queued_units: number;
      readonly released: boolean;
    };
    expect(facts.triggers).toBe(1);
    expect(facts.queued_units).toBe(1);
    expect(facts.released).toBe(true);
    await service.closeAll();
  });

  it("stops observing at its trigger budget", async () => {
    let call = 0;
    const { service, timers } = await harness({
      observer: {
        snapshot: async () => {
          call += 1;
          return snapshot([
            { path: "target.bin", bytes: call, mtime_ms: call },
          ]);
        },
      },
    });
    const started = await service.startWatch({
      source: { kind: "directory", path: "/cases/api/build", recursive: true },
      target: target(TARGET),
      operation: "list_strings",
      intervalMs: 1_000,
      maxTriggers: 1,
      maxUnits: undefined,
      maxSeconds: undefined,
    });
    if (!started.ok) return;
    const session = huntingWatchStartResultSchema.parse(
      started.value.normalized_result,
    );
    timers.fire();
    await waitFor(async () => {
      const read = await service.read({
        batchId: undefined,
        offset: 0,
        limit: 10,
      });
      return read.ok && read.value.totals.units === 1;
    });
    const stopped = await service.stopWatch({ sessionId: session.session_id });
    // The session retired itself at the trigger budget, so its identity is gone.
    expect(stopped.ok).toBe(false);
    if (stopped.ok) return;
    expect(stopped.error).toBeInstanceOf(AnalysisInputError);
    await service.closeAll();
  });
});

describe("hunting watch lifecycle", () => {
  it("refuses a device or endpoint source with a typed unavailable state", async () => {
    const { service } = await harness();
    const refused = await service.startWatch({
      source: { kind: "endpoint", url: "https://example.test/health" },
      target: target(TARGET),
      operation: "binary_overview",
      intervalMs: 1_000,
      maxTriggers: 1,
      maxUnits: undefined,
      maxSeconds: undefined,
    });
    expect(refused.ok).toBe(false);
    if (refused.ok) return;
    expect(refused.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    await service.closeAll();
  });

  it("returns typed cancellation when the start call is aborted during the baseline read", async () => {
    const controller = new AbortController();
    let baselineStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      baselineStarted = resolve;
    });
    const { service } = await harness({
      observer: {
        snapshot: (_root, _recursive, signal) =>
          new Promise((_resolve, reject) => {
            baselineStarted?.();
            signal.addEventListener("abort", () => {
              reject(
                new AnalysisCancelledError("start_watch_session", {
                  cause: "stop",
                }),
              );
            });
          }),
      },
    });
    const pending = service.startWatch(
      {
        source: {
          kind: "directory",
          path: "/cases/api/build",
          recursive: true,
        },
        target: target(TARGET),
        operation: "binary_overview",
        intervalMs: 1_000,
        maxTriggers: 1,
        maxUnits: undefined,
        maxSeconds: undefined,
      },
      { signal: controller.signal },
    );
    await started;
    controller.abort("caller stopped");
    const observed = await pending;
    expect(observed.ok).toBe(false);
    if (observed.ok) return;
    expect(observed.error).toBeInstanceOf(AnalysisCancelledError);
    await service.closeAll();
  });

  it("returns typed cancellation with the partial observation when the stop call is aborted", async () => {
    const { service } = await harness({
      observer: { snapshot: async () => snapshot([]) },
    });
    const started = await service.startWatch({
      source: { kind: "directory", path: "/cases/api/build", recursive: true },
      target: target(TARGET),
      operation: "binary_overview",
      intervalMs: 1_000,
      maxTriggers: 2,
      maxUnits: undefined,
      maxSeconds: undefined,
    });
    if (!started.ok) return;
    const session = huntingWatchStartResultSchema.parse(
      started.value.normalized_result,
    );
    const controller = new AbortController();
    controller.abort("caller stopped");
    const stopped = await service.stopWatch(
      { sessionId: session.session_id },
      { signal: controller.signal },
    );
    expect(stopped.ok).toBe(false);
    if (stopped.ok) return;
    expect(stopped.error).toBeInstanceOf(AnalysisCancelledError);
    const partial = stopped.error.partialObservation as
      | { readonly normalized_result: { readonly released: boolean } }
      | undefined;
    expect(partial).toBeDefined();
    expect(partial?.normalized_result.released).toBe(true);
    await service.closeAll();
  });

  it("retains the session when the owned timer cannot be released", async () => {
    const { service, timers } = await harness({
      observer: { snapshot: async () => snapshot([]) },
    });
    const started = await service.startWatch({
      source: { kind: "directory", path: "/cases/api/build", recursive: true },
      target: target(TARGET),
      operation: "binary_overview",
      intervalMs: 1_000,
      maxTriggers: 2,
      maxUnits: undefined,
      maxSeconds: undefined,
    });
    if (!started.ok) return;
    const session = huntingWatchStartResultSchema.parse(
      started.value.normalized_result,
    );
    timers.failNextClear();
    const failed = await service.stopWatch({ sessionId: session.session_id });
    expect(failed.ok).toBe(false);
    if (failed.ok) return;
    expect(failed.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    const retried = await service.stopWatch({ sessionId: session.session_id });
    expect(retried.ok).toBe(true);
    await service.closeAll();
  });
});
