/** Identity, bounds, and operator-facing guidance for the hunting queue. */
export const HUNTING_PROVIDER = {
  id: "rea-hunting-queue",
  name: "REA hunting queue",
  version: "1",
} as const;

/** Public operation names owned by this lane. */
export const HUNTING_OPERATIONS = {
  schedule: "schedule_investigation_batch",
  run: "run_scheduled_batch",
  read: "read_hunting_queue",
  cancel: "cancel_hunting_batch",
  watchStart: "start_watch_session",
  watchStop: "stop_watch_session",
} as const;

/**
 * Fixed allowances. A caller may schedule less, never more; REA refuses an
 * oversized request instead of clamping it.
 */
export const HUNTING_LIMITS = {
  maxTargets: 16,
  maxRecipes: 8,
  maxUnitsPerBatch: 128,
  maxUnknownIdsPerTarget: 32,
  maxQueuePage: 100,
  defaultQueuePage: 25,
  maxWatchTriggers: 256,
  maxWatchEntries: 4_096,
  maxWatchPathsPerTick: 16,
  minWatchIntervalMs: 1_000,
  maxWatchIntervalMs: 3_600_000,
  maxLiveWatches: 4,
  maxUnitSeconds: 86_400,
  maxBatchSeconds: 86_400,
} as const;

/** Agent-editable defaults; both are also runtime settings. */
export const HUNTING_DEFAULT_UNIT_SECONDS = 300;
export const HUNTING_DEFAULT_BATCH_SECONDS = 1_800;
export const HUNTING_DEFAULT_WATCH_INTERVAL_MS = 5_000;
export const HUNTING_DEFAULT_WATCH_TRIGGERS = 32;

/**
 * Priority weights. The score is derived only from a caller-supplied coverage
 * ledger and residual-unknown facts, so the same queue always orders the same
 * way; no timing or provider prose enters it.
 */
export const HUNTING_PRIORITY_WEIGHTS = {
  coverageFail: 40,
  coverageTruncated: 20,
  coverageUnknown: 10,
  coverageMissing: 5,
  unknownCritical: 80,
  unknownHigh: 40,
  unknownMedium: 15,
  unknownLow: 5,
  maximumScore: 1_000_000,
} as const;

/** This lane starts no child of its own; every launch belongs to a composed lane. */
export const HUNTING_LAUNCH_NOTE =
  "This lane starts no subprocess. Every unit delegates to the capability that owns the work (the admitted analysis owner, the fuzz loop, the protocol probe lane, or a replay plane), and that owner confines its own launch and reports its own limitations. A unit reports only what the composed runner observed.";

/** A watch triggers queued work; it never analyzes inside the watch itself. */
export const HUNTING_WATCH_NOTE =
  "A watch session only enqueues re-analysis units for the paths it observed change. Nothing is analyzed inside the watch: the next run_scheduled_batch call executes the queued unit, so a watch never consumes analysis time the caller did not ask for.";

/** Directory watch is real this release; device and endpoint sources are not. */
export const HUNTING_WATCH_SOURCE_LIMITATION =
  "This release watches one directory tree. A device or endpoint watch source is refused with a typed unavailable state because no watcher for it is composed yet.";

/** Budget stops are retryable; the queued unit is not consumed. */
export const HUNTING_BUDGET_NOTE =
  "A unit that reaches its deadline, or a batch that reaches its unit or wall-clock budget, ends with a typed stop and stays queued. No unit is retried automatically; the next run_scheduled_batch call admits it again.";

/** Blocked units report a precondition, never a completed observation. */
export const HUNTING_BLOCKED_NOTE =
  "A blocked unit names a precondition this server cannot satisfy right now, such as a re-analysis target that is not the admitted analysis target. It stays in the queue and is retried after every queued unit.";

/** Unknowns recorded per unit execution keep the unit's own Evidence identity. */
export const HUNTING_UNKNOWN_NOTE =
  "A unit that does not complete records one residual unknown scoped to its own unit Evidence, so the unfinished claim stays visible instead of being reported as done.";

/** Re-analysis runs against the admitted target only. */
export const HUNTING_REANALYSIS_REMEDIATION =
  "Open the unit's target with open_binary first: a re-analysis unit runs one inspection operation over the server's admitted analysis target, and refuses to analyze a different path.";

/** The queue store is durable by design. */
export const HUNTING_STORE_NOTE =
  "The queue, its batches, and its watch sessions live in an owner-only SQLite file under the REA home state directory, so a restarted REA resumes the same queue. A unit that was running when the process stopped returns to queued with an interrupted stop reason.";

/** Path of the durable queue file, relative to the REA home directory. */
export const HUNTING_STATE_RELATIVE_DIRECTORY = ["state", "hunting"] as const;
export const HUNTING_QUEUE_FILE_NAME = "queue.sqlite";

/** Sandbox reporting the queue attaches to the launches it admits. */
export const HUNTING_SANDBOX = {
  /** An unrecognized REA_DISABLE_SANDBOX value refuses the unit instead of guessing. */
  invalid:
    "REA_DISABLE_SANDBOX holds a value REA cannot interpret, so this unit cannot be admitted under a known confinement state. Set it to 1/true/yes/on to disable confinement deliberately, or remove it.",
  /** A device or endpoint watcher is not composed this release. */
  unwatchedSource:
    "This release watches a directory tree only. A device or endpoint watch source needs a watcher that is not composed here, so no session was started.",
  /** The emergency exit is reported, never assumed away. */
  disabled: (unitCount: number): string =>
    `REA_DISABLE_SANDBOX disabled the deny-default sandbox profile for the launches of ${String(unitCount)} unit(s); the composed capabilities' subprocesses are not confined on this host.`,
} as const;
