import { z } from "zod";

import { prefixedDigestSchema } from "../digests.js";
import {
  huntingRecipeKindSchema,
  huntingReanalysisOperationSchema,
} from "./huntingRecipes.js";
import { huntingPriorityReasons } from "./huntingPriority.js";

const evidenceIdSchema = prefixedDigestSchema("ev");
const unitIdSchema = prefixedDigestSchema("hunt");

/** Lifecycle state of one queued unit. */
export const huntingUnitStates = [
  "queued",
  "running",
  "blocked",
  "succeeded",
  "failed",
  "stopped",
  "cancelled",
] as const;
export const huntingUnitStateSchema = z.enum(huntingUnitStates);
export type HuntingUnitState = z.infer<typeof huntingUnitStateSchema>;

/** Lifecycle state of one scheduled batch. */
export const huntingBatchStates = [
  "open",
  "exhausted",
  "complete",
  "cancelled",
] as const;
export const huntingBatchStateSchema = z.enum(huntingBatchStates);
export type HuntingBatchState = z.infer<typeof huntingBatchStateSchema>;

/** Why a unit ended without completing its recipe. */
export const huntingStopKinds = [
  "unit_budget",
  "batch_budget",
  "cancelled",
  "precondition",
  "runner_failure",
  "interrupted",
] as const;
export const huntingStopKindSchema = z.enum(huntingStopKinds);
export type HuntingStopKind = z.infer<typeof huntingStopKindSchema>;

/**
 * Typed stop facts. No message text enters this record: a composed runner's
 * diagnostics can carry target-authored prose, so only its error tag and
 * operation name are retained.
 */
export const huntingStopSchema = z.strictObject({
  kind: huntingStopKindSchema.describe(
    "unit_budget: the unit's own deadline elapsed. batch_budget: the batch reached its declared unit or wall-clock budget. cancelled: the caller aborted or cancelled the batch. precondition: a named requirement is not satisfied, such as an admitted target. runner_failure: the composed capability reported a failure. interrupted: the process stopped while this unit was running.",
  ),
  error_tag: z
    .string()
    .min(1)
    .nullable()
    .describe("Tagged error class the composed runner reported, or null."),
  operation: z
    .string()
    .min(1)
    .nullable()
    .describe("Operation the composed runner was executing, or null."),
});
export type HuntingStop = z.infer<typeof huntingStopSchema>;

/** Counted reason the queue ordered one unit where it did. */
export const huntingPriorityReasonSchema = z.strictObject({
  kind: z.enum(huntingPriorityReasons),
  count: z.int().min(0),
  weight: z.int().min(0),
});
export const huntingPrioritySchema = z.strictObject({
  score: z.int().min(0),
  reasons: z.array(huntingPriorityReasonSchema),
});
export type HuntingPriorityFacts = z.infer<typeof huntingPrioritySchema>;

/** Identity and ordering facts of one queued unit. */
export const huntingUnitFactSchema = z.strictObject({
  unit_id: unitIdSchema,
  batch_id: z.string().uuid(),
  recipe_kind: huntingRecipeKindSchema,
  target_path: z.string().min(1),
  operation: huntingReanalysisOperationSchema
    .nullable()
    .describe(
      "Inspection this unit repeats when its recipe is re-analysis; null for every other recipe.",
    ),
  state: huntingUnitStateSchema,
  attempt: z.int().min(0),
  priority: huntingPrioritySchema,
  updated_at: z.string().min(1),
});
export type HuntingUnitFact = z.infer<typeof huntingUnitFactSchema>;

/** Composed observation retained for one completed unit. */
export const huntingObservationFactsSchema = z.strictObject({
  evidence_id: evidenceIdSchema.describe(
    "Retained Evidence identity of the composed capability's observation; read it with get_evidence_bundle.",
  ),
  provider_id: z.string().min(1),
  operation: z.string().min(1),
  confidence: z.enum(["observed", "derived", "inferred"]),
  result_sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .describe("Canonical digest of the retained observation's result."),
  limitations: z.array(z.string().min(1)),
});
export type HuntingObservationFacts = z.infer<
  typeof huntingObservationFactsSchema
>;

/** Queue counters at the moment one call observed them. */
export const huntingQueueCountsSchema = z.strictObject({
  queued: z.int().min(0),
  running: z.int().min(0),
  blocked: z.int().min(0),
  succeeded: z.int().min(0),
  failed: z.int().min(0),
  stopped: z.int().min(0),
  cancelled: z.int().min(0),
  total: z.int().min(0),
  next_unit_id: unitIdSchema.nullable(),
});
export type HuntingQueueCounts = z.infer<typeof huntingQueueCountsSchema>;

/** Batch budget as the batch recorded it. */
export const huntingBatchBudgetSchema = z.strictObject({
  max_units: z.int().min(1),
  max_seconds: z.int().min(1),
  units_started: z.int().min(0),
  spent_ms: z.int().min(0),
});
export type HuntingBatchBudget = z.infer<typeof huntingBatchBudgetSchema>;

/** Result of scheduling one batch. */
export const huntingScheduleResultSchema = z.strictObject({
  batch_id: z.string().uuid(),
  created_at: z.string().min(1),
  state: huntingBatchStateSchema,
  budget: huntingBatchBudgetSchema,
  units: z.array(huntingUnitFactSchema),
  limitations: z.array(z.string().min(1)),
});
export type HuntingScheduleResult = z.infer<typeof huntingScheduleResultSchema>;

/** Unit budget applied to one run, with the precedence that selected it. */
export const huntingUnitBudgetSchema = z.strictObject({
  unit_ms: z.int().min(1),
  source: z
    .enum(["request", "setting"])
    .describe(
      "request: the call's max_unit_seconds was tighter. setting: the hunting.max_unit_seconds setting applied.",
    ),
  batch_remaining_seconds: z.int().min(0),
  batch_remaining_units: z.int().min(0),
});
export type HuntingUnitBudget = z.infer<typeof huntingUnitBudgetSchema>;

/** Result of executing the next queued unit. */
export const huntingRunResultSchema = z.strictObject({
  batch_id: z.string().uuid().nullable(),
  batch_state: huntingBatchStateSchema.nullable(),
  unit: huntingUnitFactSchema
    .nullable()
    .describe(
      "The unit this call admitted, or null when the queue had no runnable unit.",
    ),
  state: huntingUnitStateSchema
    .nullable()
    .describe("The admitted unit's state after this call, or null."),
  stop: huntingStopSchema.nullable(),
  observation: huntingObservationFactsSchema.nullable(),
  budget: huntingUnitBudgetSchema.nullable(),
  elapsed_ms: z.int().min(0),
  sandbox: z
    .enum(["enabled", "disabled"])
    .describe(
      "Whether this host's deny-default sandbox is in effect for composed launches; disabled carries the operator's emergency-exit limitation.",
    ),
  queue: huntingQueueCountsSchema,
  limitations: z.array(z.string().min(1)),
});
export type HuntingRunResult = z.infer<typeof huntingRunResultSchema>;

/** Result of reading the durable queue. */
export const huntingQueueReadResultSchema = z.strictObject({
  batches: z.array(
    z.strictObject({
      batch_id: z.string().uuid(),
      created_at: z.string().min(1),
      state: huntingBatchStateSchema,
      budget: huntingBatchBudgetSchema,
    }),
  ),
  units: z.array(huntingUnitFactSchema),
  totals: z.strictObject({
    batches: z.int().min(0),
    units: z.int().min(0),
    matching_units: z.int().min(0),
  }),
  offset: z.int().min(0),
  limit: z.int().min(1),
  next_offset: z.int().min(0).nullable(),
  limitations: z.array(z.string().min(1)),
});
export type HuntingQueueReadResult = z.infer<
  typeof huntingQueueReadResultSchema
>;

/** Result of cancelling one batch. */
export const huntingCancelResultSchema = z.strictObject({
  batch_id: z.string().uuid(),
  state: huntingBatchStateSchema,
  cancelled_units: z.int().min(0),
  units_in_flight: z.int().min(0),
  limitations: z.array(z.string().min(1)),
});
export type HuntingCancelResult = z.infer<typeof huntingCancelResultSchema>;

/** Directory watch source echoed by a started session. */
export const huntingWatchSourceFactsSchema = z.strictObject({
  kind: z.literal("directory"),
  path: z.string().min(1),
  recursive: z.boolean(),
});

/** Result of starting one watch session. */
export const huntingWatchStartResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  source: huntingWatchSourceFactsSchema,
  interval_ms: z.int().min(1),
  state: z.enum(["watching", "stopped"]),
  triggers: z.int().min(0),
  triggers_limit: z.int().min(1),
  queued_units: z.int().min(0),
  batch_id: z
    .string()
    .uuid()
    .nullable()
    .describe(
      "Batch this session enqueues into; created with the first observed change.",
    ),
  limitations: z.array(z.string().min(1)),
});
export type HuntingWatchStartResult = z.infer<
  typeof huntingWatchStartResultSchema
>;

/** Result of stopping one watch session. */
export const huntingWatchStopResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  state: z.enum(["watching", "stopped"]),
  triggers: z.int().min(0),
  queued_units: z.int().min(0),
  batch_id: z.string().uuid().nullable(),
  released: z
    .boolean()
    .describe(
      "Whether the owned timer and any in-flight directory read were released by this call.",
    ),
  stop: huntingStopSchema.nullable(),
  limitations: z.array(z.string().min(1)),
});
export type HuntingWatchStopResult = z.infer<
  typeof huntingWatchStopResultSchema
>;
