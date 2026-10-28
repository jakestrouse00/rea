import { z } from "zod";

import {
  HUNTING_LIMITS,
  HUNTING_DEFAULT_WATCH_INTERVAL_MS,
  HUNTING_DEFAULT_WATCH_TRIGGERS,
} from "../../domain/hunting/huntingLimits.js";
import {
  huntingReanalysisOperationSchema,
  huntingRecipeSchema,
  huntingTargetSchema,
} from "../../domain/hunting/huntingRecipes.js";
import { huntingWatchSourceSchema } from "../../domain/hunting/huntingWatch.js";

const batchBudgetShape = {
  max_units: z
    .int()
    .min(1)
    .max(HUNTING_LIMITS.maxUnitsPerBatch)
    .optional()
    .describe(
      `Units this batch may start before it is exhausted; at most ${String(HUNTING_LIMITS.maxUnitsPerBatch)}. Omitted means one slot per queued unit.`,
    ),
  max_seconds: z
    .int()
    .min(1)
    .max(HUNTING_LIMITS.maxBatchSeconds)
    .optional()
    .describe(
      `Wall clock this batch may spend across admitted units; also capped by the hunting.max_batch_seconds setting. Omitted means that setting.`,
    ),
};

/** Queue one target list against one recipe list with a declared budget. */
export const scheduleInvestigationBatchInputSchema = z.strictObject({
  targets: z
    .array(huntingTargetSchema)
    .min(1)
    .max(HUNTING_LIMITS.maxTargets)
    .describe(
      "Investigation targets. Each carries the completion ledger and residual-unknown identities that order its units; nothing about a target is inferred from its path.",
    ),
  recipes: z
    .array(huntingRecipeSchema)
    .min(1)
    .max(HUNTING_LIMITS.maxRecipes)
    .describe(
      "Task recipes. Every target is paired with every recipe, so N targets × M recipes queues N×M units.",
    ),
  budget: z.strictObject(batchBudgetShape).optional(),
});

/** Admit the next queueable unit of one batch, or of the oldest runnable batch. */
export const runScheduledBatchInputSchema = z.strictObject({
  batch_id: z
    .string()
    .uuid()
    .optional()
    .describe(
      "Batch to admit from. Omitted means the oldest batch that still has a runnable unit.",
    ),
  max_unit_seconds: z
    .int()
    .min(1)
    .max(HUNTING_LIMITS.maxUnitSeconds)
    .optional()
    .describe(
      "Deadline for this unit; the tighter of this value and the hunting.max_unit_seconds setting applies.",
    ),
});

/** Read one page of the durable queue. */
export const readHuntingQueueInputSchema = z.strictObject({
  batch_id: z
    .string()
    .uuid()
    .optional()
    .describe("Report only this batch's units; omitted reports every batch."),
  offset: z.int().min(0).default(0),
  limit: z
    .int()
    .min(1)
    .max(HUNTING_LIMITS.maxQueuePage)
    .default(HUNTING_LIMITS.defaultQueuePage),
});

/** Release every unit of one batch that has not started. */
export const cancelHuntingBatchInputSchema = z.strictObject({
  batch_id: z.string().uuid(),
});

/** Observe one source and enqueue re-analysis for one target on each change. */
export const startWatchSessionInputSchema = z.strictObject({
  source: huntingWatchSourceSchema.describe(
    "What to observe. A directory tree is watched this release; a device or endpoint source is refused with a typed unavailable state.",
  ),
  target: huntingTargetSchema.describe(
    "Investigation target whose re-analysis each observed change enqueues, with the ledger and unknown facts that order it.",
  ),
  operation: huntingReanalysisOperationSchema
    .default("binary_overview")
    .describe("Inspection each triggered re-analysis unit repeats."),
  interval_ms: z
    .int()
    .min(HUNTING_LIMITS.minWatchIntervalMs)
    .max(HUNTING_LIMITS.maxWatchIntervalMs)
    .default(HUNTING_DEFAULT_WATCH_INTERVAL_MS)
    .describe(
      `Observation interval. A tick that is still running is not overlapped; the next tick is skipped instead.`,
    ),
  max_triggers: z
    .int()
    .min(1)
    .max(HUNTING_LIMITS.maxWatchTriggers)
    .default(HUNTING_DEFAULT_WATCH_TRIGGERS)
    .describe(
      `Units this session may enqueue before it stops observing; at most ${String(HUNTING_LIMITS.maxWatchTriggers)}.`,
    ),
  budget: z.strictObject(batchBudgetShape).optional(),
});

/** Release one watch session's timer and any in-flight observation. */
export const stopWatchSessionInputSchema = z.strictObject({
  session_id: z
    .string()
    .uuid()
    .describe(
      "Watch session identity start_watch_session issued for this REA server's lifetime.",
    ),
});
