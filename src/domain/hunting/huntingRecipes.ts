import { z } from "zod";

import { digestCanonicalValue } from "../canonicalDigest.js";
import { prefixedDigestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import { evidenceCompletionLedgerSchema } from "../evidenceCompletionLedger.js";
import { probeLearnedModelInputSchema } from "../protolearn/protocolLearningInputs.js";
import { fuzzingEngineSchema } from "../fuzzing/fuzzingEngine.js";
import { sanitizerClassSchema } from "../crashTriage/crashReport.js";
import { REPLAY_LIMITS } from "../replay/replayLimits.js";
import { HUNTING_LIMITS } from "./huntingLimits.js";

/** Recipe kinds this release executes. */
export const huntingRecipeKinds = [
  "re-analysis",
  "fuzz-campaign",
  "probe",
  "replay",
] as const;
export const huntingRecipeKindSchema = z.enum(huntingRecipeKinds);
export type HuntingRecipeKind = z.infer<typeof huntingRecipeKindSchema>;

/**
 * Inspection operations a re-analysis unit may re-run. The set is closed so a
 * scheduled unit cannot ask the admitted analysis owner for an operation this
 * lane has not audited for repetition.
 */
export const huntingReanalysisOperations = [
  "binary_overview",
  "list_procedures",
  "list_strings",
] as const;
export const huntingReanalysisOperationSchema = z.enum(
  huntingReanalysisOperations,
);
export type HuntingReanalysisOperation = z.infer<
  typeof huntingReanalysisOperationSchema
>;

/** Re-run one inspection over the server's admitted analysis target. */
export const huntingReanalysisRecipeSchema = z.strictObject({
  kind: z.literal("re-analysis"),
  operation: huntingReanalysisOperationSchema.describe(
    "Inspection to repeat: binary_overview, list_procedures, or list_strings.",
  ),
});

/** Launch one already-registered fuzz campaign through the fuzz loop. */
export const huntingFuzzRecipeSchema = z.strictObject({
  kind: z.literal("fuzz-campaign"),
  campaign_id: z
    .string()
    .uuid()
    .describe("Campaign identity register_fuzzing_campaign returned."),
  engine: fuzzingEngineSchema.describe(
    "Engine adapter the fuzz loop drives for this unit.",
  ),
  pov_repeats: z
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe(
      "Reproductions per candidate crash; the fuzz loop's default when omitted.",
    ),
  expected_sanitizer: sanitizerClassSchema
    .optional()
    .describe("Sanitizer class an accepted crash must report."),
  minimize_crashes: z
    .boolean()
    .default(false)
    .describe(
      "Also minimize each accepted crash through the crash-triage seam.",
    ),
});

/** Probe one learned protocol model against one operator-allowlisted lab socket. */
export const huntingProbeRecipeSchema = z.strictObject({
  kind: z.literal("probe"),
  ...probeLearnedModelInputSchema.pick({
    endpoint: true,
    model_path: true,
    probes: true,
    repeats: true,
  }).shape,
});

/** Re-send one captured entry through an existing replay plane. */
export const huntingReplaySessionSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("replay"),
    session_id: z
      .string()
      .uuid()
      .describe("Session identity http_replay_session_start issued."),
    entry_ordinal: z
      .int()
      .min(0)
      .nullable()
      .default(null)
      .describe(
        "Capture entry to send, or null for the session's draft request.",
      ),
  }),
  z.strictObject({
    kind: z.literal("mitm"),
    session_id: z
      .string()
      .uuid()
      .describe("Session identity start_interception_session issued."),
    sequence: z
      .int()
      .min(0)
      .describe("Captured entry sequence the interception inventory reported."),
  }),
]);

/** Replay one captured exchange through the plane that owns the session. */
export const huntingReplayRecipeSchema = z.strictObject({
  kind: z.literal("replay"),
  session: huntingReplaySessionSchema,
  timeout_ms: z
    .int()
    .min(1)
    .max(REPLAY_LIMITS.maxTimeoutMs)
    .optional()
    .describe(
      "Deadline of the composed send; that plane's default when omitted.",
    ),
  follow_redirects: z.boolean().default(false),
});

/** One executable unit recipe. */
export const huntingRecipeSchema = z.discriminatedUnion("kind", [
  huntingReanalysisRecipeSchema,
  huntingFuzzRecipeSchema,
  huntingProbeRecipeSchema,
  huntingReplayRecipeSchema,
]);
export type HuntingRecipe = z.output<typeof huntingRecipeSchema>;
export type HuntingRecipeInput = z.input<typeof huntingRecipeSchema>;

const unknownIdSchema = prefixedDigestSchema("unk");

/** One investigation target with the facts that order its units. */
export const huntingTargetSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute local path of the investigation target this batch advances; relative paths are rejected.",
  ),
  coverage: evidenceCompletionLedgerSchema
    .nullable()
    .default(null)
    .describe(
      "Completion ledger this target's verifier produced, used only to order work. Omit when no ledger exists; a missing ledger is unknown coverage, never complete.",
    ),
  unknown_ids: z
    .array(unknownIdSchema)
    .max(HUNTING_LIMITS.maxUnknownIdsPerTarget)
    .default([])
    .describe(
      "Residual-unknown heads that scope this target. Each must already exist in this session's registry; priority rises with severity and unresolved status.",
    ),
});
export type HuntingTarget = z.output<typeof huntingTargetSchema>;
export type HuntingTargetInput = z.input<typeof huntingTargetSchema>;

/** Deterministic unit identity from the batch slot, target, and recipe. */
export const huntingUnitId = (
  batchId: string,
  position: number,
  targetPath: string,
  recipe: HuntingRecipe,
): string =>
  `hunt_${digestCanonicalValue(
    { batch_id: batchId, position, target_path: targetPath, recipe },
    "Hunting unit",
  )}`;
