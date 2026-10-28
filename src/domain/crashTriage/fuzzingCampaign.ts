import { z } from "zod";

import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  CRASH_REPORT_MAX_LABEL_CHARS,
  crashFrameSchema,
  crashReportFormatSchema,
  sanitizerClassSchema,
} from "./crashReport.js";
import {
  CRASH_STATE_DEFAULT_FRAMES,
  CRASH_STATE_MAX_FRAMES,
  crashDedupIdSchema,
} from "./crashStateHash.js";

/** Campaign states this batch can observe; a runner adds execution states later. */
export const FUZZING_CAMPAIGN_STATUSES = ["registered"] as const;

export const fuzzingCampaignStatusSchema = z.enum(FUZZING_CAMPAIGN_STATUSES);

export type FuzzingCampaignStatus = z.infer<typeof fuzzingCampaignStatusSchema>;

/** Largest number of seed inputs one campaign may register. */
export const CRASH_TRIAGE_MAX_SEEDS = 32;

/** Largest artifact REA will digest for a campaign target or seed. */
export const CRASH_TRIAGE_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;

/** Deduplicated groups one listing may return. */
export const CRASH_TRIAGE_MAX_DEDUP_GROUPS = 200;

/** Deduplicated groups returned when the caller omits `limit`. */
export const CRASH_TRIAGE_MAX_DEDUP_GROUPS_DEFAULT = 50;

/** Stored crash records one campaign may retain. */
export const CRASH_TRIAGE_MAX_CAMPAIGN_CRASHES = 5_000;

/** Stored campaign records one REA server retains. */
export const CRASH_TRIAGE_MAX_CAMPAIGNS = 32;

/** Largest execution budget a campaign may declare, in runs. */
export const CRASH_TRIAGE_MAX_RUNS = 1_000_000_000;

/** Largest execution budget a campaign may declare, in seconds (28 days). */
export const CRASH_TRIAGE_MAX_SECONDS = 2_419_200;

/** Largest number of accepted crashes a campaign may declare. */
export const CRASH_TRIAGE_MAX_CRASHES = 10_000;

const positiveBound = (maximum: number) => z.int().min(1).max(maximum);

/**
 * Declared execution budget. A campaign without one of these bounds would run
 * without a stop condition, so at least one must be present.
 */
export const fuzzingCampaignBudgetSchema = z.strictObject({
  max_runs: positiveBound(CRASH_TRIAGE_MAX_RUNS)
    .nullable()
    .optional()
    .describe("Execution budget in engine runs, or null for no run bound."),
  max_seconds: positiveBound(CRASH_TRIAGE_MAX_SECONDS)
    .nullable()
    .optional()
    .describe(
      "Execution budget in wall-clock seconds, or null for no time bound.",
    ),
  max_crashes: positiveBound(CRASH_TRIAGE_MAX_CRASHES)
    .nullable()
    .optional()
    .describe("Accepted-crash budget, or null for no crash bound."),
});

export type FuzzingCampaignBudget = z.infer<typeof fuzzingCampaignBudgetSchema>;

/** Whether a budget states at least one stop condition. */
export const fuzzingCampaignBudgetIsBounded = (
  budget: FuzzingCampaignBudget,
): boolean =>
  (budget.max_runs ?? null) !== null ||
  (budget.max_seconds ?? null) !== null ||
  (budget.max_crashes ?? null) !== null;

/** Window of top frames the crash-state hash covers. */
export const crashStateFramesField = positiveBound(CRASH_STATE_MAX_FRAMES)
  .optional()
  .describe(
    `Frames the crash-state hash covers (default ${String(CRASH_STATE_DEFAULT_FRAMES)}). Two reports group only when their first N normalized frames, sanitizer class, and crash kind agree.`,
  );

/** Target or seed artifact identity observed when the campaign was registered. */
export const campaignArtifactSchema = z.strictObject({
  path: absoluteLocalPathStringSchema,
  sha256: digestSchema,
  bytes: z.int().min(0),
});

export type CampaignArtifact = z.infer<typeof campaignArtifactSchema>;

/** One registered campaign, as the registration call observed it. */
export const fuzzingCampaignRegistrationSchema = z.strictObject({
  campaign_id: z.string().uuid(),
  status: fuzzingCampaignStatusSchema,
  target: campaignArtifactSchema,
  seeds: z.array(campaignArtifactSchema),
  budget: fuzzingCampaignBudgetSchema,
  dedup_frames: z.int().min(1).max(CRASH_STATE_MAX_FRAMES),
  registered_at: z
    .string()
    .min(1)
    .describe("When REA recorded the campaign, in UTC."),
  report_store_path: z
    .string()
    .min(1)
    .describe(
      "Private directory (owner-only) that holds retained crash report copies for this server process.",
    ),
});

export type FuzzingCampaignRegistration = z.infer<
  typeof fuzzingCampaignRegistrationSchema
>;

/** Campaign counters as stored, with no execution claim. */
export const fuzzingCampaignStatusResultSchema = z.strictObject({
  campaign_id: z.string().uuid(),
  status: fuzzingCampaignStatusSchema,
  target: campaignArtifactSchema,
  seed_count: z.int().min(0),
  seed_bytes: z.int().min(0),
  budget: fuzzingCampaignBudgetSchema,
  dedup_frames: z.int().min(1).max(CRASH_STATE_MAX_FRAMES),
  crash_count: z.int().min(0),
  dedup_count: z.int().min(0),
  last_crash_at: z.string().min(1).nullable(),
  registered_at: z.string().min(1),
  report_store_path: z.string().min(1),
});

export type FuzzingCampaignStatusResult = z.infer<
  typeof fuzzingCampaignStatusResultSchema
>;

/** One deduplicated crash group in a campaign listing. */
export const crashDedupEntrySchema = z.strictObject({
  dedup_id: crashDedupIdSchema,
  dedup_hash: digestSchema,
  crash_kind: z.string().min(1),
  sanitizer_class: sanitizerClassSchema,
  top_frames: z
    .array(z.string().min(1))
    .describe("Normalized frames the crash state hashes, in report order."),
  frame_count: z.int().min(0),
  occurrence_count: z.int().min(1),
  crash_ids: z.array(z.string().min(1)),
  first_seen_at: z.string().min(1),
  last_seen_at: z.string().min(1),
});

export type CrashDedupEntry = z.infer<typeof crashDedupEntrySchema>;

/** Bounded deduplicated group listing for one campaign. */
export const crashDedupListSchema = z.strictObject({
  campaign_id: z.string().uuid(),
  dedup_count: z.int().min(0),
  dedup_frames: z.int().min(1).max(CRASH_STATE_MAX_FRAMES),
  dedups: z.array(crashDedupEntrySchema),
  truncated: z
    .boolean()
    .describe("The caller's limit stopped the listing before every group."),
});

export type CrashDedupList = z.infer<typeof crashDedupListSchema>;

/** Retained copy of one parsed crash report. */
export const crashReportReferenceSchema = z.strictObject({
  format: crashReportFormatSchema,
  path: absoluteLocalPathStringSchema,
  sha256: digestSchema,
  bytes: z.int().min(0),
});

/** Caller-owned reproducer input referenced by a stored crash. */
export const crashReproReferenceSchema = z.strictObject({
  path: absoluteLocalPathStringSchema,
  bytes: z
    .int()
    .min(0)
    .describe(
      "Size observed when the crash was recorded; REA does not retain this file.",
    ),
  exists_now: z
    .boolean()
    .nullable()
    .describe(
      "Whether the path still existed when this call read the record; null when the observation failed.",
    ),
});

/** Structural facts for one stored crash, with no report body inlined. */
export const crashEvidenceSchema = z.strictObject({
  crash_id: z.string().min(1),
  campaign_id: z.string().uuid(),
  dedup_id: crashDedupIdSchema,
  dedup_hash: digestSchema,
  crash_kind: z.string().min(1),
  sanitizer_class: sanitizerClassSchema,
  access: z.string().min(1).nullable(),
  signal: z.string().min(1).max(CRASH_REPORT_MAX_LABEL_CHARS).nullable(),
  exception_type: z
    .string()
    .min(1)
    .max(CRASH_REPORT_MAX_LABEL_CHARS)
    .nullable(),
  termination_reason: z
    .string()
    .min(1)
    .max(CRASH_REPORT_MAX_LABEL_CHARS)
    .nullable(),
  summary: z
    .string()
    .min(1)
    .nullable()
    .describe(
      "Bounded sanitizer summary line; the complete report body stays at crash_report.path.",
    ),
  frames: z.array(crashFrameSchema),
  frames_truncated: z
    .boolean()
    .describe("The report carried more frames than the retention budget."),
  text_truncated: z
    .boolean()
    .describe(
      "A retained frame field or short report label was clipped to its text budget; the complete report body stays at crash_report.path.",
    ),
  frame_count: z.int().min(0),
  state_hash: digestSchema,
  top_frames: z.array(z.string().min(1)),
  occurrence_count: z.int().min(1),
  crash_report: crashReportReferenceSchema,
  repro_input: crashReproReferenceSchema,
  recorded_at: z.string().min(1),
  first_seen_at: z.string().min(1),
  last_seen_at: z.string().min(1),
});

export type CrashEvidenceResult = z.infer<typeof crashEvidenceSchema>;
