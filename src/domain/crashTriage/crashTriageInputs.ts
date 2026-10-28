import { z } from "zod";

import { prefixedDigestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  CRASH_TRIAGE_MAX_DEDUP_GROUPS,
  CRASH_TRIAGE_MAX_SEEDS,
  crashStateFramesField,
  fuzzingCampaignBudgetSchema,
} from "./fuzzingCampaign.js";

/** One campaign registration: target, seeds, stop condition, dedup window. */
export const registerFuzzingCampaignInputSchema = z.strictObject({
  target_path: absoluteLocalPathStringSchema.describe(
    "Absolute path to the fuzz target binary or harness REA should digest and book-keep. REA never runs it in this release.",
  ),
  seed_paths: z
    .array(absoluteLocalPathStringSchema)
    .max(CRASH_TRIAGE_MAX_SEEDS)
    .optional()
    .describe(
      `Absolute seed corpus paths, at most ${String(CRASH_TRIAGE_MAX_SEEDS)}; each is digested once at registration.`,
    ),
  budget: fuzzingCampaignBudgetSchema,
  dedup_frames: crashStateFramesField,
});

/** Campaign identity for the bookkeeping reads. */
export const campaignIdInputShape = {
  campaign_id: z
    .string()
    .uuid()
    .describe("Campaign identity issued by register_fuzzing_campaign."),
} as const;

/** One campaign's stored counters. */
export const readCampaignStatusInputSchema = z.strictObject({
  ...campaignIdInputShape,
});

/** One bounded deduplicated crash-group listing. */
export const listCrashDedupsInputSchema = z.strictObject({
  ...campaignIdInputShape,
  limit: z
    .int()
    .min(1)
    .max(CRASH_TRIAGE_MAX_DEDUP_GROUPS)
    .optional()
    .describe(
      `Largest number of deduplicated groups to return, up to ${String(CRASH_TRIAGE_MAX_DEDUP_GROUPS)}. Omit for the 50-group default; truncated marks a cut listing.`,
    ),
});

/** One stored crash inside one campaign. */
export const fetchCrashEvidenceInputSchema = z.strictObject({
  ...campaignIdInputShape,
  crash_id: prefixedDigestSchema("crash").describe(
    "Crash identity from list_crash_dedups.",
  ),
});
