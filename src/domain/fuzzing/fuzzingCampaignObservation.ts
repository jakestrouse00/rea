import { z } from "zod";

import { crashMinimizeEngineSchema } from "../crashTriage/crashMinimization.js";
import { sanitizerClassSchema } from "../crashTriage/crashReport.js";
import { crashDedupIdSchema } from "../crashTriage/crashStateHash.js";
import {
  CRASH_TRIAGE_MAX_CRASHES,
  CRASH_TRIAGE_MAX_RUNS,
  CRASH_TRIAGE_MAX_SECONDS,
  fuzzingCampaignBudgetSchema,
} from "../crashTriage/fuzzingCampaign.js";
import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  fuzzingCampaignOutcomeSchema,
  fuzzingEngineSchema,
  fuzzingRouteSchema,
  fuzzingStopReasonSchema,
} from "./fuzzingEngine.js";
import { fuzzingStatsSampleSchema } from "./fuzzingStats.js";
import { fuzzingPovRejectionSchema } from "./povValidation.js";

/** Stop conditions one campaign actually enforced, after runtime caps. */
export const fuzzingBudgetLimitsSchema = z.strictObject({
  max_runs: z.int().min(1).max(CRASH_TRIAGE_MAX_RUNS).nullable(),
  max_seconds: z.int().min(1).max(CRASH_TRIAGE_MAX_SECONDS).nullable(),
  max_crashes: z.int().min(1).max(CRASH_TRIAGE_MAX_CRASHES).nullable(),
});

export type FuzzingBudgetLimits = z.infer<typeof fuzzingBudgetLimitsSchema>;

/** Declared budget, enforced budget, and which bound set the wall clock. */
export const fuzzingBudgetObservationSchema = z.strictObject({
  declared: fuzzingCampaignBudgetSchema,
  effective: fuzzingBudgetLimitsSchema,
  runtime_cap_seconds: z
    .int()
    .min(1)
    .describe(
      "Runtime cap from the `fuzzing.max_campaign_seconds` analysis setting at the moment the campaign started.",
    ),
  seconds_bound: z
    .enum(["declared", "runtime_cap"])
    .describe(
      "Which seconds budget the run enforced: the campaign's declared max_seconds or the tighter runtime cap.",
    ),
});

/** One crash the crash-triage store accepted from this campaign. */
export const fuzzingIngestedCrashSchema = z.strictObject({
  input_path: absoluteLocalPathStringSchema,
  crash_id: z.string().min(1),
  dedup_id: crashDedupIdSchema,
  dedup_is_new: z.boolean(),
  sanitizer_class: sanitizerClassSchema,
  crash_kind: z.string().min(1),
  frame_count: z.int().min(0),
  occurrence_count: z.int().min(1),
});

export type FuzzingIngestedCrash = z.infer<typeof fuzzingIngestedCrashSchema>;

/** One candidate the POV rule refused, with the candidate path only. */
export const fuzzingRejectedCrashSchema = z.strictObject({
  input_path: absoluteLocalPathStringSchema,
  reason: fuzzingPovRejectionSchema,
});

export type FuzzingRejectedCrash = z.infer<typeof fuzzingRejectedCrashSchema>;

/** One minimization attempt over an accepted crash. */
export const fuzzingMinimizationRowSchema = z.strictObject({
  crash_id: z.string().min(1),
  engine: crashMinimizeEngineSchema,
  status: z.enum(["succeeded", "failed"]),
  input_bytes: z.int().min(0).nullable(),
  output_bytes: z.int().min(0).nullable(),
  output_path: absoluteLocalPathStringSchema.nullable(),
  failure: z
    .string()
    .min(1)
    .nullable()
    .describe(
      "Typed failure tag when the minimizer could not run; no engine output text.",
    ),
});

export type FuzzingMinimizationRow = z.infer<
  typeof fuzzingMinimizationRowSchema
>;

/** Facts the existing lab-VM lane observed for one guest campaign command. */
export const fuzzingLabVmObservationSchema = z.strictObject({
  session_id: z.string().uuid(),
  workspace_path: z
    .string()
    .min(1)
    .describe("Host directory mounted read-write in the guest."),
  guest_directory: z.string().min(1),
  exit_type: z.enum([
    "exited",
    "signalled",
    "timeout",
    "cancelled",
    "output_truncated",
    "not_started",
  ]),
  exit_code: z.int().nullable(),
  duration_ms: z.int().min(0),
  timeout_ms: z.int().min(1),
  stdout_bytes: z.int().min(0),
  stderr_bytes: z.int().min(0),
  output_truncated: z.boolean(),
  produced_paths: z.array(z.string().min(1)),
  modified_paths: z.array(z.string().min(1)),
  changes_truncated: z.boolean(),
});

export type FuzzingLabVmObservation = z.infer<
  typeof fuzzingLabVmObservationSchema
>;

/** Engine selection recorded as provenance for one campaign run. */
export const fuzzingEngineSelectionSchema = z.strictObject({
  engine: fuzzingEngineSchema,
  command: absoluteLocalPathStringSchema,
  target_path: absoluteLocalPathStringSchema,
  argv: z.array(z.string()),
  stats_source: z.enum(["stdout", "file"]),
  artifact_directory: absoluteLocalPathStringSchema,
});

/** Where the campaign's corpus, artifacts, and reports live. */
export const fuzzingCampaignWorkspaceSchema = z.strictObject({
  root: absoluteLocalPathStringSchema,
  corpus_directory: absoluteLocalPathStringSchema,
  artifact_directory: absoluteLocalPathStringSchema,
  output_directory: absoluteLocalPathStringSchema,
});

/** What one campaign observed, with no report body inlined. */
export const fuzzingCampaignObservationSchema = z.strictObject({
  campaign_id: z.string().uuid(),
  engine: fuzzingEngineSchema,
  route: fuzzingRouteSchema,
  status: fuzzingCampaignOutcomeSchema,
  stop_reason: fuzzingStopReasonSchema,
  started_at: z.string().min(1),
  finished_at: z.string().min(1),
  duration_ms: z.int().min(0),
  target: z.strictObject({
    path: absoluteLocalPathStringSchema,
    sha256: digestSchema,
  }),
  budget: fuzzingBudgetObservationSchema,
  consumed: z.strictObject({
    runs: z
      .int()
      .min(0)
      .nullable()
      .describe(
        "Executions the stat stream reported, or null when it reported none.",
      ),
    seconds: z.int().min(0),
    observed_crashes: z.int().min(0),
  }),
  stats: z.strictObject({
    samples: z.array(fuzzingStatsSampleSchema),
    sample_stride_ms: z.int().min(1),
    first: fuzzingStatsSampleSchema.nullable(),
    last: fuzzingStatsSampleSchema.nullable(),
    peak_executions_per_second: z.int().min(0).nullable(),
    edges: z.int().min(0).nullable(),
    corpus_entries: z.int().min(0).nullable(),
  }),
  crashes: z.strictObject({
    observed: z.int().min(0),
    inspected: z.int().min(0),
    accepted: z.int().min(0),
    rejected: z.int().min(0),
    ingested: z.array(fuzzingIngestedCrashSchema),
    rejected_rows: z.array(fuzzingRejectedCrashSchema),
    truncated: z
      .boolean()
      .describe(
        "An artifact or row budget stopped the listing before it covered every candidate.",
      ),
  }),
  minimization: z.strictObject({
    requested: z.boolean(),
    attempted: z.int().min(0),
    succeeded: z.int().min(0),
    rows: z.array(fuzzingMinimizationRowSchema),
  }),
  engine_selection: fuzzingEngineSelectionSchema,
  workspace: fuzzingCampaignWorkspaceSchema,
  sandbox: z.strictObject({
    confined: z
      .boolean()
      .describe(
        "The engine was launched through the deny-default seatbelt profile on this host.",
      ),
    limitations: z.array(z.string().min(1)),
  }),
  lab_vm: fuzzingLabVmObservationSchema.nullable(),
  limitations: z.array(z.string().min(1)),
});

export type FuzzingCampaignObservation = z.infer<
  typeof fuzzingCampaignObservationSchema
>;
