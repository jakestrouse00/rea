import { z } from "zod";

import {
  sanitizerClassSchema,
  type SanitizerClass,
} from "../crashTriage/crashReport.js";
import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import { labVmExitTypeSchema, type LabVmExitType } from "../vmlab/labVm.js";
import {
  BENCH_LIMITS,
  benchProfileSchema,
  type BenchProfile,
} from "./benchLimits.js";

/** What makes one benchmark task a success, declared before it runs. */
export const benchSuccessMetricSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("flag"),
    expected_flag_sha256: digestSchema.describe(
      "SHA-256 of the exact flag the task must recover. The recovered flag is hashed and discarded, so neither the expected nor the recovered value becomes Evidence.",
    ),
  }),
  z.strictObject({
    kind: z.literal("pov"),
    expected_sanitizer: sanitizerClassSchema
      .optional()
      .describe(
        "Sanitizer class the recorded POV must name. Omit to accept any class the harness reported.",
      ),
  }),
]);

export type BenchSuccessMetric = z.infer<typeof benchSuccessMetricSchema>;

/** One caller-supplied benchmark task, resolved for one run. */
export interface BenchTaskDescriptor {
  readonly taskId: string;
  readonly suite: BenchProfile;
  readonly workspacePath: string;
  readonly entrypoint: string;
  readonly success: BenchSuccessMetric;
  readonly budgetSeconds: number;
}

/** The outcome file the guest harness writes for one task. */
export const benchGuestOutcomeSchema = z.strictObject({
  status: z
    .enum(["completed", "failed"])
    .describe("Whether the harness itself completed its run."),
  flag: z
    .string()
    .min(1)
    .max(4_096)
    .optional()
    .describe("Recovered flag; hashed on the host and never published."),
  pov: z
    .strictObject({
      recorded: z.boolean(),
      sanitizer_class: sanitizerClassSchema.optional(),
    })
    .optional()
    .describe("Proof-of-vulnerability bit the harness recorded, if any."),
});

export type BenchGuestOutcome = z.infer<typeof benchGuestOutcomeSchema>;

/** How the outcome file was observed on the host. */
export const BENCH_OUTCOME_STATES = [
  "read",
  "missing",
  "unreadable",
  "oversized",
] as const;

export const benchOutcomeStateSchema = z.enum(BENCH_OUTCOME_STATES);

export type BenchOutcomeState = z.infer<typeof benchOutcomeStateSchema>;

/** Why a declared success metric was not satisfied. */
export const BENCH_METRIC_REASONS = [
  "flag_absent",
  "flag_mismatch",
  "pov_not_recorded",
  "sanitizer_mismatch",
  "task_failed",
  "outcome_missing",
  "outcome_unreadable",
  "outcome_oversized",
  "budget_exhausted",
  "cancelled",
] as const;

export const benchMetricReasonSchema = z.enum(BENCH_METRIC_REASONS);

export type BenchMetricReason = z.infer<typeof benchMetricReasonSchema>;

/** One task's final state. */
export const BENCH_TASK_STATUSES = [
  "succeeded",
  "unsatisfied",
  "budget_exhausted",
  "cancelled",
] as const;

export const benchTaskStatusSchema = z.enum(BENCH_TASK_STATUSES);

export type BenchTaskStatus = z.infer<typeof benchTaskStatusSchema>;

/** The metric bit and the facts that support it, with no flag value. */
export const benchMetricObservationSchema = z.strictObject({
  kind: z.enum(["flag", "pov"]),
  satisfied: z.boolean(),
  reason: benchMetricReasonSchema
    .nullable()
    .describe("Why the metric is unsatisfied; null when it is satisfied."),
  recovered_flag_sha256: digestSchema
    .nullable()
    .describe(
      "SHA-256 of the flag the harness recovered, or null when it recovered none.",
    ),
  sanitizer_class: sanitizerClassSchema
    .nullable()
    .describe("Sanitizer class the harness named, when it named one."),
});

export type BenchMetricObservation = z.infer<
  typeof benchMetricObservationSchema
>;

/** Facts one outcome file establishes, after the flag value is discarded. */
export interface BenchOutcomeFacts {
  readonly status: "completed" | "failed";
  readonly recoveredFlagSha256: string | null;
  readonly pov: {
    readonly recorded: boolean;
    readonly sanitizerClass: SanitizerClass | null;
  } | null;
}

const outcomeStateReason = (
  state: Exclude<BenchOutcomeState, "read">,
): BenchMetricReason =>
  state === "missing"
    ? "outcome_missing"
    : state === "oversized"
      ? "outcome_oversized"
      : "outcome_unreadable";

/**
 * Decide the metric bit from the declared success and one observed outcome.
 *
 * The rule is content-free on both sides: a flag task compares the recovered
 * flag's digest, and a POV task reads the recorded bit and any declared
 * sanitizer class. A missing, oversized, or unparseable outcome is unknown and
 * never counts as a satisfied metric.
 */
export const evaluateBenchMetric = (
  success: BenchSuccessMetric,
  outcome: BenchOutcomeFacts | { readonly state: BenchOutcomeState },
): BenchMetricObservation => {
  const kind = success.kind;
  if ("state" in outcome && outcome.state !== "read")
    return {
      kind,
      satisfied: false,
      reason: outcomeStateReason(outcome.state),
      recovered_flag_sha256: null,
      sanitizer_class: null,
    };
  const facts = outcome as BenchOutcomeFacts;
  const recovered = facts.recoveredFlagSha256;
  const sanitizerClass = facts.pov?.sanitizerClass ?? null;
  if (success.kind === "flag") {
    const satisfied =
      recovered !== null && recovered === success.expected_flag_sha256;
    return {
      kind,
      satisfied,
      reason: satisfied
        ? null
        : facts.status === "failed"
          ? "task_failed"
          : recovered === null
            ? "flag_absent"
            : "flag_mismatch",
      recovered_flag_sha256: recovered,
      sanitizer_class: null,
    };
  }
  if (facts.status === "failed" && facts.pov?.recorded !== true)
    return {
      kind,
      satisfied: false,
      reason: "task_failed",
      recovered_flag_sha256: recovered,
      sanitizer_class: sanitizerClass,
    };
  if (facts.pov?.recorded !== true)
    return {
      kind,
      satisfied: false,
      reason: "pov_not_recorded",
      recovered_flag_sha256: recovered,
      sanitizer_class: sanitizerClass,
    };
  if (
    success.expected_sanitizer !== undefined &&
    sanitizerClass !== success.expected_sanitizer
  )
    return {
      kind,
      satisfied: false,
      reason: "sanitizer_mismatch",
      recovered_flag_sha256: recovered,
      sanitizer_class: sanitizerClass,
    };
  return {
    kind,
    satisfied: true,
    reason: null,
    recovered_flag_sha256: recovered,
    sanitizer_class: sanitizerClass,
  };
};

/**
 * A guest deadline or cancellation outranks the metric.
 *
 * A command REA stopped at its budget cannot establish anything about the
 * task, even when a stray outcome file is left in the workspace.
 */
export const benchTaskStatusFor = (
  exitType: LabVmExitType,
  metric: BenchMetricObservation,
): BenchTaskStatus =>
  exitType === "timeout"
    ? "budget_exhausted"
    : exitType === "cancelled"
      ? "cancelled"
      : metric.satisfied
        ? "succeeded"
        : "unsatisfied";

/** Structural facts of one guest command, with no output bytes. */
export const benchGuestFactsSchema = z.strictObject({
  exit_type: labVmExitTypeSchema,
  exit_code: z.int().nullable(),
  duration_ms: z.int().min(0),
  timeout_ms: z.int().min(1),
});

export type BenchGuestFacts = z.infer<typeof benchGuestFactsSchema>;

/** Result of one benchmark task run: the metric bit and its supporting facts. */
export const benchTaskObservationSchema = z.strictObject({
  task_id: z.string().min(1).max(BENCH_LIMITS.maxTaskIdCharacters),
  suite: benchProfileSchema,
  status: benchTaskStatusSchema,
  metric: benchMetricObservationSchema,
  outcome_state: benchOutcomeStateSchema,
  budget_seconds: z.int().min(1).max(BENCH_LIMITS.maxTaskSeconds),
  guest: benchGuestFactsSchema,
  produced_paths: z
    .array(z.string().min(1))
    .describe(
      "Workspace-relative paths that did not exist before the task command and exist after it.",
    ),
  changes_truncated: z
    .boolean()
    .describe(
      "A bounded workspace inventory stopped before it covered the workspace.",
    ),
  vm: z.strictObject({
    stopped: z
      .boolean()
      .describe(
        "Whether this run released its lab VM. False means the lab-VM lane still owns the instance and stop_lab_vm must be retried.",
      ),
  }),
});

export type BenchTaskObservation = z.infer<typeof benchTaskObservationSchema>;

/** One caller-supplied task for the run_bench_task contract. */
export const benchTaskRequestSchema = z.strictObject({
  task_id: z
    .string()
    .min(1)
    .max(BENCH_LIMITS.maxTaskIdCharacters)
    .describe("Benchmark task identity from the caller's own corpus."),
  suite: benchProfileSchema.describe(
    "Benchmark suite this task belongs to; it must equal the selected profile.",
  ),
  workspace_path: absoluteLocalPathStringSchema.describe(
    "Absolute host directory the lab VM mounts at /workspace. The task harness, images, and recovered outcome live here.",
  ),
  entrypoint: z
    .string()
    .min(1)
    .max(BENCH_LIMITS.maxEntrypointBytes)
    .describe(
      "Guest command line that runs the containerized task from /workspace and writes its outcome to /workspace/.rea-bench/outcome.json.",
    ),
  success: benchSuccessMetricSchema.describe(
    "Metric that makes this task count as solved.",
  ),
  budget_seconds: z
    .int()
    .min(1)
    .max(BENCH_LIMITS.maxTaskSeconds)
    .optional()
    .describe(
      `Wall-clock budget for the task command; ${String(BENCH_LIMITS.defaultTaskSeconds)} when omitted, at most ${String(BENCH_LIMITS.maxTaskSeconds)}.`,
    ),
});
