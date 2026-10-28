import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { z } from "zod";

import type { Evidence } from "../../../src/domain/evidence.js";
import { fuzzingCampaignObservationSchema } from "../../../src/domain/fuzzing/fuzzingCampaignObservation.js";
import { mitmInventoryResultSchema } from "../../../src/domain/mitm/mitmInterception.js";
import {
  protocolModelSchema,
  type ProtocolModel,
} from "../../../src/domain/protolearn/protocolModel.js";

/** Which autonomy loop one score belongs to. */
export type BenchLoopId = "A" | "B" | "C";

const fuzzing = fuzzingCampaignObservationSchema.shape;

/**
 * The subset of a campaign observation this eval scores.
 *
 * The field schemas are the fuzzing lane's own, so a renamed or reinterpreted
 * budget or POV counter fails here instead of scoring a stale shape.
 */
export const fuzzingLoopMetricViewSchema = z.object({
  status: fuzzing.status,
  budget: z.object({
    effective: fuzzing.budget.shape.effective,
    seconds_bound: fuzzing.budget.shape.seconds_bound,
  }),
  consumed: z.object({
    seconds: fuzzing.consumed.shape.seconds,
    runs: fuzzing.consumed.shape.runs,
    observed_crashes: fuzzing.consumed.shape.observed_crashes,
  }),
  crashes: z.object({ accepted: fuzzing.crashes.shape.accepted }),
});

export type FuzzingLoopMetricView = z.infer<typeof fuzzingLoopMetricViewSchema>;

/** The POV bit one fuzzing run established. */
export interface PovBitMetric {
  readonly kind: "pov_bit";
  readonly satisfied: boolean;
  readonly acceptedPovs: number;
  readonly campaignStatus: FuzzingLoopMetricView["status"];
}

/** The campaign budget the run reported as enforced. */
export interface CampaignBudgetMetric {
  readonly kind: "campaign_budget";
  readonly satisfied: boolean;
  readonly declaredSeconds: number | null;
  readonly consumedSeconds: number;
  readonly bound: FuzzingLoopMetricView["budget"]["seconds_bound"];
}

export interface ProtocolModelExportedMetric {
  readonly kind: "protocol_model_exported";
  readonly satisfied: boolean;
  readonly classCount: number;
  readonly stateCount: number;
  readonly modelFile: string | null;
}

export interface FlagFoundMetric {
  readonly kind: "flag_found";
  readonly satisfied: boolean;
  readonly recoveredFlagSha256: string | null;
  readonly captureDirectory: string;
  readonly bodiesRead: number;
}

export type BenchLoopMetric =
  | PovBitMetric
  | CampaignBudgetMetric
  | ProtocolModelExportedMetric
  | FlagFoundMetric;

/** Largest capture body this eval hashes. */
export const MAX_CAPTURE_BODY_BYTES = 1024 * 1024;

/** Score Loop A: a POV bit plus the campaign budget the run honored. */
export const scoreFuzzingLoop = (
  evidence: Evidence,
): { readonly pov: PovBitMetric; readonly budget: CampaignBudgetMetric } => {
  const view = fuzzingLoopMetricViewSchema.parse(evidence.normalized_result);
  const declared = view.budget.effective.max_seconds;
  return {
    pov: {
      kind: "pov_bit",
      satisfied: view.crashes.accepted > 0,
      acceptedPovs: view.crashes.accepted,
      campaignStatus: view.status,
    },
    budget: {
      kind: "campaign_budget",
      satisfied: declared !== null && view.consumed.seconds <= declared,
      declaredSeconds: declared,
      consumedSeconds: view.consumed.seconds,
      bound: view.budget.seconds_bound,
    },
  };
};

/** The learning result is the learned model wrapped under `model`. */
export const protocolLearningViewSchema = z.strictObject({
  model: protocolModelSchema,
});

/** Score Loop B: a protocol model the lane wrote to the caller's store. */
export const scoreProtolearnLoop = (
  learningResult: unknown,
  exportedModel: ProtocolModel | null,
): ProtocolModelExportedMetric => {
  const { model } = protocolLearningViewSchema.parse(learningResult);
  const store = model.model_store;
  return {
    kind: "protocol_model_exported",
    satisfied: store !== null && exportedModel !== null,
    classCount: exportedModel?.classes.length ?? 0,
    stateCount: exportedModel?.states.length ?? 0,
    modelFile: store === null ? null : join(store.directory, store.model_file),
  };
};

/** Score Loop C: the flag a captured body carried, read from the owner-only store. */
export const scoreMitmLoop = async (
  evidence: Evidence,
  expectedFlagSha256: string,
): Promise<FlagFoundMetric> => {
  const inventory = mitmInventoryResultSchema.parse(evidence.normalized_result);
  const captureDirectory = inventory.capture.directory;
  const entries = await readdir(captureDirectory, { withFileTypes: true });
  let bodiesRead = 0;
  let recovered: string | null = null;
  for (const entry of entries.sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  )) {
    if (!entry.isFile()) continue;
    const path = join(captureDirectory, entry.name);
    const observed = await stat(path);
    if (observed.size > MAX_CAPTURE_BODY_BYTES) continue;
    bodiesRead += 1;
    const body = await readFile(path);
    recovered ??= createHash("sha256").update(body).digest("hex");
    if (
      createHash("sha256").update(body).digest("hex") === expectedFlagSha256
    ) {
      recovered = expectedFlagSha256;
      break;
    }
  }
  return {
    kind: "flag_found",
    satisfied: recovered === expectedFlagSha256,
    recoveredFlagSha256: recovered,
    captureDirectory,
    bodiesRead,
  };
};

/** Whether every metric in one loop score is satisfied. */
export const loopMetricsSatisfied = (
  metrics: readonly BenchLoopMetric[],
): boolean => metrics.every((metric) => metric.satisfied);

/** Whether a value the lane must not publish appears anywhere in Evidence. */
export const evidenceContainsValue = (
  evidence: Evidence,
  value: string,
): boolean => JSON.stringify(evidence).includes(value);
