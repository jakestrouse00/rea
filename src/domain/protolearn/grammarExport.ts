import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";
import { protocolGrammarSeedSchema } from "./protocolLearningInputs.js";
import {
  protocolModelSourceSchema,
  type ProtocolModel,
} from "./protocolModel.js";
import { protocolModelIndex } from "./protocolProbe.js";
import { PROTOLEARN_LIMITS } from "./protolearnLimits.js";

type SeedCover = {
  from: string;
  to: string;
  class_id: string;
};

/** One structure-aware seed, as the class sequence it replays. */
export interface ProtocolSeedPlan {
  readonly classes: readonly string[];
  readonly covers: readonly SeedCover[];
}

/**
 * Plan seeds that together exercise every learned transition.
 *
 * Each seed is the shortest class path from the initial state that reaches one
 * transition and replays that transition's message, so a campaign starts from
 * message sequences the model actually observed rather than from random bytes.
 * Two transitions that need the same class sequence share one seed, which
 * reports both.
 */
export const planProtocolGrammarSeeds = (
  model: ProtocolModel,
): {
  readonly plans: readonly ProtocolSeedPlan[];
  readonly skipped: number;
} => {
  const index = protocolModelIndex(model);
  const parents = new Map<string, { parent: string; class_id: string }>();
  const queue = [index.initialState];
  const seen = new Set(queue);
  while (queue.length > 0) {
    const state = queue.shift();
    if (state === undefined) break;
    for (const transition of index.transitionsFrom.get(state) ?? [])
      if (!seen.has(transition.to)) {
        seen.add(transition.to);
        parents.set(transition.to, {
          parent: state,
          class_id: transition.class_id,
        });
        queue.push(transition.to);
      }
  }
  const routeTo = (state: string): readonly string[] => {
    const classes: string[] = [];
    let current = state;
    for (let guard = 0; guard <= model.states.length; guard += 1) {
      const step = parents.get(current);
      if (step === undefined) return [...classes].reverse();
      classes.push(step.class_id);
      current = step.parent;
    }
    return [...classes].reverse();
  };
  const byKey = new Map<string, { classes: string[]; covers: SeedCover[] }>();
  let skipped = 0;
  for (const transition of model.transitions) {
    const classes = [...routeTo(transition.from), transition.class_id];
    const key = classes.join(">");
    const cover = {
      from: transition.from,
      to: transition.to,
      class_id: transition.class_id,
    };
    const existing = byKey.get(key);
    if (existing !== undefined) {
      existing.covers.push(cover);
      continue;
    }
    if (byKey.size >= PROTOLEARN_LIMITS.maxSeeds) {
      skipped += 1;
      continue;
    }
    byKey.set(key, { classes, covers: [cover] });
  }
  return { plans: [...byKey.values()], skipped };
};

/**
 * Handoff shape a Batch 3.3 fuzz campaign consumes. The fuzz lane is not part
 * of this release: the exported Evidence names the contract and the exact seed
 * paths so a later wiring task can pass them unchanged to
 * `start_fuzzing_campaign` instead of re-deriving seeds from the model.
 */
export interface FuzzCampaignSeedHandoff {
  readonly contract: "rea.fuzzing.campaign-seeds/v1";
  readonly seed_paths: readonly string[];
}

export const FUZZ_CAMPAIGN_SEED_CONTRACT = "rea.fuzzing.campaign-seeds/v1";

/** Grammar export: seeds, their coverage, and the campaign handoff. */
export const protocolGrammarExportSchema = z.strictObject({
  contract: z.literal(FUZZ_CAMPAIGN_SEED_CONTRACT),
  model_source: protocolModelSourceSchema,
  seed_directory: localPathStringSchema,
  seeds: z.array(protocolGrammarSeedSchema).max(PROTOLEARN_LIMITS.maxSeeds),
  seed_count: z.int().nonnegative(),
  skipped_count: z.int().nonnegative(),
  covered_transitions: z.int().nonnegative(),
  transition_count: z.int().nonnegative(),
  campaign_handoff: z.strictObject({
    tool: z.literal("start_fuzzing_campaign"),
    seed_paths: z.array(localPathStringSchema).max(PROTOLEARN_LIMITS.maxSeeds),
    note: z.string().min(1),
  }),
  limitations: z.array(z.string().min(1)),
});

export type ProtocolGrammarExport = z.output<
  typeof protocolGrammarExportSchema
>;

/** Project one export onto the fuzz-campaign handoff contract. */
export const fuzzCampaignSeedHandoff = (
  exported: ProtocolGrammarExport,
): FuzzCampaignSeedHandoff => ({
  contract: FUZZ_CAMPAIGN_SEED_CONTRACT,
  seed_paths: [...exported.campaign_handoff.seed_paths],
});
