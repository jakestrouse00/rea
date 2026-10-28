import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import {
  FUZZ_CAMPAIGN_SEED_CONTRACT,
  planProtocolGrammarSeeds,
  type ProtocolGrammarExport,
} from "../domain/protolearn/grammarExport.js";
import type { ProtocolGrammarSeed } from "../domain/protolearn/protocolLearningInputs.js";
import type { ProtocolModel } from "../domain/protolearn/protocolModel.js";
import { payloadDigest } from "../domain/protolearn/protocolMessage.js";
import { PROTOLEARN_LIMITS } from "../domain/protolearn/protolearnLimits.js";
import { readProtocolModelTemplates } from "./ProtocolModelStore.js";

const OPERATION = "export_protocol_grammar";

export const PROTOCOL_GRAMMAR_LIMITATIONS = [
  "Seeds replay message sequences the model observed; a class keeps one exemplar, so a field whose value changes between sessions is not varied",
  "Coverage counts the model's transitions the written seeds reach, not the protocol's real states",
  "The exported contract is the handoff shape a fuzz campaign consumes; this release does not start a campaign",
];

/**
 * Write structure-aware seeds and their campaign handoff from one model.
 *
 * Every seed is the exemplar sequence for the shortest observed path to one
 * transition, written 0600 into the caller's directory. A class without an
 * exemplar, or a seed above the byte bound, is counted as skipped instead of
 * being silently shortened.
 */
export const exportProtocolGrammar = async (options: {
  readonly model: ProtocolModel;
  readonly outputDirectory: string;
  readonly signal?: AbortSignal;
}): Promise<ProtocolGrammarExport> => {
  const { model, outputDirectory, signal } = options;
  if (signal?.aborted)
    throw new AnalysisCancelledError(OPERATION, { cause: signal.reason });
  const templates = await readProtocolModelTemplates({
    operation: OPERATION,
    model,
    ...(signal === undefined ? {} : { signal }),
  });
  const planned = planProtocolGrammarSeeds(model);
  const seeds: ProtocolGrammarSeed[] = [];
  const covered = new Set<string>();
  let skipped = planned.skipped;
  try {
    await mkdir(outputDirectory, { recursive: true, mode: 0o700 });
    for (const plan of planned.plans) {
      if (signal?.aborted)
        throw new AnalysisCancelledError(OPERATION, { cause: signal.reason });
      const parts: Buffer[] = [];
      let complete = true;
      for (const classId of plan.classes) {
        const template = templates.get(classId);
        if (template === undefined) {
          complete = false;
          break;
        }
        parts.push(template);
      }
      const seed = Buffer.concat(parts);
      if (!complete || seed.length === 0) {
        skipped += 1;
        continue;
      }
      if (seed.length > PROTOLEARN_LIMITS.maxSeedBytes) {
        skipped += 1;
        continue;
      }
      const seedId = `seed-${String(seeds.length)}`;
      const file = `${seedId}.bin`;
      const path = join(outputDirectory, file);
      await writeFile(path, seed, { mode: 0o600 });
      await chmod(path, 0o600);
      for (const cover of plan.covers)
        covered.add(`${cover.from}|${cover.to}|${cover.class_id}`);
      seeds.push({
        seed_id: seedId,
        file,
        bytes: seed.length,
        sha256: payloadDigest(seed),
        message_count: plan.classes.length,
        covers_transitions: plan.covers.map((cover) => ({ ...cover })),
      });
    }
  } catch (cause: unknown) {
    if (cause instanceof AnalysisCancelledError) throw cause;
    throw new AnalysisOutputError(
      OPERATION,
      `The seed directory ${outputDirectory} could not be written: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
  return {
    contract: FUZZ_CAMPAIGN_SEED_CONTRACT,
    model_source: model.source,
    seed_directory: outputDirectory,
    seeds,
    seed_count: seeds.length,
    skipped_count: skipped,
    covered_transitions: covered.size,
    transition_count: model.transitions.length,
    campaign_handoff: {
      tool: "start_fuzzing_campaign",
      seed_paths: seeds.map(({ file }) => join(outputDirectory, file)),
      note: "Pass these seed paths to a Batch 3.3 campaign as its starting corpus; each seed replays one observed message sequence that covers the named transitions. This release does not start one.",
    },
    limitations: [...PROTOCOL_GRAMMAR_LIMITATIONS],
  };
};
