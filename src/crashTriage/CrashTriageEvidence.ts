import type { JsonValue } from "../domain/jsonValue.js";
import { CRASH_TRIAGE_PROVIDER } from "../domain/crashTriage/crashReport.js";
import {
  crashDedupListSchema,
  crashEvidenceSchema,
  fuzzingCampaignRegistrationSchema,
  fuzzingCampaignStatusResultSchema,
} from "../domain/crashTriage/fuzzingCampaign.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceSubjectTarget,
} from "../domain/evidence.js";

/** Records and report copies vanish when the owning REA server closes. */
export const CRASH_TRIAGE_STORE_LIMITATION =
  "Campaign records, crash records, and retained report copies live in a private runtime root that this REA server removes when it closes, so a later server process cannot resume or read them.";

/** A report proves what the engine reported, not how the target behaved. */
export const CRASH_TRIAGE_EXECUTION_LIMITATION =
  "The crash report was produced by a caller-run engine. REA parsed the report it was given and did not observe the target process, its arguments, its build, or the environment the crash happened in.";

/** Addresses and paths are reported, never relied on across builds. */
export const CRASH_TRIAGE_DEDUP_LIMITATION =
  "Crash states hash a bounded window of normalized top frames with the sanitizer class and crash kind. Reports whose frames differ below that window, or whose symbols were generated differently, remain separate groups; a shared dedup id is an observation about the frames, not proof of one root cause.";

/** Raw report text is on disk; only the sanitizer's own summary is inline. */
export const CRASH_TRIAGE_EXCERPT_LIMITATION =
  "The complete report body stays at the recorded path. Only the sanitizer's own summary line, bounded to 200 characters, is inlined, and it can name a source path from the crashing build.";

const environment = null;

const subjectOf = (target: {
  readonly path: string;
  readonly sha256: string;
}): EvidenceSubjectTarget => ({
  path: target.path,
  sha256: target.sha256,
  format: "file",
});

const campaignParameters = (
  target: { readonly path: string },
  seeds: readonly { readonly path: string }[],
  dedupFrames: number,
): Readonly<Record<string, JsonValue>> => ({
  target_path: target.path,
  seed_paths: seeds.map((seed) => seed.path),
  dedup_frames: dedupFrames,
});

/** Evidence for one registered fuzzing campaign. */
export const createCampaignRegistrationEvidence = (
  input: {
    readonly target: { readonly path: string; readonly sha256: string };
    readonly seeds: readonly { readonly path: string }[];
    readonly dedupFrames: number;
  },
  result: unknown,
): Evidence => {
  const parsed = fuzzingCampaignRegistrationSchema.parse(result);
  return createEvidence(subjectOf(parsed.target), CRASH_TRIAGE_PROVIDER, {
    predicateType: "fuzzing-campaign",
    operation: "register_fuzzing_campaign",
    parameters: campaignParameters(
      parsed.target,
      parsed.seeds,
      parsed.dedup_frames,
    ),
    result: parsed,
    confidence: "observed",
    authority: "controlled-replay",
    environment,
    limitations: [CRASH_TRIAGE_STORE_LIMITATION],
    locations: [
      { kind: "artifact-path", path: parsed.target.path },
      ...parsed.seeds.map((seed) => ({
        kind: "artifact-path" as const,
        path: seed.path,
      })),
    ],
  });
};

/** Evidence for one campaign's stored counters. */
export const createCampaignStatusEvidence = (result: unknown): Evidence => {
  const parsed = fuzzingCampaignStatusResultSchema.parse(result);
  return createEvidence(subjectOf(parsed.target), CRASH_TRIAGE_PROVIDER, {
    predicateType: "fuzzing-campaign",
    operation: "read_campaign_status",
    parameters: { campaign_id: parsed.campaign_id },
    result: parsed,
    confidence: "observed",
    authority: "controlled-replay",
    environment,
    limitations: [CRASH_TRIAGE_STORE_LIMITATION],
    locations: [],
  });
};

/** Evidence for one bounded deduplicated group listing. */
export const createCrashDedupListEvidence = (
  target: { readonly path: string; readonly sha256: string },
  result: unknown,
): Evidence => {
  const parsed = crashDedupListSchema.parse(result);
  return createEvidence(subjectOf(target), CRASH_TRIAGE_PROVIDER, {
    predicateType: "crash-dedup",
    operation: "list_crash_dedups",
    parameters: { campaign_id: parsed.campaign_id },
    result: parsed,
    confidence: "observed",
    authority: "controlled-replay",
    environment,
    limitations: [CRASH_TRIAGE_STORE_LIMITATION, CRASH_TRIAGE_DEDUP_LIMITATION],
    locations: [],
  });
};

/** Evidence for one stored crash, with the retained report path as a location. */
export const createCrashEvidence = (input: {
  readonly target: { readonly path: string; readonly sha256: string };
  readonly result: unknown;
  readonly reportPath: string;
  readonly reproPath: string;
}): Evidence => {
  const parsed = crashEvidenceSchema.parse(input.result);
  return createEvidence(subjectOf(input.target), CRASH_TRIAGE_PROVIDER, {
    predicateType: "crash-evidence",
    operation: "fetch_crash_evidence",
    parameters: {
      campaign_id: parsed.campaign_id,
      crash_id: parsed.crash_id,
    },
    result: parsed,
    confidence: "observed",
    authority: "controlled-replay",
    environment,
    limitations: [
      CRASH_TRIAGE_STORE_LIMITATION,
      CRASH_TRIAGE_EXECUTION_LIMITATION,
      CRASH_TRIAGE_EXCERPT_LIMITATION,
    ],
    locations: [
      { kind: "artifact-path", path: input.reportPath },
      { kind: "artifact-path", path: input.reproPath },
    ],
  });
};
