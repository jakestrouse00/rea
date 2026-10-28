import { digestCanonicalValue } from "../domain/canonicalDigest.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import {
  HUNTING_BLOCKED_NOTE,
  HUNTING_BUDGET_NOTE,
  HUNTING_LAUNCH_NOTE,
  HUNTING_PROVIDER,
  HUNTING_STORE_NOTE,
  HUNTING_WATCH_NOTE,
} from "../domain/hunting/huntingLimits.js";
import type {
  HuntingCancelResult,
  HuntingObservationFacts,
  HuntingRunResult,
  HuntingScheduleResult,
  HuntingWatchStartResult,
  HuntingWatchStopResult,
} from "../domain/hunting/huntingObservation.js";
import { huntingObservationFactsSchema } from "../domain/hunting/huntingObservation.js";

const SUBJECT_UNAVAILABLE =
  "This record describes REA's own queue and the budgets it enforced, not facts about one analysis-target artifact.";

const baseLimitations = (): readonly string[] => [
  HUNTING_LAUNCH_NOTE,
  HUNTING_BUDGET_NOTE,
  HUNTING_STORE_NOTE,
];

/** Retain one scheduled batch's units, ordering, and budget. */
export const createHuntingScheduleEvidence = (
  result: HuntingScheduleResult,
): Evidence =>
  createEvidence(undefined, HUNTING_PROVIDER, {
    predicateType: "hunting-queue-batch",
    operation: "schedule_investigation_batch",
    parameters: {
      target_count: new Set(result.units.map((unit) => unit.target_path)).size,
      unit_count: result.units.length,
      max_units: result.budget.max_units,
      max_seconds: result.budget.max_seconds,
    },
    result,
    confidence: "derived",
    authority: "controlled-replay",
    limitations: [...baseLimitations(), ...result.limitations],
    subjectUnavailableReason: SUBJECT_UNAVAILABLE,
  });

/** Record the executed unit, its typed stop, and the queue it left behind. */
export const createHuntingRunEvidence = (result: HuntingRunResult): Evidence =>
  createEvidence(undefined, HUNTING_PROVIDER, {
    predicateType: "hunting-queue-unit",
    operation: "run_scheduled_batch",
    parameters: {
      batch_id: result.batch_id,
      unit_id: result.unit?.unit_id ?? null,
      recipe_kind: result.unit?.recipe_kind ?? null,
    },
    result,
    confidence: "observed",
    authority: "controlled-replay",
    limitations: [...baseLimitations(), ...result.limitations],
    subjectUnavailableReason: SUBJECT_UNAVAILABLE,
  });

/** Record one cancelled batch and how many queued units it released. */
export const createHuntingCancelEvidence = (
  result: HuntingCancelResult,
): Evidence =>
  createEvidence(undefined, HUNTING_PROVIDER, {
    predicateType: "hunting-queue-batch",
    operation: "cancel_hunting_batch",
    parameters: { batch_id: result.batch_id },
    result,
    confidence: "observed",
    authority: "controlled-replay",
    limitations: [
      ...baseLimitations(),
      "A cancelled batch releases only units it had not started. A unit already running is not interrupted by this call; it finishes and records its own outcome.",
      ...result.limitations,
    ],
    subjectUnavailableReason: SUBJECT_UNAVAILABLE,
  });

/** Record one started watch session and the source it observes. */
export const createHuntingWatchStartEvidence = (
  result: HuntingWatchStartResult,
): Evidence =>
  createEvidence(undefined, HUNTING_PROVIDER, {
    predicateType: "hunting-watch-session",
    operation: "start_watch_session",
    parameters: {
      session_id: result.session_id,
      source_kind: result.source.kind,
      interval_ms: result.interval_ms,
      triggers_limit: result.triggers_limit,
    },
    result,
    confidence: "observed",
    authority: "controlled-replay",
    limitations: [
      HUNTING_WATCH_NOTE,
      ...baseLimitations(),
      ...result.limitations,
    ],
    locations: [{ kind: "artifact-path", path: result.source.path }],
    subjectUnavailableReason: SUBJECT_UNAVAILABLE,
  });

/** Record one released watch session, including an interrupted finalization. */
export const createHuntingWatchStopEvidence = (
  result: HuntingWatchStopResult,
): Evidence =>
  createEvidence(undefined, HUNTING_PROVIDER, {
    predicateType: "hunting-watch-session",
    operation: "stop_watch_session",
    parameters: { session_id: result.session_id },
    result,
    confidence: "observed",
    authority: "controlled-replay",
    limitations: [
      HUNTING_WATCH_NOTE,
      HUNTING_BLOCKED_NOTE,
      ...baseLimitations(),
      ...result.limitations,
    ],
    subjectUnavailableReason: SUBJECT_UNAVAILABLE,
  });

/** Project a retained composed observation without inlining its result. */
export const huntingObservationFacts = (
  evidence: Evidence,
): HuntingObservationFacts =>
  huntingObservationFactsSchema.parse({
    evidence_id: evidence.evidence_id,
    provider_id: evidence.provider.id,
    operation: evidence.operation,
    confidence: evidence.confidence,
    result_sha256: digestCanonicalValue(
      evidence.normalized_result,
      "Hunting unit observation",
    ),
    limitations: [...evidence.limitations],
  });
