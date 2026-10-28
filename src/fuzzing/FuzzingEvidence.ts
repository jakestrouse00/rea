import { FUZZING_PROVIDER } from "../domain/fuzzing/fuzzingEngine.js";
import { fuzzingCampaignObservationSchema } from "../domain/fuzzing/fuzzingCampaignObservation.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceSubjectTarget,
} from "../domain/evidence.js";

/** Campaign roots live only as long as the REA server that owns them. */
export const FUZZING_RETENTION_LIMITATION =
  "The campaign corpus copy, engine artifacts, and minimized files live in a private runtime root that this REA server removes when it closes; a later server process cannot resume the campaign or read those inputs.";

/** A POV is a reproduced signature, not a proof of exploitability. */
export const FUZZING_POV_LIMITATION =
  "A crash is accepted only when every requested reproduction parsed as a crash report, named an accepted sanitizer class, carried frames, and agreed on the crash-state hash. Agreement is a stable signature over normalized frames; it does not prove the defect is reachable by an attacker or that the input is a minimal proof of vulnerability.";

/** Engine counters describe the engine's own instrumentation. */
export const FUZZING_COVERAGE_LIMITATION =
  "Executions per second, coverage, and corpus counts are the engine's own counters as REA observed them; they describe that engine's instrumentation and this run, not the target's complete behavior or a guarantee about unreached code.";

const subjectOf = (target: {
  readonly path: string;
  readonly sha256: string;
}): EvidenceSubjectTarget => ({
  path: target.path,
  sha256: target.sha256,
  format: "file",
});

/** Evidence for one completed, stopped, or failed campaign run. */
export const createFuzzingCampaignEvidence = (result: unknown): Evidence => {
  const parsed = fuzzingCampaignObservationSchema.parse(result);
  return createEvidence(subjectOf(parsed.target), FUZZING_PROVIDER, {
    predicateType: "fuzzing-campaign",
    operation: "start_fuzzing_campaign",
    parameters: {
      campaign_id: parsed.campaign_id,
      engine: parsed.engine,
      route: parsed.route,
      effective_budget: parsed.budget.effective,
    },
    result: parsed,
    confidence: "observed",
    authority: "controlled-replay",
    environment: null,
    limitations: [
      ...parsed.limitations,
      FUZZING_RETENTION_LIMITATION,
      FUZZING_POV_LIMITATION,
      FUZZING_COVERAGE_LIMITATION,
    ],
    locations: [
      { kind: "artifact-path", path: parsed.target.path },
      { kind: "artifact-path", path: parsed.workspace.root },
      { kind: "artifact-path", path: parsed.workspace.artifact_directory },
    ],
  });
};
