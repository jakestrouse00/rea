import type {
  AnalysisOperationPort,
  ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { FuzzingCampaignPort } from "../application/fuzzing/FuzzingCampaignPort.js";
import type {
  HuntingFuzzRequest,
  HuntingProbeRequest,
  HuntingRecipeRunner,
  HuntingRecipeRunners,
  HuntingReanalysisRequest,
  HuntingReplayRequest,
} from "../application/hunting/HuntingRecipePort.js";
import type { MitmInterceptionPort } from "../application/mitm/MitmInterceptionPort.js";
import type { ProtocolLearningPort } from "../application/protolearn/ProtocolLearningPort.js";
import type { ReplayPort } from "../application/replay/ReplayPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { createAnalysisExecutionEvidence } from "../domain/analysisObservation.js";
import type { Evidence } from "../domain/evidence.js";
import { HUNTING_PROVIDER } from "../domain/hunting/huntingLimits.js";
import { REPLAY_LIMITS } from "../domain/replay/replayLimits.js";
import { err, ok, type Result } from "../domain/result.js";

/** The admitted-analysis seam, structurally typed to keep adapters outside. */
export type HuntingAnalysisRun = <Value>(
  operationName: string,
  signal: AbortSignal | undefined,
  operation: (analysis: AnalysisOperationPort) => Promise<Value>,
) => Promise<Result<Value, AnalysisError>>;

export interface HuntingReanalysisRunnerOptions {
  readonly withAnalysis: HuntingAnalysisRun;
  /** Path of the server's admitted analysis target, if it has one. */
  readonly activeTargetPath: () => string | undefined;
}

/**
 * Re-analysis over the server's admitted analysis owner.
 *
 * The unit's declared path is a precondition, not a selector: this runner
 * refuses to analyze a different target, because re-targeting the caller's
 * session from a queued unit would retire work they did not ask to lose.
 */
export const createHuntingReanalysisRunner = (
  options: HuntingReanalysisRunnerOptions,
): HuntingRecipeRunner<HuntingReanalysisRequest> => ({
  async run(request, execution) {
    const active = options.activeTargetPath();
    if (active !== request.targetPath)
      return err(
        new AnalysisCapabilityUnavailableError(
          HUNTING_PROVIDER.id,
          request.operation,
          active === undefined
            ? `No analysis target is admitted; ${request.targetPath} is not open.`
            : `The admitted analysis target is not ${request.targetPath}, so this queued unit would analyze another artifact.`,
          {
            userMessage:
              "Open the unit's target with open_binary, then admit the unit again.",
            remediationAction:
              "Re-analysis runs one inspection over the server's admitted analysis target; it never switches targets.",
            retryable: true,
          },
        ),
      );
    const signal = execution?.signal;
    const executed = await options.withAnalysis(
      request.operation,
      signal,
      (analysis) =>
        analysis.execute(
          request.operation,
          {},
          signal === undefined ? {} : { signal },
        ),
    );
    if (!executed.ok) return executed;
    const observation = executed.value;
    if (!observation.ok) return observation;
    const evidence: Evidence = createAnalysisExecutionEvidence(
      request.operation,
      {},
      observation.value,
      "observed",
    );
    return ok(evidence);
  },
});

/** Fuzz campaigns through the fuzz loop's own service seam. */
export const createHuntingFuzzRunner = (
  fuzzing: FuzzingCampaignPort,
): HuntingRecipeRunner<HuntingFuzzRequest> => ({
  run: (request: HuntingFuzzRequest, options?: ExecutionOptions) =>
    fuzzing.startCampaign(
      {
        campaignId: request.campaignId,
        engine: request.engine,
        povRepeats: request.povRepeats ?? 2,
        expectedSanitizer: request.expectedSanitizer,
        minimizeCrashes: request.minimizeCrashes,
        labVm: null,
      },
      options,
    ),
});

/** Probes through the protocol-learning lane's guard and runner. */
export const createHuntingProbeRunner = (
  protolearn: ProtocolLearningPort,
): HuntingRecipeRunner<HuntingProbeRequest> => ({
  async run(request, options) {
    const availability = await protolearn.inspectProbeAvailability();
    if (availability.status !== "available")
      return err(
        new AnalysisCapabilityUnavailableError(
          HUNTING_PROVIDER.id,
          "probe_learned_model",
          availability.reason ?? "The protocol probe lane is not available.",
        ),
      );
    const input = {
      endpoint: request.endpoint,
      model_path: request.modelPath,
      probes: request.connections.map((connection) => ({
        label: connection.label,
        steps: connection.steps.map((step) => ({
          template_hex: step.templateHex,
          wait_for_response: step.waitForResponse,
        })),
      })),
      repeats: request.repeats,
    };
    const executed = await protolearn.execute(
      { operation: "probe_learned_model", input },
      options,
    );
    if (!executed.ok) return executed;
    return ok(
      createAnalysisExecutionEvidence(
        "probe_learned_model",
        input,
        executed.value,
        "observed",
      ),
    );
  },
});

/** Replays through whichever plane already owns a live session. */
export const createHuntingReplayRunner = (input: {
  readonly replay: ReplayPort | null;
  readonly mitm: MitmInterceptionPort | null;
}): HuntingRecipeRunner<HuntingReplayRequest> => ({
  async run(request, options) {
    const timeoutMs = request.timeoutMs ?? REPLAY_LIMITS.defaultTimeoutMs;
    if (request.session.kind === "mitm") {
      if (input.mitm === null)
        return err(
          new AnalysisCapabilityUnavailableError(
            HUNTING_PROVIDER.id,
            "proxy_replay_send",
            "This server composes no interception plane, so an interception replay unit cannot run.",
          ),
        );
      return input.mitm.replay(
        {
          sessionId: request.session.sessionId,
          sequence: request.session.sequence,
          mutation: {},
          timeoutMs,
          followRedirects: request.followRedirects,
          dump: undefined,
        },
        options,
      );
    }
    if (input.replay === null)
      return err(
        new AnalysisCapabilityUnavailableError(
          HUNTING_PROVIDER.id,
          "http_replay_send",
          "This server composes no request plane, so a replay unit cannot run.",
        ),
      );
    return input.replay.send(
      {
        sessionId: request.session.sessionId,
        entryOrdinal: request.session.entryOrdinal ?? undefined,
        mutation: {},
        timeoutMs,
        followRedirects: request.followRedirects,
        dump: undefined,
      },
      options,
    );
  },
});

/** Compose whatever this server can execute; an absent owner stays null. */
export const createHuntingRecipeRunners = (input: {
  readonly fuzzing: FuzzingCampaignPort;
  readonly protolearn: ProtocolLearningPort;
  readonly replay: ReplayPort;
  readonly mitm: MitmInterceptionPort;
  readonly withAnalysis: HuntingAnalysisRun;
  readonly activeTargetPath: () => string | undefined;
}): HuntingRecipeRunners => ({
  "re-analysis": createHuntingReanalysisRunner({
    withAnalysis: input.withAnalysis,
    activeTargetPath: input.activeTargetPath,
  }),
  "fuzz-campaign": createHuntingFuzzRunner(input.fuzzing),
  probe: createHuntingProbeRunner(input.protolearn),
  replay: createHuntingReplayRunner({
    replay: input.replay,
    mitm: input.mitm,
  }),
});
