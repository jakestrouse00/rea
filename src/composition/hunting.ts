import type { FuzzingCampaignPort } from "../application/fuzzing/FuzzingCampaignPort.js";
import type { HuntingQueuePort } from "../application/hunting/HuntingQueuePort.js";
import type { MitmInterceptionPort } from "../application/mitm/MitmInterceptionPort.js";
import type { ProtocolLearningPort } from "../application/protolearn/ProtocolLearningPort.js";
import type { ReplayPort } from "../application/replay/ReplayPort.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import { createHuntingRecipeRunners } from "../hunting/HuntingRecipeRunners.js";
import type { HuntingAnalysisRun } from "../hunting/HuntingRecipeRunners.js";
import {
  HuntingQueueService,
  type HuntingEvidenceWriter,
  type HuntingUnknownRegistry,
} from "../hunting/HuntingQueueService.js";

export interface HuntingCompositionOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly platform?: NodeJS.Platform;
  readonly settings?: AnalysisSettingsReader;
  readonly fuzzing: FuzzingCampaignPort;
  readonly protocolLearning: ProtocolLearningPort;
  readonly replay: ReplayPort;
  readonly mitm: MitmInterceptionPort;
  /** The server's admitted analysis owner. */
  readonly withAnalysis: HuntingAnalysisRun;
  readonly activeTargetPath: () => string | undefined;
  readonly unknowns?: HuntingUnknownRegistry;
  readonly writer?: HuntingEvidenceWriter;
}

/**
 * Compose the hunting queue over the capabilities it admits.
 *
 * Each recipe delegates to the lane that owns the work, so this composition
 * adds ordering, budgets, and durable state rather than a second analyzer.
 */
export const createHuntingQueueService = (
  options: HuntingCompositionOptions,
): HuntingQueuePort =>
  new HuntingQueueService({
    ...(options.environment === undefined
      ? {}
      : { environment: options.environment }),
    ...(options.platform === undefined ? {} : { platform: options.platform }),
    ...(options.settings === undefined ? {} : { settings: options.settings }),
    ...(options.unknowns === undefined ? {} : { unknowns: options.unknowns }),
    ...(options.writer === undefined ? {} : { writer: options.writer }),
    runners: createHuntingRecipeRunners({
      fuzzing: options.fuzzing,
      protolearn: options.protocolLearning,
      replay: options.replay,
      mitm: options.mitm,
      withAnalysis: options.withAnalysis,
      activeTargetPath: options.activeTargetPath,
    }),
  });
