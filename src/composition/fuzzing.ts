import type { CrashTriagePort } from "../application/crashTriage/CrashTriagePort.js";
import type { FuzzingCampaignPort } from "../application/fuzzing/FuzzingCampaignPort.js";
import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import { fuzzingEngineAvailability } from "../fuzzing/FuzzingEngineConfiguration.js";
import { FuzzingCampaignService } from "../fuzzing/FuzzingCampaignService.js";

/** Compose the fuzz loop over the campaign bookkeeping it feeds. */
export const createFuzzingCampaignService = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
  crashTriage: CrashTriagePort,
  labVm?: LabVmPort,
  settings?: AnalysisSettingsReader,
): FuzzingCampaignPort =>
  new FuzzingCampaignService({
    environment,
    crashTriage,
    ...(labVm === undefined ? {} : { labVm }),
    ...(settings === undefined ? {} : { settings }),
  });

/** Whether at least one engine is selected, without launching any. */
export const fuzzingCampaignLaneEnabled = (
  environment: Readonly<Record<string, string | undefined>>,
  provided: boolean,
): boolean =>
  provided || fuzzingEngineAvailability(environment).status === "available";
