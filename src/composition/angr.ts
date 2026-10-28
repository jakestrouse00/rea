import type { AngrAnalysisPort } from "../application/angr/AngrAnalysisPort.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import { angrLaneConfigured } from "../angr/AngrConfiguration.js";
import { AngrProvider } from "../angr/AngrProvider.js";

/** Construct the symbolic lane over the caller-managed angr environment. */
export const createAngrAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
  settings?: AnalysisSettingsReader,
): AngrAnalysisPort =>
  new AngrProvider({
    environment,
    ...(settings === undefined ? {} : { settings }),
  });

/** Whether an interpreter and bridge script are both selected. */
export const angrLaneEnabled = (
  environment: Readonly<Record<string, string | undefined>>,
  provided: boolean,
): boolean => provided || angrLaneConfigured(environment);
