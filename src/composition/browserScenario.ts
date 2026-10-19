import type { BrowserScenarioCapturePort } from "../application/BrowserScenarioCapturePort.js";
import { createBrowserScenarioProviderByDriver } from "../browser/PydollBrowserScenarioProvider.js";

/** Construct a fresh provider without opening a target or acquiring an engine. */
export const createBrowserScenarioProvider = (
  environment: Readonly<Record<string, string | undefined>>,
): BrowserScenarioCapturePort =>
  createBrowserScenarioProviderByDriver(environment);
