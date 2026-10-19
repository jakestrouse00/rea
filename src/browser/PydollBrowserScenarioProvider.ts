import type { BrowserScenarioCapturePort } from "../application/BrowserScenarioCapturePort.js";
import type { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { PlaywrightBrowserScenarioProvider } from "./PlaywrightBrowserScenarioProvider.js";
import { PlaywrightScenarioSession } from "./PlaywrightScenarioSession.js";
import { PydollScenarioSession } from "./PydollScenarioSession.js";
import { PYDOLL_BROWSER_SCENARIO_PROVIDER_IDENTITY } from "./providerIdentities.js";

/** Environment variable selecting the scenario driver; absent or any other value keeps Playwright. */
export const PYDOLL_SCENARIO_DRIVER_ENV =
  "REA_BROWSER_SCENARIO_DRIVER" as const;
const PYDOLL_DRIVER_VALUE = "pydoll" as const;

/** Which scenario driver the caller's process environment selects. */
export const selectedScenarioDriver = (
  environment: Readonly<Record<string, string | undefined>>,
): "playwright" | "pydoll" =>
  environment[PYDOLL_SCENARIO_DRIVER_ENV] === PYDOLL_DRIVER_VALUE
    ? PYDOLL_DRIVER_VALUE
    : "playwright";

/** Controlled pydoll-driven scenario capture with the same serial scheduling as Playwright. */
export class PydollBrowserScenarioProvider extends PlaywrightBrowserScenarioProvider {
  constructor(environment: Readonly<Record<string, string | undefined>>) {
    super(
      (scenario, options) =>
        PydollScenarioSession.open(scenario, environment, options),
      PYDOLL_BROWSER_SCENARIO_PROVIDER_IDENTITY,
    );
  }
}

/** Construct a fresh provider without opening a target or acquiring an engine. */
export const createBrowserScenarioProviderByDriver = (
  environment: Readonly<Record<string, string | undefined>>,
): BrowserScenarioCapturePort =>
  selectedScenarioDriver(environment) === PYDOLL_DRIVER_VALUE
    ? new PydollBrowserScenarioProvider(environment)
    : new PlaywrightBrowserScenarioProvider(
        (
          scenario,
          options: {
            readonly signal?: AbortSignal;
            readonly retainCleanup?: (lease: AnalysisCleanupLease) => void;
          },
        ) => PlaywrightScenarioSession.open(scenario, environment, options),
      );
