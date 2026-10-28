import type { AnalysisError } from "../../../src/domain/analysisErrorBase.js";
import type { BrowserObservationEndpoint } from "../../../src/domain/browserObservation.js";
import type { Result } from "../../../src/domain/result.js";
import type { FakeCdpBrowser } from "../../fixtures/fakeCdpBrowser.js";

/** One loopback HTTP discovery endpoint for the fake browser. */
export const browserEndpoint = (
  browser: FakeCdpBrowser,
): BrowserObservationEndpoint => ({
  transport: "http_discovery",
  url: browser.endpoint,
  recorded: browser.endpoint,
});

/** Await a refused mutation so its typed failure can be asserted. */
export const analyzeBrowserMutation = async <Value>(
  pending: Promise<Result<Value, AnalysisError>>,
): Promise<AnalysisError> => {
  const result = await pending;
  if (result.ok) throw new Error("Expected the mutation to be refused");
  return result.error;
};

/** Resolve a successful mutation or rethrow its typed failure. */
export const expectBrowserMutation = async <Value>(
  pending: Promise<Result<Value, AnalysisError>>,
): Promise<Value> => {
  const result = await pending;
  if (!result.ok) throw result.error;
  return result.value;
};
