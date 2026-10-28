import type { Evidence } from "../domain/evidence.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type {
  BrowserEvaluateInput,
  BrowserFetchInput,
  BrowserRequestRuleClearInput,
  BrowserRequestRuleSetInput,
} from "../domain/browserMutation.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import type { ExecutionOptions } from "./AnalysisProvider.js";
import type { BrowserObservationPort } from "./BrowserObservationPort.js";
import { createBrowserMutationEvidence } from "./BrowserMutationEvidence.js";
import { completeProviderEvidence } from "./ProviderOperationExecution.js";

/** Evaluate one expression in the authorized main frame of one page. */
export const evaluateBrowserPage = async (
  browser: BrowserObservationPort | undefined,
  input: BrowserEvaluateInput,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const ready = requireBrowser(browser, "browser_evaluate", options);
  if (!ready.ok) return ready;
  const evaluated = await ready.value.evaluatePage(input, options);
  return evaluated.ok
    ? mutationEvidence(
        {
          operation: "browser_evaluate",
          input,
          result: evaluated.value,
        },
        ready.value,
        options,
      )
    : evaluated;
};

/** Arm one interception rule on the authorized main frame of one page. */
export const armBrowserRequestRule = async (
  browser: BrowserObservationPort | undefined,
  input: BrowserRequestRuleSetInput,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const ready = requireBrowser(browser, "browser_request_rule_set", options);
  if (!ready.ok) return ready;
  const armed = await ready.value.armRequestRule(input, options);
  return armed.ok
    ? mutationEvidence(
        {
          operation: "browser_request_rule_set",
          input,
          result: armed.value,
        },
        ready.value,
        options,
      )
    : armed;
};

/** Release one armed rule and report what it observed. */
export const clearBrowserRequestRule = async (
  browser: BrowserObservationPort | undefined,
  input: BrowserRequestRuleClearInput,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const ready = requireBrowser(browser, "browser_request_rule_clear", options);
  if (!ready.ok) return ready;
  const cleared = await ready.value.clearRequestRule(input, options);
  return cleared.ok
    ? mutationEvidence(
        {
          operation: "browser_request_rule_clear",
          input,
          result: cleared.value,
        },
        ready.value,
        options,
      )
    : cleared;
};

/** Dispatch one page-context request through the replay send core. */
export const fetchBrowserPage = async (
  browser: BrowserObservationPort | undefined,
  input: BrowserFetchInput,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const ready = requireBrowser(browser, "browser_fetch", options);
  if (!ready.ok) return ready;
  const fetched = await ready.value.fetchPage(input, options);
  return fetched.ok
    ? mutationEvidence(
        {
          operation: "browser_fetch",
          input,
          result: fetched.value,
        },
        ready.value,
        options,
      )
    : fetched;
};

const requireBrowser = (
  browser: BrowserObservationPort | undefined,
  operation: string,
  options: ExecutionOptions,
): Result<BrowserObservationPort, AnalysisError> => {
  if (browser === undefined)
    return err(
      new AnalysisCapabilityUnavailableError(
        "rea-cdp-browser",
        operation,
        "browser observation provider is not configured",
      ),
    );
  if (options.signal?.aborted === true)
    return err(
      new AnalysisCancelledError(operation, { cause: options.signal.reason }),
    );
  return ok(browser);
};

const mutationEvidence = (
  observation: Parameters<typeof createBrowserMutationEvidence>[0],
  provider: BrowserObservationPort,
  options: ExecutionOptions,
): Result<Evidence, AnalysisError> => {
  const json = jsonValueSchema.safeParse(observation.result);
  if (!json.success)
    return err(
      new AnalysisOutputError(
        observation.operation,
        "Browser provider returned non-JSON mutation data.",
        { cause: json.error },
      ),
    );
  return completeProviderEvidence(
    createBrowserMutationEvidence(observation, provider.identity()),
    options.signal,
  );
};
