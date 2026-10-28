import type { ProviderIdentity } from "./AnalysisProvider.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type {
  BrowserEvaluateInput,
  BrowserEvaluateResult,
  BrowserFetchInput,
  BrowserFetchResult,
  BrowserRequestRuleClearInput,
  BrowserRequestRuleClearResult,
  BrowserRequestRuleSetInput,
  BrowserRequestRuleSetResult,
} from "../domain/browserMutation.js";

type BrowserMutationObservation =
  | {
      readonly operation: "browser_evaluate";
      readonly input: BrowserEvaluateInput;
      readonly result: BrowserEvaluateResult;
    }
  | {
      readonly operation: "browser_request_rule_set";
      readonly input: BrowserRequestRuleSetInput;
      readonly result: BrowserRequestRuleSetResult;
    }
  | {
      readonly operation: "browser_request_rule_clear";
      readonly input: BrowserRequestRuleClearInput;
      readonly result: BrowserRequestRuleClearResult;
    }
  | {
      readonly operation: "browser_fetch";
      readonly input: BrowserFetchInput;
      readonly result: BrowserFetchResult;
    };

/** Create Evidence for one caller-authorized browser mutation. */
export const createBrowserMutationEvidence = (
  observation: BrowserMutationObservation,
  provider: ProviderIdentity,
): Evidence => {
  const { operation, result } = observation;
  return createEvidence(undefined, provider, {
    predicateType: PREDICATES[operation],
    operation,
    parameters: parametersOf(observation) as JsonValue,
    result,
    confidence: "observed",
    authority: "external-service",
    environment: null,
    limitations: result.limitations,
  });
};

const PREDICATES: Readonly<
  Record<BrowserMutationObservation["operation"], string>
> = {
  browser_evaluate: "rea.browser-evaluate",
  browser_request_rule_set: "rea.browser-request-rule",
  browser_request_rule_clear: "rea.browser-request-rule-release",
  browser_fetch: "rea.browser-page-fetch",
};

const parametersOf = (
  observation: BrowserMutationObservation,
): Readonly<Record<string, JsonValue>> => {
  switch (observation.operation) {
    case "browser_evaluate":
      return {
        ...scopeOf(observation.input),
        expression_sha256: observation.result.expression_sha256,
        expression_bytes: observation.result.expression_bytes,
        await_promise: observation.input.await_promise,
        outcome: observation.result.outcome,
      };
    case "browser_request_rule_set":
      return {
        ...scopeOf(observation.input),
        rule_id: observation.result.rule_id,
        action_kind: observation.result.action_kind,
        match: observation.result.match,
        ttl_ms: observation.result.limits.ttl_ms,
        expires_at: observation.result.expires_at,
      };
    case "browser_request_rule_clear":
      return {
        rule_id: observation.result.rule_id,
        target_id: observation.result.target.target_id,
        release_reason: observation.result.release_reason,
        counters: observation.result.counters,
      };
    case "browser_fetch":
      return {
        ...scopeOf(observation.input),
        method: observation.result.request.method,
        url: observation.result.request.url,
        origin: observation.result.request.origin,
        header_names: observation.result.request.header_names,
        credential_header_names:
          observation.result.request.credential_header_names,
        browser_managed_header_names:
          observation.result.browser_managed_header_names,
        body_bytes: observation.result.request.body_bytes,
        timeout_ms: observation.input.timeout_ms,
      };
  }
};

const scopeOf = (
  input: BrowserEvaluateInput | BrowserRequestRuleSetInput | BrowserFetchInput,
): Readonly<Record<string, JsonValue>> => ({
  cdp_endpoint: input.cdp_endpoint.recorded,
  allowed_origins: input.allowed_origins,
  target_id: input.target_id,
  ...(input.command_timeout_ms === undefined
    ? {}
    : { command_timeout_ms: input.command_timeout_ms }),
});
