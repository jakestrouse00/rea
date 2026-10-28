import { z } from "zod";
import {
  javaScriptRoutesCompleteDeliveryShape,
  webRoutesSummaryDeliveryShape,
} from "../domain/analysisView/javascriptRoutesView.js";
import { javaScriptRoutesViewResultSchema } from "../domain/analysisView/analysisView.js";
import type { ToolContract } from "./toolContractTypes.js";
import {
  inspectWebPageInputSchema,
  listBrowserTargetsInputSchema,
} from "../domain/browserObservation.js";
import {
  browserTargetListSchema,
  webPageInspectionSchema,
} from "../domain/browserObservationSchemas.js";
import {
  analyzeWebBundleInputSchema,
  webBundleAnalysisSchema,
} from "../domain/webBundleAnalysis.js";
import {
  observeWebSessionInputSchema,
  webObservationSessionSchema,
} from "../domain/browserSession.js";
import {
  discoverWebMcpToolsInputSchema,
  webMcpDiscoverySchema,
} from "../domain/webMcpDiscovery.js";
import {
  browserCaptureComparisonInputSchema,
  browserCaptureComparisonSchema,
} from "../domain/browserCaptureComparison.js";
import { DEFAULT_BROWSER_SCENARIO_CAPTURE_LIMITS } from "../domain/browserScenarioCaptureLimits.js";
import {
  captureWebScreenshotInputSchema,
  compareWebScreenshotsInputSchema,
  webScreenshotDiffSchema,
  webScreenshotSchema,
} from "../domain/webScreenshot.js";
import {
  browserEvaluateInputSchema,
  browserEvaluateResultSchema,
  browserFetchInputSchema,
  browserFetchResultSchema,
  browserRequestRuleClearInputSchema,
  browserRequestRuleClearResultSchema,
  browserRequestRuleSetInputSchema,
  browserRequestRuleSetResultSchema,
} from "../domain/browserMutation.js";
import { BROWSER_MUTATION_LIMITS } from "../domain/browserMutationLimits.js";
import { toolContractMetadata } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";

const listOutputSchema = evidenceResultOf(browserTargetListSchema);
const inspectionOutputSchema = evidenceResultOf(webPageInspectionSchema);
export const analyzeWebBundleRequestSchema = z
  .discriminatedUnion("detail", [
    analyzeWebBundleInputSchema.extend(javaScriptRoutesCompleteDeliveryShape),
    analyzeWebBundleInputSchema.extend(webRoutesSummaryDeliveryShape),
  ])
  .meta({ "x-rea-root-discriminator": "detail" });
const bundleOutputSchema = evidenceResultOf(
  z.union([webBundleAnalysisSchema, javaScriptRoutesViewResultSchema]),
);
const observationSessionOutputSchema = evidenceResultOf(
  webObservationSessionSchema,
);
const webMcpOutputSchema = evidenceResultOf(webMcpDiscoverySchema);
const captureDiffOutputSchema = evidenceResultOf(
  browserCaptureComparisonSchema,
);
const screenshotOutputSchema = evidenceResultOf(webScreenshotSchema);
const screenshotDiffOutputSchema = evidenceResultOf(webScreenshotDiffSchema);
const evaluateOutputSchema = evidenceResultOf(browserEvaluateResultSchema);
const ruleSetOutputSchema = evidenceResultOf(browserRequestRuleSetResultSchema);
const ruleClearOutputSchema = evidenceResultOf(
  browserRequestRuleClearResultSchema,
);
const pageFetchOutputSchema = evidenceResultOf(browserFetchResultSchema);
const exampleRuleId = "0f6a2b1c-6d1a-4f1b-9c3e-1a2b3c4d5e6f";

const endpoint = "http://127.0.0.1:9222";
const origin = "https://app.example.test";
const scenarioUrl = {
  url: `${origin}/`,
  origin,
  query_parameter_names: [],
  redacted: false,
};
const scenarioCompleteness = {
  status: "complete",
  equality_eligible: true,
  missing_sections: [],
  truncated_sections: [],
};
const scenarioArtifacts = {
  screenshot: { state: "not_requested" },
  dom: { state: "not_requested" },
  accessibility: { state: "not_requested" },
  url: { state: "not_requested" },
  history: { state: "not_requested" },
  storage: { state: "not_requested" },
};
const exampleScenarioCapture = () => ({
  browser: {
    mode: "connect",
    process_ownership: "external",
    cleanup: "disconnected-external",
    product: "Chromium",
    version: "149",
  },
  scenario: {
    start_origin: origin,
    action_count: 1,
    secret_references: [],
    network_content: {
      request_body: false,
      response_body: false,
      header_values: false,
    },
    event_families: [],
    limits: DEFAULT_BROWSER_SCENARIO_CAPTURE_LIMITS,
  },
  duration_ms: 10,
  steps: [
    {
      step_index: 0,
      step_id: "scenario_start",
      action: "scenario_start",
      status: "completed",
      elapsed_ms: 0,
      before_url: scenarioUrl,
      after_url: scenarioUrl,
      error: null,
      event_sequence_start: 1,
      event_sequence_end: 0,
      artifacts: scenarioArtifacts,
      completeness: scenarioCompleteness,
    },
    {
      step_index: 1,
      step_id: "open-settings",
      action: "click",
      status: "completed",
      elapsed_ms: 10,
      before_url: scenarioUrl,
      after_url: scenarioUrl,
      error: null,
      event_sequence_start: 1,
      event_sequence_end: 0,
      artifacts: scenarioArtifacts,
      completeness: scenarioCompleteness,
    },
  ],
  events: {
    retained: 0,
    dropped: 0,
    items: [],
    omissions: {
      by_kind: [],
      network_transactions: [],
      network_transaction_range: null,
    },
  },
  completeness: {
    status: "incomplete",
    equality_eligible: false,
    missing_sections: ["events"],
    truncated_sections: [],
  },
  limitations: [
    "CDP attachment cannot recover pre-attach events or guarantee launch-time context options.",
    "Attached locale en-US applies to Intl formatting only; navigator.language(s) and Accept-Language remain caller-controlled. Use launch mode for matching page and request languages.",
    "Detaching a CDP page session may clear caller-owned navigator.platform emulation. REA cannot snapshot the caller's complete user-agent/client-hint state before attachment; use launch mode to avoid mutating that external browser.",
  ],
});

/** Passive browser reverse-engineering contracts. */
export const BROWSER_TOOL_CONTRACTS = [
  {
    name: "list_browser_targets",
    ...toolContractMetadata("list_browser_targets"),
    description:
      "List page targets exposed by the selected loopback Chrome DevTools Protocol endpoint. Optionally filter by exact origin. URLs preserve query values and fragments; only URL userinfo credentials are removed. HTTP discovery and browser-socket discovery use the fixed 10-second discovery deadline, then the socket closes without a later command. This operation accepts no command_timeout_ms; that listing deadline has no runtime override.",
    kind: "browser-provider",
    inputSchema: listBrowserTargetsInputSchema,
    outputSchema: listOutputSchema,
    examples: [
      {
        title: "List browser page targets",
        input: {
          cdp_endpoint: endpoint,
        },
      },
    ],
  },
  {
    name: "inspect_web_page",
    ...toolContractMetadata("inspect_web_page"),
    description:
      "Passively inspect one selected page target through CDP without evaluating JavaScript, navigating, clicking, closing, or mutating the page. If no origin filter is supplied, capture is scoped to the target's current origin. Returns DOM structure, accessibility, scripts, resources, attach-window network and console metadata, workers, and redacted storage inventory as Evidence. With stealth_safe, the attacher never sends Runtime.enable or Debugger.enable; script inventory, script sources, and console events are then reported as missing with explicit reasons instead of being captured.",
    kind: "browser-provider",
    inputSchema: inspectWebPageInputSchema,
    outputSchema: inspectionOutputSchema,
    examples: [
      {
        title: "Inspect one browser page",
        input: {
          cdp_endpoint: endpoint,
          target_id: "TARGET_ID_FROM_LIST_BROWSER_TARGETS",
        },
      },
    ],
  },
  {
    name: "analyze_web_bundle",
    ...toolContractMetadata("analyze_web_bundle"),
    description:
      "Capture JavaScript source from one selected CDP page and statically derive a chunk graph, route and endpoint candidates, vendor fingerprints, page-declared WebMCP metadata, and optionally fetch source maps from the selected target origin or explicitly requested origins. JavaScript is parsed but never executed. Select detail summary and an explicit javascript-routes view for filtered route patterns, occurrences, sources, unknowns or summary counts; complete Evidence remains retained for later views. Static candidates do not establish reachability or a complete application route denominator. With stealth_safe, the attacher never sends Runtime.enable or Debugger.enable; the script inventory and script sources are then reported as missing with explicit reasons instead of being captured.",
    kind: "browser-provider",
    inputSchema: analyzeWebBundleRequestSchema,
    outputSchema: bundleOutputSchema,
    examples: [
      {
        title: "Analyze a page bundle",
        input: {
          cdp_endpoint: endpoint,
          target_id: "TARGET_ID_FROM_LIST_BROWSER_TARGETS",
          observation_ms: 500,
          include_accessibility_text: false,
          include_script_sources: true,
          include_storage_keys: false,
          fetch_source_maps: false,
        },
      },
    ],
  },
  {
    name: "observe_web_session",
    ...toolContractMetadata("observe_web_session"),
    description:
      "Arm a CDP observation window of the requested duration while the user operates the page. By default it follows the selected target's current origin; an explicit origin list controls which origins may be retained. Records navigation, redirect, lifecycle, and failure events.",
    kind: "browser-provider",
    inputSchema: observeWebSessionInputSchema,
    outputSchema: observationSessionOutputSchema,
    examples: [
      {
        title: "Observe one external user action",
        input: {
          cdp_endpoint: endpoint,
          target_id: "TARGET_ID_FROM_LIST_BROWSER_TARGETS",
          observation_ms: 10_000,
        },
      },
    ],
  },
  {
    name: "discover_webmcp_tools",
    ...toolContractMetadata("discover_webmcp_tools"),
    description:
      "Passively inventory every page-registered WebMCP tool and its complete structural input-schema summary using the experimental CDP WebMCP domain. Metadata is page-declared-untrusted; REA never registers or invokes discovered tools.",
    kind: "browser-provider",
    inputSchema: discoverWebMcpToolsInputSchema,
    outputSchema: webMcpOutputSchema,
    examples: [
      {
        title: "Discover current WebMCP declarations",
        input: {
          cdp_endpoint: endpoint,
          target_id: "TARGET_ID_FROM_LIST_BROWSER_TARGETS",
          observation_ms: 100,
        },
      },
    ],
  },
  {
    name: "compare_web_captures",
    ...toolContractMetadata("compare_web_captures"),
    description:
      "Compare passive web captures by providing before and after, each with the complete inspect_web_page normalized_result in inspection and an optional complete discover_webmcp_tools normalized_result in webmcp; or compare recorded scenarios by passing complete capture_browser_scenario normalized_result objects in before_scenario and after_scenario with an optional normalization policy. Use exactly one input group. Network comparison includes observed HTTP requests and WebSocket frame streams; same-URL connections are compared as an unordered collection of ordered streams, retaining connection counts without claiming stable identity between individual connections. Scenario comparison aligns exact step IDs, records deterministic literal normalization, and returns every artifact-level difference plus alignment failures inline. Missing or truncated evidence never proves equality.",
    kind: "browser-provider",
    inputSchema: browserCaptureComparisonInputSchema,
    outputSchema: captureDiffOutputSchema,
    examples: [
      {
        title: "Compare two recorded browser scenarios",
        input: {
          before_scenario: exampleScenarioCapture(),
          after_scenario: exampleScenarioCapture(),
          normalization: {
            rules: [
              {
                rule_id: "volatile-build-id",
                artifacts: ["dom", "accessibility"],
                match: "build-123",
                replacement: "[BUILD_ID]",
              },
            ],
          },
        },
      },
    ],
  },
  {
    name: "capture_web_screenshot",
    ...toolContractMetadata("capture_web_screenshot"),
    description:
      "Capture the current visible viewport of one configured page as an inline, content-addressed PNG artifact. The operation never scrolls, navigates, or evaluates page JavaScript.",
    kind: "browser-provider",
    inputSchema: captureWebScreenshotInputSchema,
    outputSchema: screenshotOutputSchema,
    examples: [
      {
        title: "Capture a viewport",
        input: {
          cdp_endpoint: endpoint,
          target_id: "TARGET_ID_FROM_LIST_BROWSER_TARGETS",
        },
      },
    ],
  },
  {
    name: "compare_web_screenshots",
    ...toolContractMetadata("compare_web_screenshots"),
    description:
      "Compare two self-verifying PNG screenshot artifacts with local pixel metrics. Returns exact changed-pixel ratios and channel deltas without OCR or external services.",
    kind: "browser-provider",
    inputSchema: compareWebScreenshotsInputSchema,
    outputSchema: screenshotDiffOutputSchema,
    examples: [
      {
        title: "Compare two screenshot artifacts",
        input: {
          before: exampleScreenshot(),
          after: exampleScreenshot(),
          channel_threshold: 0,
        },
      },
    ],
  },
  {
    name: "browser_evaluate",
    ...toolContractMetadata("browser_evaluate"),
    description:
      "Evaluate one caller expression with Runtime.evaluate in the main world of an authorized main frame, then report the answer. The frame is authorized against the declared origin scope before the command is sent; a target REA did not open through its own CDP endpoint, another origin, and a non-page target are refused. The result, its value type, and any exception text are page-authored and reported as untrusted `evaluated-untrusted` text, truncated at " +
      String(BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes) +
      " UTF-8 bytes. Evaluation is one page-side effect: it can submit forms, change storage, or dispatch events, and REA cannot undo it.",
    kind: "browser-provider",
    inputSchema: browserEvaluateInputSchema,
    outputSchema: evaluateOutputSchema,
    examples: [
      {
        title: "Read the page title",
        input: {
          cdp_endpoint: endpoint,
          target_id: "TARGET_ID_FROM_LIST_BROWSER_TARGETS",
          expression: "document.title",
        },
      },
    ],
  },
  {
    name: "browser_request_rule_set",
    ...toolContractMetadata("browser_request_rule_set"),
    description:
      "Arm one CDP Fetch-domain interception rule on an authorized main frame and keep its attached session open until browser_request_rule_clear, its ttl_ms deadline, or server shutdown. The caller supplies the predicates (URL prefixes, methods, CDP resource types) and the action: block, hold, or modify headers, query parameters, and the request body. At least one predicate is required, so no rule matches every request by accident. Interception only applies to requests this attached session is asked to route: cache hits, requests that started before arming, and some service-worker paths are not seen. Retained decisions report method, origin, path, resource type, and REA's decision, never header or query values; enforcement is never budgeted, but the observation ledger stops at " +
      String(BROWSER_MUTATION_LIMITS.maxRuleDecisions) +
      " decisions and reports the drop counts.",
    kind: "browser-provider",
    inputSchema: browserRequestRuleSetInputSchema,
    outputSchema: ruleSetOutputSchema,
    examples: [
      {
        title: "Rewrite one API header for a prefix",
        input: {
          cdp_endpoint: endpoint,
          target_id: "TARGET_ID_FROM_LIST_BROWSER_TARGETS",
          match: {
            url_prefixes: [`${origin}/api/`],
            methods: ["GET"],
          },
          action: {
            kind: "modify",
            set_headers: [{ name: "x-rea-probe", value: "1" }],
          },
          ttl_ms: 60_000,
        },
      },
    ],
  },
  {
    name: "browser_request_rule_clear",
    ...toolContractMetadata("browser_request_rule_clear"),
    description:
      "Release one armed request rule. Every request the rule still holds is continued before the Fetch domain is disabled, so no paused request outlives the rule that owned it, and the result reports the counters and the retained interception decisions with their omission reasons. Clearing a rule this REA process does not own fails instead of guessing at another server's state.",
    kind: "browser-provider",
    inputSchema: browserRequestRuleClearInputSchema,
    outputSchema: ruleClearOutputSchema,
    examples: [
      {
        title: "Release one armed rule",
        input: {
          rule_id: exampleRuleId,
        },
      },
    ],
  },
  {
    name: "browser_fetch",
    ...toolContractMetadata("browser_fetch"),
    description:
      "Dispatch one request from the authorized page's own context, so it shares that page's cookies, client hints, and network identity. This is the CDP counterpart of http_replay_send and composes the same send core: one dispatch, no retry, the caller's declared origins narrowed by the operator allowlist, bounded body retention, and a value-free echo. The browser owns the wire bytes, so Host, framing, Cookie, Origin, and Sec-* stay under its control and are reported in browser_managed_header_names instead of being sent. A page-context redirect is opaque, so the send ends as no_response rather than following a hop the core could not gate. Without dump_path at most " +
      String(BROWSER_MUTATION_LIMITS.maxPageFetchBodyBytes) +
      " response bytes cross the protocol; a larger body is a partial observation.",
    kind: "browser-provider",
    inputSchema: browserFetchInputSchema,
    outputSchema: pageFetchOutputSchema,
    examples: [
      {
        title: "Re-request one API path as the page",
        input: {
          cdp_endpoint: endpoint,
          target_id: "TARGET_ID_FROM_LIST_BROWSER_TARGETS",
          method: "GET",
          url: `${origin}/api/session`,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];

function exampleScreenshot() {
  return {
    sha256: "cdb30873bdf16770bfea1fe86e44db7476e504c2dca1542b0660b20f47f523a7",
    bytes: 70,
    media_type: "image/png",
    data_base64:
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==",
  };
}
