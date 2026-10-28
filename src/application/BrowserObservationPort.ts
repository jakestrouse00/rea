import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type {
  InspectWebPageInput,
  ListBrowserTargetsInput,
} from "../domain/browserObservation.js";
import type {
  BrowserTargetList,
  WebPageInspection,
} from "../domain/browserObservationSchemas.js";
import type { Result } from "../domain/result.js";
import type {
  AnalyzeWebBundleInput,
  WebBundleAnalysis,
} from "../domain/webBundleAnalysis.js";
import type {
  ObserveWebSessionInput,
  WebObservationSession,
} from "../domain/browserSession.js";
import type {
  DiscoverWebMcpToolsInput,
  WebMcpDiscovery,
} from "../domain/webMcpDiscovery.js";
import type {
  BrowserCaptureComparison,
  BrowserCaptureComparisonInput,
} from "../domain/browserCaptureComparison.js";
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
import type {
  CaptureWebScreenshotInput,
  CompareWebScreenshotsInput,
  WebScreenshot,
  WebScreenshotDiff,
} from "../domain/webScreenshot.js";
import type { ProviderIdentity, ExecutionOptions } from "./AnalysisProvider.js";

/** Provider-neutral application boundary for the browser observation and mutation lane. */
export interface BrowserObservationPort {
  /** Release provider-owned transports during command or server shutdown. */
  close?(): Promise<void>;
  identity(): ProviderIdentity;
  listTargets(
    input: ListBrowserTargetsInput,
    options?: ExecutionOptions,
  ): Promise<Result<BrowserTargetList, AnalysisError>>;
  inspectPage(
    input: InspectWebPageInput,
    options?: ExecutionOptions,
  ): Promise<Result<WebPageInspection, AnalysisError>>;
  analyzeBundle(
    input: AnalyzeWebBundleInput,
    options?: ExecutionOptions,
  ): Promise<Result<WebBundleAnalysis, AnalysisError>>;
  observeSession(
    input: ObserveWebSessionInput,
    options?: ExecutionOptions,
  ): Promise<Result<WebObservationSession, AnalysisError>>;
  discoverWebMcpTools(
    input: DiscoverWebMcpToolsInput,
    options?: ExecutionOptions,
  ): Promise<Result<WebMcpDiscovery, AnalysisError>>;
  compareCaptures(
    input: BrowserCaptureComparisonInput,
  ): Promise<Result<BrowserCaptureComparison, AnalysisError>>;
  captureScreenshot(
    input: CaptureWebScreenshotInput,
    options?: ExecutionOptions,
  ): Promise<Result<WebScreenshot, AnalysisError>>;
  compareScreenshots(
    input: CompareWebScreenshotsInput,
  ): Promise<Result<WebScreenshotDiff, AnalysisError>>;
  /** Evaluate one expression in an authorized main frame's main world. */
  evaluatePage(
    input: BrowserEvaluateInput,
    options?: ExecutionOptions,
  ): Promise<Result<BrowserEvaluateResult, AnalysisError>>;
  /** Arm one interception rule and keep its owned session until released. */
  armRequestRule(
    input: BrowserRequestRuleSetInput,
    options?: ExecutionOptions,
  ): Promise<Result<BrowserRequestRuleSetResult, AnalysisError>>;
  /** Release one armed rule, including any request it still holds. */
  clearRequestRule(
    input: BrowserRequestRuleClearInput,
    options?: ExecutionOptions,
  ): Promise<Result<BrowserRequestRuleClearResult, AnalysisError>>;
  /** Dispatch one page-context request through the replay send core. */
  fetchPage(
    input: BrowserFetchInput,
    options?: ExecutionOptions,
  ): Promise<Result<BrowserFetchResult, AnalysisError>>;
}
