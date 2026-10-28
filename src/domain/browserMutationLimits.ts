/**
 * Fixed resource policy for the browser mutation lane.
 *
 * These bounds follow real constraints: one CDP command round trip for an
 * evaluation, one armed interception rule per attached main frame, and a
 * bounded ledger of interception decisions. None of them is a runtime setting.
 */
export const BROWSER_MUTATION_LIMITS = {
  /** Caller expression text admitted for one Runtime.evaluate. */
  maxEvaluateExpressionBytes: 64 * 1_024,
  /** Result text returned inline for one evaluation, then truncated. */
  maxEvaluateResultBytes: 256 * 1_024,
  /** Interception rules one REA process may hold armed at a time. */
  maxArmedRules: 8,
  /** Rule lifetime applied when the caller omits ttl_ms. */
  defaultRuleTtlMs: 300_000,
  /** Longest admitted caller-selected rule lifetime. */
  maxRuleTtlMs: 1_800_000,
  /** URL prefixes one rule may match. */
  maxRuleUrlPrefixes: 16,
  /** HTTP methods one rule may match. */
  maxRuleMethods: 8,
  /** CDP resource types one rule may match. */
  maxRuleResourceTypes: 16,
  /** Header edits one rule may apply per intercepted request. */
  maxRuleHeaderEdits: 32,
  /** Query edits one rule may apply per intercepted request. */
  maxRuleQueryEdits: 32,
  /** Replacement request body one rule may apply, in bytes. */
  maxRuleBodyBytes: 1 * 1_024 * 1_024,
  /** Requests one hold rule may keep paused before it fails closed. */
  maxHeldRequestsPerRule: 32,
  /** Interception decisions one rule retains as observations. */
  maxRuleDecisions: 1_000,
  /** Allocation cost of the retained decision ledger. */
  maxRuleDecisionAllocationBytes: 2 * 1_024 * 1_024,
  /** Response bytes one page-context fetch may carry over the CDP frame. */
  maxPageFetchBodyBytes: 32 * 1_024 * 1_024,
} as const;

/** Interception decisions a rule can record; enforcement is never budgeted. */
export const BROWSER_REQUEST_RULE_DECISIONS = [
  "continued",
  "modified",
  "blocked",
  "held",
  "released",
  "hold-overflow",
] as const;
export type BrowserRequestRuleDecision =
  (typeof BROWSER_REQUEST_RULE_DECISIONS)[number];

/** Why one interception decision was omitted from the retained ledger. */
export const BROWSER_REQUEST_RULE_OMISSION_REASONS = [
  "max-decisions",
  "max-decision-allocation-bytes",
] as const;
export type BrowserRequestRuleOmissionReason =
  (typeof BROWSER_REQUEST_RULE_OMISSION_REASONS)[number];

/**
 * Header names the browser itself owns for a page-context fetch: a caller
 * cannot set them, and REA cannot observe what the browser finally sent.
 */
export const BROWSER_MANAGED_REQUEST_HEADERS: ReadonlySet<string> = new Set([
  "accept-charset",
  "accept-encoding",
  "access-control-request-headers",
  "access-control-request-method",
  "connection",
  "content-length",
  "cookie",
  "cookie2",
  "date",
  "dnt",
  "expect",
  "host",
  "keep-alive",
  "origin",
  "referer",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "set-cookie",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "via",
]);

/** Whether the browser, not the caller, decides this header's value. */
export const isBrowserManagedRequestHeader = (name: string): boolean => {
  const lower = name.toLowerCase();
  return (
    BROWSER_MANAGED_REQUEST_HEADERS.has(lower) ||
    lower.startsWith("proxy-") ||
    lower.startsWith("sec-")
  );
};
