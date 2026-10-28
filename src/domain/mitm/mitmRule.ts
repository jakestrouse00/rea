import type {
  MitmRuleActionSummary,
  MitmRuleClearResult,
} from "./mitmInterception.js";
import { MITM_LIMITS, type MitmRulePhase } from "./mitmLimits.js";
import type { MitmRuleMatchEvent } from "./mitmStream.js";

/** Caller-supplied rule predicate; every list is an OR, lists combine with AND. */
export interface MitmRuleMatch {
  readonly origins: readonly string[];
  readonly pathPrefixes: readonly string[];
  readonly methods: readonly string[];
}

export interface MitmRuleHeader {
  readonly name: string;
  readonly value: string;
}

/** One standing rewrite; the kind is the phase it applies to. */
export type MitmRuleAction =
  | {
      readonly kind: "request";
      readonly setHeaders: readonly MitmRuleHeader[];
      readonly removeHeaders: readonly string[];
      readonly setQuery: readonly MitmRuleHeader[];
      readonly removeQuery: readonly string[];
      readonly bodyBase64: string | undefined;
    }
  | {
      readonly kind: "response";
      readonly setHeaders: readonly MitmRuleHeader[];
      readonly removeHeaders: readonly string[];
      readonly status: number | undefined;
      readonly bodyBase64: string | undefined;
    };

export const mitmRulePhase = (action: MitmRuleAction): MitmRulePhase =>
  action.kind;

/** Value-free, names-only projection of one rule action. */
export const mitmRuleActionSummary = (
  action: MitmRuleAction,
): MitmRuleActionSummary =>
  action.kind === "request"
    ? {
        kind: "request",
        set_header_names: action.setHeaders.map(({ name }) => name),
        removed_header_names: [...action.removeHeaders],
        set_query_names: action.setQuery.map(({ name }) => name),
        removed_query_names: [...action.removeQuery],
        body_replaced: action.bodyBase64 !== undefined,
      }
    : {
        kind: "response",
        set_header_names: action.setHeaders.map(({ name }) => name),
        removed_header_names: [...action.removeHeaders],
        status: action.status ?? null,
        body_replaced: action.bodyBase64 !== undefined,
      };

const countersOf = () => ({
  matched: 0,
  requests_rewritten: 0,
  responses_rewritten: 0,
  headers_changed: 0,
  query_changed: 0,
  bodies_replaced: 0,
  statuses_replaced: 0,
});

/** Bounded, value-free ledger of one rule's matches. */
export class MitmRuleLedger {
  readonly counters = countersOf();
  readonly decisions: MitmRuleClearResult["decisions"]["items"] = [];
  #dropped = 0;

  apply(event: MitmRuleMatchEvent): void {
    this.counters.matched += 1;
    if (event.phase === "request") this.counters.requests_rewritten += 1;
    else this.counters.responses_rewritten += 1;
    this.counters.headers_changed += event.headers_changed;
    this.counters.query_changed += event.query_changed;
    if (event.body_replaced) this.counters.bodies_replaced += 1;
    const statusReplaced =
      event.status_before !== null &&
      event.status_after !== null &&
      event.status_before !== event.status_after;
    if (statusReplaced) this.counters.statuses_replaced += 1;
    if (this.decisions.length >= MITM_LIMITS.maxRetainedDecisions) {
      this.#dropped += 1;
      return;
    }
    this.decisions.push({
      sequence: this.counters.matched,
      phase: event.phase,
      method: event.method,
      origin: event.origin,
      path_template: event.path_template,
      status_before: event.status_before,
      status_after: event.status_after,
      headers_changed: event.headers_changed,
      query_changed: event.query_changed,
      body_replaced: event.body_replaced,
      status_replaced: statusReplaced,
    });
  }

  snapshot(): MitmRuleClearResult["decisions"] {
    return {
      retained: this.decisions.length,
      dropped: this.#dropped,
      items: this.decisions.map((item) => ({ ...item })),
      omissions:
        this.#dropped === 0
          ? []
          : [{ reason: "retention-budget" as const, count: this.#dropped }],
    };
  }
}
