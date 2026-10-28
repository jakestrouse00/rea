import type { SanitizedBrowserUrl } from "../domain/browserObservation.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import type {
  BrowserRequestRuleAction,
  BrowserRequestRuleClearResult,
  BrowserRequestRuleMatch,
  BrowserRequestRuleSetResult,
} from "../domain/browserMutation.js";
import {
  BROWSER_REQUEST_RULE_HOLD_LIMITATION,
  BROWSER_REQUEST_RULE_SCOPE_LIMITATION,
  BROWSER_REQUEST_RULE_VALUE_FREE_LIMITATION,
  browserRequestRuleClearResultSchema,
} from "../domain/browserMutation.js";
import { BROWSER_MUTATION_LIMITS } from "../domain/browserMutationLimits.js";
import type { CdpEvent } from "./CdpConnection.js";
import {
  closeCdpTargetSession,
  type CdpTargetSession,
} from "./CdpTargetSession.js";
import type { CdpTargetSessionOwner } from "./CdpTargetSessionOwner.js";
import { cdpStringValue, recordValue } from "./CdpCaptureValues.js";
import {
  BrowserRequestRuleBudget,
  type BrowserRequestRuleDecisionRecord,
} from "./BrowserRequestRuleBudget.js";

export interface ArmedBrowserRequestRule {
  readonly ruleId: string;
  readonly target: {
    readonly target_id: string;
    readonly url: SanitizedBrowserUrl;
    readonly origin: string;
  };
  readonly match: BrowserRequestRuleMatch;
  readonly action: BrowserRequestRuleAction;
  readonly session: CdpTargetSession;
}

interface RuleCounters {
  paused: number;
  continued: number;
  modified: number;
  blocked: number;
  held: number;
  held_released: number;
  hold_overflow: number;
}

interface HeldRequest {
  readonly method: string;
  readonly url: string;
  readonly resourceType: string | null;
}

type ReleaseReason = BrowserRequestRuleClearResult["release_reason"];

interface RuleRecord extends ArmedBrowserRequestRule {
  readonly budget: BrowserRequestRuleBudget;
  readonly counters: RuleCounters;
  readonly held: Map<string, HeldRequest>;
  readonly expiresAt: number;
  timer: ReturnType<typeof setTimeout> | undefined;
  detach: () => void;
  releasing: Promise<BrowserRequestRuleClearResult> | undefined;
}

/** One request decision REA made while a rule held the Fetch domain open. */
interface DecisionFacts {
  readonly method: string;
  readonly url: string;
  readonly resourceType: string | null;
  readonly decision: BrowserRequestRuleDecisionRecord["decision"];
  readonly headersChanged?: number;
  readonly queryChanged?: number;
  readonly bodyReplaced?: boolean;
}

interface ActionInput {
  readonly url: string;
  readonly method: string;
  readonly resourceType: string | null;
  readonly headers: readonly HeaderPair[];
}

interface HeaderPair {
  readonly name: string;
  readonly value: string;
}

interface RewrittenRequest {
  readonly url: string | undefined;
  readonly headers: readonly HeaderPair[] | undefined;
  readonly postData: string | undefined;
  readonly headersChanged: number;
  readonly queryChanged: number;
  readonly bodyReplaced: boolean;
}

const RULE_SET_OPERATION = "browser_request_rule_set";
const RULE_CLEAR_OPERATION = "browser_request_rule_clear";

/**
 * Owns every armed request rule and the CDP sessions that keep them armed.
 *
 * A rule is a live resource: it holds one attached main frame open, answers
 * each paused request, and is only released by an explicit clear, its own
 * deadline, or server shutdown. Held requests are released before the Fetch
 * domain is disabled, because a paused request that outlived its rule would
 * leave the page waiting on a decision REA no longer owns.
 */
export class BrowserRequestRuleRegistry {
  readonly #rules = new Map<string, RuleRecord>();

  constructor(private readonly owner: CdpTargetSessionOwner) {}

  /** Arm one rule, refusing duplicates and exceeding the fixed concurrency. */
  arm(
    rule: ArmedBrowserRequestRule,
    ttlMs: number,
  ): BrowserRequestRuleSetResult {
    if (this.#rules.has(rule.ruleId))
      throw new BrowserObservationError(
        RULE_SET_OPERATION,
        "invalid_endpoint_response",
        {
          detail: `Rule ${rule.ruleId} is already armed; clear it before arming another rule with that identity.`,
        },
      );
    if (this.#rules.size >= BROWSER_MUTATION_LIMITS.maxArmedRules)
      throw new BrowserObservationError(RULE_SET_OPERATION, "payload_limit", {
        detail: `At most ${String(BROWSER_MUTATION_LIMITS.maxArmedRules)} request rules may stay armed at once. Clear one before arming another.`,
      });
    const expiresAt = Date.now() + ttlMs;
    this.#rules.set(rule.ruleId, this.#record(rule, ttlMs, expiresAt));
    return {
      rule_id: rule.ruleId,
      state: "armed",
      target: rule.target,
      match: {
        url_prefixes: rule.match.url_prefixes,
        methods: rule.match.methods,
        resource_types: rule.match.resource_types,
      },
      action_kind: rule.action.kind,
      expires_at: new Date(expiresAt).toISOString(),
      limits: {
        ttl_ms: ttlMs,
        max_held_requests: BROWSER_MUTATION_LIMITS.maxHeldRequestsPerRule,
        max_retained_decisions: BROWSER_MUTATION_LIMITS.maxRuleDecisions,
      },
      limitations: [
        BROWSER_REQUEST_RULE_SCOPE_LIMITATION,
        BROWSER_REQUEST_RULE_VALUE_FREE_LIMITATION,
        ...(rule.action.kind === "hold"
          ? [BROWSER_REQUEST_RULE_HOLD_LIMITATION]
          : []),
      ],
    };
  }

  /** Release one rule and report everything it observed before releasing. */
  async clear(
    ruleId: string,
    signal?: AbortSignal,
  ): Promise<BrowserRequestRuleClearResult> {
    const record = this.#rules.get(ruleId);
    if (record === undefined)
      throw new BrowserObservationError(
        RULE_CLEAR_OPERATION,
        "target_not_found",
        {
          detail: `Rule ${ruleId} is not armed in this REA process; it may already have been cleared, expired, or owned by another server.`,
        },
      );
    return await this.#release(record, "cleared", signal);
  }

  /** Release every armed rule during provider shutdown. */
  async closeAll(): Promise<void> {
    const records = [...this.#rules.values()].reverse();
    const failures: unknown[] = [];
    for (const record of records) {
      try {
        await this.#release(record, "server-close");
      } catch (cause: unknown) {
        failures.push(cause);
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new AggregateError(
        failures,
        "One or more browser request rules did not release.",
      );
  }

  #record(
    rule: ArmedBrowserRequestRule,
    ttlMs: number,
    expiresAt: number,
  ): RuleRecord {
    const record: RuleRecord = {
      ...rule,
      budget: new BrowserRequestRuleBudget(),
      counters: {
        paused: 0,
        continued: 0,
        modified: 0,
        blocked: 0,
        held: 0,
        held_released: 0,
        hold_overflow: 0,
      },
      held: new Map(),
      expiresAt,
      timer: undefined,
      detach: () => undefined,
      releasing: undefined,
    };
    record.detach = rule.session.connection.onEvent((event) => {
      this.#onEvent(record, event);
    });
    record.timer = setTimeout(() => {
      void this.#release(record, "expired").catch(() => undefined);
    }, ttlMs);
    record.timer.unref();
    return record;
  }

  async #release(
    record: RuleRecord,
    reason: ReleaseReason,
    signal?: AbortSignal,
  ): Promise<BrowserRequestRuleClearResult> {
    record.releasing ??= this.#releaseOnce(record, reason, signal);
    return await record.releasing;
  }

  async #releaseOnce(
    record: RuleRecord,
    reason: ReleaseReason,
    signal?: AbortSignal,
  ): Promise<BrowserRequestRuleClearResult> {
    if (record.timer !== undefined) clearTimeout(record.timer);
    record.timer = undefined;
    record.detach();
    try {
      for (const [requestId, held] of record.held) {
        record.held.delete(requestId);
        await this.#send(record, "Fetch.continueRequest", requestId);
        record.counters.held_released += 1;
        record.budget.push(
          decision({
            method: held.method,
            url: held.url,
            resourceType: held.resourceType,
            decision: "released",
          }),
        );
      }
      await closeCdpTargetSession(
        record.session,
        ["Fetch"],
        signal,
        this.owner,
      );
    } finally {
      this.#rules.delete(record.ruleId);
    }
    return browserRequestRuleClearResultSchema.parse({
      rule_id: record.ruleId,
      state: "cleared",
      target: {
        target_id: record.target.target_id,
        origin: record.target.origin,
      },
      release_reason: reason,
      counters: {
        paused: record.counters.paused,
        continued: record.counters.continued,
        modified: record.counters.modified,
        blocked: record.counters.blocked,
        held: record.counters.held,
        held_released: record.counters.held_released,
        hold_overflow: record.counters.hold_overflow,
      },
      decisions: record.budget.result(),
      limitations: [
        BROWSER_REQUEST_RULE_VALUE_FREE_LIMITATION,
        "Counters describe what REA did at the Fetch boundary. A continued request was forwarded unmodified; neither its answer nor the server's response is observed by the rule.",
      ],
    });
  }

  #onEvent(record: RuleRecord, event: CdpEvent): void {
    if (event.method !== "Fetch.requestPaused") return;
    if (event.sessionId !== record.session.sessionId) return;
    const params = recordValue(event.params);
    const requestId = cdpStringValue(params?.requestId);
    if (requestId === undefined) return;
    const request = recordValue(params?.request);
    const url = cdpStringValue(request?.url) ?? "";
    const method = (cdpStringValue(request?.method) ?? "").toUpperCase();
    const resourceType = cdpStringValue(params?.resourceType) ?? null;
    record.counters.paused += 1;
    if (record.releasing !== undefined) {
      this.#respond(record, "Fetch.continueRequest", requestId);
      return;
    }
    if (!matches(record.match, url, method, resourceType)) {
      record.counters.continued += 1;
      this.#respond(record, "Fetch.continueRequest", requestId);
      return;
    }
    this.#apply(
      record,
      {
        url,
        method,
        resourceType,
        headers: headerPairs(request?.headers),
      },
      requestId,
    );
  }

  #apply(record: RuleRecord, input: ActionInput, requestId: string): void {
    const action = record.action;
    if (action.kind === "block") {
      record.counters.blocked += 1;
      record.budget.push(decision({ ...factsOf(input), decision: "blocked" }));
      this.#respond(record, "Fetch.failRequest", requestId, {
        errorReason: action.reason,
      });
      return;
    }
    if (action.kind === "hold") {
      if (record.held.size >= BROWSER_MUTATION_LIMITS.maxHeldRequestsPerRule) {
        record.counters.hold_overflow += 1;
        record.budget.push(
          decision({ ...factsOf(input), decision: "hold-overflow" }),
        );
        this.#respond(record, "Fetch.failRequest", requestId, {
          errorReason: "BlockedByClient",
        });
        return;
      }
      record.held.set(requestId, {
        method: input.method,
        url: input.url,
        resourceType: input.resourceType,
      });
      record.counters.held += 1;
      record.budget.push(decision({ ...factsOf(input), decision: "held" }));
      return;
    }
    const mutation = mutate(action, input);
    record.counters.modified += 1;
    record.budget.push(
      decision({
        ...factsOf(input),
        decision: "modified",
        headersChanged: mutation.headersChanged,
        queryChanged: mutation.queryChanged,
        bodyReplaced: mutation.bodyReplaced,
      }),
    );
    this.#respond(record, "Fetch.continueRequest", requestId, {
      ...(mutation.url === undefined ? {} : { url: mutation.url }),
      ...(mutation.headers === undefined ? {} : { headers: mutation.headers }),
      ...(mutation.postData === undefined
        ? {}
        : { postData: mutation.postData }),
    });
  }

  #respond(
    record: RuleRecord,
    method: string,
    requestId: string,
    params: Readonly<Record<string, unknown>> = {},
  ): void {
    void this.#send(record, method, requestId, params);
  }

  async #send(
    record: RuleRecord,
    method: string,
    requestId: string,
    params: Readonly<Record<string, unknown>> = {},
  ): Promise<void> {
    await record.session.connection
      .send(method, { requestId, ...params }, record.session.sessionId)
      .catch(() => undefined);
  }
}

const factsOf = (input: ActionInput): Omit<DecisionFacts, "decision"> => ({
  method: input.method,
  url: input.url,
  resourceType: input.resourceType,
});

const matches = (
  match: BrowserRequestRuleMatch,
  url: string,
  method: string,
  resourceType: string | null,
): boolean =>
  (match.url_prefixes.length === 0 ||
    match.url_prefixes.some((prefix) => url.startsWith(prefix))) &&
  (match.methods.length === 0 || match.methods.includes(method)) &&
  (match.resource_types.length === 0 ||
    (resourceType !== null &&
      match.resource_types.some((type) => type === resourceType)));

/** Pair a CDP header map or entry list without reordering it. */
const headerPairs = (value: unknown): readonly HeaderPair[] => {
  if (Array.isArray(value))
    return value.flatMap((entry) => {
      const record = recordValue(entry);
      const name = cdpStringValue(record?.name);
      const headerValue = cdpStringValue(record?.value);
      return name === undefined || headerValue === undefined
        ? []
        : [{ name, value: headerValue }];
    });
  const record = recordValue(value);
  if (record === undefined) return [];
  return Object.entries(record).flatMap(([name, headerValue]) =>
    typeof headerValue === "string" ? [{ name, value: headerValue }] : [],
  );
};

const mutate = (
  action: Extract<BrowserRequestRuleAction, { kind: "modify" }>,
  input: ActionInput,
): RewrittenRequest => {
  const removed = new Set(
    action.remove_headers.map((name) => name.toLowerCase()),
  );
  const set = new Map(
    action.set_headers.map((header) => [header.name.toLowerCase(), header]),
  );
  const headers: HeaderPair[] = [];
  let headersChanged = 0;
  for (const header of input.headers) {
    const name = header.name.toLowerCase();
    if (removed.has(name)) {
      headersChanged += 1;
      continue;
    }
    const replacement = set.get(name);
    if (replacement !== undefined) {
      headersChanged += 1;
      headers.push({ name: header.name, value: replacement.value });
      continue;
    }
    headers.push(header);
  }
  for (const [name, header] of set)
    if (!headers.some((existing) => existing.name.toLowerCase() === name)) {
      headersChanged += 1;
      headers.push(header);
    }
  const parsed = URL.parse(input.url);
  let url: string | undefined;
  let queryChanged = 0;
  if (
    parsed !== null &&
    (action.set_query.length > 0 || action.remove_query.length > 0)
  ) {
    for (const name of action.remove_query) {
      if (parsed.searchParams.has(name)) queryChanged += 1;
      parsed.searchParams.delete(name);
    }
    for (const entry of action.set_query) {
      parsed.searchParams.set(entry.name, entry.value);
      queryChanged += 1;
    }
    url = parsed.href;
  }
  return {
    url,
    headers: headersChanged === 0 ? undefined : headers,
    postData: action.body_base64,
    headersChanged,
    queryChanged,
    bodyReplaced: action.body_base64 !== undefined,
  };
};

const decision = (
  facts: DecisionFacts,
): Omit<BrowserRequestRuleDecisionRecord, "sequence"> => {
  const parsed = URL.parse(facts.url);
  const origin =
    parsed === null || parsed.origin === "null" ? null : parsed.origin;
  return {
    method: facts.method.length === 0 ? "UNKNOWN" : facts.method,
    origin,
    path: parsed === null ? "/" : parsed.pathname,
    query_parameter_names:
      parsed === null ? [] : [...new Set(parsed.searchParams.keys())].sort(),
    resource_type: facts.resourceType,
    decision: facts.decision,
    headers_changed: facts.headersChanged ?? 0,
    query_changed: facts.queryChanged ?? 0,
    body_replaced: facts.bodyReplaced ?? false,
  };
};
