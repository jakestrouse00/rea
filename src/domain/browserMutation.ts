import { z } from "zod";

import { webRuntimeCommandTimeoutSchema } from "./browserDeadline.js";
import {
  BROWSER_MUTATION_LIMITS,
  BROWSER_REQUEST_RULE_DECISIONS,
  BROWSER_REQUEST_RULE_OMISSION_REASONS,
} from "./browserMutationLimits.js";
import {
  browserAllowedOriginsSchema,
  browserObservationEndpointSchema,
  sanitizedBrowserUrlSchema,
} from "./browserObservation.js";
import { absoluteLocalPathStringSchema } from "./localPath.js";
import { REPLAY_LIMITS } from "./replay/replayLimits.js";
import { replayBodyByteLength } from "./replay/replayRequest.js";
import {
  REPLAY_OUTCOMES,
  replayRedirectStepSchema,
  replayRequestEchoSchema,
  replayResponseSchema,
  replayTransportFailureSchema,
} from "./replay/replayObservation.js";
import { isCanonicalBase64 } from "./stringPatterns.js";

/** Target identity of a mutation: the page REA itself launched or attached. */
export const browserMutationTargetSchema = z.strictObject({
  target_id: z.string().min(1),
  url: sanitizedBrowserUrlSchema,
  origin: z.string().min(1),
});

const mutationTargetInput = {
  cdp_endpoint: browserObservationEndpointSchema,
  allowed_origins: browserAllowedOriginsSchema,
  target_id: z.string().trim().min(1),
} as const;

/** Target text returned by an evaluation is data, never an REA claim. */
export const BROWSER_EVALUATE_TEXT_LIMITATION =
  "The expression ran inside the selected page, so its result, exception text, and value type are target-derived text. They are reported because the page produced them, not because REA verified their meaning.";

/** One evaluation is one page-side effect REA cannot undo. */
export const BROWSER_EVALUATE_SIDE_EFFECT_LIMITATION =
  "Runtime.evaluate runs the caller expression in the page's main world. Reading is not guaranteed: the expression can submit forms, change storage, or dispatch events, and REA cannot reverse those effects.";

/** Interception only sees what the attached session is asked to route. */
export const BROWSER_REQUEST_RULE_SCOPE_LIMITATION =
  "A request rule is armed on one attached main frame through the CDP Fetch domain. Requests the browser serves from cache, starts before arming, or routes through a service worker without the session seeing them are not intercepted.";

/** A hold is a paused request the browser is waiting to release. */
export const BROWSER_REQUEST_RULE_HOLD_LIMITATION = `A hold rule leaves matched requests paused until something continues them. REA releases every held request it still owns when the rule is cleared or the server closes, and fails closed with BlockedByClient once ${String(BROWSER_MUTATION_LIMITS.maxHeldRequestsPerRule)} requests are held at once. Traffic paused by a rule is not answered while it stays held.`;

/** Rule decisions are value-free observations of REA's own choices. */
export const BROWSER_REQUEST_RULE_VALUE_FREE_LIMITATION =
  "Retained decisions report the method, origin, path, resource type, and the decision REA made. Request and response header values, query values, and rewritten bodies are never retained.";

/** A page-context fetch shares the browser session, and inherits its rules. */
export const BROWSER_FETCH_SESSION_LIMITATION =
  "The request originated inside the selected page, so it shares that page's cookies, client hints, and network identity. Server state, nonces, and one-time tokens may have changed, and an armed request rule applies to this fetch like any other page traffic.";

/** Response bytes cross one CDP frame, so the page-context cap is smaller. */
export const BROWSER_FETCH_BODY_LIMITATION = `Response bytes cross one CDP frame: the page retains at most ${String(BROWSER_MUTATION_LIMITS.maxPageFetchBodyBytes)} bytes. A larger body ends as a partial observation, so without a dump_path REA counts at most ${String(REPLAY_LIMITS.maxRetainedBodyBytes)} bytes inline and reports body_truncated, while with a dump_path the send fails and the partially written file is removed rather than left looking like a complete capture.`;

/** The browser owns framing, credentials, and redirect handling here. */
export const BROWSER_FETCH_TRANSPORT_LIMITATION =
  "The browser owns the wire bytes: it composes Host, Content-Length, Connection, Cookie, Origin, Referer, Accept-Charset, Accept-Encoding, and every Sec-* or Proxy-* header, supplies the page session's own Cookie header, and drops caller values for those names, which are reported in browser_managed_header_names. Other Accept-* headers stay caller-settable. A redirected page fetch is an opaque response whose status, location, and headers the page cannot read, so the send ends as no_response instead of following an ungated hop. Cross-origin responses are additionally filtered by the page's CORS policy.";

/** Caller expression and page identity for one main-frame evaluation. */
export const browserEvaluateInputSchema = z
  .strictObject({
    ...mutationTargetInput,
    expression: z
      .string()
      .min(1)
      .describe(
        "JavaScript expression or program text evaluated in the authorized main frame's main world. It can mutate the page; REA cannot undo what it does.",
      ),
    await_promise: z
      .boolean()
      .default(true)
      .describe(
        "Wait for a returned promise to settle before reading the result.",
      ),
    command_timeout_ms: webRuntimeCommandTimeoutSchema,
  })
  .superRefine((value, context) => {
    if (
      Buffer.byteLength(value.expression, "utf8") >
      BROWSER_MUTATION_LIMITS.maxEvaluateExpressionBytes
    )
      context.addIssue({
        code: "custom",
        path: ["expression"],
        message: `One expression is limited to ${String(BROWSER_MUTATION_LIMITS.maxEvaluateExpressionBytes)} UTF-8 bytes.`,
      });
  });

/** How one evaluation ended; a thrown page error is an answer, not a crash. */
export const BROWSER_EVALUATE_OUTCOMES = [
  "value",
  "exception",
  "not_serializable",
] as const;

/** Value-free identity plus the target-derived result of one evaluation. */
export const browserEvaluateResultSchema = z.strictObject({
  target: browserMutationTargetSchema,
  expression_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  expression_bytes: z.int().min(0),
  outcome: z.enum(BROWSER_EVALUATE_OUTCOMES),
  value_type: z.string().min(1).nullable(),
  value_text: z.string().nullable(),
  value_bytes: z.int().min(0),
  value_truncated: z.boolean(),
  exception_text: z.string().nullable(),
  trust: z.literal("evaluated-untrusted"),
  limitations: z.array(z.string().min(1)),
});
export type BrowserEvaluateResult = z.infer<typeof browserEvaluateResultSchema>;

/** One caller-supplied interception predicate set. */
const browserRequestRuleMatchSchema = z
  .strictObject({
    url_prefixes: z
      .array(z.string().min(1).max(8_192))
      .max(BROWSER_MUTATION_LIMITS.maxRuleUrlPrefixes)
      .default([])
      .describe(
        "Absolute http or https URL prefixes; a request matches when its URL starts with one of them.",
      ),
    methods: z
      .array(z.string().min(1).max(32))
      .max(BROWSER_MUTATION_LIMITS.maxRuleMethods)
      .default([])
      .describe("Upper-cased HTTP method names to match."),
    resource_types: z
      .array(
        z.enum([
          "Document",
          "Stylesheet",
          "Image",
          "Media",
          "Font",
          "Script",
          "TextTrack",
          "XHR",
          "Fetch",
          "Prefetch",
          "EventSource",
          "WebSocket",
          "Manifest",
          "SignedExchange",
          "Ping",
          "CSPViolationReport",
          "Preflight",
          "Other",
        ]),
      )
      .max(BROWSER_MUTATION_LIMITS.maxRuleResourceTypes)
      .default([])
      .describe("CDP request resource types to match."),
  })
  .superRefine((value, context) => {
    for (const [index, prefix] of value.url_prefixes.entries()) {
      const parsed = URL.parse(prefix);
      if (
        parsed === null ||
        (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
        parsed.username !== "" ||
        parsed.password !== ""
      )
        context.addIssue({
          code: "custom",
          path: ["url_prefixes", index],
          message:
            "A URL prefix must be an absolute http or https URL without userinfo.",
        });
    }
    if (
      value.url_prefixes.length === 0 &&
      value.methods.length === 0 &&
      value.resource_types.length === 0
    )
      context.addIssue({
        code: "custom",
        path: ["url_prefixes"],
        message:
          "Supply at least one predicate: a rule never matches every request by accident.",
      });
  });

const ruleHeaderSchema = z.strictObject({
  name: z.string().min(1).max(256),
  value: z.string().max(REPLAY_LIMITS.maxHeaderBytes),
});
const ruleQuerySchema = z.strictObject({
  name: z.string().min(1).max(256),
  value: z.string().max(REPLAY_LIMITS.maxHeaderBytes),
});

const browserRequestRuleActionSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("block"),
    reason: z
      .enum([
        "Failed",
        "Aborted",
        "TimedOut",
        "AccessDenied",
        "ConnectionClosed",
        "ConnectionReset",
        "ConnectionRefused",
        "NameNotResolved",
        "InternetDisconnected",
        "AddressUnreachable",
        "BlockedByClient",
        "BlockedByResponse",
      ])
      .default("BlockedByClient")
      .describe(
        "CDP network error reported to the page for a blocked request.",
      ),
  }),
  z.strictObject({
    kind: z.literal("hold"),
  }),
  z
    .strictObject({
      kind: z.literal("modify"),
      set_headers: z
        .array(ruleHeaderSchema)
        .max(BROWSER_MUTATION_LIMITS.maxRuleHeaderEdits)
        .default([]),
      remove_headers: z
        .array(z.string().min(1).max(256))
        .max(BROWSER_MUTATION_LIMITS.maxRuleHeaderEdits)
        .default([]),
      set_query: z
        .array(ruleQuerySchema)
        .max(BROWSER_MUTATION_LIMITS.maxRuleQueryEdits)
        .default([]),
      remove_query: z
        .array(z.string().min(1).max(256))
        .max(BROWSER_MUTATION_LIMITS.maxRuleQueryEdits)
        .default([]),
      body_base64: z
        .string()
        .refine(isCanonicalBase64, {
          message: "A replacement body must be canonical padded base64.",
        })
        .optional()
        .describe(
          `Replacement request body bytes. Limited to ${String(BROWSER_MUTATION_LIMITS.maxRuleBodyBytes)} bytes.`,
        ),
    })
    .superRefine((value, context) => {
      const bytes =
        value.body_base64 === undefined
          ? 0
          : Math.floor((value.body_base64.length * 3) / 4);
      if (bytes > BROWSER_MUTATION_LIMITS.maxRuleBodyBytes)
        context.addIssue({
          code: "custom",
          path: ["body_base64"],
          message: `A replacement body is limited to ${String(BROWSER_MUTATION_LIMITS.maxRuleBodyBytes)} bytes.`,
        });
    }),
]);

/** Arm one interception rule on the authorized main frame. */
export const browserRequestRuleSetInputSchema = z.strictObject({
  ...mutationTargetInput,
  rule_id: z
    .string()
    .uuid()
    .optional()
    .describe(
      "Caller-selected rule identity. Omit to have REA issue one; a supplied identity that is already armed is refused rather than replaced.",
    ),
  match: browserRequestRuleMatchSchema,
  action: browserRequestRuleActionSchema,
  ttl_ms: z
    .int()
    .min(1)
    .max(BROWSER_MUTATION_LIMITS.maxRuleTtlMs)
    .default(BROWSER_MUTATION_LIMITS.defaultRuleTtlMs)
    .describe(
      `How long the rule stays armed before REA releases it (default ${String(BROWSER_MUTATION_LIMITS.defaultRuleTtlMs)} ms, at most ${String(BROWSER_MUTATION_LIMITS.maxRuleTtlMs)} ms).`,
    ),
  command_timeout_ms: webRuntimeCommandTimeoutSchema,
});

/** Facts one armed rule reports back to its caller. */
export const browserRequestRuleSetResultSchema = z.strictObject({
  rule_id: z.string().uuid(),
  state: z.literal("armed"),
  target: browserMutationTargetSchema,
  match: z.strictObject({
    url_prefixes: z.array(z.string().min(1)),
    methods: z.array(z.string().min(1)),
    resource_types: z.array(z.string().min(1)),
  }),
  action_kind: z.enum(["block", "hold", "modify"]),
  expires_at: z.string().min(1),
  limits: z.strictObject({
    ttl_ms: z.int().min(1),
    max_held_requests: z.int().min(1),
    max_retained_decisions: z.int().min(1),
  }),
  limitations: z.array(z.string().min(1)),
});
export type BrowserRequestRuleSetResult = z.infer<
  typeof browserRequestRuleSetResultSchema
>;

/** Release one armed rule; the rule identity is the whole input. */
export const browserRequestRuleClearInputSchema = z.strictObject({
  rule_id: z
    .string()
    .uuid()
    .describe("Rule identity issued by browser_request_rule_set."),
});

/** One retained interception decision, without header or query values. */
export const browserRequestRuleDecisionSchema = z.strictObject({
  sequence: z.int().min(1),
  method: z.string().min(1),
  origin: z.string().min(1).nullable(),
  path: z.string().min(1),
  query_parameter_names: z.array(z.string()),
  resource_type: z.string().min(1).nullable(),
  decision: z.enum(BROWSER_REQUEST_RULE_DECISIONS),
  headers_changed: z.int().min(0),
  query_changed: z.int().min(0),
  body_replaced: z.boolean(),
});

/** Result of releasing one rule, including everything it observed. */
export const browserRequestRuleClearResultSchema = z.strictObject({
  rule_id: z.string().uuid(),
  state: z.literal("cleared"),
  target: z.strictObject({
    target_id: z.string().min(1),
    origin: z.string().min(1),
  }),
  release_reason: z.enum(["cleared", "expired", "server-close"]),
  counters: z.strictObject({
    paused: z.int().min(0),
    continued: z.int().min(0),
    modified: z.int().min(0),
    blocked: z.int().min(0),
    held: z.int().min(0),
    held_released: z.int().min(0),
    hold_overflow: z.int().min(0),
  }),
  decisions: z.strictObject({
    retained: z.int().min(0),
    dropped: z.int().min(0),
    items: z.array(browserRequestRuleDecisionSchema),
    omissions: z.array(
      z.strictObject({
        decision: z.enum(BROWSER_REQUEST_RULE_DECISIONS),
        count: z.int().min(1),
        reasons: z.array(z.enum(BROWSER_REQUEST_RULE_OMISSION_REASONS)).min(1),
      }),
    ),
  }),
  limitations: z.array(z.string().min(1)),
});
export type BrowserRequestRuleClearResult = z.infer<
  typeof browserRequestRuleClearResultSchema
>;

const browserFetchHeaderInputSchema = z.strictObject({
  name: z.string().min(1).max(256),
  value: z.string().max(REPLAY_LIMITS.maxHeaderBytes),
});

type BrowserFetchBodyInput =
  | { readonly kind: "none" }
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "base64"; readonly base64: string };

/** Byte length a page-context body sends, without materializing it. */
const fetchBodyByteLength = (value: BrowserFetchBodyInput): number =>
  replayBodyByteLength(value);

/** Refuse an oversized or non-canonical body before any dispatch is spent. */
const refineFetchBody = (
  value: BrowserFetchBodyInput,
  context: z.RefinementCtx,
): void => {
  if (value.kind === "base64" && !isCanonicalBase64(value.base64)) {
    context.addIssue({
      code: "custom",
      path: ["base64"],
      message: "Request body bytes must be canonical padded base64.",
    });
    return;
  }
  if (fetchBodyByteLength(value) > REPLAY_LIMITS.maxRequestBodyBytes)
    context.addIssue({
      code: "custom",
      path: [value.kind === "base64" ? "base64" : "text"],
      message: `One request body is limited to ${String(REPLAY_LIMITS.maxRequestBodyBytes)} bytes.`,
    });
};

const browserFetchBodyInputSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("none") }).superRefine(refineFetchBody),
  z
    .strictObject({ kind: z.literal("text"), text: z.string() })
    .superRefine(refineFetchBody),
  z
    .strictObject({ kind: z.literal("base64"), base64: z.string() })
    .superRefine(refineFetchBody),
]);

/** One page-context request through the real browser's own session. */
export const browserFetchInputSchema = z.strictObject({
  ...mutationTargetInput,
  method: z
    .string()
    .min(1)
    .max(32)
    .describe("HTTP method token; composed upper-cased."),
  url: z
    .string()
    .min(1)
    .max(8_192)
    .describe(
      "Absolute http or https URL to request from the page. Its origin must be inside allowed_origins or the target's origin, and inside the operator allowlist.",
    ),
  headers: z
    .array(browserFetchHeaderInputSchema)
    .max(REPLAY_LIMITS.maxHeaderCount)
    .default([])
    .describe(
      "Caller header pairs. Browser-owned names (Host, Content-Length, Cookie, Origin, Sec-*, ...) are reported and dropped instead of being sent.",
    ),
  body: browserFetchBodyInputSchema.default({ kind: "none" }),
  timeout_ms: z
    .int()
    .min(1)
    .max(REPLAY_LIMITS.maxTimeoutMs)
    .default(REPLAY_LIMITS.defaultTimeoutMs)
    .describe(
      `One-shot send deadline in milliseconds (default ${String(REPLAY_LIMITS.defaultTimeoutMs)}, at most ${String(REPLAY_LIMITS.maxTimeoutMs)}). REA never retries a timed-out send.`,
    ),
  dump_path: absoluteLocalPathStringSchema
    .optional()
    .describe(
      `Absolute path for the raw response bytes, written owner-only. At most ${String(REPLAY_LIMITS.maxDumpBodyBytes)} bytes are retained. Without it REA reads at most ${String(REPLAY_LIMITS.maxRetainedBodyBytes)} bytes to classify size, then abandons the body.`,
    ),
  overwrite: z
    .boolean()
    .default(false)
    .describe("Replace an existing dump_path file instead of refusing."),
  command_timeout_ms: webRuntimeCommandTimeoutSchema,
});

/** One page-context dispatch, projected with the replay exchange vocabulary. */
export const browserFetchResultSchema = z.strictObject({
  target: browserMutationTargetSchema,
  request: replayRequestEchoSchema,
  browser_managed_header_names: z.array(z.string().min(1)),
  redirect_chain: z.array(replayRedirectStepSchema),
  response: replayResponseSchema.nullable(),
  outcome: z.enum(REPLAY_OUTCOMES),
  failure: replayTransportFailureSchema.nullable(),
  retry: z.literal("none"),
  elapsed_ms: z.int().min(0),
  limitations: z.array(z.string().min(1)),
});
export type BrowserFetchResult = z.infer<typeof browserFetchResultSchema>;

export type BrowserEvaluateInput = z.output<typeof browserEvaluateInputSchema>;
export type BrowserRequestRuleSetInput = z.output<
  typeof browserRequestRuleSetInputSchema
>;
export type BrowserRequestRuleClearInput = z.output<
  typeof browserRequestRuleClearInputSchema
>;
export type BrowserFetchInput = z.output<typeof browserFetchInputSchema>;

export type BrowserRequestRuleMatch = z.output<
  typeof browserRequestRuleMatchSchema
>;
export type BrowserRequestRuleAction = z.output<
  typeof browserRequestRuleActionSchema
>;
