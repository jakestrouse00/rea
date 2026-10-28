import { z } from "zod";

import {
  REPLAY_OUTCOMES,
  replayRedirectStepSchema,
  replayRequestEchoSchema,
  replayResponseSchema,
  replayTransportFailureSchema,
} from "../replay/replayObservation.js";
import {
  MITM_RULE_PHASES,
  MITM_RULE_RELEASE_REASONS,
  MITM_SESSION_STATES,
  MITM_TARGET_APPS,
} from "./mitmLimits.js";
import { mitmShapeSketchSchema } from "./mitmStream.js";

/** The proxy sees only the clients a caller pointed at it. */
export const MITM_SCOPE_LIMITATION =
  "A proxy sees exactly the clients a caller configured to use it. Traffic the target sends directly, over QUIC/HTTP3, from a pinned client, or before the listener was ready is not observed, and an empty inventory is not evidence that the target made no requests.";

/** Structure is reported; values and bodies stay out of Evidence. */
export const MITM_VALUE_FREE_LIMITATION =
  "This inventory reports only structure: origins, methods, path templates, parameter names and type classes, status counts, header names, and a bounded response-shape sketch. Header values, query values, path values, and body content are never reported; bodies exist only as owner-only files the addon wrote in the session's capture directory.";

/** Bodies live in a private directory that close removes. */
export const MITM_CAPTURE_DIRECTORY_LIMITATION =
  "Captured request and response bodies live in an owner-only capture directory for this session only. Closing the session removes that directory, so copy any body you still need out of it before closing.";

/** The addon is caller-supplied code running inside the proxy. */
export const MITM_ADDON_LIMITATION =
  "REA spawns the caller-selected mitmdump binary with the caller-supplied addon script. Both are code REA does not own; this lane verifies the protocol the addon speaks, not what the addon does with the traffic it sees.";

/** TLS interception trust stays a caller decision. */
export const MITM_TLS_LIMITATION =
  "Interception covers the applications configured to use this proxy and nothing else. REA never edits a system, browser, or device trust store, never installs a CA, and never disables certificate pinning: importing the mitmproxy CA is the caller's own reversible change, and a pinned client will refuse the proxy.";

/** A rewrite rule changes what the target receives or reads. */
export const MITM_RULE_LIMITATION =
  "A rewrite rule changes traffic as it passes. Request-phase rules alter what the server receives and response-phase rules alter what the client reads, so an observation made while a rule is armed describes the rewritten exchange, not the application's own bytes.";

/** The addon applies a control revision at its next flow hook. */
export const MITM_RULE_APPLICATION_LIMITATION =
  "A rule revision is written to the session's control file and applied by the addon when it next reads that file, so traffic already inside the proxy when the rule was armed is not rewritten. Retained decisions are REA's bounded ledger of the matches the addon reported.";

/** Rule decisions are value-free. */
export const MITM_RULE_VALUE_FREE_LIMITATION =
  "Retained decisions report the phase, method, origin, path template, status before and after, and how many header or query fields were changed. They never retain a header value, query value, or rewritten body.";

/** One-shot replay, shared with the replay lane. */
export const MITM_REPLAY_LIMITATION =
  "proxy_replay_send dispatches through the shared replay send core: exactly one request per hop, no retry, no challenge re-solve, and a replayed entry describes an earlier capture rather than the current server.";

/** Everything one start reports about the proxy it owns. */
export const mitmProxyGuidanceSchema = z.strictObject({
  target_app: z.enum(MITM_TARGET_APPS),
  per_app_only: z.literal(true),
  steps: z.array(z.string().min(1)),
  out_of_scope: z.array(z.string().min(1)),
});
export type MitmProxyGuidanceResult = z.infer<typeof mitmProxyGuidanceSchema>;

const mitmDaemonFactsSchema = z.strictObject({
  pid: z.int().min(0).nullable(),
  mitmproxy_version: z.string().min(1),
  addon: z.strictObject({
    id: z.string().min(1),
    version: z.int().min(1),
  }),
  running: z.boolean(),
});

const mitmListenFactsSchema = z.strictObject({
  host: z.literal("127.0.0.1"),
  port: z.int().min(1).max(65_535),
  proxy_url: z.string().min(1),
});

const mitmCaptureFactsSchema = z.strictObject({
  directory: z.string().min(1),
  entries: z.int().min(0),
  entries_omitted: z.int().min(0),
  permissions: z.enum(["0700", "unverified"]),
});

/** Result of one started interception session; no traffic has been read yet. */ export const mitmStartResultSchema =
  z.strictObject({
    session_id: z.string().uuid(),
    state: z.enum(MITM_SESSION_STATES),
    daemon: mitmDaemonFactsSchema,
    listen: mitmListenFactsSchema,
    capture: mitmCaptureFactsSchema,
    proxy_guidance: mitmProxyGuidanceSchema,
    tls: z.strictObject({
      scope: z.literal("per-application"),
      trust_store_changes: z.literal("out-of-scope"),
      device_wide_interception: z.literal("out-of-scope"),
      ca: z.strictObject({
        supplied_by: z.literal("caller"),
        served_at: z.literal("http://mitm.it"),
      }),
    }),
    target_origins: z.array(z.string().min(1)),
    retry: z.literal("none"),
    limitations: z.array(z.string().min(1)),
  });
export type MitmStartResult = z.infer<typeof mitmStartResultSchema>;

export const mitmInventoryTotalsSchema = z.strictObject({
  flows: z.int().min(0),
  endpoints: z.int().min(0),
  endpoints_omitted: z.int().min(0),
  facts_omitted: z.int().min(0),
  requests_without_response: z.int().min(0),
  bodies_held: z.int().min(0),
  body_bytes_held: z.int().min(0),
});

export const mitmParameterSummarySchema = z.strictObject({
  name: z.string().min(1),
  location: z.enum(["query", "path", "body"]),
  types: z.array(z.string().min(1)),
});

export const mitmStatusCountSchema = z.strictObject({
  status: z.int().min(100).max(999),
  status_class: z.string().min(1),
  count: z.int().min(1),
});

/** One endpoint of the inventory: structure, names, types and counts. */
export const mitmEndpointFactsSchema = z.strictObject({
  origin: z.string().min(1),
  method: z.string().min(1),
  path_template: z.string().min(1),
  occurrences: z.int().min(1),
  first_at: z.string().min(1),
  last_at: z.string().min(1),
  status_histogram: z.array(mitmStatusCountSchema),
  request_header_names: z.array(z.string().min(1)),
  response_header_names: z.array(z.string().min(1)),
  parameters: z.array(mitmParameterSummarySchema),
  response_shape: mitmShapeSketchSchema.nullable(),
  shape_variants: z.int().min(0),
});
export type MitmEndpointFactsResult = z.infer<typeof mitmEndpointFactsSchema>;

/** Health of the structure stream itself; a degraded stream is incomplete. */
export const mitmStreamFactsSchema = z.strictObject({
  lines: z.int().min(0),
  events: z.int().min(0),
  malformed: z.int().min(0),
  oversized: z.int().min(0),
  unknown_type: z.int().min(0),
  unknown_rule_matches: z.int().min(0),
  notices: z.int().min(0),
  errors: z.int().min(0),
  last_error: z.string().min(1).nullable(),
});

export const mitmRuleMatchSummarySchema = z.strictObject({
  origins: z.array(z.string().min(1)),
  path_prefixes: z.array(z.string().min(1)),
  methods: z.array(z.string().min(1)),
});

export const mitmRuleActionSummarySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("request"),
    set_header_names: z.array(z.string().min(1)),
    removed_header_names: z.array(z.string().min(1)),
    set_query_names: z.array(z.string().min(1)),
    removed_query_names: z.array(z.string().min(1)),
    body_replaced: z.boolean(),
  }),
  z.strictObject({
    kind: z.literal("response"),
    set_header_names: z.array(z.string().min(1)),
    removed_header_names: z.array(z.string().min(1)),
    status: z.int().min(100).max(999).nullable(),
    body_replaced: z.boolean(),
  }),
]);
export type MitmRuleActionSummary = z.infer<typeof mitmRuleActionSummarySchema>;

export const mitmRuleCountersSchema = z.strictObject({
  matched: z.int().min(0),
  requests_rewritten: z.int().min(0),
  responses_rewritten: z.int().min(0),
  headers_changed: z.int().min(0),
  query_changed: z.int().min(0),
  bodies_replaced: z.int().min(0),
  statuses_replaced: z.int().min(0),
});

/** One armed rule as the session reports it. */
export const mitmArmedRuleSchema = z.strictObject({
  rule_id: z.string().uuid(),
  phase: z.enum(MITM_RULE_PHASES),
  match: mitmRuleMatchSummarySchema,
  expires_at: z.string().min(1),
  expired: z.boolean(),
  counters: mitmRuleCountersSchema,
});

/** Read the live inventory without mutating the session. */
export const mitmInventoryResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  state: z.enum(MITM_SESSION_STATES),
  daemon: mitmDaemonFactsSchema,
  listen: mitmListenFactsSchema,
  capture: mitmCaptureFactsSchema,
  target_origins: z.array(z.string().min(1)),
  totals: mitmInventoryTotalsSchema,
  endpoints: z.array(mitmEndpointFactsSchema),
  next_offset: z.int().min(0).nullable(),
  stream: mitmStreamFactsSchema,
  rules: z.array(mitmArmedRuleSchema),
  retry: z.literal("none"),
  limitations: z.array(z.string().min(1)),
});
export type MitmInventoryResult = z.infer<typeof mitmInventoryResultSchema>;

/** The complete inventory as Evidence, optionally copied to a caller path. */
export const mitmExportResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  state: z.enum(MITM_SESSION_STATES),
  exported_at: z.string().min(1),
  totals: mitmInventoryTotalsSchema,
  endpoints: z.array(mitmEndpointFactsSchema),
  stream: mitmStreamFactsSchema,
  file: z
    .strictObject({
      path: z.string().min(1),
      bytes: z.int().min(0),
      sha256: z.string().regex(/^[a-f0-9]{64}$/u),
      permissions: z.enum(["0600", "unverified"]),
    })
    .nullable(),
  retry: z.literal("none"),
  limitations: z.array(z.string().min(1)),
});
export type MitmExportResult = z.infer<typeof mitmExportResultSchema>;

/** Write the control file and report the revision the addon will read. */
export const mitmRuleSetResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  rule_id: z.string().uuid(),
  state: z.literal("armed"),
  phase: z.enum(MITM_RULE_PHASES),
  match: mitmRuleMatchSummarySchema,
  action: mitmRuleActionSummarySchema,
  ttl_ms: z.int().min(1),
  expires_at: z.string().min(1),
  control: z.strictObject({
    revision: z.int().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  }),
  counters: mitmRuleCountersSchema,
  limitations: z.array(z.string().min(1)),
});
export type MitmRuleSetResult = z.infer<typeof mitmRuleSetResultSchema>;

/** One value-free rule decision retained in the ledger. */
export const mitmRuleDecisionSchema = z.strictObject({
  sequence: z.int().min(1),
  phase: z.enum(MITM_RULE_PHASES),
  method: z.string().min(1),
  origin: z.string().min(1),
  path_template: z.string().min(1),
  status_before: z.int().min(100).max(999).nullable(),
  status_after: z.int().min(100).max(999).nullable(),
  headers_changed: z.int().min(0),
  query_changed: z.int().min(0),
  body_replaced: z.boolean(),
  status_replaced: z.boolean(),
});

export const MITM_RULE_OMISSION_REASONS = ["retention-budget"] as const;

/** Release one rule and report every match the ledger still holds. */
export const mitmRuleClearResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  rule_id: z.string().uuid(),
  state: z.literal("cleared"),
  release_reason: z.enum(MITM_RULE_RELEASE_REASONS),
  counters: mitmRuleCountersSchema,
  decisions: z.strictObject({
    retained: z.int().min(0),
    dropped: z.int().min(0),
    items: z.array(mitmRuleDecisionSchema),
    omissions: z.array(
      z.strictObject({
        reason: z.enum(MITM_RULE_OMISSION_REASONS),
        count: z.int().min(1),
      }),
    ),
  }),
  limitations: z.array(z.string().min(1)),
});
export type MitmRuleClearResult = z.infer<typeof mitmRuleClearResultSchema>;

/** Result of one captured entry re-sent through the shared replay send core. */
export const mitmReplaySendResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  captured_sequence: z.int().min(1),
  request: replayRequestEchoSchema,
  redirect_chain: z.array(replayRedirectStepSchema),
  response: replayResponseSchema.nullable(),
  outcome: z.enum(REPLAY_OUTCOMES),
  failure: replayTransportFailureSchema.nullable(),
  retry: z.literal("none"),
  elapsed_ms: z.int().min(0),
});
export type MitmReplaySendResult = z.infer<typeof mitmReplaySendResultSchema>;

/** Observed release of one proxy session and its capture directory. */
export const mitmStopResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  state: z.enum(MITM_SESSION_STATES),
  daemon: z.strictObject({
    pid: z.int().min(0).nullable(),
    exit: z.strictObject({
      kind: z.enum(["exited", "signalled", "running", "unknown"]),
      code: z.int().nullable(),
      signal: z.string().min(1).nullable(),
    }),
  }),
  capture: z.strictObject({
    directory: z.string().min(1),
    removed: z.boolean(),
  }),
  rules_released: z.int().min(0),
  retry: z.literal("none"),
  limitations: z.array(z.string().min(1)),
});
export type MitmStopResult = z.infer<typeof mitmStopResultSchema>;
