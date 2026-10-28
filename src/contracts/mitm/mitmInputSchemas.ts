import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../../domain/localPath.js";
import { MITM_LIMITS, MITM_TARGET_APPS } from "../../domain/mitm/mitmLimits.js";
import { REPLAY_LIMITS } from "../../domain/replay/replayLimits.js";
import {
  hasHeaderLineBreakOrNul,
  isHttpFieldNameToken,
  replayBodyByteLength,
} from "../../domain/replay/replayRequest.js";
import { isCanonicalBase64 } from "../../domain/stringPatterns.js";
import {
  replayBodyInputSchema,
  replayHeaderInputSchema,
  replayOriginSchema,
} from "../replay/replayInputSchemas.js";
import { mitmSessionIdSchema } from "../sessionLifecycleInputs.js";

const mitmPathPrefixSchema = z
  .string()
  .min(1)
  .max(8_192)
  .refine(
    (value) =>
      value.startsWith("/") && !value.includes("?") && !value.includes("#"),
    "A path prefix starts with / and carries no query or fragment; it matches a request path that starts with it.",
  );

const mitmRuleMatchSchema = z
  .strictObject({
    origins: z
      .array(replayOriginSchema)
      .max(16)
      .default([])
      .describe("Exact origins a request must belong to."),
    path_prefixes: z
      .array(mitmPathPrefixSchema)
      .max(16)
      .default([])
      .describe("Request path prefixes to match."),
    methods: z
      .array(z.string().min(1).max(32))
      .max(MITM_LIMITS.maxRuleHeaderEdits)
      .default([])
      .describe("Upper-cased HTTP methods to match."),
  })
  .superRefine((value, context) => {
    if (
      value.origins.length === 0 &&
      value.path_prefixes.length === 0 &&
      value.methods.length === 0
    )
      context.addIssue({
        code: "custom",
        path: ["origins"],
        message:
          "Supply at least one predicate: a rule never matches the whole proxy by accident.",
      });
  });

const mitmRuleHeaderNameSchema = z
  .string()
  .min(1)
  .max(256)
  .refine(
    isHttpFieldNameToken,
    "An HTTP header name is a token: no spaces, colons, or control characters.",
  );

const mitmRuleQueryNameSchema = z
  .string()
  .min(1)
  .max(256)
  .refine(
    (value) => !hasHeaderLineBreakOrNul(value),
    "A query field name cannot contain CR, LF, or NUL.",
  );

const mitmRuleHeaderSchema = z.strictObject({
  name: mitmRuleHeaderNameSchema,
  value: z
    .string()
    .max(REPLAY_LIMITS.maxHeaderBytes)
    .refine(
      (value) => !hasHeaderLineBreakOrNul(value),
      "A header value cannot contain CR, LF, or NUL.",
    ),
});

const mitmRuleQuerySchema = z.strictObject({
  name: mitmRuleQueryNameSchema,
  value: z
    .string()
    .max(REPLAY_LIMITS.maxHeaderBytes)
    .refine(
      (value) => !hasHeaderLineBreakOrNul(value),
      "A query field value cannot contain CR, LF, or NUL.",
    ),
});

const mitmRuleBodySchema = z
  .string()
  .refine(isCanonicalBase64, {
    message: "A replacement body must be canonical padded base64.",
  })
  .describe(
    `Replacement body bytes; limited to ${String(MITM_LIMITS.maxRuleBodyBytes)} bytes.`,
  )
  .superRefine((value, context) => {
    if (
      replayBodyByteLength({ kind: "base64", base64: value }) >
      MITM_LIMITS.maxRuleBodyBytes
    )
      context.addIssue({
        code: "custom",
        message: `A replacement body is limited to ${String(MITM_LIMITS.maxRuleBodyBytes)} bytes.`,
      });
  });

const mitmRuleActionSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("request"),
    set_headers: z
      .array(mitmRuleHeaderSchema)
      .max(MITM_LIMITS.maxRuleHeaderEdits)
      .default([]),
    remove_headers: z
      .array(mitmRuleHeaderNameSchema)
      .max(MITM_LIMITS.maxRuleHeaderEdits)
      .default([]),
    set_query: z
      .array(mitmRuleQuerySchema)
      .max(MITM_LIMITS.maxRuleQueryEdits)
      .default([]),
    remove_query: z
      .array(mitmRuleQueryNameSchema)
      .max(MITM_LIMITS.maxRuleQueryEdits)
      .default([]),
    body_base64: mitmRuleBodySchema.optional(),
  }),
  z.strictObject({
    kind: z.literal("response"),
    set_headers: z
      .array(mitmRuleHeaderSchema)
      .max(MITM_LIMITS.maxRuleHeaderEdits)
      .default([]),
    remove_headers: z
      .array(mitmRuleHeaderNameSchema)
      .max(MITM_LIMITS.maxRuleHeaderEdits)
      .default([]),
    status: z.int().min(100).max(999).optional(),
    body_base64: mitmRuleBodySchema.optional(),
  }),
]);

/** Start one per-application interception session on the loopback listener. */
export const startInterceptionSessionInputSchema = z.strictObject({
  target_app: z
    .enum(MITM_TARGET_APPS)
    .describe(
      "Application the proxy configuration guidance is written for. Every step changes that application's own proxy setting, never the host's or device's.",
    ),
  app_identifier: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Package name, bundle identifier, or harness name the guidance names. Never interpreted as a path.",
    ),
  listen_port: z
    .int()
    .min(1)
    .max(MITM_LIMITS.maxListenPort)
    .default(MITM_LIMITS.defaultListenPort)
    .describe(
      `Loopback port the proxy binds (default ${String(MITM_LIMITS.defaultListenPort)}). It never binds a routable interface.`,
    ),
  target_origins: z
    .array(replayOriginSchema)
    .min(1)
    .max(16)
    .describe(
      "Exact origins proxy_replay_send may dispatch to. Each must also appear in REA_REPLAY_ALLOWED_ORIGINS. This list bounds REA-initiated replays only; it never filters what the configured client may send through the proxy.",
    ),
  start_timeout_ms: z
    .int()
    .min(1)
    .max(MITM_LIMITS.maxStartTimeoutMs)
    .default(MITM_LIMITS.defaultStartTimeoutMs)
    .describe(
      `Deadline for the addon's startup advertisement (default ${String(MITM_LIMITS.defaultStartTimeoutMs)} ms).`,
    ),
});

/** Read one bounded page of the live inventory. */
export const readInterceptionInventoryInputSchema = z.strictObject({
  session_id: mitmSessionIdSchema,
  offset: z
    .int()
    .nonnegative()
    .default(0)
    .describe("Zero-based endpoint row to start this page with."),
  limit: z
    .int()
    .min(1)
    .max(MITM_LIMITS.maxListedEndpoints)
    .default(10)
    .describe(
      `Endpoint rows to return (at most ${String(MITM_LIMITS.maxListedEndpoints)}). next_offset names the following page.`,
    ),
});

/** Export the complete inventory as Evidence, optionally copied to a path. */
export const exportEndpointInventoryInputSchema = z.strictObject({
  session_id: mitmSessionIdSchema,
  path: absoluteLocalPathStringSchema
    .optional()
    .describe(
      "Absolute path for a JSON copy of the same inventory, written owner-only. The Evidence result carries the inventory either way.",
    ),
  overwrite: z
    .boolean()
    .default(false)
    .describe("Replace an existing path file instead of refusing."),
});

/** Arm one standing request or response rewrite rule. */
export const proxyRuleSetInputSchema = z.strictObject({
  session_id: mitmSessionIdSchema,
  rule_id: z
    .string()
    .uuid()
    .optional()
    .describe(
      "Caller-selected rule identity. Omit to have REA issue one; a supplied identity that is already armed is refused rather than replaced.",
    ),
  match: mitmRuleMatchSchema,
  action: mitmRuleActionSchema,
  ttl_ms: z
    .int()
    .min(1)
    .max(MITM_LIMITS.maxRuleTtlMs)
    .default(MITM_LIMITS.defaultRuleTtlMs)
    .describe(
      `How long the rule stays armed before REA releases it (default ${String(MITM_LIMITS.defaultRuleTtlMs)} ms, at most ${String(MITM_LIMITS.maxRuleTtlMs)} ms).`,
    ),
});

/** Release one armed rule and read its ledger. */
export const proxyRuleClearInputSchema = z.strictObject({
  session_id: mitmSessionIdSchema,
  rule_id: z
    .string()
    .uuid()
    .describe("Rule identity issued by proxy_rule_set."),
});

/** Release one live interception session and its capture directory. */
export const stopInterceptionSessionInputSchema = z.strictObject({
  session_id: mitmSessionIdSchema,
});

/** Re-send one captured entry through the shared send core. */
export const proxyReplaySendInputSchema = z.strictObject({
  session_id: mitmSessionIdSchema,
  sequence: z
    .int()
    .min(1)
    .describe(
      "Structure-stream sequence of the captured entry to re-send, as read_interception_inventory and export_endpoint_inventory report it.",
    ),
  method: z.string().min(1).max(32).optional(),
  url: z
    .string()
    .min(1)
    .max(8_192)
    .optional()
    .describe(
      "Replacement absolute URL. Its origin must be one this session declared.",
    ),
  set_headers: z
    .array(replayHeaderInputSchema)
    .max(REPLAY_LIMITS.maxHeaderCount)
    .optional()
    .describe("Headers to add or replace by name before the one dispatch."),
  remove_headers: z
    .array(z.string().min(1).max(256))
    .max(REPLAY_LIMITS.maxHeaderCount)
    .optional()
    .describe("Headers to drop by name before set_headers is applied."),
  body: replayBodyInputSchema
    .optional()
    .describe("Replacement body; kind none sends an empty body."),
  timeout_ms: z
    .int()
    .min(1)
    .max(REPLAY_LIMITS.maxTimeoutMs)
    .default(REPLAY_LIMITS.defaultTimeoutMs)
    .describe(
      `One-shot send deadline in milliseconds (default ${String(REPLAY_LIMITS.defaultTimeoutMs)}, at most ${String(REPLAY_LIMITS.maxTimeoutMs)}). REA never retries a timed-out send.`,
    ),
  follow_redirects: z
    .boolean()
    .default(true)
    .describe(
      `Follow at most ${String(REPLAY_LIMITS.maxRedirects)} redirects, each gated by the session's declared origins.`,
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
});
