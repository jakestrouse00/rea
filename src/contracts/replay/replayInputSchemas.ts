import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../../domain/localPath.js";
import { REPLAY_LIMITS } from "../../domain/replay/replayLimits.js";
import { normalizedReplayOrigin } from "../../domain/replay/replayOrigins.js";
import { replaySessionIdSchema } from "../sessionLifecycleInputs.js";

/** Exact http or https origin: scheme, host, and optional port only. */
const replayOriginSchema = z
  .string()
  .min(1)
  .max(255)
  .refine(
    (value) => normalizedReplayOrigin(value) !== undefined,
    "Declare an exact http or https origin such as https://api.example.test; paths, queries, fragments, wildcards and userinfo are rejected.",
  );

const headerNameSchema = z
  .string()
  .min(1)
  .max(256)
  .describe(
    "HTTP header name token. A canonical credential header value travels to the server unchanged but is never echoed in Evidence.",
  );

/** One request header pair; duplicates are preserved in order. */
export const replayHeaderInputSchema = z.strictObject({
  name: headerNameSchema,
  value: z.string().max(REPLAY_LIMITS.maxHeaderBytes),
});

/** A request body as bytes or UTF-8 text; bodies never enter Evidence. */
export const replayBodyInputSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("none") }),
  z.strictObject({ kind: z.literal("text"), text: z.string() }),
  z.strictObject({ kind: z.literal("base64"), base64: z.string() }),
]);

const replayMethodSchema = z
  .string()
  .min(1)
  .max(32)
  .describe("HTTP method token; stored upper-cased.");

const replayRequestInputSchema = z.strictObject({
  method: replayMethodSchema,
  url: z
    .string()
    .min(1)
    .max(8_192)
    .describe(
      "Absolute http or https URL. Userinfo is rejected; put credentials in headers.",
    ),
  headers: z
    .array(replayHeaderInputSchema)
    .max(REPLAY_LIMITS.maxHeaderCount)
    .default([]),
  body: replayBodyInputSchema.default({ kind: "none" }),
});

const replayTimeoutSchema = z
  .int()
  .min(1)
  .max(REPLAY_LIMITS.maxTimeoutMs)
  .default(REPLAY_LIMITS.defaultTimeoutMs)
  .describe(
    `One-shot send deadline in milliseconds (default ${String(REPLAY_LIMITS.defaultTimeoutMs)}, at most ${String(REPLAY_LIMITS.maxTimeoutMs)}). REA never retries a timed-out send.`,
  );

/** Start one replay session from a HAR entry or a caller-drafted request. */
export const httpReplaySessionStartInputSchema = z
  .strictObject({
    capture_path: absoluteLocalPathStringSchema
      .optional()
      .describe(
        "Absolute path to a HAR 1.2 capture whose entries can be replayed. Required with entry_ordinal; omit when supplying request.",
      ),
    entry_ordinal: z
      .int()
      .nonnegative()
      .optional()
      .describe(
        "Zero-based capture entry to select now. Omit to list replayable entries and pass entry_ordinal to http_replay_send later.",
      ),
    request: replayRequestInputSchema
      .optional()
      .describe(
        "Caller-drafted request instead of a capture. A draft session persists this request, including credential header values, in an owner-only session file until it closes.",
      ),
    target_origins: z
      .array(replayOriginSchema)
      .min(1)
      .max(16)
      .describe(
        "Origins this session may dispatch to. Each must also appear in the operator allowlist; REA never widens either set.",
      ),
  })
  .superRefine((value, context) => {
    if ((value.capture_path === undefined) === (value.request === undefined))
      context.addIssue({
        code: "custom",
        path: [value.request === undefined ? "request" : "capture_path"],
        message:
          "Supply exactly one source: capture_path for a HAR entry, or request for a drafted request.",
      });
    if (value.entry_ordinal !== undefined && value.capture_path === undefined)
      context.addIssue({
        code: "custom",
        path: ["entry_ordinal"],
        message: "entry_ordinal selects an entry of capture_path.",
      });
  });

/** One one-shot send with an optional structured mutation. */
export const httpReplaySendInputSchema = z.strictObject({
  session_id: replaySessionIdSchema,
  entry_ordinal: z
    .int()
    .nonnegative()
    .optional()
    .describe(
      "Capture entry to send, overriding the session's selection for this send only.",
    ),
  method: replayMethodSchema.optional(),
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
    .describe(
      "Headers to add or replace by name. Content-Length and Transfer-Encoding are composed by REA from the selected body.",
    ),
  remove_headers: z
    .array(z.string().min(1).max(256))
    .max(REPLAY_LIMITS.maxHeaderCount)
    .optional()
    .describe("Headers to drop by name before set_headers is applied."),
  body: replayBodyInputSchema
    .optional()
    .describe("Replacement body; kind none sends an empty body."),
  timeout_ms: replayTimeoutSchema,
  follow_redirects: z
    .boolean()
    .default(true)
    .describe(
      `Follow at most ${String(REPLAY_LIMITS.maxRedirects)} redirects, each gated by the session's declared origins. A redirect outside them stops the chain with redirect_blocked.`,
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

export const httpReplaySessionStatusInputSchema = z.strictObject({
  session_id: replaySessionIdSchema,
});

export const httpReplaySessionCloseInputSchema = z.strictObject({
  session_id: replaySessionIdSchema,
});
