import { z } from "zod";

import {
  REPLAY_CONTENT_TYPE_CLASSES,
  REPLAY_SIZE_CLASSES,
  REPLAY_STATUS_CLASSES,
} from "./replayLimits.js";

/** One caller-selected destination for response bytes; never inline. */
export interface ReplayDumpTarget {
  readonly path: string;
  readonly overwrite: boolean;
}

/** Response bodies stay on disk; the inline form is names, classes and sizes. */
export const REPLAY_BODY_LIMITATION =
  "Response bodies are never inlined. Without a dump_path REA reads at most 1048576 bytes to classify the size and then abandons the remaining stream; with a dump_path it writes at most 67108864 bytes to that caller-selected file. A truncated body is a partial observation of the response, not its complete content.";

/** One dispatch per hop; an anti-bot refusal is an answer, not an invitation. */
export const REPLAY_RETRY_LIMITATION =
  "REA dispatched exactly one request per hop and never retries, re-solves a challenge, or varies headers after a response. A 401, 403, 429, or challenge page is a terminal observation of what this request produced.";

/** Echoed forms carry names and sizes, never credential values. */
export const REPLAY_REDACTION_LIMITATION =
  "The echoed request lists header names, a credential-header disclosure list, and body size only. Canonical credential header values are not echoed, while the exact wire bytes sent to the server are unmodified.";

/** A replayed capture describes an earlier exchange, not the current server. */
export const REPLAY_CAPTURE_LIMITATION =
  "The selected request was captured earlier than this send. Server state, session cookies, nonces, timestamps, and one-time tokens may have changed, so a different status or body does not by itself show a server behavior change.";

/** Target text is data, never a claim REA verified. */
export const REPLAY_TARGET_TEXT_LIMITATION =
  "Status lines, header names, and redirect locations are target-authored text. They are reported because the target sent them, not because REA verified their meaning.";

/** A draft session persists its credential-bearing request on disk. */
export const REPLAY_SESSION_FILE_LIMITATION =
  "A draft session persists the caller-drafted request, including credential header values, in an owner-only session file under the REA home directory. http_replay_session_close removes it; an interrupted REA process can leave it behind for a later cleanup.";

const headerNameSchema = z.string().min(1);

/** Value-free echo of one dispatched or selected request. */
export const replayRequestEchoSchema = z.strictObject({
  method: z.string().min(1),
  url: z.string().min(1),
  origin: z.string().min(1),
  header_names: z.array(headerNameSchema),
  credential_header_names: z.array(headerNameSchema),
  body_bytes: z.int().min(0),
  body_present: z.boolean(),
});

/** One dispatched hop in the redirect chain. */
export const replayRedirectStepSchema = z.strictObject({
  step: z.int().min(0),
  method: z.string().min(1),
  url: z.string().min(1),
  origin: z.string().min(1),
  status: z.int().min(100).max(999),
  status_class: z.enum(REPLAY_STATUS_CLASSES),
  location: z
    .strictObject({
      url: z.string().min(1),
      origin: z.string().min(1).nullable(),
      approved: z.boolean(),
    })
    .nullable(),
});

/** Bytes REA retained on disk for one response. */
export const replayDumpSchema = z.strictObject({
  path: z.string().min(1),
  bytes: z.int().min(0),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  truncated: z.boolean(),
});

/** Final response facts; no body content, no header values. */
export const replayResponseSchema = z.strictObject({
  status: z.int().min(100).max(999),
  status_class: z.enum(REPLAY_STATUS_CLASSES),
  content_type_class: z.enum(REPLAY_CONTENT_TYPE_CLASSES),
  header_names: z.array(headerNameSchema),
  size_class: z.enum(REPLAY_SIZE_CLASSES),
  bytes_observed: z.int().min(0),
  body_truncated: z.boolean(),
  dump: replayDumpSchema.nullable(),
});

/** A transport failure observed before any response arrived. */
export const replayTransportFailureSchema = z.strictObject({
  kind: z.enum([
    "connection",
    "dns",
    "tls",
    "reset",
    "protocol",
    "aborted",
    "other",
  ]),
  message: z.string().min(1),
});

export const REPLAY_OUTCOMES = [
  "response",
  "no_response",
  "redirect_blocked",
  "redirect_limit",
] as const;

/** Result of one one-shot send. */
export const replaySendResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  entry_ordinal: z.int().min(0).nullable(),
  request: replayRequestEchoSchema,
  redirect_chain: z.array(replayRedirectStepSchema),
  response: replayResponseSchema.nullable(),
  outcome: z.enum(REPLAY_OUTCOMES),
  failure: replayTransportFailureSchema.nullable(),
  retry: z.literal("none"),
  elapsed_ms: z.int().min(0),
});

/** One selectable capture entry, as a value-free summary. */
export const replayEntrySummarySchema = z.strictObject({
  /** Capture ordinal, or null for a drafted request with no capture. */
  ordinal: z.int().min(0).nullable(),
  method: z.string().min(1),
  url: z.string().min(1),
  origin: z.string().min(1).nullable(),
  header_names: z.array(headerNameSchema),
  credential_header_names: z.array(headerNameSchema),
  body_bytes: z.int().min(0),
});

/** Session identity and the capture it was started from. */
export const replaySessionSourceSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("draft"),
  }),
  z.strictObject({
    kind: z.literal("har"),
    path: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    entry_count: z.int().min(0),
  }),
]);

export const replaySessionFileSchema = z.strictObject({
  path: z.string().min(1),
  permissions: z.enum(["0600", "unverified"]),
});

/** Result of starting one replay session. */
export const replaySessionStartResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  source: replaySessionSourceSchema,
  entries: z.array(replayEntrySummarySchema),
  entries_truncated: z.boolean(),
  entry_count: z.int().min(0),
  selected: replayEntrySummarySchema.nullable(),
  target_origins: z.array(z.string().min(1)),
  session_file: replaySessionFileSchema,
  retry: z.literal("none"),
});

/** Result of reading one session's declared identity and counters. */
export const replaySessionStatusResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  state: z.literal("open"),
  source: replaySessionSourceSchema,
  selected: replayEntrySummarySchema.nullable(),
  entry_count: z.int().min(0),
  target_origins: z.array(z.string().min(1)),
  send_count: z.int().min(0),
  last_send_at: z.string().min(1).nullable(),
  session_file: replaySessionFileSchema,
  retry: z.literal("none"),
});

/** Result of closing one session; a failed unlink stays visible. */
export const replaySessionCloseResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  state: z.literal("closed"),
  send_count: z.int().min(0),
  session_file: z.strictObject({
    path: z.string().min(1),
    removed: z.boolean(),
  }),
});
