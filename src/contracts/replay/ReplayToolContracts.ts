import {
  httpReplaySendInputSchema,
  httpReplaySessionCloseInputSchema,
  httpReplaySessionStartInputSchema,
  httpReplaySessionStatusInputSchema,
} from "./replayInputSchemas.js";
import {
  replaySendResultSchema,
  replaySessionCloseResultSchema,
  replaySessionStartResultSchema,
  replaySessionStatusResultSchema,
} from "../../domain/replay/replayObservation.js";
import { REPLAY_ALLOWED_ORIGINS_ENV } from "../../domain/replay/replayOrigins.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/**
 * The active request plane: what does the server do when this captured request
 * (or a deliberate mutation of it) is sent again?
 *
 * A session owns one capture or drafted request plus its declared origins, and
 * every origin must also appear in the operator allowlist. A send dispatches
 * exactly once per hop and never retries. Response bodies stay on disk behind a
 * caller-selected path, and echoed forms carry header names, credential
 * disclosures, classes and sizes rather than values.
 */
export const REPLAY_TOOL_CONTRACTS = [
  {
    name: "http_replay_session_start",
    ...toolContractMetadata("http_replay_session_start"),
    description: `Open one replay session over a HAR 1.2 capture entry or a caller-drafted request. Declare the exact origins this session may dispatch to (target_origins); every one must also appear in ${REPLAY_ALLOWED_ORIGINS_ENV}, so the plane stays disabled until an operator approves origins — unless the operator set ${REPLAY_ALLOWED_ORIGINS_ENV} to "*", in which case target_origins may be omitted and every http or https origin is in scope for this session. Returns the session_id, a bounded list of capture entries that can be replayed verbatim (each with its origin, header names, credential-header disclosure and body size), the selection, and the owner-only session record path. Entries that cannot be replayed verbatim are listed with the reason. No request is sent here.`,
    kind: "replay-provider",
    inputSchema: httpReplaySessionStartInputSchema,
    outputSchema: evidenceResultOf(replaySessionStartResultSchema),
    examples: [
      {
        title: "Select a capture entry and declare its origin",
        input: {
          capture_path: "/captures/session.har",
          entry_ordinal: 3,
          target_origins: ["https://api.example.test"],
        },
      },
      {
        title: "Draft one request without a capture",
        input: {
          request: {
            method: "POST",
            url: "https://api.example.test/v1/login",
            headers: [{ name: "content-type", value: "application/json" }],
            body: { kind: "text", text: '{"user":"a"}' },
          },
          target_origins: ["https://api.example.test"],
        },
      },
    ],
  },
  {
    name: "http_replay_send",
    ...toolContractMetadata("http_replay_send"),
    description:
      "Re-send the session's selected request, optionally mutated by method, url, set_headers, remove_headers and body. REA dispatches exactly one request per hop and never retries, re-solves a challenge, or rotates headers: a 401, 403, 429 or challenge page is a terminal observation. Evidence reports the dispatched request's echoed form, the redirect chain shape, and the final status, status class, content-type class, header-name inventory, size class, elapsed time and optional raw-dump identity. Response bodies are never inlined; without dump_path REA reads at most 1048576 bytes to classify size and then abandons the body. Every redirect hop must stay inside the session's declared origins.",
    kind: "replay-provider",
    inputSchema: httpReplaySendInputSchema,
    outputSchema: evidenceResultOf(replaySendResultSchema),
    examples: [
      {
        title: "Send the selected entry verbatim",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          timeout_ms: 15000,
        },
      },
      {
        title: "Probe one mutated header with a raw dump",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          set_headers: [{ name: "x-probe", value: "1" }],
          remove_headers: ["if-none-match"],
          dump_path: "/captures/replay-1.bin",
        },
      },
    ],
  },
  {
    name: "http_replay_session_status",
    ...toolContractMetadata("http_replay_session_status"),
    description:
      "Report one replay session's source, current selection, declared origins, owner-only record path, and this server's send count and last send time. Counters describe sends this REA server performed, not the target's behavior. A record written by another REA server is never adopted.",
    kind: "replay-provider",
    inputSchema: httpReplaySessionStatusInputSchema,
    outputSchema: evidenceResultOf(replaySessionStatusResultSchema),
    examples: [
      {
        title: "Read one session's declared state",
        input: { session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7" },
      },
    ],
  },
  {
    name: "http_replay_session_close",
    ...toolContractMetadata("http_replay_session_close"),
    description:
      "Drain admitted sends, then remove this server's owner-only session record. A record that cannot be removed stays owned by the session so a later close retries it; REA never deletes a record it did not write.",
    kind: "replay-provider",
    inputSchema: httpReplaySessionCloseInputSchema,
    outputSchema: evidenceResultOf(replaySessionCloseResultSchema),
    examples: [
      {
        title: "Close one replay session",
        input: { session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
