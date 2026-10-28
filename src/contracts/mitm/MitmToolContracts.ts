import {
  exportEndpointInventoryInputSchema,
  proxyReplaySendInputSchema,
  proxyRuleClearInputSchema,
  proxyRuleSetInputSchema,
  readInterceptionInventoryInputSchema,
  startInterceptionSessionInputSchema,
  stopInterceptionSessionInputSchema,
} from "./mitmInputSchemas.js";
import {
  mitmExportResultSchema,
  mitmInventoryResultSchema,
  mitmReplaySendResultSchema,
  mitmRuleClearResultSchema,
  mitmRuleSetResultSchema,
  mitmStartResultSchema,
  mitmStopResultSchema,
} from "../../domain/mitm/mitmInterception.js";
import {
  MITM_ADDON_DIR_ENV,
  MITM_COMMAND_ENV,
} from "../../domain/mitm/mitmLimits.js";
import { REPLAY_ALLOWED_ORIGINS_ENV } from "../../domain/replay/replayOrigins.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/**
 * The interception lane answers: what does this application actually send, and
 * what happens if one request or response is rewritten or re-sent?
 *
 * One caller-supplied mitmdump process serves a per-application proxy; its
 * addon streams structure to REA, retains bodies in an owner-only capture
 * directory, and reads standing rewrite rules from a control file. Nothing here
 * changes a system or device trust store, and no body enters Evidence.
 */
export const MITM_TOOL_CONTRACTS = [
  {
    name: "start_interception_session",
    ...toolContractMetadata("start_interception_session"),
    description: `Open one interception session on the loopback proxy at 127.0.0.1:<listen_port>, using the caller-supplied mitmdump binary in ${MITM_COMMAND_ENV} and the generated addon in ${MITM_ADDON_DIR_ENV}. The result names the session_id, the per-application proxy configuration steps for target_app, and what this lane never changes: no system, browser, or device trust store, no device-wide interception, and no pinning bypass. The addon streams only structure — origins, methods, path templates, parameter names and type classes, status counts, header names, and a response-shape sketch — and retains request and response bodies as owner-only files in a private capture directory. Declare target_origins for later proxy_replay_send calls; they bound REA-initiated replays only and never filter what the configured client may send through the proxy.`,
    kind: "mitm-provider",
    inputSchema: startInterceptionSessionInputSchema,
    outputSchema: evidenceResultOf(mitmStartResultSchema),
    examples: [
      {
        title: "Proxy one Android package on the default port",
        input: {
          target_app: "android-app",
          app_identifier: "com.example.app",
          target_origins: ["https://api.example.test"],
        },
      },
      {
        title: "Proxy one browser profile on a chosen port",
        input: {
          target_app: "browser",
          listen_port: 9090,
          target_origins: ["https://api.example.test"],
        },
      },
    ],
  },
  {
    name: "read_interception_inventory",
    ...toolContractMetadata("read_interception_inventory"),
    description:
      "Read one bounded page of the live endpoint inventory: per origin/method/path-template, how often it was seen, its status histogram, request and response header names, parameter names with the type classes observed for them, and a bounded response-shape sketch. Also reports how many frames the structure stream carried and how many were refused, so a degraded stream cannot be mistaken for complete observation. Header values, query values, path values, and body content are never reported. No traffic is dispatched.",
    kind: "mitm-provider",
    inputSchema: readInterceptionInventoryInputSchema,
    outputSchema: evidenceResultOf(mitmInventoryResultSchema),
    examples: [
      {
        title: "Read the first page of ten endpoints",
        input: { session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7" },
      },
      {
        title: "Page past the first twenty endpoints",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          offset: 20,
          limit: 20,
        },
      },
    ],
  },
  {
    name: "export_endpoint_inventory",
    ...toolContractMetadata("export_endpoint_inventory"),
    description:
      "Export the complete retained endpoint inventory as Evidence, including every endpoint, its totals and omissions, and the structure-stream health. Pass path to also write an owner-only JSON copy of the same inventory, which is the candidate pool a rate-limited, lab-only Arjun-style parameter probe consumes. Omitted endpoints and facts stay explicit; the export is not a claim that the proxy saw every request the target made.",
    kind: "mitm-provider",
    inputSchema: exportEndpointInventoryInputSchema,
    outputSchema: evidenceResultOf(mitmExportResultSchema),
    examples: [
      {
        title: "Export the inventory inline",
        input: { session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7" },
      },
      {
        title: "Export and keep a JSON copy",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          path: "/cases/api/endpoints.json",
        },
      },
    ],
  },
  {
    name: "proxy_rule_set",
    ...toolContractMetadata("proxy_rule_set"),
    description:
      "Arm one standing rewrite rule on the session's proxy. A request-phase rule sets or removes request headers and query parameters and can replace the request body; a response-phase rule sets or removes response headers, replaces the status, and can replace the response body. At least one predicate (origin, path prefix, method) is required, so a rule never matches every exchange by accident. REA writes the rule into the addon's control file atomically and reports the revision and digest the addon will read; matches are counted without header, query, or body values. The rule is released by proxy_rule_clear, its ttl_ms deadline, or server shutdown.",
    kind: "mitm-provider",
    inputSchema: proxyRuleSetInputSchema,
    outputSchema: evidenceResultOf(mitmRuleSetResultSchema),
    examples: [
      {
        title: "Add one probe header to one path",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          match: { path_prefixes: ["/v1/users"] },
          action: {
            kind: "request",
            set_headers: [{ name: "x-probe", value: "1" }],
          },
          ttl_ms: 60000,
        },
      },
      {
        title: "Replace one response status",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          match: { origins: ["https://api.example.test"], methods: ["GET"] },
          action: { kind: "response", status: 418 },
        },
      },
    ],
  },
  {
    name: "proxy_rule_clear",
    ...toolContractMetadata("proxy_rule_clear"),
    description:
      "Release one armed rewrite rule and report its bounded decision ledger: how many exchanges matched, how many headers, query parameters, bodies, and statuses were changed, and a value-free row per retained match. Clearing a rule that expired reports release_reason expired; an unknown rule identity is a typed input error, so a retry after an unremovable control write is the only safe repeat.",
    kind: "mitm-provider",
    inputSchema: proxyRuleClearInputSchema,
    outputSchema: evidenceResultOf(mitmRuleClearResultSchema),
    examples: [
      {
        title: "Release one rule",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          rule_id: "0b4f5d4c-1a52-4f7f-9a0e-9f9a1a0b3c4d",
        },
      },
    ],
  },
  {
    name: "proxy_replay_send",
    ...toolContractMetadata("proxy_replay_send"),
    description:
      "Re-send one captured entry through the same send core as http_replay_send: exactly one request per hop, no retry, no challenge re-solve, and an optional structured mutation (method, url, set_headers, remove_headers, body). The entry's request and body come from the addon's owner-only record in the capture directory. Evidence reports the echoed request, the redirect chain shape, and the final status, classes, header-name inventory, size class, elapsed time, and optional raw-dump identity; response bodies are never inlined. Every hop must stay inside the origins this session declared and the operator allowlist in " +
      `${REPLAY_ALLOWED_ORIGINS_ENV}.`,
    kind: "mitm-provider",
    inputSchema: proxyReplaySendInputSchema,
    outputSchema: evidenceResultOf(mitmReplaySendResultSchema),
    examples: [
      {
        title: "Re-send one captured entry verbatim",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          sequence: 4,
        },
      },
      {
        title: "Probe one mutated header with a raw dump",
        input: {
          session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          sequence: 4,
          set_headers: [{ name: "x-probe", value: "1" }],
          remove_headers: ["if-none-match"],
          dump_path: "/cases/api/probe.bin",
        },
      },
    ],
  },
  {
    name: "stop_interception_session",
    ...toolContractMetadata("stop_interception_session"),
    description:
      "Stop one interception session: stop the owned proxy, release every armed rule, and remove the session's owner-only capture directory. Copy any captured body you still need out of that directory first, because removal deletes it. A failed stop or an unremovable capture directory keeps the session identity so a retry can finish the release.",
    kind: "mitm-provider",
    inputSchema: stopInterceptionSessionInputSchema,
    outputSchema: evidenceResultOf(mitmStopResultSchema),
    examples: [
      {
        title: "Stop one session",
        input: { session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
