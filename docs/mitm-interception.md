# mitmproxy interception

`start_interception_session` runs one caller-supplied `mitmdump` on a loopback
listener and answers two questions: **what does this application actually
send?**, and **what happens when one request or response is rewritten, or one
captured entry is sent again?**

The lane is a per-application proxy, not a device tap. It reads structure from a
generated addon over a JSON-lines stream, keeps bodies in an owner-only capture
directory, and dispatches replays through the same send core as
[HTTP replay](./replay-client.md).

| Tool                          | Purpose                                                              |
| ----------------------------- | -------------------------------------------------------------------- |
| `start_interception_session`  | Start the loopback proxy and report per-app configuration guidance   |
| `read_interception_inventory` | Page the live endpoint inventory                                     |
| `export_endpoint_inventory`   | Return the complete inventory as Evidence, optionally as a JSON file |
| `proxy_rule_set`              | Arm one standing request or response rewrite rule                    |
| `proxy_rule_clear`            | Release one rule and read its value-free decision ledger             |
| `proxy_replay_send`           | Re-send one captured entry, verbatim or mutated, exactly once        |
| `stop_interception_session`   | Stop the proxy and remove its capture directory                      |

These are MCP-only session tools; this release has no CLI command for them.

## Enabling the lane

| Setting                      | Meaning                                                                                                                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REA_MITMDUMP_COMMAND`       | **Required.** Absolute path to a caller-supplied `mitmdump` binary (mitmproxy 12.x is what the lane is written for). A relative, missing, or non-executable path is a configuration refusal naming the setting and remediation. |
| `REA_MITM_ADDON_DIR`         | **Required.** Absolute path to the directory holding the generated `rea_mitm_addon.py`. The addon is not shipped pre-generated; the directory must contain it.                                                                  |
| `REA_REPLAY_ALLOWED_ORIGINS` | **Required for `proxy_replay_send`.** The same JSON array of exact origins the replay plane uses. Capture and rewriting work without it; a replay does not.                                                                     |
| `REA_ARJUN_COMMAND`          | Documented hook only. See [parameter mining](#parameter-mining).                                                                                                                                                                |

Generate the addon into a directory of your own:

```sh
node bridge/mitm/generate_addon.ts --out /absolute/addon-directory
REA_MITM_ADDON_DIR=/absolute/addon-directory REA_MITMDUMP_COMMAND=/absolute/bin/mitmdump rea mcp
```

`--check` verifies that a generated addon still matches the generator, and
`--force` replaces an existing file. REA never downloads, installs, or upgrades
mitmproxy, and it never writes a certificate into a trust store.

## Per-application proxy configuration only

`start_interception_session` accepts `target_app` (`browser`, `android-app`,
`ios-app`, `desktop-app`, `other`) and returns the steps that configure **that
application's own proxy setting**:

- **browser** — launch only the profile under test with
  `--proxy-server=http://127.0.0.1:<port>` and a separate `--user-data-dir`;
- **android-app** — a debuggable build with `adb reverse tcp:<port> tcp:<port>`
  and a per-package network-security-config that trusts the mitmproxy CA;
- **ios-app** — an instrumented simulator or lab-owned device app with its own
  proxy configuration;
- **desktop-app** — `HTTPS_PROXY`/`HTTP_PROXY` in the application's own
  environment.

Explicitly **out of scope**, and refused rather than performed:

- no CA certificate is imported into a system, browser, or device trust store;
- no device-wide or system-wide interception (global proxy, Wi-Fi proxy
  payload, transparent redirect, firewall rule);
- no certificate-pinning bypass inside the target. A pinned client refuses this
  proxy, and that refusal is the observation.

The CA stays caller-supplied; `http://mitm.it` serves it while the proxy runs.

## The structure stream

The addon writes one JSON object per line to its stdout. REA parses a **closed**
vocabulary — `ready`, `flow`, `rule_match`, `notice`, `error` — and refuses
anything else instead of interpreting it:

- `ready` — protocol version, addon identity, mitmproxy version, loopback
  listener. A mismatched protocol, port, or shape is a refused startup.
- `flow` — origin, method, path template with value segments replaced by
  `{integer}`, `{uuid}`, or `{hex}`, parameter names with their type classes,
  request and response header names, the response status, and a bounded
  response-shape sketch.
- `rule_match` — the phase, method, origin, path template, statuses, and how many
  header or query fields a rule changed.
- `notice` / `error` — control-file or capture conditions and hook failures.

Nothing in the stream carries a header value, a query value, a path value, or a
body. Bodies reach REA only as files the addon already wrote owner-only inside
the session's capture directory, and the frame names them by path, size, and
SHA-256. Header names, path templates, and shape keys are target-authored text;
they are reported as untrusted data.

A frame that does not parse, exceeds 262144 bytes, or carries an unknown type is
counted (`stream.malformed`, `stream.oversized`, `stream.unknown_type`) and the
session keeps capturing. After 32 refused frames the session reports
`state: "degraded"`, because a partially parsed stream is not complete
observation. It never crashes the proxy on its own output.

## Inventory

`read_interception_inventory` returns one page of endpoints (`offset`, `limit`,
`next_offset`) plus session-wide totals: flows, endpoints, omitted endpoints,
omitted facts, requests without a response, bodies held, and their bytes. Each
endpoint reports its status histogram, header names per direction, parameter
names with every type class observed, the first response-shape sketch, and
`shape_variants` when later responses differed.

`export_endpoint_inventory` returns the complete retained inventory as Evidence
and, with `path`, writes an owner-only (`0600`) JSON copy of the same inventory.
That file is the candidate pool for parameter mining. The inventory is bounded
(512 endpoints, 32 parameter rows and 16 status counts per endpoint, 64 header
names per direction); omissions are counted, never replaced silently.

## Rewrite rules

`proxy_rule_set` arms one standing rule per session:

- `match` — at least one of `origins`, `path_prefixes`, `methods`. All supplied
  lists must match, so a rule never rewrites the whole proxy by accident.
- `action` — `kind: "request"` sets or removes request headers and query
  parameters and can replace the request body; `kind: "response"` sets or
  removes response headers, replaces the status, and can replace the response
  body.
- `ttl_ms` — default 300000, at most 3600000. At most 32 rules stay armed on one
  session.

REA writes the rule set into the session's `rules.json` atomically (owner-only,
revisioned, with a SHA-256). The addon re-reads that file when its modification
time changes and applies the new revision at its next flow hook, so traffic
already inside the proxy when the rule was armed is not rewritten. The addon also
drops a rule past its `expires_at`, so a failed control write cannot leave a rule
applied forever.

`proxy_rule_clear` removes the rule, reports `release_reason` (`cleared`,
`expired`, or `server-close`), and returns the bounded decision ledger: counters
for matched exchanges, rewritten requests and responses, changed headers, query
fields, replaced bodies, and replaced statuses, plus one value-free row per
retained match. Clearing an unknown or already-cleared rule is a typed input
error, so a retry only makes sense after an unremovable control write.

## Captured-entry replay

Every completed exchange leaves an owner-only replayable record in
`<capture>/entries/<sequence>.json` with the exact request line, header pairs,
and a reference to the retained request body. `proxy_replay_send` reads that
record and hands a `ReplayRequest` to the shared send core:

- one dispatch per hop, no retry, no challenge re-solve;
- each hop must stay inside the origins this session declared **and** inside
  `REA_REPLAY_ALLOWED_ORIGINS`;
- mutation order is method/url, then header removal, then header set, then body;
- response bodies are never inlined: without `dump_path` at most 1 MiB is
  counted inline and the stream abandoned, with `dump_path` at most 64 MiB is
  written owner-only with its digest, and a partial dump is removed;
- the echoed request lists header names and a credential-header disclosure list,
  never values.

The entry record itself holds the captured credential header values, exactly
like a HAR capture, because a verbatim replay needs them. It lives in the
session's private capture directory and is removed when the session stops.

## Capture directory lifecycle

```text
start_interception_session → capture_directory (0700)
                             ├── bodies/<sequence>.req.bin, .res.bin (0600)
                             ├── entries/<sequence>.json (0600)
                             └── rules.json (0600)
stop_interception_session  → proxy stopped, capture_directory removed
```

`stop_interception_session` stops the owned proxy, releases every armed rule,
and removes the capture directory. Copy any body you still need out of that
directory first. A failed stop or an unremovable directory keeps the session
identity so a retry finishes the release; server shutdown stops every session
the same way.

The proxy child is supervised by `src/process/`: it is spawned in its own
process group, stopped with TERM then KILL, and retained when cleanup cannot be
verified.

## Parameter mining

`REA_ARJUN_COMMAND` is a documented hook, not a tool: this release ships no
Arjun runner. The intended workflow is to take the candidate pool from
`export_endpoint_inventory`, run a caller-supplied Arjun binary yourself against
a **lab-owned** target, rate-limit it, and keep it to the same one-session,
one-try anti-bot discipline the replay plane uses. Any probe that dispatches
must also go through an approved origin, which is what `proxy_replay_send`
enforces; Arjun is not wired to that gate.

## Limits

| Limit                          | Value        | Override |
| ------------------------------ | ------------ | -------- |
| One structure-stream frame     | 262144 bytes | fixed    |
| Refused frames before degraded | 32           | fixed    |
| Endpoints per session          | 512          | fixed    |
| Parameter rows per endpoint    | 32           | fixed    |
| Status counts per endpoint     | 16           | fixed    |
| Header names per direction     | 64           | fixed    |
| Armed rules per session        | 32           | fixed    |
| Rule lifetime                  | 1–3600000 ms | per rule |
| Retained decisions per rule    | 256          | fixed    |
| Retained body                  | 64 MiB       | fixed    |
| Tracked replayable entries     | 1024         | fixed    |
| Replay send deadline           | 1–60000 ms   | per send |

## Verification scope

The offline suite exercises this lane with a scripted `mitmdump` stand-in and a
scripted transport: startup refusals, stream parsing, inventory round-trips and
bounds, export permissions, rule arm/clear lifecycle and the control file, and
one-shot replay through the shared core. `bridge/mitm/test_addon.py` imports the
generated addon without `mitmproxy` installed and exercises its pure helpers and
hooks against local fakes.

This branch has not run a real mitmdump, a real device, or a real TLS handshake,
so no claim is made about a specific client's proxy behavior, certificate
validation, or negotiation.
