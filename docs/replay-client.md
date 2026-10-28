# HTTP replay client (active request plane)

The replay client answers one question: **I captured this request in evidence —
what does the server do when I re-send it, or a deliberate mutation of it?**

It is the only REA lane that dispatches traffic on the analyst's behalf. It is
therefore default-disabled, allowlisted by origin, one-shot, and value-free in
what it reports.

## Tools

| Tool                         | Purpose                                                                 |
| ---------------------------- | ----------------------------------------------------------------------- |
| `http_replay_session_start`  | Open a session over one HAR 1.2 entry or a caller-drafted request       |
| `http_replay_send`           | Dispatch that request once, optionally mutated, and report the exchange |
| `http_replay_session_status` | Read the session's selection, declared origins, and send counters       |
| `http_replay_session_close`  | Drain admitted sends, then remove the owner-only session record         |

`http_replay_session_start` accepts exactly one source: `capture_path` (plus an
optional `entry_ordinal`) or a drafted `request`. It always requires
`target_origins`, the exact origins the session may reach. Entries that cannot
be replayed verbatim are still listed, with the reason: a body that the capture
stored only as form parameters, a URL that is not `http`/`https`, or an entry
whose request facts are missing.

`http_replay_send` applies a structured mutation in a fixed order: replace
`method` and `url`, remove `remove_headers`, set `set_headers` (a set replaces
every earlier pair of that name), then replace `body`. `body` is `none`, UTF-8
`text`, or canonical `base64`. An empty mutation re-sends the selected request
verbatim.

## Enabling the plane

```sh
REA_REPLAY_ALLOWED_ORIGINS='["https://api.example.test","https://api.example.test:8443"]'
```

The value is a JSON array of **exact origins**: scheme, host, and optional port,
with no path, query, fragment, userinfo, or wildcard. An unset, empty,
malformed, or entirely invalid setting leaves the plane disabled. A session's
declared `target_origins` must all appear in that operator list; REA never adds
an origin from a request, a redirect, or a capture entry. Every refusal is a
typed `AnalysisCapabilityUnavailableError` whose remediation names the setting.

`inspect_analysis_settings` reports `REA_REPLAY_ALLOWED_ORIGINS` (operator
authority, unknown observation) and `replay.request_timeout` (fixed) so an agent
can see why a call was refused instead of retrying it.

## One-shot semantics — no retry, ever

REA dispatches **exactly one request per hop** and never retries, re-solves a
challenge, rotates headers, or re-sends after a failure. A `401`, `403`, `429`,
challenge page, reset, or timeout is a terminal observation of what that request
produced. This matches the workspace anti-bot discipline: one session, one try,
then back off.

Following a redirect is not a retry: each hop is a new request composed at the
send boundary, gated by the same origin allowlist, and reported as its own step
in `redirect_chain`. At most five hops are followed. A `Location` outside the
session's declared origins ends the chain with `outcome: "redirect_blocked"` and
no second dispatch. A followed redirect rewrites the method per Fetch
(`303` → `GET`, `301`/`302` on `POST` → `GET`), drops the body when the method
changes, and drops canonical credential headers when the next hop has a
different origin.

## Evidence is value-free

A send reports:

- the echoed request: method, URL, origin, header **names**, the canonical
  credential header names that travelled, and body size;
- the redirect chain shape: each hop's method, URL, origin, status, status
  class, and `Location` (with its approval decision);
- the final response: status, status class, content-type class, header-name
  inventory, size class, observed byte count, truncation, and an optional raw
  dump identity;
- `outcome` (`response`, `no_response`, `redirect_blocked`, `redirect_limit`),
  the transport failure kind when no response arrived, `retry: "none"`, and
  elapsed milliseconds.

Response bodies are **never** inline. Without `dump_path` REA reads at most 1
MiB to classify the size and then abandons the stream; with `dump_path` it
writes at most 64 MiB to that caller-selected file (owner-only `0600`, created
exclusively unless `overwrite: true`) and reports its digest, byte count, and
truncation. An occupied path is detected before the one dispatch is spent. A
dump that is cancelled or fails mid-write is removed, so a partial file never
looks like a complete capture — the same convention as `research/*/har/`.

Canonical credential headers (`Authorization`, `Proxy-Authorization`, `Cookie`,
`Set-Cookie`, the `WWW-Authenticate`/`Proxy-Authenticate` challenges, and a
declared set of token-bearing names such as `x-api-key`) are redacted from every
**echoed** form and never from the exact wire bytes: the server receives exactly
what the capture or caller supplied. The list is a declared closed vocabulary in
`src/domain/replay/replayRedaction.ts`, not a guess about a header's meaning.
URL userinfo is refused outright, and echoed locations strip it.

Status, header names, and redirect targets are target-authored text: REA reports
them because the target sent them and marks the result as untrusted content.

## Sessions and their records

A session lives for this REA server's lifetime and owns its record at
`$HOME/.rea/state/replay/<session_id>.json` (owner-only `0600` on POSIX; Windows
privacy is unverified, like other private runtime roots). A HAR session records
only the capture path, its digest, the declared origins, and the selection — the
credentials stay in the capture. A drafted session has no other home, so its
request (including credential header values) is stored in that record and
removed by `http_replay_session_close`.

Ownership is the record's creator, not its path. A record written by another REA
server is never adopted, rewritten, or deleted: `status`, `send`, and `close`
return a typed input error naming the file. Counters describe this server's own
dispatches, not the target's behavior.

`http_replay_session_close` is not idempotent: a second close of the same
session is a typed input error, not a no-op, so the tool advertises
`idempotentHint: false`. Retrying a close is only safe after a close that
reported an unremovable record.

## Composition contract for later lanes

`http_replay_send` is a thin projection over a reusable send core. Later batches
**must** compose this core rather than re-implementing it:

- `browser_fetch` (Batch 2.7, shipped in
  [driving and rewriting the page](browser-observation.md#driving-and-rewriting-the-page)) —
  the CDP counterpart sends from the page context through `CdpPageFetchTransport`
  and shares this core's one-shot policy, per-hop origin gate, body budget, and
  echoed-form redaction. Only the transport differs, and the differences stay at
  that seam: the browser composes `Host`, framing, `Cookie`, and `Sec-*`, the
  caller's origins are intersected with this plane's operator allowlist before
  the core sees them, and a redirected page fetch is opaque, so the core is
  never handed a hop it did not approve.
- `proxy_replay_send` (Batch 3.4) — re-sends a captured mitmproxy entry through
  the same boundary with the same dump convention.
- Arjun-style parameter probes (Batch 3.4) — many one-shot sends, each gated and
  each reported value-free.

The boundary is:

```
ReplayRequest                 src/domain/replay/replayRequest.ts   (compose + framing)
  → ReplaySendCore.send(...)  src/replay/ReplaySendCore.ts         (gate, dispatch, retain, redact)
    → ReplayExchange          src/replay/ReplaySendCore.ts         (project into Evidence)
```

`src/replay/ReplayTransport.ts` is the only dispatch seam; `ReplaySendCore` owns
the per-hop origin check, the no-retry policy, the body budget, and the echoed
form. A later lane supplies a `ReplayRequest`, a `ReplayTransport` (or the real
`NodeReplayTransport`), the approved origins, and an optional dump target; it
does not add its own redirect handling or credential redaction.

## Limits

| Limit                            | Value               | Override                   |
| -------------------------------- | ------------------- | -------------------------- |
| One send deadline (`timeout_ms`) | 1–60000 ms          | per send; default 10000 ms |
| Hops per send                    | 6 (1 + 5 redirects) | fixed                      |
| Composed headers                 | 128                 | fixed                      |
| One header name + value          | 8192 bytes          | fixed                      |
| Request body                     | 8 MiB               | fixed                      |
| HAR container inspected          | 32 MiB              | fixed                      |
| Response bytes counted inline    | 1 MiB               | fixed                      |
| Response bytes written to a dump | 64 MiB              | fixed                      |

`Content-Length` and `Transfer-Encoding` are composed by the boundary from the
selected body; a captured framing header describes the capture, not this send.
`Host` is sent as captured when the capture fixed one, and derived from the URL
otherwise. This release adds no default `User-Agent`.

## Transport and verification scope

REA has no declared `undici` dependency, and the built-in `fetch` (undici) folds
duplicate headers and refuses replay-fidelity request headers such as `Host` and
`Connection`. The adapter therefore uses `node:http`/`node:https` — the same
built-in client the CDP endpoint uses — for exact header lines, no automatic
redirect, no automatic decoding, and no retry. Every test runs offline against a
scripted transport; this lane has not been exercised against a real server in
this branch, so no claim is made about a specific server's behavior.
