# Protocol learning

Answer "what state machine does this capture show?", "does a lab service still
answer the way the model expects?", and "can the observed structure seed a fuzz
campaign?" — through one lane that keeps payload values out of Evidence.

MCP registers three tools for this lane:

| Tool                     | Question it answers                                                                     |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `learn_protocol_model`   | Which message classes, states, and counted transitions does one saved capture show?      |
| `probe_learned_model`    | Does one allowlisted lab socket still answer what the model expects next, repeatedly?   |
| `export_protocol_grammar` | Which structure-aware seeds cover the model's transitions, for a later fuzz campaign?   |

## What the lane is, and is not

The loop is Pulsar/ProtocolState-Fuzzer-shaped: learn a finite-state machine
from observed messages, probe the live service against it, then hand the
structure to a fuzzer. This release implements the first two steps and the
handoff contract for the third. It does **not** reimplement a specific research
prototype, and no upstream source was vendored; the model, probe, and export
rules here are written for REA and documented below.

A learned model is a description of one capture, not a protocol specification:

- States are bounded suffixes of the observed message-class sequence. The
  machine is deterministic by construction, not inferred by a proof.
- A state the capture never showed is absent, not impossible.
- Message **order** is the only evidence used. Two services that exchange the
  same shapes in the same order learn the same model regardless of payload.
- Field-type sketches keep delimiter-separated type tokens and byte counts;
  they never keep a payload value, a header value, or a token's text.

## Evidence sources

### pcap and pcapng

`learn_protocol_model` reads a saved capture through the packet-capture lane:
the same caller-selected `tshark` and `capinfos` (`REA_TSHARK_COMMAND`,
`REA_CAPINFOS_COMMAND`), the same owned snapshot with its SHA-256 identity, the
same native memory bound, and the same command supervision. As with
`inspect_pcap_capture`, that native bound exists only on Linux (util-linux
`prlimit`) and Windows (owned Job Objects); on other hosts a pcap source is
refused with that reason, and the qlog source below still works.

The projection asks tshark for frame numbers, addresses, ports, stream ids, and
the payload field, groups frames into conversations by stream id (or by
endpoint pair when no stream id exists), and attributes direction from the
**first frame each conversation shows**. A server-speaks-first protocol is
therefore labelled from its greeting; that limitation is reported with the
model.

### qlog

An aioquic JSON qlog 0.3 capture is decoded by the **owned** qlog decoder that
`npm run verify:web:qlog` also exercises (`decodeQlogCapture`), so there is one
qlog parser in the repository. `learn_protocol_model` projects the decoder's
packet events onto messages: direction from the trace's vantage point, and one
class per `(packet type, frame types)` combination. No QUIC payload byte or
header value becomes Evidence, and a qlog-derived model has **no** exemplars —
qlog records lengths and frame types, not bytes — so it cannot feed
`export_protocol_grammar`.

## The model

```json
{
  "source": { "kind": "pcap", "path": "…", "sha256": "…", "format": "pcap", "packets": 41 },
  "sessions": { "total": 2, "retained": 2, "omitted": 0 },
  "messages": { "total": 8, "retained": 8, "omitted": 0, "request": 4, "response": 4, "unattributed": 0 },
  "alphabet": { "class_count": 2, "omitted": 0, "sketch_kinds": ["text"] },
  "classes": [
    {
      "class_id": "c0",
      "direction": "request",
      "sketch": { "kind": "text", "printable_ratio": "high", "line_terminated": true, "segments": 1, "segment_types": ["alpha"], "examined_bytes": 6 },
      "message_count": 2,
      "byte_length": { "min": 6, "max": 6, "total": 12 },
      "segment_count": { "min": 1, "max": 1 },
      "positions": [{ "position": 0, "types": ["alpha"], "observed": 2 }],
      "exemplar_sha256": "…",
      "template": { "file": "class-c0.bin", "bytes": 6, "sha256": "…" }
    }
  ],
  "states": [{ "state_id": "s0", "context": [], "message_count": 2, "session_ends": 0, "accepting": false }],
  "transitions": [{ "from": "s0", "to": "s1", "class_id": "c0", "count": 2, "sessions": 2 }],
  "merge": { "requested_suffix_length": 2, "retained_suffix_length": 2, "max_states": 24, "suffix_reduced": false },
  "coverage": "complete",
  "model_store": { "directory": "/evidence/protolearn/lab", "model_file": "model.json", "template_count": 2 },
  "limitations": ["…"]
}
```

A **state** is the last *k* message classes that led to it (`context`), so a
transition is "from this context, this class is next". `suffix_length` sets
*k*. When *k* would produce more states than `max_states`, REA shrinks *k* until
the model fits and reports `suffix_reduced` and `partial` coverage. At most
20 000 messages, 512 conversations, and 64 classes are retained; a conversation
is truncated at the first message whose class the alphabet cannot hold, and that
truncation also makes coverage partial.

### Exemplars

`exemplar_sha256` is the digest of the first payload observed for a class.
A qlog class reports `null` there and `template: null`, because qlog records
packet and frame facts rather than payload bytes: null means *unknown*, never an
empty message, so two null-exemplar classes make no claim that their payloads
match. A pcap class always has both.

### Model store

Pass `model_directory` to keep what the probe and export operations read back.
The directory receives `model.json` (the model above), one `class-<id>.bin`
exemplar per class that had payload bytes (none for a qlog model), and
`manifest.json` binding every written exemplar to its digest. Files are created `0600`. A later read of the store
verifies the manifest contract and every class digest before any probe or seed
is built.

## Probing a lab service

`probe_learned_model` sends caller-authored steps to **one** allowlisted lab
socket and compares each reply with what the model expects next.

Two closures gate the network side effect, and both must pass:

1. **Operator allowlist.** `REA_PROTOLEARN_LAB_ENDPOINTS` is a JSON array of
   exact `host:port` literals in the REA launch environment. Unset, empty, or
   malformed means the lane is disabled; a request naming an endpoint outside
   the list is refused with the operator remediation.
2. **Deny-default sandbox.** Each connection is its own child process
   (`REA_PROTOLEARN_PYTHON` interpreter, `REA_PROTOLEARN_BRIDGE_DIR` runner
   script) wrapped in the Task 4 seatbelt profile. The profile admits exactly
   one outbound destination, the interpreter as an executable, the runner's
   directory as readable, and the job's own workspace as writable.

`sandbox-exec` names only `*` or `localhost` in a network address and refuses a
numeric literal, so the profile writes `localhost:<port>` and this lane admits
**loopback endpoints only**. A probe to another address is refused rather than
run unconfined; forward the lab service to a loopback port from a host you
control. If `REA_DISABLE_SANDBOX` is set, the launch still happens but the
result reports `confinement: "disabled"` with the exact limitation — an
unconfined probe is never presented as confined.

Verdicts per step:

| Verdict      | Meaning                                                                     |
| ------------ | --------------------------------------------------------------------------- |
| `consistent` | Every repeat answered a response class the model expects after this message |
| `divergent`  | The replies were stable but landed outside the model's expected classes      |
| `unmodeled`  | The sent class is not in the model, or the model predicts nothing afterwards |
| `unstable`   | The repeats disagreed on exact reply bytes, so no differential verdict holds |

Replies are reported as **lengths, SHA-256 digests, and type sketches only**.
The runner returns reply bytes to REA over its own pipe; REA digests and
sketches them and drops them, so no response payload is echoed back.

`protolearn.probe_timeout_ms` (or `REA_PROTOLEARN_PROBE_TIMEOUT_MS`) sets the
deadline of one connection, default 10 000 ms, at most 120 000 ms, then 2 000 ms
of stop grace before REA stops the owned child.

## Exporting a grammar for a fuzz campaign

`export_protocol_grammar` turns one model into structure-aware seeds: for every
transition, the seed is the shortest observed class path from the initial state
that reaches it, materialized from the class exemplars. Seeds are written
`0600` into the caller's `output_directory`, and the result names the handoff
contract `rea.fuzzing.campaign-seeds/v1`:

```json
{
  "contract": "rea.fuzzing.campaign-seeds/v1",
  "seed_directory": "/evidence/protolearn/seeds",
  "seeds": [{ "seed_id": "seed-0", "file": "seed-0.bin", "bytes": 6, "sha256": "…", "message_count": 1, "covers_transitions": [{ "from": "s0", "to": "s1", "class_id": "c0" }] }],
  "seed_count": 4,
  "skipped_count": 0,
  "covered_transitions": 4,
  "transition_count": 4,
  "campaign_handoff": { "tool": "start_fuzzing_campaign", "seed_paths": ["…"], "note": "…" }
}
```

A model with no exemplars — every qlog-derived model — writes no seeds and
reports each planned seed in `skipped_count`, because a seed must carry bytes.

The fuzz loop (Batch 3.3) is a separate lane. This release publishes the
contract and the exact seed paths so that lane can pass them unchanged as its
starting corpus; it does not start a campaign, and it does not invent a second
campaign adapter. A class without an exemplar, or a seed above 65 536 bytes, is
counted in `skipped_count` instead of being silently shortened.

## Setup and limits

| Control                          | Effect                                                                              |
| -------------------------------- | ----------------------------------------------------------------------------------- |
| `REA_TSHARK_COMMAND`             | Caller-supplied tshark for a pcap source (absolute). REA never installs Wireshark.   |
| `REA_CAPINFOS_COMMAND`           | Caller-supplied capinfos for a pcap source (absolute).                               |
| `REA_PROTOLEARN_PYTHON`          | Absolute interpreter for the probe runner (standard library only).                   |
| `REA_PROTOLEARN_BRIDGE_DIR`      | Absolute directory holding `probe_runner.py`.                                        |
| `REA_PROTOLEARN_LAB_ENDPOINTS`   | Operator allowlist of lab socket literals; unset disables probing.                   |
| `protolearn.probe_timeout_ms`    | Deadline of one probe connection (default 10 000 ms, at most 120 000 ms).            |
| `REA_DISABLE_SANDBOX`            | Emergency exit; reported as `confinement: "disabled"` with its limitation.           |

Fixed allowances in this release: 20 000 messages, 96 states, 64 classes,
16 384 response bytes per probe step, 262 144 response bytes per connection, and
a 4 MiB model file. `inspect_analysis_settings` lists each one with its
recovery text.

## Verification scope

Offline tests cover the model learner, the tshark message projection, the qlog
projection through the owned decoder, the store round trip and tamper refusal,
the seed planner and its coverage counts, the probe verdicts, the operator and
sandbox guards, the sandbox profile source, malformed frames, oversized frames,
runner refusals, deadlines, and cancellation. The probe tests drive a scripted
stdio runner against scripted replies; `bridge/protolearn/test_bridge.py` drives
the real runner against loopback socket fakes. **No real lab service, real
`tshark`, or real sandboxed Python launch was exercised here**, so a passing run
does not establish real-service behaviour.

## Evidence discipline

- The model carries state ids, class ids, type tokens, counts, byte lengths, and
  digests. It never carries a payload value.
- Probe steps report the caller's own templates by digest and length; replies by
  digest, length, and sketch.
- Seed files hold observed exemplars on disk under `0600`; Evidence holds their
  paths, digests, and coverage, so the bytes stay where the caller put them.
