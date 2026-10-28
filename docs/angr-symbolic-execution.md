# Symbolic execution with angr

Answer "can these bytes reach that address under these assumptions?", "what
does one bounded exploration keep alive?", and "what control-flow graph does a
second engine derive for this artifact?" — through REA's own angr sidecar.

MCP registers three tools for this lane:

| Tool                                | Question it answers                                                                                           |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `find_paths_to_target`              | Does one of these addresses become reachable, given constraints on symbolic inputs, and under what condition? |
| `run_symbolic_function_exploration` | What does one bounded exploration of this function keep alive, and how many states ended where?               |
| `recover_control_flow_angr`         | What functions, blocks, and edges does angr derive for this artifact, to cross-check rizin or Ghidra?         |

## What the lane is, and is not

Each request runs **one** job: a queue slot is taken, a fresh sidecar process is
spawned, the job is answered, and the process is stopped. Nothing executes on or
is written to the target, and no live process is inspected or driven.

The answers are angr's model of the artifact, not observations of a running
program:

- Constraints and paths describe what angr's loader and stub environment permit.
  A found path is a modelled path, not a verified real-world input.
- "No path found" is a bounded negative. It never establishes that the address is
  unreachable; it says this exploration, with these bounds and this angr release,
  did not reach it.
- No operating-system behaviour is modelled beyond the substitutions angr makes,
  so a function that depends on files, sockets, or a real allocator is only as
  faithful as those substitutions.
- Symbolic solutions are **never** returned. See
  [Evidence discipline](#evidence-discipline).

## Setup

The sidecar is REA-owned source; angr is bring-your-own. REA never creates the
Python environment, never installs a wheel, and never upgrades it.

1. Create an environment with the pinned engine release:

   ```sh
   python3 -m venv ~/.local/share/rea-angr
   ~/.local/share/rea-angr/bin/pip install 'angr>=9.2,<9.3'
   ```

2. Point REA at that interpreter and at this repository's bridge directory, then
   restart REA:

   ```sh
   export REA_ANGR_PYTHON="$HOME/.local/share/rea-angr/bin/python"
   export REA_ANGR_BRIDGE_DIR="$PWD/bridge/angr"
   ```

Both settings are fail-closed. If either is unset, relative, missing, or not
executable, the tools refuse with a `capability_unavailable` result that names
the setting and its remediation; nothing is spawned and no partial result is
reported. `binary_session` reports the same selection through
`angrSymbolicEnabled`, so a misconfigured host is visible before the first call.

### Concurrency

`REA_ANGR_JOBS` caps how many jobs the lane admits at once, from 1 (the default)
to 8. Every admitted job owns one angr process, and angr trades memory for
exploration width, so the queue is deliberately small. Callers beyond the cap
wait in arrival order; a caller that cancels while queued leaves the queue
without ever starting a process. REA reads this setting when it starts.

### Deadline

`REA_ANGR_OPERATION_TIMEOUT_MS` is the wall-clock deadline of one job when the
request names no `timeout_ms`, from 1 to 2 147 483 647 ms; the published default
is 120 000 ms. The runtime setting `angr.operation_timeout_ms` overrides the
launch environment for the next operation without a restart, and an explicit
request `timeout_ms` takes precedence over both. The deadline is enforced by
stopping the owned sidecar process; it is not a cooperative hint.

### Version pinning

The bridge is written against **angr 9.2.x** and refuses any other minor release
(`version_unsupported`). It reports the exact `angr` version it loaded in every
result, so a recorded observation always names the engine that produced it. A
missing `angr` or `claripy` import is `missing_dependency`, with installation
guidance rather than a stack trace.

### Wire protocol

One JSON request line on stdin, one JSON answer line on stdout, diagnostics on
stderr, protocol `1`:

```json
{"protocol":1,"job_id":"<uuid>","kind":"find_paths","path":"/artifacts/firmware.bin","binary_sha256":"<hex>","entry":"0x401000","stdin_bytes":16,"symbolic_registers":[],"assertions":[],"find_addresses":["0x4010a0"],"avoid_addresses":[],"max_paths":1,"max_states":64,"max_steps":200000,"timeout_ms":120000,"limits":{"max_conditions":64,"max_condition_nodes":512,"max_model_values":32,"max_visited_blocks":2048,"max_paths":8,"max_successors":16}}
{"protocol":1,"job_id":"<uuid>","kind":"find_paths","ok":true,"result":{...}}
```

A frame that is not one JSON line, exceeds the 1 MiB frame budget, or does not
match the declared contract is a typed protocol refusal; it is never partially
accepted. An answer above the budget is replaced by a bounded `job_failed`
refusal rather than truncated.

## Evidence discipline

The caller names an absolute artifact path. REA digests the whole file it read
and the bridge digests the file it loaded; if the two disagree the job is a
protocol refusal, so a result always names the bytes that were analysed.

`find_paths_to_target` and `run_symbolic_function_exploration` return:

- `target`: the path, entry address, and SHA-256 of exactly the artifact REA
  selected.
- `termination`: which bound or stash move ended the job (`find_hit`,
  `avoid_hit`, `deadended`, `state_bound`, `step_bound`, `deadline`,
  `no_viable_state`, `unsupported`).
- `paths[].conditions`: an operator tree of nodes — `op`, `bits`,
  `kind` (`operation`, `symbol`, `constant`, `unknown`), and for a symbol the
  REA-owned operand name. A constant carries `constant_sha256`, the SHA-256 of
  its fixed-width value, **never the value**.
- `paths[].model`: for each symbolic input, its name, bit width, and
  `value_sha256` — the digest of the solution, never the solution.
- Counts, visited addresses, and truncation flags for the exploration.

`recover_control_flow_angr` returns functions and blocks as addresses only,
their sizes, successors, and an edge count. No function, block, or symbol
**name** is returned: a name can carry text read from the target, and an
address is enough to line the result up with rizin or Ghidra.

Why values are digests rather than values: a symbolic solution is a concrete
input that satisfies constraints on bytes read from the target, which is exactly
the shape of a recovered secret. Reporting the digest preserves the only thing
Evidence needs — "these two paths solved the same value", "this condition pinned
one byte" — while keeping the solution out of the transcript. `values_redacted`
is always `true` in these results, and it is part of the contract, not a note.

Every result is target-derived and is marked as untrusted content when MCP
delivers it.

## Bounds

| Bound                     | Value                                                | Control               |
| ------------------------- | ---------------------------------------------------- | --------------------- |
| Job wall time             | `timeout_ms`, default 120 000 ms, at most 600 000 ms | `angr.timeout`        |
| Concurrent jobs           | 1 by default, at most 8                              | `angr.jobs`           |
| Exploration steps         | `max_steps`, default 200 000, at most 2 000 000      | `angr.max_steps`      |
| Live states               | `max_states`, default 64, at most 256                | `angr.max_states`     |
| Satisfying paths retained | `max_paths`, default 1, at most 8                    | `angr.max_paths`      |
| Caller assertions         | 16 per request                                       | `angr.assertions`     |
| Symbolic stdin window     | 4 096 bytes                                          | `angr.stdin_bytes`    |
| Condition nodes retained  | 64 conditions of 512 nodes per path                  | `angr.conditions`     |
| Model values retained     | 32 per path                                          | `angr.model_values`   |
| Visited blocks retained   | 2 048 addresses                                      | `angr.visited_blocks` |
| CFG functions retained    | 4 096                                                | `angr.functions`      |
| CFG blocks retained       | 16 384                                               | `angr.blocks`         |
| CFG successors per block  | 16                                                   | `angr.successors`     |
| Bridge frame              | 1 MiB per line                                       | `angr.frame_bytes`    |

Exceeding a step, state, or time bound is a completed job whose `coverage` is
`partial` and whose `termination` names the bound. Exceeding a storage bound
keeps the job and sets the matching `*_truncated` flag, so an omitted path,
condition, or edge is never reported as absence. The job deadline is the only
one of these controls with a runtime override: `inspect_analysis_settings`
reports `angr.operation_timeout_ms`. The rest are fixed published limits, and
`REA_ANGR_JOBS` is read from the launch environment.

## Symbols and assertions

Caller-supplied assumptions enter the job in two ways:

- `symbolic_registers`: entry registers whose value is a fresh symbolic bit
  vector of the artifact's word width.
- `stdin_bytes`: a symbolic standard-input window of that many bytes.

`assertions` then constrain those inputs before exploration. An assertion names
a register or a byte range of the stdin window, a relation (`eq`, `ne`, `lt`,
`le`, `gt`, `ge`, compared unsigned), and a hexadecimal value. An assertion that
names a register the request did not make symbolic, or a stdin range past the
window, is a typed input refusal rather than a silently concrete constraint.

## Cross-checking a control-flow graph

`recover_control_flow_angr` exists to disagree usefully with another engine.

- An edge rizin or Ghidra recovered and angr did not — or the reverse — is a
  question about the artifact, not a verdict from either side.
- A block angr reaches through an indirect branch it could not resolve has no
  successor recorded, so a missing edge is not evidence that no edge exists.
- Block sizes come from angr's recovery, so cross-engine size disagreement
  belongs in the report rather than being reconciled silently.

## Job queue and shutdown

The lane owns one bounded queue for its lifetime. Admission is in arrival order,
a cancelled waiter leaves without a slot, and a session close cancels every
waiter and resolves once the admitted jobs have settled. Each job owns its
sidecar process through REA's process supervision, so a cancelled or timed-out
job takes its process with it; a stop that cannot be proven leaves the job as a
cleanup failure rather than reporting success.

## Limitations

- One exploration per call. Alternate branches need another call with different
  assertions or bounds.
- angr's loader decides what is mapped. An entry outside the loader's main
  object is refused before exploration.
- Shared libraries are not loaded (`auto_load_libs=False`), so a call into an
  unmodelled library is a stub or an error, not the library's behaviour.
- Path-condition operators come from angr's constraint representation; an
  operator this bridge does not name is reported as `unknown` rather than
  guessed.
- CFG recovery has no internal deadline knob: it is bounded by the job deadline,
  which stops the process.
- `inspectAvailability` reports the configured selection; it does not import
  angr. A missing or mismatched engine surfaces on the first job as
  `capability_unavailable` with a bounded stderr excerpt.

## Offline verification

The lane's boundary tests run against a scripted fake sidecar: a fixture process
that reads one request line and writes one answer line. They cover path
structure, digest-only values, target-identity mismatch, frame and JSON refusal,
the deadline, cooperative cancellation, a pre-cancelled caller, queued
cancellation, close during a job, bridge refusals, and every configuration
refusal. The Python bridge tests install a stand-in `angr`/`claripy` that models
only the API surface the bridge calls. No real angr, native target, or host
execution is exercised by those tests, so they establish REA's own framing,
bounds, and redaction, not engine behaviour.
