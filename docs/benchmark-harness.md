# Benchmark harness

The benchmark harness runs caller-supplied containerized CTF tasks inside the
Lima lab VM and reports whether the task's declared success metric was met. It
is the regression lane for autonomy: the same task set, the same metric rule,
and the same budget every time, so a change in agent behavior shows up as a
changed flag or POV bit instead of a narrative.

REA ships no benchmark corpus. The NYU CTF Bench and Cybench task trees,
container images, and expected answers stay in the caller's corpus; this lane
boots the VM, runs one entrypoint, and reads the harness's own outcome file.

## One task, one call

MCP registers `run_bench_task`. One call:

1. Resolves the selected profile from `REA_BENCH_LIMA_PROFILE`.
2. Boots one lab VM from that profile with `workspace_path` mounted at
   `/workspace` (the lab-VM lane owns boot, `limactl`, and removal).
3. Runs `entrypoint` in the guest with `REA_BENCH_TASK_ID` and
   `REA_BENCH_OUTCOME_PATH=/workspace/.rea-bench/outcome.json` exported.
4. Reads the outcome file on the host, hashes any recovered flag, and drops the
   value.
5. Removes the VM and returns the metric bit as Evidence.

Only one lab VM is live per REA process. A run while another caller owns one
fails with the lab-VM lane's capacity error; the harness never queues behind it.

## Profiles

`REA_BENCH_LIMA_PROFILE` selects the only suite this process may run:

| Profile         | Suite         |
| --------------- | ------------- |
| `nyu-ctf-bench` | NYU CTF Bench |
| `cybench`       | Cybench       |

The setting is required. Unset or blank is a typed `not_configured` refusal with
remediation; an unrecognized value is an `unsupported_profile` refusal that
names the configured value and the supported set. A task whose `suite` does not
equal the selected profile is an input error, so a process cannot silently run
a suite it was not started for.

## Metric rule

The caller declares success before the task runs:

- `{"kind": "flag", "expected_flag_sha256": "<64 hex>"}` — satisfied only when
  the harness's recovered flag hashes to that digest.
- `{"kind": "pov", "expected_sanitizer": "address"}` — satisfied only when the
  harness recorded a proof-of-vulnerability bit, and named the declared
  sanitizer class when one is given.

The outcome file has this shape (`/workspace/.rea-bench/outcome.json`):

```json
{
  "status": "completed",
  "flag": "flag{...}",
  "pov": { "recorded": true, "sanitizer_class": "address" }
}
```

A task writes whichever field its metric needs. The flag value is used for one
SHA-256 and discarded; neither the expected nor the recovered value reaches
Evidence. The observation publishes the metric bit, the reason it is
unsatisfied, the recovered flag digest, and the sanitizer class.

`status` records whether the harness itself completed. A failed harness with a
matching flag still satisfies a flag metric; a failed harness with no POV is
`task_failed`.

## Unknown outcomes, deadlines, and cleanup

| Situation                                 | Result                                                   |
| ----------------------------------------- | -------------------------------------------------------- |
| Outcome file absent                       | `outcome_state: missing`, reason `outcome_missing`       |
| Outcome malformed or schema-invalid       | `outcome_state: unreadable`, reason `outcome_unreadable` |
| Outcome over 1048576 bytes                | `outcome_state: oversized`, reason `outcome_oversized`   |
| Guest command stopped at `budget_seconds` | `status: budget_exhausted`                               |
| Caller cancelled before boot              | typed cancellation                                       |
| VM removal failed                         | `vm.stopped: false` and a `stop_lab_vm` retry limitation |

An unknown outcome never means "not solved": the harness may have crashed
before writing anything. A deadline or cancellation outranks the metric even if
a stray outcome file is present, because a stopped run establishes nothing.

`budget_seconds` defaults to 900 and is capped at 7200. The value sets the
guest command deadline; the MCP client deadline is separate and must stay above
it.

## Evidence

Each run records one `benchmark-task` observation with the task identity,
suite, profile, entrypoint, budget, metric bit, guest call facts (exit type,
exit code, duration, timeout), produced workspace paths, and whether the VM was
released. Captured output bytes, flag values, and container logs never become
Evidence. The lane is marked `observed` / `controlled-replay`, and every
limitation that matters is stated: the metric is the harness's own bit, the
corpus is caller-supplied, and this release is exercised only with a scripted
`limactl` stand-in.

## Offline evaluation

`tests/evaluation/bench` is the in-repo eval suite. It never boots a VM or
launches an engine:

- **Loop A (fuzzing)** — a scripted `FuzzingCampaignPort` reports a POV count
  and the budget it enforced; the eval scores the POV bit and whether the run
  stayed inside its declared seconds.
- **Loop B (protocol learning)** — a scripted `ProtocolLearningPort` writes a
  synthetic model to a fixture store; the eval reads the file back, validates it
  against the learning lane's model schema, and scores the export.
- **Loop C (interception)** — a scripted `MitmInterceptionPort` reports the
  capture directory it owns; the eval hashes the fixture body there, scores the
  flag, and asserts the value never appears in Evidence.
- **Benchmark lane** — a scripted lab-VM port writes a fixture outcome, and the
  real adapter scores it, so the metric plumbing is exercised end to end.

These tests assert plumbing, not engine behavior: a real fuzz engine, a real
capture decoder, or a real mitmproxy is out of scope for the offline suite.
