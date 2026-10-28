# Fuzzing campaigns

`start_fuzzing_campaign` runs one registered crash-triage campaign through one
caller-selected engine, reports the counters it observed, and hands only
validated crashes back to crash triage.

The lane starts no engine until `register_fuzzing_campaign` has booked the
target, seeds, declared stop condition, and crash-state window. REA never
builds, downloads, installs, or upgrades an engine or a fuzz target; every
engine is a caller-selected executable recorded in the launch environment.

| Step | Tool | Question it answers |
| --- | --- | --- |
| 1 | `register_fuzzing_campaign` | Which target, seeds, budget, and dedup window should be booked? |
| 2 | `start_fuzzing_campaign` | Which engine ran, how far did it get, and which crashes survived POV validation? |
| 3 | `list_crash_dedups` | Which distinct crash states did it record, and how often? |
| 4 | `fetch_crash_evidence` | What are the structural facts of one accepted crash? |

## Engines

Each engine is an adapter behind one contract: it declares the argv that starts
a campaign, the argv that reproduces one input, which artifact names are crash
candidates, where its progress counters live, and which crash-triage minimizer
can shrink an accepted crash.

| Engine | Selection | Host | Guide |
| --- | --- | --- | --- |
| `libfuzzer` | `REA_LFZ_FUZZER_COMMAND` | any host that runs the caller's target | [libFuzzer](fuzzing-libfuzzer.md) |
| `aflpp_frida` | `REA_AFLFRIDA_FUZZER_COMMAND` | macOS arm64 (FRIDA mode) | [AFL++ FRIDA](fuzzing-aflpp-frida.md) |
| `jackalope` | `REA_JACKALOPE_DIR` | the platform the build targets | [Jackalope/TinyInst](fuzzing-jackalope.md) |

The campaign lane appears in `session_status` availability only when at least
one engine resolves. Selecting an engine that is not configured is a typed
capability refusal that names the setting and the remediation; the registration
reads and every other engine stay usable.

## One launch

```text
start_fuzzing_campaign {
  "campaign_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "engine": "libfuzzer",
  "pov_repeats": 2,
  "expected_sanitizer": "address"
}
```

A launch:

- copies the campaign's registered seeds into a private corpus (owner-only
  `0700` root, `0600` seed copies) so the engine never mutates a caller file;
- starts the engine under a deny-default seatbelt profile on macOS, with only
  the campaign root writable, the target and engine directories readable, and
  no outbound network or Mach lookups (`REA_DISABLE_SANDBOX=1` records an
  unconfined launch instead of hiding it; an unrecognized value refuses the
  launch);
- reads the engine's own progress counters every 500 ms;
- stops the engine with `SIGTERM` (then `SIGKILL` after five seconds) when a
  budget is reached, the caller cancels, or the retained output budget is
  exceeded;
- reproduces every crash artifact, accepts only validated POVs, and records
  them into the campaign;
- returns one Evidence observation and keeps the campaign root until the server
  closes, so the reproducer paths a crash record names still exist.

One campaign runs at a time. A second launch is a resource refusal rather than a
queued run, because each engine owns the host's cores.

## Budgets

The declared budget comes from `register_fuzzing_campaign`; the enforced budget
is the declared value capped by the agent-editable `fuzzing.max_campaign_seconds`
setting.

| Bound | Declared in | Enforced by | Stop reason |
| --- | --- | --- | --- |
| Runs | `budget.max_runs` | REA stops the engine at the observed execution count | `budget_runs` |
| Wall clock | `budget.max_seconds`, capped by `fuzzing.max_campaign_seconds` | engine flag where it exists, plus REA's own deadline | `budget_seconds` or `runtime_cap_seconds` |
| Crashes | `budget.max_crashes` | REA stops the engine at the observed crash-artifact count | `budget_crashes` |

The observation reports both `budget.declared` and `budget.effective` plus
`seconds_bound`, so a campaign stopped by the runtime cap is never reported as
the caller's own bound. `fuzzing.max_campaign_seconds` defaults to 900 and
accepts 1 to 2419200 through `update_analysis_settings`.

The crash budget counts observed artifacts, not accepted POVs: acceptance is
decided after the run, and the reported `crashes.accepted` can be lower than the
observed count.

## POV validation

A crash artifact is only a candidate. It becomes an accepted crash when every
requested reproduction (`pov_repeats`, 1–3, default 2):

- ran the target under the same deny-default profile as the engine launch, with
  the campaign root writable, the adapter's declared paths readable, and no
  outbound network, and exited as a crash;
- parsed as a crash report through the crash-triage parser;
- named an accepted sanitizer class — the caller's `expected_sanitizer` when
  given, otherwise any sanitizer-identified class, which refuses signal-only OS
  reports unless `expected_sanitizer: "none"` says otherwise;
- carried at least one frame;
- agreed with every other reproduction on the crash-state hash.

A candidate that fails is reported with one reason: `missing_input`,
`not_reproduced` (a requested reproduction exited without crashing, or the
repetitions stopped early), `report_unreadable`, `report_too_large`,
`unsupported_sanitizer`, `no_frames`, or `unstable_state`. Rejected candidates
never reach the store, so `crash_count` and `list_crash_dedups` only describe
validated crashes. A stable crash-state hash is a reproducible signature over
normalized frames; it is not proof that a defect is exploitable.

Minimization is opt-in (`minimize_crashes: true`) and goes through the existing
crash-triage minimizer seam: `REA_LFZ_MINIMIZE_COMMAND` for the libFuzzer
adapter, `REA_AFLTMIN_COMMAND` for AFL++. Jackalope has no documented minimizer
adapter, so accepted crashes stay unminimized and the observation says so.

## Stats stream

The observation carries a bounded series of samples (`at_ms`, `executions`,
`executions_per_second`, `edges`, `corpus_entries`, `observed_crashes`), plus
`first`, `last`, `peak_executions_per_second`, `edges`, and `corpus_entries`.
At most 240 samples are retained; when the series is full every second retained
sample survives and `sample_stride_ms` doubles, so a long campaign widens the
reported interval instead of growing the result.

Counters are the engine's own instrumentation (`cov`/`ft` for libFuzzer and
Jackalope, `execs_done`/`edges_found`/`paths_total` from AFL++'s
`fuzzer_stats`). They describe this run, not the target's complete behavior.

## Routes

`lab_vm_session_id` plus `lab_vm_workspace_path` runs the same adapter inside an
already-started lab VM through the existing Lima lane: the guest command writes
`engine.log`, artifacts, and per-candidate `report.log` files into
`rea-fuzzing/<campaign_id>/` inside the mounted workspace, and REA reads them on
the host. The campaign target and seeds must live inside the mounted workspace.
The guest is the isolation boundary, so the host seatbelt profile does not
apply, and only the time budget stops the guest command while it runs; run and
crash budgets are checked after it returns. See [lab VMs](lab-vms.md).

## Bounds

| Bound | Value | Override |
| --- | --- | --- |
| Campaigns running at once | 1 | None in this release |
| Retained campaign roots per server | 8 | Restart the server |
| Crash artifacts inspected per campaign | 64 | None in this release |
| Retained stats samples | 240 | None in this release |
| Engine output retained per stream | 4194304 bytes | None in this release |
| Reproductions per candidate | 1–3 (default 2) | `pov_repeats` |
| POV reproduction deadline | 60000 ms | None in this release |
| Campaign wall clock | 900 s default | `fuzzing.max_campaign_seconds` |

## Verification limits

This lane is exercised offline with scripted stand-in engines that print the
documented stat shapes and write the documented artifact names. The offline
suite does not run libFuzzer, afl-fuzz, Jackalope, or a real sanitizer-instrumented
target, so no claim is made here about a specific engine version's output beyond
the parsed shapes recorded in the adapter guides.
