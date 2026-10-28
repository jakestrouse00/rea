# Autonomy walkthrough: one lab-owned target, end to end

This page is the manual smoke walkthrough for the autonomy loop:

```text
open_binary → capa + YARA → start_fuzzing_campaign (deny-default sandbox, lab VM)
            → crash dedup and triage → Evidence bundle export
```

It has two halves. The **offline path** runs the same steps against scripted
producer binaries and needs no engine, VM, network, or provider; it is what the
test suite exercises. The **real-host path** performs each step against your own
engines. Every real-host step is marked, so nothing here claims that a scripted
fixture proves a real engine's behavior.

Neither path authorizes a target. Before starting, read the
[autonomous execution policy](./autonomous-execution.md): the target, seeds,
network destinations, writable directories, and budgets must be lab-owned and
written down, and a scope that grows during the run is a finding to report.

## What each step is allowed to do

| Step               | Tool                          | Executes                   | Needs a real host            |
| ------------------ | ----------------------------- | -------------------------- | ---------------------------- |
| Open the target    | `open_binary`                 | no (reads the artifact)    | provider/engine on `PATH`    |
| Match capabilities | `analyze_binary_capabilities` | no (capa reads the file)   | `REA_CAPA_COMMAND`           |
| Match rules        | `scan_artifact_with_rules`    | no (YARA-X reads the file) | `REA_YARAX_COMMAND`          |
| Start a lab VM     | `start_lab_vm`                | guest commands only        | `REA_LIMACTL_COMMAND` + Lima |
| Fuzz               | `start_fuzzing_campaign`      | **yes**, the fuzz target   | a fuzz engine                |
| Deduplicate        | `list_crash_dedups`           | no                         | —                            |
| Describe a crash   | `fetch_crash_evidence`        | no                         | —                            |
| Export the bundle  | `export_evidence_bundle`      | no                         | —                            |

`open_binary`, capa, and YARA each read the artifact by path. The session
binding proves which bytes the native provider analyzed; the other two lanes
report their own SHA-256, so compare digests rather than assuming one lane's
read applies to another.

## Offline path: the scripted walkthrough

Run each covering test from the repository root. They use fake producer
executables (`tests/fixtures/`), in-memory MCP transports, and temporary
directories; no engine starts, no VM boots, and nothing reaches the network.

| Step                         | Command                                                                    | What it establishes                                                              |
| ---------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Session and evidence binding | `npm run test:focused -- tests/boundary/mcp/sessionMcp.test.ts`            | `open_binary` binds a target, `export_evidence_bundle` writes a canonical bundle |
| Fuzz → dedup → crash facts   | `npm run test:focused -- tests/boundary/mcp/fuzzingMcp.test.ts`            | register, launch under a scripted engine, validate POVs, list dedups             |
| Recorded crash triage        | `npm run test:focused -- tests/boundary/mcp/recordedCrashMcp.test.ts`      | a recorded sanitizer report parses into structural Evidence                      |
| Bundled evidence export      | `npm run test:focused -- tests/boundary/mcp/evidenceBundleInline.test.ts`  | a bundle round-trips without losing record identity                              |
| Fuzzing loop metrics         | `npm run test:local -- tests/evaluation/bench/benchLoopEvaluation.test.ts` | the Loop A fuzzing score, the declared budget, and the scripted lab-VM lane      |

The fuzzing test sets `REA_FAKE_ENGINE_SCENARIO` and `REA_DISABLE_SANDBOX=1`
because the fake engine is a Node script, not a libFuzzer build. That is the
documented emergency exit: it records an unconfined launch instead of claiming
confinement. A real campaign should not need it.

## Real-host path: the manual smoke

Set the selections in the server's environment before it starts. A missing,
relative, or non-executable selection is a typed `capability_unavailable`
refusal that names the setting; REA never installs or downloads an engine.

```bash
export REA_CAPA_COMMAND=/opt/homebrew/bin/capa          # capa
export REA_YARAX_COMMAND=/opt/homebrew/bin/yr            # YARA-X
export REA_LFZ_FUZZER_COMMAND=/lab/target/fuzz_target    # libFuzzer build
export REA_LIMACTL_COMMAND=/opt/homebrew/bin/limactl     # lab VM lane
```

### 1. Record the scope

Write the target's absolute path, its SHA-256, the seeds, the guest or host
directories the run may write, the time and command budgets, and who owns the
result. Keep that note beside the bundle you export at the end.

### 2. Open the target — real host

```text
open_binary {"path": "/lab/target/fuzz_target"}
```

The result names the bound format, provider, and artifact SHA-256. A provider
that cannot analyze the format refuses; there is no silent fallback to a
different engine.

### 3. Match capabilities and rules — real host

```text
analyze_binary_capabilities {"path": "/lab/target/fuzz_target", "backend": "default"}
scan_for_crypto_constants {"path": "/lab/target/fuzz_target"}
scan_artifact_with_rules {"path": "/lab/target/fuzz_target", "rules_path": "/lab/rules"}
```

Both results are indicators, not proof: capa rules and shared constant tables
can match benign builds. Compare each result's SHA-256 with the digest
`open_binary` reported.

### 4. Start the lab VM — real host

```text
start_lab_vm {"workspace_path": "/lab/target"}
run_lab_vm_command {"session_id": "<vm-session>", "command": "cmake --build build", "command_timeout_ms": 600000}
```

The guest mounts the workspace at `/workspace`. The build runs in the guest;
the host only passes the command line through the guest shell. Keep the VM
session id: the campaign needs it next.

### 5. Fuzz inside the VM — real host

```text
register_fuzzing_campaign {
  "target_path": "/workspace/build/fuzz_target",
  "seed_paths": ["/workspace/seeds/empty"],
  "budget": {"max_seconds": 600},
  "dedup_frames": 3
}
start_fuzzing_campaign {
  "campaign_id": "<campaign-id>",
  "engine": "libfuzzer",
  "pov_repeats": 2,
  "expected_sanitizer": "address",
  "lab_vm_session_id": "<vm-session>",
  "lab_vm_workspace_path": "/lab/target"
}
```

Two routes exist. Omit `lab_vm_session_id` and the engine runs on this host,
wrapped by the deny-default seatbelt profile on macOS (on other platforms the
observation says no kernel confinement applies). Pass it and the engine runs
inside the lab VM, where the VM boundary is the isolation; the host-side
`limactl` calls still carry their own profile. In both routes the engine writes
only inside the campaign root, and no outbound network is permitted.

The campaign stops at the declared budget or the `fuzzing.max_campaign_seconds`
cap. The observation reports `sandbox.confined`, the declared and effective
budgets, the stop reason, the engine's own counters, and the crash candidates
that survived reproduction (`pov_repeats`), sanitizer, frame, and crash-state
agreement. A rejected candidate is reported with one reason and never stored.

### 6. Deduplicate and describe — offline

```text
list_crash_dedups {"campaign_id": "<campaign-id>", "limit": 20}
fetch_crash_evidence {"campaign_id": "<campaign-id>", "crash_id": "<crash-id>"}
```

Each dedup group is one crash-state hash with the crash ids that share it. The
hash is a stable signature over normalized frames; it is not proof that a
defect is exploitable. Fetch one crash to read its frames, sanitizer class, and
the reproducer and report paths the campaign root still holds.

### 7. Export the bundle — offline

```text
export_evidence_bundle {"path": "/lab/results/autonomy-smoke.json"}
close_binary {}
stop_lab_vm {"session_id": "<vm-session>"}
```

The bundle is canonical and byte-stable, and carries the session's records with
their subject digests, isolation, locations, and limitations. Export before
`close_binary` if anything in the session is mutable; the campaign root and
crash report store stay until the server closes, so copy anything you need to
keep.

## What this smoke does not prove

- Scripted fixtures establish lane wiring, bounds, and refusal shapes; they do
  not establish how a real capa, YARA-X, or fuzz engine behaves on your target.
- `sandbox.confined: true` means REA launched the process under a profile it
  rendered. It does not claim the guest kernel confined anything, and a
  `REA_DISABLE_SANDBOX=1` launch reports itself as unconfined.
- A crash-state hash groups reproductions; it is not a severity, exploitability,
  or uniqueness claim across targets.
- Evidence is the record, not the verdict: compare subject digests, read the
  limitations, and keep the scope note you wrote in step 1 beside the bundle.
