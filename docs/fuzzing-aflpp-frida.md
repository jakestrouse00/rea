# AFL++ FRIDA adapter

`start_fuzzing_campaign` with `"engine": "aflpp_frida"` drives a
caller-supplied afl-fuzz binary in FRIDA mode (`-O`), which instruments a target
that was not compiled with AFL++'s compiler wrapper.

## Selection

| Setting                       | Value                                         |
| ----------------------------- | --------------------------------------------- |
| `REA_AFLFRIDA_FUZZER_COMMAND` | absolute path to a caller-supplied `afl-fuzz` |

`REA_AFLTMIN_COMMAND` names the `afl-tmin` binary used when
`minimize_crashes: true`.

Host execution is documented for macOS arm64. On any other host the selection
refuses with `unsupported_host` and points at the lab-VM route for a Linux
target. REA never installs or upgrades AFL++ tooling.

## Launch

```text
"$REA_AFLFRIDA_FUZZER_COMMAND" -O \
  -i <corpus-copy> \
  -o <campaign-root>/output \
  [-V <max_seconds>] \
  -- <registered-target> @@
```

- `-O` selects FRIDA mode.
- `-i` is the private corpus copy; `-o` is the campaign's output root.
- `-V` mirrors the seconds budget (already capped by
  `fuzzing.max_campaign_seconds`) where AFL++ supports it; REA stops the engine
  itself when any budget is reached, so a run budget is enforced even though
  afl-fuzz has no run-count flag.
- `@@` passes the mutated input path to the target.

## Crash artifacts and stats

- Crash inputs: `<campaign-root>/output/default/crashes/id:<seq>,sig:<n>,…`.
  The `README.txt` afl-fuzz writes beside them is not a candidate.
- Counters: `<campaign-root>/output/default/fuzzer_stats`, read on every
  observation tick. `execs_done` → `executions`, `execs_per_sec` →
  `executions_per_second`, `edges_found` → `edges`, `paths_total` →
  `corpus_entries`. `bitmap_cvg` is a percentage, so it is not reported as an
  edge count; a build that writes no `edges_found` line leaves `edges` null
  rather than guessing.

## Reproduction

AFL++ needs no fuzzer process to reproduce a crash: the registered target is run
directly with the artifact path.

```text
<registered-target> <artifact-path>
```

The target must accept the input path as its first argument, which is what `@@`
does during the campaign. A sanitizer-instrumented target produces the report
REA parses; a target without a sanitizer exits as a signal-only crash, which the
POV rule refuses unless `expected_sanitizer: "none"` is declared.

## Linux targets

For full AFL++ quality on a Linux target, start a lab VM over the directory that
holds the target and seeds, then pass `lab_vm_session_id` and
`lab_vm_workspace_path` with `"engine": "aflpp_frida"`. The guest command uses
the same argv; the `fuzzer_stats` and crash files are read back from the shared
workspace. See [lab VMs](lab-vms.md) and
[fuzzing campaigns](fuzzing-campaigns.md#routes).
