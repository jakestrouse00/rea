# libFuzzer adapter

`start_fuzzing_campaign` with `"engine": "libfuzzer"` drives a
caller-supplied, libFuzzer-instrumented fuzz target.

## Selection

| Setting                  | Value                                              |
| ------------------------ | -------------------------------------------------- |
| `REA_LFZ_FUZZER_COMMAND` | absolute path to the libFuzzer-instrumented target |

The path must be an absolute, executable regular file. REA never builds,
downloads, or installs a fuzz target, and the campaign target registered with
`register_fuzzing_campaign` is digested separately, so a wrapper around the
instrumented binary is allowed as long as the engine argv below is meaningful
for it.

`REA_LFZ_MINIMIZE_COMMAND` is a separate selection: it names the binary used
for `-minimize_crash=1` when `minimize_crashes: true`.

## Launch

```text
"$REA_LFZ_FUZZER_COMMAND" <corpus-copy> \
  -artifact_prefix=<campaign-root>/artifacts/ \
  -print_final_stats=1 \
  [-runs=<max_runs>] [-max_total_time=<max_seconds>]
```

- `<corpus-copy>` is a private copy of the registered seeds; libFuzzer mutates
  it in place, so the caller's seeds are never touched.
- `-artifact_prefix` keeps every crashing input inside the campaign root.
- `-runs` and `-max_total_time` mirror the declared run and seconds budgets; the
  seconds value is already capped by `fuzzing.max_campaign_seconds`.
- REA still watches the counters and stops the engine itself, so a budget is
  enforced even when the engine ignores the flag.

## Crash artifacts

The adapter treats these names in `<campaign-root>/artifacts/` as candidates:

```text
crash-*  leak-*  oom-*  timeout-*  slow-unit-*
```

## Statistics

libFuzzer's console counter lines are parsed directly:

```text
#1234	pulse  cov: 45 ft: 12 corp: 30/300b lim: 4096 exec/s: 1000 rss: 20Mb
#7	NEW    cov: 9 ft: 9 corp: 2/20b exec/s: 7 rss: 12Mb
```

Read from each line: `executions` (`#N`), `cov` → `edges`, `exec/s` →
`executions_per_second`, `corp` → `corpus_entries`. Seed-corpus notices,
`INFO:` lines, and any line without a recognized counter are ignored rather
than reported as progress.

## Reproduction

One candidate is reproduced by running the target with the artifact path as its
only argument:

```text
"$REA_LFZ_FUZZER_COMMAND" <artifact-path>
```

A clean exit means the candidate did not reproduce (`not_reproduced`). A crash
exit's stderr (or stdout when stderr is empty) is the report body, which the
crash-triage parser then reads. Repetition is what turns a report into a POV: at
least two runs by default must name the same sanitizer class and crash-state
hash.

## Failure modes

| Refusal                 | When                                       |
| ----------------------- | ------------------------------------------ |
| `engine_not_configured` | `REA_LFZ_FUZZER_COMMAND` is unset or empty |
| `not_absolute`          | the selected path is relative              |
| `binary_missing`        | the selected path does not exist           |
| `binary_not_executable` | the path is not an executable regular file |
