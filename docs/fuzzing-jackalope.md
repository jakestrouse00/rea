# Jackalope/TinyInst adapter

`start_fuzzing_campaign` with `"engine": "jackalope"` drives a caller-built
Jackalope fuzzer, which uses TinyInst to instrument a target without a
specialized compiler.

## Selection and build

| Setting | Value |
| --- | --- |
| `REA_JACKALOPE_DIR` | absolute path to a Jackalope/TinyInst build directory |

The directory must contain:

```text
<REA_JACKALOPE_DIR>/fuzzer           executable
<REA_JACKALOPE_DIR>/instrumentation  TinyInst instrumentation module
```

Build it from the upstream C++ sources with CMake in `Release` configuration and
follow that project's own build notes; REA never clones, builds, downloads, or
updates Jackalope, and it does not assume a fixed checkout layout. Point
`REA_JACKALOPE_DIR` at whichever directory holds the two artifacts above, then
restart REA. A missing artifact is a `build_missing` refusal naming the
directory.

Jackalope is a host-platform build: the adapter runs it on this host only, so it
is not offered on the lab-VM route.

## Launch

```text
"$REA_JACKALOPE_DIR/fuzzer" -i <corpus-copy> -o <campaign-root>/artifacts \
  -t <registered-target> [-n <max_runs>]
```

- `-i` is the private corpus copy.
- `-o` is the campaign artifact directory; every regular file the build writes
  there is a crash candidate except `README.txt`, dotfiles, and REA's own
  `engine.log`.
- `-t` is the registered target.
- `-n` is the iteration budget when `budget.max_runs` is declared.

Jackalope has no wall-clock flag, so the seconds budget is enforced by REA
stopping the owned process at its deadline (then killing it after five seconds).

## Statistics

The adapter reads the console's counter lines, which use either an elapsed-time
bracket or an iteration prefix with `key: value` counters:

```text
[ 12 sec ] exec/s: 500 cov: 21 corpus: 4
#88 iterations: 88 exec/s: 40 cov: 12
```

Read from each line: `iterations`/`execs`/`#N` → `executions` (the bracket is
elapsed time, so it never becomes an execution count), `exec/s` →
`executions_per_second`, `cov`/`edges` → `edges`, `corp`/`corpus` →
`corpus_entries`. A bracketed line that names no counter is ignored rather than
counted as progress, and the observed-crash count always comes from the artifact
directory, not from the console.

## Reproduction

One candidate is reproduced by running the build over a corpus holding exactly
that input for one iteration:

```text
"$REA_JACKALOPE_DIR/fuzzer" -i <single-input-corpus> -o <pov-output> \
  -t <registered-target> -n 1
```

The build's stderr carries the sanitizer report REA parses; repeated runs must
agree on the crash-state hash before the crash is accepted. `-n 1` bounds the
reproduction to a single iteration.

## Minimization

No crash-triage minimizer adapter is documented for a Jackalope build, so
`minimize_crashes: true` leaves accepted crashes unminimized and the observation
reports the limitation instead of inventing a command.
