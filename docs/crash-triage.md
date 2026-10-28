# Crash triage

`register_fuzzing_campaign`, `read_campaign_status`, `list_crash_dedups`, and
`fetch_crash_evidence` record and read the bookkeeping of a fuzzing campaign on
the MCP server. The module parses sanitizer reports, computes a crash-state
hash, and groups crashes the way ClusterFuzz does; the fuzzing engine itself is
owned by a later lane, so these four tools start nothing.

The tools exist so an analyst can answer, without re-reading raw logs: which
campaign recorded this crash, which other reports share its state, and what the
retained report and reproducer look like on disk.

| Tool                        | Question it answers                                                     |
| --------------------------- | ----------------------------------------------------------------------- |
| `register_fuzzing_campaign` | Which target, seeds, stop condition, and dedup window should be booked? |
| `read_campaign_status`      | What has this campaign retained so far?                                 |
| `list_crash_dedups`         | Which distinct crash states did it record, and how often?               |
| `fetch_crash_evidence`      | What are the structural facts of one crash, and where are its files?    |

## Registration

```text
register_fuzzing_campaign {
  "target_path": "/artifacts/fuzz_target",
  "seed_paths": ["/artifacts/seeds/empty"],
  "budget": {"max_seconds": 600},
  "dedup_frames": 3
}
```

Registration validates the absolute target and seed paths, digests each one
(regular files only, symbolic links refused, 64 MiB per artifact), records the
declared budget, and issues a server-lifetime `campaign_id`. At least one of
`max_runs`, `max_seconds`, or `max_crashes` must be present: a campaign without
a stop condition is refused rather than registered. `dedup_frames` chooses how
many top frames the crash-state hash covers (1–8, default 3).

Registration writes no target bytes and starts no process. It only records
identity.

## Crash state and deduplication

Two reports share a `dedup_id` when their sanitizer class, normalized crash
kind, and first N de-symbolized frames agree:

- reported addresses, module offsets, build paths, and line numbers are
  dropped, so ASLR, a different build directory, or a shifted source line does
  not move the hash;
- a trailing argument list becomes `()`, and decimal runs become `N`, so
  `parse<int>(std::vector const&)` and `parse<char>(char*)` are the same frame
  and `GeneratedFuzz_17` matches `GeneratedFuzz_42`;
- `dedup_id` is `dedup_<sha256>` over that canonical tuple, the same
  prefixed-digest shape the rest of REA uses.

A shared group is an observation about frames, not proof of one root cause.
Reports whose frames differ below the chosen window stay separate, and a report
that names an error type but carries no frame is refused rather than grouped on
its kind alone. Raise `dedup_frames` only when you want a stricter split; the
window is fixed per campaign.

## Supported reports

| Family                     | `sanitizer_class` | Notes                                                    |
| -------------------------- | ----------------- | -------------------------------------------------------- |
| AddressSanitizer           | `address`         | crash stack only; allocation and free stacks are ignored |
| ThreadSanitizer            | `thread`          | the reported access stack                                |
| UndefinedBehaviorSanitizer | `undefined`       | `runtime error:` and `SUMMARY:` forms                    |
| LeakSanitizer              | `leak`            | reported allocations                                     |
| MemorySanitizer            | `memory`          | first report frame onward                                |
| macOS `.ips`               | `none`            | faulting thread, `usedImages` names                      |
| macOS text crash report    | `none`            | crashed thread section, symbols and offsets              |

## Evidence

Every tool records one Evidence observation. `fetch_crash_evidence` returns the
crash kind, dedup identity, sanitizer class, access and signal when the runtime
named them, the parsed frames with their reported symbols and source locations,
the normalized top frames and state hash, occurrence count, the retained report
path with digest and size, and the reproducer path with the size observed at
recording plus whether it exists now.

The complete report body stays on disk, mode `0600`, inside a private runtime
root. Only the sanitizer's own summary line is inlined, bounded to 200
characters, and it can name a source path from the crashing build. Every other
string is bounded at the parse boundary: a frame's symbol, module, and source
path to 512 characters, and a short label such as the exception type or signal
to 128. A clipped value ends in `…`, the frame carries `text_truncated`, and the
result carries `text_truncated` when any field was clipped, so a reader can tell
a structural fact from a clipped one. The reproducer belongs to the caller: REA
records its path and observed size and never copies or rewrites it.

## Lifetime and bounds

Campaigns, crash records, and report copies live in a private runtime root that
the owning REA server removes when it closes. A campaign id is therefore valid
only in the process that issued it; a later server reports it as unknown rather
than pretending to resume it. `read_campaign_status`, `list_crash_dedups`, and
`fetch_crash_evidence` never allocate the store, so a read on a fresh server
creates nothing.

| Bound                              | Value            | Override             |
| ---------------------------------- | ---------------- | -------------------- |
| Seed paths per campaign            | 32               | None in this release |
| Artifact digest per target or seed | 67108864 bytes   | None in this release |
| Campaigns per REA server           | 32               | None in this release |
| Crash records per campaign         | 5000             | None in this release |
| Deduplicated groups per listing    | 200 (default 50) | `limit` per call     |
| Frames hashed per crash state      | 1–8 (default 3)  | `dedup_frames`       |
| Frames retained from one report    | 512              | None in this release |
| Sanitizer summary characters       | 200              | None in this release |

## Minimization hooks

The module also owns the minimizer adapters the fuzzing lane will call:
`libFuzzer -minimize_crash=1` and `afl-tmin`. Both read one caller-owned crash
input and write one caller-owned output path, and neither is reachable from a
public tool in this release.

| Setting                    | Meaning                                                                                                                                                                                           |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REA_LFZ_MINIMIZE_COMMAND` | Absolute path to a libFuzzer-instrumented target binary that accepts `-minimize_crash=1`. Fail-closed: unset, relative, missing, or non-executable is a configuration refusal naming the setting. |
| `REA_AFLTMIN_COMMAND`      | Absolute path to a caller-supplied `afl-tmin` binary. Same fail-closed rules.                                                                                                                     |

REA never builds, downloads, or installs a fuzz target or an AFL++ binary. The
minimizer output is the caller's file: REA reports its observed size and digest,
the engine's own counters when it printed them, and how the call ended. An
existing output path is refused before the minimizer starts, because REA never
overwrites a caller-selected file. Both engine logs stay bounded to 4 MiB per
stream, and only a 512-byte stderr tail can reach a failure message.

## Verification status

The automated tests use synthetic sanitizer and macOS report fixtures and
scripted minimizer stand-ins. They are offline: no sanitizer, no libFuzzer
target, no `afl-tmin`, and no fuzzing engine runs. Report shapes follow the
documented formats but are not captured from a real build, and the crash-state
rules are a documented ClusterFuzz-style reduction, not a byte-for-byte
reimplementation of ClusterFuzz's own normalizer.

See [autonomous execution](./autonomous-execution.md) before pointing a fuzzing
campaign at anything other than a lab-owned target.
