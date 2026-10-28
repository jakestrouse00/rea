# iOS static analysis (ipsw)

The `ipsw` provider reads iOS firmware images, dyld shared caches, Mach-O
images, and crash reports through a **caller-supplied** [blacktop/ipsw](https://github.com/blacktop/ipsw)
CLI. REA never downloads firmware or shared caches, never installs or updates
`ipsw`, and never executes a target. Everything the lane reports comes from
files the caller already holds.

## Configuration

| Setting             | Meaning                                                                         |
| ------------------- | ------------------------------------------------------------------------------- |
| `REA_IPSW_COMMAND`  | **Required.** Absolute path to the caller's `ipsw` binary.                      |
| `REA_IPSW_DSC_PATH` | Optional absolute path to a dyld shared cache file or the directory holding it. |

`REA_IPSW_COMMAND` has no `PATH` fallback: an unset value is a typed
configuration refusal (`not_configured`) that names the setting and the
remediation. When `REA_IPSW_DSC_PATH` is unset on macOS, the provider probes
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld` read-only; it never
writes there. A directory must contain exactly one `dyld_shared_cache_*` file,
otherwise pass `cache` explicitly.

The provider asserts the client with `ipsw version` before every operation and
records the recognized version in Evidence. Install `ipsw` yourself, for
example with `brew install blacktop/tap/ipsw`; REA does not run that command.

## Operations

| Tool                               | Question it answers                                                                             |
| ---------------------------------- | ----------------------------------------------------------------------------------------------- |
| `inspect_ipsw`                     | Which product, iOS version, build, devices, and partitions does this archive hold?              |
| `extract_dyld_shared_cache_images` | Which images are in this shared cache, at which addresses and sizes, and how do I extract some? |
| `dump_ios_class_metadata`          | Which Objective-C or Swift types, methods, and ivar types does this image declare?              |
| `symbolicate_ios_crash`            | Which symbols and source locations do this report's frames resolve to?                          |
| `inspect_macho_entitlements`       | Which entitlement keys and load commands does this Mach-O image carry?                          |

Every tool is also available on the CLI with the same name in kebab case
(`rea inspect-ipsw …`, `rea extract-dyld-shared-cache-images …`).

## Boundaries and discipline

- **Value-free Evidence.** Entitlement values (including team identifiers),
  property values, and method bodies never enter Evidence. Reports carry
  structure: names, offsets, load addresses, sizes, counts, hashes, and rules.
- **Bounded child processes.** Every command is a supervised child with a
  32 MiB stdout cap and a stop signal. Inspection waits at most 120 s;
  extraction waits at most 600 s. This release has no runtime override for
  those deadlines or the capture budget.
- **Caller-owned output.** `extract_dyld_shared_cache_images` creates one new
  subdirectory under the caller's `output_directory` and refuses to replace an
  existing one. Each published image is copied exclusively and digested with
  SHA-256; extraction staging happens in an REA-private runtime root that is
  removed at operation exit, and a root whose removal cannot be confirmed stays
  owned for close-time retry.
- **No archive digest.** `inspect_ipsw` reports the archive size but not a
  SHA-256: IPSW files commonly exceed a bounded scan, and an unbounded read
  would trade the caller's budget for an identity value the inventory already
  describes.
- **Missing is not substituted.** Image selectors the cache manifest does not
  contain are reported in `missing`; they are never mapped to a similar name.

## Objective-C and Swift metadata

`dsdump` is archived upstream, so this lane uses `ipsw`'s own class and Swift
type dumps instead of reviving a dead extractor. Both dialects normalize into
one class table: name, superclass, protocols, methods with signature types,
and ivars with declared types. `max_classes` bounds the reported table and
`unparsed_entries` counts rows the reader could not name instead of guessing
them; either condition makes the observation partial.

## Honest limitations

- **CLI shapes are unverified.** The argv table
  (`src/iosipsw/IpswCommand.ts`) assumes `ipsw info --json`,
  `ipsw dyld info --json`, `ipsw dyld extract <cache> <dir> <image…> --json`,
  `ipsw macho class-dump --json`, `ipsw swift dump --json`,
  `ipsw symbolicate <crash> --dsc <cache> --json`, and
  `ipsw macho info --json --entitlements`. The implementing host had no `ipsw`
  binary, so these remain documented assumptions until a maintainer lane
  records a verified release. No release is pinned as verified.
- **Output dialects are read tolerantly.** The readers accept the field
  spellings they know and count the rest; a partial inventory is reported as
  partial rather than completed by inference.
- **Simulated-fixture tests only.** `tests/boundary/providers/ipsw/` exercises
  provider and lifecycle behavior against a scripted fake executable. It does
  not establish real `ipsw` behavior.
- Symbolication depends on the cache matching the crash report's build; a
  mismatched cache can produce wrong or unresolved symbols and REA cannot
  detect that mismatch.
