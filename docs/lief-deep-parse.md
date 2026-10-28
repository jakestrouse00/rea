# LIEF deep parse

Two tools answer "what does this container declare beyond its layout, and is
there debug information to name these addresses?" through a caller-supplied
LIEF release. `inspect_binary_deep` reports the cross-format structure that the
existing lanes do not own; `extract_pdb_dwarf_info` reports the PDB and DWARF
surfaces and answers bounded symbol and address lookups.

| Tool                     | Input                 | Owner module(s)                                                                       | Provider kind    |
| ------------------------ | --------------------- | ------------------------------------------------------------------------------------- | ---------------- |
| `inspect_binary_deep`    | one ELF/PE/Mach-O     | `src/lief/LiefDeepProvider.ts` + `LiefBridgeClient.ts` (`bridge/lief/lief_bridge.py`) | launched process |
| `extract_pdb_dwarf_info` | one PDB/ELF/PE/Mach-O | same                                                                                  | launched process |

Domain contracts live in `src/domain/lief/`, tool contracts in
`src/contracts/lief/liefToolContracts.ts`, the shared workflow in
`src/application/lief/LiefService.ts`, composition in `src/composition/lief.ts`,
adapters in `src/cli/liefCommands.ts` and `src/server/registerLiefTools.ts`, and
the doctor entry in `src/lief/LiefDoctor.ts`.

## What this lane owns, and what it leaves alone

LIEF is a _second opinion on declarations_, not a replacement for the tools
that already own a fact. `inspect_binary_deep` returns counts for sections,
segments and linked libraries and lists each delegated fact in
`delegated_facts`, naming the tool that owns it:

| Fact                                     | Owning tool               |
| ---------------------------------------- | ------------------------- |
| Section/segment file layout, relocations | `inspect_binary_layout`   |
| ELF notes, build-id                      | `inspect_elf_notes`       |
| Exported symbols and addresses           | `inspect_native_exports`  |
| PE imports                               | `inspect_pe_imports`      |
| PE TLS callbacks, load configuration     | `inspect_pe_load_config`  |
| Authenticode certificate table           | `inspect_pe_certificates` |
| Mach-O header, sections, symbol table    | `inspect_macho`           |
| Code signatures, entitlements            | `inspect_signature`       |

`inspect_binary_deep` adds:

- container classification, including universal Mach-O, and one row per
  architecture with entry point, image base and fat-slice file span;
- ELF interpreter, soname, `DT_NEEDED`, `DT_RPATH`/`DT_RUNPATH` and typed
  dynamic-tag/value rows;
- Mach-O UUID, linked dylibs with their current and compatibility versions, and
  the load-command inventory (kind, size, segment name);
- PE machine, subsystem, characteristics, the data-directory declaration table
  and debug-directory entries with any CodeView PDB identity;
- the DWARF debug-section inventory for the artifact.

A PDB is refused here: `extract_pdb_dwarf_info` owns its symbol surface.

`extract_pdb_dwarf_info` adds the artifact kind, the DWARF section inventory
with compilation-unit and function counts where the reader exposes them, the
CodeView path/GUID/age/signature a PE debug directory recorded, whether the
selected LIEF release can read a PDB symbol table at all, and up to 64 exact
symbol or virtual-address lookups. Each lookup answers `found`, `not_found` or
`unsupported`: an unanswerable lookup is `unsupported` with its reason, never
`not_found`, and every fact the reader could not establish stays `null`.

## Bring your own LIEF

REA never installs, downloads, upgrades or vendors LIEF or Python. Both tools
run one bounded bridge process with the caller's interpreter:

```sh
# 1. Select an interpreter you installed LIEF into yourself.
export REA_LIEF_COMMAND=/usr/local/bin/python3     # absolute, executable
# 2. Copy this release's bridge script into a directory you own.
mkdir -p ~/.local/share/rea/lief
cp bridge/lief/lief_bridge.py ~/.local/share/rea/lief/
export REA_LIEF_BRIDGE_DIR=$HOME/.local/share/rea/lief
```

- `REA_LIEF_COMMAND` must be an absolute path to a regular executable file.
  Unset, relative, missing or non-executable selections are typed
  `AnalysisCapabilityUnavailableError` refusals naming the setting and its fix;
  they never fall back to `PATH`.
- `REA_LIEF_BRIDGE_DIR` must be an absolute directory holding an unmodified
  `lief_bridge.py`. REA reads that script and never writes, replaces or
  refreshes it. `python -B` and `PYTHONDONTWRITEBYTECODE=1` keep the run from
  leaving bytecode in your directory.
- The bridge imports LIEF from the interpreter's own environment. A missing
  import is a `lief_missing` frame that REA reports with the import
  remediation; it is not a partial report.

`rea doctor` gains a `lief` provider entry that probes the selected interpreter
with `-B -c "import json, lief; ..."` under a 20 s deadline and a 64 KiB output
budget and reports `not_configured`, `not_absolute`, `command_missing`,
`command_not_executable`, `bridge_directory_missing`, `bridge_script_not_found`,
`invalid_path`, `executable_missing`, `import_failed`, `version_unresolved` or
`version_unsupported` with the matching remediation.

## Version pinning

The bridge targets `LIEF >= 0.14.0` and `< 0.17.0`
(`src/domain/lief/liefLimits.ts`). A report whose `bridge.lief_version` falls
outside that range is refused typed with the import remediation instead of
being interpreted. The range is a declared API-target range: the surfaces the
bridge uses are feature-detected per release (`DWARF.from_binary` /
`dwarf.load` / `DWARF.parse`, `PDB.from_file` / `PDB.parse` / `pdb.load`,
`MachO.FatBinary`), and every patch release inside the range is **not**
separately verified. See the coverage note below.

## Protocol and bounds

One request line reaches the bridge's stdin; exactly one JSON frame leaves its
stdout. Nothing else is written to stdout, and diagnostics go to stderr.

```
-> {"protocol":1,"operation":"inspect_binary_deep","path":"…",
    "artifact":{"sha256":"…","bytes":1234}}
<- {"kind":"lief_report","protocol":1,"operation":"inspect_binary_deep",
    "bridge":{"lief_version":"0.16.0","python_version":"3.13.1",
              "capabilities":{"dwarf":true,"pdb":true,"fat":true}},
    "report":{…}}
```

Refusals use a closed code set: `empty_request`, `oversized_request`,
`malformed_request`, `unsupported_protocol`, `unsupported_operation`,
`lief_missing`, `artifact_unreadable`, `artifact_mismatch`,
`unsupported_format`, `parse_failed`, `internal_error`. REA projects each onto
its error algebra (unsupported target, input error, artifact-changed, output
error, capability unavailable) with remediation.

Integrity: REA hashes the selected artifact before the run and puts the digest
and byte count in the request; the bridge re-hashes the file and refuses
`artifact_mismatch` if the bytes changed. The Evidence subject digest is the
same SHA-256.

Fixed bounds (settings constraints, no runtime override):

| Bound                      | Value                                    |
| -------------------------- | ---------------------------------------- |
| Request frame              | 1 MiB                                    |
| Response frame             | 8 MiB (larger is refused, never clipped) |
| Retained bridge stderr     | 64 KiB                                   |
| One bridge run             | 120 000 ms                               |
| Architectures / fat slices | 32                                       |
| Dynamic entries            | 256                                      |
| Linked libraries           | 256                                      |
| Mach-O load commands       | 512                                      |
| PE data directories        | 32                                       |
| PE debug entries           | 16                                       |
| DWARF sections listed      | 64                                       |
| Lookups per request        | 64                                       |
| Matches per lookup         | 16                                       |
| DWARF functions scanned    | 200 000                                  |

Exceeding a structure bound sets that row's `truncated` flag; exceeding a
lookup bound sets `truncated.matches` or `truncated.dwarf_functions`.
`complete` is the exact negation of any truncation, so a truncated report is
never presented as complete.

## Authority and safety

The lane is read-only with respect to the target: LIEF parses bytes, REA never
executes the selected artifact, and the only process launched is the
caller-selected interpreter running the copied bridge script under
`src/process/` supervision (owned process group, TERM→KILL cleanup, no network
access, no ambient-environment persistence). No target-content bytes are
inlined: the reports carry names, enumerations, addresses, sizes and digests
that LIEF exposes as structure, plus the caller's own lookup values. Symbol and
path names are still target-authored text, so both tools are marked as
returning target content.

## Coverage and honesty notes

- The bridge was written against LIEF's documented Python surface and
  feature-detects every entry point it uses. LIEF is not installed on the
  development host used for this change, so **no real LIEF release parsed a real
  ELF, PE, Mach-O or PDB during this work**. `bridge/lief/test_lief_bridge.py`
  (17 tests) exercises the frame contract, refusals, structure extraction and
  lookup semantics against an in-process fake LIEF and a one-line fake module;
  `tests/boundary/providers/lief/liefDeepParse.test.ts` (9 tests) drives the
  composed service, including one end-to-end run of the shipped script against
  a fake `lief.py`. Verify against a real release before claiming real-provider
  coverage, and expect vendor attribute drift inside the pinned range.
- LIEF's DWARF and PDB Python surfaces are thinner than its ELF/PE/Mach-O
  surfaces: which of them answer depends on the installed release. A missing
  reader, not missing debug data, produces `unsupported`.
- PDB lookups are exact-name matches over public symbols only; private and
  local symbols stay unlisted, and no source-server stream is parsed, fetched
  or executed.
