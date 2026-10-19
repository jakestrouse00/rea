# Windows offline artifact lanes

Three offline Windows crash-artifact inspection tools, all strictly
Evidence-wrapped and free of target execution:

| Tool                       | Input      | Owner module(s)                                                        | Provider kind     |
| -------------------------- | ---------- | ---------------------------------------------------------------------- | ----------------- |
| `inspect_windows_minidump` | one `.dmp` | `src/windows/WindowsMinidump.ts` + `WindowsMinidumpProvider.ts`        | bundled (offline) |
| `inspect_wer_report`       | one `.wer` | `src/windows/WindowsWer.ts` + `WindowsWerProvider.ts`                  | bundled (offline) |
| `inspect_pdb_symbols`      | one `.pdb` | `src/pdb/PdbSymbolProvider.ts` + `PdbDumpText.ts` (BYO `llvm-pdbutil`) | launched process  |

Domain contracts live in `src/domain/windowsArtifacts/`, tool contracts in
`src/contracts/windowsArtifacts/windowsArtifactsToolContracts.ts`, the shared
workflow in
`src/application/windowsArtifacts/WindowsArtifactsService.ts`, composition in
`src/composition/windowsArtifacts.ts`, adapters in `src/cli/windowsArtifactsCommands.ts`
and `src/server/registerWindowsArtifactsTools.ts`, and doctor entries in
`src/windows/WindowsArtifactsDoctor.ts` and `src/pdb/PdbDoctor.ts`.

## Windows minidump (`inspect_windows_minidump`)

Pure TypeScript byte parser in the fork's bounded-parser style. It reads a
stable snapshot (`readStableArtifact`, 1 GiB input budget, SHA-256 Evidence)
and returns, inline:

- Header: raw `Version`, timestamp, 64-bit `Flags`.
- The complete stream directory — every declared stream typed and located;
  stream types this reader does not model are listed as `unparsed` entries and
  are never fabricated or summarized.
- Modeled streams: `ThreadListStream` (type 3), `ModuleListStream` (4),
  `MemoryListStream` (5), `ExceptionStream` (6), `SystemInfoStream` (7),
  `Memory64ListStream` (9), `MemoryInfoListStream` (16).
- Module entries carry their MINIDUMP_STRING names (plus raw name bytes when
  the name is not valid UTF-16LE), base/size/checksum/timestamp and the full
  `VS_FIXEDFILEINFO` field set.
- Threads are reported as addresses only: id, suspend/priority, TEB, stack
  range and location, and the context-record file location. CONTEXT register
  values are deliberately unknown.
- The exception record's code (e.g. an NTSTATUS), flags, record/address
  values, thread id, parameter vector and context location.
- Memory inventories as ranges and facts: `MemoryList` ranges with file RVAs,
  `Memory64` ranges with sequential data offsets, and `MemoryInfoList` region
  facts (state/protect/type), iterated with the dump's own `SizeOfEntry`/
  `SizeOfHeader` values.

Malformed structure fails typed (`MinidumpFormatFailure`); declared tables
above the measured budgets (4096 streams, 65536 entries) fail typed
(`MinidumpResourceFailure`); neither returns partial success.

Tests: `src/windows/WindowsMinidump.test.ts` against hand-built synthetic
dumps assembled byte-for-byte by `src/windows/WindowsMinidump.fixture.ts`
(committed builder, no binary fixtures); boundary coverage in
`tests/boundary/providers/windows/windowsArtifacts.test.ts` materializes the
same bytes as stable files.

## WER reports (`inspect_wer_report`)

WER files are UTF-16LE key=value text. The reader decodes the exact bytes
(BOM-detected, with a zero-byte-pattern fallback for BOM-less UTF-16LE, plus
UTF-8/ASCII fallbacks), returns every field verbatim in file order, groups
`Sig[N]` and `DynamicSig[N]` module-signature entries, and preserves lines
without a separator as unparsed text. Redaction discipline: no value is
rewritten, defaulted or inferred from its key name, and no secrecy is
inferred — values including usernames and paths reach the caller so that the
caller's own policy decides. Budget: 64 MiB / 65536 lines, typed failure above.

## PDB symbol inspection (`inspect_pdb_symbols`)

Bring-your-own `llvm-pdbutil` (Kuna pattern):

- `REA_LLVM_PDBUTIL_COMMAND` must name an absolute path to a caller-supplied
  executable; REA never installs, downloads, or updates LLVM tooling. Unset or
  invalid → the doctor reports it and the tool refuses typed
  (`AnalysisCapabilityUnavailableError`, provider `llvm-pdbutil`).
- One bounded invocation per inspection:
  `llvm-pdbutil dump -summary -streams -modules -files -symbols -publics <pdb>`
  with a 120 s deadline and a 128 MiB output budget; truncation, timeouts and
  nonzero exits fail typed rather than returning a partial symbol table.
- The documented `dump` text shapes (verified against LLVM's own FileCheck
  tests: `<offset> | S_* [size = N] `name`` records, `addr = seg:off`
  continuations, `Mod 0000` headings, `Named Stream: '...'` lines) are parsed
  into modules, compilands, symbol records with segment:offset addresses and
  code sizes, and named-stream names. Every unmatched line is preserved
  verbatim as unparsed text with a total count.
- Source-server discipline: named streams under `/src/` are recorded as inert
  stream names only (`srcsrv_streams_observed` with a schema-enforced
  `srcsrv_executed: false`). Nothing inside the PDB is executed, fetched, or
  resolved — srcsrv streams are never parsed as configuration.
- Selected PDB bytes are SHA-256-hashed as Evidence identity; the bytes are
  never executed.

Doctor: `rea doctor` gains an `llvm-pdbutil` provider entry probing
`--version` (10 s, 64 KiB budget) with remediations per failure code, and a
bundled `windows-artifacts` entry reporting the offline lanes.

## Integration (wired)

The Windows-artifact contracts and commands are wired into the canonical
registries and composed in both adapters:

- Effects: `src/contracts/toolEffects.ts#TOOL_EFFECTS` carries
  `inspect_windows_minidump: evidence`, `inspect_wer_report: evidence` and
  `inspect_pdb_symbols: nativeEvidence`; the contract module derives each
  entry's metadata through `toolContractMetadata("<name>")`.
- Contracts: `src/contracts/toolContracts.ts` imports and spreads
  `WINDOWS_ARTIFACTS_TOOL_CONTRACTS` from
  `src/contracts/windowsArtifacts/windowsArtifactsToolContracts.ts` into the
  canonical `TOOL_CONTRACTS` registry.
- CLI names: `src/cliCommandNames.ts#CLI_COMMANDS` carries
  `inspectWindowsMinidump`, `inspectWerReport` and `inspectPdbSymbols`;
  `src/cli/windowsArtifactsCommands.ts` uses those `CLI_COMMANDS` lookups
  directly.
- CLI registration: `src/cli.ts` calls
  `registerWindowsArtifactsCommands(cli, logger)` beside the other
  `register…Commands` calls.
- MCP: `src/server/createServer.ts` declares the
  `windowsArtifacts?: WindowsArtifactsService` option, composes it with
  `createWindowsArtifactsService(...)` from
  `../composition/windowsArtifacts.js`, includes it in the provider close
  list, and calls `registerWindowsArtifactsTools(...)` beside the other tool
  registrations. The registrar binds each handler by contract name and fails
  closed if a contract has no registered operation; name coverage is asserted
  by `src/contracts/windowsArtifacts/windowsArtifactsToolContracts.test.ts`.
- Doctor: `src/doctorRuntime.ts` imports `inspectLlvmPdbutil` and
  `inspectWindowsArtifacts` and awaits both in its `providerInspections`
  list.

After contract metadata changes, regenerate the derived catalog artifacts
(`npm run mcp-catalog:generate`).

## Coverage and honesty notes

- Minidump lane: verified against hand-built synthetic fixtures only (the
  builder lays out the documented `MINIDUMP_*` structs field-by-field). No
  real crash dump from a production Windows system was parsed during this
  change; real-dump shape drift (e.g. stream 5/9 coexistence in large dumps,
  dumpsys-produced dumps) is unverified.
- WER lane: synthetic UTF-16LE fixtures only; behavior of real WER output
  variants (older `ReportIdentifier` layouts, embedded newlines in values) is
  unverified.
- PDB lane: the text-shape parser was written from LLVM's published `dump`
  output tests; `llvm-pdbutil` is not installed on the development host used
  for this change, so no real PDB (MSVC- or lld-link-produced) was dumped.
  The fake-launcher boundary tests verify process invocation, argument shape,
  refusal paths and doctor readiness only, and do not establish real-PDB
  parsing. Verify with a real PDB before claiming coverage.
