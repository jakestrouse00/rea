# .NET NativeAOT / ReadyToRun structural recovery

`inspect_nativeaot_types` is a read-only, bounded byte-parser lane that
recovers the publicly documented structural subset of .NET NativeAOT and
ReadyToRun (R2R) PE artifacts: the ReadyToRun directory, MethodTable-shaped
structures, and frozen `String` objects. It complements — and is separate
from — the ECMA-335 metadata lane (`inspect_managed_artifact` /
`inspect_managed_members`), which NativeAOT and native PE images defeat.

## Analyst question

"What types and string literals does this NativeAOT binary contain, and where
are they in the artifact?" Answer at the structural level: recovered rows carry
exact artifact-relative file offsets and virtual addresses (when a PE mapping
exists), because original managed type names are not restored by this lane.

## What is recovered

- **Detection signals**, each reported independently with
  `present` / `absent` / `uncertain`:
  - `readytorun-cli-signature`: the CLI header's managed-native directory
    carrying the `RTR\0` signature (R2R images); parsed by the shared managed
    PE reader.
  - `readytorun-header`: a file scan for the `RTR\0` sentinel over
    initialized non-executable section bytes, with structural validation.
    Sentinel matches that do not validate are `uncertain`, never rows.
  - `dotnet-runtime-debug-header-export`: the exact export name
    `DotNetRuntimeDebugHeader` in the PE export table.
  - `managed-section`: PE sections named `.managed` or `__managed__`.
    Absence of the indicators never claims the binary is not NativeAOT;
    indicators can be stripped.
- **ReadyToRun directory** (`ReadyToRunHeader` + section table): signature,
  major/minor version, flags, entry size/type, and each section row with its
  documented type id and name. NativeAOT module entries are
  `{u32 type, u32 flags, u64 start, u64 end}` (EntrySize 24, EntryType 1);
  CoreCLR ReadyToRun entries are `{u32 type, u32 rva, u32 size}`
  (EntrySize 12). Both layouts are self-describing through EntrySize and
  EntryType, and the detected version is reported as a format hint.
- **MethodTable rows**: pointer targets validated against the documented
  `MethodTable.h` field set (flags with element type 0x14/0x15, base size,
  related type, vtable/interface counts, and vtable slots resolving into
  executable sections). Rows are structural candidates, labelled as such.
- **Frozen string rows**: objects inside the file-backed `FrozenObjectRegion`
  (ReadyToRun section 206) matching the documented ILCompiler
  `FrozenStringNode` layout — a MethodTable reference, an int32 length, UTF-16
  code units, and one NUL terminator — whose MethodTable reference also
  validates as a recovered MethodTable candidate. Layout-only byte sequences
  elsewhere (including inside the directory table) are dropped rather than
  reported.

## What stays unknown (explicit limitation strings)

- Original managed type names, method identities, and runtime type identities.
  Recovering them requires the native-layout blobs and (since .NET 8) the
  dehydrated-data hydration interpreter, whose field sets diverge across
  NativeAOT compiler versions; the lane records the detected version and does
  not guess beyond the verified subset.
- The `TypeManagerIndirection` (204) module header and type-map walks, and any
  native-layout blob: not parsed.
- `DehydratedData` (207) content: the documented rehydration opcodes
  (`DehydratedData.cs`) are known, but a second rehydration interpreter would
  duplicate the dedicated Ghidra-snapshot lane; its bytes therefore remain
  unknown here.
- Frozen objects living only inside the runtime-hydrated overlay, when the
  `FrozenObjectRegion` (206) range is not file-backed.
- CoreCLR R2R directory planes: the directory header is parsed, but
  NativeAOT-style structural row recovery does not apply, and no rows are
  claimed from that plane.
- ELF and Mach-O NativeAOT images: this lane inspects PE artifacts only.
- More than one structurally validated ReadyToRun directory: reported as
  ambiguous (`partial` status) rather than guessed.

## Budgets and coverage

The parser enforces exact, documented bounds — sentinel scan 32 MiB, pointer
scan 64 MiB, 4096 rows per page universe — and reports examined and omitted
bytes plus omitted row counts in `coverage`. Paging (`offset`/`limit`) slices
the recovered rows in a stable file-offset order and never reinterprets bytes.
Artifact identity (path + SHA-256) binds the row set; the provider reads the
artifact stably and fails closed on changes.

## Format sources

- dotnet/runtime (MIT): `src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs`
  (`ReadyToRunHeader`, section ids), `src/coreclr/inc/readytorun.h`
  (`READYTORUN_SECTION`, CoreCLR entry layout, versioning rules),
  `src/coreclr/nativeaot/Runtime/inc/MethodTable.h`,
  `src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/FrozenStringNode.cs`
  and `ArrayOfFrozenObjectsNode.cs` (frozen object layouts),
  `src/coreclr/tools/Common/Internal/Runtime/DehydratedData.cs` (hydration
  opcodes, not implemented here).
- Washi, "Recovering Metadata from .NET Native AOT Binaries" (April 2025) and
  the MIT-licensed `Washi1337/ghidra-nativeaot` plug-in: RTR locator and
  validation, MethodTable discovery, frozen-record annotations.
- `dump-guy/ida-nativeaot`: independent confirmation of the EntrySize/EntryType
  values (0x18/0x01) and section-count bound (0x50).
- HarfangLab detection notes: single `DotNetRuntimeDebugHeader` export and the
  `.managed` section as NativeAOT indicators.

## Lane boundaries

- The Ghidra snapshot lane (`src/domain/native/nativeAotPe.ts`,
  `GhidraNativeAotSnapshotOwner.ts`) owns snapshot-time recovery for
  Ghidra-captured PE snapshots, including the .NET 8 (RTR 9.1) hydration
  interpreter and Ghidra-side type projection. This lane owns caller-selected
  artifact-file inspection with per-row Evidence, detection, and paging. The
  two lanes intentionally differ in consumer, authority, and output shape;
  this lane does not hydrate dehydrated data.
- The ECMA-335 lane owns managed CLI metadata: NativeAOT PE images have no CLI
  metadata, and R2R images are handled by this lane's directory plane only.

## Integration (wired)

- `src/contracts/toolEffects.ts#TOOL_EFFECTS` carries the audited
  `inspect_nativeaot_types` entry, and
  `src/contracts/managed/nativeAotToolContracts.ts` derives its metadata
  through `toolContractMetadata("inspect_nativeaot_types")`
  (`returnsTargetContent: true` — frozen strings are target content).
- `src/contracts/toolContracts.ts` imports `NATIVE_AOT_TOOL_CONTRACTS` from
  `./managed/nativeAotToolContracts.js` and spreads it into the
  `TOOL_CONTRACTS` array.
- `src/server/createServer.ts` declares a
  `nativeAot?: NativeAotArtifactService` option, composes it with
  `createNativeAotArtifactService()` from `src/composition/nativeAot.js`
  next to the Go composition, includes it in the provider close list, and
  calls `registerNativeAotTools(server, nativeAot, ...)` next to
  `registerGoTools`. The registrar binds its handler by contract name and
  fails closed if a contract has no registered operation; name coverage is
  asserted by `src/contracts/managed/nativeAotToolContracts.test.ts`.
- `src/cliCommandNames.ts` carries
  `inspectNativeAotTypes: "inspect-nativeaot-types"`;
  `src/cli/nativeAotCommands.ts` binds it through `CLI_COMMANDS`, and
  `src/cli.ts` calls `registerNativeAotCommands(cli, logger)` next to
  `registerGoCommands`.
- After contract metadata changes, regenerate the derived artifacts with
  `npm run mcp-catalog:generate` and validate with `npm run docs:check`.

## Verification status

Covered by source tests:

- `src/dotnet/ManagedNativeAotImage.test.ts` — golden source-built fixture
  (`ManagedNativeAotPe.fixture.ts`, hand-built PE32 `.managed` section with a
  ReadyToRun directory, MethodTables, and frozen strings) plus ambiguity,
  sentinel-uncertain, absence, CoreCLR-plane, export, and non-PE cases.
- `src/application/nativeAot/NativeAotArtifactService.test.ts` — input
  rejection, paging, Evidence binding, cancellation, identity and malformed
  outputs (fixture-driven, no network).
- `src/contracts/managed/nativeAotToolContracts.test.ts` — contract metadata,
  input boundaries, and Evidence-wrapped output rejection.

Unverified coverage (reported honestly):

- No .NET SDK is installed on the verification host, so no real
  `dotnet publish -p:PublishAot=true` fixture was compiled; claims about real
  NativeAOT images (LayoutKind differences, 64-bit pointer layouts in
  practice, RTR versions other than the fixture's 9.1) are unverified by this
  change beyond the cited public sources.
- No real NativeAOT ELF/Mach-O image was examined; PE-only scope stands.
