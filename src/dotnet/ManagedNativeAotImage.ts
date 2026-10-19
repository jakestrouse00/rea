import type {
  NativeAotArtifactInspection,
  NativeAotInspectionRow,
} from "../domain/managed/nativeAotArtifact.js";
import { nativeAotArtifactInspectionSchema } from "../domain/managed/nativeAotArtifact.js";
import {
  readManagedPeLayout,
  type ManagedPeLayout,
} from "./ManagedPeReader.js";
import { ManagedReaderFailure } from "./ManagedReaderFailure.js";

/**
 * Bounded NativeAOT/ReadyToRun structural recovery from PE artifacts.
 *
 * The implemented subset is exactly the publicly documented surface:
 * `ReadyToRunHeader` / `READYTORUN_SECTION` fields and the section-type ids
 * from `src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs` and
 * `src/coreclr/inc/readytorun.h` (dotnet/runtime, MIT), the MethodTable field
 * layout from `src/coreclr/nativeaot/Runtime/inc/MethodTable.h`, the frozen
 * object/String object layouts from the ILCompiler `FrozenStringNode` and
 * `ArrayOfFrozenObjectsNode`, and the detection procedure documented by the
 * public Washi `ghidra-nativeaot` and dump-guy `ida-nativeaot` plug-ins.
 * Everything else — the dehydrated-data hydration interpreter, native-layout
 * blobs, module/type-name walks — stays unknown with limitation strings
 * instead of guessed across NativeAOT compiler versions.
 */

/** 'RTR\0' ReadyToRunHeaderConstants.Signature. */
const RTR_SIGNATURE = 0x00525452;
const RTR_HEADER_BYTES = 16;
/**
 * Self-describing directory entry layouts verified against dotnet/runtime:
 * NativeAOT module entries are {u32 type, u32 flags, u64 start, u64 end};
 * CoreCLR ReadyToRun entries are {u32 type, u32 rva, u32 size}. Other
 * EntrySize/EntryType combinations are unknown, never guessed.
 */
const RTR_ENTRY_SIZE_NATIVEAOT = 24;
const RTR_ENTRY_TYPE_NATIVEAOT = 1;
const RTR_ENTRY_SIZE_CORECLR = 12;
const RTR_ENTRY_TYPE_CORECLR = 0;
/** Public plug-ins and the runtime bound the directory table to 0x50 rows. */
const MAX_RTR_SECTIONS = 80;

const IMAGE_SCN_MEM_EXECUTE = 0x2000_0000;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x0000_0080;

/** Exact parser bounds (documented budgets, not operating-system limits). */
const SENTINEL_SCAN_BUDGET_BYTES = 32 * 1024 * 1024;
const POINTER_SCAN_BUDGET_BYTES = 64 * 1024 * 1024;
const MAX_ROWS = 4096;
const MAX_STRING_LENGTH = 0x10000;
const MAX_STRING_CHARS = 1024;
const MAX_EXPORT_NAMES = 0x10000;
const MAX_EXPORT_NAME_BYTES = 256;
/** Minimum MethodTable base size follows the runtime's minimum object size. */
const MIN_MT_BASE_SIZE = (pointerSize: 4 | 8): number =>
  pointerSize === 8 ? 16 : 12;
const MAX_MT_BASE_SIZE = 0x1000_0000;
const MAX_MT_SLOTS = 4096;
const DEBUG_HEADER_EXPORT_NAME = "DotNetRuntimeDebugHeader";

const RTR_SECTION_FROZEN_OBJECT_REGION = 206;
const RTR_SECTION_DEHYDRATED_DATA = 207;
const RTR_SECTION_TYPE_MANAGER_INDIRECTION = 204;

/**
 * ReadyToRun section ids from `ModuleHeaders.cs` / `readytorun.h`. Ids
 * outside the documented enum stay null with a limitation string.
 */
const RTR_SECTION_TYPE_NAMES: Readonly<Record<number, string>> = {
  100: "CompilerIdentifier",
  101: "ImportSections",
  102: "RuntimeFunctions",
  103: "MethodDefEntryPoints",
  104: "ExceptionInfo",
  105: "DebugInfo",
  106: "DelayLoadMethodCallThunks",
  108: "AvailableTypes",
  109: "InstanceMethodEntryPoints",
  111: "ProfileDataInfo",
  112: "ManifestMetadata",
  113: "AttributePresence",
  114: "InliningInfo2",
  115: "ComponentAssemblies",
  116: "OwnerCompositeExecutable",
  117: "PgoInstrumentationData",
  118: "ManifestAssemblyMvids",
  119: "CrossModuleInlineInfo",
  120: "HotColdMap",
  121: "MethodIsGenericMap",
  122: "EnclosingTypeMap",
  123: "TypeGenericInfoMap",
  124: "ExternalTypeMaps",
  125: "ProxyTypeMaps",
  126: "TypeMapAssemblyTargets",
  127: "WasmAsyncResumeInfo",
  200: "StringTable",
  201: "GCStaticRegion",
  202: "ThreadStaticRegion",
  204: "TypeManagerIndirection",
  205: "EagerCctor",
  206: "FrozenObjectRegion",
  207: "DehydratedData",
  208: "ThreadStaticOffsetRegion",
  209: "InterfaceDispatchCellInfoRegion",
  210: "InterfaceDispatchCellRegion",
  212: "ImportAddressTables",
  213: "ModuleInitializerList",
  214: "GvmDispatchCellInfoRegion",
  215: "GvmDispatchCellRegion",
};

interface RtrSectionEntry {
  readonly type: number;
  readonly flags: number | null;
  readonly start: bigint | null;
  readonly end: bigint | null;
  readonly rva: number | null;
  readonly size: number | null;
}

interface RtrHeader {
  readonly offset: number;
  readonly major: number;
  readonly minor: number;
  readonly flags: number;
  readonly sectionCount: number;
  readonly entrySize: number;
  readonly entryType: number;
  readonly layout: "nativeaot-module" | "coreclr-readytorun";
  readonly entries: readonly RtrSectionEntry[];
}

interface PeScope {
  readonly bytes: Buffer;
  readonly layout: ManagedPeLayout;
  readonly pointerSize: 4 | 8;
  readonly vaToFileOffset: (
    va: bigint,
    size: number,
    scope: string,
  ) => number | null;
  readonly offsetToVa: (offset: number) => string | null;
  readonly isExecutableVa: (va: bigint) => boolean;
  readonly scanRanges: readonly {
    readonly start: number;
    readonly end: number;
  }[];
}

/** Non-executable, initialized, file-backed extents the byte scans admit. */
const scannableRanges = (
  layout: ManagedPeLayout,
): {
  readonly start: number;
  readonly end: number;
}[] =>
  layout.sections
    .filter(
      (section) =>
        section.rawSize > 0 &&
        (section.characteristics & IMAGE_SCN_MEM_EXECUTE) === 0 &&
        (section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) === 0,
    )
    .map((section) => ({
      start: section.rawOffset,
      end: section.rawOffset + Math.min(section.rawSize, section.virtualSize),
    }))
    .filter((range) => range.end > range.start);

const scannableBytes = (layout: ManagedPeLayout): number =>
  scannableRanges(layout).reduce(
    (total, range) => total + (range.end - range.start),
    0,
  );

const containsVa = (layout: ManagedPeLayout, va: bigint): boolean => {
  const rva = va - layout.imageBase;
  if (rva < 0n || rva > 0xffff_fffn) return false;
  const rvaNumber = Number(rva);
  return layout.sections.some(
    (section) =>
      section.virtualSize > 0 &&
      rvaNumber >= section.virtualAddress &&
      rvaNumber < section.virtualAddress + section.virtualSize,
  );
};

const isExecutableVa = (layout: ManagedPeLayout, va: bigint): boolean => {
  const rva = va - layout.imageBase;
  if (rva < 0n || rva > 0xffff_fffn) return false;
  const rvaNumber = Number(rva);
  return layout.sections.some(
    (section) =>
      (section.characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0 &&
      section.virtualSize > 0 &&
      rvaNumber >= section.virtualAddress &&
      rvaNumber < section.virtualAddress + section.virtualSize,
  );
};

const buildScope = (bytes: Buffer, layout: ManagedPeLayout): PeScope => ({
  bytes,
  layout,
  pointerSize: layout.optionalHeader === "pe32-plus" ? 8 : 4,
  vaToFileOffset: (va, size, scopeName) => {
    const rva = va - layout.imageBase;
    if (rva < 0n || rva > 0xffff_fffn) return null;
    return layout.tryRvaToOffset(Number(rva), size, scopeName);
  },
  offsetToVa: (offset) => {
    const section = layout.sections.find(
      (candidate) =>
        candidate.rawSize > 0 &&
        offset >= candidate.rawOffset &&
        offset <
          candidate.rawOffset +
            Math.min(candidate.rawSize, candidate.virtualSize),
    );
    return section === undefined
      ? null
      : hex(
          layout.imageBase +
            BigInt(section.virtualAddress + offset - section.rawOffset),
        );
  },
  isExecutableVa: (va) => isExecutableVa(layout, va),
  scanRanges: scannableRanges(layout),
});

const hex = (value: bigint): string => `0x${value.toString(16)}`;

/** Reserve the complete directory table once it validates structurally. */
const consumedTable = (budget: ScanBudget, header: RtrHeader): void => {
  consume(budget, header.sectionCount * header.entrySize);
};

interface ScanBudget {
  remaining: number;
  readonly total: number;
}

const exhausted = (budget: ScanBudget): boolean => budget.remaining <= 0;

const consume = (budget: ScanBudget, bytes: number): boolean => {
  if (bytes > budget.remaining) {
    budget.remaining = 0;
    return false;
  }
  budget.remaining -= bytes;
  return true;
};

/** Decode and structurally validate one ReadyToRun directory candidate. */
const parseRtrHeader = (
  bytes: Buffer,
  offset: number,
  limitOffset: number,
): RtrHeader | null => {
  if (offset < 0 || offset > bytes.length - RTR_HEADER_BYTES) return null;
  if (bytes.readUInt32LE(offset) !== RTR_SIGNATURE) return null;
  const major = bytes.readUInt16LE(offset + 4);
  const minor = bytes.readUInt16LE(offset + 6);
  const flags = bytes.readUInt32LE(offset + 8);
  const sectionCount = bytes.readUInt16LE(offset + 12);
  const entrySize = bytes.readUInt8(offset + 14);
  const entryType = bytes.readUInt8(offset + 15);
  const layout =
    entrySize === RTR_ENTRY_SIZE_NATIVEAOT &&
    entryType === RTR_ENTRY_TYPE_NATIVEAOT
      ? "nativeaot-module"
      : entrySize === RTR_ENTRY_SIZE_CORECLR &&
          entryType === RTR_ENTRY_TYPE_CORECLR
        ? "coreclr-readytorun"
        : null;
  if (layout === null || sectionCount < 1 || sectionCount > MAX_RTR_SECTIONS)
    return null;
  if (offset + RTR_HEADER_BYTES + sectionCount * entrySize > limitOffset)
    return null;
  const entries: RtrSectionEntry[] = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const entryOffset = offset + RTR_HEADER_BYTES + index * entrySize;
    const type = bytes.readUInt32LE(entryOffset);
    if (layout === "nativeaot-module") {
      const entryFlags = bytes.readUInt32LE(entryOffset + 4);
      const start = bytes.readBigUInt64LE(entryOffset + 8);
      const end = bytes.readBigUInt64LE(entryOffset + 16);
      if (end < start) return null;
      entries.push({
        type,
        flags: entryFlags,
        start,
        end,
        rva: null,
        size: null,
      });
    } else {
      entries.push({
        type,
        flags: null,
        start: null,
        end: null,
        rva: bytes.readUInt32LE(entryOffset + 4),
        size: bytes.readUInt32LE(entryOffset + 8),
      });
    }
  }
  return {
    offset,
    major,
    minor,
    flags,
    sectionCount,
    entrySize,
    entryType,
    layout,
    entries,
  };
};

interface SentinelScan {
  readonly sentinelMatches: number;
  readonly validated: readonly RtrHeader[];
  readonly examined: number;
  readonly omitted: number;
}

/** Documented locator: scan initialized non-executable data for the sentinel. */
const scanSentinels = (scope: PeScope, budget: ScanBudget): SentinelScan => {
  let sentinelMatches = 0;
  const validated: RtrHeader[] = [];
  let examined = 0;
  scan: for (const range of scope.scanRanges) {
    for (let offset = range.start; offset + 4 <= range.end; offset += 4) {
      if (exhausted(budget)) break scan;
      if (!consume(budget, 4)) break scan;
      examined += 4;
      if (scope.bytes.readUInt32LE(offset) !== RTR_SIGNATURE) continue;
      sentinelMatches += 1;
      const header = parseRtrHeader(
        scope.bytes,
        offset,
        Math.min(range.end, scope.bytes.length),
      );
      // A validated directory is self-describing plus at least one mapped image range.
      const referencesImage =
        header === null
          ? false
          : header.layout === "nativeaot-module"
            ? header.entries.some(
                (entry) =>
                  entry.start !== null && containsVa(scope.layout, entry.start),
              )
            : header.entries.some(
                (entry) =>
                  entry.rva !== null &&
                  entry.rva !== 0 &&
                  scope.layout.tryRvaToOffset(
                    entry.rva,
                    1,
                    "nativeaot.rtr-section",
                  ) !== null,
              );
      if (header !== null && referencesImage) {
        consumedTable(budget, header);
        examined += header.sectionCount * header.entrySize;
        validated.push(header);
      } else if (header !== null) {
        sentinelMatches -= 1;
      }
    }
  }
  const scannedTotal = scannableBytes(scope.layout);
  return {
    sentinelMatches,
    validated,
    examined,
    omitted: Math.max(0, scannedTotal - examined),
  };
};

interface MethodTableCandidate {
  readonly fileOffset: number;
  readonly endFileOffset: number | null;
  readonly va: string | null;
  readonly flags: number;
  readonly elementType: "class" | "value-type";
  readonly baseSize: number;
  readonly relatedVa: bigint | null;
  readonly relatedFileOffset: number | null;
  readonly vtableSlots: number;
  readonly interfaces: number;
}

/** Validate the documented MethodTable field set at a pointer target. */
const validateMethodTable = (
  scope: PeScope,
  va: bigint,
): MethodTableCandidate | null => {
  const fileOffset = scope.vaToFileOffset(va, 8, "nativeaot.method-table");
  if (fileOffset === null) return null;
  const bytes = scope.bytes;
  if (fileOffset + 8 > bytes.length) return null;
  const flags = bytes.readUInt32LE(fileOffset);
  const baseSize = bytes.readUInt32LE(fileOffset + 4);
  const elementTypeRaw = (flags & 0x7c00_0000) >>> 26;
  const elementType =
    elementTypeRaw === 0x14
      ? "class"
      : elementTypeRaw === 0x15
        ? "value-type"
        : null;
  if (elementType === null) return null;
  if (
    baseSize < MIN_MT_BASE_SIZE(scope.pointerSize) ||
    baseSize > MAX_MT_BASE_SIZE
  )
    return null;
  const related =
    scope.pointerSize === 8
      ? bytes.readBigUInt64LE(fileOffset + 8)
      : BigInt(bytes.readUInt32LE(fileOffset + 8));
  const countsOffset = fileOffset + 8 + scope.pointerSize;
  if (countsOffset + 4 > bytes.length) return null;
  const vtableSlots = bytes.readUInt16LE(countsOffset);
  const interfaces = bytes.readUInt16LE(countsOffset + 2);
  if (vtableSlots + interfaces > MAX_MT_SLOTS) return null;
  const tableBytes =
    (scope.pointerSize === 8 ? 24 : 16) +
    (vtableSlots + interfaces) * scope.pointerSize;
  const endFileOffset = fileOffset + tableBytes;
  if (endFileOffset > bytes.length) return null;
  for (let slot = 0; slot < vtableSlots; slot += 1) {
    const slotOffset =
      fileOffset +
      (scope.pointerSize === 8 ? 24 : 16) +
      slot * scope.pointerSize;
    const target =
      scope.pointerSize === 8
        ? bytes.readBigUInt64LE(slotOffset)
        : BigInt(bytes.readUInt32LE(slotOffset));
    if (target !== 0n && !scope.isExecutableVa(target)) return null;
  }
  for (let index = 0; index < interfaces; index += 1) {
    const slotOffset =
      fileOffset +
      (scope.pointerSize === 8 ? 24 : 16) +
      (vtableSlots + index) * scope.pointerSize;
    const target =
      scope.pointerSize === 8
        ? bytes.readBigUInt64LE(slotOffset)
        : BigInt(bytes.readUInt32LE(slotOffset));
    if (
      target !== 0n &&
      scope.vaToFileOffset(target, 1, "nativeaot.mt-interface") === null
    )
      return null;
  }
  return {
    fileOffset,
    endFileOffset: Math.min(endFileOffset, bytes.length),
    va: scope.offsetToVa(fileOffset),
    flags,
    elementType,
    baseSize,
    relatedVa: related === 0n ? null : related,
    relatedFileOffset:
      related === 0n
        ? null
        : scope.vaToFileOffset(related, 1, "nativeaot.mt-related"),
    vtableSlots,
    interfaces,
  };
};

interface FrozenStringMatch {
  readonly fileOffset: number;
  readonly va: string | null;
  readonly charLength: number;
  readonly value: string | null;
  readonly dataFileOffset: number;
  /** File offset of the referenced MethodTable; layout-only rows without a
   * validated MethodTable target are dropped after the pointer scan. */
  readonly mtFileOffset: number;
}

/**
 * Validate the documented frozen-string object layout: a MethodTable
 * reference, an int32 length, UTF-16 code units, and one NUL terminator.
 */
const validateFrozenString = (
  scope: PeScope,
  rangeEnd: number,
  fileOffset: number,
): FrozenStringMatch | null => {
  const bytes = scope.bytes;
  const mtFieldOffset = fileOffset;
  if (mtFieldOffset + scope.pointerSize + 4 > bytes.length) return null;
  const mtPointer =
    scope.pointerSize === 8
      ? bytes.readBigUInt64LE(mtFieldOffset)
      : BigInt(bytes.readUInt32LE(mtFieldOffset));
  // The documented layout starts with a MethodTable reference; require that
  // reference to map into the image so length or padding fields cannot satisfy
  // the shape.
  if (
    mtPointer === 0n ||
    scope.vaToFileOffset(mtPointer, 1, "nativeaot.frozen-string-mt") === null
  )
    return null;
  const mtFileOffset = scope.vaToFileOffset(
    mtPointer,
    1,
    "nativeaot.frozen-string-mt",
  );
  if (mtFileOffset === null) return null;
  const charLength = bytes.readUInt32LE(mtFieldOffset + scope.pointerSize);
  if (charLength > MAX_STRING_LENGTH) return null;
  const dataFileOffset = mtFieldOffset + scope.pointerSize + 4;
  const byteLength = (charLength + 1) * 2;
  if (dataFileOffset + byteLength > bytes.length) return null;
  if (dataFileOffset + byteLength > rangeEnd) return null;
  if (bytes.readUInt16LE(dataFileOffset + charLength * 2) !== 0) return null;
  return {
    fileOffset,
    va: scope.offsetToVa(fileOffset),
    charLength,
    value:
      charLength <= MAX_STRING_CHARS
        ? bytes
            .subarray(dataFileOffset, dataFileOffset + charLength * 2)
            .toString("utf16le")
        : null,
    dataFileOffset,
    mtFileOffset,
  };
};

/**
 * One bounded pointer-slot scan over the initialized non-executable extents.
 * Each pointer-sized slot is tested both as a frozen-string object header and
 * as a reference to a MethodTable-shaped structure, exactly as the public
 * recovery procedure documents.
 */
const scanPointerSlots = (
  scope: PeScope,
  budget: ScanBudget,
  frozenRange: { readonly start: number; readonly end: number } | null,
  methodTables: Map<number, MethodTableCandidate>,
  strings: Map<number, FrozenStringMatch>,
): { readonly slots: number; readonly examined: number } => {
  let slots = 0;
  let examined = 0;
  scan: for (const range of scope.scanRanges) {
    for (
      let offset = range.start;
      offset + scope.pointerSize <= range.end;
      offset += scope.pointerSize
    ) {
      if (exhausted(budget)) break scan;
      if (!consume(budget, scope.pointerSize)) break scan;
      examined += scope.pointerSize;
      slots += 1;
      const pointer =
        scope.pointerSize === 8
          ? scope.bytes.readBigUInt64LE(offset)
          : BigInt(scope.bytes.readUInt32LE(offset));
      if (pointer !== 0n) {
        const candidate = validateMethodTable(scope, pointer);
        if (candidate !== null && !methodTables.has(candidate.fileOffset))
          methodTables.set(candidate.fileOffset, candidate);
      }
      const stringEnd =
        frozenRange === null ? range.end : Math.min(range.end, frozenRange.end);
      if (
        frozenRange === null ||
        (offset >= frozenRange.start && offset < stringEnd)
      ) {
        const stringMatch = validateFrozenString(scope, stringEnd, offset);
        if (stringMatch !== null) strings.set(offset, stringMatch);
      }
    }
  }
  return { slots, examined };
};

const parseExportNameMatches = (
  scope: PeScope,
): {
  readonly status: "present" | "absent" | "uncertain";
  readonly nameFileOffset: number | null;
} => {
  const exportDirectory = scope.layout.exportDirectory;
  if (exportDirectory === null || exportDirectory.rva === 0)
    return { status: "absent", nameFileOffset: null };
  const directoryOffset = scope.layout.tryRvaToOffset(
    exportDirectory.rva,
    40,
    "nativeaot.export-directory",
  );
  if (directoryOffset === null || directoryOffset + 40 > scope.bytes.length)
    return { status: "uncertain", nameFileOffset: null };
  const numberOfNames = scope.bytes.readUInt32LE(directoryOffset + 24);
  const addressOfNames = scope.bytes.readUInt32LE(directoryOffset + 32);
  if (numberOfNames > MAX_EXPORT_NAMES)
    return { status: "uncertain", nameFileOffset: null };
  const namesOffset = scope.layout.tryRvaToOffset(
    addressOfNames,
    Math.min(numberOfNames, MAX_EXPORT_NAMES) * 4,
    "nativeaot.export-names",
  );
  if (namesOffset === null)
    return { status: "uncertain", nameFileOffset: null };
  for (let index = 0; index < numberOfNames; index += 1) {
    const nameRva = scope.bytes.readUInt32LE(namesOffset + index * 4);
    const nameOffset = scope.layout.tryRvaToOffset(
      nameRva,
      1,
      "nativeaot.export-name",
    );
    if (nameOffset === null) continue;
    const end = scope.bytes.indexOf(0, nameOffset);
    if (end < 0 || end - nameOffset > MAX_EXPORT_NAME_BYTES) continue;
    if (
      scope.bytes.toString("ascii", nameOffset, end) ===
      DEBUG_HEADER_EXPORT_NAME
    )
      return { status: "present", nameFileOffset: nameOffset };
  }
  return { status: "absent", nameFileOffset: null };
};

const notApplicable = (
  sha256: string,
  bytes: Buffer,
  failure: ManagedReaderFailure,
): NativeAotArtifactInspection =>
  nativeAotArtifactInspectionSchema.parse({
    artifact: {
      path: "",
      sha256,
      byte_length: bytes.length,
      format: "pe",
    },
    pe: null,
    status: "not-applicable",
    reason: failure.issue.detail,
    detection: [],
    readytorun_header: null,
    rows: [],
    paging: {
      offset: 0,
      limit: 1,
      total_rows: 0,
      returned_rows: 0,
      complete: true,
    },
    coverage: {
      sentinel_scan_bytes_examined: 0,
      sentinel_scan_bytes_omitted: 0,
      sentinel_candidates: 0,
      validated_readytorun_candidates: 0,
      pointer_slots_examined: 0,
      pointer_scan_bytes_omitted: 0,
      method_tables_recovered: 0,
      frozen_strings_recovered: 0,
      rows_omitted: 0,
      truncated: false,
    },
    limitations: [
      "The artifact is not admitted as a PE image by the shared managed PE reader, so NativeAOT structural inspection is not applicable.",
      failure.issue.detail,
    ],
  });

/**
 * Recover the documented NativeAOT/ReadyToRun structures from artifact bytes
 * without loading or executing anything. Absent, ambiguous, truncated, and
 * version-divergent facts stay explicit unknowns. `sha256` binds the admitted
 * artifact identity that the caller read.
 */
export const inspectManagedNativeAotBytes = (
  sha256: string,
  bytes: Buffer,
): NativeAotArtifactInspection => {
  let layout: ManagedPeLayout;
  try {
    layout = readManagedPeLayout(bytes);
  } catch (cause: unknown) {
    if (cause instanceof ManagedReaderFailure)
      return notApplicable(sha256, bytes, cause);
    throw cause;
  }
  const scope = buildScope(bytes, layout);
  const sentinelBudget: ScanBudget = {
    remaining: SENTINEL_SCAN_BUDGET_BYTES,
    total: SENTINEL_SCAN_BUDGET_BYTES,
  };
  const sentinel = scanSentinels(scope, sentinelBudget);
  const ambiguous = sentinel.validated.length > 1;
  const directory = ambiguous ? null : (sentinel.validated[0] ?? null);
  // Frozen objects live inside the (single, file-backed) FrozenObjectRegion
  // when the directory declares one; the region bounds frozen-string matching.
  const frozenEntries =
    directory?.layout === "nativeaot-module"
      ? directory.entries.filter(
          (entry) => entry.type === RTR_SECTION_FROZEN_OBJECT_REGION,
        )
      : [];
  let frozenRange: { readonly start: number; readonly end: number } | null =
    null;
  const frozenStartEntry =
    frozenEntries.length === 1 ? frozenEntries[0] : undefined;
  const frozenStart = frozenStartEntry?.start ?? null;
  if (frozenStart !== null && containsVa(scope.layout, frozenStart)) {
    const startOffset = scope.vaToFileOffset(
      frozenStart,
      1,
      "nativeaot.frozen-region",
    );
    const frozenEnd = frozenStartEntry?.end ?? null;
    const endOffset =
      frozenEnd !== null &&
      frozenEnd > frozenStart &&
      containsVa(scope.layout, frozenEnd)
        ? scope.vaToFileOffset(frozenEnd, 1, "nativeaot.frozen-region")
        : null;
    if (startOffset !== null && endOffset !== null)
      frozenRange = { start: startOffset, end: endOffset };
  }
  const pointerBudget: ScanBudget = {
    remaining: POINTER_SCAN_BUDGET_BYTES,
    total: POINTER_SCAN_BUDGET_BYTES,
  };
  const methodTables = new Map<number, MethodTableCandidate>();
  const strings = new Map<number, FrozenStringMatch>();
  const pointerScan = scanPointerSlots(
    scope,
    pointerBudget,
    frozenRange,
    methodTables,
    strings,
  );

  const exportMatch = parseExportNameMatches(scope);
  const managedSectionNames = layout.sections
    .map((section) => section.name)
    .filter((name) => name === ".managed" || name === "__managed__");
  const cliSignaturePresent = layout.cli?.readyToRunSignature === true;

  const limitations: string[] = [
    "Rows are structural candidates recovered by the documented MethodTable and frozen-String layouts; original managed type names, method identities, and runtime type-system identities are not recovered by this lane.",
    "Frozen-string rows require the object's MethodTable reference to match a recovered MethodTable candidate; frozen objects whose MethodTable reference does not validate are not reported as rows.",
    "The dehydrated-data hydration interpreter (ReadyToRun section type 207, dotnet 8+ metadata rehydration) is not implemented, so metadata that exists only inside the runtime-hydrated overlay is not recovered.",
    "Native-layout blobs, module headers reached through TypeManagerIndirection, and type-map walks are not parsed; their field sets diverge across NativeAOT compiler versions and are left unknown rather than guessed.",
    "Only PE artifacts are inspected; NativeAOT ELF and Mach-O images are outside this lane.",
  ];

  const detection: NativeAotArtifactInspection["detection"] = [
    {
      signal: "readytorun-cli-signature",
      status:
        layout.cli === null
          ? "absent"
          : cliSignaturePresent
            ? "present"
            : "absent",
      detail:
        layout.cli === null
          ? "The PE has no CLI data directory; the ReadyToRun CLI-header signature is not applicable."
          : cliSignaturePresent
            ? "The CLI header's managed-native directory carries the RTR signature."
            : "A CLI header exists, but its managed-native directory does not carry the RTR signature.",
      file_offset: layout.cli === null ? null : layout.cli.headerOffset,
      va:
        layout.cli === null ? null : scope.offsetToVa(layout.cli.headerOffset),
    },
    {
      signal: "readytorun-header",
      status:
        sentinel.validated.length === 0
          ? sentinel.sentinelMatches > 0
            ? "uncertain"
            : "absent"
          : ambiguous
            ? "uncertain"
            : "present",
      detail:
        sentinel.validated.length === 0
          ? sentinel.sentinelMatches > 0
            ? `${sentinel.sentinelMatches} RTR sentinel matches; none validated as a ReadyToRun directory.`
            : "No RTR sentinel was found in initialized non-executable section bytes."
          : ambiguous
            ? `${sentinel.validated.length} structurally validated ReadyToRun directories; selection would be a guess, so the directory is left unknown.`
            : `Validated ReadyToRun directory, ${directory === null ? 0 : directory.sectionCount} sections, ${directory?.layout === "nativeaot-module" ? "NativeAOT" : "CoreCLR"} entry layout.`,
      file_offset: directory === null ? null : directory.offset,
      va: directory === null ? null : scope.offsetToVa(directory.offset),
    },
    {
      signal: "dotnet-runtime-debug-header-export",
      status:
        exportMatch.status === "absent" && scope.layout.exportDirectory === null
          ? "absent"
          : exportMatch.status,
      detail:
        exportMatch.status === "present"
          ? "The export table contains the DotNetRuntimeDebugHeader export name."
          : exportMatch.status === "uncertain"
            ? "The export directory exists but could not be completely examined; export presence is unknown."
            : scope.layout.exportDirectory === null
              ? "The PE has no export directory."
              : "The export directory contains no DotNetRuntimeDebugHeader export name.",
      file_offset: exportMatch.nameFileOffset,
      va:
        exportMatch.nameFileOffset === null
          ? null
          : scope.offsetToVa(exportMatch.nameFileOffset),
    },
    {
      signal: "managed-section",
      status: managedSectionNames.length > 0 ? "present" : "absent",
      detail:
        managedSectionNames.length > 0
          ? `PE sections named ${managedSectionNames.map((name) => JSON.stringify(name)).join(", ")} are present.`
          : "No PE section is named .managed or __managed__.",
      file_offset: null,
      va: null,
    },
  ];

  const readytorunHeader: NativeAotArtifactInspection["readytorun_header"] =
    directory === null
      ? null
      : {
          file_offset: directory.offset,
          va: scope.offsetToVa(directory.offset),
          signature: "0x00525452",
          major_version: directory.major,
          minor_version: directory.minor,
          flags: directory.flags,
          section_count: directory.sectionCount,
          entry_size: directory.entrySize,
          entry_type: directory.entryType,
          entry_layout: directory.layout,
          format_hint: `ReadyToRun ${directory.major}.${directory.minor} ${directory.layout === "nativeaot-module" ? "NativeAOT module" : "CoreCLR"} entry layout (${directory.entrySize}-byte entries)`,
          sections: directory.entries.map((entry) => {
            const startVa = entry.start;
            const endVa = entry.end;
            const startFileOffset =
              startVa === null
                ? scope.layout.tryRvaToOffset(
                    entry.rva ?? 0,
                    1,
                    "nativeaot.rtr-section",
                  )
                : containsVa(scope.layout, startVa)
                  ? scope.vaToFileOffset(startVa, 1, "nativeaot.rtr-section")
                  : null;
            const endFileOffset =
              endVa === null
                ? null
                : containsVa(scope.layout, endVa)
                  ? scope.vaToFileOffset(endVa, 1, "nativeaot.rtr-section")
                  : null;
            return {
              type: entry.type,
              type_name: RTR_SECTION_TYPE_NAMES[entry.type] ?? null,
              flags: entry.flags,
              start_va:
                startVa === null || startVa === 0n ? null : hex(startVa),
              end_va: endVa === null || endVa === 0n ? null : hex(endVa),
              start_file_offset: startFileOffset,
              end_file_offset: endFileOffset,
            };
          }),
        };

  if (
    directory?.layout !== undefined &&
    directory.layout !== "nativeaot-module"
  )
    limitations.push(
      "The validated ReadyToRun directory uses the CoreCLR ReadyToRun entry layout (RVA/size sections); NativeAOT structural recovery does not apply to that directory plane, so no rows are recovered from it.",
    );
  if (
    directory?.layout === "nativeaot-module" &&
    directory.entries.some(
      (entry) => entry.type === RTR_SECTION_DEHYDRATED_DATA,
    )
  )
    limitations.push(
      "The ReadyToRun directory contains a DehydratedData section (type 207); hydrated runtime metadata is not recovered by this lane.",
    );
  if (
    directory?.layout === "nativeaot-module" &&
    directory.entries.some(
      (entry) => entry.type === RTR_SECTION_TYPE_MANAGER_INDIRECTION,
    )
  )
    limitations.push(
      "The ReadyToRun directory contains a TypeManagerIndirection section (type 204); the module header it points to is not parsed (version-divergent), so module-level metadata stays unknown.",
    );

  // Frozen-object-region coverage: a FrozenObjectRegion entry (206) that is
  // absent or not file-backed is an explicit unknown, not an empty result.
  if (directory?.layout === "nativeaot-module") {
    const frozenEntries = directory.entries.filter(
      (entry) => entry.type === RTR_SECTION_FROZEN_OBJECT_REGION,
    );
    if (frozenEntries.length === 0)
      limitations.push(
        "The ReadyToRun directory has no FrozenObjectRegion section (type 206); frozen-object recovery is limited to other initialized data bytes.",
      );
    else if (frozenEntries.length > 1)
      limitations.push(
        "The ReadyToRun directory declares more than one FrozenObjectRegion section; which region owns which object is unknown.",
      );
    else if (
      frozenEntries[0]?.start === null ||
      !containsVa(scope.layout, frozenEntries[0]?.start ?? 0n)
    )
      limitations.push(
        "The FrozenObjectRegion start range is not file-backed in the artifact, so frozen objects in that region are not recovered (bytes hydrated at runtime are unknown).",
      );
  }

  // Merge rows in one stable order: by primary file offset ascending.
  // Frozen-string rows follow the documented procedure: the object's
  // MethodTable reference must match a recovered MethodTable candidate, so
  // layout-only matches (e.g. directory bytes that happen to read like an
  // empty string) are dropped rather than reported.
  const frozenStringsRecovered = [...strings.values()].filter((match) =>
    methodTables.has(match.mtFileOffset),
  );
  const orderedRows: NativeAotInspectionRow[] = [
    ...[...methodTables.values()].map((candidate): NativeAotInspectionRow => ({
      kind: "method-table",
      index: 0,
      file_offset: candidate.fileOffset,
      end_file_offset: candidate.endFileOffset,
      va: candidate.va,
      flags: candidate.flags,
      element_type: candidate.elementType,
      base_size: candidate.baseSize,
      related_type:
        candidate.relatedVa === null ? null : hex(candidate.relatedVa),
      related_type_file_offset: candidate.relatedFileOffset,
      vtable_slot_count: candidate.vtableSlots,
      interface_count: candidate.interfaces,
    })),
    ...frozenStringsRecovered.map((match): NativeAotInspectionRow => ({
      kind: "frozen-string",
      index: 0,
      file_offset: match.fileOffset,
      va: match.va,
      char_length: match.charLength,
      value: match.value,
      data_file_offset: match.dataFileOffset,
    })),
  ]
    .sort((left, right) => left.file_offset - right.file_offset)
    .map((row, index) => ({ ...row, index }));
  const rowsOmitted = Math.max(0, orderedRows.length - MAX_ROWS);
  const boundedRows = orderedRows.slice(0, MAX_ROWS);

  const noIndicators =
    sentinel.validated.length === 0 &&
    sentinel.sentinelMatches === 0 &&
    !cliSignaturePresent &&
    exportMatch.status !== "present" &&
    managedSectionNames.length === 0;

  const truncated =
    exhausted(sentinelBudget) ||
    exhausted(pointerBudget) ||
    sentinel.examined < scannableBytes(layout) ||
    rowsOmitted > 0 ||
    ambiguous;

  const status: NativeAotArtifactInspection["status"] = truncated
    ? "partial"
    : "complete";

  if (noIndicators)
    limitations.push(
      "No ReadyToRun directory, DotNetRuntimeDebugHeader export, .managed section, or CLI ReadyToRun signature was found; absence of the documented indicators does not establish that the binary is not NativeAOT (indicators can be stripped).",
    );

  const report: NativeAotArtifactInspection = {
    artifact: {
      path: "",
      sha256,
      byte_length: bytes.length,
      format: "pe",
    },
    pe: {
      machine: layout.machine,
      machine_hex: `0x${layout.machine.toString(16).padStart(4, "0")}`,
      architecture: layout.architecture,
      image_base: hex(layout.imageBase),
      pointer_size: scope.pointerSize,
    },
    status,
    reason: truncated
      ? ambiguous
        ? `${sentinel.validated.length} structurally validated ReadyToRun directories were found; selection would be a guess.`
        : exhausted(sentinelBudget) || exhausted(pointerBudget)
          ? "The documented scan budgets were reached before the complete initialized non-executable extents were examined; omitted bytes are counted explicitly."
          : rowsOmitted > 0
            ? `${rowsOmitted} recovered rows beyond the row budget were omitted.`
            : null
      : null,
    detection,
    readytorun_header: readytorunHeader,
    rows: boundedRows,
    paging: {
      offset: 0,
      limit: Math.max(1, boundedRows.length),
      total_rows: boundedRows.length,
      returned_rows: boundedRows.length,
      complete: true,
    },
    coverage: {
      sentinel_scan_bytes_examined: sentinel.examined,
      sentinel_scan_bytes_omitted: sentinel.omitted,
      sentinel_candidates: sentinel.sentinelMatches,
      validated_readytorun_candidates: sentinel.validated.length,
      pointer_slots_examined: pointerScan.slots,
      pointer_scan_bytes_omitted: Math.max(
        0,
        scannableBytes(layout) - pointerScan.examined,
      ),
      method_tables_recovered: methodTables.size,
      frozen_strings_recovered: frozenStringsRecovered.length,
      rows_omitted: rowsOmitted,
      truncated:
        exhausted(sentinelBudget) ||
        exhausted(pointerBudget) ||
        rowsOmitted > 0 ||
        ambiguous,
    },
    limitations,
  };
  return nativeAotArtifactInspectionSchema.parse(report);
};
