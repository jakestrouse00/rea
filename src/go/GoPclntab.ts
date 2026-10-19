import { readGoBinaryContainer } from "./GoBinaryImage.js";
import {
  GoBinaryFormatFailure,
  GoBinaryResourceFailure,
  GoBinaryReader,
  goUtf8,
  mappedFileOffset,
  type GoBinaryContainer,
} from "./GoBinaryContainer.js";

/** Runtime producer eras distinguished only by the pclntab magic word. */
export type GoPclntabEra =
  | "go1.2-1.15"
  | "go1.16-1.17"
  | "go1.18-1.19"
  | "go1.20+";

const MODERN_ERAS: Readonly<Record<number, GoPclntabEra>> = {
  0xfffffffa: "go1.16-1.17",
  0xfffffff0: "go1.18-1.19",
  0xfffffff1: "go1.20+",
};
const LEGACY_MAGIC = 0xfffffffb;

const FIXED_HEADER_BYTES = 8;
const MAX_TABLE_BYTES = 16 * 1024 * 1024;
const MAX_SEARCH_BYTES = 256 * 1024 * 1024;

/** Where a validated pclntab was found and its exact bounded file span. */
export interface GoPclntabLocation {
  readonly source: "section" | "search";
  readonly section_name: string | null;
  readonly file_offset: number;
  readonly address: bigint;
  readonly bytes: number;
}

/** Facts read from one validated moduledata, or the unestablished default. */
export interface GoModuledataFacts {
  readonly found: boolean;
  /**
   * True when the 16 MiB moduledata budget stopped the scan before covering
   * every candidate span, so `found: false` records not-searched rather than
   * proven absence.
   */
  readonly budget_limited: boolean;
  readonly file_offset: number | null;
  readonly nfunc_matches: boolean | null;
  readonly text: bigint | null;
}

/**
 * Header, bounds and text-base facts for one validated pclntab. Procedure
 * names are not decoded until the caller pages through the function table.
 */
export interface GoPclntabTable {
  readonly location: GoPclntabLocation;
  readonly magic: number;
  readonly era: GoPclntabEra;
  readonly min_lc: number;
  readonly ptr_size: number;
  readonly nfunc: number | null;
  readonly nfiles: number | null;
  readonly funcnametab: {
    readonly file_offset: number;
    readonly bytes: number;
  } | null;
  readonly functab: {
    readonly file_offset: number;
    readonly entry_width: number;
    readonly count: number;
  } | null;
  readonly text_start: bigint | null;
  readonly text_base: {
    readonly address: bigint;
    readonly source: "pclntab-header" | "moduledata" | "first-entry";
  } | null;
  readonly moduledata: GoModuledataFacts;
}

/** One decoded function-table row; unresolved values stay null instead of absent. */
export interface GoProcedureRow {
  readonly index: number;
  readonly name: string | null;
  readonly entry_offset: bigint | null;
  readonly end_offset: bigint | null;
  readonly entry: bigint | null;
  readonly end: bigint | null;
}

interface PclntabCandidate {
  readonly declared: boolean;
  readonly section_name: string | null;
  readonly file_offset: number;
  readonly address: bigint;
  readonly bytes: number;
}

/**
 * Locate and validate one pclntab alongside its native container, or report
 * absence without guessing causes. A declared gopclntab section is producer
 * evidence, so malformed contents there are a format failure while searched
 * spans simply fail validation. When several declared gopclntab sections
 * qualify, the first one wins and later sections are not compared.
 */
export const readGoPclntabImage = (
  bytes: Buffer,
): {
  readonly container: GoBinaryContainer;
  readonly pclntab: GoPclntabTable | null;
} => {
  const container = readGoBinaryContainer(bytes);
  const { declared, searched } = pclntabCandidates(container);
  for (const candidate of declared)
    return {
      container,
      pclntab: parsePclntab(bytes, container, candidate, true),
    };
  let remaining = MAX_SEARCH_BYTES;
  const seen = new Set<string>();
  for (const span of searched) {
    const identity = `${span.file_offset}:${span.bytes}:${span.address}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    if (span.bytes > remaining)
      throw new GoBinaryResourceFailure(
        "search",
        MAX_SEARCH_BYTES,
        "Go pclntab discovery exceeds the cumulative 256 MiB search budget",
      );
    remaining -= span.bytes;
    for (const hit of scanHeader(bytes, span)) {
      const table = parsePclntab(
        bytes,
        container,
        {
          declared: false,
          section_name: span.section_name,
          file_offset: hit,
          address: span.address + BigInt(hit - span.file_offset),
          bytes: span.file_offset + span.bytes - hit,
        },
        false,
      );
      if (table !== null) return { container, pclntab: table };
    }
  }
  return { container, pclntab: null };
};

// Both endiannesses: little stores the distinguishing byte first; big stores
// three 0xff bytes before it. Pad bytes follow the 4-byte magic in both.
const HEADER_NEEDLES = [0xfb, 0xfa, 0xf0, 0xf1].flatMap((low) => [
  Buffer.from([low, 0xff, 0xff, 0xff, 0x00, 0x00]),
  Buffer.from([0xff, 0xff, 0xff, low, 0x00, 0x00]),
]);

/** Yield file offsets whose first bytes could begin a valid pclntab header. */
const scanHeader = (bytes: Buffer, span: PclntabCandidate): number[] => {
  const end = span.file_offset + span.bytes;
  const hits: number[] = [];
  for (const needle of HEADER_NEEDLES) {
    let offset = span.file_offset;
    while (offset < end) {
      const found = bytes.indexOf(needle, offset);
      if (found < 0 || found >= end) break;
      const minLc = bytes[found + 6];
      const ptrSize = bytes[found + 7];
      if (
        (minLc === 1 || minLc === 2 || minLc === 4) &&
        (ptrSize === 4 || ptrSize === 8)
      )
        hits.push(found);
      offset = found + 1;
    }
  }
  return hits.sort((first, second) => first - second);
};

/** Locate and validate one pclntab, or report absence without guessing causes. */
export const readGoPclntab = (bytes: Buffer): GoPclntabTable | null =>
  readGoPclntabImage(bytes).pclntab;

/** Decode one bounded page of function-table rows against a validated table. */
export const readGoPclntabProcedures = (
  bytes: Buffer,
  table: GoPclntabTable,
  offset: number,
  limit: number,
): readonly GoProcedureRow[] => {
  const functab = table.functab;
  if (functab === null || table.nfunc === null || table.funcnametab === null)
    return [];
  const rows: GoProcedureRow[] = [];
  const first = Math.min(Math.max(offset, 0), table.nfunc);
  const last = Math.min(first + limit, table.nfunc);
  for (let index = first; index < last; index++)
    rows.push(procedureRow(bytes, table, index));
  return rows;
};

/** Producer-shaped candidate spans, declared gopclntab sections first. */
const pclntabCandidates = (
  container: GoBinaryContainer,
): {
  readonly declared: readonly PclntabCandidate[];
  readonly searched: readonly PclntabCandidate[];
} => {
  if (container.sections.length === 0)
    return {
      declared: [],
      searched: container.mappings
        .filter((mapping) => mapping.size !== 0)
        .map((mapping) => ({
          declared: false,
          section_name: null,
          file_offset: mapping.offset,
          address: mapping.address,
          bytes: mapping.size,
        })),
    };
  const declared: PclntabCandidate[] = [];
  const searched: PclntabCandidate[] = [];
  for (const section of container.sections) {
    if (!section.file_backed || section.compressed || section.size === 0)
      continue;
    let fileOffset: number | null = null;
    try {
      fileOffset = mappedFileOffset(
        container.mappings,
        section.address,
        section.size,
        container.zero_fills,
      );
    } catch {
      fileOffset = null;
    }
    // A section with an unusable declared mapping still contributes its raw
    // declared bytes to the search pool; unmapped spans cannot hide a table.
    const candidate: PclntabCandidate = {
      declared: section.name.includes("gopclntab"),
      section_name: section.name,
      file_offset: fileOffset ?? section.offset,
      address: section.address,
      bytes: section.size,
    };
    if (candidate.declared) declared.push(candidate);
    else if (fileOffset !== null) {
      if (isPclntabDataSection(section.name) || section.read_only)
        searched.push(candidate);
    }
  }
  return { declared, searched };
};

const isPclntabDataSection = (name: string): boolean =>
  name.includes("noptrdata") ||
  name.includes("rdata") ||
  name.includes("rodata") ||
  name.includes("__DATA,__data") ||
  name.includes(".data");

const isModuledataSection = (name: string): boolean =>
  name.includes("noptrdata") ||
  name.includes("go_module") ||
  name.includes("__DATA,__data") ||
  name.includes(".data");

const parsePclntab = (
  bytes: Buffer,
  container: GoBinaryContainer,
  candidate: PclntabCandidate,
  declared: boolean,
): GoPclntabTable | null => {
  const reader = new GoBinaryReader(bytes, container.byte_order === "little");
  const reject = (reason: string) => {
    if (!declared) return null;
    throw new GoBinaryFormatFailure("malformed", reason);
  };
  if (candidate.bytes < FIXED_HEADER_BYTES)
    return reject("Go pclntab header is truncated");
  let magic: number;
  try {
    magic = reader.u32(candidate.file_offset);
  } catch (cause: unknown) {
    if (cause instanceof GoBinaryFormatFailure) return reject(cause.message);
    throw cause;
  }
  if (magic === LEGACY_MAGIC) {
    const pad1 = bytes[candidate.file_offset + 4] ?? 0xff;
    const pad2 = bytes[candidate.file_offset + 5] ?? 0xff;
    const minLc = bytes[candidate.file_offset + 6] ?? 0xff;
    const ptrSize = bytes[candidate.file_offset + 7] ?? 0xff;
    if (pad1 !== 0 || pad2 !== 0)
      return reject("Go pclntab header padding bytes are not zero");
    if (![1, 2, 4].includes(minLc))
      return reject("Go pclntab minLC is not 1, 2 or 4");
    if (ptrSize !== 4 && ptrSize !== 8)
      return reject("Go pclntab pointer size is not 4 or 8");
    if (ptrSize !== container.bits / 8)
      return reject("Go pclntab pointer size disagrees with the image");
    const nfunc = reader.word(
      candidate.file_offset + FIXED_HEADER_BYTES,
      ptrSize === 8 ? 64 : 32,
    );
    return {
      location: locationOf(candidate),
      magic,
      era: "go1.2-1.15",
      min_lc: minLc,
      ptr_size: ptrSize,
      nfunc: nfunc <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(nfunc) : null,
      nfiles: null,
      funcnametab: null,
      functab: null,
      text_start: null,
      text_base: null,
      moduledata: {
        found: false,
        budget_limited: false,
        file_offset: null,
        nfunc_matches: null,
        text: null,
      },
    };
  }
  const era = MODERN_ERAS[magic];
  if (era === undefined)
    return reject(`Unrecognized Go pclntab magic 0x${magic.toString(16)}`);
  const pad1 = bytes[candidate.file_offset + 4] ?? 0xff;
  const pad2 = bytes[candidate.file_offset + 5] ?? 0xff;
  const minLc = bytes[candidate.file_offset + 6] ?? 0xff;
  const ptrSize = bytes[candidate.file_offset + 7] ?? 0xff;
  if (pad1 !== 0 || pad2 !== 0)
    return reject("Go pclntab header padding bytes are not zero");
  if (![1, 2, 4].includes(minLc))
    return reject("Go pclntab minLC is not 1, 2 or 4");
  if (ptrSize !== 4 && ptrSize !== 8)
    return reject("Go pclntab pointer size is not 4 or 8");
  if (ptrSize !== container.bits / 8)
    return reject("Go pclntab pointer size disagrees with the image");
  const layout = era !== "go1.16-1.17";
  const base = FIXED_HEADER_BYTES;
  const width = ptrSize === 8 ? 64 : 32;
  const fieldAt = (index: number): bigint =>
    reader.word(candidate.file_offset + base + index * ptrSize, width);
  const textStart = layout ? fieldAt(2) : null;
  const funcnameOffset = fieldAt(layout ? 3 : 2);
  const cuOffset = fieldAt(layout ? 4 : 3);
  const filetabOffset = fieldAt(layout ? 5 : 4);
  const pctabOffset = fieldAt(layout ? 6 : 5);
  const pclnOffset = fieldAt(layout ? 7 : 6);
  const headerEnd = base + (layout ? 8 : 7) * ptrSize;
  const spanEnd = BigInt(candidate.bytes);
  if (
    [funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset].some(
      (offset) => offset < BigInt(headerEnd) || offset > spanEnd,
    )
  )
    return reject("Go pclntab sub-table offsets leave the pclntab span");
  if (funcnameOffset < BigInt(headerEnd))
    return reject("Go pclntab funcnametab overlaps the header");
  const nfunc = fieldAt(0);
  if (nfunc > BigInt(Number.MAX_SAFE_INTEGER))
    return reject("Go pclntab function count exceeds safe decoding range");
  const nf = Number(nfunc);
  const nfiles = fieldAt(1);
  const nfFiles =
    nfiles <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(nfiles) : null;
  if (nfFiles !== null && BigInt(nfFiles) * 4n > BigInt(MAX_TABLE_BYTES))
    return reject("Go pclntab file table count exceeds the decoding budget");
  const entryWidth = layout ? 8 : 2 * ptrSize;
  const ftabBytes = (BigInt(nf) + 1n) * BigInt(entryWidth);
  if (ftabBytes > BigInt(MAX_TABLE_BYTES))
    throw new GoBinaryResourceFailure(
      "pclntab",
      MAX_TABLE_BYTES,
      "Go pclntab function table exceeds the 16 MiB structural decoding budget",
    );
  if (pclnOffset + ftabBytes > spanEnd)
    return reject("Go pclntab function table leaves the pclntab span");
  const ftabFileOffset = candidate.file_offset + Number(pclnOffset);
  if (!functabIsSorted(reader, ftabFileOffset, nf, entryWidth, layout, ptrSize))
    return reject("Go pclntab function table entries are not sorted by entry");
  const funcnameEnd = nextOffsetAfter(
    funcnameOffset,
    [cuOffset, filetabOffset, pctabOffset, pclnOffset],
    spanEnd,
  );
  let textBase: GoPclntabTable["text_base"] = null;
  let moduledata: GoModuledataFacts = {
    found: false,
    budget_limited: false,
    file_offset: null,
    nfunc_matches: null,
    text: null,
  };
  if (textStart !== null && textStart !== 0n) {
    try {
      mappedFileOffset(container.mappings, textStart, 1, container.zero_fills);
    } catch {
      return reject("Go pclntab textStart is not mapped in the native image");
    }
    textBase = { address: textStart, source: "pclntab-header" };
  } else {
    // go1.26+ producers zero textStart and carry the real text base in the
    // moduledata, which also cross-checks nfunc for every era's slices.
    moduledata = findModuledata(bytes, container, reader, {
      address: candidate.address,
      file_offset: candidate.file_offset,
      bytes: candidate.bytes,
      funcnameOffset,
      cuOffset,
      filetabOffset,
      pctabOffset,
      pclnOffset,
      nfunc: nf,
      ptrSize,
    });
    if (moduledata.text !== null)
      textBase = { address: moduledata.text, source: "moduledata" };
    else if (!layout)
      textBase = {
        address: reader.word(ftabFileOffset, ptrSize === 8 ? 64 : 32),
        source: "first-entry",
      };
  }
  return {
    location: locationOf(candidate),
    magic,
    era,
    min_lc: minLc,
    ptr_size: ptrSize,
    nfunc: nf,
    nfiles: nfFiles,
    funcnametab: {
      file_offset: candidate.file_offset + Number(funcnameOffset),
      bytes: Number(funcnameEnd - funcnameOffset),
    },
    functab: {
      file_offset: ftabFileOffset,
      entry_width: entryWidth,
      count: nf + 1,
    },
    text_start: textStart,
    text_base: textBase,
    moduledata,
  };
};

const locationOf = (candidate: PclntabCandidate): GoPclntabLocation => ({
  source: candidate.declared ? "section" : "search",
  section_name: candidate.section_name,
  file_offset: candidate.file_offset,
  address: candidate.address,
  bytes: candidate.bytes,
});

/** Bound one sub-table by the next declared sub-table or the span end. */
const nextOffsetAfter = (
  offset: bigint,
  later: readonly bigint[],
  max: bigint,
): bigint => {
  let bound = max;
  for (const candidate of later)
    if (candidate > offset && candidate < bound) bound = candidate;
  return bound;
};

const functabIsSorted = (
  reader: GoBinaryReader,
  ftabFileOffset: number,
  nfunc: number,
  entryWidth: number,
  relative: boolean,
  ptrSize: 4 | 8,
): boolean => {
  const entryAt = (index: number): bigint => {
    const slot = ftabFileOffset + index * entryWidth;
    return relative
      ? BigInt(reader.u32(slot))
      : reader.word(slot, ptrSize === 8 ? 64 : 32);
  };
  let previous = entryAt(0);
  for (let index = 1; index <= nfunc; index++) {
    const current = entryAt(index);
    if (current < previous) return false;
    previous = current;
  }
  return true;
};

interface ModuledataProbe {
  readonly address: bigint;
  readonly file_offset: number;
  readonly bytes: number;
  readonly funcnameOffset: bigint;
  readonly cuOffset: bigint;
  readonly filetabOffset: bigint;
  readonly pctabOffset: bigint;
  readonly pclnOffset: bigint;
  readonly nfunc: number;
  readonly ptrSize: 4 | 8;
}

/**
 * Find the moduledata whose slices point at this pclntab. Its text field is
 * the producer's ground-truth base, and the slice agreement filters stray
 * pointer false positives.
 */
const findModuledata = (
  bytes: Buffer,
  container: GoBinaryContainer,
  reader: GoBinaryReader,
  probe: ModuledataProbe,
): GoModuledataFacts => {
  let remaining = MAX_TABLE_BYTES;
  let budgetLimited = false;
  for (const span of moduledataSpans(container)) {
    if (span.bytes > remaining) {
      budgetLimited = true;
      continue;
    }
    remaining -= span.bytes;
    const facts = scanModuledata(bytes, span, reader, probe);
    if (facts !== null) return facts;
  }
  return {
    found: false,
    budget_limited: budgetLimited,
    file_offset: null,
    nfunc_matches: null,
    text: null,
  };
};

const moduledataSpans = (
  container: GoBinaryContainer,
): readonly PclntabCandidate[] => {
  if (container.sections.length === 0)
    return container.mappings
      .filter((mapping) => mapping.size !== 0)
      .map((mapping) => ({
        declared: false,
        section_name: null,
        file_offset: mapping.offset,
        address: mapping.address,
        bytes: mapping.size,
      }));
  const spans: PclntabCandidate[] = [];
  for (const section of container.sections) {
    if (!section.file_backed || section.compressed || section.size === 0)
      continue;
    if (!isModuledataSection(section.name)) continue;
    spans.push({
      declared: false,
      section_name: section.name,
      file_offset: section.offset,
      address: section.address,
      bytes: section.size,
    });
  }
  return spans;
};

const scanModuledata = (
  bytes: Buffer,
  span: PclntabCandidate,
  reader: GoBinaryReader,
  probe: ModuledataProbe,
): GoModuledataFacts | null => {
  const width = probe.ptrSize;
  let offset = span.file_offset;
  const end = span.file_offset + span.bytes;
  while (offset + width * MODULEDATA_WORDS <= end) {
    if (reader.word(offset, width === 8 ? 64 : 32) === probe.address) {
      const facts = moduledataAt(offset, reader, probe);
      if (facts !== null) return facts;
    }
    offset += width;
  }
  return null;
};

const MODULEDATA_WORDS = 24;

const moduledataAt = (
  fileOffset: number,
  reader: GoBinaryReader,
  probe: ModuledataProbe,
): GoModuledataFacts | null => {
  const width = probe.ptrSize === 8 ? 64 : 32;
  const word = (index: number): bigint =>
    reader.word(fileOffset + index * probe.ptrSize, width);
  const equalsExpected = (index: number, expected: bigint): boolean =>
    word(index) === probe.address + expected;
  // Slice layout: {ptr, len, cap} per table, ftab sharing the pclntable span.
  if (
    !equalsExpected(1, probe.funcnameOffset) ||
    !equalsExpected(4, probe.cuOffset) ||
    !equalsExpected(7, probe.filetabOffset) ||
    !equalsExpected(10, probe.pctabOffset) ||
    !equalsExpected(13, probe.pclnOffset) ||
    word(16) !== word(13) ||
    word(17) !== word(18)
  )
    return null;
  return {
    found: true,
    budget_limited: false,
    file_offset: fileOffset,
    nfunc_matches: Number(word(17)) === probe.nfunc + 1,
    text: word(22),
  };
};

const procedureRow = (
  bytes: Buffer,
  table: GoPclntabTable,
  index: number,
): GoProcedureRow => {
  const functab = table.functab;
  const funcnametab = table.funcnametab;
  if (functab === null || funcnametab === null || table.nfunc === null)
    throw new GoBinaryFormatFailure(
      "malformed",
      "Go procedure rows require a decoded modern pclntab",
    );
  const reader = new GoBinaryReader(bytes, table.magic !== 0xfffffffb);
  const spanEnd = table.location.file_offset + table.location.bytes;
  const relative = table.era !== "go1.16-1.17";
  const slot = functab.file_offset + index * functab.entry_width;
  const base = table.text_base?.address ?? null;
  if (relative) {
    const entryOffset = BigInt(reader.u32(slot));
    const funcoff = reader.u32(slot + 4);
    const next = BigInt(
      reader.u32(functab.file_offset + (index + 1) * functab.entry_width),
    );
    return {
      index,
      name: resolvedName(
        bytes,
        reader,
        BigInt(functab.file_offset + funcoff) + 4n,
        spanEnd,
        funcnametab,
      ),
      entry_offset: entryOffset,
      end_offset: next,
      entry: base === null ? null : base + entryOffset,
      end: base === null ? null : base + next,
    };
  }
  const width = table.ptr_size === 8 ? 64 : 32;
  const entry = reader.word(slot, width);
  const funcoff = reader.word(slot + table.ptr_size, width);
  const next = reader.word(
    functab.file_offset + (index + 1) * functab.entry_width,
    width,
  );
  const allOnes = (1n << BigInt(table.ptr_size * 8)) - 1n;
  return {
    index,
    name:
      funcoff === allOnes
        ? null
        : resolvedName(
            bytes,
            reader,
            BigInt(functab.file_offset) + funcoff + BigInt(table.ptr_size),
            spanEnd,
            funcnametab,
          ),
    entry_offset: base === null ? null : entry - base,
    end_offset: base === null ? null : next - base,
    entry,
    end: next,
  };
};

/** Read the name offset at the producer's _func record and resolve its text. */
const resolvedName = (
  bytes: Buffer,
  reader: GoBinaryReader,
  nameoffSlot: bigint,
  spanEnd: number,
  funcnametab: { readonly file_offset: number; readonly bytes: number },
): string | null => {
  if (
    nameoffSlot < 0n ||
    nameoffSlot > BigInt(Number.MAX_SAFE_INTEGER) ||
    nameoffSlot + 4n > BigInt(spanEnd)
  )
    return null;
  const nameoff = int32At(reader, Number(nameoffSlot));
  if (nameoff < 0 || nameoff >= funcnametab.bytes) return null;
  return nameAt(bytes, funcnametab, nameoff);
};

const int32At = (reader: GoBinaryReader, offset: number): number => {
  const value = reader.range(offset, 4, "Go function name offset");
  return reader.little ? value.readInt32LE() : value.readInt32BE();
};

const nameAt = (
  bytes: Buffer,
  funcnametab: { readonly file_offset: number; readonly bytes: number },
  nameoff: number,
): string | null => {
  const start = funcnametab.file_offset + nameoff;
  const end = bytes.indexOf(0, start);
  if (end < 0 || end - start > funcnametab.bytes - nameoff) return null;
  try {
    return goUtf8(bytes.subarray(start, end), "Go function name");
  } catch (cause: unknown) {
    if (cause instanceof GoBinaryFormatFailure) return null;
    throw cause;
  }
};
