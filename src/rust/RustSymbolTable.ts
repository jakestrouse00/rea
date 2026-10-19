import {
  GoBinaryFormatFailure,
  GoBinaryReader,
  type GoBinaryContainer,
} from "../go/GoBinaryContainer.js";
import { readElfFixedHeader } from "../domain/elfFixedHeader.js";

/** Highest symbol count admitted from one table; the rest is reported incomplete. */
export const RUST_SYMBOL_COUNT_LIMIT = 200_000;
/** C-string budget per symbol name beyond which the name is cut short. */
export const RUST_SYMBOL_NAME_BYTES = 4096;

/** One raw symbol-table row; demangling stays with the caller. */
export interface RawRustSymbol {
  readonly index: number;
  readonly name: string;
  readonly value: bigint;
  readonly size: number | null;
  readonly binding: "local" | "global" | "weak" | "unknown";
  readonly section_index: number | null;
}

/** Examined symbol table with its declared size and completeness fact. */
export interface RustSymbolTable {
  readonly table: "symtab" | "dynsym" | "lc_symtab";
  readonly declared_count: number;
  readonly complete: boolean;
  /** A second ELF table that was present but not read; null for Mach-O. */
  readonly other_table: "symtab" | "dynsym" | null;
  readonly symbols: readonly RawRustSymbol[];
}

/**
 * Read the symbol table of a container already admitted by the shared reader.
 * ELF requires a local section-header walk because the shared container keeps
 * neither symbol-table link indices nor raw string-table ranges; that local
 * walk mirrors GoElfImage.ts header decoding.
 */
export const readRustSymbolTable = (
  bytes: Buffer,
  container: GoBinaryContainer,
): RustSymbolTable | null => {
  if (container.format === "pe") return null;
  if (container.format === "macho")
    return readMachoSymbolTable(bytes, container);
  return readElfSymbolTable(bytes, container);
};

/** Map one symbol value to a file offset without treating ambiguity as fact. */
export const symbolFileOffset = (
  container: GoBinaryContainer,
  value: bigint,
): number | null => {
  if (value === 0n) return null;
  let found: number | undefined;
  let ambiguity = false;
  for (const mapping of container.mappings) {
    if (
      value < mapping.address ||
      value >= mapping.address + BigInt(mapping.size)
    )
      continue;
    const offset = mapping.offset + Number(value - mapping.address);
    if (found !== undefined && found !== offset) ambiguity = true;
    found = offset;
  }
  if (found === undefined || ambiguity) return null;
  for (const zeroFill of container.zero_fills) {
    if (value >= zeroFill.address && value < zeroFill.address + zeroFill.size)
      return null;
  }
  return found;
};

// ---------------------------------------------------------------------------
// ELF: symtab (preferred) or dynsym with its linked string table.
// ---------------------------------------------------------------------------

/** GoBinaryReader has no byte-width primitive; read through validated ranges. */
const u8At = (reader: GoBinaryReader, offset: number): number => {
  const range = reader.range(offset, 1, "8-bit field");
  return range[0] ?? 0;
};

const readElfSymbolTable = (
  bytes: Buffer,
  container: GoBinaryContainer,
): RustSymbolTable => {
  const fixed = readElfFixedHeader(bytes);
  if (!fixed.ok) throw new GoBinaryFormatFailure("malformed", fixed.error);
  const reader = new GoBinaryReader(bytes, fixed.value.byteOrder === "little");
  const wide = container.bits === 64;
  const bits = wide ? 64 : 32;
  const shOffset = reader.word(wide ? 40 : 32, bits);
  let shCount = reader.u16(wide ? 60 : 48);
  const shWidth = reader.u16(wide ? 58 : 46);
  if (shWidth < (wide ? 64 : 40))
    throw new GoBinaryFormatFailure(
      "malformed",
      "ELF section header width is invalid",
    );
  if (shOffset === 0n)
    throw new GoBinaryFormatFailure(
      "unsupported",
      "ELF image has no section header table",
    );
  if (shCount === 0) {
    if (shWidth < (wide ? 64 : 40))
      throw new GoBinaryFormatFailure(
        "malformed",
        "ELF extended section header width is invalid",
      );
    const zero = reader.fileRange(
      shOffset,
      BigInt(shWidth),
      "ELF section zero",
    ).offset;
    if (reader.u32(zero + 4) !== 0)
      throw new GoBinaryFormatFailure(
        "malformed",
        "ELF initial section for extended numbering must have SHT_NULL type",
      );
    const extended = reader.word(zero + (wide ? 32 : 20), bits);
    if (extended < 0xff00n || extended > BigInt(Number.MAX_SAFE_INTEGER))
      throw new GoBinaryFormatFailure(
        "malformed",
        "ELF extended section count is invalid",
      );
    shCount = Number(extended);
  }
  const shStart = reader.table(
    shOffset,
    shCount,
    shWidth,
    "ELF section headers",
  );
  const sections = Array.from({ length: shCount }, (_, index) =>
    elfSectionHeader(reader, shStart + index * shWidth, wide),
  );
  const symtab = sections.findIndex((section) => section.type === 2);
  const dynsym = sections.findIndex((section) => section.type === 11);
  const primary = symtab >= 0 ? symtab : dynsym;
  if (primary < 0)
    throw new GoBinaryFormatFailure(
      "unsupported",
      "ELF image declares neither a symtab nor a dynsym section",
    );
  const primaryType = symtab >= 0 ? 2 : 11;
  if (
    sections.some(
      (section, index) => index > primary && section.type === primaryType,
    )
  )
    throw new GoBinaryFormatFailure(
      "malformed",
      "ELF image declares more than one symbol table",
    );
  const header = sections[primary]!;
  const symbols = elfSymbolRange(reader, header, wide);
  const strings = elfStringTable(reader, sections, header.link);
  const count = Math.min(symbols.count, RUST_SYMBOL_COUNT_LIMIT);
  const rows: RawRustSymbol[] = [];
  for (let index = 0; index < count; index += 1) {
    const entry = symbols.offset + index * symbols.width;
    const nameOffset = reader.u32(entry);
    if (nameOffset === 0) continue;
    if (nameOffset >= strings.size)
      throw new GoBinaryFormatFailure(
        "malformed",
        "ELF symbol name offset is outside its string table",
      );
    const name = cString(
      bytes,
      strings.offset + nameOffset,
      strings.offset + strings.size,
    );
    if (name.length === 0) continue;
    const info = u8At(reader, entry + (wide ? 4 : 12));
    const shndx = reader.u16(entry + (wide ? 6 : 14));
    const bind = (info >> 4) & 7;
    rows.push({
      index,
      name,
      value: reader.word(entry + (wide ? 8 : 4), bits),
      size: safeSize(reader.word(entry + (wide ? 16 : 8), bits)),
      binding:
        bind === 0
          ? "local"
          : bind === 1
            ? "global"
            : bind === 2
              ? "weak"
              : "unknown",
      section_index: shndx === 0 ? null : shndx,
    });
  }
  return {
    table: symtab >= 0 ? "symtab" : "dynsym",
    declared_count: symbols.count,
    complete: symbols.count <= RUST_SYMBOL_COUNT_LIMIT,
    other_table: symtab >= 0 && dynsym >= 0 ? "dynsym" : null,
    symbols: rows,
  };
};

interface ElfSectionHeader {
  readonly type: number;
  readonly offset: bigint;
  readonly size: bigint;
  readonly link: number;
  readonly entsize: bigint;
}

const elfSectionHeader = (
  reader: GoBinaryReader,
  header: number,
  wide: boolean,
): ElfSectionHeader => {
  const bits = wide ? 64 : 32;
  return {
    type: reader.u32(header + 4),
    offset: reader.word(header + (wide ? 24 : 16), bits),
    size: reader.word(header + (wide ? 32 : 20), bits),
    link: reader.u32(header + (wide ? 40 : 24)),
    entsize: reader.word(header + (wide ? 56 : 36), bits),
  };
};

const elfSymbolRange = (
  reader: GoBinaryReader,
  section: ElfSectionHeader,
  wide: boolean,
): {
  readonly offset: number;
  readonly count: number;
  readonly width: number;
} => {
  const width =
    section.entsize === 0n ? (wide ? 24 : 16) : Number(section.entsize);
  if (width !== (wide ? 24 : 16))
    throw new GoBinaryFormatFailure(
      "malformed",
      "ELF symbol entry width is invalid",
    );
  if (section.size % BigInt(width) !== 0n)
    throw new GoBinaryFormatFailure(
      "malformed",
      "ELF symbol table size is not a multiple of its entry width",
    );
  if (
    section.offset > BigInt(Number.MAX_SAFE_INTEGER) ||
    section.size > BigInt(Number.MAX_SAFE_INTEGER) ||
    section.offset + section.size > BigInt(reader.bytes.length)
  )
    throw new GoBinaryFormatFailure(
      "malformed",
      "ELF symbol table range is outside the file",
    );
  const count = Number(section.size / BigInt(width));
  if (count === 0)
    throw new GoBinaryFormatFailure("malformed", "ELF symbol table is empty");
  return { offset: Number(section.offset), count, width };
};

const elfStringTable = (
  reader: GoBinaryReader,
  sections: readonly ElfSectionHeader[],
  link: number,
): { readonly offset: number; readonly size: number } => {
  const table = sections[link];
  if (table === undefined || table.type !== 3)
    throw new GoBinaryFormatFailure(
      "malformed",
      "ELF symbol table does not link to a string table",
    );
  if (
    table.offset > BigInt(Number.MAX_SAFE_INTEGER) ||
    table.size > BigInt(Number.MAX_SAFE_INTEGER) ||
    table.offset + table.size > BigInt(reader.bytes.length)
  )
    throw new GoBinaryFormatFailure(
      "malformed",
      "ELF string table range is outside the file",
    );
  return { offset: Number(table.offset), size: Number(table.size) };
};

const cString = (bytes: Buffer, start: number, end: number): string => {
  const limit = Math.min(start + RUST_SYMBOL_NAME_BYTES, end);
  const nul = bytes.subarray(start, limit).indexOf(0);
  if (nul < 0)
    throw new GoBinaryFormatFailure(
      "malformed",
      "Symbol name is not terminated inside its string table",
    );
  return bytes.toString("utf8", start, start + nul);
};

const safeSize = (value: bigint): number | null =>
  value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;

// ---------------------------------------------------------------------------
// Mach-O: LC_SYMTAB via a load-command walk; symbol values map through the
// container's file-backed segments.
// ---------------------------------------------------------------------------

const readMachoSymbolTable = (
  bytes: Buffer,
  container: GoBinaryContainer,
): RustSymbolTable => {
  const wide = container.bits === 64;
  const reader = new GoBinaryReader(bytes, container.byte_order === "little");
  const headerSize = wide ? 32 : 28;
  const headerStart = reader.range(0, headerSize, "Mach-O header");
  if (headerStart.length === 0)
    throw new GoBinaryFormatFailure("malformed", "Mach-O header is empty");
  const count = reader.u32(16);
  const commandBytes = reader.u32(20);
  const commandStart = reader.table(
    BigInt(headerSize),
    commandBytes,
    1,
    "Mach-O load commands",
  );
  const symtabCommands: number[] = [];
  const end = commandStart + commandBytes;
  let offset = commandStart;
  for (let index = 0; index < count; index += 1) {
    if (offset + 8 > end)
      throw new GoBinaryFormatFailure(
        "malformed",
        "Mach-O load command is truncated",
      );
    const command = reader.u32(offset);
    const size = reader.u32(offset + 4);
    if (size < 8 || size % 4 !== 0 || size > end - offset)
      throw new GoBinaryFormatFailure(
        "malformed",
        "Mach-O load command size is invalid or truncated",
      );
    if (command === 2) symtabCommands.push(offset);
    offset += size;
  }
  if (offset !== end)
    throw new GoBinaryFormatFailure(
      "malformed",
      "Mach-O load-command byte count does not match its commands",
    );
  if (symtabCommands.length === 0)
    throw new GoBinaryFormatFailure(
      "unsupported",
      "Mach-O image declares no LC_SYMTAB load command",
    );
  if (symtabCommands.length > 1)
    throw new GoBinaryFormatFailure(
      "malformed",
      "Mach-O image declares more than one LC_SYMTAB load command",
    );
  const command = symtabCommands[0]!;
  const symOffset = BigInt(reader.u32(command + 8));
  const declared = reader.u32(command + 12);
  const strOffset = BigInt(reader.u32(command + 16));
  const strSize = reader.u32(command + 20);
  const width = wide ? 16 : 12;
  const table = reader.fileRange(
    symOffset,
    BigInt(declared) * BigInt(width),
    "Mach-O symbol table",
  );
  const strings = reader.fileRange(
    strOffset,
    BigInt(strSize),
    "Mach-O symbol string table",
  );
  const limit = Math.min(declared, RUST_SYMBOL_COUNT_LIMIT);
  const rows: RawRustSymbol[] = [];
  for (let index = 0; index < limit; index += 1) {
    const entry = table.offset + index * width;
    const strx = reader.u32(entry);
    if (strx === 0) continue;
    if (strx >= strings.size)
      throw new GoBinaryFormatFailure(
        "malformed",
        "Mach-O symbol name offset is outside its string table",
      );
    const name = cString(
      bytes,
      strings.offset + strx,
      strings.offset + strings.size,
    );
    if (name.length === 0) continue;
    const nType = u8At(reader, entry + 4);
    const nSect = u8At(reader, entry + 5);
    const nDesc = reader.u16(entry + 6);
    rows.push({
      index,
      name,
      value: reader.word(entry + 8, wide ? 64 : 32),
      size: null,
      binding:
        (nType & 1) === 0
          ? "local"
          : (nDesc & 0x0040) !== 0 || (nDesc & 0x0080) !== 0
            ? "weak"
            : "global",
      section_index: nSect === 0 ? null : nSect,
    });
  }
  return {
    table: "lc_symtab",
    declared_count: declared,
    complete: declared <= RUST_SYMBOL_COUNT_LIMIT,
    other_table: null,
    symbols: rows,
  };
};
