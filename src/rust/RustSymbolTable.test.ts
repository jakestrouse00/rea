import { expect, it } from "vitest";
import { BinaryFormatFailure } from "../native/metadata/BinaryContainer.js";
import { readBinaryContainer } from "../native/metadata/readBinaryContainer.js";
import {
  RUST_SYMBOL_COUNT_LIMIT,
  readRustSymbolTable,
  symbolFileOffset,
} from "./RustSymbolTable.js";

// ---------------------------------------------------------------------------
// Synthetic ELF64 builder. Sections: (0) NULL, (1) .text, (2) symtab,
// (3) strtab, (4) dynsym, (5) dynstr; the symtab can be omitted so dynsym
// becomes the primary table.
// ---------------------------------------------------------------------------

interface ElfSymbol {
  readonly nameOffset: number;
  readonly value: bigint;
  readonly size: bigint;
  readonly info: number;
  readonly shndx: number;
}

const elfStringTable = (names: readonly string[]): Buffer => {
  const table = Buffer.concat([
    Buffer.from([0]),
    ...names.map((name) =>
      Buffer.concat([Buffer.from(name, "utf8"), Buffer.from([0])]),
    ),
  ]);
  return table;
};

const nameOffsetIn = (table: Buffer, name: string): number =>
  name.length === 0 ? 0 : table.indexOf(Buffer.from(name, "utf8"));

const elf64Image = ({
  declaredSymtab,
  names,
  symtabEntries,
  includeSymtab = true,
  symtabLink,
}: {
  readonly declaredSymtab?: number;
  readonly names: readonly string[];
  readonly symtabEntries: readonly ElfSymbol[];
  readonly includeSymtab?: boolean;
  readonly symtabLink?: number;
}): Buffer => {
  const strs = elfStringTable(names);
  const symtabCount = declaredSymtab ?? symtabEntries.length;
  const dynCount = includeSymtab ? 0 : symtabEntries.length;
  const shnum = includeSymtab ? 6 : 4;
  const symOff = 64 + 56;
  const strOff = symOff + symtabCount * 24;
  const dynOff = strOff + strs.length;
  const shOff = dynOff + dynCount * 24;
  const total = shOff + shnum * 64;
  const bytes = Buffer.alloc(total);
  bytes.set(Buffer.from("7f454c46", "hex"), 0);
  bytes.set([2, 1, 1, 0, 0, 0, 0, 0, 0], 4);
  bytes.writeUInt16LE(2, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(1, 56);
  bytes.writeUInt16LE(64, 58);
  bytes.writeUInt16LE(shnum, 60);
  bytes.writeUInt16LE(3, 62);
  bytes.writeBigUInt64LE(0x400000n, 24);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeBigUInt64LE(BigInt(shOff), 40);
  bytes.writeBigUInt64LE(1n, 8);
  const program = Buffer.alloc(56);
  program.writeUInt32LE(1, 0);
  program.writeUInt32LE(5, 4);
  program.writeBigUInt64LE(0n, 8);
  program.writeBigUInt64LE(0x400000n, 16);
  program.writeBigUInt64LE(0x400000n, 24);
  program.writeBigUInt64LE(BigInt(total), 32);
  program.writeBigUInt64LE(BigInt(total), 40);
  program.writeBigUInt64LE(4096n, 48);
  program.copy(bytes, 64);
  const symbolAt = (target: Buffer, at: number, symbol: ElfSymbol): void => {
    target.writeUInt32LE(symbol.nameOffset, at);
    target.writeUInt8(symbol.info, at + 4);
    target.writeUInt8(0, at + 5);
    target.writeUInt16LE(symbol.shndx, at + 6);
    target.writeBigUInt64LE(symbol.value, at + 8);
    target.writeBigUInt64LE(symbol.size, at + 16);
  };
  symtabEntries.forEach((symbol, index) =>
    symbolAt(bytes, symOff + index * 24, symbol),
  );
  if (!includeSymtab)
    symtabEntries.forEach((symbol, index) =>
      symbolAt(bytes, dynOff + index * 24, symbol),
    );
  strs.copy(bytes, strOff);
  const writeSection = (
    index: number,
    type: number,
    offset: number,
    size: number,
    link: number,
    entsize = 0,
  ): void => {
    const at = shOff + index * 64;
    bytes.writeUInt32LE(0, at);
    bytes.writeUInt32LE(type, at + 4);
    bytes.writeBigUInt64LE(BigInt(entsize), at + 8);
    bytes.writeBigUInt64LE(0n, at + 16);
    bytes.writeBigUInt64LE(BigInt(offset), at + 24);
    bytes.writeBigUInt64LE(BigInt(size), at + 32);
    bytes.writeUInt32LE(link, at + 40);
    bytes.writeBigUInt64LE(BigInt(entsize), at + 56);
  };
  writeSection(0, 0, 0, 0, 0);
  writeSection(1, 1, 0, 0, 0);
  if (includeSymtab) {
    writeSection(2, 2, symOff, symtabCount * 24, symtabLink ?? 3, 24);
    writeSection(3, 3, strOff, strs.length, 0);
    writeSection(4, 11, dynOff, dynCount * 24, 5, 24);
    writeSection(5, 3, strOff, 0, 0);
  } else {
    writeSection(2, 11, dynOff, dynCount * 24, symtabLink ?? 3, 24);
    writeSection(3, 3, strOff, strs.length, 0);
  }
  return bytes;
};

const NAMES = [
  "",
  "main",
  "_ZN4core3ptr13drop_in_place17h1a2b3c4d5e6f7a8bE",
  "_ZN7example5STATEE",
];
const nameOffset = (name: string): number =>
  nameOffsetIn(elfStringTable(NAMES), name);

it("reads ELF symtab rows with bindings, sections, and mapped values", () => {
  const bytes = elf64Image({
    names: NAMES,
    symtabEntries: [
      { nameOffset: 0, value: 0n, size: 0n, info: 0, shndx: 0 },
      {
        nameOffset: nameOffset("main"),
        value: 0x400100n,
        size: 10n,
        info: 0x12,
        shndx: 2,
      },
      {
        nameOffset: nameOffset(
          "_ZN4core3ptr13drop_in_place17h1a2b3c4d5e6f7a8bE",
        ),
        value: 0x400110n,
        size: 20n,
        info: 0x00,
        shndx: 2,
      },
      {
        nameOffset: nameOffset("_ZN7example5STATEE"),
        value: 0n,
        size: 0n,
        info: 0x20,
        shndx: 0,
      },
    ],
  });
  const container = readBinaryContainer(bytes);
  expect(container.format).toBe("elf");
  const table = readRustSymbolTable(bytes, container);
  expect(table?.table).toBe("symtab");
  expect(table?.complete).toBe(true);
  expect(table?.other_table).toBe("dynsym");
  expect(table?.declared_count).toBe(4);
  expect(table?.symbols).toHaveLength(3);
  expect(table?.symbols[0]).toEqual({
    index: 1,
    name: "main",
    value: 0x400100n,
    size: 10,
    binding: "global",
    section_index: 2,
  });
  expect(table?.symbols[1]?.binding).toBe("local");
  expect(table?.symbols[2]).toMatchObject({
    binding: "weak",
    section_index: null,
  });
  expect(symbolFileOffset(container, 0x400100n)).toBe(0x100);
  expect(symbolFileOffset(container, 0n)).toBeNull();
});

it("falls back to dynsym and keeps the section linkage unknown-preserving", () => {
  const bytes = elf64Image({
    includeSymtab: false,
    names: NAMES,
    symtabEntries: [
      {
        nameOffset: nameOffset("main"),
        value: 0x401000n,
        size: 4n,
        info: 0x12,
        shndx: 2,
      },
    ],
  });
  const container = readBinaryContainer(bytes);
  const table = readRustSymbolTable(bytes, container);
  expect(table?.table).toBe("dynsym");
  expect(table?.other_table).toBeNull();
  expect(table?.symbols.map((symbol) => symbol.name)).toEqual(["main"]);
});

it("rejects a symbol table whose link is not a string table", () => {
  const bytes = elf64Image({
    names: NAMES,
    symtabLink: 1,
    symtabEntries: [
      {
        nameOffset: nameOffset("main"),
        value: 0x401000n,
        size: 4n,
        info: 0x12,
        shndx: 2,
      },
    ],
  });
  const container = readBinaryContainer(bytes);
  expect(() => readRustSymbolTable(bytes, container)).toThrow(
    BinaryFormatFailure,
  );
});

it("marks tables declared beyond the symbol count limit incomplete", () => {
  const bytes = elf64Image({
    names: NAMES,
    declaredSymtab: RUST_SYMBOL_COUNT_LIMIT + 1,
    symtabEntries: [],
  });
  const container = readBinaryContainer(bytes);
  const table = readRustSymbolTable(bytes, container);
  expect(table?.declared_count).toBe(RUST_SYMBOL_COUNT_LIMIT + 1);
  expect(table?.complete).toBe(false);
  expect(table?.symbols).toHaveLength(0);
});

// ---------------------------------------------------------------------------
// Synthetic Mach-O builders (64-bit and 32-bit) with one LC_SYMTAB.
// ---------------------------------------------------------------------------

interface Nlist {
  readonly nameOffset: number;
  readonly type: number;
  readonly sect: number;
  readonly desc: number;
  readonly value: bigint;
}

const machoImage = (
  wide: boolean,
  names: readonly string[],
  entries: readonly Nlist[],
  symtabCommands = 1,
): Buffer => {
  const headerSize = wide ? 32 : 28;
  const segmentSize = wide ? 72 : 56;
  const nlistWidth = wide ? 16 : 12;
  const strs = elfStringTable(names);
  const nsyms = entries.length;
  const commandBytes = segmentSize + 24 * symtabCommands;
  const symOff = headerSize + commandBytes;
  const strOff = symOff + nsyms * nlistWidth;
  const total = strOff + strs.length;
  const bytes = Buffer.alloc(total);
  bytes.writeUInt32LE(wide ? 0xfeedfacf : 0xfeedface, 0);
  bytes.writeUInt32LE(wide ? 0x01000007 : 7, 4);
  bytes.writeUInt32LE(0, 8);
  bytes.writeUInt32LE(2, 12);
  bytes.writeUInt32LE(1 + symtabCommands, 16);
  bytes.writeUInt32LE(commandBytes, 20);
  bytes.writeUInt32LE(0, 24);
  const segment = Buffer.alloc(segmentSize);
  segment.writeUInt32LE(wide ? 0x19 : 1, 0);
  segment.writeUInt32LE(segmentSize, 4);
  segment.write("__TEXT", 8, "latin1");
  if (wide) {
    segment.writeBigUInt64LE(0x100000000n, 24);
    segment.writeBigUInt64LE(BigInt(total), 32);
    segment.writeBigUInt64LE(0n, 40);
    segment.writeBigUInt64LE(BigInt(total), 48);
    segment.writeUInt32LE(5, 56);
    segment.writeUInt32LE(5, 60);
    segment.writeUInt32LE(0, 64);
    segment.writeUInt32LE(0, 68);
  } else {
    segment.writeUInt32LE(0x10000000, 24);
    segment.writeUInt32LE(total, 28);
    segment.writeUInt32LE(0, 32);
    segment.writeUInt32LE(total, 36);
    segment.writeUInt32LE(5, 40);
    segment.writeUInt32LE(5, 44);
    segment.writeUInt32LE(0, 48);
    segment.writeUInt32LE(0, 52);
  }
  segment.copy(bytes, headerSize);
  for (let symtabIndex = 0; symtabIndex < symtabCommands; symtabIndex += 1) {
    const symtab = Buffer.alloc(24);
    symtab.writeUInt32LE(2, 0);
    symtab.writeUInt32LE(24, 4);
    symtab.writeUInt32LE(symOff, 8);
    symtab.writeUInt32LE(nsyms, 12);
    symtab.writeUInt32LE(strOff, 16);
    symtab.writeUInt32LE(strs.length, 20);
    symtab.copy(bytes, headerSize + segmentSize + symtabIndex * 24);
  }
  entries.forEach((entry, index) => {
    const at = symOff + index * nlistWidth;
    bytes.writeUInt32LE(entry.nameOffset, at);
    bytes.writeUInt8(entry.type, at + 4);
    bytes.writeUInt8(entry.sect, at + 5);
    bytes.writeUInt16LE(entry.desc, at + 6);
    if (wide) bytes.writeBigUInt64LE(entry.value, at + 8);
    else bytes.writeUInt32LE(Number(entry.value), at + 8);
  });
  strs.copy(bytes, strOff);
  return bytes;
};

const MACHO_NAMES = [
  "",
  "_ZN3std2io5stdio6_print17h0c4e6d4e9a8b7c6dE",
  "_ZN7example5STATEE",
  "memcpy",
];
const machoNameOffset = (name: string): number =>
  nameOffsetIn(elfStringTable(MACHO_NAMES), name);

it("reads LC_SYMTAB nlists and maps symbol values through segments", () => {
  const bytes = machoImage(true, MACHO_NAMES, [
    {
      nameOffset: 0,
      type: 0x0e,
      sect: 1,
      desc: 0,
      value: 0x100000100n,
    },
    {
      nameOffset: machoNameOffset(
        "_ZN3std2io5stdio6_print17h0c4e6d4e9a8b7c6dE",
      ),
      type: 0x0f,
      sect: 1,
      desc: 0,
      value: 0x100000100n,
    },
    {
      nameOffset: machoNameOffset("_ZN7example5STATEE"),
      type: 0x0f,
      sect: 1,
      desc: 0x0080,
      value: 0n,
    },
    {
      nameOffset: machoNameOffset("memcpy"),
      type: 0x01,
      sect: 0,
      desc: 0,
      value: 0n,
    },
  ]);
  const container = readBinaryContainer(bytes);
  expect(container.format).toBe("macho");
  const table = readRustSymbolTable(bytes, container);
  expect(table?.table).toBe("lc_symtab");
  expect(table?.complete).toBe(true);
  expect(table?.other_table).toBeNull();
  expect(table?.symbols).toHaveLength(3);
  expect(table?.symbols[0]).toEqual({
    index: 1,
    name: "_ZN3std2io5stdio6_print17h0c4e6d4e9a8b7c6dE",
    value: 0x100000100n,
    size: null,
    binding: "global",
    section_index: 1,
  });
  expect(table?.symbols[1]?.binding).toBe("weak");
  expect(table?.symbols[2]).toMatchObject({
    binding: "global",
    section_index: null,
    value: 0n,
  });
  expect(table?.declared_count).toBe(4);
  expect(symbolFileOffset(container, 0x100000100n)).toBe(0x100);
  expect(symbolFileOffset(container, 0x200000000n)).toBeNull();
});

it("reads 32-bit Mach-O nlists", () => {
  const bytes = machoImage(false, MACHO_NAMES, [
    {
      nameOffset: machoNameOffset("_ZN7example5STATEE"),
      type: 0x0e,
      sect: 1,
      desc: 0,
      value: 0x10000080n,
    },
  ]);
  const container = readBinaryContainer(bytes);
  const table = readRustSymbolTable(bytes, container);
  expect(table?.table).toBe("lc_symtab");
  expect(table?.symbols[0]?.name).toBe("_ZN7example5STATEE");
  expect(table?.symbols[0]?.binding).toBe("local");
  expect(symbolFileOffset(container, 0x10000080n)).toBe(0x80);
});

it("rejects a second LC_SYMTAB command", () => {
  const bytes = machoImage(true, MACHO_NAMES, [], 2);
  const container = readBinaryContainer(bytes);
  expect(() => readRustSymbolTable(bytes, container)).toThrow(
    BinaryFormatFailure,
  );
});
