export const BASE = 0x400000n;
export const TEXT_BASE = 0x401000n;
export const NFUNC = 3;
export const TABLE_OFFSET = 2048;

const TABLE_SPAN = 1024;
const MODULEDATA_OFFSET = 4096;
const NAMES = "go:buildid\0runtime.text\0main.main\0";
const PCLN_OFFSET = 0x60;
const FUNCNAME_OFFSET = 0x100;
const CU_OFFSET = 0x180;
const FILETAB_OFFSET = 0x1a0;
const PCTAB_OFFSET = 0x1b0;
const NAMEOFFS = [0, 11, 24];

export interface FixtureOptions {
  magic?: "go120" | "go118" | "go116" | "legacy";
  textStart?: bigint | null;
  withModuledata?: boolean;
  sectionless?: boolean;
  holeRow?: number;
  badNameoffRow?: number;
  unsorted?: boolean;
  noTable?: boolean;
  /** Declares the moduledata section larger than the 16 MiB decode budget. */
  oversizedModuledata?: boolean;
}

/** Author a minimal little-endian ELF64 image carrying a pclntab the parser owns. */
export const createPclntabFixture = (options: FixtureOptions = {}): Buffer => {
  const bytes = Buffer.alloc(
    options.oversizedModuledata ? 24 * 1024 * 1024 : 65536,
  );
  const u32 = (offset: number, value: number) =>
    bytes.writeUInt32LE(value, offset);
  const u64 = (offset: number, value: bigint) =>
    bytes.writeBigUInt64LE(value, offset);
  const i32 = (offset: number, value: number) =>
    bytes.writeInt32LE(value, offset);
  const sectionless = options.sectionless ?? false;
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  u32(16, 2);
  u32(18, 62);
  u32(20, 1);
  u64(32, 128n);
  u64(40, sectionless ? 0n : 512n);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(64, 58);
  bytes.writeUInt16LE(1, 56);
  bytes.writeUInt16LE(sectionless ? 0 : 4, 60);
  bytes.writeUInt16LE(sectionless ? 0 : 3, 62);
  u32(128, 1);
  u32(132, 4);
  u64(136, 0n);
  u64(144, BASE);
  u64(160, BigInt(bytes.length));
  u64(168, BigInt(bytes.length));
  if (!sectionless) {
    const shstrtab = Buffer.from("\0.gopclntab\0.noptrdata\0.shstrtab\0");
    shstrtab.copy(bytes, 768);
    const header = (index: number) => 512 + index * 64;
    bytes.writeUInt16LE(4, 60);
    bytes.writeUInt16LE(3, 62);
    u32(header(1) + 4, 1);
    u32(header(1) + 8, 2);
    u64(header(1) + 16, BASE + BigInt(TABLE_OFFSET));
    u64(header(1) + 24, BigInt(TABLE_OFFSET));
    u64(header(1) + 32, BigInt(TABLE_SPAN));
    u32(header(1), 1);
    u32(header(2) + 4, 1);
    u32(header(2) + 8, 3);
    u64(header(2) + 16, BASE + BigInt(MODULEDATA_OFFSET));
    u64(header(2) + 24, BigInt(MODULEDATA_OFFSET));
    u64(
      header(2) + 32,
      options.oversizedModuledata ? BigInt(17 * 1024 * 1024 + 8) : 512n,
    );
    u32(header(2), 12);
    // shstrtab entry, referenced by shstrndx and required to be a string table.
    u32(header(3) + 4, 3);
    u64(header(3) + 16, 768n);
    u64(header(3) + 24, 768n);
    u64(header(3) + 32, BigInt(shstrtab.length));
    u32(header(3), 23);
  }
  if (options.noTable) return bytes;
  const magic = options.magic ?? "go120";
  u32(
    TABLE_OFFSET,
    magic === "go120"
      ? 0xfffffff1
      : magic === "go118"
        ? 0xfffffff0
        : magic === "go116"
          ? 0xfffffffa
          : 0xfffffffb,
  );
  bytes[TABLE_OFFSET + 6] = 1;
  bytes[TABLE_OFFSET + 7] = 8;
  const relative = magic === "go120" || magic === "go118";
  const entryWidth = relative ? 8 : 16;
  const ftab = TABLE_OFFSET + PCLN_OFFSET;
  const funcRecords = ftab + (NFUNC + 1) * entryWidth;
  const funcWidth = relative ? 8 : 16;
  const tableBytes = (NFUNC + 1) * entryWidth;
  const entry = (index: number) => index * 3;
  if (magic === "legacy") {
    u64(TABLE_OFFSET + 8, BigInt(NFUNC));
    return bytes;
  }
  if (magic === "go116") {
    u64(TABLE_OFFSET + 8, BigInt(NFUNC));
    u64(TABLE_OFFSET + 16, 1n);
    u64(TABLE_OFFSET + 24, BigInt(FUNCNAME_OFFSET));
    u64(TABLE_OFFSET + 32, BigInt(CU_OFFSET));
    u64(TABLE_OFFSET + 40, BigInt(FILETAB_OFFSET));
    u64(TABLE_OFFSET + 48, BigInt(PCTAB_OFFSET));
    u64(TABLE_OFFSET + 56, BigInt(PCLN_OFFSET));
  } else {
    u64(TABLE_OFFSET + 8, BigInt(NFUNC));
    u64(TABLE_OFFSET + 16, 1n);
    u64(
      TABLE_OFFSET + 24,
      (options.textStart ?? TEXT_BASE) === 0n
        ? 0n
        : (options.textStart ?? TEXT_BASE),
    );
    u64(TABLE_OFFSET + 32, BigInt(FUNCNAME_OFFSET));
    u64(TABLE_OFFSET + 40, BigInt(CU_OFFSET));
    u64(TABLE_OFFSET + 48, BigInt(FILETAB_OFFSET));
    u64(TABLE_OFFSET + 56, BigInt(PCTAB_OFFSET));
    u64(TABLE_OFFSET + 64, BigInt(PCLN_OFFSET));
  }
  for (let index = 0; index <= NFUNC; index++) {
    const slot = ftab + index * entryWidth;
    const endoff = index === NFUNC ? 9 : entry(index);
    const funcoff =
      options.holeRow === index && relative
        ? 0xffffffff
        : BigInt(funcRecords - ftab + index * funcWidth);
    if (relative) {
      const stored = options.unsorted && index === 1 ? 100 : endoff;
      u32(slot, index === NFUNC ? 9 : stored);
      u32(slot + 4, Number(funcoff));
      if (options.holeRow !== index) {
        u32(funcRecords + index * funcWidth, entry(index));
        i32(
          funcRecords + index * funcWidth + 4,
          options.badNameoffRow === index ? 100000 : (NAMEOFFS[index] ?? 0),
        );
      }
    } else {
      u64(slot, TEXT_BASE + BigInt(endoff));
      u64(
        slot + 8,
        options.holeRow === index
          ? (1n << 64n) - 1n
          : BigInt(funcRecords - ftab + index * funcWidth),
      );
      u64(
        funcRecords + index * funcWidth,
        TEXT_BASE + BigInt(endoff === 9 ? 6 : endoff),
      );
      i32(
        funcRecords + index * funcWidth + 8,
        options.badNameoffRow === index ? 100000 : (NAMEOFFS[index] ?? 0),
      );
    }
  }
  Buffer.from(NAMES).copy(bytes, TABLE_OFFSET + FUNCNAME_OFFSET);
  if ((options.withModuledata ?? true) && sectionless === false)
    writeModuledata(bytes, u64, tableBytes);
  return bytes;
};

/** The moduledata record whose two member-tables point into this pclntab. */
const writeModuledata = (
  bytes: Buffer,
  u64: (offset: number, value: bigint) => void,
  tableBytes: number,
): void => {
  const md = MODULEDATA_OFFSET;
  const pcAddress = BASE + BigInt(TABLE_OFFSET);
  u64(md, pcAddress);
  u64(md + 8, pcAddress + BigInt(FUNCNAME_OFFSET));
  u64(md + 16, BigInt(NAMES.length));
  u64(md + 24, BigInt(NAMES.length));
  u64(md + 32, pcAddress + BigInt(CU_OFFSET));
  u64(md + 40, 16n);
  u64(md + 48, 16n);
  u64(md + 56, pcAddress + BigInt(FILETAB_OFFSET));
  u64(md + 64, 32n);
  u64(md + 72, 32n);
  u64(md + 80, pcAddress + BigInt(PCTAB_OFFSET));
  u64(md + 88, 32n);
  u64(md + 96, 32n);
  u64(md + 104, pcAddress + BigInt(PCLN_OFFSET));
  u64(md + 112, BigInt(tableBytes));
  u64(md + 120, BigInt(tableBytes));
  u64(md + 128, pcAddress + BigInt(PCLN_OFFSET));
  u64(md + 136, BigInt(NFUNC + 1));
  u64(md + 144, BigInt(NFUNC + 1));
  u64(md + 152, 0n);
  u64(md + 160, TEXT_BASE);
  u64(md + 168, TEXT_BASE + 9n);
  u64(md + 176, TEXT_BASE);
  u64(md + 184, TEXT_BASE + 9n);
};
