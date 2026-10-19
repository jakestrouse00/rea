/**
 * Source-owned golden fixture builder for the NativeAOT/R2R structural lane
 * (docs/testing.md producer-golden rule): a hand-built minimal PE32 with a
 * `.managed` initialized-data section carrying
 *
 * - one structurally valid NativeAOT ReadyToRun directory (`RTR\0`, entry
 *   size 24, entry type 1) whose FrozenObjectRegion (206) and
 *   TypeManagerIndirection (204) rows map into the image,
 * - MethodTable-shaped structures following the documented
 *   `src/coreclr/nativeaot/Runtime/inc/MethodTable.h` field set, and
 * - frozen String objects following the documented ILCompiler
 *   `FrozenStringNode` layout (MethodTable reference, int32 length, UTF-16
 *   characters, NUL terminator).
 *
 * Layout is fully deterministic so tests can assert exact file offsets. The
 * bytes are built by this source file at test time; no binary fixture is
 * committed.
 */

const IMAGE_BASE = 0x0040_0000n;
const TEXT_RVA = 0x1000;
const TEXT_VSIZE = 0x1000;
const TEXT_RAW_OFFSET = 0x0200;
const TEXT_RAW_SIZE = 0x0200;
const MANAGED_RVA = 0x2000;
const MANAGED_VSIZE = 0x3000;
const MANAGED_RAW_OFFSET = 0x0400;
const MANAGED_RAW_SIZE = 0x3000;

const u16 = (value: number): Buffer => {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value, 0);
  return bytes;
};
const u32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value, 0);
  return bytes;
};

const vaForManagedOffset = (managedOffset: number): bigint =>
  IMAGE_BASE + BigInt(MANAGED_RVA + managedOffset);
const vaForTextOffset = (textOffset: number): bigint =>
  IMAGE_BASE + BigInt(TEXT_RVA + textOffset - TEXT_RAW_OFFSET);

export interface ManagedNativeAotFixture {
  readonly bytes: Buffer;
  readonly imageBase: bigint;
  /** File offset of the RTR header inside .managed. */
  readonly rtrHeaderOffset: number;
  readonly rtrHeaderVa: string;
  /** File offset of the DotNetRuntimeDebugHeader export name, when built. */
  readonly exportNameOffset: number | null;
  /** File offsets of frozen-string objects in the fixture order. */
  readonly frozenStringOffsets: readonly number[];
  /** File offsets of the recovered MethodTables in fixture order. */
  readonly methodTableOffsets: {
    readonly objectMt: number;
    readonly stringMt: number;
    readonly interfaceMt: number;
    readonly classMt: number;
  };
  /** Exact UTF-16 text of each fixture frozen string. */
  readonly frozenStrings: readonly string[];
}

interface FixtureOptions {
  /** Rename the data section from `.managed` to `.rdata`. */
  readonly plainDataSectionName?: boolean;
  /** Add a single valid export named DotNetRuntimeDebugHeader. */
  readonly debugHeaderExport?: boolean;
  /** Record a DehydratedData (207) row in the ReadyToRun directory. */
  readonly dehydratedSection?: boolean;
  /** Corrupt the directory's EntrySize so no candidate validates. */
  readonly corruptEntrySize?: boolean;
  /** Emit a second, structurally valid directory to force ambiguity. */
  readonly duplicateDirectory?: boolean;
  /** Strip the ReadyToRun directory entirely. */
  readonly noDirectory?: boolean;
  /** Emit a CoreCLR-layout (entry size 12) directory instead. */
  readonly coreclrLayout?: boolean;
}

const methodTableBytes = (
  flags: number,
  baseSize: number,
  related: bigint | null,
  vtableTargets: readonly bigint[],
  interfaceTargets: readonly bigint[],
  pointerSize: 4 | 8,
): Buffer => {
  const pointer = (value: bigint): Buffer => {
    if (pointerSize === 4) return u32(Number(value));
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64LE(value, 0);
    return bytes;
  };
  const count = Buffer.alloc(4);
  count.writeUInt16LE(vtableTargets.length, 0);
  count.writeUInt16LE(interfaceTargets.length, 2);
  return Buffer.concat([
    u32(flags),
    u32(baseSize),
    ...(related === null ? [pointer(0n)] : [pointer(related)]),
    count,
    ...vtableTargets.map(pointer),
    ...interfaceTargets.map(pointer),
  ]);
};

/** Build the deterministic golden NativeAOT fixture bytes. */
// oxlint-disable-next-line max-lines-per-function -- one golden builder keeps every documented PE section layout in one reviewable place.
export const buildManagedNativeAotPeFixture = (
  options: FixtureOptions = {},
): ManagedNativeAotFixture => {
  const pointerSize = 4;
  const managed = Buffer.alloc(MANAGED_RAW_SIZE);
  let cursor = 0x0100; // slack at the start of .managed stays zero

  // MethodTables (placed first so the frozen objects can reference them).
  const objectMtOffset = cursor;
  const objectMt = methodTableBytes(
    0x5000_0000, // class element type (0x14 << 26), documented Object shape
    0x0c, // 3 * pointerSize minimum object size for PE32
    null,
    [vaForTextOffset(0x0300), vaForTextOffset(0x0300), vaForTextOffset(0x0300)],
    [],
    pointerSize,
  );
  objectMt.copy(managed, cursor);
  cursor += objectMt.length;

  const stringMtOffset = cursor;
  const stringMt = methodTableBytes(
    0x5000_0000,
    0x0e, // unaligned composed String size: gc + mt + int32 + NUL (PE32)
    vaForManagedOffset(objectMtOffset),
    [vaForTextOffset(0x0300), vaForTextOffset(0x0300), vaForTextOffset(0x0300)],
    [],
    pointerSize,
  );
  stringMt.copy(managed, cursor);
  cursor += stringMt.length;

  const interfaceMtOffset = cursor;
  const interfaceMt = methodTableBytes(
    0x5000_0000,
    0x0c,
    vaForManagedOffset(objectMtOffset),
    [],
    [vaForManagedOffset(objectMtOffset)],
    pointerSize,
  );
  interfaceMt.copy(managed, cursor);
  cursor += interfaceMt.length;

  const classMtOffset = cursor;
  const classMt = methodTableBytes(
    0x5000_0000,
    0x10,
    vaForManagedOffset(objectMtOffset),
    [vaForTextOffset(0x0310)],
    [vaForManagedOffset(interfaceMtOffset)],
    pointerSize,
  );
  classMt.copy(managed, cursor);
  cursor += classMt.length;
  // A data pointer to the class MethodTable, exercising target discovery.
  u32(Number(vaForManagedOffset(classMtOffset))).copy(managed, cursor);
  cursor += 4;

  // Frozen strings: MethodTable reference, int32 length, UTF-16, NUL.
  const frozenStrings = ["Hello, NativeAOT!", "abc"];
  const frozenStringOffsets: number[] = [];
  for (const value of frozenStrings) {
    const aligned = (cursor + pointerSize - 1) & ~(pointerSize - 1);
    cursor = aligned;
    frozenStringOffsets.push(cursor);
    const text = Buffer.from(value, "utf16le");
    Buffer.concat([
      u32(Number(vaForManagedOffset(stringMtOffset))),
      u32(value.length),
      text,
      u16(0),
    ]).copy(managed, cursor);
    cursor += pointerSize + 4 + text.length + 2;
  }
  // Terminating null pointer, as ArrayOfFrozenObjectsNode documents.
  u32(0).copy(managed, cursor);
  cursor += 4;

  // ReadyToRun directory, 8-aligned.
  const coreclr = options.coreclrLayout === true;
  const entryCount = coreclr ? 1 : options.dehydratedSection === true ? 3 : 2;
  const rtrHeaderOffset = (cursor + 7) & ~7;
  cursor = rtrHeaderOffset;
  const sectionBytes = (
    type: number,
    flagBits: number,
    start: bigint,
    end: bigint,
  ): Buffer => {
    const bytes = Buffer.alloc(24);
    bytes.writeUInt32LE(type, 0);
    bytes.writeUInt32LE(flagBits, 4);
    bytes.writeBigUInt64LE(start, 8);
    bytes.writeBigUInt64LE(end, 16);
    return bytes;
  };
  const frozenStart = vaForManagedOffset(objectMtOffset);
  const frozenEnd = vaForManagedOffset(cursor);
  const typeManagerStart = vaForManagedOffset(objectMtOffset);
  // ReadyToRunHeader: uint32 signature; uint16 major/minor; uint32 flags;
  // uint16 NumberOfSections; uint8 EntrySize; uint8 EntryType — 16 bytes.
  const directoryHeader = Buffer.alloc(16);
  directoryHeader.writeUInt32LE(0x00525452, 0);
  directoryHeader.writeUInt16LE(9, 4);
  directoryHeader.writeUInt16LE(1, 6);
  directoryHeader.writeUInt32LE(0, 8);
  directoryHeader.writeUInt16LE(coreclr ? 1 : entryCount, 12);
  directoryHeader.writeUInt8(
    options.corruptEntrySize === true ? 20 : coreclr ? 12 : 24,
    14,
  );
  directoryHeader.writeUInt8(coreclr ? 0 : 1, 15);
  const directory = Buffer.concat([
    directoryHeader,
    ...(coreclr
      ? [
          // CoreCLR layout: {type, rva, size} — a CompilerIdentifier row with
          // an RVA inside .managed exercises the unsupported directory plane.
          Buffer.concat([u32(100), u32(MANAGED_RVA + 0x0100), u32(8)]),
        ]
      : [
          sectionBytes(206, 0, frozenStart, frozenEnd),
          sectionBytes(204, 0, typeManagerStart, typeManagerStart),
          ...(options.dehydratedSection === true
            ? [
                sectionBytes(
                  207,
                  0,
                  vaForManagedOffset(0x0100),
                  vaForManagedOffset(0x0104),
                ),
              ]
            : []),
        ]),
  ]);
  const wroteDirectory = options.noDirectory !== true;
  if (wroteDirectory) {
    directory.copy(managed, cursor);
    cursor += directory.length;
    if (options.duplicateDirectory === true) {
      const secondOffset = (cursor + 7) & ~7;
      directory.copy(managed, secondOffset);
      cursor = secondOffset + directory.length;
    }
  }

  const sectionName =
    options.plainDataSectionName === true ? ".rdata" : ".managed";

  const text = Buffer.alloc(TEXT_RAW_SIZE);
  text.writeUInt8(0xc3, 0x300 - TEXT_RAW_OFFSET);

  // Optional export directory naming DotNetRuntimeDebugHeader, laid out
  // directly after the ReadyToRun table inside .managed.
  let exportDirectory: Buffer | null = null;
  let exportDirectoryManagedOffset = 0;
  let exportDirectoryRva = 0;
  if (options.debugHeaderExport === true && wroteDirectory) {
    exportDirectoryManagedOffset = (cursor + 7) & ~7;
    exportDirectoryRva = MANAGED_RVA + exportDirectoryManagedOffset;
    const dllNameOffset = exportDirectoryManagedOffset + 40;
    const nameTableOffset = dllNameOffset + 16;
    const nameStringOffset = nameTableOffset + 4;
    const ordinalOffset = nameStringOffset + 25;
    const functionTableOffset = ordinalOffset + 2;
    exportDirectory = Buffer.concat([
      u32(0), // Characteristics
      u32(0), // TimeDateStamp
      u16(0), // MajorVersion
      u16(0), // MinorVersion
      u32(exportDirectoryRva + (dllNameOffset - exportDirectoryManagedOffset)), // Name RVA
      u32(1), // Base
      u32(1), // NumberOfFunctions
      u32(1), // NumberOfNames
      u32(
        exportDirectoryRva +
          (functionTableOffset - exportDirectoryManagedOffset),
      ),
      u32(
        exportDirectoryRva + (nameTableOffset - exportDirectoryManagedOffset),
      ),
      u32(exportDirectoryRva + (ordinalOffset - exportDirectoryManagedOffset)),
    ]);
    exportDirectory.copy(managed, exportDirectoryManagedOffset);
    Buffer.from("rea-fixture.dll\0", "ascii").copy(managed, dllNameOffset);
    u32(
      exportDirectoryRva + (nameStringOffset - exportDirectoryManagedOffset),
    ).copy(managed, nameTableOffset);
    Buffer.from("DotNetRuntimeDebugHeader\0", "ascii").copy(
      managed,
      nameStringOffset,
    );
    u16(0).copy(managed, ordinalOffset);
    u32(TEXT_RVA + 0x100).copy(managed, functionTableOffset);
    cursor = functionTableOffset + 4;
  }

  const totalRawSize = MANAGED_RAW_OFFSET + MANAGED_RAW_SIZE;
  const image = Buffer.concat([Buffer.alloc(totalRawSize)]);

  // DOS header.
  image.write("MZ", 0, "ascii");
  image.writeUInt32LE(0x80, 0x3c);
  // PE signature and COFF header.
  image.writeUInt32LE(0x0000_4550, 0x80);
  const coff = 0x84;
  image.writeUInt16LE(0x014c, coff); // i386
  image.writeUInt16LE(2, coff + 2); // two sections
  image.writeUInt16LE(0x00e0, coff + 16); // optional header size
  image.writeUInt16LE(0x0102, coff + 18); // executable, 32-bit
  const optional = coff + 20;
  image.writeUInt16LE(0x010b, optional); // PE32
  image.writeUInt32LE(0x0400, optional + 16); // size of headers
  image.writeUInt32LE(0x0040_0000, optional + 28); // image base
  image.writeUInt32LE(0x1000, optional + 32); // section alignment
  image.writeUInt32LE(0x0200, optional + 36); // file alignment
  image.writeUInt32LE(0x5000, optional + 56); // size of image
  image.writeUInt32LE(0x0400, optional + 60); // size of headers
  image.writeUInt32LE(16, optional + 92); // data directory count
  if (exportDirectory !== null) {
    image.writeUInt32LE(exportDirectoryRva, optional + 96);
    image.writeUInt32LE(exportDirectory.length, optional + 96 + 4);
  }
  const sectionTable = optional + 0x00e0;
  image.write(".text\0\0\0", sectionTable, "ascii");
  image.writeUInt32LE(TEXT_VSIZE, sectionTable + 8);
  image.writeUInt32LE(TEXT_RVA, sectionTable + 12);
  image.writeUInt32LE(TEXT_RAW_SIZE, sectionTable + 16);
  image.writeUInt32LE(TEXT_RAW_OFFSET, sectionTable + 20);
  image.writeUInt32LE(0x6000_0020, sectionTable + 36);
  image.write(sectionName.padEnd(8, "\0"), sectionTable + 40, "ascii");
  image.writeUInt32LE(MANAGED_VSIZE, sectionTable + 48);
  image.writeUInt32LE(MANAGED_RVA, sectionTable + 52);
  image.writeUInt32LE(MANAGED_RAW_SIZE, sectionTable + 56);
  image.writeUInt32LE(MANAGED_RAW_OFFSET, sectionTable + 60);
  image.writeUInt32LE(0x4000_0040, sectionTable + 76); // initialized data, read

  text.copy(image, TEXT_RAW_OFFSET);
  managed.copy(image, MANAGED_RAW_OFFSET);

  return {
    bytes: image,
    imageBase: IMAGE_BASE,
    rtrHeaderOffset: MANAGED_RAW_OFFSET + rtrHeaderOffset,
    rtrHeaderVa: `0x${(IMAGE_BASE + BigInt(MANAGED_RVA + rtrHeaderOffset)).toString(16)}`,
    exportNameOffset:
      options.debugHeaderExport === true && wroteDirectory
        ? MANAGED_RAW_OFFSET + exportDirectoryManagedOffset + 60
        : null,
    frozenStringOffsets: frozenStringOffsets.map(
      (offset) => MANAGED_RAW_OFFSET + offset,
    ),
    methodTableOffsets: {
      objectMt: MANAGED_RAW_OFFSET + objectMtOffset,
      stringMt: MANAGED_RAW_OFFSET + stringMtOffset,
      interfaceMt: MANAGED_RAW_OFFSET + interfaceMtOffset,
      classMt: MANAGED_RAW_OFFSET + classMtOffset,
    },
    frozenStrings,
  };
};
