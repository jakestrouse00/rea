import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";

/** Deterministic byte builders for the committed game-data parser fixtures. */

export const md5Hex = (bytes: Buffer): string =>
  createHash("md5").update(bytes).digest("hex");

interface GodotEntryFixture {
  readonly path: string;
  readonly body?: Buffer;
  readonly encrypted?: boolean;
  /** Absolute offset of the body within the pack, when preplaced. */
  readonly storedOffset?: number;
}

class Cursor {
  readonly chunks: Buffer[] = [];
  u8(value: number): this {
    this.chunks.push(Buffer.from([value & 0xff]));
    return this;
  }
  u16(value: number): this {
    const bytes = Buffer.alloc(2);
    bytes.writeUInt16LE(value & 0xffff);
    this.chunks.push(bytes);
    return this;
  }
  u32(value: number): this {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(value >>> 0);
    this.chunks.push(bytes);
    return this;
  }
  u64(value: number): this {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64LE(BigInt(Math.min(value, Number.MAX_SAFE_INTEGER)));
    this.chunks.push(bytes);
    return this;
  }
  bytes(value: Buffer): this {
    this.chunks.push(value);
    return this;
  }
  text(value: string): this {
    const encoded = Buffer.from(value, "utf8");
    this.u32(encoded.length);
    return this.bytes(encoded);
  }
  raw(value: string): this {
    this.chunks.push(Buffer.from(value, "latin1"));
    return this;
  }
  cstring(value: string): this {
    return this.bytes(
      Buffer.concat([Buffer.from(value, "utf8"), Buffer.from([0])]),
    );
  }
  buffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

export interface GodotPckOptions {
  readonly formatVersion: 1 | 2;
  readonly engine: {
    readonly major: number;
    readonly minor: number;
    readonly patch: number;
  };
  readonly packFlags?: number;
  readonly fileBase?: number;
}

/**
 * v1/v2 fixture layout: GDPC header, then the plain directory index, then the
 * entry bodies (when bodies are supplied).
 */
export const buildGodotPck = (
  options: GodotPckOptions,
  entries: readonly GodotEntryFixture[],
): Buffer => {
  const header = new Cursor();
  header.bytes(Buffer.from("GDPC", "latin1"));
  header.u32(options.formatVersion);
  header.u32(options.engine.major);
  header.u32(options.engine.minor);
  header.u32(options.engine.patch);
  if (options.formatVersion === 2) {
    header.u32(options.packFlags ?? 0);
    header.u64(options.fileBase ?? 0);
    header.bytes(Buffer.alloc(64));
  }
  header.u32(entries.length);
  const headerBytes = header.buffer().length;
  const recordBytesOf = (entry: GodotEntryFixture): number => {
    const pathBytes = Buffer.byteLength(entry.path, "utf8");
    return 4 + pathBytes + 8 + 8 + 16 + (options.formatVersion === 2 ? 4 : 0);
  };
  // Bodies start behind the whole index; offsets are assigned in layout order.
  const recordsStart =
    headerBytes +
    entries.reduce((total, entry) => total + recordBytesOf(entry), 0);
  const records: Buffer[] = [];
  const placements: { readonly storedOffset: number; readonly body: Buffer }[] =
    [];
  let position = recordsStart;
  for (const entry of entries) {
    const body = entry.body ?? Buffer.alloc(0);
    const storedOffset = entry.storedOffset ?? position;
    if (entry.body !== undefined) {
      placements.push({ storedOffset, body });
      position += body.length;
    }
    const record = new Cursor();
    record.text(entry.path);
    record.u64(storedOffset);
    record.u64(body.length);
    record.bytes(Buffer.from(md5Hex(body), "hex"));
    if (options.formatVersion === 2)
      record.u32(entry.encrypted === true ? 1 : 0);
    records.push(record.buffer());
  }
  const bodies: Buffer[] = [];
  let bodyCursor = recordsStart;
  for (const { storedOffset, body } of placements) {
    bodies.push(Buffer.alloc(Math.max(0, storedOffset - bodyCursor)), body);
    bodyCursor = storedOffset + body.length;
  }
  const index = Buffer.concat([header.buffer(), ...records]);
  return Buffer.concat([index, ...bodies]);
};

/** Fake executable prefix, then the PCK, then the embedded footer. */
export const embedGodotPckWithFooter = (
  pck: Buffer,
  leadingBytes = 64,
): Buffer => {
  const footer = new Cursor();
  footer.u64(pck.length);
  footer.bytes(Buffer.from("GDPC", "latin1"));
  return Buffer.concat([
    Buffer.alloc(leadingBytes, 0x7f),
    pck,
    footer.buffer(),
  ]);
};

export interface VpkEntryFixture {
  readonly dir: string;
  readonly name: string;
  readonly ext: string;
  readonly crc32: number;
  readonly preload?: Buffer;
  readonly archiveIndex?: number;
  readonly entryOffset?: number;
  readonly entryLength?: number;
}

export const buildVpkDirectory = (
  formatVersion: 1 | 2,
  entries: readonly VpkEntryFixture[],
): Buffer => {
  const tree = new Cursor();
  const byExtension = new Map<string, VpkEntryFixture[]>();
  for (const entry of entries) {
    const group = byExtension.get(entry.ext) ?? [];
    group.push(entry);
    byExtension.set(entry.ext, group);
  }
  for (const [ext, group] of byExtension) {
    tree.cstring(ext);
    const byDirectory = new Map<string, VpkEntryFixture[]>();
    for (const entry of group) {
      const list = byDirectory.get(entry.dir) ?? [];
      list.push(entry);
      byDirectory.set(entry.dir, list);
    }
    for (const [dir, directoryEntries] of byDirectory) {
      tree.cstring(dir);
      for (const entry of directoryEntries) {
        tree.cstring(entry.name);
        tree.u32(entry.crc32 >>> 0);
        const preload = entry.preload ?? Buffer.alloc(0);
        tree.u16(preload.length);
        tree.u16(entry.archiveIndex ?? 0);
        tree.u32(entry.entryOffset ?? 0);
        tree.u32(entry.entryLength ?? 0);
        tree.u16(0xffff);
        tree.bytes(preload);
      }
      tree.u8(0);
    }
    tree.u8(0);
  }
  tree.u8(0);
  const treeBytes = tree.buffer();
  const header = new Cursor();
  header.u32(0x55aa1234);
  header.u32(formatVersion);
  header.u32(treeBytes.length);
  if (formatVersion === 2) {
    header.u32(0);
    header.u32(0);
    header.u32(0);
    header.u32(0);
  }
  const padding = Buffer.alloc(16, 0x41);
  return Buffer.concat([header.buffer(), treeBytes, padding]);
};

export interface GamemakerChunkFixture {
  readonly fourcc: string;
  readonly payload: Buffer;
}

export const buildGamemakerForm = (
  chunks: readonly GamemakerChunkFixture[],
): Buffer => {
  const bodies = chunks.map((chunk) =>
    Buffer.concat([
      Buffer.from(chunk.fourcc, "latin1"),
      (() => {
        const size = Buffer.alloc(4);
        size.writeUInt32LE(chunk.payload.length);
        return size;
      })(),
      chunk.payload,
    ]),
  );
  const bodyBytes = bodies.reduce((total, bytes) => total + bytes.length, 0);
  const formSize = Buffer.alloc(4);
  formSize.writeUInt32LE(bodyBytes);
  return Buffer.concat([Buffer.from("FORM", "latin1"), formSize, ...bodies]);
};

/** GEN8 fixed-prefix payload; string pointers are absolute file offsets. */
export const buildGen8Payload = (fields: {
  readonly debuggerDisabled?: number;
  readonly bytecodeVersion?: number;
  readonly filename?: string;
  readonly config?: string;
  readonly name?: string;
  readonly lastObj?: number;
  readonly lastTile?: number;
  readonly gameId?: number;
  readonly tailBytes?: number;
  /** Absolute file offset where this payload begins, so pointers resolve. */
  readonly baseOffset?: number;
}): { payload: Buffer; pointers: Record<string, number> } => {
  const base = fields.baseOffset ?? 0;
  const head = new Cursor();
  head.bytes(
    Buffer.from([
      fields.debuggerDisabled ?? 1,
      fields.bytecodeVersion ?? 17,
      0,
      0,
    ]),
  );
  const strings: Buffer[] = [];
  const pointers: Record<string, number> = {};
  let stringOffset = base + 44;
  for (const key of ["filename", "config"] as const) {
    const value = fields[key];
    const pointer = new Cursor();
    pointer.u32(value === undefined ? 0 : stringOffset);
    head.bytes(pointer.buffer());
    if (value !== undefined) {
      const encoded = Buffer.from(value, "utf8");
      const lengthBytes = new Cursor();
      lengthBytes.u32(encoded.length);
      strings.push(lengthBytes.buffer(), encoded, Buffer.from([0]));
      pointers[key] = stringOffset;
      stringOffset += lengthBytes.buffer().length + encoded.length + 1;
    }
  }
  head.u32(fields.lastObj ?? 100000);
  head.u32(fields.lastTile ?? 10000000);
  head.u32(fields.gameId ?? 13371337);
  head.bytes(Buffer.alloc(16, 0x33));
  const nameValue = fields.name;
  const namePointer = new Cursor();
  namePointer.u32(nameValue === undefined ? 0 : stringOffset);
  head.bytes(namePointer.buffer());
  if (nameValue !== undefined) {
    const encoded = Buffer.from(nameValue, "utf8");
    const lengthBytes = new Cursor();
    lengthBytes.u32(encoded.length);
    strings.push(lengthBytes.buffer(), encoded, Buffer.from([0]));
    pointers.name = stringOffset;
  }
  const payload = Buffer.concat([
    head.buffer(),
    ...strings,
    Buffer.alloc(fields.tailBytes ?? 0, 0x55),
  ]);
  return { payload, pointers };
};

/** BININT when signed-32 safe, otherwise LONG1 (two's-complement little-endian). */
export const pickleInt = (value: number): Buffer => {
  if (value >= -0x80000000 && value <= 0x7fffffff) {
    const bytes = Buffer.alloc(5);
    bytes.writeUInt8(0x4a, 0);
    bytes.writeInt32LE(value, 1);
    return bytes;
  }
  if (value < 0 || value > 0xffff_ffff)
    throw new Error(`fixture int out of the u32/LONG1 range: ${String(value)}`);
  const magnitude = Buffer.alloc(5);
  magnitude.writeUInt32LE(value, 0);
  magnitude[4] = 0;
  let length = 5;
  // Keep the sign byte: trailing zeroes stay when the byte below has the high bit set.
  for (;;) {
    if (length <= 1) break;
    const top = magnitude[length - 1];
    const below = magnitude[length - 2];
    if (top === undefined || below === undefined) break;
    if (top !== 0 || (below & 0x80) !== 0) break;
    length--;
  }
  const bytes = Buffer.alloc(2 + length);
  bytes.writeUInt8(0x8a, 0);
  bytes.writeUInt8(length, 1);
  magnitude.subarray(0, length).copy(bytes, 2);
  return bytes;
};

export const pickleString = (value: string): Buffer => {
  const encoded = Buffer.from(value, "utf8");
  if (encoded.length < 256) {
    const bytes = Buffer.alloc(2 + encoded.length);
    bytes.writeUInt8(0x8c, 0);
    bytes.writeUInt8(encoded.length, 1);
    encoded.copy(bytes, 2);
    return bytes;
  }
  const bytes = Buffer.alloc(5 + encoded.length);
  bytes.writeUInt8(0x58, 0);
  bytes.writeUInt32LE(encoded.length, 1);
  encoded.copy(bytes, 5);
  return bytes;
};

const pickleBytes = (value: Buffer): Buffer => {
  if (value.length < 256) {
    const bytes = Buffer.alloc(2 + value.length);
    bytes.writeUInt8(0x43, 0);
    bytes.writeUInt8(value.length, 1);
    value.copy(bytes, 2);
    return bytes;
  }
  const bytes = Buffer.alloc(5 + value.length);
  bytes.writeUInt8(0x42, 0);
  bytes.writeUInt32LE(value.length, 1);
  value.copy(bytes, 5);
  return bytes;
};

export type RpaIndexFixture = Record<
  string,
  readonly (readonly [number, number] | readonly [number, number, Buffer])[]
>;

const pickleTuple = (values: readonly Buffer[]): Buffer => {
  const parts: Buffer[] = [];
  if (values.length === 2) {
    parts.push(...values, Buffer.from([0x86]));
  } else if (values.length === 3) {
    parts.push(...values, Buffer.from([0x87]));
  } else parts.push(Buffer.from([0x29]));
  return Buffer.concat(parts);
};

const pickleList = (items: readonly Buffer[]): Buffer => {
  const parts: Buffer[] = [Buffer.from([0x5d])];
  for (const item of items) parts.push(item, Buffer.from([0x61]));
  return Buffer.concat(parts);
};

export const pickleIndexOf = (index: RpaIndexFixture): Buffer => {
  const parts: Buffer[] = [Buffer.from([0x80, 2, 0x7d])];
  for (const [key, segments] of Object.entries(index)) {
    parts.push(pickleString(key));
    parts.push(
      pickleList(
        segments.map((segment) =>
          pickleTuple([
            pickleInt(segment[0]),
            pickleInt(segment[1]),
            ...(segment.length === 3 ? [pickleBytes(segment[2])] : []),
          ]),
        ),
      ),
    );
    parts.push(Buffer.from([0x73]));
  }
  parts.push(Buffer.from([0x2e]));
  return Buffer.concat(parts);
};

/** APPENDS (0x65) list build: mark, items, one batched append opcode. */
const pickleListAppends = (items: readonly Buffer[]): Buffer =>
  Buffer.concat([Buffer.from([0x5d, 0x28]), ...items, Buffer.from([0x65])]);

/**
 * Index pickle in the shape CPython itself emits for multi-item containers
 * (protocol 2 batch forms): every value list is built with MARK/APPENDS and
 * the outer dict with MARK/SETITEMS.
 */
export const pickleIndexOfBatched = (index: RpaIndexFixture): Buffer => {
  const parts: Buffer[] = [Buffer.from([0x80, 2, 0x7d, 0x28])];
  for (const [key, segments] of Object.entries(index)) {
    parts.push(pickleString(key));
    parts.push(
      pickleListAppends(
        segments.map((segment) =>
          pickleTuple([
            pickleInt(segment[0]),
            pickleInt(segment[1]),
            ...(segment.length === 3 ? [pickleBytes(segment[2])] : []),
          ]),
        ),
      ),
    );
  }
  parts.push(Buffer.from([0x75]), Buffer.from([0x2e]));
  return Buffer.concat(parts);
};

export const RPA3_HEADER = "RPA-3.0 %016x %08x\n";

const buildRpa3Bytes = (
  key: number,
  pickle: Buffer,
  bodyBytes: number,
): Buffer => {
  const indexBytes = deflateSync(pickle);
  const indexOffset = bodyBytes;
  const header = Buffer.from(
    RPA3_HEADER.replace(
      "%016x",
      indexOffset.toString(16).padStart(16, "0"),
    ).replace("%08x", key.toString(16).padStart(8, "0")),
    "ascii",
  );
  return Buffer.concat([
    header,
    Buffer.alloc(bodyBytes - header.length, 0x42),
    indexBytes,
  ]);
};

/** Header, filler body bytes, and the zlib-compressed pickle index. */
export const buildRpa3 = (
  key: number,
  index: RpaIndexFixture,
  bodyBytes = 512,
): Buffer => buildRpa3Bytes(key, pickleIndexOf(index), bodyBytes);

/** Same archive with a batched (APPENDS/SETITEMS) CPython-shaped index pickle. */
export const buildRpa3Batched = (
  key: number,
  index: RpaIndexFixture,
  bodyBytes = 512,
): Buffer => buildRpa3Bytes(key, pickleIndexOfBatched(index), bodyBytes);

export const buildRpa2 = (index: RpaIndexFixture, bodyBytes = 512): Buffer => {
  const pickleBytesOut = deflateSync(pickleIndexOf(index));
  const indexOffset = bodyBytes;
  const header = Buffer.from(
    `RPA-2.0 ${indexOffset.toString(16).padStart(16, "0")}\n`,
    "ascii",
  );
  return Buffer.concat([
    header,
    Buffer.alloc(bodyBytes - header.length, 0x42),
    pickleBytesOut,
  ]);
};

/** RPG Maker MV/MZ fake 16-byte header followed by post-stripped bytes. */
export const RPGMAKER_FAKE_HEADER = Buffer.from([
  0x52, 0x50, 0x47, 0x4d, 0x56, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00,
]);
const RESTORED_PNG_MAGIC = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
]);

/** Fake header, then the PNG magic the 16-byte strip removes. */
export const buildRpgmakerEncryptedPng = (
  tail = Buffer.alloc(8, 0x11),
): Buffer => Buffer.concat([RPGMAKER_FAKE_HEADER, RESTORED_PNG_MAGIC, tail]);

/** Fake header, then the original file's OggS magic. */
export const buildRpgmakerEncryptedOgg = (
  tail = Buffer.alloc(8, 0x22),
): Buffer =>
  Buffer.concat([RPGMAKER_FAKE_HEADER, Buffer.from("OggS", "latin1"), tail]);

/** Fake header over a continuation no decrypter classifies: honest unknown. */
export const buildRpgmakerEncryptedUnknown = (
  tail = Buffer.alloc(8, 0x33),
): Buffer => Buffer.concat([RPGMAKER_FAKE_HEADER, tail]);

export const buildPlainPng = (): Buffer =>
  Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.alloc(24),
  ]);

export const buildPlainOgg = (): Buffer =>
  Buffer.concat([Buffer.from("OggS", "latin1"), Buffer.alloc(24)]);
