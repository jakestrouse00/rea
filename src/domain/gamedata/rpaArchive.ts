import { inflateSync } from "node:zlib";
import { z } from "zod";

import {
  gamedataArtifactSchema,
  gamedataPageSchema,
  pagedSliceSchema,
  sliceEntries,
} from "./gamedataShared.js";
import { localPathStringSchema } from "../localPath.js";
import { compareUnicodeCodePoints as compare } from "../unicodeCodePointOrder.js";

/** RPA-3.0 header layout (renpy/loader.py): magic, 16-hex offset, key hex. */
export const RPA3_MAGIC = Buffer.from("RPA-3.0 ");
export const RPA2_MAGIC = Buffer.from("RPA-2.0 ");
export const RPA_HEADER_MAGIC_BYTES = 8;
export const RPA3_HEADER_BYTES = 34;
export const RPA2_HEADER_BYTES = 25;
export const RPA_MAX_INDEX_DECOMPRESSED = 64 * 1024 * 1024;
export const RPA_MAX_INDEX_COMPRESSED = 256 * 1024 * 1024;
/** Obfuscated-index XOR arithmetic only; file bytes are never transformed. */
export const RPA_INDEX_ARITHMETIC_ONLY =
  "index offsets and lengths were XOR deobfuscated with the archive key (index-structure arithmetic only)";

/** One contiguous data segment of one archived file. */
export const rpaSegmentSchema = z.strictObject({
  /** The value the pickle declared; obfuscated when the header key is nonzero. */
  stored_offset: z.number().int().nonnegative(),
  stored_length: z.number().int().nonnegative(),
  /** XOR-deobfuscated segment location within the archive. */
  offset: z.number().int().nonnegative(),
  length: z.number().int().nonnegative(),
  has_inline_prefix: z.boolean(),
  prefix_bytes: z.number().int().nonnegative().nullable(),
});
export type RpaSegment = z.infer<typeof rpaSegmentSchema>;

/** One archived file: archive-spelled name plus its segments. */
export const rpaEntrySchema = z
  .strictObject({
    path: z.string().min(1),
    index_obfuscated: z.boolean(),
    segments: z.array(rpaSegmentSchema).min(1),
    encrypted: z.boolean(),
  })
  .superRefine((entry, context) => {
    if (
      !entry.index_obfuscated &&
      entry.segments.some(
        (segment) =>
          segment.stored_offset !== segment.offset ||
          segment.stored_length !== segment.length,
      )
    )
      context.addIssue({
        code: "custom",
        path: ["segments"],
        message: "Unobfuscated indexes cannot differ from their stored values.",
      });
  });
export type RpaEntry = z.infer<typeof rpaEntrySchema>;

/** Compressed pickle index facts plus the readable-or-refused entry table. */
export const rpaIndexSchema = z.strictObject({
  offset_in_file: z.number().int().nonnegative(),
  compressed_bytes: z.number().int().nonnegative(),
  decompressed_bytes: z.number().int().nonnegative(),
  pickle_protocol: z.number().int().min(0).max(5).nullable(),
  key_hex: z.string().regex(/^[0-9a-f]{8}$/u),
  index_values_obfuscated: z.boolean(),
  readable: z.boolean(),
  unsupported_detail: z.string().nullable(),
  entry_total: z.number().int().nonnegative(),
  entries: z.array(rpaEntrySchema),
  slice: pagedSliceSchema,
});
export type RpaIndex = z.infer<typeof rpaIndexSchema>;

/** Structure-only observation of one Ren'Py archive. */
export const rpaReportSchema = z
  .strictObject({
    artifact: gamedataArtifactSchema,
    archive_format_version: z.enum(["2.0", "3.0"]),
    header_bytes: z.number().int().nonnegative(),
    header_terminated_by_newline: z.boolean(),
    index: rpaIndexSchema,
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    const bound = report.artifact.bytes;
    const index = report.index;
    if (index.offset_in_file > bound)
      context.addIssue({
        code: "custom",
        path: ["index", "offset_in_file"],
        message: "Index offset is outside the inspected artifact.",
      });
    if (index.compressed_bytes > bound - index.offset_in_file)
      context.addIssue({
        code: "custom",
        path: ["index", "compressed_bytes"],
        message: "Index byte range is outside the inspected artifact.",
      });
    if (!index.readable) return;
    for (const [entryIndex, entry] of index.entries.entries())
      for (const [segmentIndex, segment] of entry.segments.entries())
        if (segment.offset > bound || segment.length > bound - segment.offset)
          context.addIssue({
            code: "custom",
            path: [
              "index",
              "entries",
              String(entryIndex),
              "segments",
              String(segmentIndex),
            ],
            message: "Segment range is outside the inspected artifact.",
          });
  });
export type RpaReport = z.infer<typeof rpaReportSchema>;

export const inspectRpaArchiveInputSchema = z.strictObject({
  path: localPathStringSchema,
  ...gamedataPageSchema.shape,
});

export class RpaFormatError extends Error {
  constructor(message: string) {
    super(message);
  }
}

class RpaUnsupportedPickleError extends Error {
  constructor(
    readonly opcode: number,
    readonly offset: number,
    message: string,
  ) {
    super(message);
  }
}

const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER;
const MAX_PICKLE_OPCODES = 1_000_000;
const MAX_STACK_DEPTH = 64;
const MAX_STRING_BYTES = 1 << 16;

type IntValue = { readonly type: "int"; readonly value: number };
type StrValue = { readonly type: "str"; readonly value: string };
type BytesValue = { readonly type: "bytes"; readonly raw: Buffer };
type ListValue = { readonly type: "list"; readonly items: unknown[] };
type TupleValue = { readonly type: "tuple"; readonly items: unknown[] };
type DictValue = {
  readonly type: "dict";
  readonly items: Map<string, unknown>;
};
type MarkValue = { readonly type: "mark" };
type PickleValue =
  | IntValue
  | StrValue
  | BytesValue
  | ListValue
  | TupleValue
  | DictValue
  | MarkValue
  | { readonly type: "bool"; readonly value: boolean };

const isSafeInt = (value: bigint, at: number): number => {
  if (value > BigInt(MAX_SAFE_INT) || value < -BigInt(MAX_SAFE_INT))
    throw new RpaUnsupportedPickleError(
      0,
      at,
      "integer exceeds the supported range",
    );
  return Number(value);
};

const signedFromTwos = (data: Buffer, at: number): number => {
  if (data.length > 8)
    throw new RpaUnsupportedPickleError(0, at, "integer is wider than 64 bits");
  let magnitude = 0n;
  for (const [index, byte] of data.entries())
    magnitude += BigInt(byte) * (1n << BigInt(8 * index));
  const top = data.length === 0 ? 0 : byteAt(data, data.length - 1, at);
  const negative = data.length > 0 && (top & 0x80) !== 0;
  return isSafeInt(
    negative ? magnitude - (1n << BigInt(8 * data.length)) : magnitude,
    at,
  );
};

const byteAt = (bytes: Buffer, index: number, at: number): number => {
  const value = bytes[index];
  if (value === undefined)
    throw new RpaUnsupportedPickleError(0, at, "pickle stream is truncated");
  return value;
};

/**
 * Bounded pure evaluator for the exact pickle shapes a Ren'Py index uses
 * (one dict of string paths to lists of tuples of ints and optional byte or
 * string prefixes). Every other opcode is refused, never evaluated.
 */
export const parseRpaPickleIndex = (
  bytes: Buffer,
): { entries: Map<string, unknown>; protocol: number | null } => {
  const stack: PickleValue[] = [];
  const memo = new Map<number, PickleValue>();
  let protocol: number | null = null;
  let at = 0;
  let opcodes = 0;
  const push = (value: PickleValue): void => {
    if (stack.length >= MAX_STACK_DEPTH)
      throw new RpaUnsupportedPickleError(
        0,
        at,
        "stack depth exceeds the bound",
      );
    stack.push(value);
  };
  const popMarked = (): PickleValue[] => {
    const markIndex = stack.findLastIndex((value) => value.type === "mark");
    if (markIndex < 0)
      throw new RpaUnsupportedPickleError(0, at, "mark object is missing");
    const items = stack.slice(markIndex + 1);
    stack.length = markIndex;
    return items;
  };
  const readLength = (
    bytes2: Buffer,
    offset: number,
    width: number,
    opcode: number,
  ): number => {
    if (offset + width > bytes2.length)
      throw new RpaUnsupportedPickleError(
        opcode,
        at,
        "length argument is truncated",
      );
    const value =
      width === 1
        ? byteAt(bytes2, offset, at)
        : width === 4
          ? bytes2.readUInt32LE(offset)
          : readU64(bytes2, offset);
    return value;
  };
  while (at < bytes.length) {
    opcodes++;
    if (opcodes > MAX_PICKLE_OPCODES)
      throw new RpaUnsupportedPickleError(
        0,
        at,
        "opcode count exceeds the bound",
      );
    const opcode = byteAt(bytes, at, at);
    const argument = at + 1;
    switch (opcode) {
      case 0x80: {
        if (argument >= bytes.length)
          throw new RpaUnsupportedPickleError(opcode, at, "PROTO is truncated");
        const version = byteAt(bytes, argument, at);
        if (version > 5)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "pickle protocol is not evaluated",
          );
        protocol = version;
        at = argument + 1;
        break;
      }
      case 0x95:
        readLength(bytes, argument, 8, opcode); // frames are layout metadata; data stays contiguous
        at = argument + 8;
        break;
      case 0x28:
        push({ type: "mark" });
        at++;
        break;
      case 0x29:
        push({ type: "tuple", items: [] });
        at++;
        break;
      case 0x5d:
        push({ type: "list", items: [] });
        at++;
        break;
      case 0x7d:
        push({ type: "dict", items: new Map() });
        at++;
        break;
      case 0x74: {
        push({ type: "tuple", items: popMarked() });
        at++;
        break;
      }
      case 0x85:
      case 0x86:
      case 0x87: {
        const count = opcode - 0x84;
        if (stack.length < count)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "tuple build lacks stack items",
          );
        push({
          type: "tuple",
          items: stack.splice(stack.length - count, count),
        });
        at++;
        break;
      }
      case 0x61: {
        const list = stack[stack.length - 2];
        const value = stack.pop();
        if (list?.type !== "list" || value === undefined)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "APPEND shape mismatch",
          );
        list.items.push(value);
        at++;
        break;
      }
      case 0x65: {
        // CPython APPENDS pops the mark first, then appends to the container
        // the mark left behind.
        const values = popMarked();
        const list = stack.at(-1);
        if (list?.type !== "list")
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "APPENDS shape mismatch",
          );
        list.items.push(...values);
        at++;
        break;
      }
      case 0x73: {
        const value = stack.pop();
        const key = stack.pop();
        const dict = stack.at(-1);
        if (key?.type !== "str" || value === undefined || dict?.type !== "dict")
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "SETITEM shape mismatch",
          );
        dict.items.set(key.value, value);
        at++;
        break;
      }
      case 0x75: {
        // CPython SETITEMS pops the mark first, then fills the container the
        // mark left behind.
        const values = popMarked();
        const dict = stack.at(-1);
        if (dict?.type !== "dict" || values.length % 2 !== 0)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "SETITEMS shape mismatch",
          );
        for (let i = 0; i < values.length; i += 2) {
          const key = values[i];
          const value = values[i + 1];
          if (key?.type !== "str" || value === undefined)
            throw new RpaUnsupportedPickleError(
              opcode,
              at,
              "SETITEMS key mismatch",
            );
          dict.items.set(key.value, value);
        }
        at++;
        break;
      }
      case 0x88:
        push({ type: "bool", value: true });
        at++;
        break;
      case 0x89:
        push({ type: "bool", value: false });
        at++;
        break;
      case 0x4a:
        if (argument + 4 > bytes.length)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "BININT is truncated",
          );
        push({ type: "int", value: bytes.readInt32LE(argument) });
        at = argument + 4;
        break;
      case 0x4b:
        push({ type: "int", value: byteAt(bytes, argument, at) });
        at = argument + 1;
        break;
      case 0x4d:
        if (argument + 2 > bytes.length)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "BININT2 is truncated",
          );
        push({ type: "int", value: bytes.readUInt16LE(argument) });
        at = argument + 2;
        break;
      case 0x49: {
        const newline = bytes.indexOf(0x0a, argument);
        if (newline < 0)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "INT lacks a newline",
          );
        const text = bytes.subarray(argument, newline).toString("ascii");
        if (!/^-?[0-9]+$/u.test(text))
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "INT payload is not an integer literal",
          );
        push({ type: "int", value: isSafeInt(BigInt(text), at) });
        at = newline + 1;
        break;
      }
      case 0x4c: {
        const newline = bytes.indexOf(0x0a, argument);
        if (newline < 0)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "LONG lacks a newline",
          );
        const text = bytes.subarray(argument, newline).toString("ascii");
        if (!/^-?[0-9]+L?$/u.test(text))
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "LONG payload is not an integer literal",
          );
        push({
          type: "int",
          value: isSafeInt(BigInt(text.replace(/L$/u, "")), at),
        });
        at = newline + 1;
        break;
      }
      case 0x8a: {
        if (argument >= bytes.length)
          throw new RpaUnsupportedPickleError(opcode, at, "LONG1 is truncated");
        const length = byteAt(bytes, argument, at);
        if (argument + 1 + length > bytes.length)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "LONG1 payload is truncated",
          );
        push({
          type: "int",
          value: signedFromTwos(
            bytes.subarray(argument + 1, argument + 1 + length),
            at,
          ),
        });
        at = argument + 1 + length;
        break;
      }
      case 0x8b: {
        if (argument + 4 > bytes.length)
          throw new RpaUnsupportedPickleError(opcode, at, "LONG4 is truncated");
        const length = bytes.readInt32LE(argument);
        if (length < 0 || argument + 4 + length > bytes.length)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "LONG4 payload is truncated",
          );
        push({
          type: "int",
          value: signedFromTwos(
            bytes.subarray(argument + 4, argument + 4 + length),
            at,
          ),
        });
        at = argument + 4 + length;
        break;
      }
      case 0x58:
      case 0x8c: {
        const offsetWidth = opcode === 0x58 ? 4 : 1;
        const prefixLength = readLength(bytes, argument, offsetWidth, opcode);
        const text = utf8String(
          bytes,
          argument + offsetWidth,
          prefixLength,
          opcode,
        );
        push(text);
        at = argument + offsetWidth + prefixLength;
        break;
      }
      case 0x42:
      case 0x43: {
        const offsetWidth = opcode === 0x42 ? 4 : 1;
        const length = readLength(bytes, argument, offsetWidth, opcode);
        const start = argument + offsetWidth;
        if (start + length > bytes.length)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "bytes payload overruns",
          );
        push({ type: "bytes", raw: bytes.subarray(start, start + length) });
        at = start + length;
        break;
      }
      case 0x8d:
      case 0x8e: {
        const isUnicode = opcode === 0x8d;
        const length = readLength(bytes, argument, 8, opcode);
        const start = argument + 8;
        if (start + length > bytes.length)
          throw new RpaUnsupportedPickleError(opcode, at, "payload overruns");
        push(
          isUnicode
            ? utf8String(bytes, start, length, opcode)
            : ({
                type: "bytes",
                raw: bytes.subarray(start, start + length),
              } as PickleValue),
        );
        at = start + length;
        break;
      }
      case 0x71:
      case 0x72: {
        const width = opcode === 0x71 ? 1 : 4;
        const index = readLength(bytes, argument, width, opcode);
        const value = stack.at(-1);
        if (value === undefined)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "BINPUT has no stack item",
          );
        memo.set(index, value);
        at = argument + width;
        break;
      }
      case 0x68:
      case 0x6a: {
        const width = opcode === 0x68 ? 1 : 4;
        const index = readLength(bytes, argument, width, opcode);
        const value = memo.get(index);
        if (value === undefined)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "memo index is unresolved",
          );
        push(value);
        at = argument + width;
        break;
      }
      case 0x94: {
        const value = stack.at(-1);
        if (value === undefined)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "MEMOIZE has no stack item",
          );
        memo.set(memo.size, value);
        at++;
        break;
      }
      case 0x2e: {
        const top = stack.pop();
        if (top === undefined || top.type !== "dict" || stack.length !== 0)
          throw new RpaUnsupportedPickleError(
            opcode,
            at,
            "STOP did not leave exactly one index dict",
          );
        return { entries: top.items, protocol };
      }
      default:
        throw new RpaUnsupportedPickleError(
          opcode,
          at,
          `opcode 0x${opcode.toString(16).padStart(2, "0")} is not part of the evaluated index subset`,
        );
    }
  }
  throw new RpaUnsupportedPickleError(
    0,
    at,
    "pickle stream ended without STOP",
  );
};

const readU64 = (bytes: Buffer, offset: number): number => {
  const value = bytes.readBigUInt64LE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new RpaUnsupportedPickleError(
      0,
      offset,
      "64-bit length exceeds the supported range",
    );
  return Number(value);
};

const utf8String = (
  bytes: Buffer,
  start: number,
  length: number,
  opcode: number,
): PickleValue => {
  if (length > MAX_STRING_BYTES)
    throw new RpaUnsupportedPickleError(
      opcode,
      start,
      "string exceeds the length bound",
    );
  if (start + length > bytes.length)
    throw new RpaUnsupportedPickleError(
      opcode,
      start,
      "string payload overruns",
    );
  const text = bytes.subarray(start, start + length).toString("utf8");
  if (Buffer.byteLength(text, "utf8") !== length)
    throw new RpaUnsupportedPickleError(
      opcode,
      start,
      "string is not valid UTF-8",
    );
  return { type: "str", value: text };
};

const readSegment = (
  raw: PickleValue,
  key: number,
  obfuscated: boolean,
  path: string,
): RpaSegment => {
  if (
    raw.type !== "tuple" ||
    (raw.items.length !== 2 && raw.items.length !== 3)
  )
    throw new RpaFormatError(
      `Index tuple for ${JSON.stringify(path)} must have 2 or 3 elements`,
    );
  const [offsetValue, lengthValue, prefixValue] = raw.items as PickleValue[];
  const asInt = (value: PickleValue | undefined, field: string): number => {
    if (value === undefined || value.type !== "int")
      throw new RpaFormatError(
        `Index ${field} for ${JSON.stringify(path)} is not an integer`,
      );
    return value.value;
  };
  const asUnsigned = (value: number, field: string): number => {
    if (value < 0 || !Number.isSafeInteger(value))
      throw new RpaFormatError(
        `Deobfuscated index ${field} for ${JSON.stringify(path)} is not a representable unsigned value`,
      );
    return value;
  };
  const storedOffset = asInt(offsetValue, "offset");
  const storedLength = asInt(lengthValue, "length");
  const offset = asUnsigned(
    obfuscated ? (storedOffset ^ key) >>> 0 : storedOffset,
    "offset",
  );
  const length = asUnsigned(
    obfuscated ? (storedLength ^ key) >>> 0 : storedLength,
    "length",
  );
  let hasPrefix = false;
  let prefixBytes: number | null = null;
  if (prefixValue !== undefined) {
    if (prefixValue.type === "bytes") {
      hasPrefix = true;
      prefixBytes = prefixValue.raw.length;
    } else if (prefixValue.type === "str") {
      hasPrefix = true;
      prefixBytes = Buffer.byteLength(prefixValue.value, "utf8");
    } else
      throw new RpaFormatError(
        `Index prefix for ${JSON.stringify(path)} is neither bytes nor a string`,
      );
  }
  return {
    stored_offset: storedOffset,
    stored_length: storedLength,
    offset,
    length,
    has_inline_prefix: hasPrefix,
    prefix_bytes: prefixBytes,
  };
};

const readEntryTable = (
  entries: Map<string, unknown>,
  key: number,
  obfuscated: boolean,
): readonly RpaEntry[] =>
  [...entries.keys()].sort(compare).map((path) => {
    const bucket = entries.get(path) as PickleValue | undefined;
    if (bucket === undefined || bucket.type !== "list")
      throw new RpaFormatError(
        `Index value for ${JSON.stringify(path)} is not a list`,
      );
    const items: readonly PickleValue[] =
      bucket.items as readonly PickleValue[];
    if (items.length === 0)
      throw new RpaFormatError(
        `Index list for ${JSON.stringify(path)} is empty`,
      );
    const mapped = items.map((raw) => {
      if (typeof raw !== "object" || raw === null)
        throw new RpaFormatError(
          `Index value for ${JSON.stringify(path)} is not structured`,
        );
      return readSegment(raw, key, obfuscated, path);
    });
    return {
      path,
      index_obfuscated: obfuscated,
      segments: mapped,
      encrypted: obfuscated,
    };
  });

/** Parse the RPA header, decompress the index, and evaluate its entry table. */
export const parseRpaArchive = (
  bytes: Buffer,
  page: { readonly entries_start: number; readonly entries_limit: number },
): Omit<RpaReport, "artifact"> => {
  const is3 = bytes.subarray(0, RPA_HEADER_MAGIC_BYTES).equals(RPA3_MAGIC);
  const is2 = bytes.subarray(0, RPA_HEADER_MAGIC_BYTES).equals(RPA2_MAGIC);
  if (!is3 && !is2)
    throw new RpaFormatError(
      "Archive does not start with the RPA-2.0 or RPA-3.0 magic",
    );
  if (bytes.length < RPA_HEADER_MAGIC_BYTES + 17)
    throw new RpaFormatError("RPA header is truncated before the index offset");
  const headerBytes = is3 ? RPA3_HEADER_BYTES : RPA2_HEADER_BYTES;
  const hexOffsetEnd = RPA_HEADER_MAGIC_BYTES + 16;
  const headerSlice = (start: number, end: number): string =>
    bytes.subarray(start, end).toString("ascii");
  if (
    !/^[0-9a-fA-F]{16}$/u.test(
      headerSlice(RPA_HEADER_MAGIC_BYTES, hexOffsetEnd),
    )
  )
    throw new RpaFormatError("RPA index offset is not 16 hexadecimal digits");
  const indexOffset = Number.parseInt(
    headerSlice(RPA_HEADER_MAGIC_BYTES, hexOffsetEnd),
    16,
  );
  let key = 0;
  let terminatedByNewline = false;
  if (is3) {
    if (
      bytes.length < RPA3_HEADER_BYTES ||
      bytes.readUInt8(RPA_HEADER_MAGIC_BYTES + 16) !== 0x20
    )
      throw new RpaFormatError(
        "RPA-3.0 header lacks the space between offset and key",
      );
    const keyHex = headerSlice(hexOffsetEnd + 1, RPA3_HEADER_BYTES - 1);
    if (!/^[0-9a-fA-F]{8}$/u.test(keyHex))
      throw new RpaFormatError("RPA key is not 8 hexadecimal digits");
    key = Number.parseInt(keyHex, 16);
    terminatedByNewline = bytes.readUInt8(RPA3_HEADER_BYTES - 1) === 0x0a;
  } else {
    terminatedByNewline = bytes.readUInt8(RPA2_HEADER_BYTES - 1) === 0x0a;
  }
  if (indexOffset < headerBytes || indexOffset >= bytes.length)
    throw new RpaFormatError(
      `RPA index offset ${String(indexOffset)} is not between the header and the file end`,
    );
  const compressed = bytes.subarray(indexOffset);
  if (compressed.length > RPA_MAX_INDEX_COMPRESSED)
    throw new RpaFormatError("Index stream exceeds the compressed-bound");
  let decompressed: Buffer;
  try {
    decompressed = inflateSync(compressed, {
      maxOutputLength: RPA_MAX_INDEX_DECOMPRESSED,
    });
  } catch (cause) {
    throw new RpaFormatError(
      `RPA index is not a bounded zlib stream: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  const obfuscated = is3 && key !== 0;
  let parsedEntries: readonly RpaEntry[];
  let protocol: number | null = null;
  let unsupportedDetail: string | null = null;
  try {
    const evaluated = parseRpaPickleIndex(decompressed);
    protocol = evaluated.protocol;
    parsedEntries = readEntryTable(evaluated.entries, key, obfuscated);
  } catch (cause) {
    if (cause instanceof RpaFormatError) throw cause;
    unsupportedDetail =
      cause instanceof RpaUnsupportedPickleError
        ? `opcode 0x${cause.opcode.toString(16).padStart(2, "0")} at offset ${String(cause.offset)}: ${cause.message}`
        : `index evaluation was refused: ${cause instanceof Error ? cause.message : String(cause)}`;
    parsedEntries = [];
  }
  const sliced = sliceEntries(
    parsedEntries,
    page.entries_start,
    page.entries_limit,
  );
  return {
    archive_format_version: is3 ? "3.0" : "2.0",
    header_bytes: headerBytes,
    header_terminated_by_newline: terminatedByNewline,
    index: {
      offset_in_file: indexOffset,
      compressed_bytes: compressed.length,
      decompressed_bytes: decompressed.length,
      pickle_protocol: protocol,
      key_hex: key.toString(16).padStart(8, "0"),
      index_values_obfuscated: obfuscated,
      readable: unsupportedDetail === null,
      unsupported_detail: unsupportedDetail,
      entry_total: parsedEntries.length,
      entries: sliced.entries,
      slice: sliced.slice,
    },
    limitations: [
      `Structure-only inspection: ${RPA_INDEX_ARITHMETIC_ONLY}; file bodies were not read, transformed or decrypted.`,
      `Encrypted flag records the archive-level index obfuscation (header key 0x${key
        .toString(16)
        .padStart(
          8,
          "0",
        )}); the format defines no per-body encryption field, so body secrecy stays unknown.`,
      "Inline prefix segments report their presence and byte length only; prefix contents were not retained.",
      "Segment ranges use the Ren'Py loader reading convention (length counted at the offset); some third-party writers count the prefix inside length, so range ends near the file end stay approximate.",
      "Entry paths keep the archive's own spelling; the table is sorted by Unicode code point for stable paging.",
      ...(unsupportedDetail === null
        ? []
        : [
            "The compressed pickle index was not fully evaluated; the refused opcode is reported and entry counts are partial.",
          ]),
    ],
  };
};
