import { z } from "zod";
import {
  ContainerFormatError,
  containerLimitError,
} from "./containerFormatError.js";

/**
 * Minimal marshal reader for PYZ TOC blobs. It supports exactly the shapes
 * the PyInstaller ZlibArchive writer emits (dict before PyInstaller 3.1, list
 * of (name, entry) tuples since 3.1) plus the shared marshal scalar and
 * composite encodings, bounded by byte count, object count, and recursion
 * depth. Entry contents are never decoded.
 */

export const MAX_PYZ_TOC_BYTES = 16 * 1024 * 1024;
export const MAX_MARSHAL_OBJECTS = 262_144;
export const MAX_MARSHAL_DEPTH = 128;
export const MAX_MARSHAL_STRING_BYTES = 1024 * 1024;

const nonnegative = z.number().int().nonnegative();

export const pyzTocEntrySchema = z.strictObject({
  name: z.string(),
  /** ZlibArchive item code: 0 module, 1 package, 2 data (legacy), 3 namespace package. */
  item_type_code: z.number().int().nonnegative(),
  item_type: z.enum(["module", "package", "data", "namespace_package"]),
  /** Entry blob position, relative to the start of the embedded PYZ archive. */
  position: nonnegative,
  /** Compressed entry length in bytes. */
  length: nonnegative,
});
export type PyzTocEntry = z.infer<typeof pyzTocEntrySchema>;

export const pyzTocSchema = z.strictObject({
  entries: z.array(pyzTocEntrySchema),
  toc_position: nonnegative,
  limitations: z.array(z.string()),
});
export type PyzToc = z.infer<typeof pyzTocSchema>;

type MarshalPrimitive = null | boolean | number | string;
type MarshalTuple = readonly MarshalValue[];
interface MarshalValue {
  readonly kind: "null" | "bool" | "int" | "string" | "tuple" | "list" | "dict";
  readonly value: MarshalPrimitive | MarshalTuple | unknown;
}

const readerFailure = (
  message: string,
  cause?: unknown,
): ContainerFormatError =>
  new ContainerFormatError(
    "format",
    `PYZ TOC marshal data is malformed: ${message}`,
    {
      cause,
    },
  );

interface MarshalReaderState {
  readonly position: number;
  readonly referencesUsed: number;
}

class MarshalReader {
  #position = 0;
  readonly #references: MarshalValue[] = [];

  constructor(readonly bytes: Uint8Array) {}

  get state(): MarshalReaderState {
    return {
      position: this.#position,
      referencesUsed: this.#references.length,
    };
  }

  readObject(depth: number): MarshalValue {
    if (depth > MAX_MARSHAL_DEPTH)
      throw readerFailure(
        `nesting exceeds the ${String(MAX_MARSHAL_DEPTH)}-level bound`,
      );
    const code = this.#readByte();
    const flag = code >= 0x80;
    const type = String.fromCharCode(code & 0x7f);
    // Wire-shape mirror of CPython r_object: flagged composites reserve their
    // reference slot before their children so shared objects resolve the same.
    const reserve = (): number => {
      if (flag) this.#references.push({ kind: "null", value: null });
      return this.#references.length - 1;
    };
    const complete = (index: number, value: MarshalValue): MarshalValue => {
      if (flag) this.#references[index] = value;
      return value;
    };
    const parse = (value: MarshalValue, immediate: boolean): MarshalValue => {
      if (flag && immediate) this.#references.push(value);
      return value;
    };
    switch (type) {
      case "0":
      case "N":
        return { kind: "null", value: null };
      case "F":
        return { kind: "bool", value: false };
      case "T":
        return { kind: "bool", value: true };
      case "i": {
        return parse({ kind: "int", value: this.#readInt32() }, true);
      }
      case "I": {
        return parse({ kind: "int", value: this.#readInt64() }, true);
      }
      case "l":
        throw readerFailure(
          "arbitrary-precision TYPE_LONG integers are not part of the PYZ TOC shape",
        );
      case "s":
      case "t":
      case "u":
      case "a":
      case "A": {
        const length = this.#readInt32();
        this.#assertBlobBounds(length);
        const bytes = this.#readBytes(length);
        const value =
          type === "a" || type === "A" ? asciiString(bytes) : decodeUtf8(bytes);
        return parse({ kind: "string", value }, true);
      }
      case "z":
      case "Z": {
        const length = this.#readByte();
        const bytes = this.#readBytes(length);
        return parse({ kind: "string", value: asciiString(bytes) }, true);
      }
      case "r": {
        const index = this.#readInt32();
        const referenced = this.#references[index - 1];
        if (referenced === undefined)
          throw readerFailure(
            `TYPE_REF index ${String(index)} has no table entry`,
          );
        return referenced;
      }
      case "(": {
        const count = this.#readInt32();
        return this.#readSequence(
          count,
          depth,
          reserve,
          complete,
          "tuple",
          true,
        );
      }
      case ")": {
        const count = this.#readByte();
        return this.#readSequence(
          count,
          depth,
          reserve,
          complete,
          "tuple",
          false,
        );
      }
      case "[": {
        const count = this.#readInt32();
        return this.#readSequence(
          count,
          depth,
          reserve,
          complete,
          "list",
          true,
        );
      }
      case "{":
      case "}": {
        const index = reserve();
        const collected: (readonly [MarshalValue, MarshalValue])[] = [];
        for (;;) {
          const key = this.readObject(depth + 1);
          // The writer terminates a dict with a bare TYPE_NULL, never flagged.
          if (key.kind === "null" && key.value === null) break;
          const value = this.readObject(depth + 1);
          collected.push([key, value] as const);
          if (collected.length > MAX_MARSHAL_OBJECTS)
            throw containerLimitError(
              "PYZ TOC dict entries",
              collected.length,
              MAX_MARSHAL_OBJECTS,
            );
        }
        return complete(index, { kind: "dict", value: collected });
      }
      default:
        throw readerFailure(`unsupported marshal type ${JSON.stringify(type)}`);
    }
  }

  #readSequence(
    count: number,
    depth: number,
    reserve: () => number,
    complete: (index: number, value: MarshalValue) => MarshalValue,
    kind: "tuple" | "list",
    assertSafe: boolean,
  ): MarshalValue {
    if (assertSafe)
      this.#assertBounds(count, `${kind} length`, MAX_MARSHAL_OBJECTS);
    const index = reserve();
    const items: MarshalValue[] = [];
    for (let item = 0; item < count; item += 1)
      items.push(this.readObject(depth + 1));
    return complete(index, { kind, value: items });
  }

  #readByte(): number {
    if (this.#position >= this.bytes.length)
      throw readerFailure("unexpected end of data");
    const byte = this.byteAt(this.#position);
    this.#position += 1;
    return byte;
  }

  private byteAt(position: number): number {
    const byte = this.bytes[position];
    if (byte === undefined) throw readerFailure("unexpected end of data");
    return byte;
  }

  #readBytes(length: number): Uint8Array {
    const bytes = this.bytes.subarray(this.#position, this.#position + length);
    this.#position += length;
    return bytes;
  }

  #readInt32(): number {
    if (this.#position + 4 > this.bytes.length)
      throw readerFailure("truncated 4-byte integer");
    const b0 = this.byteAt(this.#position);
    const b1 = this.byteAt(this.#position + 1);
    const b2 = this.byteAt(this.#position + 2);
    const b3 = this.byteAt(this.#position + 3);
    const value = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    this.#position += 4;
    return value;
  }

  #readInt64(): number {
    if (this.#position + 8 > this.bytes.length)
      throw readerFailure("truncated 8-byte integer");
    const low = this.#readInt32();
    const high = this.#readInt32();
    const value = high * 0x1_0000_0000 + (low >>> 0);
    if (!Number.isSafeInteger(value))
      throw containerLimitError(
        "PYZ TOC integer",
        value,
        Number.MAX_SAFE_INTEGER,
      );
    return value;
  }

  #assertBounds(length: number, subject: string, maximum: number): void {
    if (length < 0) throw readerFailure(`negative ${subject}`);
    if (length > maximum)
      throw containerLimitError(`PYZ TOC ${subject}`, length, maximum);
    if (this.#position + length > this.bytes.length)
      throw readerFailure(
        `${subject} ${String(length)} exceeds the remaining ${String(this.bytes.length - this.#position)} bytes`,
      );
    if (this.state.referencesUsed > MAX_MARSHAL_OBJECTS)
      throw containerLimitError(
        "PYZ TOC object count",
        this.state.referencesUsed,
        MAX_MARSHAL_OBJECTS,
      );
  }

  #assertBlobBounds(length: number): void {
    this.#assertBounds(length, "blob length", MAX_MARSHAL_STRING_BYTES);
  }
}

const asciiString = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");

const decodeUtf8 = (bytes: Uint8Array): string => {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (cause: unknown) {
    throw readerFailure("string value is not valid UTF-8", cause);
  }
};

const projectName = (value: MarshalValue): string => {
  if (value.kind !== "string" || typeof value.value !== "string")
    throw readerFailure("PYZ TOC names must be strings");
  return value.value;
};

const projectInteger = (
  value: MarshalValue | undefined,
  subject: string,
): number => {
  if (
    value === undefined ||
    value.kind !== "int" ||
    typeof value.value !== "number" ||
    value.value < 0 ||
    !Number.isSafeInteger(value.value)
  )
    throw readerFailure(
      `PYZ TOC entry ${subject} is missing, out of range, or not produced by ZlibArchive`,
    );
  return value.value;
};

const projectItemCode = (value: MarshalValue | undefined): number => {
  if (
    value === undefined ||
    value.kind !== "int" ||
    typeof value.value !== "number"
  )
    throw readerFailure(
      "PYZ TOC entry type code is missing or not produced by ZlibArchive",
    );
  if (value.value < 0 || value.value > 3 || !Number.isInteger(value.value))
    throw readerFailure(
      "PYZ TOC entry type code is outside the 0-3 ZlibArchive item-code range",
    );
  return value.value;
};

const projectEntry = (
  name: MarshalValue,
  rawEntry: MarshalValue,
): PyzTocEntry | undefined => {
  const decodedName = projectName(name);
  if (rawEntry.kind !== "tuple" || !Array.isArray(rawEntry.value))
    throw readerFailure(
      `PYZ TOC entry ${JSON.stringify(decodedName)} is not a tuple`,
    );
  if (rawEntry.value.length !== 3)
    throw readerFailure(
      `PYZ TOC entry ${JSON.stringify(decodedName)} does not carry the (type, position, length) ZlibArchive shape`,
    );
  const [typeCode, position, length] = rawEntry.value;
  const itemCode = projectItemCode(typeCode);
  const item_type =
    itemCode === 0
      ? "module"
      : itemCode === 1
        ? "package"
        : itemCode === 2
          ? "data"
          : "namespace_package";
  return pyzTocEntrySchema.parse({
    name: decodedName,
    item_type_code: itemCode,
    item_type,
    position: projectInteger(position, "position"),
    length: projectInteger(length, "length"),
  });
};

/** Parse a bounded PYZ TOC marshal payload. */
export const parsePyzToc = (bytes: Uint8Array, tocPosition: number): PyzToc => {
  const reader = new MarshalReader(bytes);
  const top = reader.readObject(0);
  const entries: PyzTocEntry[] = [];
  if (top.kind === "dict") {
    const pairs = top.value as readonly (readonly [
      MarshalValue,
      MarshalValue,
    ])[];
    for (const [key, value] of pairs) {
      const entry = projectEntry(key, value);
      if (entry !== undefined) entries.push(entry);
    }
  } else if (top.kind === "list") {
    const items = top.value as readonly MarshalValue[];
    for (const item of items) {
      if (
        item.kind !== "tuple" ||
        !Array.isArray(item.value) ||
        item.value.length !== 2
      )
        throw readerFailure(
          "PYZ TOC list members must be (name, entry) tuples",
        );
      const entry = projectEntry(item.value[0], item.value[1]);
      if (entry !== undefined) entries.push(entry);
    }
  } else
    throw readerFailure(
      "PYZ TOC must be a dict or a list of (name, entry) tuples",
    );
  const limitations: string[] = [];
  if (reader.state.position !== bytes.length)
    limitations.push(
      `PYZ TOC parse stopped at byte ${String(reader.state.position)} of ${String(bytes.length)}; trailing marshal bytes were not interpreted.`,
    );
  return pyzTocSchema.parse({
    entries,
    toc_position: tocPosition,
    limitations,
  });
};
