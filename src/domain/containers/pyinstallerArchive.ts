import { z } from "zod";
import { canonicalBase64Schema } from "../stringPatterns.js";
import {
  ContainerFormatError,
  containerLimitError,
} from "./containerFormatError.js";
import { pyzTocSchema } from "./pyzToc.js";
import { pycHeaderSchema } from "./pycHeader.js";

/**
 * PyInstaller CArchive (PKG) inventory, following
 * PyInstaller/archive/readers.py and pyinstxtractor's dual-cookie reader:
 *
 * cookie (PyInstaller 2.0):  !8sIIII  magic pkg_length toc toc_length pyvers
 * cookie (PyInstaller 2.1+): !8sIIII64s (64-byte Python library name appended)
 * TOC entry:                 entry_length !I, offset !I, data length !I,
 *                            uncompressed length !I, compression flag !B,
 *                            type code !c, NUL-padded UTF-8 name
 *
 * Positions are absolute and derive from archive_start = cookie_end -
 * package_length. Entries are indexed only: no entry content is decompressed,
 * decrypted, or otherwise interpreted beyond optional pyc-header facts.
 */

export const CARCHIVE_COOKIE_BYTES_20 = 24;
export const CARCHIVE_COOKIE_BYTES_21 = 88;
export const CARCHIVE_MAGIC_LENGTH = 8;
export const CARCHIVE_TOC_ENTRY_HEADER_BYTES = 18;
export const CARCHIVE_MAGIC_SEARCH_CHUNK_BYTES = 8192;
export const MAX_CARCHIVE_TOC_BYTES = 64 * 1024 * 1024;
export const MAX_CARCHIVE_ENTRIES = 262_144;
export const MAX_CARCHIVE_NAME_BYTES = 4096;
export const MAX_PYZ_HEADER_BYTES = 12;

const nonnegative = z.number().int().nonnegative();
const base64 = canonicalBase64Schema;

export const carchiveCookieSchema = z.strictObject({
  cookie_offset: nonnegative,
  cookie_bytes: z.union([
    z.literal(CARCHIVE_COOKIE_BYTES_20),
    z.literal(CARCHIVE_COOKIE_BYTES_21),
  ]),
  cookie_format: z.enum(["pyinstaller-2.0", "pyinstaller-2.1-plus"]),
  /** The byte length the bootloader believes the CArchive occupies. */
  package_length: nonnegative,
  toc_offset: nonnegative,
  toc_length: nonnegative,
  python_version: nonnegative,
  python_libname: z.string().nullable(),
  python_libname_bytes: nonnegative.nullable(),
  /** archive_start = cookie end - package_length, per PyInstaller readers. */
  archive_start: nonnegative,
  archive_end: nonnegative,
  /** Appended bytes after the cookie, outside the declared package length. */
  tail_bytes: nonnegative,
  limitations: z.array(z.string()),
});
export type CarchiveCookie = z.infer<typeof carchiveCookieSchema>;

export const CARCHIVE_TYPECODES = [
  "b",
  "d",
  "z",
  "Z",
  "M",
  "m",
  "s",
  "x",
  "o",
  "l",
] as const;

const CARCHIVE_TYPECODE_LABELS: Readonly<Record<string, string>> = {
  b: "binary",
  d: "dependency",
  z: "pyz-archive",
  Z: "zipfile-archive",
  M: "python-package",
  m: "python-module",
  s: "python-script",
  x: "data",
  o: "runtime-option",
  l: "splash-resources",
};

export const carchivePycHeaderStateSchema = z.enum([
  "parsed",
  "opaque",
  "compressed",
  "not-module-data",
]);
export const carchiveTocEntrySchema = z.strictObject({
  name: z.string().nullable(),
  name_bytes_base64: base64.nullable(),
  typecode: z.enum(CARCHIVE_TYPECODES),
  type_label: z.string(),
  entry_length: nonnegative,
  position: nonnegative,
  compressed_size: nonnegative,
  uncompressed_size: nonnegative,
  compressed: z.boolean(),
  /**
   * The CArchive TOC carries no per-entry encryption flag. Entries are
   * recorded as unencrypted-by-TOC; the global limitation explains what that
   * cannot rule out.
   */
  encrypted: z.literal(false),
  pyc_header_state: carchivePycHeaderStateSchema,
  pyc_header: pycHeaderSchema.nullable(),
  unrecognized_typecode: z.boolean(),
});
export type CarchiveTocEntry = z.infer<typeof carchiveTocEntrySchema>;

export const pyzArchiveInventorySchema = z.strictObject({
  name: z.string().nullable(),
  archive_position: nonnegative,
  python_magic_bytes_base64: base64.nullable(),
  toc_position: nonnegative,
  pyz_toc: pyzTocSchema.nullable(),
  limitations: z.array(z.string()),
});
export type PyzArchiveInventory = z.infer<typeof pyzArchiveInventorySchema>;

export const pyinstallerInventorySchema = z.strictObject({
  cookie: carchiveCookieSchema,
  toc_offset: nonnegative,
  entries: z.array(carchiveTocEntrySchema),
  pyz_archives: z.array(pyzArchiveInventorySchema),
  limitations: z.array(z.string()),
});

const CARCHIVE_MAGIC = new Uint8Array([
  0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e,
]);

const byteAt = (bytes: Uint8Array, offset: number): number => {
  const byte = bytes[offset];
  if (byte === undefined)
    throw new ContainerFormatError(
      "format",
      `Container bytes end at index ${String(offset)}`,
    );
  return byte;
};

const readUint32BE = (bytes: Uint8Array, offset: number): number =>
  ((byteAt(bytes, offset) << 24) |
    (byteAt(bytes, offset + 1) << 16) |
    (byteAt(bytes, offset + 2) << 8) |
    byteAt(bytes, offset + 3)) >>>
  0;

const readByteChunk = (
  handle: { read: (position: number, length: number) => Promise<Uint8Array> },
  position: number,
  length: number,
  signal: AbortSignal | undefined,
): Promise<Uint8Array> => {
  if (signal?.aborted)
    throw new ContainerFormatError(
      "format",
      "PyInstaller cookie scan cancelled",
      {
        cause: signal.reason,
      },
    );
  return handle.read(position, length);
};

/** Scan backwards from EOF for the CArchive cookie magic, bounded to the tail. */
export const locateCarchiveCookie = async (
  handle: { read: (position: number, length: number) => Promise<Uint8Array> },
  fileBytes: number,
  signal?: AbortSignal,
): Promise<number> => {
  if (fileBytes < CARCHIVE_MAGIC_LENGTH)
    throw new ContainerFormatError(
      "format",
      "Selected file is shorter than a CArchive cookie magic",
    );
  let end = fileBytes;
  while (end >= CARCHIVE_MAGIC_LENGTH) {
    const start = Math.max(end - CARCHIVE_MAGIC_SEARCH_CHUNK_BYTES, 0);
    const chunk = await readByteChunk(handle, start, end - start, signal);
    for (
      let offset = chunk.length - CARCHIVE_MAGIC_LENGTH;
      offset >= 0;
      offset -= 1
    ) {
      const candidate = chunk.subarray(offset, offset + CARCHIVE_MAGIC_LENGTH);
      if (CARCHIVE_MAGIC.every((byte, index) => candidate[index] === byte))
        return start + offset;
    }
    // Overlap by magic length - 1 so a match split across chunks cannot hide.
    if (start === 0) break;
    end = start + CARCHIVE_MAGIC_LENGTH - 1;
  }
  throw new ContainerFormatError(
    "format",
    "No CArchive cookie magic found near the end of the selected file",
  );
};

/** Trim trailing NUL padding (JAR/CArchive name fields are zero padded). */
const trimTrailingNul = (bytes: Uint8Array): Uint8Array => {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end -= 1;
  return bytes.subarray(0, end);
};

/**
 * Distinguish the 88-byte 2.1+ cookie by its 64-byte Python library name
 * after the 24-byte prefix, following pyinstxtractor's b"python" probe.
 */
export const carchiveCookieBytesFor = (followsCookie: Uint8Array): 24 | 88 => {
  const probe = Array.from(followsCookie.subarray(0, 64), (byte) => byte & 0xff)
    .map((byte) => String.fromCharCode(byte).toLowerCase())
    .join("");
  return probe.includes("python")
    ? CARCHIVE_COOKIE_BYTES_21
    : CARCHIVE_COOKIE_BYTES_20;
};

/** Parse one cookie byte range (24 or 88 bytes) already read from the tail. */
export const parseCarchiveCookieBytes = (
  cookieBytes: Uint8Array,
  cookieBytesCount: 24 | 88,
  cookieOffset: number,
  fileBytes: number,
): CarchiveCookie => {
  const cookieEnd = cookieOffset + cookieBytesCount;
  const tailBytes = fileBytes - cookieEnd;
  const packageLength = readUint32BE(cookieBytes, 8);
  const tocOffset = readUint32BE(cookieBytes, 12);
  const limitations: string[] = [];
  const archiveStartValue = cookieEnd - packageLength;
  const archiveStart = Math.max(archiveStartValue, 0);
  if (archiveStartValue < 0)
    limitations.push(
      `CArchive package_length ${String(packageLength)} exceeds the ${String(cookieOffset + cookieBytesCount)} bytes before and inside the cookie; archive_start is clamped to zero.`,
    );
  if (tocOffset > packageLength)
    limitations.push(
      `CArchive TOC offset ${String(tocOffset)} lies beyond the declared package length ${String(packageLength)}; declared offsets are preserved.`,
    );
  return carchiveCookieSchema.parse({
    cookie_offset: cookieOffset,
    cookie_bytes: cookieBytesCount,
    cookie_format:
      cookieBytesCount === CARCHIVE_COOKIE_BYTES_21
        ? "pyinstaller-2.1-plus"
        : "pyinstaller-2.0",
    package_length: packageLength,
    toc_offset: tocOffset,
    toc_length: readUint32BE(cookieBytes, 16),
    python_version: readUint32BE(cookieBytes, 20),
    python_libname:
      cookieBytesCount === CARCHIVE_COOKIE_BYTES_21
        ? new TextDecoder("ascii").decode(
            trimTrailingNul(cookieBytes.subarray(24, CARCHIVE_COOKIE_BYTES_21)),
          )
        : null,
    python_libname_bytes:
      cookieBytesCount === CARCHIVE_COOKIE_BYTES_21
        ? trimTrailingNul(cookieBytes.subarray(24, CARCHIVE_COOKIE_BYTES_21))
            .length
        : null,
    archive_start: archiveStart,
    archive_end: cookieEnd,
    tail_bytes: Math.max(tailBytes, 0),
    limitations,
  });
};

interface RawTocEntry {
  readonly entryLength: number;
  readonly relativeOffset: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly compressed: boolean;
  readonly typecode: string;
  readonly name: string | null;
  readonly nameBytes: Uint8Array;
}

const decodeName = (nameBytes: Uint8Array): string | null => {
  if (nameBytes.length > MAX_CARCHIVE_NAME_BYTES)
    throw containerLimitError(
      "CArchive TOC entry name",
      nameBytes.length,
      MAX_CARCHIVE_NAME_BYTES,
    );
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(nameBytes);
  } catch {
    return null;
  }
};

const parseRawTocEntries = (toc: Uint8Array): RawTocEntry[] => {
  const entries: RawTocEntry[] = [];
  let cursor = 0;
  while (cursor < toc.length) {
    if (cursor + 4 > toc.length)
      throw new ContainerFormatError(
        "format",
        `CArchive TOC entry length at byte ${String(cursor)} is truncated`,
      );
    const entryLength = readUint32BE(toc, cursor);
    if (entryLength < CARCHIVE_TOC_ENTRY_HEADER_BYTES)
      throw new ContainerFormatError(
        "format",
        `CArchive TOC entry at byte ${String(cursor)} declares an implausible entry length ${String(entryLength)}`,
      );
    if (cursor + entryLength > toc.length)
      throw new ContainerFormatError(
        "format",
        `CArchive TOC entry at byte ${String(cursor)} declares ${String(entryLength)} bytes, exceeding the ${String(toc.length)}-byte TOC`,
      );
    const entry = toc.subarray(cursor, cursor + entryLength);
    const rawName = entry.subarray(CARCHIVE_TOC_ENTRY_HEADER_BYTES);
    entries.push({
      entryLength,
      relativeOffset: readUint32BE(entry, 4),
      compressedSize: readUint32BE(entry, 8),
      uncompressedSize: readUint32BE(entry, 12),
      compressed: byteAt(entry, 16) !== 0,
      typecode: String.fromCharCode(byteAt(entry, 17)),
      name: decodeName(trimTrailingNul(rawName)),
      nameBytes: rawName,
    });
    cursor += entryLength;
    if (entries.length > MAX_CARCHIVE_ENTRIES)
      throw containerLimitError(
        "CArchive TOC entries",
        entries.length,
        MAX_CARCHIVE_ENTRIES,
      );
  }
  return entries;
};

/**
 * Parse bounded CArchive TOC bytes into the value-free entry inventory. The
 * caller supplies absolute pyc-header facts separately; this projection keeps
 * module-entry pyc facts opaque.
 */
export const parseCarchiveToc = (
  tocBytes: Uint8Array,
  archiveStart: number,
): { readonly entries: CarchiveTocEntry[]; readonly limitations: string[] } => {
  const raw = parseRawTocEntries(tocBytes);
  const limitations: string[] = [
    "CArchive TOC entries carry no per-entry encryption flag; entry contents are never decrypted and an encrypted build's data is not detected here.",
  ];
  const entries = raw.map((rawEntry): CarchiveTocEntry => {
    const recognized = (CARCHIVE_TYPECODES as readonly string[]).includes(
      rawEntry.typecode,
    );
    const isModuleData =
      recognized &&
      (rawEntry.typecode === "m" ||
        rawEntry.typecode === "M" ||
        rawEntry.typecode === "s");
    return carchiveTocEntrySchema.parse({
      name: rawEntry.name,
      name_bytes_base64:
        rawEntry.name === null
          ? Buffer.from(
              rawEntry.nameBytes.subarray(0, MAX_CARCHIVE_NAME_BYTES),
            ).toString("base64")
          : null,
      typecode: recognized ? rawEntry.typecode : "x",
      type_label: recognized
        ? (CARCHIVE_TYPECODE_LABELS[rawEntry.typecode] ?? rawEntry.typecode)
        : `unrecognized (${JSON.stringify(rawEntry.typecode)})`,
      entry_length: rawEntry.entryLength,
      position: archiveStart + rawEntry.relativeOffset,
      compressed_size: rawEntry.compressedSize,
      uncompressed_size: rawEntry.uncompressedSize,
      compressed: rawEntry.compressed,
      encrypted: false as const,
      pyc_header_state: isModuleData
        ? rawEntry.compressed
          ? "compressed"
          : "opaque"
        : "not-module-data",
      pyc_header: null,
      unrecognized_typecode: !recognized,
    });
  });
  return { entries, limitations };
};

const PYZ_MAGIC_PREFIX = new Uint8Array([0x50, 0x59, 0x5a, 0x00]);

export const pyzHeaderSchema = z.strictObject({
  python_magic_bytes_base64: base64,
  toc_position: nonnegative,
});
export type PyzHeader = z.infer<typeof pyzHeaderSchema>;

/** Parse the 12-byte PYZ archive header (magic, pyc magic, TOC offset). */
export const parsePyzHeader = (bytes: Uint8Array): PyzHeader => {
  if (bytes.length < MAX_PYZ_HEADER_BYTES)
    throw new ContainerFormatError(
      "format",
      `PYZ header requires ${String(MAX_PYZ_HEADER_BYTES)} bytes; observed ${String(bytes.length)}`,
    );
  if (!PYZ_MAGIC_PREFIX.every((byte, index) => bytes[index] === byte))
    throw new ContainerFormatError(
      "format",
      "Embedded archive magic does not match PYZ\\0",
    );
  const signedToc =
    (byteAt(bytes, 8) << 24) |
    (byteAt(bytes, 9) << 16) |
    (byteAt(bytes, 10) << 8) |
    byteAt(bytes, 11);
  if (signedToc < 0)
    throw new ContainerFormatError(
      "format",
      `PYZ TOC position ${String(signedToc)} is negative`,
    );
  return pyzHeaderSchema.parse({
    python_magic_bytes_base64: Buffer.from(bytes.subarray(4, 8)).toString(
      "base64",
    ),
    toc_position: signedToc,
  });
};
