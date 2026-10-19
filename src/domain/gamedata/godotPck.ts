import { createHash } from "node:crypto";
import { z } from "zod";

import {
  gamedataPageSchema,
  gamedataArtifactSchema,
  pagedSliceSchema,
  sliceEntries,
} from "./gamedataShared.js";
import { localPathStringSchema } from "../localPath.js";

/** "GDPC" read as a little-endian 32-bit value, the only pack magic. */
export const PCK_MAGIC = 0x43504447;
/** Godot 4.x pack flags (file_access_pack.h, engine 4.3). */
export const PACK_DIR_ENCRYPTED = 1 << 0;
export const PACK_REL_FILEBASE = 1 << 1;
/** Godot 4.x per-entry flags (engine 4.3). */
export const PACK_FILE_ENCRYPTED = 1 << 0;
/** v2 headers reserve 16 additional 32-bit words between file_base and the directory. */
export const PCK_V2_RESERVED_BYTES = 64;
/** Single-entry extraction budget; entries above this refuse extraction. */
export const PCK_EXTRACTION_MAX_BYTES = 128 * 1024 * 1024;
/** Directory entries parsed per pack; larger packs stay unsupported rather than truncated. */
export const PCK_MAX_ENTRIES = 500_000;

/** Encrypted indexes and bodies are reported as unknowns; call keys are never read. */
export const CALLER_KEY_NOT_READ = "encrypted (caller-supplied key not read)";

/**
 * One indexed pack member. `data_offset` is absolute within the inspected
 * artifact (footer relocation and `rel_filebase` applied); `stored_offset`
 * is the value the index declared. Bodies are never parsed, decompressed or
 * decrypted.
 */
export const godotPckEntrySchema = z.strictObject({
  path: z.string().min(1),
  stored_offset: z.number().int().nonnegative(),
  data_offset: z.number().int().nonnegative(),
  size: z.number().int().nonnegative(),
  md5_hex: z.string().regex(/^[0-9a-f]{32}$/u),
  flags: z.number().int().nonnegative().max(0xffffffff).nullable(),
  encrypted: z.boolean(),
});
export type GodotPckEntry = z.infer<typeof godotPckEntrySchema>;

/** Directory projection: a complete readable index, or one typed unknown. */
export const godotPckIndexSchema = z.discriminatedUnion("readable", [
  z.strictObject({
    readable: z.literal(true),
    entries: z.array(godotPckEntrySchema),
    slice: pagedSliceSchema,
  }),
  z.strictObject({
    readable: z.literal(false),
    reason: z.literal("encrypted_index"),
    detail: z.literal(CALLER_KEY_NOT_READ),
    file_count: z.null(),
    entries: z.null(),
    directory_offset: z.number().int().min(0),
    unknowns: z.array(
      z.strictObject({
        kind: z.literal("encrypted-index"),
        detail: z.literal(CALLER_KEY_NOT_READ),
      }),
    ),
  }),
]);
export type GodotPckIndex = z.infer<typeof godotPckIndexSchema>;

/** Optional bounded single-entry body fact: digest only, written file, no content. */
export const godotPckExtractionSchema = z.strictObject({
  path: z.string().min(1),
  output_path: localPathStringSchema,
  bytes: z.number().int().min(0),
  sha256: z.string().regex(/^[0-9a-f]{64}$/u),
  stored_md5_hex: z.string().regex(/^[0-9a-f]{32}$/u),
  computed_md5_hex: z.string().regex(/^[0-9a-f]{32}$/u),
  md5_matches_stored: z.boolean(),
});
export type GodotPckExtraction = z.infer<typeof godotPckExtractionSchema>;

/** Structure-only v1/v2 pack observation; encrypted sections stay typed unknowns. */
export const godotPckReportSchema = z
  .strictObject({
    artifact: gamedataArtifactSchema,
    container: z.enum(["standalone", "embedded-with-footer"]),
    footer: z
      .strictObject({
        pck_start: z.number().int().nonnegative(),
        pck_bytes: z.number().int().nonnegative(),
      })
      .nullable(),
    magic_offset: z.number().int().nonnegative(),
    format_version: z.union([z.literal(1), z.literal(2)]),
    engine: z.strictObject({
      major: z.number().int().nonnegative(),
      minor: z.number().int().nonnegative(),
      patch: z.number().int().nonnegative(),
    }),
    pack_flags: z.number().int().nonnegative().max(0xffffffff).nullable(),
    dir_encrypted_flag: z.boolean(),
    rel_filebase: z.boolean(),
    file_base: z.number().int().nonnegative(),
    reserved_bytes: z.number().int().nonnegative(),
    directory_offset: z.number().int().nonnegative(),
    index: godotPckIndexSchema,
    encrypted_entry_count: z.number().int().nonnegative(),
    extraction: godotPckExtractionSchema.nullable(),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    const bound = report.artifact.bytes;
    const check = (offset: number, bytes: number, path: string[]) => {
      if (offset > bound || bytes > bound - offset)
        context.addIssue({
          code: "custom",
          path,
          message: "Reported byte range is outside the inspected artifact.",
        });
    };
    check(report.magic_offset, 0, ["magic_offset"]);
    check(report.directory_offset, 0, ["directory_offset"]);
    if (report.footer !== null)
      check(report.footer.pck_start, report.footer.pck_bytes, ["footer"]);
    if (report.index.readable)
      for (const [index, entry] of report.index.entries.entries())
        check(entry.data_offset, entry.size, [
          "index",
          "entries",
          String(index),
          "data_offset",
        ]);
  });
export type GodotPckReport = z.infer<typeof godotPckReportSchema>;

export const inspectGodotPckInputSchema = z.strictObject({
  path: localPathStringSchema,
  ...gamedataPageSchema.shape,
  extract: z
    .strictObject({
      entry_path: z.string().min(1).max(65536),
      output_directory: localPathStringSchema,
    })
    .optional(),
});
export type InspectGodotPckInput = z.infer<typeof inspectGodotPckInputSchema>;

/** A pack header was found but its declared structure cannot be parsed. */
export class PckFormatError extends Error {
  constructor(
    readonly reason: "invalid_format" | "unsupported_version",
    message: string,
  ) {
    super(message);
  }
}

/** The artifact carries no GDPC header at offset 0 nor an embedded footer. */
export class PckNotFoundError extends Error {
  constructor(message: string) {
    super(message);
  }
}

const readU32 = (bytes: Buffer, offset: number): number =>
  bytes.readUInt32LE(offset);
const readU64 = (bytes: Buffer, offset: number): number => {
  const value = bytes.readBigUInt64LE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new PckFormatError(
      "invalid_format",
      `Declared 64-bit value at offset ${String(offset)} exceeds the supported range: ${value.toString()} bytes`,
    );
  return Number(value);
};

/** Locate the GDPC header: standalone first, then the embedded footer layout. */
const locateHeader = (
  bytes: Buffer,
):
  | {
      magic_offset: number;
      footer: { pck_start: number; pck_bytes: number } | null;
    }
  | undefined => {
  if (bytes.length >= 4 && readU32(bytes, 0) === PCK_MAGIC)
    return { magic_offset: 0, footer: null };
  if (bytes.length >= 12) {
    const end = bytes.length;
    if (readU32(bytes, end - 4) !== PCK_MAGIC) return undefined;
    const pck_bytes = readU64(bytes, end - 12);
    const pck_start = end - pck_bytes - 12;
    if (
      pck_start < 0 ||
      pck_start + 4 > end ||
      readU32(bytes, pck_start) !== PCK_MAGIC
    )
      return undefined;
    return { magic_offset: pck_start, footer: { pck_start, pck_bytes } };
  }
  return undefined;
};

const readUtf8 = (
  bytes: Buffer,
  start: number,
  length: number,
): string | null => {
  let decoded: string;
  try {
    decoded = bytes.subarray(start, start + length).toString("utf8");
  } catch {
    return null;
  }
  return Buffer.byteLength(decoded, "utf8") === length ? decoded : null;
};

export interface ParsedGodotPck {
  readonly report: Omit<GodotPckReport, "artifact" | "extraction">;
  readonly allEntries: readonly GodotPckEntry[];
  readonly locateEntry: (entryPath: string) => GodotPckEntry | undefined;
}

/**
 * Parse the pack header and directory index without touching entry bodies.
 * Callers must not have more than one of these reports alive per admission
 * because entry paths retain target-originating text.
 */
export const parseGodotPck = (
  bytes: Buffer,
  page: { readonly entries_start: number; readonly entries_limit: number },
): ParsedGodotPck => {
  const located = locateHeader(bytes);
  if (located === undefined)
    throw new PckNotFoundError(
      "No GDPC pack header: the artifact has neither the magic at offset 0 nor the embedded footer trailer",
    );
  const { magic_offset: at, footer } = located;
  if (at + 20 > bytes.length)
    throw new PckFormatError(
      "invalid_format",
      `Pack header at ${String(at)} is truncated before the version fields`,
    );
  const formatVersion = readU32(bytes, at + 4);
  if (formatVersion !== 1 && formatVersion !== 2)
    throw new PckFormatError(
      "unsupported_version",
      `Pack format version ${String(formatVersion)} is reported but not parsed; supported versions are 1 (Godot 3.x) and 2 (Godot 4.x)`,
    );
  const engineMajor = readU32(bytes, at + 8);
  const engineMinor = readU32(bytes, at + 12);
  const enginePatch = readU32(bytes, at + 16);
  let cursor = at + 20;
  let packFlags: number | null = null;
  let fileBase = 0;
  let reservedBytes = 0;
  let relFilebase = false;
  let dirEncrypted = false;
  if (formatVersion === 2) {
    packFlags = readU32(bytes, cursor);
    dirEncrypted = (packFlags & PACK_DIR_ENCRYPTED) !== 0;
    relFilebase = (packFlags & PACK_REL_FILEBASE) !== 0;
    cursor += 4;
    fileBase = readU64(bytes, cursor);
    cursor += 8;
    if (relFilebase) fileBase += at;
    reservedBytes = PCK_V2_RESERVED_BYTES;
    cursor += PCK_V2_RESERVED_BYTES;
  }
  /** Absolute entry locations are pack_header + file_base + stored offset. */
  const packBase = at + fileBase;
  const directoryOffset = cursor;
  if (dirEncrypted) {
    return {
      report: {
        container: footer === null ? "standalone" : "embedded-with-footer",
        footer,
        magic_offset: at,
        format_version: formatVersion,
        engine: {
          major: engineMajor,
          minor: engineMinor,
          patch: enginePatch,
        },
        pack_flags: packFlags,
        dir_encrypted_flag: dirEncrypted,
        rel_filebase: relFilebase,
        file_base: fileBase,
        reserved_bytes: reservedBytes,
        directory_offset: directoryOffset,
        index: {
          readable: false,
          reason: "encrypted_index",
          detail: CALLER_KEY_NOT_READ,
          file_count: null,
          entries: null,
          directory_offset: directoryOffset,
          unknowns: [{ kind: "encrypted-index", detail: CALLER_KEY_NOT_READ }],
        },
        encrypted_entry_count: 0,
        limitations: [
          `The directory index block starting at offset ${String(directoryOffset)} is encrypted; ${CALLER_KEY_NOT_READ}, so entry names, offsets and sizes are unknown rather than absent.`,
          `Entries whose index declares the body also encrypted would report the same unknown; bodies are never read, decompressed or decrypted.`,
        ],
      },
      allEntries: [],
      locateEntry: () => undefined,
    };
  }
  if (directoryOffset + 4 > bytes.length)
    throw new PckFormatError(
      "invalid_format",
      `Directory file-count field at ${String(directoryOffset)} is outside the artifact`,
    );
  const fileCount = readU32(bytes, directoryOffset);
  if (fileCount > PCK_MAX_ENTRIES)
    throw new PckFormatError(
      "invalid_format",
      `Directory declares ${String(fileCount)} entries, above the ${String(PCK_MAX_ENTRIES)}-entry parse bound`,
    );
  cursor += 4;
  const allEntries: GodotPckEntry[] = [];
  let encryptedEntryCount = 0;
  const entrySize = formatVersion === 2 ? 30 : 26;
  for (let index = 0; index < fileCount; index++) {
    const start = cursor;
    if (start + entrySize > bytes.length)
      throw new PckFormatError(
        "invalid_format",
        `Directory entry ${String(index)} at ${String(start)} is truncated`,
      );
    const pathLength = readU32(bytes, cursor);
    cursor += 4;
    if (pathLength > 65536 || start + pathLength > bytes.length)
      throw new PckFormatError(
        "invalid_format",
        `Directory entry ${String(index)} declares an unusable path length ${String(pathLength)} at ${String(start)}`,
      );
    const path = readUtf8(bytes, cursor, pathLength);
    if (path === null || path.length === 0)
      throw new PckFormatError(
        "invalid_format",
        `Directory entry ${String(index)} path is not valid UTF-8`,
      );
    cursor += pathLength;
    if (cursor + entrySize - 4 > bytes.length)
      throw new PckFormatError(
        "invalid_format",
        `Directory entry ${String(index)} fixed fields at ${String(cursor)} are truncated`,
      );
    const storedOffset = readU64(bytes, cursor);
    cursor += 8;
    const size = readU64(bytes, cursor);
    cursor += 8;
    const md5Hex = bytes.subarray(cursor, cursor + 16).toString("hex");
    cursor += 16;
    let flags: number | null = null;
    let encrypted = false;
    if (formatVersion === 2) {
      flags = readU32(bytes, cursor);
      cursor += 4;
      encrypted = (flags & PACK_FILE_ENCRYPTED) !== 0;
      if (encrypted) encryptedEntryCount++;
    }
    allEntries.push({
      path,
      stored_offset: storedOffset,
      data_offset: packBase + storedOffset,
      size,
      md5_hex: md5Hex,
      flags,
      encrypted,
    });
  }
  const sliced = sliceEntries(
    allEntries,
    page.entries_start,
    page.entries_limit,
  );
  const encryptedEntryLimitation =
    encryptedEntryCount > 0
      ? [
          `The index reports ${String(encryptedEntryCount)} encrypted entr${
            encryptedEntryCount === 1 ? "y" : "ies"
          }; their bodies are unknown and never read.`,
        ]
      : [];
  return {
    report: {
      container: footer === null ? "standalone" : "embedded-with-footer",
      footer,
      magic_offset: at,
      format_version: formatVersion,
      engine: { major: engineMajor, minor: engineMinor, patch: enginePatch },
      pack_flags: packFlags,
      dir_encrypted_flag: dirEncrypted,
      rel_filebase: relFilebase,
      file_base: fileBase,
      reserved_bytes: reservedBytes,
      directory_offset: directoryOffset,
      index: {
        readable: true,
        entries: sliced.entries,
        slice: sliced.slice,
      },
      encrypted_entry_count: encryptedEntryCount,
      limitations: [
        `Structure-only inspection: entry paths, offsets, sizes and stored MD5 values are index observations; body bytes were not read, decompressed or decrypted.`,
        `Pack formats v1 and v2 define no compressed-body flag; sizes are stored verbatim bytes on disk.`,
        ...(encryptedEntryLimitation.length > 0
          ? encryptedEntryLimitation
          : []),
      ],
    },
    allEntries,
    locateEntry: (entryPath) =>
      allEntries.find((entry) => entry.path === entryPath),
  };
};

/** Digest one bounded entry body slice without writing or returning content. */
export const digestEntryBody = (
  bytes: Buffer,
  entry: GodotPckEntry,
): { sha256: string; computed_md5_hex: string } => {
  const body = bytes.subarray(
    entry.data_offset,
    entry.data_offset + entry.size,
  );
  return {
    sha256: createHash("sha256").update(body).digest("hex"),
    computed_md5_hex: createHash("md5").update(body).digest("hex"),
  };
};
