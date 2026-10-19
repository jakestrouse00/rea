import { z } from "zod";

import {
  gamedataArtifactSchema,
  gamedataPageSchema,
  pagedSliceSchema,
  sliceEntries,
} from "./gamedataShared.js";
import { localPathStringSchema } from "../localPath.js";

/** VPK directory signature and structure limits (Valve VPK format). */
export const VPK_SIGNATURE = 0x55aa1234;
export const VPK_DIRECTORY_ARCHIVE_INDEX = 0x7fff;
export const VPK_ENTRY_TERMINATOR = 0xffff;
export const VPK_V2_HEADER_BYTES = 28;
export const VPK_V1_HEADER_BYTES = 12;
export const VPK_MAX_ENTRIES = 500_000;
export const VPK_MAX_TREE_BYTES = 512 * 1024 * 1024;

/** One directory-tree entry; archive bodies are never opened. */
export const vpkEntrySchema = z.strictObject({
  path: z.string().min(1),
  crc32_hex: z.string().regex(/^[0-9a-f]{8}$/u),
  preload_bytes: z.number().int().nonnegative(),
  archive_index: z.number().int().nonnegative().max(0xffff),
  entry_offset: z.number().int().nonnegative().max(0xffffffff),
  entry_length: z.number().int().nonnegative().max(0xffffffff),
  total_size: z.number().int().nonnegative(),
  stored_in_directory: z.boolean(),
});
export type VpkEntry = z.infer<typeof vpkEntrySchema>;

/** Structure-only inventory of the caller-selected `_dir.vpk` (or single-file VPK). */
export const vpkReportSchema = z
  .strictObject({
    artifact: gamedataArtifactSchema,
    format_version: z.union([z.literal(1), z.literal(2)]),
    header_bytes: z.number().int().nonnegative(),
    tree_size: z.number().int().nonnegative(),
    tree_offset: z.number().int().nonnegative(),
    sections: z
      .strictObject({
        file_data_bytes: z.number().int().nonnegative(),
        archive_md5_bytes: z.number().int().nonnegative(),
        other_md5_bytes: z.number().int().nonnegative(),
        signature_bytes: z.number().int().nonnegative(),
      })
      .nullable(),
    directory_data_offset: z.number().int().nonnegative(),
    entries: z.array(vpkEntrySchema),
    slice: pagedSliceSchema,
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    const bound = report.artifact.bytes;
    if (report.tree_size > bound - report.tree_offset)
      context.addIssue({
        code: "custom",
        path: ["tree_size"],
        message: "Declared tree exceeds the inspected artifact.",
      });
  });
export type VpkReport = z.infer<typeof vpkReportSchema>;

export const inspectVpkArchiveInputSchema = z.strictObject({
  path: localPathStringSchema,
  ...gamedataPageSchema.shape,
});

/** The artifact is not a VPK directory file. */
export class VpkFormatError extends Error {
  constructor(
    readonly reason: "invalid_format" | "unsupported_version",
    message: string,
  ) {
    super(message);
  }
}

const readU32 = (bytes: Buffer, offset: number): number =>
  bytes.readUInt32LE(offset);
type Cursor = { readonly bytes: Buffer; offset: number };

const readCString = (cursor: Cursor, treeEnd: number): string | null => {
  const start = cursor.offset;
  const limit = Math.max(0, Math.min(4096, treeEnd - start));
  for (let i = 0; i < limit; i++) {
    if (cursor.bytes[start + i] === 0) {
      const value = cursor.bytes.subarray(start, start + i).toString("utf8");
      cursor.offset = start + i + 1;
      return Buffer.byteLength(value, "utf8") === i ? value : null;
    }
  }
  throw new VpkFormatError(
    "invalid_format",
    `Directory tree string at offset ${String(start)} overruns its region or the length bound`,
  );
};
const joinEntryPath = (dir: string, name: string, ext: string): string => {
  const filename = ext === "" ? name : `${name}.${ext}`;
  return dir === "" ? filename : `${dir}/${filename}`;
};

/** Walk the three-level tree and collect entries without reading file data. */
export const parseVpkTree = (bytes: Buffer): readonly VpkEntry[] => {
  const headerBytes =
    readU32(bytes, 4) === 1 ? VPK_V1_HEADER_BYTES : VPK_V2_HEADER_BYTES;
  const treeSize = readU32(bytes, 8);
  const treeEnd = headerBytes + treeSize;
  const cursor: Cursor = { bytes, offset: headerBytes };
  const entries: VpkEntry[] = [];
  while (cursor.offset < treeEnd) {
    const extStart = cursor.offset;
    const ext = readCString(cursor, treeEnd);
    if (ext === null)
      throw new VpkFormatError(
        "invalid_format",
        `Directory tree extension at ${String(extStart)} is not valid UTF-8`,
      );
    if (ext === "") break;
    for (;;) {
      const dirStart = cursor.offset;
      const dir = readCString(cursor, treeEnd);
      if (dir === null)
        throw new VpkFormatError(
          "invalid_format",
          `Directory tree path at ${String(dirStart)} is not valid UTF-8`,
        );
      if (dir === "") break;
      for (;;) {
        const nameStart = cursor.offset;
        const name = readCString(cursor, treeEnd);
        if (name === null)
          throw new VpkFormatError(
            "invalid_format",
            `Directory tree file name at ${String(nameStart)} is not valid UTF-8`,
          );
        if (name === "") break;
        if (cursor.offset + 18 > treeEnd)
          throw new VpkFormatError(
            "invalid_format",
            `Directory entry structure at ${String(cursor.offset)} overruns the declared tree`,
          );
        const structure = cursor.offset;
        const crc32 = bytes.readUInt32LE(cursor.offset);
        const preloadBytes = bytes.readUInt16LE(cursor.offset + 4);
        const archiveIndex = bytes.readUInt16LE(cursor.offset + 6);
        const entryOffset = bytes.readUInt32LE(cursor.offset + 8);
        const entryLength = bytes.readUInt32LE(cursor.offset + 12);
        const terminator = bytes.readUInt16LE(cursor.offset + 16);
        cursor.offset += 18;
        if (terminator !== VPK_ENTRY_TERMINATOR)
          throw new VpkFormatError(
            "invalid_format",
            `Directory entry at ${String(structure)} has terminator 0x${terminator.toString(16)}, expected 0xffff`,
          );
        if (cursor.offset + preloadBytes > treeEnd)
          throw new VpkFormatError(
            "invalid_format",
            `Preload bytes of the entry at ${String(structure)} overruns the declared tree`,
          );
        cursor.offset += preloadBytes;
        entries.push({
          path: joinEntryPath(dir, name, ext),
          crc32_hex: crc32.toString(16).padStart(8, "0"),
          preload_bytes: preloadBytes,
          archive_index: archiveIndex,
          entry_offset: entryOffset,
          entry_length: entryLength,
          total_size: preloadBytes + entryLength,
          stored_in_directory: archiveIndex === VPK_DIRECTORY_ARCHIVE_INDEX,
        });
        if (entries.length > VPK_MAX_ENTRIES)
          throw new VpkFormatError(
            "invalid_format",
            `Directory declares more than ${String(VPK_MAX_ENTRIES)} entries, above the walk bound`,
          );
      }
    }
  }
  return entries;
};

/** Parse the selected directory file: header, sections, and the full tree. */
export const parseVpkArchive = (
  bytes: Buffer,
  page: { readonly entries_start: number; readonly entries_limit: number },
): Omit<VpkReport, "artifact"> => {
  if (bytes.length < VPK_V1_HEADER_BYTES)
    throw new VpkFormatError(
      "invalid_format",
      `Artifact is ${String(bytes.length)} bytes, shorter than the VPK v1 header`,
    );
  if (readU32(bytes, 0) !== VPK_SIGNATURE)
    throw new VpkFormatError(
      "invalid_format",
      `Directory signature 0x${readU32(bytes, 0)
        .toString(16)
        .padStart(
          8,
          "0",
        )} is not the VPK magic 0x55aa1234; the pre-2009 headerless layout is not supported`,
    );
  const formatVersion = readU32(bytes, 4);
  if (formatVersion !== 1 && formatVersion !== 2)
    throw new VpkFormatError(
      "unsupported_version",
      `VPK version ${String(formatVersion)} is reported but not parsed; supported versions are 1 and 2`,
    );
  const headerBytes =
    formatVersion === 1 ? VPK_V1_HEADER_BYTES : VPK_V2_HEADER_BYTES;
  const treeSize = readU32(bytes, 8);
  if (treeSize > VPK_MAX_TREE_BYTES)
    throw new VpkFormatError(
      "invalid_format",
      `Declared tree of ${String(treeSize)} bytes exceeds the ${String(VPK_MAX_TREE_BYTES)}-byte walk bound`,
    );
  if (headerBytes + treeSize > bytes.length)
    throw new VpkFormatError(
      "invalid_format",
      `Declared tree of ${String(treeSize)} bytes at ${String(headerBytes)} overruns the artifact`,
    );
  let sections: VpkReport["sections"] = null;
  if (formatVersion === 2) {
    if (headerBytes > bytes.length)
      throw new VpkFormatError("invalid_format", "VPK v2 header is truncated");
    sections = {
      file_data_bytes: readU32(bytes, 12),
      archive_md5_bytes: readU32(bytes, 16),
      other_md5_bytes: readU32(bytes, 20),
      signature_bytes: readU32(bytes, 24),
    };
  }
  const directoryDataOffset = headerBytes + treeSize;
  const entries = parseVpkTree(bytes);
  const sliced = sliceEntries(entries, page.entries_start, page.entries_limit);
  return {
    format_version: formatVersion,
    header_bytes: headerBytes,
    tree_size: treeSize,
    tree_offset: headerBytes,
    sections,
    directory_data_offset: directoryDataOffset,
    entries: sliced.entries,
    slice: sliced.slice,
    limitations: [
      "Companion archive parts (…_NNN.vpk with matching stems) were not opened; entry offsets, lengths and CRC32 values are directory declarations, not verified observations.",
      "Preload bytes are reported as counts only; inline contents were not read, decoded or extracted.",
      "Entry paths keep the directory tree spelling; archive-relative identity is (archive_index, entry_offset, entry_length).",
    ],
  };
};
