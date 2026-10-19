import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";

/** RPG Maker MV/MZ fake header: "RPGMV" plus version and padding bytes. */
export const RPGMAKER_PREFIX_MAGIC = Buffer.from("RPGMV");
export const RPGMAKER_PREFIX_BYTES = 16;
export const RPGMAKER_SNIFF_BYTES = 8;
/** Candidate asset extensions scanned for the fake header; MV/MZ encrypt these. */
export const RPGMAKER_CANDIDATE_EXTENSIONS = [
  "png",
  "ogg",
  "oga",
  "m4a",
] as const;
export const RPGMAKER_MAX_CANDIDATE_FILES = 20_000;
export const RPGMAKER_MAX_DIRECTORY_DEPTH = 16;

/** Per-file detection fact; contents are never decrypted, stripped or extracted. */
export const rpgmakerAssetSchema = z.strictObject({
  path: z.string().min(1),
  bytes: z.number().int().nonnegative(),
  prefix_present: z.boolean(),
  prefix_hex: z
    .string()
    .regex(/^[0-9a-f]{32}$/u)
    .nullable(),
  following_hex: z
    .string()
    .regex(/^[0-9a-f]{2,16}$/u)
    .nullable(),
  encrypted_kind_guess: z.enum(["png", "ogg", "unknown", "insufficient_bytes"]),
  plain_kind: z.enum(["png", "ogg", "unknown"]),
});
export type RpgmakerAsset = z.infer<typeof rpgmakerAssetSchema>;

/** Detection-only inventory of one caller-selected asset directory. */
export const rpgmakerReportSchema = z.strictObject({
  directory: localPathStringSchema,
  candidate_extensions: z.array(z.enum(RPGMAKER_CANDIDATE_EXTENSIONS)),
  candidate_total: z.number().int().nonnegative(),
  encrypted_count: z.number().int().nonnegative(),
  plain_count: z.number().int().nonnegative(),
  symlink_skipped: z.number().int().nonnegative(),
  unreadable_paths: z.array(z.string()),
  files: z.array(rpgmakerAssetSchema),
  slice: z.strictObject({
    entry_total: z.number().int().nonnegative(),
    entry_start: z.number().int().nonnegative(),
    entry_returned: z.number().int().nonnegative(),
    complete: z.boolean(),
  }),
  limitations: z.array(z.string()),
});
export type RpgmakerReport = z.infer<typeof rpgmakerReportSchema>;

export const inspectRpgmakerAssetPrefixesInputSchema = z.strictObject({
  directory: localPathStringSchema,
  extensions: z
    .array(z.enum(RPGMAKER_CANDIDATE_EXTENSIONS))
    .default([...RPGMAKER_CANDIDATE_EXTENSIONS]),
  entries_start: z.number().int().min(0).default(0),
  entries_limit: z.number().int().min(1).max(500).default(200),
});
export type InspectRpgmakerAssetPrefixesInput = z.infer<
  typeof inspectRpgmakerAssetPrefixesInputSchema
>;

/** Structural failures of the bounded RPG Maker directory scan. */
export type RpgmakerDirectoryErrorKind = "nesting" | "capacity";

export class RpgmakerDirectoryError extends Error {
  constructor(
    readonly kind: RpgmakerDirectoryErrorKind,
    message: string,
  ) {
    super(message);
  }
}

export const hex = (bytes: Buffer): string => bytes.toString("hex");

/** Classify one 24-byte head: fake-header detection plus a kind sniff. */
export const classifyRpgmakerHead = (
  size: number,
  head: Buffer,
): Omit<RpgmakerAsset, "path" | "bytes"> => {
  const prefixPresent =
    size >= RPGMAKER_PREFIX_BYTES &&
    head
      .subarray(0, RPGMAKER_PREFIX_MAGIC.length)
      .equals(RPGMAKER_PREFIX_MAGIC);
  const following = head.subarray(
    RPGMAKER_PREFIX_BYTES,
    RPGMAKER_PREFIX_BYTES + RPGMAKER_SNIFF_BYTES,
  );
  const hasFollowing = size > RPGMAKER_PREFIX_BYTES;
  // Bytes 16-24 are the original (restored) header: `\x89PNG\r\n\x1a\n` marks
  // a stripped PNG and `OggS` a stripped Ogg; anything else stays unknown.
  const sniffable = size >= RPGMAKER_PREFIX_BYTES + 4;
  let encryptedKind: RpgmakerAsset["encrypted_kind_guess"] = "unknown";
  if (prefixPresent) {
    if (!sniffable) encryptedKind = "insufficient_bytes";
    else if (
      following.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))
    )
      encryptedKind = "png";
    else if (following.subarray(0, 4).equals(Buffer.from("OggS", "latin1")))
      encryptedKind = "ogg";
    else encryptedKind = "unknown";
  }
  const plain = head.subarray(0, 8);
  const plainKind: RpgmakerAsset["plain_kind"] = plain
    .subarray(0, 4)
    .equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))
    ? "png"
    : plain.subarray(0, 4).equals(Buffer.from("OggS", "latin1"))
      ? "ogg"
      : "unknown";
  return {
    prefix_present: prefixPresent,
    prefix_hex: prefixPresent
      ? hex(head.subarray(0, RPGMAKER_PREFIX_BYTES))
      : null,
    following_hex: hasFollowing ? hex(following) : null,
    encrypted_kind_guess: encryptedKind,
    plain_kind: plainKind,
  };
};

/** Page an ordered collection with exact examined counts. */
export const sliceRpgmakerFiles = (
  files: readonly RpgmakerAsset[],
  start: number,
  limit: number,
): { files: RpgmakerAsset[]; slice: RpgmakerReport["slice"] } => {
  const startApplied = Math.min(start, files.length);
  const page = files.slice(startApplied, startApplied + limit);
  return {
    files: page,
    slice: {
      entry_total: files.length,
      entry_start: startApplied,
      entry_returned: page.length,
      complete: startApplied + page.length >= files.length,
    },
  };
};
