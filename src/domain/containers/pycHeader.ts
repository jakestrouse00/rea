import { z } from "zod";
import { canonicalBase64Schema } from "../stringPatterns.js";
import { ContainerFormatError } from "./containerFormatError.js";

/**
 * Python byte-code header facts for CPython 3.7+ (PEP 552, 16-byte header):
 *
 * [4] pyc magic: u16 magic number, little-endian, followed by b"\r\n"
 * [4] flags: bit 0 = hash-based, bit 1 = check-source (hash-based only)
 * [8] timestamp mode: u32 mtime + u32 source size, else 8-byte source hash
 *
 * Pre-3.7 headers (8 or 12 bytes, no flags field) are not parsed.
 */

export const PYC_HEADER_BYTES = 16;
/** Canonical magic number of each release line; in-development intermediates stay unknown. */
export const PYC_MAGIC_VERSIONS: Readonly<Record<number, string>> = {
  3394: "3.7",
  3413: "3.8",
  3425: "3.9",
  3439: "3.10",
  3495: "3.11",
  3531: "3.12",
  3571: "3.13",
};

export const pycHeaderSchema = z.strictObject({
  magic_number: z.number().int().nonnegative(),
  python_version: z
    .enum(["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13"])
    .nullable(),
  magic_bytes_base64: canonicalBase64Schema,
  hash_based: z.boolean(),
  check_source: z.boolean().nullable(),
  timestamp: z.number().int().nonnegative().nullable(),
  source_size: z.number().int().nonnegative().nullable(),
  source_hash_base64: canonicalBase64Schema.nullable(),
  limitations: z.array(z.string()),
});
export type PycHeader = z.infer<typeof pycHeaderSchema>;

const byteAt = (bytes: Uint8Array, offset: number): number => {
  const byte = bytes[offset];
  if (byte === undefined)
    throw new ContainerFormatError(
      "format",
      `pyc header bytes end at index ${String(offset)}`,
    );
  return byte;
};

const readUint32LE = (bytes: Uint8Array, offset: number): number =>
  byteAt(bytes, offset) |
  (byteAt(bytes, offset + 1) << 8) |
  (byteAt(bytes, offset + 2) << 16) |
  (byteAt(bytes, offset + 3) << 24);

/** Parse one 16-byte CPython 3.7+ byte-code header prefix. */
export const parsePycHeader = (bytes: Uint8Array): PycHeader => {
  if (bytes.length < PYC_HEADER_BYTES)
    throw new ContainerFormatError(
      "format",
      `pyc header requires ${String(PYC_HEADER_BYTES)} bytes; observed ${String(bytes.length)}`,
    );
  if (byteAt(bytes, 2) !== 0x0d || byteAt(bytes, 3) !== 0x0a)
    throw new ContainerFormatError(
      "format",
      "pyc magic does not end with CR LF; pre-3.7 or malformed headers are not parsed",
    );
  const magicNumber = byteAt(bytes, 0) | (byteAt(bytes, 1) << 8);
  const flags = readUint32LE(bytes, 4);
  const hashBased = (flags & 0b1) === 1;
  const checkSource = hashBased ? (flags & 0b10) === 0b10 : null;
  const payload = bytes.subarray(8, PYC_HEADER_BYTES);
  const limitations: string[] = [];
  if (flags >>> 2 !== 0)
    limitations.push(
      `pyc flags bits above the hash/check-source pair are set (flags ${String(flags)}); they were ignored.`,
    );
  if (PYC_MAGIC_VERSIONS[magicNumber] === undefined)
    limitations.push(
      `pyc magic number ${String(magicNumber)} is outside the release-line map (3.7 through 3.13); the Python version stays unknown.`,
    );
  return pycHeaderSchema.parse({
    magic_number: magicNumber,
    python_version: PYC_MAGIC_VERSIONS[magicNumber] ?? null,
    magic_bytes_base64: Buffer.from(bytes.subarray(0, 4)).toString("base64"),
    hash_based: hashBased,
    check_source: checkSource,
    timestamp: hashBased ? null : readUint32LE(payload, 0),
    source_size: hashBased ? null : readUint32LE(payload, 4),
    source_hash_base64: hashBased
      ? Buffer.from(payload).toString("base64")
      : null,
    limitations,
  });
};
