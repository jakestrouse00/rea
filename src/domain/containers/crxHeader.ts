import { createHash } from "node:crypto";
import { z } from "zod";
import { digestSchema } from "../digests.js";
import {
  ContainerFormatError,
  containerLimitError,
} from "./containerFormatError.js";

/**
 * CRX₃ container layout from
 * https://source.chromium.org/chromium/chromium/src/+/main:components/crx_file/crx3.proto
 *
 * [4 octets]: "Cr24" magic
 * [4 octets]: version, currently 3
 * [4 octets]: N, little-endian header-section length
 * [N octets]: CrxFileHeader protobuf message
 * [M octets]: ZIP archive (offset 12 + N)
 */

export const CRX3_MAGIC = "Cr24";
export const CRX3_HEADER_PREFIX_BYTES = 12;
/** The archive section carries the signed content; N is parsed, not trusted. */
export const MAX_CRX3_HEADER_BYTES = 1024 * 1024;

const nonnegative = z.number().int().nonnegative();

const crxProofSchema = z.strictObject({
  proof_type: z.enum(["sha256_with_rsa", "sha256_with_ecdsa"]),
  public_key_bytes: nonnegative.nullable(),
  /** SHA-256 over the observed public-key bytes; no crypto verification. */
  public_key_sha256: digestSchema.nullable(),
  signature_bytes: nonnegative.nullable(),
});

/**
 * Observed CrxFileHeader facts. Signatures are reported as metadata only:
 * signature validity is deliberately not verified.
 */
export const crx3HeaderSchema = z.strictObject({
  magic: z.literal(CRX3_MAGIC),
  version: z.literal(3),
  header_size: nonnegative,
  archive_offset: nonnegative,
  /** Chromium derives the crx_id as the first 128 bits of SHA-256 over the
   *  single Sha256WithRsa developer-key proof. Absent, multiple, or ECDSA-only
   *  proofs leave it unknown rather than guessed. */
  crx_id: z
    .string()
    .regex(/^[0-9a-f]{32}$/u)
    .nullable(),
  proofs: z.array(crxProofSchema),
  verified_contents_bytes: nonnegative.nullable(),
  signed_header_data_bytes: nonnegative.nullable(),
  unrecognized_field_count: nonnegative,
  limitations: z.array(z.string()),
});
export type Crx3Header = z.infer<typeof crx3HeaderSchema>;
export type CrxProof = Crx3Header["proofs"][number];

const CRX_HASH_LIMITATION =
  "CRX signature validity was not verified: proof and signed-header entries are reported as metadata only.";

interface ParsedCrxFileHeader {
  readonly proofs: CrxProof[];
  readonly verifiedContentsBytes: number | null;
  readonly signedHeaderDataBytes: number | null;
  readonly unrecognizedFieldCount: number;
}

/** Decode the pre-parsed header-section bytes (field 2/3/4/10000 of CrxFileHeader). */
const parseCrxFileHeader = (blob: Uint8Array): ParsedCrxFileHeader => {
  let position = 0;
  let unrecognized = 0;
  const proofs: CrxProof[] = [];
  let verifiedContentsBytes: number | null = null;
  let signedHeaderDataBytes: number | null = null;

  while (position < blob.length) {
    const [tag, afterTag] = readVarint(blob, position);
    const field = tag >>> 3;
    const wireType = tag & 0x7;
    position = afterTag;
    if (field === 0)
      throw new ContainerFormatError(
        "format",
        "CRX3 header declares reserved field number zero",
      );
    if (wireType !== 0 && wireType !== 1 && wireType !== 2 && wireType !== 5)
      throw new ContainerFormatError(
        "format",
        `CRX3 header protobuf declares unsupported wire type ${String(wireType)}`,
      );
    if (wireType === 2) {
      const [length, afterLength] = readVarint(blob, position);
      position = afterLength;
      if (position + length > blob.length)
        throw new ContainerFormatError(
          "format",
          `CRX3 header field ${String(field)} truncated: needs ${String(length)} bytes at offset ${String(position)}`,
        );
      if (field === 2 || field === 3) {
        const proof = parseAsymmetricKeyProof(
          blob.subarray(position, position + length),
          field === 2 ? "sha256_with_rsa" : "sha256_with_ecdsa",
        );
        position += length;
        proofs.push(proof);
        continue;
      }
      if (field === 4) {
        verifiedContentsBytes = length;
        position += length;
        continue;
      }
      if (field === 10000) {
        signedHeaderDataBytes = length;
        position += length;
        continue;
      }
      unrecognized += 1;
      position += length;
      continue;
    }
    if (wireType === 0) {
      const [, afterValue] = readVarint(blob, position);
      position = afterValue;
      unrecognized += 1;
      continue;
    }
    position += wireType === 1 ? 8 : 4;
    unrecognized += 1;
  }
  return {
    proofs: proofs.map((proof) => ({ ...proof })),
    verifiedContentsBytes,
    signedHeaderDataBytes,
    unrecognizedFieldCount: unrecognized,
  };
};

const parseAsymmetricKeyProof = (
  blob: Uint8Array,
  proofType: "sha256_with_rsa" | "sha256_with_ecdsa",
): CrxProof => {
  let position = 0;
  let publicKey: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  while (position < blob.length) {
    const [tag, afterTag] = readVarint(blob, position);
    const field = tag >>> 3;
    const wireType = tag & 0x7;
    position = afterTag;
    if (wireType !== 2)
      throw new ContainerFormatError(
        "format",
        `CRX3 ${proofType} proof field ${String(field)} is not a length-delimited entry`,
      );
    const [length, afterLength] = readVarint(blob, position);
    position = afterLength;
    if (position + length > blob.length)
      throw new ContainerFormatError(
        "format",
        `CRX3 ${proofType} proof field ${String(field)} truncated`,
      );
    if (field === 1) publicKey = blob.subarray(position, position + length);
    else if (field === 2)
      signature = blob.subarray(position, position + length);
    position += length;
  }
  return {
    proof_type: proofType,
    public_key_bytes: publicKey?.length ?? null,
    public_key_sha256:
      publicKey === undefined
        ? null
        : createHash("sha256").update(publicKey).digest("hex"),
    signature_bytes: signature?.length ?? null,
  };
};

const readVarint = (
  bytes: Uint8Array,
  start: number,
): readonly [number, number] => {
  let value = 0;
  let shift = 0;
  let position = start;
  while (position < bytes.length) {
    const byte = bytes[position];
    if (byte === undefined)
      throw new ContainerFormatError(
        "format",
        "CRX3 header varint is truncated",
      );
    if (shift >= 32)
      throw new ContainerFormatError(
        "format",
        "CRX3 header varint exceeds 32 bits",
      );
    value |= (byte & 0x7f) << shift;
    position += 1;
    if ((byte & 0x80) === 0) return [value >>> 0, position] as const;
    shift += 7;
  }
  throw new ContainerFormatError("format", "CRX3 header varint is truncated");
};

const byteAt = (bytes: Uint8Array, offset: number): number => {
  const byte = bytes[offset];
  if (byte === undefined)
    throw new ContainerFormatError(
      "format",
      `CRX3 bytes end at index ${String(offset)}`,
    );
  return byte;
};

export const crx3MagicMatches = (prefix: Uint8Array): boolean =>
  prefix.length >= 4 &&
  prefix[0] === 0x43 &&
  prefix[1] === 0x72 &&
  prefix[2] === 0x32 &&
  prefix[3] === 0x34;

/** Parse one CRX₃ prefix (at least 12 bytes plus the whole header section). */
export const parseCrx3Header = (
  prefix: Uint8Array,
  fileBytes: number,
): Crx3Header => {
  if (prefix.length < CRX3_HEADER_PREFIX_BYTES)
    throw new ContainerFormatError(
      "format",
      "CRX3 prefix is shorter than its fixed header",
    );
  const magic = String.fromCharCode(
    byteAt(prefix, 0),
    byteAt(prefix, 1),
    byteAt(prefix, 2),
    byteAt(prefix, 3),
  );
  if (magic !== CRX3_MAGIC)
    throw new ContainerFormatError(
      "format",
      `Selected file is not a CRX3 container: magic ${JSON.stringify(magic)}`,
    );
  const version =
    byteAt(prefix, 4) |
    (byteAt(prefix, 5) << 8) |
    (byteAt(prefix, 6) << 16) |
    (byteAt(prefix, 7) << 24);
  if (version !== 3)
    throw new ContainerFormatError(
      "format",
      `Unsupported CRX container version ${String(version)}; only CRX3 is parsed`,
    );
  const headerSize =
    byteAt(prefix, 8) |
    (byteAt(prefix, 9) << 8) |
    (byteAt(prefix, 10) << 16) |
    (byteAt(prefix, 11) << 24);
  if (headerSize > MAX_CRX3_HEADER_BYTES)
    throw containerLimitError(
      "CRX3 header section",
      headerSize,
      MAX_CRX3_HEADER_BYTES,
    );
  const archiveOffset = CRX3_HEADER_PREFIX_BYTES + headerSize;
  if (fileBytes < archiveOffset)
    throw new ContainerFormatError(
      "format",
      `CRX3 declares a ${String(headerSize)}-byte header but the file is only ${String(fileBytes)} bytes`,
    );
  if (prefix.length < archiveOffset)
    throw containerLimitError("CRX3 header read", archiveOffset, prefix.length);
  const parsed = parseCrxFileHeader(
    prefix.subarray(CRX3_HEADER_PREFIX_BYTES, archiveOffset),
  );

  const singleProof = parsed.proofs[0];
  let crxId: string | null = null;
  const limitations: string[] = [CRX_HASH_LIMITATION];
  if (
    parsed.proofs.length === 1 &&
    singleProof !== undefined &&
    singleProof.proof_type === "sha256_with_rsa" &&
    singleProof.public_key_sha256 !== null
  ) {
    crxId = singleProof.public_key_sha256.slice(0, 32);
    limitations.push(
      "crx_id is derived as the first 128 bits of the SHA-256 over the single Sha256WithRsa proof's public key; the derived identity was not verified against a crx signing infrastructure.",
    );
  } else if (parsed.proofs.length > 1) {
    limitations.push(
      "crx_id is unknown: multiple header proofs prevent the unambiguous developer-key derivation.",
    );
  }
  if (parsed.unrecognizedFieldCount > 0)
    limitations.push(
      `${String(parsed.unrecognizedFieldCount)} unrecognized CrxFileHeader field(s) were skipped; only field numbers 2, 3, 4 and 10000 are parsed.`,
    );

  return crx3HeaderSchema.parse({
    magic: CRX3_MAGIC,
    version: 3,
    header_size: headerSize,
    archive_offset: archiveOffset,
    crx_id: crxId,
    proofs: parsed.proofs,
    verified_contents_bytes: parsed.verifiedContentsBytes ?? null,
    signed_header_data_bytes: parsed.signedHeaderDataBytes ?? null,
    unrecognized_field_count: parsed.unrecognizedFieldCount,
    limitations,
  });
};
