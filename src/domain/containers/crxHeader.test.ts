import { createHash } from "node:crypto";
import { Uint8ArrayWriter, ZipWriter, TextReader } from "@zip.js/zip.js";
import { describe, expect, it } from "vitest";

import {
  CRX3_HEADER_PREFIX_BYTES,
  MAX_CRX3_HEADER_BYTES,
  parseCrx3Header,
} from "./crxHeader.js";
import { ContainerFormatError } from "./containerFormatError.js";

const varint = (value: number): Buffer => {
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining > 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining > 0);
  return Buffer.from(bytes);
};

const lengthDelimited = (field: number, payload: Uint8Array): Buffer =>
  Buffer.concat([
    varint((field << 3) | 2),
    varint(payload.length),
    Buffer.from(payload),
  ]);

const buildSha256WithRsaProof = (
  publicKey: Buffer,
  signature: Buffer,
): Buffer =>
  Buffer.concat([lengthDelimited(1, publicKey), lengthDelimited(2, signature)]);

const buildCrxFileHeader = (): { header: Buffer; publicKey: Buffer } => {
  const publicKey = Buffer.alloc(32, 7);
  const signature = Buffer.alloc(256, 3);
  const proof = buildSha256WithRsaProof(publicKey, signature);
  const ecdsaProof = buildSha256WithRsaProof(
    Buffer.alloc(64, 9),
    Buffer.alloc(72, 4),
  );
  const header = Buffer.concat([
    lengthDelimited(2, proof),
    lengthDelimited(3, ecdsaProof),
    // Unknown field carried forward as an unrecognized-field fact.
    varint((5 << 3) | 0),
    varint(9),
    Buffer.from("CRX3 SignedData\x00example-signed-header", "utf8").subarray(
      0,
      0,
    ),
    lengthDelimited(10000, Buffer.from("signed-header-data", "utf8")),
  ]);
  return { header, publicKey };
};

const buildZipPayload = async (): Promise<Buffer> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  await writer.add("manifest.json", new TextReader('{"manifest_version":3}'));
  await writer.add("assets/icon.png", new TextReader("icon bytes"));
  return Buffer.from(await writer.close());
};

const buildCrx3Bytes = (zipBytes: Buffer): Buffer => {
  const { header } = buildCrxFileHeader();
  return Buffer.concat([
    Buffer.from("Cr24", "utf8"),
    Buffer.from([3, 0, 0, 0]),
    Buffer.from([
      header.length & 0xff,
      (header.length >>> 8) & 0xff,
      (header.length >>> 16) & 0xff,
      (header.length >>> 24) & 0xff,
    ]),
    header,
    zipBytes,
  ]);
};

describe("parseCrx3Header", () => {
  it("parses proofs, offsets, and the derived crx_id from a hand-built CRX3", () => {
    const { header, publicKey } = buildCrxFileHeader();
    const zipBytes = Buffer.alloc(120, 0xaa);
    const crx = buildCrx3Bytes(zipBytes);
    const parsed = parseCrx3Header(crx, crx.length);
    expect(parsed.magic).toBe("Cr24");
    expect(parsed.version).toBe(3);
    expect(parsed.archive_offset).toBe(
      CRX3_HEADER_PREFIX_BYTES + header.length,
    );
    expect(parsed.proofs).toHaveLength(2);
    expect(parsed.proofs[0]?.proof_type).toBe("sha256_with_rsa");
    expect(parsed.proofs[0]?.public_key_bytes).toBe(32);
    expect(parsed.proofs[0]?.public_key_sha256).toBe(
      createHash("sha256").update(publicKey).digest("hex"),
    );
    expect(parsed.proofs[0]?.signature_bytes).toBe(256);
    expect(parsed.proofs[1]?.proof_type).toBe("sha256_with_ecdsa");
    expect(parsed.crx_id).toBe(null);
    expect(parsed.signed_header_data_bytes).toBe("signed-header-data".length);
    expect(parsed.verified_contents_bytes).toBe(null);
    expect(parsed.unrecognized_field_count).toBe(1);
    expect(
      parsed.limitations.some((line) =>
        line.includes("signature validity was not verified"),
      ),
    ).toBe(true);
  });

  it("derives crx_id from a single sha256_with_rsa proof", () => {
    const publicKey = Buffer.alloc(32, 5);
    const signature = Buffer.alloc(256, 1);
    const header = Buffer.concat([
      lengthDelimited(2, buildSha256WithRsaProof(publicKey, signature)),
    ]);
    const crx = Buffer.concat([
      Buffer.from("Cr24", "utf8"),
      Buffer.from([3, 0, 0, 0]),
      Buffer.from([
        header.length & 0xff,
        (header.length >>> 8) & 0xff,
        (header.length >>> 16) & 0xff,
        (header.length >>> 24) & 0xff,
      ]),
      header,
      Buffer.alloc(8),
    ]);
    const parsed = parseCrx3Header(crx, crx.length);
    expect(parsed.crx_id).toBe(
      createHash("sha256").update(publicKey).digest("hex").slice(0, 32),
    );
  });

  it("rejects wrong magic and non-CRX3 versions with typed format failures", () => {
    const notCrx = Buffer.alloc(64, 1);
    expect(() => parseCrx3Header(notCrx, notCrx.length)).toThrowError(
      ContainerFormatError,
    );
    const crx = buildCrx3Bytes(Buffer.alloc(16));
    crx[4] = 2;
    expect(() => parseCrx3Header(new Uint8Array(crx), crx.length)).toThrowError(
      /Unsupported CRX container version/u,
    );
  });

  it("refuses headers beyond the read budget and truncated files", () => {
    const oversized = Buffer.alloc(CRX3_HEADER_PREFIX_BYTES);
    Buffer.from("Cr24", "utf8").copy(oversized, 0);
    oversized.writeUInt32LE(3, 4);
    oversized.writeUInt32LE(MAX_CRX3_HEADER_BYTES + 1, 8);
    expect(() => parseCrx3Header(oversized, 1_000_000_000)).toThrowError(
      /read budget/u,
    );
    const crx = buildCrx3Bytes(Buffer.alloc(16));
    expect(() => parseCrx3Header(crx, crx.length - 30)).toThrowError(
      /only.*bytes/u,
    );
  });

  it("keeps the ZIP payload offset pointed at the archive section", async () => {
    const zipBytes = await buildZipPayload();
    const crx = buildCrx3Bytes(zipBytes);
    const parsed = parseCrx3Header(crx, crx.length);
    const archiveSection = crx.subarray(parsed.archive_offset);
    expect(Buffer.compare(archiveSection, zipBytes)).toBe(0);
  });
});
