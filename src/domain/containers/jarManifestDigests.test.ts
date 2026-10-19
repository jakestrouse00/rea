import { describe, expect, it } from "vitest";

import { parseJarDigestFile } from "./jarManifestDigests.js";
import { ContainerFormatError } from "./containerFormatError.js";

// base64 of 23 zero bytes: 31 "A" characters plus one "=" pad character.
const ZERO_SHA1_B64 = `${"A".repeat(31)}=`;
// Canonical base64 requires zero pad bits: the final content char before "="
// must lie in the valid one-pad-bit group.
const ONE_SHA1_B64 = `${"A".repeat(30)}A=`;

const MANIFEST_MF = [
  "Manifest-Version: 1.0",
  "Created-By: fixture",
  "",
  "Name: background.js",
  `SHA1-Digest: ${ZERO_SHA1_B64}`,
  "X-Extra: ignored",
  "",
  "Name: content.js",
  `SHA1-Digest: ${ONE_SHA1_B64}`,
  "",
].join("\r\n");

const MOZILLA_SF = [
  "Signature-Version: 1.0",
  `SHA1-Digest-Manifest: ${ONE_SHA1_B64}`,
  "",
  "Name: background.js",
  `SHA1-Digest: ${ZERO_SHA1_B64}`,
  "",
].join("\n");

describe("parseJarDigestFile", () => {
  it("lists per-entry SHA1 digest facts from manifest.mf", () => {
    const parsed = parseJarDigestFile(Buffer.from(MANIFEST_MF, "utf8"));
    expect(parsed.entries).toEqual([
      {
        name: "background.js",
        sha1_digest: ZERO_SHA1_B64,
        digest_attributes: ["SHA1-Digest"],
        unrecognized_attribute_count: 1,
      },
      {
        name: "content.js",
        sha1_digest: ONE_SHA1_B64,
        digest_attributes: ["SHA1-Digest"],
        unrecognized_attribute_count: 0,
      },
    ]);
    expect(parsed.digest_manifest).toBe(null);
  });

  it("reports the digest-over-manifest main attribute from mozilla.sf", () => {
    const parsed = parseJarDigestFile(Buffer.from(MOZILLA_SF, "utf8"));
    expect(parsed.digest_manifest).toBe(ONE_SHA1_B64);
    expect(parsed.digest_manifest_attributes).toEqual(["SHA1-Digest-Manifest"]);
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0]?.name).toBe("background.js");
  });

  it("joins wrapped continuation lines", () => {
    // The digest value is split across a 70-byte wrap boundary.
    const wrapped = [
      "Name: background.js",
      `SHA1-Digest: ${"A".repeat(30)}`,
      " A=",
      "",
    ].join("\n");
    const parsed = parseJarDigestFile(Buffer.from(wrapped, "utf8"));
    expect(parsed.entries[0]?.sha1_digest).toBe(ZERO_SHA1_B64);
  });

  it("counts unrecognized lines instead of failing", () => {
    const text = [
      "Name: a.js",
      `SHA1-Digest: ${ZERO_SHA1_B64}`,
      "not an attribute",
      "",
    ].join("\n");
    const parsed = parseJarDigestFile(Buffer.from(text, "utf8"));
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.limitations[0]).toContain(
      "unrecognized digest-manifest line(s)",
    );
  });

  it("rejects non-UTF-8 digest files with a typed failure", () => {
    expect(() =>
      parseJarDigestFile(Buffer.from([0xff, 0xfe, 0x00])),
    ).toThrowError(ContainerFormatError);
  });
});
