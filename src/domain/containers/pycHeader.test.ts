import { describe, expect, it } from "vitest";

import { PYC_MAGIC_VERSIONS, parsePycHeader } from "./pycHeader.js";

const pycMagicBytes = (magicNumber: number): Buffer[] => {
  const low = magicNumber & 0xff;
  const high = (magicNumber >>> 8) & 0xff;
  return [Buffer.from([low, high, 0x0d, 0x0a])];
};

const timestampHeader = (magicNumber: number, flags = 0): Buffer =>
  Buffer.concat([
    ...pycMagicBytes(magicNumber),
    Buffer.from([flags & 0xff, 0, 0, 0]),
    Buffer.from([1, 2, 3, 4, 0x40, 0x0d, 3, 0]),
  ]);

const hashHeader = (magicNumber: number, flags = 0b11): Buffer =>
  Buffer.concat([
    ...pycMagicBytes(magicNumber),
    Buffer.from([flags & 0xff, 0, 0, 0]),
    Buffer.alloc(8, 0x5a),
  ]);

describe("parsePycHeader", () => {
  it("maps the release-line magic numbers of 3.7 through 3.13", () => {
    const expected: Record<number, string> = {
      3394: "3.7",
      3413: "3.8",
      3425: "3.9",
      3439: "3.10",
      3495: "3.11",
      3531: "3.12",
      3571: "3.13",
    };
    for (const [magicNumber, version] of Object.entries(expected)) {
      const parsed = parsePycHeader(timestampHeader(Number(magicNumber)));
      expect(parsed.python_version).toBe(version);
      expect(parsed.magic_number).toBe(Number(magicNumber));
      expect(parsed.timestamp).toBe(0x04030201);
      expect(parsed.source_size).toBe(0x00030d40);
      expect(parsed.hash_based).toBe(false);
      expect(parsed.check_source).toBe(null);
      expect(parsed.source_hash_base64).toBe(null);
    }
  });

  it("parses hash-based flags and the source hash payload", () => {
    const parsed = parsePycHeader(hashHeader(3531, 0b11));
    expect(parsed.python_version).toBe("3.12");
    expect(parsed.hash_based).toBe(true);
    expect(parsed.check_source).toBe(true);
    expect(parsed.timestamp).toBe(null);
    expect(parsed.source_size).toBe(null);
    expect(parsed.source_hash_base64).toBe(
      Buffer.alloc(8, 0x5a).toString("base64"),
    );
    const unchecked = parsePycHeader(hashHeader(3531, 0b01));
    expect(unchecked.check_source).toBe(false);
  });

  it("keeps unknown magic numbers unknown with a limitation", () => {
    const parsed = parsePycHeader(timestampHeader(3000));
    expect(parsed.python_version).toBe(null);
    expect(parsed.limitations[0]).toContain("outside the release-line map");
  });

  it("notes reserved flag bits instead of failing", () => {
    const parsed = parsePycHeader(timestampHeader(3531, 0b100));
    expect(parsed.hash_based).toBe(false);
    expect(parsed.limitations[0]).toContain("ignored");
  });

  it("rejects short and pre-3.7 shaped headers", () => {
    expect(() => parsePycHeader(Buffer.alloc(8))).toThrowError(/16 bytes/u);
    // A pre-3.7 header lacks the CR LF terminator after the magic word.
    const noCrLf = Buffer.alloc(16);
    noCrLf[0] = 0x42;
    noCrLf[1] = 0x0d;
    expect(() => parsePycHeader(noCrLf)).toThrowError(/CR LF/u);
  });

  it("keeps the canonical release-line magic table intact", () => {
    expect(Object.keys(PYC_MAGIC_VERSIONS)).toEqual([
      "3394",
      "3413",
      "3425",
      "3439",
      "3495",
      "3531",
      "3571",
    ]);
  });
});
