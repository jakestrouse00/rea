import { describe, expect, it } from "vitest";

import {
  CARCHIVE_COOKIE_BYTES_20,
  CARCHIVE_COOKIE_BYTES_21,
  carchiveCookieBytesFor,
  parseCarchiveCookieBytes,
  parseCarchiveToc,
  parsePyzHeader,
} from "./pyinstallerArchive.js";

const be32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value >>> 0, 0);
  return bytes;
};

const buildCookie = (option: {
  readonly packageLength: number;
  readonly tocOffset: number;
  readonly tocLength: number;
  readonly pythonVersion: number;
  readonly libName?: string;
}): Buffer => {
  const prefix = Buffer.concat([
    Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e", "latin1"),
    be32(option.packageLength),
    be32(option.tocOffset),
    be32(option.tocLength),
    be32(option.pythonVersion),
  ]);
  if (option.libName === undefined) return prefix;
  const libName = Buffer.alloc(64, 0);
  Buffer.from(option.libName, "ascii").copy(libName);
  return Buffer.concat([prefix, libName]);
};

describe("parseCarchiveCookieBytes", () => {
  it("parses the 88-byte 2.1+ cookie and overlays", () => {
    const cookie = buildCookie({
      packageLength: 1024,
      tocOffset: 512,
      tocLength: 128,
      pythonVersion: 311,
      libName: "python311.dll",
    });
    const fileBytes = 5000 + CARCHIVE_COOKIE_BYTES_21;
    const parsed = parseCarchiveCookieBytes(
      cookie,
      CARCHIVE_COOKIE_BYTES_21,
      5000,
      fileBytes,
    );
    expect(parsed.cookie_format).toBe("pyinstaller-2.1-plus");
    expect(parsed.package_length).toBe(1024);
    expect(parsed.toc_offset).toBe(512);
    expect(parsed.toc_length).toBe(128);
    expect(parsed.python_version).toBe(311);
    expect(parsed.python_libname).toBe("python311.dll");
    expect(parsed.python_libname_bytes).toBe(13);
    expect(parsed.archive_start).toBe(5000 + CARCHIVE_COOKIE_BYTES_21 - 1024);
    expect(parsed.archive_end).toBe(5000 + CARCHIVE_COOKIE_BYTES_21);
    expect(parsed.tail_bytes).toBe(0);
    expect(parsed.limitations).toEqual([]);
  });

  it("parses the 24-byte 2.0 cookie without a library name", () => {
    const cookie = buildCookie({
      packageLength: 256,
      tocOffset: 64,
      tocLength: 32,
      pythonVersion: 27,
    });
    const parsed = parseCarchiveCookieBytes(
      cookie,
      CARCHIVE_COOKIE_BYTES_20,
      700,
      700 + CARCHIVE_COOKIE_BYTES_20,
    );
    expect(parsed.cookie_format).toBe("pyinstaller-2.0");
    expect(parsed.python_libname).toBe(null);
    expect(parsed.archive_start).toBe(700 + CARCHIVE_COOKIE_BYTES_20 - 256);
  });

  it("keeps clamped-overlay and out-of-range TOC facts as limitations", () => {
    const cookie = buildCookie({
      packageLength: 100_000,
      tocOffset: 110_000,
      tocLength: 16,
      pythonVersion: 312,
      libName: "python312.dll",
    });
    const parsed = parseCarchiveCookieBytes(
      cookie,
      CARCHIVE_COOKIE_BYTES_21,
      100,
      200,
    );
    expect(parsed.archive_start).toBe(0);
    expect(
      parsed.limitations.some((line) => line.includes("clamped to zero")),
    ).toBe(true);
    expect(
      parsed.limitations.some((line) => line.includes("package length")),
    ).toBe(true);
  });
});

describe("carchiveCookieBytesFor", () => {
  it("detects the 2.1+ layout by the python library name probe", () => {
    const follows = Buffer.alloc(64, 0);
    Buffer.from("python312.dll", "ascii").copy(follows);
    expect(carchiveCookieBytesFor(follows)).toBe(CARCHIVE_COOKIE_BYTES_21);
    expect(carchiveCookieBytesFor(Buffer.alloc(64, 0))).toBe(
      CARCHIVE_COOKIE_BYTES_20,
    );
    expect(carchiveCookieBytesFor(Buffer.alloc(0))).toBe(
      CARCHIVE_COOKIE_BYTES_20,
    );
  });
});

describe("parseCarchiveToc", () => {
  const carchiveEntry = (
    name: string,
    relativeOffset: number,
    compressedSize: number,
    uncompressedSize: number,
    compressed: boolean,
    typecode: string,
  ): Buffer => {
    const nameBytes = Buffer.from(name, "utf8");
    // Names are NUL-padded to a 16-byte boundary, per PyInstaller's writer.
    const padding = Buffer.alloc((16 - (nameBytes.length % 16)) % 16);
    const entryLength = 18 + nameBytes.length + padding.length;
    return Buffer.concat([
      be32(entryLength),
      be32(relativeOffset),
      be32(compressedSize),
      be32(uncompressedSize),
      Buffer.from([compressed ? 1 : 0]),
      Buffer.from(typecode, "ascii"),
      nameBytes,
      padding,
    ]);
  };

  it("indexes typecodes, compression flags, and absolute positions", () => {
    const toc = Buffer.concat([
      carchiveEntry("pyz-archive", 0, 400, 1000, true, "z"),
      carchiveEntry("application-module", 512, 16, 16, false, "m"),
      carchiveEntry("data.bin", 640, 32, 32, false, "x"),
      carchiveEntry("py-runtime-option", 700, 0, 0, false, "o"),
    ]);
    const parsed = parseCarchiveToc(toc, 4096);
    expect(
      parsed.entries.map((entry) => [
        entry.typecode,
        entry.type_label,
        entry.compressed,
        entry.position,
      ]),
    ).toEqual([
      ["z", "pyz-archive", true, 4096],
      ["m", "python-module", false, 4096 + 512],
      ["x", "data", false, 4096 + 640],
      ["o", "runtime-option", false, 4096 + 700],
    ]);
    const pyz = parsed.entries[0];
    expect(pyz?.encrypted).toBe(false);
    expect(pyz?.pyc_header_state).toBe("not-module-data");
    const module = parsed.entries[1];
    expect(module?.pyc_header_state).toBe("opaque");
    expect(
      parsed.limitations.some((line) => line.includes("encryption flag")),
    ).toBe(true);
  });

  it("records undecodable names as raw-byte facts", () => {
    const nameBytes = Buffer.from([0xff, 0xfe]);
    const entryLength = 18 + nameBytes.length;
    const toc = Buffer.concat([
      be32(entryLength),
      be32(0),
      be32(1),
      be32(1),
      Buffer.from([0]),
      Buffer.from("x", "ascii"),
      nameBytes,
    ]);
    const parsed = parseCarchiveToc(toc, 0);
    expect(parsed.entries[0]?.name).toBe(null);
    expect(parsed.entries[0]?.name_bytes_base64).toBe(
      nameBytes.toString("base64"),
    );
  });

  it("fails closed on truncated TOC entries and implausible lengths", () => {
    expect(() => parseCarchiveToc(Buffer.from([0, 0, 0]), 0)).toThrowError(
      /truncated/u,
    );
    const tooShort = Buffer.concat([Buffer.alloc(4, 0), Buffer.alloc(10)]);
    expect(() => parseCarchiveToc(tooShort, 0)).toThrowError(/implausible/u);
    const overlong = Buffer.concat([be32(64), Buffer.alloc(20)]);
    expect(() => parseCarchiveToc(overlong, 0)).toThrowError(/exceeding/u);
  });
});

describe("parsePyzHeader", () => {
  it("parses the PYZ magic, pyc magic, and TOC position", () => {
    const header = Buffer.concat([
      Buffer.from("PYZ\x00", "latin1"),
      Buffer.from([0xcb, 0x0d, 0x0d, 0x0a]),
      be32(24),
    ]);
    const parsed = parsePyzHeader(Buffer.from(header));
    expect(parsed.python_magic_bytes_base64).toBe(
      Buffer.from([0xcb, 0x0d, 0x0d, 0x0a]).toString("base64"),
    );
    expect(parsed.toc_position).toBe(24);
  });

  it("fails closed on wrong magic or short headers", () => {
    expect(() =>
      parsePyzHeader(
        Buffer.concat([Buffer.from("ZIP\x00", "latin1"), Buffer.alloc(8)]),
      ),
    ).toThrowError(/PYZ/u);
    expect(() => parsePyzHeader(Buffer.alloc(8))).toThrowError(/12 bytes/u);
  });
});
