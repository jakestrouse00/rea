import { TextReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";

/**
 * Immutable byte fixtures for the container inspection tests. All fixtures are
 * hand-built: no real browser extension or PyInstaller output is embedded.
 */

const le32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeInt32LE(value, 0);
  return bytes;
};

const be32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value >>> 0, 0);
  return bytes;
};

const varintBytes = (value: number): Buffer => {
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
    varintBytes((field << 3) | 2),
    varintBytes(payload.length),
    Buffer.from(payload),
  ]);

export interface Crx3Fixture {
  readonly bytes: Buffer;
  readonly archiveOffset: number;
  readonly publicKey: Buffer;
}

/** Hand-built CRX3: one Sha256WithRsa proof plus signed-header-data. */
export const buildCrx3ExtensionBytes = async (): Promise<Crx3Fixture> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  await writer.add(
    "manifest.json",
    new TextReader(
      JSON.stringify({
        name: "Fixture Extension",
        version: "1.0.0",
        manifest_version: 3,
        permissions: ["storage"],
        host_permissions: ["*://example.com/*"],
        background: { service_worker: "background.js" },
        content_scripts: [
          { matches: ["https://example.com/*"], js: ["content.js"] },
        ],
        custom_note: "unrecognized",
      }),
    ),
  );
  await writer.add("assets/icon.png", new TextReader("icon-bytes"));
  const zipBytes = Buffer.from(await writer.close());
  const publicKey = Buffer.alloc(32, 7);
  const signature = Buffer.alloc(256, 3);
  const header = Buffer.concat([
    lengthDelimited(
      2,
      Buffer.concat([
        lengthDelimited(1, publicKey),
        lengthDelimited(2, signature),
      ]),
    ),
    lengthDelimited(10000, Buffer.from("signed-header-data", "utf8")),
  ]);
  const fixed = Buffer.concat([
    Buffer.from("Cr24", "utf8"),
    Buffer.from([3, 0, 0, 0]),
    le32(header.length),
  ]);
  return {
    bytes: Buffer.concat([fixed, header, zipBytes]),
    archiveOffset: fixed.length + header.length,
    publicKey,
  };
};

export interface XpiFixtureOptions {
  readonly withDigestFiles: boolean;
}

/** Hand-built XPI: root manifest plus JAR digest manifests on request. */
export const buildXpiBytes = async (
  options: XpiFixtureOptions,
): Promise<Buffer> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  await writer.add(
    "manifest.json",
    new TextReader(
      JSON.stringify({
        name: "Fixture Firefox Add-on",
        version: "2.3.4",
        manifest_version: 2,
        permissions: ["<all_urls>"],
        background: { scripts: ["bg.js"] },
        browser_specific_settings: {
          gecko: { id: "fixture@example.com", strict_min_version: "115.0" },
        },
      }),
    ),
  );
  if (options.withDigestFiles) {
    const digest = `${"A".repeat(31)}=`;
    await writer.add(
      "META-INF/manifest.mf",
      new TextReader(
        [
          "Manifest-Version: 1.0",
          "",
          "Name: bg.js",
          `SHA1-Digest: ${digest}`,
          "",
        ].join("\n"),
      ),
    );
    await writer.add(
      "META-INF/mozilla.sf",
      new TextReader(
        [
          "Signature-Version: 1.0",
          `SHA1-Digest-Manifest: ${digest}`,
          "",
          "Name: bg.js",
          `SHA1-Digest: ${digest}`,
          "",
        ].join("\n"),
      ),
    );
    await writer.add("META-INF/zigbert.rsa", new TextReader("signature-bytes"));
  }
  return Buffer.from(await writer.close());
};

const pycMagic3531 = Buffer.from([0xcb, 0x0d, 0x0d, 0x0a]);
const CARCHIVE_COOKIE_BYTES = 24;

/** CPython 3.12 timestamp-mode pyc header. */
const buildPycHeaderBytes = (): Buffer =>
  Buffer.concat([
    pycMagic3531,
    Buffer.from([0, 0, 0, 0]),
    Buffer.from([1, 2, 3, 4, 0x40, 0x0d, 3, 0]),
  ]);

const marshalAscii = (text: string): Buffer =>
  Buffer.concat([
    Buffer.from(["z".charCodeAt(0)]),
    Buffer.from([text.length]),
    Buffer.from(text, "ascii"),
  ]);

const marshalTuple = (items: readonly Buffer[]): Buffer =>
  Buffer.concat([
    Buffer.from([")".charCodeAt(0)]),
    Buffer.from([items.length]),
    ...items,
  ]);

const marshalInt = (value: number): Buffer =>
  Buffer.concat([Buffer.from(["i".charCodeAt(0)]), le32(value)]);

const marshalList = (items: readonly Buffer[]): Buffer =>
  Buffer.concat([
    Buffer.from(["[".charCodeAt(0)]),
    le32(items.length),
    ...items,
  ]);

const carchiveEntry = (
  name: string,
  relativeOffset: number,
  compressedSize: number,
  uncompressedSize: number,
  compressed: boolean,
  typecode: string,
): Buffer => {
  const nameBytes = Buffer.from(name, "utf8");
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

export interface PyInstallerFixture {
  readonly bytes: Buffer;
  readonly cookieOffset: number;
  readonly pycEntryPosition: number;
  readonly pyzEntryPosition: number;
}

/** Hand-built PyInstaller 2.1+ executable: CArchive TOC plus embedded PYZ. */
export const buildPyInstallerExecutableBytes = (): PyInstallerFixture => {
  const pyzTocBlob = marshalList([
    marshalTuple([
      marshalAscii("app.main"),
      marshalTuple([marshalInt(0), marshalInt(12), marshalInt(4)]),
    ]),
    marshalTuple([
      marshalAscii("app.ns"),
      marshalTuple([marshalInt(3), marshalInt(0), marshalInt(0)]),
    ]),
  ]);
  const pyz = Buffer.concat([
    Buffer.from("PYZ\x00", "latin1"),
    pycMagic3531,
    be32(12),
    pyzTocBlob,
  ]);
  // CArchive payload region: module pyc at 0, PYZ at 16, compressed data after.
  const payload = Buffer.concat([
    buildPycHeaderBytes(),
    pyz,
    Buffer.alloc(10, 0xee),
  ]);
  const toc = Buffer.concat([
    carchiveEntry("app.module", 0, 16, 16, false, "m"),
    carchiveEntry("app.pyz", 16, pyz.length, 9999, false, "z"),
    carchiveEntry("data.bin", 16 + pyz.length, 10, 20, true, "x"),
    carchiveEntry("py-runtime-option", 26 + pyz.length, 0, 0, false, "o"),
  ]);
  const filler = Buffer.alloc(64, 0x11);
  const archiveStart = filler.length;
  const cookieBytes = Buffer.concat([
    Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e", "latin1"),
    be32(0),
    be32(payload.length),
    be32(toc.length),
    be32(312),
    Buffer.from("python312.dll", "ascii"),
    Buffer.alloc(64 - "python312.dll".length),
  ]);
  // The package length includes the trailer cookie, per the CArchive writer.
  const packageLength = payload.length + toc.length + cookieBytes.length;
  cookieBytes.writeUInt32BE(packageLength, 8);
  return {
    bytes: Buffer.concat([filler, payload, toc, cookieBytes]),
    cookieOffset: archiveStart + packageLength - cookieBytes.length,
    pycEntryPosition: archiveStart,
    pyzEntryPosition: archiveStart + 16,
  };
};

/** A legacy PyInstaller 2.0 cookie executable with a small data-only TOC. */
export const buildLegacyPyInstallerBytes = (): Buffer => {
  const filler = Buffer.alloc(8, 0x22);
  const toc = carchiveEntry("legacy.data", 0, 4, 4, false, "x");
  const cookie = Buffer.concat([
    Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e", "latin1"),
    be32(filler.length + toc.length + CARCHIVE_COOKIE_BYTES),
    be32(filler.length),
    be32(toc.length),
    be32(27),
  ]);
  return Buffer.concat([filler, toc, cookie]);
};
