import { describe, expect, it } from "vitest";

import { buildVpkDirectory } from "./gamedataFixtures.js";
import {
  VpkFormatError,
  parseVpkArchive,
  vpkReportSchema,
} from "./vpkArchive.js";

describe("parseVpkArchive", () => {
  it("walks the v2 tree with CRCs, preload counts, and archive indices", () => {
    const bytes = buildVpkDirectory(2, [
      {
        dir: "maps",
        name: "de_test",
        ext: "bsp",
        crc32: 0xdeadbeef,
        archiveIndex: 0,
        entryOffset: 12,
        entryLength: 4000,
      },
      {
        dir: "materials",
        name: "brick",
        ext: "vmt",
        crc32: 0x000000ff,
        preload: Buffer.from([1, 2, 3]),
        archiveIndex: 0x7fff,
        entryOffset: 0,
        entryLength: 0,
      },
    ]);
    const parsed = parseVpkArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.format_version).toBe(2);
    expect(parsed.header_bytes).toBe(28);
    expect(parsed.sections).toEqual({
      file_data_bytes: 0,
      archive_md5_bytes: 0,
      other_md5_bytes: 0,
      signature_bytes: 0,
    });
    expect(parsed.slice).toEqual({
      entry_total: 2,
      entry_start: 0,
      entry_returned: 2,
      complete: true,
    });
    const [bsp, vmt] = parsed.entries;
    expect(bsp).toMatchObject({
      path: "maps/de_test.bsp",
      crc32_hex: "deadbeef",
      preload_bytes: 0,
      archive_index: 0,
      entry_offset: 12,
      entry_length: 4000,
      total_size: 4000,
      stored_in_directory: false,
    });
    expect(vmt).toMatchObject({
      path: "materials/brick.vmt",
      crc32_hex: "000000ff",
      preload_bytes: 3,
      archive_index: 0x7fff,
      total_size: 3,
      stored_in_directory: true,
    });
    expect(parsed.directory_data_offset).toBe(28 + parsed.tree_size);
  });

  it("groups files sharing an extension across directories", () => {
    const bytes = buildVpkDirectory(1, [
      { dir: "a", name: "one", ext: "txt", crc32: 1 },
      { dir: "b", name: "two", ext: "txt", crc32: 2 },
      { dir: "b", name: "three", ext: "cfg", crc32: 3 },
    ]);
    const parsed = parseVpkArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.format_version).toBe(1);
    expect(parsed.sections).toBeNull();
    expect(parsed.entries.map((entry) => entry.path)).toEqual([
      "a/one.txt",
      "b/two.txt",
      "b/three.cfg",
    ]);
    expect(parsed.header_bytes).toBe(12);
  });

  it("pages without changing the examined total", () => {
    const bytes = buildVpkDirectory(2, [
      { dir: "p", name: "loose", ext: "dat", crc32: 7 },
      { dir: "q", name: "x", ext: "dat", crc32: 8 },
    ]);
    const parsed = parseVpkArchive(bytes, {
      entries_start: 1,
      entries_limit: 500,
    });
    expect(parsed.entries.map((entry) => entry.path)).toEqual(["q/x.dat"]);
    expect(parsed.slice.entry_total).toBe(2);
  });

  it("rejects bad terminators and non-VPK artifacts", () => {
    const bytes = buildVpkDirectory(1, [
      { dir: "a", name: "one", ext: "txt", crc32: 1 },
    ]);
    const broken = Buffer.from(bytes);
    // Entry structure begins after the extension, path, and name strings.
    broken.writeUInt16LE(0x0000, 12 + 10 + 16);
    expect(() =>
      parseVpkArchive(broken, { entries_start: 0, entries_limit: 10 }),
    ).toThrow(VpkFormatError);
    const notVpk = Buffer.alloc(64, 0x33);
    expect(() =>
      parseVpkArchive(notVpk, { entries_start: 0, entries_limit: 10 }),
    ).toThrow(VpkFormatError);
    const tooLong = buildVpkDirectory(1, []);
    tooLong.writeUInt32LE(0xffff_ffff, 8);
    expect(() =>
      parseVpkArchive(tooLong, { entries_start: 0, entries_limit: 10 }),
    ).toThrow(VpkFormatError);
  });

  it("round-trips through the report schema", () => {
    const bytes = buildVpkDirectory(2, [
      { dir: "sound", name: "alarm", ext: "wav", crc32: 0x11223344 },
    ]);
    const parsed = parseVpkArchive(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    const report = vpkReportSchema.parse({
      ...parsed,
      artifact: {
        path: "/tmp/pak01_dir.vpk",
        sha256: "0".repeat(64),
        bytes: bytes.length,
      },
    });
    expect(report.limitations.length).toBeGreaterThan(0);
  });
});
