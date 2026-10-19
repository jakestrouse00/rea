import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { buildGodotPck, embedGodotPckWithFooter } from "./gamedataFixtures.js";
import {
  PCK_EXTRACTION_MAX_BYTES,
  PckFormatError,
  PckNotFoundError,
  PACK_DIR_ENCRYPTED,
  CALLER_KEY_NOT_READ,
  digestEntryBody,
  godotPckReportSchema,
  parseGodotPck,
} from "./godotPck.js";

const md5 = (bytes: Buffer): string =>
  createHash("md5").update(bytes).digest("hex");

// oxlint-disable-next-line max-lines-per-function -- one golden index suite shares the fixture builders; splitting describe blocks would rebuild the same bytes without new semantics.
describe("parseGodotPck", () => {
  it("reports the v2 index with resolved offsets, flags and paging", () => {
    const bodyA = Buffer.from([1, 2, 3, 4]);
    const bodyB = Buffer.from([5, 6, 7, 8, 9, 10]);
    const bytes = buildGodotPck(
      {
        formatVersion: 2,
        engine: { major: 4, minor: 3, patch: 2 },
        packFlags: 0,
      },
      [
        { path: "scripts/a.gdc", body: bodyA },
        { path: "assets/b.png", body: bodyB },
      ],
    );
    const parsed = parseGodotPck(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.report.format_version).toBe(2);
    expect(parsed.report.container).toBe("standalone");
    expect(parsed.report.engine).toEqual({ major: 4, minor: 3, patch: 2 });
    expect(parsed.report.dir_encrypted_flag).toBe(false);
    expect(parsed.report.index.readable).toBe(true);
    if (!parsed.report.index.readable) return;
    expect(parsed.report.index.slice).toEqual({
      entry_total: 2,
      entry_start: 0,
      entry_returned: 2,
      complete: true,
    });
    const [first, second] = parsed.report.index.entries;
    expect(first?.path).toBe("scripts/a.gdc");
    expect(first?.md5_hex).toBe(md5(bodyA));
    expect(first?.size).toBe(4);
    expect(first?.flags).toBe(0);
    expect(first?.encrypted).toBe(false);
    expect(second?.data_offset).toBe(
      first === undefined ? 0 : first.data_offset + first.size,
    );
    void second;
    const report = godotPckReportSchema.parse({
      ...parsed.report,
      artifact: {
        path: "/tmp/game.pck",
        sha256: `${"0".repeat(64)}`,
        bytes: bytes.length,
      },
      extraction: null,
    });
    expect(report.encrypted_entry_count).toBe(0);
  });

  it("pages a readable index without inventing entries", () => {
    const bytes = buildGodotPck(
      { formatVersion: 2, engine: { major: 4, minor: 0, patch: 0 } },
      [0, 1].map((index) => ({
        path: `file${String(index)}.txt`,
        body: Buffer.from([index]),
      })),
    );
    const parsed = parseGodotPck(bytes, { entries_start: 1, entries_limit: 1 });
    if (!parsed.report.index.readable)
      throw new Error("index must be readable");
    expect(parsed.report.index.entries.map((entry) => entry.path)).toEqual([
      "file1.txt",
    ]);
    expect(parsed.report.index.slice).toEqual({
      entry_total: 2,
      entry_start: 1,
      entry_returned: 1,
      complete: true,
    });
  });

  it("keeps v1 flags null and uses absolute offsets", () => {
    const body = Buffer.from([9, 9]);
    const bytes = buildGodotPck(
      { formatVersion: 1, engine: { major: 3, minor: 5, patch: 2 } },
      [{ path: "res://x.txt", body }],
    );
    const parsed = parseGodotPck(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.report.format_version).toBe(1);
    expect(parsed.report.pack_flags).toBeNull();
    expect(parsed.report.reserved_bytes).toBe(0);
    if (!parsed.report.index.readable)
      throw new Error("index must be readable");
    const entry = parsed.report.index.entries[0];
    expect(entry).toMatchObject({
      path: "res://x.txt",
      flags: null,
      encrypted: false,
      size: 2,
      data_offset: entry === undefined ? 0 : entry.stored_offset,
    });
  });

  it("reports the encrypted directory as a typed unknown", () => {
    const bytes = buildGodotPck(
      {
        formatVersion: 2,
        engine: { major: 4, minor: 3, patch: 0 },
        packFlags: PACK_DIR_ENCRYPTED,
      },
      [{ path: "unused.txt" }],
    );
    const parsed = parseGodotPck(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.report.index.readable).toBe(false);
    if (parsed.report.index.readable) return;
    expect(parsed.report.index.reason).toBe("encrypted_index");
    expect(parsed.report.index.detail).toBe(CALLER_KEY_NOT_READ);
    expect(parsed.report.index.file_count).toBeNull();
    expect(parsed.report.index.entries).toBeNull();
    expect(parsed.report.index.unknowns).toEqual([
      { kind: "encrypted-index", detail: CALLER_KEY_NOT_READ },
    ]);
  });

  it("relocates the header behind the embedded footer and keeps body offsets absolute", () => {
    const body = Buffer.from([1, 2, 3]);
    const pck = buildGodotPck(
      { formatVersion: 2, engine: { major: 4, minor: 3, patch: 1 } },
      [{ path: "a.bin", body }],
    );
    const bytes = embedGodotPckWithFooter(pck);
    const parsed = parseGodotPck(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    expect(parsed.report.container).toBe("embedded-with-footer");
    const footer = parsed.report.footer;
    expect(footer).not.toBeNull();
    if (footer === null) return;
    expect(footer.pck_start).toBe(bytes.length - pck.length - 12);
    expect(footer.pck_bytes).toBe(pck.length);
    if (!parsed.report.index.readable)
      throw new Error("index must be readable");
    const entry = parsed.report.index.entries[0];
    expect(entry === undefined ? 0 : entry.data_offset).toBe(
      footer.pck_start + (entry === undefined ? 0 : entry.stored_offset),
    );
  });

  it("digests one entry body in place for optional extraction", () => {
    const body = Buffer.from([1, 2, 3, 4, 5]);
    const bytes = buildGodotPck(
      { formatVersion: 2, engine: { major: 4, minor: 2, patch: 0 } },
      [{ path: "b.bin", body }],
    );
    const parsed = parseGodotPck(bytes, {
      entries_start: 0,
      entries_limit: 10,
    });
    const entry = parsed.locateEntry("b.bin");
    expect(entry).toBeDefined();
    if (entry === undefined) return;
    const digest = digestEntryBody(bytes, entry);
    expect(digest.computed_md5_hex).toBe(entry.md5_hex);
    expect(entry.size).toBeLessThanOrEqual(PCK_EXTRACTION_MAX_BYTES);
    expect(digest.sha256).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("refuses unsupported pack versions and non-PCK artifacts", () => {
    const bytes = buildGodotPck(
      { formatVersion: 2, engine: { major: 4, minor: 3, patch: 0 } },
      [],
    );
    bytes.writeUInt32LE(3, 4);
    expect(() =>
      parseGodotPck(bytes, { entries_start: 0, entries_limit: 10 }),
    ).toThrow(PckFormatError);
    const notPck = Buffer.alloc(64, 0x0a);
    expect(() =>
      parseGodotPck(notPck, { entries_start: 0, entries_limit: 10 }),
    ).toThrow(PckNotFoundError);
  });
});
