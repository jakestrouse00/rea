import { expect, it } from "vitest";
import {
  BinaryFormatFailure,
  BinaryResourceFailure,
} from "../native/metadata/BinaryContainer.js";
import { readBinaryContainer } from "../native/metadata/readBinaryContainer.js";
import {
  readGoPclntabProcedures,
  readGoPclntab,
  type GoPclntabTable,
} from "./GoPclntab.js";
import {
  createPclntabFixture,
  TEXT_BASE,
  NFUNC,
  TABLE_OFFSET,
} from "./GoPclntab.fixture.js";

it.each(["go120", "go118", "go116"] as const)(
  "decodes %s-era rows with ordered entries from a declared gopclntab",
  (magic) => {
    const bytes = createPclntabFixture({ magic });
    const table = readGoPclntab(bytes);
    expect(table).not.toBeNull();
    if (table === null) throw new Error("fixture table missing");
    expect(table.era).toBe(
      magic === "go120"
        ? "go1.20+"
        : magic === "go118"
          ? "go1.18-1.19"
          : "go1.16-1.17",
    );
    expect(table.location.source).toBe("section");
    expect(table.nfunc).toBe(NFUNC);
    // Relative eras already prove the text base, so the moduledata scan is skipped.
    expect(table.moduledata.found).toBe(magic === "go116");
    expect(table.moduledata.nfunc_matches).toBe(
      magic === "go116" ? true : null,
    );
    const rows = readGoPclntabProcedures(bytes, table, 0, 50);
    expect(rows.map((row) => row.index)).toEqual([0, 1, 2]);
    expect(rows.map((row) => row.name)).toEqual([
      "go:buildid",
      "runtime.text",
      "main.main",
    ]);
    for (const row of rows) {
      expect(row.entry_offset).toBe(BigInt(row.index * 3));
      expect(row.end_offset).toBe(
        row.index === NFUNC - 1 ? 9n : BigInt((row.index + 1) * 3),
      );
      expect(row.entry).toBe(TEXT_BASE + BigInt(row.entry_offset ?? 0));
    }
  },
);

it("recovers the text base through moduledata when the producer zeroed textStart", () => {
  const bytes = createPclntabFixture({ textStart: 0n });
  const table = readGoPclntab(bytes);
  expect(table?.text_base).toEqual({
    address: TEXT_BASE,
    source: "moduledata",
  });
  expect(table?.moduledata.found).toBe(true);
  expect(table?.moduledata.nfunc_matches).toBe(true);
  expect(table?.moduledata.text).toBe(TEXT_BASE);
});

it("uses the first absolute entry as a go1.16 text base without moduledata", () => {
  const bytes = createPclntabFixture({ magic: "go116" });
  const table = readGoPclntab(bytes);
  expect(table?.text_base?.source).toBe("moduledata");
  expect(table?.text_base?.address).toBe(TEXT_BASE);
});

it("keeps addresses unknown when no text base is recoverable", () => {
  const bytes = createPclntabFixture({ textStart: 0n, withModuledata: false });
  const table = readGoPclntab(bytes);
  expect(table?.text_base).toBeNull();
  const rows = readGoPclntabProcedures(bytes, table as GoPclntabTable, 0, 10);
  expect(rows[0]?.name).toBe("go:buildid");
  expect(rows[0]?.entry).toBeNull();
  expect(rows[0]?.entry_offset).toBe(0n);
});

it("finds a sectionless table through the mapped-span search", () => {
  const bytes = createPclntabFixture({
    sectionless: true,
    withModuledata: false,
  });
  const table = readGoPclntab(bytes);
  expect(table?.location.source).toBe("search");
  expect(table?.location.section_name).toBeNull();
  expect(table?.nfunc).toBe(NFUNC);
  expect(table?.text_base?.source).toBe("pclntab-header");
});

it("reports a legacy pclntab as recognized without decoding rows", () => {
  const bytes = createPclntabFixture({
    magic: "legacy",
    withModuledata: false,
  });
  const table = readGoPclntab(bytes);
  expect(table?.era).toBe("go1.2-1.15");
  expect(table?.functab).toBeNull();
  expect(table?.funcnametab).toBeNull();
  expect(table?.nfunc).toBe(NFUNC);
  expect(
    readGoPclntabProcedures(bytes, table as GoPclntabTable, 0, 10),
  ).toEqual([]);
});

it("keeps rows positioned when name resolution fails", () => {
  const bytes = createPclntabFixture({
    badNameoffRow: 1,
    textStart: 0n,
    withModuledata: false,
    magic: "go118",
  });
  const table = readGoPclntab(bytes) as GoPclntabTable;
  const rows = readGoPclntabProcedures(bytes, table, 0, 10);
  expect(rows[1]?.name).toBeNull();
  expect(rows[0]?.name).toBe("go:buildid");
  expect(rows[1]?.entry_offset).toBe(3n);
});

it("keeps linker-hole rows positioned without names", () => {
  const bytes = createPclntabFixture({ holeRow: 1, withModuledata: false });
  const table = readGoPclntab(bytes) as GoPclntabTable;
  const rows = readGoPclntabProcedures(bytes, table, 0, 10);
  expect(rows[1]?.name).toBeNull();
  expect(rows[0]?.name).toBe("go:buildid");
  expect(rows[1]?.entry).toBe(TEXT_BASE + 3n);
});

it("discloses when the moduledata scan exceeds its decoding budget", () => {
  const bytes = createPclntabFixture({
    magic: "go118",
    textStart: 0n,
    oversizedModuledata: true,
  });
  const table = readGoPclntab(bytes);
  expect(table?.moduledata).toMatchObject({
    found: false,
    budget_limited: true,
  });
});

it("rejects searched bytes that only look like a pclntab header", () => {
  const bytes = createPclntabFixture({ sectionless: true, noTable: true });
  bytes.writeUInt32LE(0xfffffff1, 8000);
  bytes[8004] = 0;
  bytes[8005] = 0;
  bytes[8006] = 1;
  bytes[8007] = 8;
  bytes.writeBigUInt64LE(BigInt(16), 8008);
  bytes.writeBigUInt64LE(BigInt(24), 8016);
  bytes.writeBigUInt64LE(0xffffffffffffffffn, 8024);
  bytes.writeBigUInt64LE(BigInt(16), 8032);
  bytes.writeBigUInt64LE(BigInt(16), 8040);
  bytes.writeBigUInt64LE(BigInt(16), 8048);
  bytes.writeBigUInt64LE(BigInt(0), 8056);
  expect(readGoPclntab(bytes)).toBeNull();
});

it("finds a searched table without declared sections", () => {
  const bytes = createPclntabFixture({
    sectionless: true,
    withModuledata: false,
  });
  const table = readGoPclntab(bytes);
  expect(table?.location.source).toBe("search");
});

it("throws a resource failure for an oversized function table", () => {
  const bytes = createPclntabFixture({
    sectionless: true,
    withModuledata: false,
  });
  bytes.writeBigUInt64LE(3000000n, TABLE_OFFSET + 8);
  expect(() => readGoPclntab(bytes)).toThrow(BinaryResourceFailure);
  expect(() => readGoPclntab(bytes)).toThrow(/16 MiB/);
});

it("treats a malformed declared gopclntab as a format failure", () => {
  const bytes = createPclntabFixture({ unsorted: true });
  expect(() => readGoPclntab(bytes)).toThrow(BinaryFormatFailure);
  expect(() => readGoPclntab(bytes)).toThrow(/sorted/);
});

it("reads bounded pages with sentinel end values", () => {
  const bytes = createPclntabFixture({});
  const table = readGoPclntab(bytes) as GoPclntabTable;
  const page = readGoPclntabProcedures(bytes, table, 1, 1);
  expect(page.map((row) => row.index)).toEqual([1]);
  expect(page[0]?.end_offset).toBe(6n);
  const tail = readGoPclntabProcedures(bytes, table, 2, 5);
  expect(tail.map((row) => row.index)).toEqual([2]);
  expect(tail[0]?.end_offset).toBe(9n);
  expect(tail[0]?.end).toBe(TEXT_BASE + 9n);
  expect(readGoPclntabProcedures(bytes, table, 3, 5)).toEqual([]);
});
