import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { collectForensicTables, parseForensicTsv } from "./IleappReport.js";
import { MOBILE_LIMITS } from "./MobileToolchainRelease.js";

const temporaryDirectories: string[] = [];

const makeDirectory = async (): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-ileapp-test-"));
  temporaryDirectories.push(directory);
  return directory;
};

afterEach(async () => {
  for (const directory of temporaryDirectories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

describe("TSV parsing", () => {
  it("reads the header and rows of a table exactly as written", () => {
    const table = parseForensicTsv(
      { name: "sms.tsv", bytes: 42, sha256: "a".repeat(64) },
      "id\taddress\tbody\n1\t+15550100\thello\n2\t+15550101\thi\n",
      { maxRows: 10 },
    );
    expect(table.columns).toEqual(["id", "address", "body"]);
    expect(table.rows).toEqual([
      ["1", "+15550100", "hello"],
      ["2", "+15550101", "hi"],
    ]);
    expect(table.rowCount).toBe(2);
    expect(table.retainedRows).toBe(2);
    expect(table.truncated).toBe(false);
    expect(table.sha256).toBe("a".repeat(64));
  });

  it("keeps ragged rows as printed and marks the table truncated", () => {
    const table = parseForensicTsv(
      { name: "ragged.tsv", bytes: 12, sha256: "b".repeat(64) },
      "a\tb\tc\n1\t2\n",
      { maxRows: 10 },
    );
    expect(table.columns).toHaveLength(3);
    expect(table.rows).toEqual([["1", "2"]]);
    expect(table.truncated).toBe(false);
  });

  it("bounds rows and long cells instead of dropping the table", () => {
    const longCell = "x".repeat(MOBILE_LIMITS.forensicCellCharacters + 10);
    const table = parseForensicTsv(
      { name: "long.tsv", bytes: 99, sha256: "c".repeat(64) },
      `h\n${longCell}\nsecond\nthird\n`,
      { maxRows: 2 },
    );
    expect(table.rows[0]).toEqual([
      "x".repeat(MOBILE_LIMITS.forensicCellCharacters),
    ]);
    expect(table.rowCount).toBe(3);
    expect(table.retainedRows).toBe(2);
    expect(table.truncated).toBe(true);
  });

  it("marks a table with no header as truncated instead of inventing columns", () => {
    const table = parseForensicTsv(
      { name: "empty.tsv", bytes: 0, sha256: "d".repeat(64) },
      "",
      { maxRows: 5 },
    );
    expect(table.columns).toEqual([]);
    expect(table.rows).toEqual([]);
    expect(table.truncated).toBe(true);
  });
});

describe("forensic table collection", () => {
  it("reads only TSV files in a deterministic order with digests", async () => {
    const directory = await makeDirectory();
    await writeFile(join(directory, "b.tsv"), "h\n2\n", "utf8");
    await writeFile(join(directory, "a.tsv"), "h\n1\n", "utf8");
    await writeFile(join(directory, "ignored.txt"), "not a table", "utf8");
    const collected = await collectForensicTables(directory, {
      maxTables: 10,
      maxRowsPerTable: 10,
    });
    expect(collected.tables.map(({ name }) => name)).toEqual([
      "a.tsv",
      "b.tsv",
    ]);
    expect(collected.tables[0]!.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(collected.totalRows).toBe(2);
    expect(collected.unparsedFiles).toEqual([]);
    expect(collected.truncated).toBe(false);
  });

  it("bounds the table count and reports that bound", async () => {
    const directory = await makeDirectory();
    await writeFile(join(directory, "a.tsv"), "h\n1\n", "utf8");
    await writeFile(join(directory, "b.tsv"), "h\n2\n", "utf8");
    const collected = await collectForensicTables(directory, {
      maxTables: 1,
      maxRowsPerTable: 10,
    });
    expect(collected.tables).toHaveLength(1);
    expect(collected.truncated).toBe(true);
  });

  it("reports an absent output directory as no tables, not an error", async () => {
    const collected = await collectForensicTables("/nonexistent-rea-out", {
      maxTables: 4,
      maxRowsPerTable: 4,
    });
    expect(collected.tables).toEqual([]);
    expect(collected.truncated).toBe(false);
  });
});
