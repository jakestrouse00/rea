import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, test } from "vitest";

import { BindiffProvider } from "../../../../src/bindiff/BindiffProvider.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { writeFakeBindiff } from "./fakeBindiff.js";

const sha256 = (contents: string): string =>
  createHash("sha256").update(contents).digest("hex");

const MATCH_TABLE = {
  matches: [
    {
      primary: { address: "0x401000", name: "main" },
      secondary: { address: "0x401020", name: "main" },
      similarity: 0.94,
      confidence: 0.88,
    },
    {
      primary: { address: "0x401100", name: "old_name" },
      secondary: { address: "0x401140", name: "new_name" },
      similarity: 1,
      confidence: 0.91,
    },
    {
      primary: { address: "0x401200", name: "weak" },
      secondary: { address: "0x401240", name: "weak" },
      similarity: 0.6,
      confidence: 0.3,
    },
  ],
  unmatched_primary: 1,
  unmatched_secondary: 2,
};

test("diffs two retained artifacts into a structural match table", async () => {
  const root = await createTestTempDirectory("rea-bindiff-");
  const { launcher, callsPath } = await writeFakeBindiff(root, "bindiff", {
    stdout: MATCH_TABLE,
  });
  const provider = new BindiffProvider({
    environment: { REA_BINDIFF_COMMAND: launcher },
  });
  const primary = join(root, "old.bin");
  const secondary = join(root, "new.bin");
  await writeFile(primary, "OLD-BYTES");
  await writeFile(secondary, "NEW-BYTES");
  const result = await provider.diff({
    primaryPath: primary,
    secondaryPath: secondary,
    primarySha256: sha256("OLD-BYTES"),
    secondarySha256: sha256("NEW-BYTES"),
    maxMatches: 10,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.status).toBe("changed");
  expect(result.value.function_match).toEqual({
    matched: 3,
    unmatched_primary: 1,
    unmatched_secondary: 2,
  });
  expect(result.value.summary).toEqual({
    matched: 3,
    changed: 3,
    unresolved: 1,
  });
  expect(result.value.matches[1]).toEqual({
    primary_address: "0x401100",
    primary_name: "old_name",
    secondary_address: "0x401140",
    secondary_name: "new_name",
    similarity: 1,
    confidence: 0.91,
    names_changed: true,
  });
  expect(
    result.value.changes.map(({ primary_address: address }) => address),
  ).toEqual(["0x401000", "0x401100", "0x401200"]);
  await provider.close();
  expect(await readFile(callsPath, "utf8")).toContain(
    `["${primary}","${secondary}"]`,
  );
});

test("refuses when a retained observation no longer matches the file", async () => {
  const root = await createTestTempDirectory("rea-bindiff-stale-");
  const { launcher } = await writeFakeBindiff(root, "bindiff", {
    stdout: MATCH_TABLE,
  });
  const provider = new BindiffProvider({
    environment: { REA_BINDIFF_COMMAND: launcher },
  });
  const primary = join(root, "old.bin");
  const secondary = join(root, "new.bin");
  await writeFile(primary, "CHANGED");
  await writeFile(secondary, "NEW-BYTES");
  const result = await provider.diff({
    primaryPath: primary,
    secondaryPath: secondary,
    primarySha256: sha256("OLD-BYTES"),
    secondarySha256: sha256("NEW-BYTES"),
    maxMatches: 10,
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  expect(result.error.userMessage).toContain("no longer matches");
  await provider.close();
});

test("rejects an adapter document without a match table", async () => {
  const root = await createTestTempDirectory("rea-bindiff-bad-");
  const { launcher } = await writeFakeBindiff(root, "bindiff", {
    stdout: { rows: [] },
  });
  const provider = new BindiffProvider({
    environment: { REA_BINDIFF_COMMAND: launcher },
  });
  const primary = join(root, "old.bin");
  const secondary = join(root, "new.bin");
  await writeFile(primary, "OLD-BYTES");
  await writeFile(secondary, "NEW-BYTES");
  const result = await provider.diff({
    primaryPath: primary,
    secondaryPath: secondary,
    primarySha256: sha256("OLD-BYTES"),
    secondarySha256: sha256("NEW-BYTES"),
    maxMatches: 10,
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("refuses plainly when no BinDiff adapter is selected", async () => {
  const provider = new BindiffProvider({ environment: {} });
  const result = await provider.diff({
    primaryPath: "/does/not/matter",
    secondaryPath: "/does/not/matter-either",
    primarySha256: "0".repeat(64),
    secondarySha256: "1".repeat(64),
    maxMatches: 10,
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_BINDIFF_COMMAND");
  await provider.close();
});

test("publishes a BINE-magic BinExport file into a new subdirectory", async () => {
  const root = await createTestTempDirectory("rea-binexport-");
  const contents = "BINE-FIXTURE-PAYLOAD";
  const { launcher, callsPath } = await writeFakeBindiff(root, "exporter", {
    exportFile: { name: "sample.BinExport", contents },
  });
  const provider = new BindiffProvider({
    environment: { REA_BINEXPORT_COMMAND: launcher },
  });
  const source = join(root, "sample.so");
  await writeFile(source, "ELF-FIXTURE");
  const result = await provider.exportBinexport({
    path: source,
    outputDirectory: join(root, "out"),
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.file).toEqual({
    relative_path: "sample.BinExport",
    bytes: contents.length,
    sha256: sha256(contents),
    format: "binexport",
  });
  const published = join(
    result.value.output_directory,
    result.value.file.relative_path,
  );
  expect(await readFile(published, "utf8")).toBe(contents);
  expect((await stat(published)).mode & 0o777).toBe(0o600);
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain(`["${source}"`);
});

test("rejects an exporter output without the BINE magic", async () => {
  const root = await createTestTempDirectory("rea-binexport-bad-");
  const { launcher } = await writeFakeBindiff(root, "exporter", {
    exportFile: { name: "sample.BinExport", contents: "NOPE" },
  });
  const provider = new BindiffProvider({
    environment: { REA_BINEXPORT_COMMAND: launcher },
  });
  const source = join(root, "sample.so");
  await writeFile(source, "ELF-FIXTURE");
  const result = await provider.exportBinexport({
    path: source,
    outputDirectory: join(root, "out"),
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("reports BinDiff and BinExport availability separately", async () => {
  const root = await createTestTempDirectory("rea-bindiff-avail-");
  const { launcher } = await writeFakeBindiff(root, "bindiff", {
    stdout: MATCH_TABLE,
  });
  const provider = new BindiffProvider({
    environment: { REA_BINDIFF_COMMAND: launcher },
  });
  expect(provider.inspectDiffAvailability()).toMatchObject({
    status: "available",
  });
  expect(provider.inspectExportAvailability()).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await provider.close();
});
