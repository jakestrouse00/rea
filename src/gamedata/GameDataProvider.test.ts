import {
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
  readFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, expect, it } from "vitest";

import { GameDataProvider } from "./GameDataProvider.js";
import { RpgmakerDirectoryError } from "../domain/gamedata/rpgmakerAssets.js";
import {
  buildGamemakerForm,
  buildGen8Payload,
  buildGodotPck,
  buildPlainPng,
  buildRpa3,
  buildRpgmakerEncryptedOgg,
  buildRpgmakerEncryptedPng,
  buildVpkDirectory,
} from "../domain/gamedata/gamedataFixtures.js";

const KEY = 0xdeadbeef;

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const root = await mkdtemp(join(tmpdir(), "rea-gamedata-"));
const provider = new GameDataProvider();
afterAll(async () => {
  await provider.close();
  await rm(root, { recursive: true, force: true });
});

const godot = buildGodotPck(
  { formatVersion: 2, engine: { major: 4, minor: 3, patch: 0 } },
  [
    { path: "scripts/main.gdc", body: Buffer.from([1, 2, 3, 4]) },
    { path: "assets/piece.png", body: Buffer.from([5, 6, 7, 8, 9, 10]) },
  ],
);
const godotPath = join(root, "game.pck");
await writeFile(godotPath, godot);

it("inspects a Godot PCK and verifies the written extraction", async () => {
  const extractDirectory = join(root, "extracts");
  await mkdir(extractDirectory, { recursive: true });
  const execution = await provider.execute({
    operation: "inspect_godot_pck",
    input: {
      path: godotPath,
      entries_start: 0,
      entries_limit: 10,
      extract: {
        entry_path: "assets/piece.png",
        output_directory: extractDirectory,
      },
    },
  });
  expect(execution.ok).toBe(true);
  if (!execution.ok) return;
  const report = execution.value.result as unknown as {
    index: {
      readable: boolean;
      entries: { path: string; data_offset: number }[];
    };
    extraction: {
      sha256: string;
      output_path: string;
      md5_matches_stored: boolean;
      bytes: number;
    };
    limitations: readonly string[];
  };
  expect(report.index.readable).toBe(true);
  expect(report.extraction).not.toBeNull();
  if (report.extraction === null) return;
  expect(report.extraction.md5_matches_stored).toBe(true);
  const written = await readFile(report.extraction.output_path);
  expect(sha256(written)).toBe(report.extraction.sha256);
  expect(execution.value.subject).toMatchObject({
    path: godotPath,
    format: "file",
  });
  expect(execution.value.limitations.length).toBeGreaterThan(0);
});

it("pages the Godot index through one provider request", async () => {
  const execution = await provider.execute({
    operation: "inspect_godot_pck",
    input: { path: godotPath, entries_start: 1, entries_limit: 1 },
  });
  expect(execution.ok).toBe(true);
  if (!execution.ok) return;
  const report = execution.value.result as unknown as {
    index: {
      readable: boolean;
      entries: { path: string }[];
      slice: { entry_total: number };
    };
  };
  expect(report.index.entries.map((entry) => entry.path)).toEqual([
    "assets/piece.png",
  ]);
  expect(report.index.slice.entry_total).toBe(2);
});

it("refuses an encrypted Godot entry without writing anything", async () => {
  const encrypted = buildGodotPck(
    {
      formatVersion: 2,
      engine: { major: 4, minor: 3, patch: 0 },
      packFlags: 1, // encrypted directory, per the header flag
    },
    [{ path: "unused.txt" }],
  );
  const path = join(root, "encrypted.pck");
  await writeFile(path, encrypted);
  const execution = await provider.execute({
    operation: "inspect_godot_pck",
    input: {
      path,
      entries_start: 0,
      entries_limit: 10,
      extract: { entry_path: "unused.txt", output_directory: root },
    },
  });
  expect(execution.ok).toBe(false);
  if (execution.ok) return;
  expect(execution.error.name).toBeDefined();
});

it("inspects a VPK directory report only", async () => {
  const vpkPath = join(root, "pak01_dir.vpk");
  await writeFile(
    vpkPath,
    buildVpkDirectory(2, [
      {
        dir: "maps",
        name: "de_test",
        ext: "bsp",
        crc32: 0x1234,
        archiveIndex: 0,
        entryOffset: 0,
        entryLength: 10,
      },
      {
        dir: "materials",
        name: "brick",
        ext: "vmt",
        crc32: 0x5678,
        preload: Buffer.from([9, 9]),
      },
    ]),
  );
  const execution = await provider.execute({
    operation: "inspect_vpk_archive",
    input: { path: vpkPath, entries_start: 0, entries_limit: 10 },
  });
  expect(execution.ok).toBe(true);
  if (!execution.ok) return;
  const report = execution.value.result as unknown as {
    entries: { path: string }[];
    format_version: number;
  };
  expect(report.format_version).toBe(2);
  expect(report.entries).toHaveLength(2);
});

it("maps GameMaker chunks and GEN8 fields", async () => {
  const gen8 = buildGen8Payload({
    filename: "made-with-gm",
    config: "default",
    name: "Fixture",
    gameId: 777,
    baseOffset: 16,
  });
  const dataPath = join(root, "data.win");
  await writeFile(
    dataPath,
    buildGamemakerForm([
      { fourcc: "GEN8", payload: gen8.payload },
      { fourcc: "CODE", payload: Buffer.alloc(16, 1) },
      { fourcc: "STRG", payload: Buffer.alloc(8, 2) },
      { fourcc: "SOND", payload: Buffer.alloc(4, 3) },
    ]),
  );
  const execution = await provider.execute({
    operation: "inspect_gamemaker_data",
    input: { path: dataPath },
  });
  expect(execution.ok).toBe(true);
  if (!execution.ok) return;
  const report = execution.value.result as unknown as {
    chunk_walk_complete: boolean;
    gen8: { game_id: number; file_identification: { text: string } | null };
    named_chunks: { CODE: unknown; SOND: unknown; TXOR: unknown };
  };
  expect(report.chunk_walk_complete).toBe(true);
  expect(report.gen8?.game_id).toBe(777);
  expect(report.gen8?.file_identification?.text).toBe("made-with-gm");
  expect(report.named_chunks.CODE).not.toBeNull();
  expect(report.named_chunks.TXOR).toBeNull();
});

it("reads an RPA-3.0 index through the provider", async () => {
  const rpaPath = join(root, "archive.rpa");
  await writeFile(
    rpaPath,
    buildRpa3(KEY, {
      "images/a.png": [[(0x100 ^ KEY) >>> 0, (0x10 ^ KEY) >>> 0]],
      "data/c.rpyc": [[(0x200 ^ KEY) >>> 0, (0x20 ^ KEY) >>> 0]],
    }),
  );
  const execution = await provider.execute({
    operation: "inspect_rpa_archive",
    input: { path: rpaPath, entries_start: 0, entries_limit: 10 },
  });
  expect(execution.ok).toBe(true);
  if (!execution.ok) return;
  const report = execution.value.result as unknown as {
    index: {
      key_hex: string;
      entry_total: number;
      entries: { path: string; offset: number; encrypted: boolean }[];
    };
  };
  expect(report.index.key_hex).toBe("deadbeef");
  expect(report.index.entries.map((entry) => entry.path)).toEqual([
    "data/c.rpyc",
    "images/a.png",
  ]);
  expect(report.index.entries.every((entry) => entry.encrypted)).toBe(true);
});

it("detects RPG Maker prefixes across a scanned directory", async () => {
  const assets = join(root, "assets");
  const nested = join(assets, "audio");
  await mkdir(nested, { recursive: true });
  await writeFile(join(nested, "encrypted.png"), buildRpgmakerEncryptedPng());
  await writeFile(join(nested, "encrypted.ogg"), buildRpgmakerEncryptedOgg());
  await writeFile(join(assets, "plain.png"), buildPlainPng());
  await writeFile(join(assets, "plain.txt"), Buffer.alloc(64, 0x61));
  await symlink(join(assets, "plain.png"), join(nested, "link.png"));
  const execution = await provider.execute({
    operation: "inspect_rpgmaker_asset_prefixes",
    input: {
      directory: assets,
      extensions: ["png", "ogg", "oga", "m4a"],
      entries_start: 0,
      entries_limit: 10,
    },
  });
  expect(execution.ok).toBe(true);
  if (!execution.ok) return;
  const report = execution.value.result as unknown as {
    encrypted_count: number;
    plain_count: number;
    candidate_total: number;
    symlink_skipped: number;
    files: { path: string; prefix_present: boolean }[];
    unreadable_paths: readonly string[];
  };
  expect(report.encrypted_count).toBe(2);
  expect(report.plain_count).toBe(1);
  expect(report.candidate_total).toBe(3);
  expect(report.symlink_skipped).toBe(1);
  expect(report.unreadable_paths).toEqual([]);
});

it("rejects relative paths before touching the filesystem", async () => {
  const execution = await provider.execute({
    operation: "inspect_godot_pck",
    input: { path: "relative/game.pck", entries_start: 0, entries_limit: 10 },
  });
  expect(execution.ok).toBe(false);
});

it("reports deep rpgmaker nesting through the typed discriminator", async () => {
  const deep = join(root, "deep");
  let leaf = deep;
  for (let level = 0; level <= 16; level += 1)
    leaf = join(leaf, `level${level}`);
  await mkdir(leaf, { recursive: true });
  await writeFile(join(leaf, "asset.png"), buildPlainPng());
  const execution = await provider.execute({
    operation: "inspect_rpgmaker_asset_prefixes",
    input: {
      directory: deep,
      extensions: ["png", "ogg", "oga", "m4a"],
      entries_start: 0,
      entries_limit: 10,
    },
  });
  expect(execution.ok).toBe(false);
  if (execution.ok) return;
  const error = execution.error as unknown as {
    _tag: string;
    operation: string;
    resource: string;
    reportedLimits: Record<string, unknown> | null;
  };
  expect(error._tag).toBe("AnalysisResourceConstraintError");
  expect(error.operation).toBe("inspect_rpgmaker_asset_prefixes");
  expect(error.resource).toBe("capacity");
  expect(error.reportedLimits).toEqual({ maximum_directory_depth: 16 });
});

it("carries the rpgmaker capacity discriminator on the producer error", () => {
  const nesting = new RpgmakerDirectoryError("nesting", "x");
  expect(nesting.kind).toBe("nesting");
  const capacity = new RpgmakerDirectoryError("capacity", "x");
  expect(capacity.kind).toBe("capacity");
});

it("reports the true operation when a selected path cannot be read", async () => {
  const godot = await provider.execute({
    operation: "inspect_godot_pck",
    input: {
      path: join(root, "missing.pck"),
      entries_start: 0,
      entries_limit: 10,
    },
  });
  expect(godot.ok).toBe(false);
  if (godot.ok) return;
  expect((godot.error as unknown as { operation: string }).operation).toBe(
    "inspect_godot_pck",
  );
  const rpgmaker = await provider.execute({
    operation: "inspect_rpgmaker_asset_prefixes",
    input: {
      directory: join(root, "missing-assets"),
      extensions: ["png", "ogg", "oga", "m4a"],
      entries_start: 0,
      entries_limit: 10,
    },
  });
  expect(rpgmaker.ok).toBe(false);
  if (rpgmaker.ok) return;
  const error = rpgmaker.error as unknown as { operation: string };
  expect(error.operation).toBe("inspect_rpgmaker_asset_prefixes");
});
