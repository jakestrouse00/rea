import { describe, expect, it } from "vitest";

import { buildGamemakerForm, buildGen8Payload } from "./gamedataFixtures.js";
import {
  GameMakerFormatError,
  parseGamemakerData,
  gamemakerReportSchema,
} from "./gamemakerData.js";

describe("parseGamemakerData", () => {
  it("walks FORM chunks and resolves GEN8 string pointers", () => {
    // GEN8 is the first chunk: its payload begins at 8 (FORM) + 8 (GEN8 header).
    const gen8 = buildGen8Payload({
      filename: "game_run.win",
      config: "default",
      name: "Sample Game",
      gameId: 424242,
      tailBytes: 16,
      baseOffset: 16,
    });
    const bytes = buildGamemakerForm([
      { fourcc: "GEN8", payload: gen8.payload },
      { fourcc: "OPTN", payload: Buffer.alloc(8, 1) },
      { fourcc: "SOND", payload: Buffer.alloc(12, 2) },
      { fourcc: "CODE", payload: Buffer.alloc(32, 3) },
      { fourcc: "STRG", payload: Buffer.alloc(24, 4) },
      { fourcc: "TXOR", payload: Buffer.alloc(4, 5) },
    ]);
    const parsed = parseGamemakerData(bytes);
    expect(parsed.chunk_walk_complete).toBe(true);
    expect(parsed.chunks.map((chunk) => chunk.fourcc)).toEqual([
      "GEN8",
      "OPTN",
      "SOND",
      "CODE",
      "STRG",
      "TXOR",
    ]);
    expect(parsed.named_chunks.SOND).not.toBeNull();
    expect(parsed.named_chunks.CODE).not.toBeNull();
    expect(parsed.named_chunks.STRG).not.toBeNull();
    expect(parsed.named_chunks.TXOR).not.toBeNull();
    const gen8Report = parsed.gen8;
    expect(gen8Report).not.toBeNull();
    if (gen8Report === null) return;
    expect(gen8Report.bytecode_version).toBe(17);
    expect(gen8Report.debugger_disabled).toBe(true);
    expect(gen8Report.game_id).toBe(424242);
    expect(gen8Report.file_identification).toMatchObject({
      text: "game_run.win",
    });
    expect(gen8Report.config).toMatchObject({ text: "default" });
    expect(gen8Report.name).toMatchObject({ text: "Sample Game" });
    expect(gen8Report.unexamined_bytes).toBe(gen8.payload.length - 44);
    expect(gen8Report.direct_play_guid_hex).toBe("33".repeat(16));
  });

  it("reports a truncated walk instead of inventing chunks", () => {
    const gen8Payload = buildGen8Payload({ tailBytes: 0 }).payload;
    const bytes = buildGamemakerForm([
      { fourcc: "GEN8", payload: gen8Payload },
      { fourcc: "SOND", payload: Buffer.alloc(4, 9) },
    ]);
    // The SOND chunk's size field sits at 8 (FORM) + 12 (GEN8) + payload + 4.
    const truncated = Buffer.from(bytes);
    truncated.writeUInt32LE(9999, 8 + 8 + gen8Payload.length + 4);
    const parsed = parseGamemakerData(truncated);
    expect(parsed.chunk_walk_complete).toBe(false);
    expect(parsed.chunks.length).toBe(1);
    expect(parsed.unexplained_bytes).toBeGreaterThan(0);
  });

  it("treats absent chunks as null presence, not empty ranges", () => {
    const bytes = buildGamemakerForm([
      { fourcc: "GEN8", payload: buildGen8Payload({}).payload },
    ]);
    const parsed = parseGamemakerData(bytes);
    expect(parsed.named_chunks.CODE).toBeNull();
    expect(parsed.named_chunks.STRG).toBeNull();
    expect(parsed.named_chunks.TXOR).toBeNull();
    expect(parsed.named_chunks.SOND).toBeNull();
    expect(parsed.gen8?.file_identification).toBeNull();
  });

  it("rejects non-FORM artifacts and round-trips the schema", () => {
    const bytes = buildGamemakerForm([
      { fourcc: "GEN8", payload: buildGen8Payload({}).payload },
    ]);
    expect(() => parseGamemakerData(Buffer.alloc(32, 7))).toThrow(
      GameMakerFormatError,
    );
    const report = gamemakerReportSchema.parse({
      ...parseGamemakerData(bytes),
      artifact: {
        path: "/tmp/game/data.win",
        sha256: "0".repeat(64),
        bytes: bytes.length,
      },
    });
    expect(report.limitations.length).toBeGreaterThan(0);
  });
});
