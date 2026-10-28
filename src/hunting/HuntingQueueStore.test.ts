import { stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  HUNTING_QUEUE_SCHEMA_VERSION,
  HuntingQueueStore,
  HuntingQueueStoreFailure,
} from "./HuntingQueueStore.js";

const TARGET = "/cases/api/target.bin";
const OTHER_TARGET = "/cases/api/other.bin";
const BATCH = "2f1c9d4e-0b6a-4c8f-9e37-5a1f0d2b7c33";

const recipe = {
  kind: "re-analysis" as const,
  operation: "binary_overview" as const,
};

const unit = (position: number, targetPath: string, score: number) => ({
  unitId: `hunt_${String(position).padStart(1, "0")}${"a".repeat(63)}`,
  position,
  targetPath,
  recipe,
  priority: { score, reasons: [] },
});

const open = async (directory: string) => {
  const store = new HuntingQueueStore(directory, "darwin");
  await store.ensure();
  return store;
};

describe("durable hunting queue store", () => {
  it("creates the queue file owner-only and keeps it after close", async () => {
    const directory = await createTestTempDirectory("hunting-store-");
    const store = await open(directory);
    store.createBatch(
      {
        batchId: BATCH,
        createdAt: "2026-10-28T00:00:00.000Z",
        maxUnits: 2,
        maxSeconds: 60,
      },
      [unit(0, TARGET, 5)],
    );
    await store.close();
    const mode = (await stat(join(directory, "queue.sqlite"))).mode & 0o777;
    expect(mode).toBe(0o600);
    const reopened = await open(directory);
    expect(reopened.batch(BATCH)?.maxUnits).toBe(2);
    expect(reopened.unitCount(BATCH)).toBe(1);
    await reopened.close();
  });

  it("refuses a schema version it does not write", async () => {
    const directory = await createTestTempDirectory("hunting-store-");
    const path = join(directory, "queue.sqlite");
    const database = new DatabaseSync(path);
    database.exec(
      `PRAGMA user_version = ${String(HUNTING_QUEUE_SCHEMA_VERSION + 1)}`,
    );
    database.close();
    const store = new HuntingQueueStore(directory, "darwin");
    await expect(store.ensure()).rejects.toBeInstanceOf(
      HuntingQueueStoreFailure,
    );
    await expect(store.ensure()).rejects.toMatchObject({
      reason: "unsupported_schema",
    });
  });

  it("reports an unreadable queue file as an io failure, never an empty queue", async () => {
    const directory = await createTestTempDirectory("hunting-store-");
    await writeFile(join(directory, "queue.sqlite"), "not a database");
    const store = new HuntingQueueStore(directory, "darwin");
    await expect(store.ensure()).rejects.toMatchObject({ reason: "io" });
  });

  it("refuses to admit a unit another store handle already took", async () => {
    const directory = await createTestTempDirectory("hunting-store-");
    const first = await open(directory);
    first.createBatch(
      {
        batchId: BATCH,
        createdAt: "2026-10-28T00:00:00.000Z",
        maxUnits: 2,
        maxSeconds: 60,
      },
      [unit(0, TARGET, 5)],
    );
    const second = await open(directory);
    const unitId = unit(0, TARGET, 5).unitId;
    first.beginUnit(unitId, "2026-10-28T00:00:01.000Z");
    expect(() => second.beginUnit(unitId, "2026-10-28T00:00:02.000Z")).toThrow(
      HuntingQueueStoreFailure,
    );
    expect(second.unit(unitId)?.state).toBe("running");
    expect(second.unit(unitId)?.attempt).toBe(1);
    await first.close();
    await second.close();
  });

  it("admits queued units before blocked ones and keeps a stable order", async () => {
    const directory = await createTestTempDirectory("hunting-store-");
    const store = await open(directory);
    store.createBatch(
      {
        batchId: BATCH,
        createdAt: "2026-10-28T00:00:00.000Z",
        maxUnits: 4,
        maxSeconds: 60,
      },
      [unit(0, OTHER_TARGET, 90), unit(1, TARGET, 5)],
    );
    expect(store.nextUnit(BATCH)?.targetPath).toBe(OTHER_TARGET);
    store.finishUnit({
      unitId: unit(0, OTHER_TARGET, 90).unitId,
      state: "blocked",
      at: "2026-10-28T00:00:01.000Z",
      stop: {
        kind: "precondition",
        error_tag: "RecipeNotComposed",
        operation: null,
      },
      observation: null,
    });
    expect(store.nextUnit(BATCH)?.targetPath).toBe(TARGET);
    store.appendUnits({
      batch: {
        batchId: BATCH,
        createdAt: "2026-10-28T00:00:00.000Z",
        maxUnits: 4,
        maxSeconds: 60,
      },
      newBatch: false,
      units: [unit(2, TARGET, 500)],
    });
    expect(store.nextUnit(BATCH)?.unitId).toBe(unit(2, TARGET, 500).unitId);
    expect(store.unitStates(BATCH)).toEqual({
      queued: 2,
      running: 0,
      blocked: 1,
      succeeded: 0,
      failed: 0,
      stopped: 0,
      cancelled: 0,
    });
    await store.close();
  });
});
