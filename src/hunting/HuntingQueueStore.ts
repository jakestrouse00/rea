import { chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { homeDirectoryFromEnvironment } from "../config/homeDirectory.js";
import type {
  HuntingBatchState,
  HuntingObservationFacts,
  HuntingPriorityFacts,
  HuntingStop,
  HuntingUnitState,
} from "../domain/hunting/huntingObservation.js";
import {
  huntingBatchStateSchema,
  huntingObservationFactsSchema,
  huntingPrioritySchema,
  huntingStopSchema,
  huntingUnitStateSchema,
} from "../domain/hunting/huntingObservation.js";
import {
  huntingRecipeSchema,
  type HuntingRecipe,
} from "../domain/hunting/huntingRecipes.js";
import {
  HUNTING_QUEUE_FILE_NAME,
  HUNTING_STATE_RELATIVE_DIRECTORY,
} from "../domain/hunting/huntingLimits.js";
import type { JsonValue } from "../domain/jsonValue.js";

/** Current on-disk schema version of the durable hunting queue. */
export const HUNTING_QUEUE_SCHEMA_VERSION = 1;

/** Why the durable queue could not be opened or used. */
export type HuntingQueueStoreFailureReason =
  | "io"
  | "unsupported_schema"
  | "cleanup";

export class HuntingQueueStoreFailure extends Error {
  readonly _tag = "HuntingQueueStoreFailure";
  constructor(
    readonly reason: HuntingQueueStoreFailureReason,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "HuntingQueueStoreFailure";
  }
}

/** Owner-only queue directory under the REA home, beside other durable state. */
export const huntingQueueDirectory = (
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform = process.platform,
): string =>
  join(
    homeDirectoryFromEnvironment(environment, platform),
    ".rea",
    ...HUNTING_STATE_RELATIVE_DIRECTORY,
  );

/** One scheduled batch as the store retained it. */
export interface StoredHuntingBatch {
  readonly batchId: string;
  readonly createdAt: string;
  readonly state: HuntingBatchState;
  readonly maxUnits: number;
  readonly maxSeconds: number;
  readonly unitsStarted: number;
  readonly spentMs: number;
  readonly cancelledAt: string | null;
}

/** One queued unit as the store retained it. */
export interface StoredHuntingUnit {
  readonly unitId: string;
  readonly batchId: string;
  readonly position: number;
  readonly targetPath: string;
  readonly recipe: HuntingRecipe;
  readonly priority: HuntingPriorityFacts;
  readonly state: HuntingUnitState;
  readonly attempt: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly stop: HuntingStop | null;
  readonly observation: HuntingObservationFacts | null;
}

/** One unit as it is first written into a batch. */
export interface HuntingUnitWrite {
  readonly unitId: string;
  readonly position: number;
  readonly targetPath: string;
  readonly recipe: HuntingRecipe;
  readonly priority: HuntingPriorityFacts;
}

export interface HuntingBatchWrite {
  readonly batchId: string;
  readonly createdAt: string;
  readonly maxUnits: number;
  readonly maxSeconds: number;
}

const HUNTING_QUEUE_SCHEMA = `
CREATE TABLE batch (
  batch_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  state TEXT NOT NULL,
  max_units INTEGER NOT NULL,
  max_seconds INTEGER NOT NULL,
  units_started INTEGER NOT NULL,
  spent_ms INTEGER NOT NULL,
  cancelled_at TEXT
);
CREATE TABLE unit (
  unit_id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  target_path TEXT NOT NULL,
  recipe_kind TEXT NOT NULL,
  recipe_json TEXT NOT NULL,
  priority INTEGER NOT NULL,
  priority_json TEXT NOT NULL,
  state TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  stop_kind TEXT,
  stop_error_tag TEXT,
  stop_operation TEXT,
  observation_json TEXT,
  UNIQUE (batch_id, position)
);
CREATE INDEX unit_queue ON unit (batch_id, state, priority DESC, position);
CREATE INDEX batch_created ON batch (created_at);
`;

interface BatchRow {
  readonly batch_id: string;
  readonly created_at: string;
  readonly state: string;
  readonly max_units: number;
  readonly max_seconds: number;
  readonly units_started: number;
  readonly spent_ms: number;
  readonly cancelled_at: string | null;
}

interface UnitRow {
  readonly unit_id: string;
  readonly batch_id: string;
  readonly position: number;
  readonly target_path: string;
  readonly recipe_kind: string;
  readonly recipe_json: string;
  readonly priority: number;
  readonly priority_json: string;
  readonly state: string;
  readonly attempt: number;
  readonly created_at: string;
  readonly updated_at: string;
  readonly stop_kind: string | null;
  readonly stop_error_tag: string | null;
  readonly stop_operation: string | null;
  readonly observation_json: string | null;
}

const recipeSchema = huntingRecipeSchema;

const parseStoredRecipe = (unitId: string, raw: string): HuntingRecipe => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause: unknown) {
    throw new HuntingQueueStoreFailure(
      "io",
      "A queued unit's recipe is not readable",
      { unit_id: unitId },
      { cause },
    );
  }
  const recipe = recipeSchema.safeParse(parsed);
  if (!recipe.success)
    throw new HuntingQueueStoreFailure(
      "io",
      "A queued unit's recipe is not readable",
      { unit_id: unitId },
    );
  return recipe.data;
};

/**
 * Durable queue for scheduled hunting units.
 *
 * The file lives in the caller's REA home rather than a temporary root because
 * the queue's whole purpose is to survive a restart: a process that stops mid
 * batch resumes the same units. The store keeps the file owner-only and refuses
 * a schema version it does not write.
 */
export class HuntingQueueStore {
  #database: DatabaseSync | null = null;
  #opening: Promise<void> | undefined;
  #closing: Promise<void> | undefined;

  constructor(
    readonly directory: string,
    private readonly platform: NodeJS.Platform = process.platform,
  ) {}

  get path(): string {
    return join(this.directory, HUNTING_QUEUE_FILE_NAME);
  }

  /** Open and migrate the queue file, once. */
  async ensure(): Promise<void> {
    this.#opening ??= this.#open().catch((cause: unknown) => {
      this.#opening = undefined;
      throw cause;
    });
    await this.#opening;
  }

  async #open(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    let database: DatabaseSync;
    try {
      database = new DatabaseSync(this.path);
    } catch (cause: unknown) {
      throw new HuntingQueueStoreFailure(
        "io",
        `The hunting queue file could not be opened: ${this.path}`,
        { queue_file: this.path },
        { cause },
      );
    }
    try {
      const version = database.prepare("PRAGMA user_version").get() as
        | { user_version?: unknown }
        | undefined;
      const current = Number(version?.user_version ?? 0);
      if (current === 0) {
        database.exec("BEGIN IMMEDIATE");
        try {
          database.exec(HUNTING_QUEUE_SCHEMA);
          database.exec(
            `PRAGMA user_version = ${String(HUNTING_QUEUE_SCHEMA_VERSION)}`,
          );
          database.exec("COMMIT");
        } catch (cause: unknown) {
          database.exec("ROLLBACK");
          throw cause;
        }
      } else if (current !== HUNTING_QUEUE_SCHEMA_VERSION) {
        throw new HuntingQueueStoreFailure(
          "unsupported_schema",
          `The hunting queue has schema version ${String(current)}, this build writes ${String(HUNTING_QUEUE_SCHEMA_VERSION)}`,
          {
            found_version: current,
            expected_version: HUNTING_QUEUE_SCHEMA_VERSION,
          },
        );
      }
      // A unit that was running when the previous process stopped was never
      // observed completing, so it returns to the queue as interrupted.
      database
        .prepare(
          "UPDATE unit SET state = 'queued', stop_kind = 'interrupted', stop_error_tag = NULL, stop_operation = NULL WHERE state = 'running'",
        )
        .run();
      if (this.platform !== "win32") await chmod(this.path, 0o600);
      this.#database = database;
    } catch (cause: unknown) {
      database.close();
      if (cause instanceof HuntingQueueStoreFailure) throw cause;
      throw new HuntingQueueStoreFailure(
        "io",
        "The hunting queue could not be migrated",
        { queue_file: this.path },
        { cause },
      );
    }
  }

  #connection(): DatabaseSync {
    if (this.#database === null)
      throw new HuntingQueueStoreFailure(
        "io",
        "The hunting queue has not been opened",
      );
    return this.#database;
  }

  /** Record one batch and every unit it queued in one transaction. */
  createBatch(
    batch: HuntingBatchWrite,
    units: readonly HuntingUnitWrite[],
  ): void {
    this.appendUnits({ batch, newBatch: true, units });
  }

  /**
   * Append units in one transaction, creating the batch with them when it is
   * new. A partially written append would leave unit positions the caller
   * cannot reuse, so either every row is written or none is.
   */
  appendUnits(request: {
    readonly batch: HuntingBatchWrite;
    readonly newBatch: boolean;
    readonly units: readonly HuntingUnitWrite[];
  }): void {
    const database = this.#connection();
    database.exec("BEGIN IMMEDIATE");
    try {
      if (request.newBatch)
        database
          .prepare(
            "INSERT INTO batch (batch_id, created_at, state, max_units, max_seconds, units_started, spent_ms, cancelled_at) VALUES (?, ?, 'open', ?, ?, 0, 0, NULL)",
          )
          .run(
            request.batch.batchId,
            request.batch.createdAt,
            request.batch.maxUnits,
            request.batch.maxSeconds,
          );
      const insert = database.prepare(
        "INSERT INTO unit (unit_id, batch_id, position, target_path, recipe_kind, recipe_json, priority, priority_json, state, attempt, created_at, updated_at, stop_kind, stop_error_tag, stop_operation, observation_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, NULL, NULL, NULL, NULL)",
      );
      for (const unit of request.units)
        insert.run(
          unit.unitId,
          request.batch.batchId,
          unit.position,
          unit.targetPath,
          unit.recipe.kind,
          JSON.stringify(unit.recipe),
          unit.priority.score,
          JSON.stringify(unit.priority),
          request.batch.createdAt,
          request.batch.createdAt,
        );
      database.exec("COMMIT");
    } catch (cause: unknown) {
      database.exec("ROLLBACK");
      throw new HuntingQueueStoreFailure(
        "io",
        "The queued units could not be recorded",
        { batch_id: request.batch.batchId, unit_count: request.units.length },
        { cause },
      );
    }
  }

  batch(batchId: string): StoredHuntingBatch | null {
    if (this.#database === null) return null;
    const row = this.#database
      .prepare("SELECT * FROM batch WHERE batch_id = ?")
      .get(batchId) as BatchRow | undefined;
    return row === undefined ? null : this.#batch(row);
  }

  /** Batches in creation order, oldest first. */
  batches(limit: number, offset: number): readonly StoredHuntingBatch[] {
    if (this.#database === null) return [];
    const rows = this.#database
      .prepare(
        "SELECT * FROM batch ORDER BY created_at, batch_id LIMIT ? OFFSET ?",
      )
      .all(Math.max(limit, 0), Math.max(offset, 0)) as unknown as BatchRow[];
    return rows.map((row) => this.#batch(row));
  }

  batchCount(): number {
    if (this.#database === null) return 0;
    return this.#count("SELECT COUNT(*) AS count FROM batch");
  }

  /** Oldest batch that still has a runnable unit. */
  nextOpenBatch(): StoredHuntingBatch | null {
    if (this.#database === null) return null;
    const row = this.#database
      .prepare(
        "SELECT * FROM batch WHERE state = 'open' AND EXISTS (SELECT 1 FROM unit WHERE unit.batch_id = batch.batch_id AND unit.state IN ('queued', 'blocked')) ORDER BY created_at, batch_id LIMIT 1",
      )
      .get() as BatchRow | undefined;
    return row === undefined ? null : this.#batch(row);
  }

  unit(unitId: string): StoredHuntingUnit | null {
    if (this.#database === null) return null;
    const row = this.#database
      .prepare("SELECT * FROM unit WHERE unit_id = ?")
      .get(unitId) as UnitRow | undefined;
    return row === undefined ? null : this.#unit(row);
  }

  /** Units of one batch, or of every batch, in canonical queue order. */
  units(
    batchId: string | null,
    limit: number,
    offset: number,
  ): readonly StoredHuntingUnit[] {
    if (this.#database === null) return [];
    const order =
      "CASE state WHEN 'queued' THEN 0 WHEN 'blocked' THEN 1 WHEN 'stopped' THEN 2 ELSE 3 END, priority DESC, position, unit_id";
    const rows = (batchId === null
      ? this.#database
          .prepare(`SELECT * FROM unit ORDER BY ${order} LIMIT ? OFFSET ?`)
          .all(Math.max(limit, 0), Math.max(offset, 0))
      : this.#database
          .prepare(
            `SELECT * FROM unit WHERE batch_id = ? ORDER BY ${order} LIMIT ? OFFSET ?`,
          )
          .all(
            batchId,
            Math.max(limit, 0),
            Math.max(offset, 0),
          )) as unknown as UnitRow[];
    return rows.map((row) => this.#unit(row));
  }

  unitCount(batchId: string | null): number {
    if (this.#database === null) return 0;
    return batchId === null
      ? this.#count("SELECT COUNT(*) AS count FROM unit")
      : this.#count(
          "SELECT COUNT(*) AS count FROM unit WHERE batch_id = ?",
          batchId,
        );
  }

  /** Units of one batch grouped by state, without reading every row. */
  unitStates(batchId: string): Readonly<Record<HuntingUnitState, number>> {
    const counts: Record<HuntingUnitState, number> = {
      queued: 0,
      running: 0,
      blocked: 0,
      succeeded: 0,
      failed: 0,
      stopped: 0,
      cancelled: 0,
    };
    if (this.#database === null) return counts;
    const rows = this.#database
      .prepare(
        "SELECT state, COUNT(*) AS count FROM unit WHERE batch_id = ? GROUP BY state",
      )
      .all(batchId) as unknown as { state: string; count: number }[];
    for (const row of rows)
      counts[huntingUnitStateSchema.parse(row.state)] = Number(row.count);
    return counts;
  }

  /** The next unit this batch may admit: queued before blocked. */
  nextUnit(batchId: string): StoredHuntingUnit | null {
    if (this.#database === null) return null;
    const row = this.#database
      .prepare(
        "SELECT * FROM unit WHERE batch_id = ? AND state IN ('queued', 'blocked') ORDER BY CASE state WHEN 'queued' THEN 0 ELSE 1 END, priority DESC, position, unit_id LIMIT 1",
      )
      .get(batchId) as UnitRow | undefined;
    return row === undefined ? null : this.#unit(row);
  }

  /**
   * Admit one unit: its attempt counter rises and it is observed running.
   *
   * The update is conditional on the unit still being admissible, so a second
   * REA process sharing the queue file cannot admit a unit another process
   * already took. A refused admission is reported instead of being silent.
   */
  beginUnit(unitId: string, at: string): void {
    const database = this.#connection();
    database.exec("BEGIN IMMEDIATE");
    try {
      const admitted = database
        .prepare(
          "UPDATE unit SET state = 'running', attempt = attempt + 1, updated_at = ?, stop_kind = NULL, stop_error_tag = NULL, stop_operation = NULL WHERE unit_id = ? AND state IN ('queued', 'blocked')",
        )
        .run(at, unitId);
      if (Number(admitted.changes) === 0) {
        database.exec("ROLLBACK");
        throw new HuntingQueueStoreFailure(
          "io",
          "The unit was no longer admissible when this process tried to admit it; another REA process may already have taken it",
          { unit_id: unitId, state_changed: true },
        );
      }
      database.exec("COMMIT");
    } catch (cause: unknown) {
      if (cause instanceof HuntingQueueStoreFailure) throw cause;
      database.exec("ROLLBACK");
      throw new HuntingQueueStoreFailure(
        "io",
        "The admitted unit could not be marked running",
        { unit_id: unitId },
        { cause },
      );
    }
  }

  /** Record one unit's observed outcome. */
  finishUnit(record: {
    readonly unitId: string;
    readonly state: HuntingUnitState;
    readonly at: string;
    readonly stop: HuntingStop | null;
    readonly observation: HuntingObservationFacts | null;
  }): void {
    const database = this.#connection();
    database.exec("BEGIN IMMEDIATE");
    try {
      database
        .prepare(
          "UPDATE unit SET state = ?, updated_at = ?, stop_kind = ?, stop_error_tag = ?, stop_operation = ?, observation_json = ? WHERE unit_id = ?",
        )
        .run(
          record.state,
          record.at,
          record.stop?.kind ?? null,
          record.stop?.error_tag ?? null,
          record.stop?.operation ?? null,
          record.observation === null
            ? null
            : JSON.stringify(record.observation),
          record.unitId,
        );
      database.exec("COMMIT");
    } catch (cause: unknown) {
      database.exec("ROLLBACK");
      throw new HuntingQueueStoreFailure(
        "io",
        "The unit outcome could not be recorded",
        { unit_id: record.unitId },
        { cause },
      );
    }
  }

  /** Charge one executed unit to its batch, or settle the batch's final state. */
  updateBatch(record: {
    readonly batchId: string;
    readonly state: HuntingBatchState;
    readonly unitsStarted: number;
    readonly spentMs: number;
  }): void {
    const database = this.#connection();
    database.exec("BEGIN IMMEDIATE");
    try {
      database
        .prepare(
          "UPDATE batch SET state = ?, units_started = ?, spent_ms = ? WHERE batch_id = ?",
        )
        .run(record.state, record.unitsStarted, record.spentMs, record.batchId);
      database.exec("COMMIT");
    } catch (cause: unknown) {
      database.exec("ROLLBACK");
      throw new HuntingQueueStoreFailure(
        "io",
        "The batch budget could not be recorded",
        { batch_id: record.batchId },
        { cause },
      );
    }
  }

  /** Cancel one batch and every unit it had not finished. */
  cancelBatch(batchId: string, at: string): { readonly cancelled: number } {
    const database = this.#connection();
    database.exec("BEGIN IMMEDIATE");
    try {
      const result = database
        .prepare(
          "UPDATE unit SET state = 'cancelled', updated_at = ?, stop_kind = 'cancelled', stop_error_tag = NULL, stop_operation = NULL WHERE batch_id = ? AND state IN ('queued', 'blocked', 'stopped')",
        )
        .run(at, batchId);
      database
        .prepare(
          "UPDATE batch SET state = 'cancelled', cancelled_at = ? WHERE batch_id = ?",
        )
        .run(at, batchId);
      database.exec("COMMIT");
      return { cancelled: Number(result.changes) };
    } catch (cause: unknown) {
      database.exec("ROLLBACK");
      throw new HuntingQueueStoreFailure(
        "io",
        "The batch could not be cancelled",
        { batch_id: batchId },
        { cause },
      );
    }
  }

  #count(sql: string, parameter?: string): number {
    if (this.#database === null) return 0;
    const row = (
      parameter === undefined
        ? this.#database.prepare(sql).get()
        : this.#database.prepare(sql).get(parameter)
    ) as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  }

  #batch(row: BatchRow): StoredHuntingBatch {
    return {
      batchId: row.batch_id,
      createdAt: row.created_at,
      state: huntingBatchStateSchema.parse(row.state),
      maxUnits: row.max_units,
      maxSeconds: row.max_seconds,
      unitsStarted: row.units_started,
      spentMs: row.spent_ms,
      cancelledAt: row.cancelled_at,
    };
  }

  #unit(row: UnitRow): StoredHuntingUnit {
    const recipe = parseStoredRecipe(row.unit_id, row.recipe_json);
    let priority: HuntingPriorityFacts;
    try {
      priority = huntingPrioritySchema.parse(JSON.parse(row.priority_json));
    } catch (cause: unknown) {
      throw new HuntingQueueStoreFailure(
        "io",
        "A queued unit's priority is not readable",
        { unit_id: row.unit_id },
        { cause },
      );
    }
    const stopKind = row.stop_kind;
    let stop: HuntingStop | null = null;
    if (stopKind !== null)
      stop = huntingStopSchema.parse({
        kind: stopKind,
        error_tag: row.stop_error_tag,
        operation: row.stop_operation,
      });
    let observation: HuntingObservationFacts | null = null;
    if (row.observation_json !== null)
      try {
        observation = huntingObservationFactsSchema.parse(
          JSON.parse(row.observation_json),
        );
      } catch (cause: unknown) {
        throw new HuntingQueueStoreFailure(
          "io",
          "A queued unit's observation is not readable",
          { unit_id: row.unit_id },
          { cause },
        );
      }
    return {
      unitId: row.unit_id,
      batchId: row.batch_id,
      position: row.position,
      targetPath: row.target_path,
      recipe,
      priority,
      state: huntingUnitStateSchema.parse(row.state),
      attempt: row.attempt,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      stop,
      observation,
    };
  }

  /** Close the database; the durable file stays on disk. */
  close(): Promise<void> {
    this.#closing ??= Promise.resolve().then(() => {
      const database = this.#database;
      this.#database = null;
      this.#opening = undefined;
      database?.close();
    });
    return this.#closing;
  }
}
