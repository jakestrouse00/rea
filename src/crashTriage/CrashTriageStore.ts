import { createHash } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import type { JsonValue } from "../domain/jsonValue.js";
import { crashReportFactsSchema } from "../domain/crashTriage/crashReport.js";
import {
  fuzzingCampaignStatusSchema,
  type CampaignArtifact,
  type FuzzingCampaignBudget,
  type FuzzingCampaignStatus,
} from "../domain/crashTriage/fuzzingCampaign.js";
import { digestSchema } from "../domain/digests.js";
import type {
  PrivateRuntimeRoot,
  PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;
import { z } from "zod";

/** Current on-disk schema version of the crash-triage store. */
export const CRASH_TRIAGE_SCHEMA_VERSION = 1;

/** Why the crash-triage store could not be opened or used. */
export type CrashTriageStoreFailureReason =
  | "io"
  | "unsupported_schema"
  | "cleanup";

export class CrashTriageStoreFailure extends Error {
  readonly _tag = "CrashTriageStoreFailure";
  constructor(
    readonly reason: CrashTriageStoreFailureReason,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "CrashTriageStoreFailure";
  }
}

/** One registered campaign as the store retained it. */
export interface StoredCampaign {
  readonly campaignId: string;
  readonly status: FuzzingCampaignStatus;
  readonly target: CampaignArtifact;
  readonly seeds: readonly CampaignArtifact[];
  readonly budget: FuzzingCampaignBudget;
  readonly dedupFrames: number;
  readonly registeredAt: string;
}

/** Immutable part of one stored crash; counters live in their own columns. */
const storedFactsSchema = z.strictObject({
  facts: crashReportFactsSchema,
  state: z.strictObject({
    dedup_hash: digestSchema,
    frames: z.array(z.string()),
    frame_count: z.int().min(0),
  }),
  report: z.strictObject({
    format: z.string().min(1),
    relative_path: z.string().min(1),
    sha256: digestSchema,
    bytes: z.int().min(0),
  }),
  repro: z.strictObject({
    path: z.string().min(1),
    bytes: z.int().min(0),
  }),
});

export type StoredCrashFacts = z.infer<typeof storedFactsSchema>;

/** One stored crash: immutable facts plus the counters that change on re-ingest. */
export interface StoredCrash extends StoredCrashFacts {
  readonly crashId: string;
  readonly campaignId: string;
  readonly dedupId: string;
  readonly occurrenceCount: number;
  readonly recordedAt: string;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
}

export interface CrashReportWrite {
  readonly relativePath: string;
  readonly sha256: string;
  readonly bytes: number;
}

const SCHEMA = `
CREATE TABLE campaign (
  campaign_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  target_path TEXT NOT NULL,
  target_sha256 TEXT NOT NULL,
  target_bytes INTEGER NOT NULL,
  max_runs INTEGER,
  max_seconds INTEGER,
  max_crashes INTEGER,
  dedup_frames INTEGER NOT NULL,
  registered_at TEXT NOT NULL
);
CREATE TABLE campaign_seed (
  campaign_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  PRIMARY KEY (campaign_id, position)
);
CREATE TABLE crash (
  crash_id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  dedup_id TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  occurrence_count INTEGER NOT NULL,
  recorded_at TEXT NOT NULL,
  document_json TEXT NOT NULL
);
CREATE INDEX crash_campaign ON crash (campaign_id, first_seen_at);
CREATE INDEX crash_dedup ON crash (dedup_id);
`;

interface CampaignTableRow {
  readonly campaign_id: string;
  readonly status: string;
  readonly target_path: string;
  readonly target_sha256: string;
  readonly target_bytes: number;
  readonly max_runs: number | null;
  readonly max_seconds: number | null;
  readonly max_crashes: number | null;
  readonly dedup_frames: number;
  readonly registered_at: string;
}

interface SeedTableRow {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

interface CrashTableRow {
  readonly crash_id: string;
  readonly campaign_id: string;
  readonly dedup_id: string;
  readonly first_seen_at: string;
  readonly last_seen_at: string;
  readonly occurrence_count: number;
  readonly recorded_at: string;
  readonly document_json: string;
}

/**
 * Server-lifetime crash bookkeeping.
 *
 * Campaigns, crash records, and retained report copies live in a private
 * runtime root allocated on first write and removed when the server closes.
 * REA therefore never resumes a campaign across processes, and never leaves
 * the store behind.
 */
export class CrashTriageStore {
  #root: RuntimeRoot | null = null;
  #database: DatabaseSync | null = null;
  #opening: Promise<void> | undefined;
  #closing: Promise<void> | undefined;

  constructor(
    private readonly createRuntimeRoot: (
      options?: PrivateRuntimeRootOptions,
    ) => Promise<RuntimeRoot>,
  ) {}

  /** Whether any campaign has been recorded in this server process. */
  get opened(): boolean {
    return this.#database !== null;
  }

  /** Private directory that holds the database and retained reports. */
  get path(): string {
    if (this.#root === null)
      throw new CrashTriageStoreFailure(
        "io",
        "The crash-triage store has not been opened",
      );
    return this.#root.path;
  }

  /** Allocate the private root and migrate the database, once. */
  async ensure(): Promise<void> {
    this.#opening ??= this.#open().catch((cause: unknown) => {
      this.#opening = undefined;
      throw cause;
    });
    await this.#opening;
  }

  async #open(): Promise<void> {
    const root = await this.createRuntimeRoot({ prefix: "rea-crash-triage-" });
    try {
      await mkdir(join(root.path, "reports"), { recursive: true, mode: 0o700 });
      const database = new DatabaseSync(join(root.path, "crash-triage.sqlite"));
      const version = database.prepare("PRAGMA user_version").get() as
        | { user_version?: unknown }
        | undefined;
      const current = Number(version?.user_version ?? 0);
      if (current === 0) {
        database.exec("BEGIN IMMEDIATE");
        try {
          database.exec(SCHEMA);
          database.exec(
            `PRAGMA user_version = ${String(CRASH_TRIAGE_SCHEMA_VERSION)}`,
          );
          database.exec("COMMIT");
        } catch (cause: unknown) {
          database.exec("ROLLBACK");
          throw cause;
        }
      } else if (current !== CRASH_TRIAGE_SCHEMA_VERSION) {
        database.close();
        throw new CrashTriageStoreFailure(
          "unsupported_schema",
          `The crash-triage store has schema version ${String(current)}, this build writes ${String(CRASH_TRIAGE_SCHEMA_VERSION)}`,
          {
            found_version: current,
            expected_version: CRASH_TRIAGE_SCHEMA_VERSION,
          },
        );
      }
      await chmod(join(root.path, "crash-triage.sqlite"), 0o600);
      this.#root = root;
      this.#database = database;
    } catch (cause: unknown) {
      await root.close().catch(() => undefined);
      if (cause instanceof CrashTriageStoreFailure) throw cause;
      throw new CrashTriageStoreFailure(
        "io",
        "The crash-triage store could not be opened",
        {},
        { cause },
      );
    }
  }

  #connection(): DatabaseSync {
    if (this.#database === null)
      throw new CrashTriageStoreFailure(
        "io",
        "The crash-triage store has not been opened",
      );
    return this.#database;
  }

  /** Record one campaign and its seed identities. */
  registerCampaign(record: {
    readonly campaignId: string;
    readonly target: CampaignArtifact;
    readonly seeds: readonly CampaignArtifact[];
    readonly budget: FuzzingCampaignBudget;
    readonly dedupFrames: number;
    readonly registeredAt: string;
  }): void {
    const database = this.#connection();
    database.exec("BEGIN IMMEDIATE");
    try {
      database
        .prepare(
          "INSERT INTO campaign (campaign_id, status, target_path, target_sha256, target_bytes, max_runs, max_seconds, max_crashes, dedup_frames, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          record.campaignId,
          "registered",
          record.target.path,
          record.target.sha256,
          record.target.bytes,
          record.budget.max_runs ?? null,
          record.budget.max_seconds ?? null,
          record.budget.max_crashes ?? null,
          record.dedupFrames,
          record.registeredAt,
        );
      const seed = database.prepare(
        "INSERT INTO campaign_seed (campaign_id, position, path, sha256, bytes) VALUES (?, ?, ?, ?, ?)",
      );
      record.seeds.forEach((value, position) => {
        seed.run(
          record.campaignId,
          position,
          value.path,
          value.sha256,
          value.bytes,
        );
      });
      database.exec("COMMIT");
    } catch (cause: unknown) {
      database.exec("ROLLBACK");
      throw new CrashTriageStoreFailure(
        "io",
        "The campaign could not be recorded",
        {},
        { cause },
      );
    }
  }

  /** Read one campaign, or null when this server never recorded it. */
  campaign(campaignId: string): StoredCampaign | null {
    if (this.#database === null) return null;
    const row = this.#database
      .prepare("SELECT * FROM campaign WHERE campaign_id = ?")
      .get(campaignId) as CampaignTableRow | undefined;
    if (row === undefined) return null;
    const seeds = this.#database
      .prepare(
        "SELECT path, sha256, bytes FROM campaign_seed WHERE campaign_id = ? ORDER BY position",
      )
      .all(campaignId) as unknown as SeedTableRow[];
    return {
      campaignId: row.campaign_id,
      status: fuzzingCampaignStatusSchema.parse(row.status),
      target: {
        path: row.target_path,
        sha256: row.target_sha256,
        bytes: row.target_bytes,
      },
      seeds: seeds.map((seed) => ({
        path: seed.path,
        sha256: seed.sha256,
        bytes: seed.bytes,
      })),
      budget: {
        max_runs: row.max_runs,
        max_seconds: row.max_seconds,
        max_crashes: row.max_crashes,
      },
      dedupFrames: row.dedup_frames,
      registeredAt: row.registered_at,
    };
  }

  /** How many campaigns this server recorded. */
  campaignCount(): number {
    if (this.#database === null) return 0;
    const row = this.#database
      .prepare("SELECT COUNT(*) AS count FROM campaign")
      .get() as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  }

  /** Retain a report copy in the private root with owner-only permissions. */
  async writeReport(crashId: string, body: string): Promise<CrashReportWrite> {
    const root = this.path;
    const relativePath = `reports/${crashId}.txt`;
    const absolute = join(root, relativePath);
    const bytes = Buffer.from(body, "utf8");
    try {
      await writeFile(absolute, bytes, { flag: "wx", mode: 0o600 });
    } catch (cause: unknown) {
      throw new CrashTriageStoreFailure(
        "io",
        "The crash report could not be retained",
        { relative_path: relativePath },
        { cause },
      );
    }
    return {
      relativePath,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.byteLength,
    };
  }

  /**
   * Insert one crash record, or count an observed repeat.
   *
   * A repeat is identified by the crash id the caller derived from the
   * retained report bytes, so re-ingesting the same report increments the
   * occurrence count instead of creating a second record.
   */
  recordCrash(record: {
    readonly crashId: string;
    readonly campaignId: string;
    readonly dedupId: string;
    readonly recordedAt: string;
    readonly observedAt: string;
    readonly document: StoredCrashFacts;
  }): void {
    const database = this.#connection();
    database.exec("BEGIN IMMEDIATE");
    try {
      database
        .prepare(
          "INSERT INTO crash (crash_id, campaign_id, dedup_id, first_seen_at, last_seen_at, occurrence_count, recorded_at, document_json) VALUES (?, ?, ?, ?, ?, 1, ?, ?) ON CONFLICT(crash_id) DO UPDATE SET occurrence_count = occurrence_count + 1, last_seen_at = excluded.last_seen_at",
        )
        .run(
          record.crashId,
          record.campaignId,
          record.dedupId,
          record.observedAt,
          record.observedAt,
          record.recordedAt,
          JSON.stringify(record.document),
        );
      database.exec("COMMIT");
    } catch (cause: unknown) {
      database.exec("ROLLBACK");
      throw new CrashTriageStoreFailure(
        "io",
        "The crash could not be recorded",
        { crash_id: record.crashId },
        { cause },
      );
    }
  }

  /** Crash records of one campaign, oldest first. */
  crashes(campaignId: string, limit: number): readonly StoredCrash[] {
    if (this.#database === null) return [];
    const rows = this.#database
      .prepare(
        "SELECT * FROM crash WHERE campaign_id = ? ORDER BY first_seen_at, crash_id LIMIT ?",
      )
      .all(
        campaignId,
        Math.max(Math.trunc(limit), 0),
      ) as unknown as CrashTableRow[];
    return rows.map((row) => this.#storedCrash(row));
  }

  /** One crash record, or null when this server never retained it. */
  crash(crashId: string): StoredCrash | null {
    if (this.#database === null) return null;
    const row = this.#database
      .prepare("SELECT * FROM crash WHERE crash_id = ?")
      .get(crashId) as CrashTableRow | undefined;
    return row === undefined ? null : this.#storedCrash(row);
  }

  /** How many crash records one campaign retained. */
  crashCount(campaignId: string): number {
    if (this.#database === null) return 0;
    const row = this.#database
      .prepare("SELECT COUNT(*) AS count FROM crash WHERE campaign_id = ?")
      .get(campaignId) as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  }

  /** Whether one campaign already recorded this crash-state identity. */
  hasDedup(campaignId: string, dedupId: string): boolean {
    if (this.#database === null) return false;
    const row = this.#database
      .prepare(
        "SELECT 1 AS present FROM crash WHERE campaign_id = ? AND dedup_id = ? LIMIT 1",
      )
      .get(campaignId, dedupId) as { readonly present?: number } | undefined;
    return row !== undefined;
  }

  /** Counters one campaign accumulated, without reading every record. */
  campaignSummary(campaignId: string): {
    readonly crashCount: number;
    readonly dedupCount: number;
    readonly lastCrashAt: string | null;
  } {
    if (this.#database === null)
      return { crashCount: 0, dedupCount: 0, lastCrashAt: null };
    const row = this.#database
      .prepare(
        "SELECT COUNT(*) AS crash_count, COUNT(DISTINCT dedup_id) AS dedup_count, MAX(last_seen_at) AS last_seen_at FROM crash WHERE campaign_id = ?",
      )
      .get(campaignId) as
      | {
          readonly crash_count?: number;
          readonly dedup_count?: number;
          readonly last_seen_at?: string | null;
        }
      | undefined;
    return {
      crashCount: Number(row?.crash_count ?? 0),
      dedupCount: Number(row?.dedup_count ?? 0),
      lastCrashAt:
        typeof row?.last_seen_at === "string" ? row.last_seen_at : null,
    };
  }

  #storedCrash(row: CrashTableRow): StoredCrash {
    let document: StoredCrashFacts;
    try {
      document = storedFactsSchema.parse(JSON.parse(row.document_json));
    } catch (cause: unknown) {
      throw new CrashTriageStoreFailure(
        "io",
        "A stored crash record is not readable",
        { crash_id: row.crash_id },
        { cause },
      );
    }
    return {
      ...document,
      crashId: row.crash_id,
      campaignId: row.campaign_id,
      dedupId: row.dedup_id,
      occurrenceCount: row.occurrence_count,
      recordedAt: row.recorded_at,
      firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at,
    };
  }

  /** Close the database and remove the private root; a failed removal is retained. */
  close(): Promise<void> {
    this.#closing ??= this.#close().catch((cause: unknown) => {
      this.#closing = undefined;
      throw cause;
    });
    return this.#closing;
  }

  async #close(): Promise<void> {
    const database = this.#database;
    const root = this.#root;
    this.#database = null;
    this.#root = null;
    this.#opening = undefined;
    database?.close();
    if (root === null) return;
    try {
      await root.close();
    } catch (cause: unknown) {
      throw new CrashTriageStoreFailure(
        "cleanup",
        `The crash-triage store could not be removed: ${root.path}`,
        { store_path: root.path },
        { cause },
      );
    }
  }
}
