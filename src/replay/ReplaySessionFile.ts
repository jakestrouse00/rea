import { randomUUID } from "node:crypto";
import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { join } from "node:path";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { REPLAY_SESSION_FILE_VERSION } from "../domain/replay/replayLimits.js";
import type {
  ReplayBody,
  ReplayRequest,
} from "../domain/replay/replayRequest.js";
import { err, ok, type Result } from "../domain/result.js";
import { homeDirectoryFromEnvironment } from "../config/homeDirectory.js";

/** Persisted selection and authorization for one replay session. */
export interface ReplaySessionRecord {
  readonly version: number;
  readonly session_id: string;
  readonly owner: {
    readonly process_id: number;
    readonly server_started_at: string;
  };
  readonly created_at: string;
  readonly source:
    | { readonly kind: "har"; readonly path: string; readonly sha256: string }
    | { readonly kind: "draft" };
  readonly selected_entry: number | null;
  readonly target_origins: readonly string[];
  readonly draft: ReplayRequest | null;
  readonly send_count: number;
  readonly last_send_at: string | null;
}

/** Owner-only protection claim for the record on this host. */
export const replaySessionPermissions = (
  platform: NodeJS.Platform,
): "0600" | "unverified" => (platform === "win32" ? "unverified" : "0600");

/** Default replay session directory under the REA home, beside other state. */
export const replaySessionDirectory = (
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform = process.platform,
): string =>
  join(
    homeDirectoryFromEnvironment(environment, platform),
    ".rea",
    "state",
    "replay",
  );

const recordFile = (directory: string, sessionId: string): string =>
  join(directory, `${sessionId}.json`);

/**
 * Owns one record file per replay session.
 *
 * A file is written when a session starts and removed when it closes, so it
 * describes the session's declared authority even if the process later exits
 * without closing. Ownership is the record's creator, not its path: a record
 * this process did not write is never adopted, rewritten, or removed.
 */
export class ReplaySessionFiles {
  constructor(
    readonly directory: string,
    private readonly platform: NodeJS.Platform = process.platform,
  ) {}

  get permissions(): "0600" | "unverified" {
    return replaySessionPermissions(this.platform);
  }

  pathFor(sessionId: string): string {
    return recordFile(this.directory, sessionId);
  }

  /** Create one owner-only record; an existing record is never overwritten. */
  async create(
    record: ReplaySessionRecord,
    operation: string,
  ): Promise<Result<string, AnalysisError>> {
    const path = this.pathFor(record.session_id);
    try {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      const handle = await open(path, "wx", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(record, null, 2)}\n`, "utf8");
        if (this.platform !== "win32") await handle.chmod(0o600);
      } finally {
        await handle.close().catch(() => undefined);
      }
      return ok(path);
    } catch (cause: unknown) {
      return err(
        new AnalysisOutputError(
          operation,
          "the replay session file could not be created",
          {
            cause,
            userMessage: `REA could not write its session record at ${path}. Select a different REA home or remove the leftover record if no REA server is using it.`,
            diagnostics: { session_file: path },
          },
        ),
      );
    }
  }

  /** Replace one record atomically; the caller owns the id. */
  async update(
    record: ReplaySessionRecord,
    operation: string,
  ): Promise<Result<void, AnalysisError>> {
    const path = this.pathFor(record.session_id);
    const temporary = `${path}.${randomUUID()}.tmp`;
    try {
      const handle = await open(temporary, "wx", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(record, null, 2)}\n`, "utf8");
        if (this.platform !== "win32") await handle.chmod(0o600);
      } finally {
        await handle.close().catch(() => undefined);
      }
      await rename(temporary, path);
      return ok(undefined);
    } catch (cause: unknown) {
      await unlink(temporary).catch(() => undefined);
      return err(
        new AnalysisOutputError(
          operation,
          "the replay session file could not be updated",
          {
            cause,
            userMessage: `REA could not update its session record at ${path}.`,
            diagnostics: { session_file: path },
          },
        ),
      );
    }
  }

  /** Read one record; absence is a distinct, non-error outcome. */
  async read(
    sessionId: string,
    operation: string,
  ): Promise<Result<ReplaySessionRecord | null, AnalysisError>> {
    const path = this.pathFor(sessionId);
    let text: string;
    try {
      text = await readFile(path, "utf8");
    } catch (cause: unknown) {
      if (systemCode(cause) === "ENOENT") return ok(null);
      return err(
        new AnalysisOutputError(
          operation,
          "the replay session file could not be read",
          {
            cause,
            userMessage: `REA could not read its session record at ${path}.`,
            diagnostics: { session_file: path },
          },
        ),
      );
    }
    return parseRecord(text, path, operation);
  }

  /** Remove one record; a missing record is already closed. */
  async remove(
    sessionId: string,
    operation: string,
  ): Promise<Result<boolean, AnalysisError>> {
    const path = this.pathFor(sessionId);
    return unlink(path).then(
      () => ok(true),
      (cause: unknown) =>
        systemCode(cause) === "ENOENT"
          ? ok(false)
          : err(
              new AnalysisOutputError(
                operation,
                "the replay session file could not be removed",
                {
                  cause,
                  userMessage: `REA could not remove its session record at ${path}; delete it manually before reusing that session id.`,
                  diagnostics: { session_file: path },
                  cleanup: {
                    reason: "the replay session record remains on disk",
                    resources: ["replay-session-file"],
                  },
                },
              ),
            ),
    );
  }
}

const systemCode = (cause: unknown): string =>
  typeof cause === "object" && cause !== null && "code" in cause
    ? String((cause as { readonly code?: unknown }).code)
    : "";

const bodyOf = (value: unknown): ReplayBody | null => {
  if (typeof value !== "object" || value === null) return null;
  const body = value as Record<string, unknown>;
  if (body.kind === "none") return { kind: "none" };
  if (body.kind === "text" && typeof body.text === "string")
    return { kind: "text", text: body.text };
  if (body.kind === "base64" && typeof body.base64 === "string")
    return { kind: "base64", base64: body.base64 };
  return null;
};

const requestOf = (value: unknown): ReplayRequest | null => {
  if (typeof value !== "object" || value === null) return null;
  const request = value as Record<string, unknown>;
  if (typeof request.method !== "string" || typeof request.url !== "string")
    return null;
  if (!Array.isArray(request.headers)) return null;
  const headers: { name: string; value: string }[] = [];
  for (const header of request.headers) {
    if (typeof header !== "object" || header === null) return null;
    const { name, value: headerValue } = header as Record<string, unknown>;
    if (typeof name !== "string" || typeof headerValue !== "string")
      return null;
    headers.push({ name, value: headerValue });
  }
  const body = bodyOf(request.body);
  return body === null
    ? null
    : { method: request.method, url: request.url, headers, body };
};

/** Parse a record this build wrote; anything else is a foreign or stale file. */
const parseRecord = (
  text: string,
  path: string,
  operation: string,
): Result<ReplaySessionRecord, AnalysisError> => {
  const invalid = (message: string): AnalysisInputError =>
    new AnalysisInputError(
      operation,
      {
        userMessage: `${message} Delete ${path} if no REA server is using it.`,
        diagnostics: { session_file: path },
      },
      [{ path: ["session_id"], reason: "invalid_format", message }],
    );
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return err(
      invalid(
        "The replay session record at this path is not valid JSON, so REA cannot establish what it authorized.",
      ),
    );
  }
  if (typeof raw !== "object" || raw === null)
    return err(invalid("The replay session record is not an object."));
  const record = raw as Record<string, unknown>;
  if (record.version !== REPLAY_SESSION_FILE_VERSION)
    return err(
      invalid(
        `The replay session record has schema version ${String(record.version)}, this build writes ${String(REPLAY_SESSION_FILE_VERSION)}.`,
      ),
    );
  if (typeof record.session_id !== "string")
    return err(invalid("The replay session record has no session identity."));
  const owner = record.owner;
  if (
    typeof owner !== "object" ||
    owner === null ||
    typeof (owner as Record<string, unknown>).process_id !== "number" ||
    typeof (owner as Record<string, unknown>).server_started_at !== "string"
  )
    return err(invalid("The replay session record has no owner."));
  const source = record.source;
  if (typeof source !== "object" || source === null)
    return err(invalid("The replay session record has no source."));
  const sourceRecord = source as Record<string, unknown>;
  const declaredSource =
    sourceRecord.kind === "har" &&
    typeof sourceRecord.path === "string" &&
    typeof sourceRecord.sha256 === "string"
      ? {
          kind: "har" as const,
          path: sourceRecord.path,
          sha256: sourceRecord.sha256,
        }
      : sourceRecord.kind === "draft"
        ? { kind: "draft" as const }
        : null;
  if (declaredSource === null)
    return err(invalid("The replay session record has an unknown source."));
  if (!Array.isArray(record.target_origins))
    return err(invalid("The replay session record has no declared origins."));
  const targetOrigins = record.target_origins.filter(
    (origin): origin is string => typeof origin === "string",
  );
  return ok({
    version: REPLAY_SESSION_FILE_VERSION,
    session_id: record.session_id,
    owner: owner as ReplaySessionRecord["owner"],
    created_at:
      typeof record.created_at === "string"
        ? record.created_at
        : new Date(0).toISOString(),
    source: declaredSource,
    selected_entry:
      typeof record.selected_entry === "number" ? record.selected_entry : null,
    target_origins: targetOrigins,
    draft: requestOf(record.draft),
    send_count: typeof record.send_count === "number" ? record.send_count : 0,
    last_send_at:
      typeof record.last_send_at === "string" ? record.last_send_at : null,
  });
};
