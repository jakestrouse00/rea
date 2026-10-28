import { randomUUID } from "node:crypto";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  CloseReplaySessionRequest,
  ReplayPort,
  ReplaySessionSource,
  ReplaySessionStatusRequest,
  SendReplayRequest,
  StartReplaySessionRequest,
} from "../application/replay/ReplayPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  type AnalysisInputIssue,
} from "../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  REPLAY_LIMITS,
  REPLAY_SESSION_FILE_VERSION,
} from "../domain/replay/replayLimits.js";
import {
  REPLAY_BODY_LIMITATION,
  REPLAY_CAPTURE_LIMITATION,
  REPLAY_REDACTION_LIMITATION,
  REPLAY_RETRY_LIMITATION,
  REPLAY_SESSION_FILE_LIMITATION,
  REPLAY_TARGET_TEXT_LIMITATION,
} from "../domain/replay/replayObservation.js";
import {
  REPLAY_ALLOWED_ORIGINS_ENV,
  REPLAY_ALLOWED_ORIGINS_REMEDIATION,
  REPLAY_PROVIDER,
  REPLAY_PROVIDER_ID,
  ReplayConfigurationFailure,
  parseReplayAllowedOrigins,
  replayDeclaredOrigin,
  replayUrlApproval,
} from "../domain/replay/replayOrigins.js";
import {
  composeReplayRequest,
  composeReplayWireRequest,
  type ReplayRequest,
} from "../domain/replay/replayRequest.js";
import {
  replayCredentialHeaderNames,
  replayHeaderNames,
} from "../domain/replay/replayRedaction.js";
import type { ReplayCapturedEntry, ReplayCapture } from "./ReplayHarCapture.js";
import { readReplayCapture } from "./ReplayHarCapture.js";
import { NodeReplayTransport } from "./NodeReplayTransport.js";
import type { ReplayTransport } from "./ReplayTransport.js";
import { ReplaySendCore } from "./ReplaySendCore.js";
import type { ReplaySessionRecord } from "./ReplaySessionFile.js";
import {
  ReplaySessionFiles,
  replaySessionDirectory,
} from "./ReplaySessionFile.js";

export interface ReplayServiceOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly platform?: NodeJS.Platform;
  readonly transport?: ReplayTransport;
  /** Deterministic seam for tests; defaults to the platform home directory. */
  readonly sessionFiles?: ReplaySessionFiles;
  readonly now?: () => string;
  readonly elapsed?: () => number;
}

interface ReplaySession {
  readonly id: string;
  record: ReplaySessionRecord;
  readonly capture: ReplayCapture | null;
  readonly pending: Set<Promise<unknown>>;
}

const REPLAY_OPERATIONS = {
  start: "http_replay_session_start",
  send: "http_replay_send",
  status: "http_replay_session_status",
  close: "http_replay_session_close",
} as const;

const entrySummary = (entry: ReplayCapturedEntry) => ({
  ordinal: entry.ordinal,
  method: entry.method,
  url: entry.url,
  origin: entry.origin,
  header_names: [...entry.headerNames],
  credential_header_names: [...entry.credentialHeaderNames],
  body_bytes: entry.bodyBytes,
});

const requestOrigin = (url: string): string | null => {
  try {
    return new URL(url).origin;
  } catch (cause: unknown) {
    void cause;
    return null;
  }
};

const requestSummary = (request: ReplayRequest) => ({
  ordinal: null,
  method: request.method,
  url: request.url,
  origin: requestOrigin(request.url),
  header_names: [...replayHeaderNames(request.headers)],
  credential_header_names: [...replayCredentialHeaderNames(request.headers)],
  body_bytes:
    request.body.kind === "text"
      ? Buffer.byteLength(request.body.text, "utf8")
      : request.body.kind === "base64"
        ? Math.floor((request.body.base64.length * 3) / 4)
        : 0,
});

/**
 * Owns replay sessions, the active request plane's authorization gate, and the
 * Evidence each session produces.
 *
 * A session's declared origins are intersected with the operator allowlist at
 * start; nothing here widens either set, retries a dispatch, or echoes a
 * credential value. The single dispatch owner is `ReplaySendCore`.
 */
export class ReplayService implements ReplayPort {
  readonly #sessions = new Map<string, ReplaySession>();
  readonly #core: ReplaySendCore;
  readonly #files: ReplaySessionFiles;
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #now: () => string;
  readonly #startedAt: string;

  constructor(options: ReplayServiceOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#core = new ReplaySendCore(
      options.transport ?? new NodeReplayTransport(),
      options.elapsed,
    );
    this.#files =
      options.sessionFiles ??
      new ReplaySessionFiles(
        replaySessionDirectory(this.#environment, options.platform),
        options.platform,
      );
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#startedAt = this.#now();
  }

  /** Directory holding this server's session records, for diagnostics. */
  get sessionDirectory(): string {
    return this.#files.directory;
  }

  async startSession(
    request: StartReplaySessionRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = REPLAY_OPERATIONS.start;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const approved = parseReplayAllowedOrigins(
      this.#environment[REPLAY_ALLOWED_ORIGINS_ENV],
    );
    if (!approved.ok)
      return err(
        providerConfigurationRefusal(
          REPLAY_PROVIDER_ID,
          operation,
          approved.error,
        ),
      );
    const declared: string[] = [];
    for (const [index, value] of request.targetOrigins.entries()) {
      const origin = replayDeclaredOrigin(value);
      if (origin === undefined)
        return err(
          this.#inputError(operation, [
            {
              path: ["target_origins", index],
              reason: "invalid_format",
              message:
                "Declare an exact http or https origin, for example https://api.example.test; paths, wildcards and userinfo are rejected.",
            },
          ]),
        );
      if (!approved.value.includes(origin))
        return err(
          providerConfigurationRefusal(
            REPLAY_PROVIDER_ID,
            operation,
            new ReplayConfigurationFailure(
              "origin_not_allowlisted",
              `The declared origin ${origin} is not in the operator allowlist ${REPLAY_ALLOWED_ORIGINS_ENV}`,
              {
                setting: REPLAY_ALLOWED_ORIGINS_ENV,
                declared_origin: origin,
                remediation: REPLAY_ALLOWED_ORIGINS_REMEDIATION,
              },
            ),
          ),
        );
      if (!declared.includes(origin)) declared.push(origin);
    }

    const loaded =
      request.source.kind === "har"
        ? await this.#loadCapture(request.source, operation, options.signal)
        : this.#draftSession(request.source.request, operation, declared);
    if (!loaded.ok) return loaded;
    const { capture, selected, sessionRequest } = loaded.value;
    const sessionId = randomUUID();
    const createdAt = this.#now();
    const record: ReplaySessionRecord = {
      version: REPLAY_SESSION_FILE_VERSION,
      session_id: sessionId,
      owner: {
        process_id: process.pid,
        server_started_at: this.#serverIdentity(),
      },
      created_at: createdAt,
      source:
        capture === null
          ? { kind: "draft" }
          : { kind: "har", path: capture.path, sha256: capture.sha256 },
      selected_entry: selected === null ? null : selected.ordinal,
      target_origins: declared,
      draft: capture === null ? sessionRequest : null,
      send_count: 0,
      last_send_at: null,
    };
    const written = await this.#files.create(record, operation);
    if (!written.ok) return written;
    this.#sessions.set(sessionId, {
      id: sessionId,
      record,
      capture,
      pending: new Set(),
    });
    const entries = capture?.entries ?? [];
    const listed = entries.slice(0, REPLAY_LIMITS.maxListedEntries);
    return ok(
      createEvidence(
        capture === null
          ? undefined
          : { path: capture.path, sha256: capture.sha256, format: "file" },
        REPLAY_PROVIDER,
        {
          predicateType: "http-replay-session",
          operation,
          parameters: {
            session_id: sessionId,
            source_kind: capture === null ? "draft" : "har",
            target_origins: [...declared],
            ...(selected === null ? {} : { entry_ordinal: selected.ordinal }),
          },
          result: {
            session_id: sessionId,
            source:
              capture === null
                ? { kind: "draft" }
                : {
                    kind: "har",
                    path: capture.path,
                    sha256: capture.sha256,
                    entry_count: entries.length,
                  },
            entries: listed.map(entrySummary),
            entries_truncated: entries.length > listed.length,
            entry_count: entries.length,
            selected:
              selected === null
                ? sessionRequest === null
                  ? null
                  : requestSummary(sessionRequest)
                : entrySummary(selected),
            target_origins: [...declared],
            session_file: {
              path: written.value,
              permissions: this.#files.permissions,
            },
            retry: "none" as const,
          },
          confidence: "observed",
          authority: "controlled-replay",
          limitations: [
            REPLAY_RETRY_LIMITATION,
            REPLAY_REDACTION_LIMITATION,
            ...(capture === null ? [] : [REPLAY_CAPTURE_LIMITATION]),
            ...(capture === null ? [REPLAY_SESSION_FILE_LIMITATION] : []),
            `Session records live at ${this.#files.directory} and are removed by http_replay_session_close.`,
          ],
          locations:
            capture === null
              ? []
              : [{ kind: "artifact-path", path: capture.path }],
          ...(capture === null
            ? {
                subjectUnavailableReason:
                  "A drafted request has no captured artifact identity; the request is the caller's composition, not an observed exchange.",
              }
            : {}),
        },
      ),
    );
  }

  async send(
    request: SendReplayRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = REPLAY_OPERATIONS.send;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const found = this.#session(request.sessionId, operation);
    if (!found.ok) return found;
    const session = found.value;
    const selected = this.#selectedRequest(
      session,
      request.entryOrdinal,
      operation,
    );
    if (!selected.ok) return selected;
    const composed = composeReplayRequest(
      selected.value.request,
      request.mutation,
    );
    if (!composed.ok) return err(this.#inputError(operation, composed.error));
    const wire = composeReplayWireRequest(composed.value);
    if (!wire.ok) return err(this.#inputError(operation, wire.error));
    const approval = replayUrlApproval(
      composed.value.url,
      session.record.target_origins,
    );
    if (!approval.approved)
      return err(
        providerConfigurationRefusal(
          REPLAY_PROVIDER_ID,
          operation,
          new ReplayConfigurationFailure(
            "origin_not_allowlisted",
            approval.reason,
            {
              remediation: `${REPLAY_ALLOWED_ORIGINS_REMEDIATION} A mutation cannot leave the origins this session declared.`,
            },
          ),
        ),
      );

    // The counter write belongs to the admitted operation: a close must not
    // remove the record between the dispatch and its own book-keeping.
    const admitted = (async () => {
      const exchange = await this.#core.send({
        operation,
        request: composed.value,
        allowedOrigins: session.record.target_origins,
        timeoutMs: request.timeoutMs,
        followRedirects: request.followRedirects,
        signal: options.signal,
        dump: request.dump,
      });
      if (exchange.ok) await this.#recordSend(session, this.#now());
      return exchange;
    })();
    session.pending.add(admitted);
    const exchange = await admitted.finally(() => {
      session.pending.delete(admitted);
    });
    if (!exchange.ok) return exchange;

    return ok(
      createEvidence(
        session.capture === null
          ? undefined
          : {
              path: session.capture.path,
              sha256: session.capture.sha256,
              format: "file",
            },
        REPLAY_PROVIDER,
        {
          predicateType: "http-replay-send",
          operation,
          parameters: {
            session_id: session.record.session_id,
            ...(selected.value.ordinal === null
              ? {}
              : { entry_ordinal: selected.value.ordinal }),
            target_origins: [...session.record.target_origins],
            timeout_ms: request.timeoutMs,
            follow_redirects: request.followRedirects,
          },
          result: {
            session_id: session.record.session_id,
            entry_ordinal: selected.value.ordinal,
            request: exchange.value.request,
            redirect_chain: exchange.value.redirectChain,
            response: exchange.value.response,
            outcome: exchange.value.outcome,
            failure: exchange.value.failure,
            retry: "none" as const,
            elapsed_ms: exchange.value.elapsedMs,
          },
          confidence: "observed",
          authority: "controlled-replay",
          limitations: [
            REPLAY_RETRY_LIMITATION,
            REPLAY_BODY_LIMITATION,
            REPLAY_REDACTION_LIMITATION,
            REPLAY_TARGET_TEXT_LIMITATION,
            ...(session.capture === null ? [] : [REPLAY_CAPTURE_LIMITATION]),
          ],
          locations:
            exchange.value.response?.dump == null
              ? []
              : [
                  {
                    kind: "artifact-path",
                    path: exchange.value.response.dump.path,
                  },
                ],
          ...(session.capture === null
            ? {
                subjectUnavailableReason:
                  "A drafted request has no captured artifact identity; the send describes a request REA composed at the caller's direction.",
              }
            : {}),
        },
      ),
    );
  }

  async sessionStatus(
    request: ReplaySessionStatusRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = REPLAY_OPERATIONS.status;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const found = await this.#ownedSession(request.sessionId, operation);
    if (!found.ok) return found;
    const session = found.value;
    const entries = session.capture?.entries ?? [];
    return ok(
      createEvidence(
        session.capture === null
          ? undefined
          : {
              path: session.capture.path,
              sha256: session.capture.sha256,
              format: "file",
            },
        REPLAY_PROVIDER,
        {
          predicateType: "http-replay-session",
          operation,
          parameters: { session_id: request.sessionId },
          result: {
            session_id: request.sessionId,
            state: "open" as const,
            source:
              session.capture === null
                ? { kind: "draft" as const }
                : {
                    kind: "har" as const,
                    path: session.capture.path,
                    sha256: session.capture.sha256,
                    entry_count: entries.length,
                  },
            selected: this.#selectedSummary(session),
            entry_count: entries.length,
            target_origins: [...session.record.target_origins],
            send_count: session.record.send_count,
            last_send_at: session.record.last_send_at,
            session_file: {
              path: this.#files.pathFor(request.sessionId),
              permissions: this.#files.permissions,
            },
            retry: "none" as const,
          },
          confidence: "observed",
          authority: "controlled-replay",
          limitations: [
            REPLAY_RETRY_LIMITATION,
            `Counters describe sends this REA server performed in this session; they are not a record of the target's behavior.`,
          ],
          locations:
            session.capture === null
              ? []
              : [{ kind: "artifact-path", path: session.capture.path }],
          ...(session.capture === null
            ? {
                subjectUnavailableReason:
                  "A drafted request has no captured artifact identity.",
              }
            : {}),
        },
      ),
    );
  }

  async closeSession(
    request: CloseReplaySessionRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = REPLAY_OPERATIONS.close;
    const aborted = (): boolean => options.signal?.aborted === true;
    if (aborted()) return err(this.#cancelled(operation, options.signal!));
    const found = await this.#ownedSession(request.sessionId, operation);
    if (!found.ok) return found;
    const session = found.value;
    // Admitted sends finish before the record is removed; a cancellation that
    // lands in this drain leaves the file for a retryable close.
    await Promise.allSettled(session.pending);
    if (aborted()) return err(this.#cancelled(operation, options.signal!));
    const removed = await this.#files.remove(request.sessionId, operation);
    if (!removed.ok) return removed;
    this.#sessions.delete(request.sessionId);
    return ok(
      createEvidence(
        session.capture === null
          ? undefined
          : {
              path: session.capture.path,
              sha256: session.capture.sha256,
              format: "file",
            },
        REPLAY_PROVIDER,
        {
          predicateType: "http-replay-session",
          operation,
          parameters: { session_id: request.sessionId },
          result: {
            session_id: request.sessionId,
            state: "closed" as const,
            send_count: session.record.send_count,
            session_file: {
              path: this.#files.pathFor(request.sessionId),
              removed: removed.value,
            },
          },
          confidence: "observed",
          authority: "controlled-replay",
          limitations: [
            REPLAY_RETRY_LIMITATION,
            ...(removed.value
              ? []
              : [
                  "No session record remained to remove; another owner already deleted it.",
                ]),
          ],
          locations: [],
          ...(session.capture === null
            ? {
                subjectUnavailableReason:
                  "A drafted request has no captured artifact identity.",
              }
            : {}),
        },
      ),
    );
  }

  async closeAll(): Promise<Result<void, ProviderCleanupError>> {
    const failures: string[] = [];
    for (const id of this.#sessions.keys()) {
      const closed = await this.closeSession({ sessionId: id });
      if (!closed.ok) failures.push(id);
    }
    return failures.length === 0
      ? ok(undefined)
      : err(
          new ProviderCleanupError(REPLAY_PROVIDER_ID, ["replay-session"], {
            session_ids: failures,
          }),
        );
  }

  /**
   * The identity of this server instance, not the process start time: a
   * reused PID cannot claim a record this instance did not write.
   */
  #serverIdentity(): string {
    return this.#startedAt;
  }

  #cancelled(operation: string, signal: AbortSignal): AnalysisCancelledError {
    return new AnalysisCancelledError(operation, { cause: signal.reason });
  }

  #inputError(
    operation: string,
    issues: readonly AnalysisInputIssue[],
    userMessage?: string,
  ): AnalysisInputError {
    return new AnalysisInputError(
      operation,
      userMessage === undefined ? undefined : { userMessage },
      issues,
    );
  }

  async #recordSend(session: ReplaySession, sentAt: string): Promise<void> {
    if (!this.#sessions.has(session.id)) return;
    const record: ReplaySessionRecord = {
      ...session.record,
      send_count: session.record.send_count + 1,
      last_send_at: sentAt,
    };
    const updated = await this.#files.update(record, REPLAY_OPERATIONS.send);
    if (updated.ok) session.record = record;
  }

  #session(
    sessionId: string,
    operation: string,
  ): Result<ReplaySession, AnalysisError> {
    const session = this.#sessions.get(sessionId);
    return session === undefined
      ? err(
          this.#inputError(
            operation,
            [
              {
                path: ["session_id"],
                reason: "invalid_value",
                message:
                  "This REA server does not own that replay session. Session identity lasts for this server's lifetime; start a new session instead of reusing an id.",
              },
            ],
            "This REA server does not own that replay session. Session identity lasts for this server's lifetime; start a new session instead of reusing an id.",
          ),
        )
      : ok(session);
  }

  async #ownedSession(
    sessionId: string,
    operation: string,
  ): Promise<Result<ReplaySession, AnalysisError>> {
    const local = this.#session(sessionId, operation);
    if (local.ok) return local;
    const foreign = await this.#files.read(sessionId, operation);
    if (!foreign.ok) return foreign;
    if (foreign.value === null) return local;
    return err(
      this.#inputError(
        operation,
        [
          {
            path: ["session_id"],
            reason: "invalid_value",
            message: `A replay session record for that id exists at ${this.#files.pathFor(sessionId)} but this REA server did not write it. REA never adopts another server's session; leave the file alone or delete it after confirming no REA server is using it.`,
          },
        ],
        `A replay session record for that id exists at ${this.#files.pathFor(sessionId)} but this REA server did not write it. REA never adopts another server's session; leave the file alone or delete it after confirming no REA server is using it.`,
      ),
    );
  }

  #selectedSummary(session: ReplaySession) {
    if (session.capture === null) {
      const draft = session.record.draft;
      return draft === null ? null : requestSummary(draft);
    }
    const entry = session.capture.entries.find(
      (candidate) => candidate.ordinal === session.record.selected_entry,
    );
    return entry === undefined ? null : entrySummary(entry);
  }

  #selectedRequest(
    session: ReplaySession,
    ordinal: number | undefined,
    operation: string,
  ): Result<
    { readonly ordinal: number | null; readonly request: ReplayRequest },
    AnalysisError
  > {
    if (session.capture === null) {
      const draft = session.record.draft;
      return draft === null
        ? err(
            this.#inputError(operation, [
              {
                path: ["session_id"],
                reason: "invalid_value",
                message: "This draft session has no stored request.",
              },
            ]),
          )
        : ok({ ordinal: null, request: draft });
    }
    const target = ordinal ?? session.record.selected_entry;
    if (target === null)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["entry_ordinal"],
              reason: "missing_argument",
              message:
                "This capture session has no selected entry; pass entry_ordinal to choose one.",
            },
          ],
          "This capture session has no selected entry; pass entry_ordinal to choose one.",
        ),
      );
    const entry = session.capture.entries.find(
      (candidate) => candidate.ordinal === target,
    );
    if (entry === undefined)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["entry_ordinal"],
              reason: "invalid_value",
              message: `The capture has ${String(session.capture.entries.length)} entries; ${String(target)} is not one of them.`,
            },
          ],
          `The capture has ${String(session.capture.entries.length)} entries; ${String(target)} is not one of them.`,
        ),
      );
    if (entry.request === null)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["entry_ordinal"],
              reason: "invalid_value",
              message: `Entry ${String(target)} cannot be replayed: ${entry.unreplayableReason ?? "the entry is not replayable"}.`,
            },
          ],
          `Entry ${String(target)} cannot be replayed: ${entry.unreplayableReason ?? "the entry is not replayable"}.`,
        ),
      );
    const approval = replayUrlApproval(
      entry.request.url,
      session.record.target_origins,
    );
    if (!approval.approved)
      return err(
        providerConfigurationRefusal(
          REPLAY_PROVIDER_ID,
          operation,
          new ReplayConfigurationFailure(
            "origin_not_allowlisted",
            approval.reason,
            {
              remediation: `${REPLAY_ALLOWED_ORIGINS_REMEDIATION} Restart the session with the captured origin declared.`,
            },
          ),
        ),
      );
    return ok({ ordinal: entry.ordinal, request: entry.request });
  }

  async #loadCapture(
    source: Extract<ReplaySessionSource, { kind: "har" }>,
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<
    Result<
      {
        readonly capture: ReplayCapture;
        readonly selected: ReplayCapturedEntry | null;
        readonly sessionRequest: null;
      },
      AnalysisError
    >
  > {
    const read = await readReplayCapture(source.path, operation, signal);
    if (!read.ok) return read;
    const capture = read.value;
    const ordinal = source.entryOrdinal;
    if (ordinal === undefined)
      return ok({ capture, selected: null, sessionRequest: null });
    const entry = capture.entries.find(
      (candidate) => candidate.ordinal === ordinal,
    );
    if (entry === undefined)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["entry_ordinal"],
              reason: "invalid_value",
              message: `The capture has ${String(capture.entries.length)} entries; ${String(ordinal)} is not one of them.`,
            },
          ],
          `The capture has ${String(capture.entries.length)} entries; ${String(ordinal)} is not one of them.`,
        ),
      );
    if (entry.request === null)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["entry_ordinal"],
              reason: "invalid_value",
              message: `Entry ${String(ordinal)} cannot be replayed: ${entry.unreplayableReason ?? "the entry is not replayable"}.`,
            },
          ],
          `Entry ${String(ordinal)} cannot be replayed: ${entry.unreplayableReason ?? "the entry is not replayable"}.`,
        ),
      );
    return ok({ capture, selected: entry, sessionRequest: null });
  }

  #draftSession(
    request: ReplayRequest,
    operation: string,
    declared: readonly string[],
  ): Result<
    {
      readonly capture: null;
      readonly selected: null;
      readonly sessionRequest: ReplayRequest;
    },
    AnalysisError
  > {
    const wire = composeReplayWireRequest(request);
    if (!wire.ok) return err(this.#inputError(operation, wire.error));
    const approval = replayUrlApproval(request.url, declared);
    if (!approval.approved)
      return err(
        providerConfigurationRefusal(
          REPLAY_PROVIDER_ID,
          operation,
          new ReplayConfigurationFailure(
            "origin_not_allowlisted",
            approval.reason,
            {
              remediation: `${REPLAY_ALLOWED_ORIGINS_REMEDIATION} A drafted request must address an origin this session declares.`,
            },
          ),
        ),
      );
    return ok({ capture: null, selected: null, sessionRequest: request });
  }
}
