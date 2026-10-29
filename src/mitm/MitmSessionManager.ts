import { createHash, randomUUID } from "node:crypto";
import { mkdir, open, stat } from "node:fs/promises";
import { join } from "node:path";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  ClearMitmRuleRequest,
  ExportMitmInventoryRequest,
  MitmInterceptionPort,
  MitmReplayRequest,
  ReadMitmInventoryRequest,
  SetMitmRuleRequest,
  StartMitmSessionRequest,
} from "../application/mitm/MitmInterceptionPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisTimeoutError,
  type AnalysisInputIssue,
} from "../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import {
  MITM_ADDON_LIMITATION,
  MITM_CAPTURE_DIRECTORY_LIMITATION,
  MITM_REPLAY_LIMITATION,
  MITM_RULE_APPLICATION_LIMITATION,
  MITM_RULE_LIMITATION,
  MITM_RULE_VALUE_FREE_LIMITATION,
  MITM_SCOPE_LIMITATION,
  MITM_TLS_LIMITATION,
  MITM_VALUE_FREE_LIMITATION,
} from "../domain/mitm/mitmInterception.js";
import {
  MITM_ADDON_DIR_REMEDIATION,
  MITM_LISTEN_HOST,
  MITM_LIMITS,
  MITM_PROVIDER,
  MITM_PROVIDER_ID,
  mitmProxyGuidance,
  type MitmSessionState,
  type MitmTargetApp,
} from "../domain/mitm/mitmLimits.js";
import { MitmInventory } from "../domain/mitm/mitmInventory.js";
import {
  MitmRuleLedger,
  mitmRuleActionIssue,
  mitmRuleActionSummary,
  mitmRulePhase,
  type MitmRuleMatch,
} from "../domain/mitm/mitmRule.js";
import type {
  MitmReadyEvent,
  MitmStreamEvent,
} from "../domain/mitm/mitmStream.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  REPLAY_ALLOWED_ORIGINS_ENV,
  REPLAY_ALLOWED_ORIGINS_REMEDIATION,
  ReplayConfigurationFailure,
  normalizedReplayOrigin,
  parseReplayAllowedOrigins,
  replayOperatorPlaneOpen,
  replayUrlApproval,
} from "../domain/replay/replayOrigins.js";
import {
  composeReplayRequest,
  composeReplayWireRequest,
} from "../domain/replay/replayRequest.js";
import { err, ok, type Result } from "../domain/result.js";
import { NodeReplayTransport } from "../replay/NodeReplayTransport.js";
import type { ReplayTransport } from "../replay/ReplayTransport.js";
import { ReplaySendCore } from "../replay/ReplaySendCore.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import {
  resolveMitmConfiguration,
  MitmConfigurationFailure,
} from "./MitmConfiguration.js";
import {
  MitmDaemonProcess,
  MitmDaemonProtocolError,
} from "./MitmDaemonProcess.js";
import { readMitmEntry } from "./MitmEntryRecord.js";
import {
  mitmControlDocument,
  writeMitmControlFile,
  type MitmArmedRule,
} from "./MitmRuleControl.js";

const OPERATIONS = {
  start: "start_interception_session",
  read: "read_interception_inventory",
  export: "export_endpoint_inventory",
  ruleSet: "proxy_rule_set",
  ruleClear: "proxy_rule_clear",
  replay: "proxy_replay_send",
  stop: "stop_interception_session",
} as const;

/** The capture root this lane creates; the test seam replaces only allocation. */
export interface MitmCaptureRoot {
  readonly path: string;
  close(): Promise<void>;
}

export interface MitmSessionManagerOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly platform?: NodeJS.Platform;
  readonly transport?: ReplayTransport;
  readonly now?: () => Date;
  readonly elapsed?: () => number;
  /** Deterministic seam for tests; defaults to a private owner-only root. */
  readonly createRuntimeRoot?: (prefix: string) => Promise<MitmCaptureRoot>;
}

interface TrackedEntry {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

interface ArmedRule extends MitmArmedRule {
  readonly ledger: MitmRuleLedger;
}

interface StreamFacts {
  lines: number;
  events: number;
  malformed: number;
  oversized: number;
  unknownType: number;
  unknownRuleMatches: number;
  notices: number;
  errors: number;
  lastError: string | null;
}

interface MitmSession {
  readonly id: string;
  readonly targetApp: MitmTargetApp;
  readonly appIdentifier: string | undefined;
  readonly listenPort: number;
  readonly targetOrigins: readonly string[];
  readonly captureRoot: MitmCaptureRoot;
  readonly captureDirectory: string;
  readonly bodiesDirectory: string;
  readonly entriesDirectory: string;
  readonly controlPath: string;
  readonly inventory: MitmInventory;
  readonly rules: Map<string, ArmedRule>;
  readonly entries: Map<number, TrackedEntry>;
  readonly stream: StreamFacts;
  readonly startedAt: string;
  readonly pending: Set<Promise<unknown>>;
  daemon: MitmDaemonProcess;
  ready: MitmReadyEvent;
  controlRevision: number;
  entriesOmitted: number;
  state: MitmSessionState;
}

const streamFacts = (): StreamFacts => ({
  lines: 0,
  events: 0,
  malformed: 0,
  oversized: 0,
  unknownType: 0,
  unknownRuleMatches: 0,
  notices: 0,
  errors: 0,
  lastError: null,
});

const normalizedOrigins = (
  values: readonly string[],
  path: readonly (string | number)[],
):
  | { readonly ok: true; readonly value: readonly string[] }
  | { readonly ok: false; readonly issues: readonly AnalysisInputIssue[] } => {
  const declared: string[] = [];
  const issues: AnalysisInputIssue[] = [];
  for (const [index, value] of values.entries()) {
    const origin = normalizedReplayOrigin(value);
    if (origin === undefined) {
      issues.push({
        path: [...path, index],
        reason: "invalid_format",
        message:
          "Declare an exact http or https origin; paths, wildcards and userinfo are rejected.",
      });
      continue;
    }
    if (!declared.includes(origin)) declared.push(origin);
  }
  return issues.length === 0
    ? { ok: true, value: declared }
    : { ok: false, issues };
};

/**
 * Owns interception sessions: one supervised proxy each, a bounded value-free
 * inventory built from the addon's structure stream, the armed rewrite rules
 * mirrored into the addon's control file, and the owner-only capture directory
 * the addon writes bodies into.
 *
 * Replay is a projection over `ReplaySendCore`; this class adds no dispatch
 * policy of its own beyond intersecting the session's declared origins with the
 * operator allowlist.
 */
export class MitmSessionManager implements MitmInterceptionPort {
  readonly #sessions = new Map<string, MitmSession>();
  readonly #core: ReplaySendCore;
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #platform: NodeJS.Platform;
  readonly #now: () => Date;
  readonly #createRuntimeRoot: (prefix: string) => Promise<MitmCaptureRoot>;

  constructor(options: MitmSessionManagerOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#platform = options.platform ?? process.platform;
    this.#now = options.now ?? (() => new Date());
    this.#core = new ReplaySendCore(
      options.transport ?? new NodeReplayTransport(),
      options.elapsed,
    );
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      (async (prefix) => PrivateRuntimeRoot.create({ prefix }));
  }

  /** Directory of one live session's capture, for diagnostics. */
  captureDirectory(sessionId: string): string | undefined {
    return this.#sessions.get(sessionId)?.captureDirectory;
  }

  async start(
    request: StartMitmSessionRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = OPERATIONS.start;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const configuration = this.#configuration(operation);
    if (!configuration.ok) return configuration;
    const declared = normalizedOrigins(request.targetOrigins, [
      "target_origins",
    ]);
    if (!declared.ok) return err(this.#inputError(operation, declared.issues));
    const captureRoot = await this.#createRuntimeRoot("rea-mitm-");
    const captureDirectory = captureRoot.path;
    const bodiesDirectory = join(captureDirectory, "bodies");
    const entriesDirectory = join(captureDirectory, "entries");
    const controlPath = join(captureDirectory, "rules.json");
    try {
      await mkdir(bodiesDirectory, { recursive: true, mode: 0o700 });
      await mkdir(entriesDirectory, { recursive: true, mode: 0o700 });
      await writeMitmControlFile(controlPath, 0, mitmControlDocument(0, []));
    } catch (cause: unknown) {
      await captureRoot.close().catch(() => undefined);
      return err(
        new AnalysisOutputError(operation, "capture-directory-unwritable", {
          cause,
          userMessage:
            "REA could not prepare the owner-only capture directory for this proxy session.",
        }),
      );
    }

    const session: MitmSession = {
      id: randomUUID(),
      targetApp: request.targetApp,
      appIdentifier: request.appIdentifier,
      listenPort: request.listenPort,
      targetOrigins: declared.value,
      captureRoot,
      captureDirectory,
      bodiesDirectory,
      entriesDirectory,
      controlPath,
      inventory: new MitmInventory(),
      rules: new Map(),
      entries: new Map(),
      stream: streamFacts(),
      startedAt: this.#now().toISOString(),
      pending: new Set(),
      // Assigned below, once the proxy has advertised its protocol.
      daemon: undefined as unknown as MitmDaemonProcess,
      ready: undefined as unknown as MitmReadyEvent,
      controlRevision: 0,
      entriesOmitted: 0,
      state: "capturing",
    };

    let started: {
      readonly daemon: MitmDaemonProcess;
      readonly ready: MitmReadyEvent;
    };
    try {
      started = await MitmDaemonProcess.start({
        command: configuration.value.command,
        addonPath: configuration.value.addonPath,
        listenPort: request.listenPort,
        runId: randomUUID(),
        captureDirectory,
        controlPath,
        hostEnvironment: this.#environment,
        startTimeoutMs: request.startTimeoutMs,
        maxLineBytes: MITM_LIMITS.maxStreamLineBytes,
        onEvent: (event) => this.#onEvent(session, event),
        onStreamProblem: (problem) => this.#onStreamProblem(session, problem),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (cause: unknown) {
      await captureRoot.close().catch(() => undefined);
      return err(this.#startFailure(operation, cause, request.startTimeoutMs));
    }
    session.daemon = started.daemon;
    session.ready = started.ready;
    this.#sessions.set(session.id, session);
    const guidance = mitmProxyGuidance(
      request.targetApp,
      request.listenPort,
      request.appIdentifier,
    );
    return ok(
      createEvidence(undefined, MITM_PROVIDER, {
        predicateType: "mitm-interception-session",
        operation,
        parameters: {
          session_id: session.id,
          target_app: request.targetApp,
          listen_port: request.listenPort,
          target_origins: [...session.targetOrigins],
          start_timeout_ms: request.startTimeoutMs,
          ...(request.appIdentifier === undefined
            ? {}
            : { app_identifier: request.appIdentifier }),
        },
        result: {
          session_id: session.id,
          state: session.state,
          daemon: this.#daemonFacts(session),
          listen: this.#listenFacts(session),
          capture: this.#captureFacts(session),
          proxy_guidance: {
            target_app: guidance.target_app,
            per_app_only: true,
            steps: [...guidance.steps],
            out_of_scope: [...guidance.out_of_scope],
          },
          tls: {
            scope: "per-application" as const,
            trust_store_changes: "out-of-scope" as const,
            device_wide_interception: "out-of-scope" as const,
            ca: {
              supplied_by: "caller" as const,
              served_at: "http://mitm.it" as const,
            },
          },
          target_origins: [...session.targetOrigins],
          retry: "none" as const,
          limitations: [
            MITM_SCOPE_LIMITATION,
            MITM_VALUE_FREE_LIMITATION,
            MITM_CAPTURE_DIRECTORY_LIMITATION,
            MITM_ADDON_LIMITATION,
            MITM_TLS_LIMITATION,
            `This lane has only been exercised with a scripted mitmdump stand-in in the offline suite; no claim is made about a specific client's proxy behavior or TLS negotiation.`,
          ],
        },
        confidence: "observed",
        authority: "controlled-replay",
        locations: [{ kind: "artifact-path", path: captureDirectory }],
        subjectUnavailableReason:
          "The proxy observes traffic a caller routed to it; there is no single analysis-target artifact to name as the subject.",
      }),
    );
  }

  async readInventory(
    request: ReadMitmInventoryRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = OPERATIONS.read;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const found = this.#session(request.sessionId, operation);
    if (!found.ok) return found;
    const session = found.value;
    await this.#expireRules(session);
    const snapshot = session.inventory.snapshot();
    const page = snapshot.endpoints.slice(
      request.offset,
      request.offset + request.limit,
    );
    const next = request.offset + page.length;
    return ok(
      createEvidence(undefined, MITM_PROVIDER, {
        predicateType: "mitm-interception-session",
        operation,
        parameters: {
          session_id: session.id,
          offset: request.offset,
          limit: request.limit,
        },
        result: {
          session_id: session.id,
          state: session.state,
          daemon: this.#daemonFacts(session),
          listen: this.#listenFacts(session),
          capture: this.#captureFacts(session),
          target_origins: [...session.targetOrigins],
          totals: snapshot.totals,
          endpoints: page,
          next_offset: next < snapshot.endpoints.length ? next : null,
          stream: this.#streamFacts(session),
          rules: this.#ruleSummaries(session),
          retry: "none" as const,
          limitations: [
            MITM_SCOPE_LIMITATION,
            MITM_VALUE_FREE_LIMITATION,
            MITM_CAPTURE_DIRECTORY_LIMITATION,
            ...(session.state === "degraded"
              ? [
                  "The structure stream reported frames this build refused. Everything retained is an observation of the frames that parsed, not of every exchange the proxy saw.",
                ]
              : []),
          ],
        },
        confidence: "observed",
        authority: "controlled-replay",
        locations: [{ kind: "artifact-path", path: session.captureDirectory }],
        subjectUnavailableReason:
          "The inventory describes traffic a caller routed to this proxy; it is not derived from one analysis-target artifact.",
      }),
    );
  }

  async exportInventory(
    request: ExportMitmInventoryRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = OPERATIONS.export;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const found = this.#session(request.sessionId, operation);
    if (!found.ok) return found;
    const session = found.value;
    await this.#expireRules(session);
    const snapshot = session.inventory.snapshot();
    const exportedAt = this.#now().toISOString();
    let file: {
      path: string;
      bytes: number;
      sha256: string;
      permissions: "0600" | "unverified";
    } | null = null;
    if (request.path !== undefined) {
      if (!request.overwrite) {
        const occupied = await stat(request.path).then(
          () => true,
          () => false,
        );
        if (occupied)
          return err(
            this.#inputError(
              operation,
              [
                {
                  path: ["path"],
                  reason: "invalid_value",
                  message:
                    "The export path already exists; pass overwrite: true to replace it.",
                },
              ],
              "The export path already exists; pass overwrite: true to replace it.",
            ),
          );
      }
      const body = JSON.stringify({
        session_id: session.id,
        exported_at: exportedAt,
        target_origins: [...session.targetOrigins],
        totals: snapshot.totals,
        endpoints: snapshot.endpoints,
        stream: this.#streamFacts(session),
      });
      const bytes = Buffer.from(body, "utf8");
      let handle;
      try {
        handle = await open(
          request.path,
          request.overwrite ? "w" : "wx",
          0o600,
        );
        await handle.writeFile(bytes);
      } catch (cause: unknown) {
        await handle?.close().catch(() => undefined);
        return err(
          new AnalysisOutputError(operation, "export-unwritable", {
            cause,
            userMessage: `REA could not write the endpoint inventory to ${request.path}.`,
          }),
        );
      }
      try {
        await handle.sync().catch(() => undefined);
      } finally {
        await handle.close();
      }
      file = {
        path: request.path,
        bytes: bytes.byteLength,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        permissions: this.#platform === "win32" ? "unverified" : "0600",
      };
    }
    return ok(
      createEvidence(undefined, MITM_PROVIDER, {
        predicateType: "mitm-endpoint-inventory",
        operation,
        parameters: {
          session_id: session.id,
          ...(request.path === undefined
            ? {}
            : { path: request.path, overwrite: request.overwrite }),
        },
        result: {
          session_id: session.id,
          state: session.state,
          exported_at: exportedAt,
          totals: snapshot.totals,
          endpoints: snapshot.endpoints,
          stream: this.#streamFacts(session),
          file,
          retry: "none" as const,
          limitations: [
            MITM_SCOPE_LIMITATION,
            MITM_VALUE_FREE_LIMITATION,
            MITM_CAPTURE_DIRECTORY_LIMITATION,
            ...(snapshot.totals.endpoints_omitted === 0 &&
            snapshot.totals.facts_omitted === 0
              ? []
              : [
                  `This inventory reported ${String(snapshot.totals.endpoints_omitted)} omitted endpoints and ${String(snapshot.totals.facts_omitted)} omitted facts at its fixed budgets; the export is not a complete record of every endpoint the proxy saw.`,
                ]),
          ],
        },
        confidence: "observed",
        authority: "controlled-replay",
        locations: [
          { kind: "artifact-path", path: session.captureDirectory },
          ...(request.path === undefined
            ? []
            : [{ kind: "artifact-path" as const, path: request.path }]),
        ],
        subjectUnavailableReason:
          "The inventory describes traffic a caller routed to this proxy; it is not derived from one analysis-target artifact.",
      }),
    );
  }

  async setRule(
    request: SetMitmRuleRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = OPERATIONS.ruleSet;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const found = this.#session(request.sessionId, operation);
    if (!found.ok) return found;
    const session = found.value;
    await this.#expireRules(session);
    if (session.rules.size >= MITM_LIMITS.maxArmedRules)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["session_id"],
              reason: "invalid_value",
              message: `At most ${String(MITM_LIMITS.maxArmedRules)} rules stay armed on one session; clear one before arming another.`,
            },
          ],
          `At most ${String(MITM_LIMITS.maxArmedRules)} rules stay armed on one session; clear one before arming another.`,
        ),
      );
    const ruleId = request.ruleId ?? randomUUID();
    if (session.rules.has(ruleId))
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["rule_id"],
              reason: "invalid_value",
              message:
                "That rule identity is already armed on this session; clear it before reusing the id.",
            },
          ],
          "That rule identity is already armed on this session; clear it before reusing the id.",
        ),
      );
    if (
      request.match.origins.length === 0 &&
      request.match.pathPrefixes.length === 0 &&
      request.match.methods.length === 0
    )
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["match"],
              reason: "missing_argument",
              message:
                "Supply at least one predicate (origin, path prefix, or method): a rule never rewrites the whole proxy by accident.",
            },
          ],
          "Supply at least one predicate (origin, path prefix, or method): a rule never rewrites the whole proxy by accident.",
        ),
      );
    const action = request.action;
    const actionIssue = mitmRuleActionIssue(action);
    if (actionIssue !== undefined)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["action"],
              reason: "invalid_format",
              message: actionIssue,
            },
          ],
          actionIssue,
        ),
      );
    const match: MitmRuleMatch = {
      origins: [...request.match.origins],
      pathPrefixes: [...request.match.pathPrefixes],
      methods: request.match.methods.map((method) => method.toUpperCase()),
    };
    const now = this.#now();
    const armed: ArmedRule = {
      ruleId,
      match,
      action,
      expiresAtMs: now.getTime() + request.ttlMs,
      ledger: new MitmRuleLedger(),
    };
    session.rules.set(ruleId, armed);
    let written;
    try {
      written = await this.#writeControl(session);
    } catch (cause: unknown) {
      session.rules.delete(ruleId);
      return err(
        new AnalysisOutputError(operation, "control-unwritable", {
          cause,
          userMessage:
            "REA could not write the addon control file, so the rule was not armed.",
        }),
      );
    }
    return ok(
      createEvidence(undefined, MITM_PROVIDER, {
        predicateType: "mitm-rewrite-rule",
        operation,
        parameters: {
          session_id: session.id,
          rule_id: ruleId,
          phase: mitmRulePhase(action),
          ttl_ms: request.ttlMs,
        },
        result: {
          session_id: session.id,
          rule_id: ruleId,
          state: "armed" as const,
          phase: mitmRulePhase(action),
          match: {
            origins: [...match.origins],
            path_prefixes: [...match.pathPrefixes],
            methods: [...match.methods],
          },
          action: mitmRuleActionSummary(action),
          ttl_ms: request.ttlMs,
          expires_at: new Date(armed.expiresAtMs).toISOString(),
          control: { revision: written.revision, sha256: written.sha256 },
          counters: { ...armed.ledger.counters },
          limitations: [
            MITM_RULE_LIMITATION,
            MITM_RULE_APPLICATION_LIMITATION,
            MITM_RULE_VALUE_FREE_LIMITATION,
          ],
        },
        confidence: "derived",
        authority: "controlled-replay",
        locations: [{ kind: "artifact-path", path: session.controlPath }],
        subjectUnavailableReason:
          "A rewrite rule describes REA's own choice for traffic the proxy carries, not a fact about one analysis-target artifact.",
      }),
    );
  }

  async clearRule(
    request: ClearMitmRuleRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = OPERATIONS.ruleClear;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const found = this.#session(request.sessionId, operation);
    if (!found.ok) return found;
    const session = found.value;
    const armed = session.rules.get(request.ruleId);
    if (armed === undefined)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["rule_id"],
              reason: "invalid_value",
              message:
                "This session has no armed rule with that identity; an expired or cleared rule cannot be cleared again.",
            },
          ],
          "This session has no armed rule with that identity; an expired or cleared rule cannot be cleared again.",
        ),
      );
    const releaseReason =
      armed.expiresAtMs <= this.#now().getTime() ? "expired" : "cleared";
    session.rules.delete(request.ruleId);
    try {
      await this.#writeControl(session);
    } catch (cause: unknown) {
      session.rules.set(request.ruleId, armed);
      return err(
        new AnalysisOutputError(operation, "control-unwritable", {
          cause,
          userMessage:
            "REA could not remove the rule from the addon control file, so it stays armed for a retry.",
        }),
      );
    }
    return ok(
      createEvidence(undefined, MITM_PROVIDER, {
        predicateType: "mitm-rewrite-rule",
        operation,
        parameters: {
          session_id: session.id,
          rule_id: request.ruleId,
        },
        result: {
          session_id: session.id,
          rule_id: request.ruleId,
          state: "cleared" as const,
          release_reason: releaseReason,
          counters: { ...armed.ledger.counters },
          decisions: armed.ledger.snapshot(),
          limitations: [
            MITM_RULE_LIMITATION,
            MITM_RULE_APPLICATION_LIMITATION,
            MITM_RULE_VALUE_FREE_LIMITATION,
            "The addon drops a rule past its expires_at even if this control write is not observed; a match that arrived after release is not in this ledger.",
          ],
        },
        confidence: "observed",
        authority: "controlled-replay",
        locations: [{ kind: "artifact-path", path: session.controlPath }],
        subjectUnavailableReason:
          "A released rewrite rule reports REA's own decisions, not a fact about one analysis-target artifact.",
      }),
    );
  }

  async replay(
    request: MitmReplayRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = OPERATIONS.replay;
    if (options.signal?.aborted === true)
      return err(this.#cancelled(operation, options.signal));
    const found = this.#session(request.sessionId, operation);
    if (!found.ok) return found;
    const session = found.value;
    const entry = session.entries.get(request.sequence);
    if (entry === undefined)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["sequence"],
              reason: "invalid_value",
              message: `This session tracks no captured entry ${String(request.sequence)}. Entries are tracked for this session's lifetime and at most ${String(MITM_LIMITS.maxTrackedEntries)} stay addressable; read the inventory again and use a sequence it reports.`,
            },
          ],
          `This session tracks no captured entry ${String(request.sequence)}. Entries are tracked for this session's lifetime and at most ${String(MITM_LIMITS.maxTrackedEntries)} stay addressable; read the inventory again and use a sequence it reports.`,
        ),
      );
    const read = await readMitmEntry(
      session.captureDirectory,
      entry.path,
      request.sequence,
      { bytes: entry.bytes, sha256: entry.sha256 },
    );
    if (!read.ok)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["sequence"],
              reason: "invalid_value",
              message: `Entry ${String(request.sequence)} cannot be re-sent: ${read.detail}.`,
            },
          ],
          `Entry ${String(request.sequence)} cannot be re-sent: ${read.detail}.`,
        ),
      );
    const composed = composeReplayRequest(read.request, request.mutation);
    if (!composed.ok) return err(this.#inputError(operation, composed.error));
    const wire = composeReplayWireRequest(composed.value);
    if (!wire.ok) return err(this.#inputError(operation, wire.error));
    const approved = parseReplayAllowedOrigins(
      this.#environment[REPLAY_ALLOWED_ORIGINS_ENV],
    );
    if (!approved.ok)
      return err(
        providerConfigurationRefusal(
          MITM_PROVIDER_ID,
          operation,
          approved.error,
        ),
      );
    const allowedOrigins = replayOperatorPlaneOpen(approved.value)
      ? session.targetOrigins
      : session.targetOrigins.filter((origin) =>
          approved.value.includes(origin),
        );
    const approval = replayUrlApproval(composed.value.url, allowedOrigins);
    if (!approval.approved)
      return err(
        providerConfigurationRefusal(
          MITM_PROVIDER_ID,
          operation,
          new ReplayConfigurationFailure(
            "origin_not_allowlisted",
            approval.reason,
            {
              remediation: `${REPLAY_ALLOWED_ORIGINS_REMEDIATION} A replayed entry must address an origin this session declared and the operator allowlist approves.`,
            },
          ),
        ),
      );

    const admitted = this.#core.send({
      operation,
      request: composed.value,
      allowedOrigins,
      timeoutMs: request.timeoutMs,
      followRedirects: request.followRedirects,
      signal: options.signal,
      dump: request.dump,
    });
    session.pending.add(admitted);
    const exchange = await admitted.finally(() => {
      session.pending.delete(admitted);
    });
    if (!exchange.ok) return exchange;
    return ok(
      createEvidence(undefined, MITM_PROVIDER, {
        predicateType: "mitm-replay-send",
        operation,
        parameters: {
          session_id: session.id,
          captured_sequence: request.sequence,
          target_origins: [...allowedOrigins],
          timeout_ms: request.timeoutMs,
          follow_redirects: request.followRedirects,
        },
        result: {
          session_id: session.id,
          captured_sequence: request.sequence,
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
          MITM_REPLAY_LIMITATION,
          "The echoed request lists header names, a credential-header disclosure list, and a body size only; the exact wire bytes sent are the capture's own bytes plus the caller's mutation.",
          "Status lines, header names, and redirect locations are target-authored text; they are reported because the target sent them.",
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
        subjectUnavailableReason:
          "The replay re-sends a captured exchange; the capture directory, not a single artifact, is the provenance.",
      }),
    );
  }

  async stop(
    request: { readonly sessionId: string },
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = OPERATIONS.stop;
    const aborted = (): boolean => options.signal?.aborted === true;
    const session = this.#sessions.get(request.sessionId);
    if (session === undefined)
      return err(
        this.#inputError(
          operation,
          [
            {
              path: ["session_id"],
              reason: "invalid_value",
              message:
                "This REA server owns no interception session with that id; session identity lasts for this server's lifetime.",
            },
          ],
          "This REA server owns no interception session with that id; session identity lasts for this server's lifetime.",
        ),
      );
    if (aborted()) return err(this.#cancelled(operation, options.signal!));
    const released = await this.#releaseSession(session, operation);
    if (released.stop.status !== "incomplete") session.state = "stopped";
    const evidence = this.#stopEvidence(session, released);
    if (released.error === null && released.captureRemoved)
      this.#sessions.delete(session.id);
    if (released.error !== null)
      return err(released.error.retainPartialObservation(evidence));
    if (aborted())
      return err(
        this.#cancelled(operation, options.signal!).retainPartialObservation(
          evidence,
        ),
      );
    return ok(evidence);
  }

  async closeAll(): Promise<Result<void, ProviderCleanupError>> {
    const failures: string[] = [];
    for (const session of this.#sessions.values()) {
      const released = await this.#releaseSession(session, OPERATIONS.stop);
      if (released.error !== null || !released.captureRemoved) {
        failures.push(session.id);
        continue;
      }
      session.state = "stopped";
      this.#sessions.delete(session.id);
    }
    return failures.length === 0
      ? ok(undefined)
      : err(
          new ProviderCleanupError(MITM_PROVIDER_ID, ["mitm-session"], {
            session_ids: failures,
          }),
        );
  }

  async #releaseSession(
    session: MitmSession,
    operation: string,
  ): Promise<{
    readonly stop: Awaited<ReturnType<MitmDaemonProcess["stop"]>>;
    readonly captureRemoved: boolean;
    readonly error: ProviderCleanupError | null;
  }> {
    let stop: Awaited<ReturnType<MitmDaemonProcess["stop"]>>;
    try {
      stop = await session.daemon.stop();
    } catch (cause: unknown) {
      stop = { status: "incomplete", reason: errorMessage(cause) };
    }
    let captureRemoved = false;
    let captureFailure: unknown;
    try {
      await session.captureRoot.close();
      captureRemoved = true;
    } catch (cause: unknown) {
      captureFailure = cause;
    }
    if (stop.status === "incomplete" || captureFailure !== undefined)
      return {
        stop,
        captureRemoved,
        error: new ProviderCleanupError(
          MITM_PROVIDER_ID,
          [
            ...(stop.status === "incomplete"
              ? [`mitm-process:${session.id}`]
              : []),
            ...(captureFailure === undefined
              ? []
              : [`mitm-capture:${session.captureDirectory}`]),
          ],
          {
            reason:
              "REA could not confirm stopping the proxy or removing its capture directory.",
            retained_sessions: [session.id],
            ...(captureFailure === undefined
              ? {}
              : { capture_error: errorMessage(captureFailure) }),
          },
          { operation },
        ),
      };
    return { stop, captureRemoved, error: null };
  }

  #stopEvidence(
    session: MitmSession,
    released: {
      readonly stop: Awaited<ReturnType<MitmDaemonProcess["stop"]>>;
      readonly captureRemoved: boolean;
    },
  ): Evidence {
    const exit = session.daemon.exitObservation;
    return createEvidence(undefined, MITM_PROVIDER, {
      predicateType: "mitm-interception-session",
      operation: OPERATIONS.stop,
      parameters: { session_id: session.id },
      result: {
        session_id: session.id,
        state: session.state,
        daemon: {
          pid: session.daemon.pid ?? null,
          exit:
            exit === undefined
              ? { kind: "unknown" as const, code: null, signal: null }
              : exit.signal === null
                ? {
                    kind: "exited" as const,
                    code: exit.code,
                    signal: null,
                  }
                : {
                    kind: "signalled" as const,
                    code: exit.code,
                    signal: exit.signal,
                  },
        },
        capture: {
          directory: session.captureDirectory,
          removed: released.captureRemoved,
        },
        rules_released: session.rules.size,
        retry: "none" as const,
        limitations: [
          MITM_CAPTURE_DIRECTORY_LIMITATION,
          ...(released.captureRemoved
            ? []
            : [
                "This session's capture directory was not removed, so REA keeps the session identity for a retry.",
              ]),
        ],
      },
      confidence: "observed",
      authority: "controlled-replay",
      locations: released.captureRemoved
        ? []
        : [{ kind: "artifact-path", path: session.captureDirectory }],
      subjectUnavailableReason:
        "Stopping an interception session reports REA's own resources, not facts about an analysis-target artifact.",
    });
  }

  #onEvent(session: MitmSession, event: MitmStreamEvent): void {
    session.stream.lines += 1;
    session.stream.events += 1;
    switch (event.type) {
      case "flow": {
        session.inventory.applyFlow(event);
        if (event.entry !== null) {
          session.entries.set(event.sequence, {
            path: event.entry.path,
            bytes: event.entry.bytes,
            sha256: event.entry.sha256,
          });
          while (session.entries.size > MITM_LIMITS.maxTrackedEntries) {
            const oldest = session.entries.keys().next().value;
            if (oldest === undefined) break;
            session.entries.delete(oldest);
            session.entriesOmitted += 1;
          }
        }
        return;
      }
      case "rule_match": {
        const armed = session.rules.get(event.rule_id);
        if (armed === undefined) session.stream.unknownRuleMatches += 1;
        else armed.ledger.apply(event);
        return;
      }
      case "notice":
        session.stream.notices += 1;
        return;
      case "error":
        session.stream.errors += 1;
        session.stream.lastError = event.message;
        return;
    }
  }

  #onStreamProblem(
    session: MitmSession,
    problem: "malformed" | "oversized" | "unknown-type",
  ): void {
    if (problem === "malformed") session.stream.malformed += 1;
    else if (problem === "oversized") session.stream.oversized += 1;
    else session.stream.unknownType += 1;
    if (
      session.stream.malformed + session.stream.oversized >
      MITM_LIMITS.maxMalformedLines
    )
      session.state = "degraded";
    if (session.daemon !== undefined && !session.daemon.running)
      session.state = "degraded";
  }

  #daemonFacts(session: MitmSession) {
    return {
      pid: session.daemon.pid ?? null,
      mitmproxy_version: session.ready.mitmproxy.version,
      addon: { ...session.ready.addon },
      running: session.daemon.running,
    };
  }

  #listenFacts(session: MitmSession) {
    return {
      host: MITM_LISTEN_HOST as "127.0.0.1",
      port: session.listenPort,
      proxy_url: `http://${MITM_LISTEN_HOST}:${String(session.listenPort)}`,
    };
  }

  #captureFacts(session: MitmSession) {
    return {
      directory: session.captureDirectory,
      entries: session.entries.size,
      entries_omitted: session.entriesOmitted,
      permissions:
        this.#platform === "win32"
          ? ("unverified" as const)
          : ("0700" as const),
    };
  }

  #streamFacts(session: MitmSession) {
    return {
      lines: session.stream.lines,
      events: session.stream.events,
      malformed: session.stream.malformed,
      oversized: session.stream.oversized,
      unknown_type: session.stream.unknownType,
      unknown_rule_matches: session.stream.unknownRuleMatches,
      notices: session.stream.notices,
      errors: session.stream.errors,
      last_error: session.stream.lastError,
    };
  }

  #ruleSummaries(session: MitmSession) {
    const nowMs = this.#now().getTime();
    return [...session.rules.values()]
      .map((rule) => ({
        rule_id: rule.ruleId,
        phase: mitmRulePhase(rule.action),
        match: {
          origins: [...rule.match.origins],
          path_prefixes: [...rule.match.pathPrefixes],
          methods: [...rule.match.methods],
        },
        expires_at: new Date(rule.expiresAtMs).toISOString(),
        expired: rule.expiresAtMs <= nowMs,
        counters: { ...rule.ledger.counters },
      }))
      .sort((left, right) => (left.rule_id < right.rule_id ? -1 : 1));
  }

  async #expireRules(session: MitmSession): Promise<void> {
    const nowMs = this.#now().getTime();
    let changed = false;
    for (const [ruleId, rule] of session.rules)
      if (rule.expiresAtMs <= nowMs) {
        session.rules.delete(ruleId);
        changed = true;
      }
    if (!changed) return;
    // The addon also drops a rule past its expires_at, so a failed rewrite
    // leaves no armed rule behind; the next control write converges.
    await this.#writeControl(session).catch(() => undefined);
  }

  async #writeControl(
    session: MitmSession,
  ): Promise<{ readonly revision: number; readonly sha256: string }> {
    const revision = session.controlRevision + 1;
    const written = await writeMitmControlFile(
      session.controlPath,
      revision,
      mitmControlDocument(revision, session.rules.values()),
    );
    session.controlRevision = written.revision;
    return written;
  }

  #configuration(
    operation: string,
  ): Result<
    { readonly command: string; readonly addonPath: string },
    AnalysisError
  > {
    try {
      return ok(resolveMitmConfiguration(this.#environment));
    } catch (cause: unknown) {
      if (cause instanceof MitmConfigurationFailure)
        return err(
          providerConfigurationRefusal(MITM_PROVIDER_ID, operation, cause),
        );
      return err(
        new AnalysisCapabilityUnavailableError(
          MITM_PROVIDER_ID,
          operation,
          `The interception lane could not read its configuration: ${errorMessage(cause)}.`,
          { cause, userMessage: errorMessage(cause) },
        ),
      );
    }
  }

  #startFailure(
    operation: string,
    cause: unknown,
    startTimeoutMs: number,
  ): AnalysisError {
    if (cause instanceof MitmDaemonProtocolError) {
      if (cause.message === "cancelled")
        return new AnalysisCancelledError(operation, { cause });
      if (cause.message.includes("did not advertise"))
        return new AnalysisTimeoutError(operation, startTimeoutMs, {
          cause,
          userMessage:
            "The proxy never advertised the REA structure stream within the start deadline. REA stopped the child and removed the capture directory.",
        });
      return new AnalysisCapabilityUnavailableError(
        MITM_PROVIDER_ID,
        operation,
        `${cause.message}. ${MITM_ADDON_DIR_REMEDIATION}`,
        { cause, userMessage: cause.message },
      );
    }
    return new AnalysisCapabilityUnavailableError(
      MITM_PROVIDER_ID,
      operation,
      `REA could not start the selected mitmdump binary: ${errorMessage(cause)}.`,
      { cause, userMessage: errorMessage(cause) },
    );
  }

  #session(
    sessionId: string,
    operation: string,
  ): Result<MitmSession, AnalysisError> {
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
                  "This REA server does not own that interception session. Session identity lasts for this server's lifetime; start a new session instead of reusing an id.",
              },
            ],
            "This REA server does not own that interception session. Session identity lasts for this server's lifetime; start a new session instead of reusing an id.",
          ),
        )
      : ok(session);
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
}

const errorMessage = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);
