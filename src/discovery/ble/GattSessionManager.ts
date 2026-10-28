/**
 * Owns CoreBluetooth GATT sessions opened through the caller-supplied
 * helper. Session state lives only in this process: session_ids are minted
 * here, re-checked on every call, and the owned child handle is the
 * session's identity, so there is no PID-reuse surface to re-verify. One
 * command is in flight per session; a helper exit marks the session closed.
 */
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";

import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  gattLineWithoutPayload,
  gattPayloadAccounting,
  parseGattLine,
  parseGattServiceTree,
  type GattPayloadAccounting,
  type ParsedGattService,
} from "./GattAnalysis.js";

/** Upper bound on a session helper's live output, enforced line-wise. */
export const GATT_MAX_SESSION_OUTPUT_BYTES = 2 * 1024 * 1024;

/** Grace before SIGTERM escalation after a disconnect handshake. */
export const GATT_CLOSE_GRACE_MS = 2_000;

const CHILD_START_GRACE_MS = 5_000;

/** Why a session could not be opened or is no longer usable. */
export type GattSessionFailure =
  | { readonly code: "authorization_denied"; readonly reason: string }
  | { readonly code: "connect_timeout"; readonly reason: string }
  | {
      readonly code: "connect_refused";
      readonly reason: string;
      readonly exit_code: number | null;
    }
  | { readonly code: "helper_missing"; readonly reason: string }
  | { readonly code: "protocol_violation"; readonly reason: string }
  | { readonly code: "peer_disconnected"; readonly reason: string }
  | { readonly code: "command_refused"; readonly reason: string }
  | { readonly code: "session_unknown"; readonly reason: string };

export type GattOutcome = GattSessionFailure | AnalysisError;

/** Facts a follow-up command carries about its target session. */
export interface GattSessionFacts {
  readonly session_id: string;
  readonly peripheral_id: string;
  readonly name: string | null;
}

/** A connected session's discovered service tree. */
export interface GattSessionOpened extends GattSessionFacts {
  readonly services: readonly ParsedGattService[];
}

/** One collected notification; payload hex is pre-filtered by the opt-in. */
export interface GattNotificationRow {
  readonly ts: string | null;
  readonly len: number;
  readonly sha256: string;
  readonly payload_hex: string | null;
  readonly raw: string;
}

/** What one helper command produced until its terminal event. */
export interface GattCommandOutcome {
  readonly payload: GattPayloadAccounting | null;
  readonly notifications: readonly GattNotificationRow[];
  /** Service tree a `services` terminal event published, else null. */
  readonly services: readonly ParsedGattService[] | null;
  /** Why a window ended, as the helper reported it; null when it did not say. */
  readonly stop_reason: string | null;
  /** Notification rows produced after the retained buffer was full. */
  readonly notifications_omitted: number;
  readonly unparsed_lines: readonly string[];
}

/** Injection seam over the owned child spawn so tests drive the protocol. */
export interface GattChild {
  readonly stdin: { write: (text: string) => void; end: () => void } | null;
  onStdoutLine(listener: (line: string) => void): void;
  onExit(listener: (report: { readonly code: number | null }) => void): void;
  stderrTail(): string;
  kill(signal: "SIGTERM" | "SIGKILL"): void;
}

export type GattProcessSpawner = (request: {
  readonly executable: string;
  readonly arguments: readonly string[];
}) => GattChild;

interface GattSession extends GattSessionFacts {
  readonly services: readonly ParsedGattService[];
  readonly child: GattChild;
  queue: Promise<unknown>;
  exited: { readonly code: number | null } | null;
  readonly exitWaiters: ((report: { readonly code: number | null }) => void)[];
}

export class GattSessionManager {
  readonly #sessions = new Map<string, GattSession>();
  readonly #spawnChild: GattProcessSpawner;
  readonly #maxOutputBytes: number;

  constructor(
    options: {
      readonly spawnChild?: GattProcessSpawner;
      readonly maxOutputBytes?: number;
    } = {},
  ) {
    this.#spawnChild = options.spawnChild ?? gattChildFromNodeSpawn;
    this.#maxOutputBytes =
      options.maxOutputBytes ?? GATT_MAX_SESSION_OUTPUT_BYTES;
  }

  has(sessionId: string): boolean {
    return this.#sessions.has(sessionId);
  }

  factsOf(sessionId: string): GattSessionFacts | null {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) return null;
    return {
      session_id: session.session_id,
      peripheral_id: session.peripheral_id,
      name: session.name,
    };
  }

  /**
   * Spawn the helper for one peripheral and await its connected handshake;
   * macOS authorization denial, a refused connection, a deadline, and a
   * protocol violation are distinct terminal failures, never retried.
   */
  async open(
    helperPath: string,
    input: {
      readonly peripheral_id: string;
      readonly connect_timeout_ms: number;
    },
    signal: AbortSignal | undefined,
    operation = "connect_ble_gatt",
    leadingArguments: readonly string[] = [],
  ): Promise<Result<GattSessionOpened, GattOutcome>> {
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    const child = this.#spawnChild({
      executable: helperPath,
      arguments: [
        ...leadingArguments,
        "--peripheral-id",
        input.peripheral_id,
        "--timeout-ms",
        String(input.connect_timeout_ms),
        "--max-output-bytes",
        String(this.#maxOutputBytes),
      ],
    });
    const abortKill = () => child.kill("SIGKILL");
    const deadlineMs = input.connect_timeout_ms + CHILD_START_GRACE_MS;
    const lines: string[] = [];
    const firstLine = new Promise<string | null>((resolve) => {
      child.onStdoutLine((line) => {
        lines.push(line);
        if (lines.length === 1) resolve(line);
      });
    });
    const exitReport = new Promise<{ readonly code: number | null }>(
      (resolve) => {
        child.onExit((report) => resolve(report));
      },
    );
    let sawAbort = false;
    const aborted = new Promise<null>((resolve) => {
      signal?.addEventListener(
        "abort",
        () => {
          sawAbort = true;
          abortKill();
          resolve(null);
        },
        { once: true },
      );
    });
    const deadline = sleep(deadlineMs).then(() => null);
    const raced = await Promise.race([
      firstLine,
      exitReport.then(() => null),
      aborted,
      deadline,
    ]);
    if (sawAbort) {
      await Promise.race([exitReport, sleep(1_000)]).then(() => undefined);
      return err(
        new AnalysisCancelledError(operation, { cause: signal?.reason }),
      );
    }
    if (raced === null) {
      abortKill();
      await Promise.race([exitReport, sleep(1_000)]).then(() => undefined);
      if (/"event"\s*:\s*"authorization_denied"/u.test(child.stderrTail()))
        return err({
          code: "authorization_denied" as const,
          reason:
            "macOS Bluetooth authorization was denied for the GATT helper, so the session opened nothing; grant access then retry once",
        });
      return err({
        code: "connect_timeout" as const,
        reason: `The helper did not report its handshake within ${String(deadlineMs)} ms`,
      });
    }
    const handshake = parseGattLine(lines[0] ?? "");
    if (handshake.kind === "unrecognized" || handshake.kind !== "connected") {
      abortKill();
      await Promise.race([exitReport, sleep(1_000)]).then(() => undefined);
      if (/"event"\s*:\s*"authorization_denied"/u.test(child.stderrTail()))
        return err({
          code: "authorization_denied" as const,
          reason:
            "macOS Bluetooth authorization was denied for the GATT helper; grant access then retry once",
        });
      if (handshake.kind === "connection_failed")
        return err({
          code:
            handshake.code === "timeout"
              ? "connect_timeout"
              : "connect_refused",
          reason: `The helper refused the connection: ${handshake.message ?? "unspecified reason"}`,
          exit_code: null,
        });
      if (handshake.kind === "error")
        return err({
          code: "connect_refused" as const,
          reason: `The helper refused the handshake: ${handshake.message ?? "unspecified reason"}`,
          exit_code: null,
        });
      return err({
        code: "protocol_violation" as const,
        reason: `The helper's first stdout line was ${handshake.kind}, not connected: ${lines[0] ?? ""}`,
      });
    }
    const services = parseGattServiceTree(handshake);
    if (!services.ok) {
      abortKill();
      return err({
        code: "protocol_violation" as const,
        reason: services.error,
      });
    }
    const sessionId = randomUUID();
    const waiters: ((report: { readonly code: number | null }) => void)[] = [];
    const session: GattSession = {
      session_id: sessionId,
      peripheral_id: input.peripheral_id,
      name: extractConnectedName(handshake.raw),
      services: services.value,
      child,
      queue: Promise.resolve(),
      exited: null,
      exitWaiters: waiters,
    };
    child.onExit((report) => {
      session.exited = report;
      for (const waiter of waiters.splice(0)) waiter(report);
    });
    this.#sessions.set(sessionId, session);
    return ok({
      session_id: sessionId,
      peripheral_id: session.peripheral_id,
      name: session.name,
      services: session.services,
    });
  }

  /**
   * Deliver one protocol command to the session's helper and collect lines
   * until the operation's terminal event. One command is in flight per
   * session; concurrent callers queue and cancellation can kill the helper,
   * which closes the session.
   */
  command(
    sessionId: string,
    operation: string,
    request: Record<string, unknown>,
    limits: {
      readonly deadlineMs: number;
      readonly signal: AbortSignal | undefined;
      readonly includePayloadHex: boolean;
      readonly collectNotifications: boolean;
      readonly maxNotifications?: number;
    },
  ): Promise<Result<GattCommandOutcome, GattOutcome>> {
    const session = this.#requireSession(sessionId, operation);
    const queued = session.queue.then(
      () => this.#runCommand(operation, session, request, limits),
      () => this.#runCommand(operation, session, request, limits),
    );
    session.queue = queued.then(
      () => undefined,
      () => undefined,
    );
    return queued;
  }

  #runCommand = async (
    operation: string,
    session: GattSession,
    request: Record<string, unknown>,
    limits: {
      readonly deadlineMs: number;
      readonly signal: AbortSignal | undefined;
      readonly includePayloadHex: boolean;
      readonly collectNotifications: boolean;
      readonly maxNotifications?: number;
    },
  ): Promise<Result<GattCommandOutcome, GattOutcome>> => {
    if (session.exited !== null)
      return err({
        code: "peer_disconnected" as const,
        reason: `The helper exited before the command (exit ${String(session.exited.code)}); open a new session with connect_ble_gatt`,
      });
    if (limits.signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: limits.signal.reason }),
      );
    const id = randomUUID();
    const notifications: GattNotificationRow[] = [];
    const maxNotifications =
      limits.maxNotifications ?? Number.POSITIVE_INFINITY;
    let notificationsOmitted = 0;
    const unparsedLines: string[] = [];
    return await new Promise((resolve) => {
      let terminalDeadline: NodeJS.Timeout | null = setTimeout(() => {
        terminalDeadline = null;
        session.child.kill("SIGKILL");
        session.exited = { code: null };
        resolve(
          err(
            new AnalysisResourceConstraintError(
              operation,
              "transport" as const,
              `The helper did not report a terminal event within ${String(limits.deadlineMs)} ms; the session process was stopped`,
              { deadline_ms: limits.deadlineMs },
              { retryable: false },
            ),
          ),
        );
      }, limits.deadlineMs);
      session.exitWaiters.push((report) => {
        if (terminalDeadline !== null) {
          clearTimeout(terminalDeadline);
          terminalDeadline = null;
        } else {
          // The deadline already stopped the process; its exit is settled.
          return;
        }
        resolve(
          err({
            code: "peer_disconnected" as const,
            reason: `The helper exited during ${operation} (exit ${String(report.code)})`,
          }),
        );
      });
      const onAbort = () => {
        if (terminalDeadline !== null) {
          clearTimeout(terminalDeadline);
          terminalDeadline = null;
        }
        session.child.kill("SIGKILL");
        session.exited = session.exited ?? { code: null };
        resolve(
          err(
            new AnalysisCancelledError(operation, {
              cause: limits.signal?.reason,
            }),
          ),
        );
      };
      limits.signal?.addEventListener("abort", onAbort, { once: true });
      const finish = (outcome: Result<GattCommandOutcome, GattOutcome>) => {
        if (terminalDeadline !== null) {
          clearTimeout(terminalDeadline);
          terminalDeadline = null;
        } else {
          return;
        }
        limits.signal?.removeEventListener("abort", onAbort);
        resolve(outcome);
      };
      session.child.onStdoutLine((text) => {
        if (terminalDeadline === null) return;
        const line = parseGattLine(text);
        if (line.kind === "unrecognized") {
          unparsedLines.push(text);
          return;
        }
        if (line.id !== null && line.id !== id) {
          unparsedLines.push(text);
          return;
        }
        if (line.kind === "notification") {
          if (!limits.collectNotifications) return;
          if (notifications.length >= maxNotifications) {
            notificationsOmitted += 1;
            return;
          }
          const accounting = gattPayloadAccounting(
            line.payload_hex,
            limits.includePayloadHex,
          );
          if (accounting === null) {
            unparsedLines.push(text);
            return;
          }
          notifications.push({
            ts: line.ts,
            ...accounting,
            raw: gattLineWithoutPayload(text),
          });
          return;
        }
        if (line.kind === "error") {
          finish(
            err({
              code: "command_refused" as const,
              reason: `The helper refused the ${operation} command: ${line.message ?? "unspecified reason"}`,
            }),
          );
          return;
        }
        if (isTerminalEvent(line.kind)) {
          const payload = gattPayloadAccounting(
            line.payload_hex,
            limits.includePayloadHex,
          );
          const services =
            line.kind === "services"
              ? parseGattServiceTree(line)
              : ok<readonly ParsedGattService[]>([]);
          if (!services.ok) {
            finish(
              err({
                code: "protocol_violation" as const,
                reason: services.error,
              }),
            );
            return;
          }
          finish(
            ok({
              payload,
              notifications,
              services: line.kind === "services" ? services.value : null,
              stop_reason: line.stopReason,
              notifications_omitted: notificationsOmitted,
              unparsed_lines: unparsedLines,
            }),
          );
        }
      });
      session.child.stdin?.write(JSON.stringify({ id, ...request }) + "\n");
    });
  };

  /**
   * Disconnect cleanly: deliver the disconnect command, await the helper's
   * own exit within the grace window, then escalate SIGTERM and finally
   * SIGKILL once each. The session leaves this manager even when the
   * escalation is needed; cleanup uncertainty stays in the returned detail.
   */
  async close(
    sessionId: string,
    signal: AbortSignal | undefined,
  ): Promise<
    Result<
      GattSessionFacts & { clean: boolean; detail: string | null },
      AnalysisError
    >
  > {
    const session = this.#requireSession(sessionId, "close_ble_gatt");
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError("close_ble_gatt", { cause: signal.reason }),
      );
    if (session.exited === null) {
      try {
        const disconnect = await this.#runCommand(
          "close_ble_gatt",
          session,
          { op: "disconnect" },
          {
            deadlineMs: GATT_CLOSE_GRACE_MS,
            signal: undefined,
            includePayloadHex: false,
            collectNotifications: false,
          },
        );
        if (!disconnect.ok) {
          return ok(await this.#escalateStop(session));
        }
      } catch {
        return ok(await this.#escalateStop(session));
      }
    }
    const awaited = await awaitExitWithDeadline(session, GATT_CLOSE_GRACE_MS);
    if (awaited !== null) {
      this.#sessions.delete(sessionId);
      return ok({
        session_id: session.session_id,
        peripheral_id: session.peripheral_id,
        name: session.name,
        clean: true,
        detail: null,
      });
    }
    return ok(await this.#escalateStop(session));
  }

  #escalateStop = async (
    session: GattSession,
  ): Promise<GattSessionFacts & { clean: boolean; detail: string | null }> => {
    session.child.kill("SIGTERM");
    const afterTerm = await awaitExitWithDeadline(session, GATT_CLOSE_GRACE_MS);
    if (afterTerm !== null) {
      this.#sessions.delete(session.session_id);
      return {
        session_id: session.session_id,
        peripheral_id: session.peripheral_id,
        name: session.name,
        clean: false,
        detail:
          "The helper did not acknowledge the disconnect command; the session process was stopped with SIGTERM",
      };
    }
    session.child.kill("SIGKILL");
    this.#sessions.delete(session.session_id);
    return {
      session_id: session.session_id,
      peripheral_id: session.peripheral_id,
      name: session.name,
      clean: false,
      detail:
        "The helper needed SIGKILL; whether the peer observed a clean disconnect is unknown",
    };
  };

  async closeAll(): Promise<void> {
    for (const sessionId of [...this.#sessions.keys()]) {
      await this.close(sessionId, undefined);
    }
  }

  #requireSession = (sessionId: string, operation: string): GattSession => {
    const session = this.#sessions.get(sessionId);
    if (session === undefined)
      throw new GattSessionUnknownError(sessionId, operation);
    return session;
  };
}

export class GattSessionUnknownError extends Error {
  constructor(sessionId: string, operation: string) {
    super(`No open GATT session ${sessionId} for ${operation}`);
    this.name = "GattSessionUnknownError";
  }
}

export const isGattSessionUnknown = (cause: unknown): boolean =>
  cause instanceof GattSessionUnknownError;

const awaitExitWithDeadline = async (
  session: {
    readonly exited: { readonly code: number | null } | null;
    readonly exitWaiters: ((report: {
      readonly code: number | null;
    }) => void)[];
  },
  deadlineMs: number,
): Promise<{ readonly code: number | null } | null> => {
  return await new Promise((resolve) => {
    if (session.exited !== null) {
      resolve(session.exited);
      return;
    }
    let settled = false;
    const waiter = (report: { readonly code: number | null }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(report);
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const index = session.exitWaiters.indexOf(waiter);
      if (index >= 0) session.exitWaiters.splice(index, 1);
      resolve(null);
    }, deadlineMs);
    session.exitWaiters.push(waiter);
  });
};

const extractConnectedName = (rawLine: string): string | null => {
  try {
    const record = JSON.parse(rawLine) as Record<string, unknown>;
    return typeof record.name === "string" ? record.name : null;
  } catch {
    return null;
  }
};

const isTerminalEvent = (
  kind:
    | "connected"
    | "connection_failed"
    | "error"
    | "value"
    | "written"
    | "notification"
    | "window_end"
    | "disconnected"
    | "services",
): boolean =>
  kind === "value" ||
  kind === "written" ||
  kind === "window_end" ||
  kind === "disconnected" ||
  kind === "services";

const sleep = (ms: number): Promise<null> =>
  new Promise((resolve) => setTimeout(() => resolve(null), ms));

/** Adapter over node:child_process; kept beside the manager for ownership. */
export const gattChildFromNodeSpawn: GattProcessSpawner = (request) => {
  const child = spawn(request.executable, request.arguments, {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let buffer = "";
  let stderrTailData = "";
  const stdoutListeners: ((line: string) => void)[] = [];
  child.stdout?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    buffer += chunk;
    for (;;) {
      const newline = buffer.indexOf("\n");
      if (newline < 0) break;
      const line = buffer.slice(0, newline).replace(/\r$/u, "");
      buffer = buffer.slice(newline + 1);
      if (line.trim().length === 0) continue;
      for (const listener of stdoutListeners) listener(line);
    }
  });
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    stderrTailData = (stderrTailData + chunk).slice(-4_000);
  });
  return {
    stdin:
      child.stdin === null
        ? null
        : {
            write: (text: string) => {
              child.stdin?.write(text);
            },
            end: () => {
              child.stdin?.end();
            },
          },
    onStdoutLine: (listener) => {
      stdoutListeners.push(listener);
    },
    onExit: (listener) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        listener({ code: child.exitCode });
        return;
      }
      child.once("exit", (code: number | null) => listener({ code }));
      child.once("error", () => listener({ code: null }));
    },
    stderrTail: () => stderrTailData,
    kill: (signal) => {
      child.kill(signal as "SIGTERM" | "SIGKILL");
    },
  };
};
