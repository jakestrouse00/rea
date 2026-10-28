import { createHash } from "node:crypto";
import { open, stat, unlink } from "node:fs/promises";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisTimeoutError,
  type AnalysisInputIssue,
} from "../domain/analysisErrorCore.js";
import {
  isFetchRedirectStatus,
  redirectMethod,
} from "../domain/fetchRedirectStatus.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  REPLAY_LIMITS,
  replayContentTypeClass,
  replaySizeClass,
  replayStatusClass,
  type ReplayContentTypeClass,
  type ReplaySizeClass,
  type ReplayStatusClass,
} from "../domain/replay/replayLimits.js";
import type { ReplayDumpTarget } from "../domain/replay/replayObservation.js";
import {
  REPLAY_ALLOWED_ORIGINS_REMEDIATION,
  REPLAY_PROVIDER_ID,
  ReplayConfigurationFailure,
  replayUrlApproval,
} from "../domain/replay/replayOrigins.js";
import {
  composeReplayWireRequest,
  type ReplayHeader,
  type ReplayRequest,
} from "../domain/replay/replayRequest.js";
import {
  isReplayCredentialHeader,
  redactedReplayLocation,
  redactedReplayUrl,
  replayRequestEcho,
  type ReplayRequestEcho,
} from "../domain/replay/replayRedaction.js";
import { err, ok, type Result } from "../domain/result.js";
import type {
  ReplayTransport,
  ReplayTransportResponse,
} from "./ReplayTransport.js";

/** One composed send, already authorized for its declared origins. */
export interface ReplaySendInput {
  readonly operation: string;
  readonly request: ReplayRequest;
  /** Approved origins for this session: every hop must stay inside them. */
  readonly allowedOrigins: readonly string[];
  readonly timeoutMs: number;
  readonly followRedirects: boolean;
  readonly signal: AbortSignal | undefined;
  readonly dump: ReplayDumpTarget | undefined;
}

export interface ReplayDumpFacts {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
  readonly truncated: boolean;
}

export interface ReplayResponseFacts {
  readonly status: number;
  readonly status_class: ReplayStatusClass;
  readonly content_type_class: ReplayContentTypeClass;
  readonly header_names: readonly string[];
  readonly size_class: ReplaySizeClass;
  readonly bytes_observed: number;
  readonly body_truncated: boolean;
  readonly dump: ReplayDumpFacts | null;
}

export interface ReplayRedirectStep {
  readonly step: number;
  readonly method: string;
  readonly url: string;
  readonly origin: string;
  readonly status: number;
  readonly status_class: ReplayStatusClass;
  readonly location: {
    readonly url: string;
    readonly origin: string | null;
    readonly approved: boolean;
  } | null;
}

export type ReplayOutcome =
  | "response"
  | "no_response"
  | "redirect_blocked"
  | "redirect_limit";

export type ReplayTransportFailureKind =
  | "connection"
  | "dns"
  | "tls"
  | "reset"
  | "protocol"
  | "aborted"
  | "other";

export interface ReplayTransportFailure {
  readonly kind: ReplayTransportFailureKind;
  readonly message: string;
}

/** Everything one dispatch observed, before session identity is attached. */
export interface ReplayExchange {
  readonly request: ReplayRequestEcho;
  readonly redirectChain: readonly ReplayRedirectStep[];
  readonly response: ReplayResponseFacts | null;
  readonly outcome: ReplayOutcome;
  readonly failure: ReplayTransportFailure | null;
  readonly elapsedMs: number;
}

interface RetainedBody {
  readonly bytes: number;
  readonly truncated: boolean;
  readonly digest: string | null;
}

/**
 * The one owner of dispatch for the active request plane.
 *
 * Every consumer that re-sends captured bytes — `http_replay_send` today,
 * `browser_fetch` and `proxy_replay_send` later — composes a `ReplayRequest`,
 * hands it here, and projects the returned `ReplayExchange`. Request
 * composition, per-hop origin gating, the no-retry policy, bounded body
 * retention, and the redaction of echoed forms stay in this module so a later
 * lane cannot quietly grow a second, weaker copy of them.
 */
export class ReplaySendCore {
  constructor(
    private readonly transport: ReplayTransport,
    private readonly now: () => number = () => performance.now(),
  ) {}

  async send(
    input: ReplaySendInput,
  ): Promise<Result<ReplayExchange, AnalysisError>> {
    const startedAt = this.now();
    const callerAborted = (): boolean => input.signal?.aborted === true;
    const stopReason = (): AnalysisError =>
      callerAborted()
        ? new AnalysisCancelledError(input.operation, {
            cause: input.signal?.reason,
          })
        : this.timeout(input.operation, input.timeoutMs);
    if (callerAborted()) return err(stopReason());
    if (input.allowedOrigins.length === 0)
      return err(this.refusal(input.operation, undefined, "not_configured"));
    // Discover an occupied dump path before the one dispatch is spent; the
    // exclusive create below still decides the race authoritatively.
    if (input.dump !== undefined && !input.dump.overwrite) {
      const occupied = await pathExists(input.dump.path);
      if (occupied === true)
        return err(
          this.inputError(
            input.operation,
            [
              {
                path: ["dump_path"],
                reason: "invalid_value",
                message:
                  "The dump path already exists; pass overwrite: true to replace it.",
              },
            ],
            "The dump path already exists; pass overwrite: true to replace it.",
          ),
        );
    }

    const deadline = new AbortController();
    const timer = setTimeout(() => {
      deadline.abort(new ReplayDeadlineElapsed(input.timeoutMs));
    }, input.timeoutMs);
    const signal =
      input.signal === undefined
        ? deadline.signal
        : AbortSignal.any([input.signal, deadline.signal]);
    const chain: ReplayRedirectStep[] = [];
    let current: ReplayRequest = input.request;
    let terminal: ReplayTransportResponse | undefined;
    let outcome: ReplayOutcome = "response";
    let failure: ReplayTransportFailure | null = null;
    try {
      for (;;) {
        const approval = replayUrlApproval(current.url, input.allowedOrigins);
        if (!approval.approved) {
          if (chain.length === 0)
            return err(
              this.refusal(
                input.operation,
                current.url,
                "origin_not_allowlisted",
                approval.reason,
              ),
            );
          return ok(
            this.exchange(
              input.request,
              chain,
              null,
              "redirect_blocked",
              null,
              startedAt,
            ),
          );
        }
        const wire = composeReplayWireRequest(current);
        if (!wire.ok) return err(this.inputError(input.operation, wire.error));
        const step = chain.length;
        let response: ReplayTransportResponse;
        const dispatch = this.transport.send({ ...wire.value, signal });
        try {
          response = await untilAborted(dispatch, signal);
        } catch (cause: unknown) {
          if (signal.aborted) {
            // The transport may still resolve after the deadline; release the
            // body it eventually produced instead of leaking the stream.
            void dispatch.then(
              (late) => late.cancel(),
              () => undefined,
            );
            return err(stopReason());
          }
          failure = replayTransportFailure(cause);
          outcome = "no_response";
          break;
        }
        if (signal.aborted) {
          await response.cancel().catch(() => undefined);
          return err(stopReason());
        }
        const location = headerValue(response.headers, "location");
        const nextUrl =
          isFetchRedirectStatus(response.status) &&
          location !== null &&
          input.followRedirects
            ? resolveLocation(location, current.url)
            : null;
        const nextApproval =
          nextUrl === null
            ? undefined
            : replayUrlApproval(nextUrl, input.allowedOrigins);
        const nextApproved = nextApproval?.approved === true;
        chain.push({
          step,
          method: current.method,
          url: redactedReplayUrl(current.url),
          origin: approval.origin,
          status: response.status,
          status_class: replayStatusClass(response.status),
          location:
            nextUrl === null
              ? null
              : {
                  url: redactedReplayLocation(nextUrl, current.url),
                  origin: nextApproved ? nextApproval.origin : null,
                  approved: nextApproved,
                },
        });
        if (nextUrl === null) {
          terminal = response;
          break;
        }
        if (!nextApproved || step >= REPLAY_LIMITS.maxRedirects) {
          await response.cancel().catch(() => undefined);
          outcome = nextApproved ? "redirect_limit" : "redirect_blocked";
          break;
        }
        await response.cancel().catch(() => undefined);
        if (signal.aborted) return err(stopReason());
        current = redirectRequest(current, response.status, nextUrl);
      }
      if (outcome !== "response" || terminal === undefined)
        return ok(
          this.exchange(
            input.request,
            chain,
            null,
            outcome,
            failure,
            startedAt,
          ),
        );
      const content = headerValue(terminal.headers, "content-type");
      const retained = await this.retainBody(
        terminal,
        signal,
        stopReason,
        input.operation,
        input.dump,
      );
      if (!retained.ok) return retained;
      return ok(
        this.exchange(
          input.request,
          chain,
          {
            status: terminal.status,
            status_class: replayStatusClass(terminal.status),
            content_type_class: replayContentTypeClass(content ?? undefined),
            header_names: headerNames(terminal.headers),
            size_class: replaySizeClass(retained.value.bytes),
            bytes_observed: retained.value.bytes,
            body_truncated: retained.value.truncated,
            dump:
              retained.value.digest === null || input.dump === undefined
                ? null
                : {
                    path: input.dump.path,
                    bytes: retained.value.bytes,
                    sha256: retained.value.digest,
                    truncated: retained.value.truncated,
                  },
          },
          "response",
          null,
          startedAt,
        ),
      );
    } finally {
      clearTimeout(timer);
      // Release listeners the combined signal attached to the caller's signal.
      deadline.abort(new ReplayDeadlineElapsed(input.timeoutMs));
    }
  }

  private exchange(
    request: ReplayRequest,
    chain: readonly ReplayRedirectStep[],
    response: ReplayResponseFacts | null,
    outcome: ReplayOutcome,
    failure: ReplayTransportFailure | null,
    startedAt: number,
  ): ReplayExchange {
    return {
      request: replayRequestEcho(request),
      redirectChain: [...chain],
      response,
      outcome,
      failure,
      elapsedMs: Math.max(0, Math.round(this.now() - startedAt)),
    };
  }

  /**
   * Count, or optionally write, the final response body. Without a dump path
   * the stream is abandoned once the retained-budget is crossed; with a path
   * the partial file is removed if the send is cancelled or the write fails,
   * because a truncated artefact must not look like a complete capture.
   */
  private async retainBody(
    response: ReplayTransportResponse,
    signal: AbortSignal,
    stopReason: () => AnalysisError,
    operation: string,
    dump: ReplayDumpTarget | undefined,
  ): Promise<Result<RetainedBody, AnalysisError>> {
    if (dump === undefined) return this.countBody(response, signal, stopReason);
    return this.writeBody(response, signal, stopReason, operation, dump);
  }

  private async countBody(
    response: ReplayTransportResponse,
    signal: AbortSignal,
    stopReason: () => AnalysisError,
  ): Promise<Result<RetainedBody, AnalysisError>> {
    let bytes = 0;
    try {
      for await (const chunk of response.body) {
        if (signal.aborted) {
          await response.cancel().catch(() => undefined);
          return err(stopReason());
        }
        if (bytes + chunk.byteLength > REPLAY_LIMITS.maxRetainedBodyBytes) {
          await response.cancel().catch(() => undefined);
          return ok({
            bytes: REPLAY_LIMITS.maxRetainedBodyBytes,
            truncated: true,
            digest: null,
          });
        }
        bytes += chunk.byteLength;
      }
    } catch (cause: unknown) {
      await response.cancel().catch(() => undefined);
      if (signal.aborted) return err(stopReason());
      void cause;
      return ok({ bytes, truncated: true, digest: null });
    }
    return ok({ bytes, truncated: false, digest: null });
  }

  private async writeBody(
    response: ReplayTransportResponse,
    signal: AbortSignal,
    stopReason: () => AnalysisError,
    operation: string,
    dump: ReplayDumpTarget,
  ): Promise<Result<RetainedBody, AnalysisError>> {
    let handle: Awaited<ReturnType<typeof open>>;
    try {
      handle = await open(dump.path, dump.overwrite ? "w" : "wx", 0o600);
    } catch (cause: unknown) {
      if (systemCode(cause) === "EEXIST")
        return err(
          this.inputError(operation, [
            {
              path: ["dump_path"],
              reason: "invalid_value",
              message:
                "The dump path already exists; pass overwrite: true to replace it.",
            },
          ]),
        );
      return err(
        new AnalysisOutputError(
          operation,
          "the caller-selected response dump could not be created",
          {
            cause,
            userMessage: `REA could not create the response dump at ${dump.path}. Select a writable absolute path outside an existing file.`,
            diagnostics: { dump_path: dump.path },
          },
        ),
      );
    }
    const hash = createHash("sha256");
    let bytes = 0;
    let truncated = false;
    try {
      await handle.chmod(0o600);
      for await (const chunk of response.body) {
        if (signal.aborted) {
          await response.cancel().catch(() => undefined);
          throw new ReplayBodyAbandoned(stopReason());
        }
        const room = REPLAY_LIMITS.maxDumpBodyBytes - bytes;
        const admitted = chunk.subarray(0, Math.max(0, room));
        if (admitted.byteLength > 0) {
          await handle.write(admitted);
          hash.update(admitted);
          bytes += admitted.byteLength;
        }
        if (admitted.byteLength < chunk.byteLength) {
          truncated = true;
          await response.cancel().catch(() => undefined);
          break;
        }
      }
    } catch (cause: unknown) {
      await response.cancel().catch(() => undefined);
      await handle.close().catch(() => undefined);
      const removed = await unlink(dump.path).then(
        () => true,
        () => false,
      );
      if (cause instanceof ReplayBodyAbandoned) {
        const error = cause.reason;
        if (!removed) error.cleanupIncomplete = true;
        return err(error);
      }
      return err(
        new AnalysisOutputError(
          operation,
          "the response dump could not be written",
          {
            cause,
            userMessage: removed
              ? `The response dump at ${dump.path} was removed after a write failure, so no partial artefact remains.`
              : `The response dump at ${dump.path} may be incomplete and could not be removed; delete it before retrying.`,
            diagnostics: { dump_path: dump.path, removed },
            ...(removed
              ? {}
              : {
                  cleanup: {
                    reason: "the partial response dump could not be removed",
                    resources: ["response-dump"],
                  },
                }),
          },
        ),
      );
    }
    const closed = await handle.close().then(
      () => true,
      () => false,
    );
    if (!closed)
      return err(
        new AnalysisOutputError(
          operation,
          "the response dump could not be closed",
          {
            userMessage: `The response dump at ${dump.path} was written but its descriptor could not be closed.`,
            diagnostics: { dump_path: dump.path, bytes },
            cleanup: {
              reason: "the response dump descriptor did not close",
              resources: ["response-dump"],
            },
          },
        ),
      );
    return ok({ bytes, truncated, digest: hash.digest("hex") });
  }

  private inputError(
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

  private refusal(
    operation: string,
    url: string | undefined,
    code: ReplayConfigurationFailure["code"],
    detail?: string,
  ): AnalysisCapabilityUnavailableError {
    return providerConfigurationRefusal(
      REPLAY_PROVIDER_ID,
      operation,
      new ReplayConfigurationFailure(
        code,
        detail ??
          `The active request plane is disabled for ${url ?? "this request"}`,
        {
          ...(url === undefined ? {} : { request_url: url }),
          remediation: REPLAY_ALLOWED_ORIGINS_REMEDIATION,
        } satisfies Readonly<Record<string, JsonValue>>,
      ),
    );
  }

  private timeout(operation: string, timeoutMs: number): AnalysisTimeoutError {
    return new AnalysisTimeoutError(operation, timeoutMs, {
      userMessage: `The one-shot send exceeded its ${String(timeoutMs)} ms timeout_ms deadline. No retry was attempted.`,
      remediationAction: `Raise timeout_ms up to ${String(REPLAY_LIMITS.maxTimeoutMs)} ms for this send, or select a smaller response. REA never retries a timed-out send; the target may still be processing it.`,
    });
  }
}

/** Why the combined deadline ended; kept distinct from a caller abort. */
class ReplayDeadlineElapsed extends Error {
  constructor(readonly timeoutMs: number) {
    super(`The replay deadline of ${String(timeoutMs)} ms elapsed`);
    this.name = "ReplayDeadlineElapsed";
  }
}

class ReplayBodyAbandoned extends Error {
  constructor(readonly reason: AnalysisError) {
    super("the response body was abandoned before it completed");
    this.name = "ReplayBodyAbandoned";
  }
}

/** Race one dispatch against the combined deadline without retrying it. */
const untilAborted = <Value>(
  promise: Promise<Value>,
  signal: AbortSignal,
): Promise<Value> =>
  new Promise<Value>((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = (): void => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (cause: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(cause);
      },
    );
  });

const pathExists = async (path: string): Promise<boolean | undefined> =>
  stat(path).then(
    () => true,
    (cause: unknown) => (systemCode(cause) === "ENOENT" ? false : undefined),
  );

const systemCode = (cause: unknown): string =>
  typeof cause === "object" && cause !== null && "code" in cause
    ? String((cause as { readonly code?: unknown }).code)
    : "";

const headerValue = (
  headers: readonly ReplayHeader[],
  name: string,
): string | null => {
  const lower = name.toLowerCase();
  const found = headers.find((header) => header.name.toLowerCase() === lower);
  return found === undefined ? null : found.value;
};

const headerNames = (headers: readonly ReplayHeader[]): readonly string[] => {
  const seen = new Set<string>();
  const names: string[] = [];
  for (const header of headers) {
    const key = header.name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    names.push(header.name);
  }
  return names;
};

const resolveLocation = (location: string, base: string): string | null => {
  try {
    return new URL(location, base).href;
  } catch (cause: unknown) {
    void cause;
    return null;
  }
};

const redirectRequest = (
  request: ReplayRequest,
  status: number,
  url: string,
): ReplayRequest => {
  const method = redirectMethod(status, request.method);
  const crossOrigin = new URL(url).origin !== new URL(request.url).origin;
  return {
    method,
    url,
    // A followed redirect never carries the previous origin's credentials to a
    // different approved origin; the caller must declare and replay that hop.
    headers: crossOrigin
      ? request.headers.filter(
          (header) => !isReplayCredentialHeader(header.name),
        )
      : request.headers,
    body:
      redirectMethod(status, request.method) !== request.method
        ? { kind: "none" }
        : request.body,
  };
};

const replayTransportFailure = (cause: unknown): ReplayTransportFailure => {
  const message =
    cause instanceof Error && cause.message.length > 0
      ? cause.message
      : "the transport reported no response";
  return {
    kind: failureKind(systemCode(cause)),
    message: message.slice(0, 200),
  };
};

const failureKind = (code: string): ReplayTransportFailureKind => {
  if (
    code === "ECONNREFUSED" ||
    code === "EHOSTUNREACH" ||
    code === "ENETUNREACH"
  )
    return "connection";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "dns";
  if (
    code.startsWith("ERR_TLS") ||
    code.startsWith("ERR_SSL") ||
    code === "EPROTO" ||
    code === "CERT_HAS_EXPIRED" ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT"
  )
    return "tls";
  if (code === "ECONNRESET" || code === "EPIPE") return "reset";
  if (code === "ABORT_ERR") return "aborted";
  if (
    code === "HPE_INVALID_CONSTANT" ||
    code === "ERR_HTTP_INVALID_STATUS_CODE"
  )
    return "protocol";
  return "other";
};
