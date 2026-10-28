import type { AnalysisInputIssue } from "../analysisErrorCore.js";
import { isCanonicalBase64 } from "../stringPatterns.js";
import { err, ok, type Result } from "../result.js";
import { REPLAY_LIMITS } from "./replayLimits.js";

/** One request header pair; duplicates of a name are preserved in order. */
export interface ReplayHeader {
  readonly name: string;
  readonly value: string;
}

/** A request body as the caller selected it; bodies never enter Evidence. */
export type ReplayBody =
  | { readonly kind: "none" }
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "base64"; readonly base64: string };

/** One replayable request, before the send boundary fixes its framing. */
export interface ReplayRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: readonly ReplayHeader[];
  readonly body: ReplayBody;
}

/** Structured mutation of a selected request. */
export interface ReplayMutation {
  readonly method?: string;
  readonly url?: string;
  readonly setHeaders?: readonly ReplayHeader[];
  readonly removeHeaders?: readonly string[];
  readonly body?: ReplayBody;
}

/** Exact bytes one hop hands to the transport. */
export interface ReplayWireRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: readonly ReplayHeader[];
  readonly body: Uint8Array | undefined;
}

const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const METHOD_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;

/**
 * Framing headers the send boundary owns: a captured `Content-Length` or
 * `Transfer-Encoding` describes the capture's body, never a mutated one.
 */
const OWNED_FRAMING_HEADERS: ReadonlySet<string> = new Set([
  "content-length",
  "transfer-encoding",
]);

const issue = (
  path: readonly (string | number)[],
  reason: AnalysisInputIssue["reason"],
  message?: string,
): AnalysisInputIssue => ({
  path,
  reason,
  ...(message === undefined ? {} : { message }),
});

const utf8Length = (value: string): number => Buffer.byteLength(value, "utf8");

/** CR, LF, and NUL cannot appear in one header line. */
const hasLineBreakOrNul = (value: string): boolean => {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code === 0 || code === 10 || code === 13) return true;
  }
  return false;
};

/** Validate one header name and value without inspecting their meaning. */
const headerIssues = (
  header: ReplayHeader,
  path: readonly (string | number)[],
): readonly AnalysisInputIssue[] => {
  const issues: AnalysisInputIssue[] = [];
  if (!HEADER_NAME.test(header.name))
    issues.push(
      issue(
        [...path, "name"],
        "invalid_format",
        "An HTTP header name is a token: no spaces, colons, or control characters.",
      ),
    );
  if (hasLineBreakOrNul(header.value))
    issues.push(
      issue(
        [...path, "value"],
        "invalid_format",
        "An HTTP header value cannot contain CR, LF, or NUL.",
      ),
    );
  else if (
    utf8Length(header.name) + utf8Length(header.value) >
    REPLAY_LIMITS.maxHeaderBytes
  )
    issues.push(
      issue(
        [...path, "value"],
        "out_of_range",
        `One header name and value are limited to ${String(REPLAY_LIMITS.maxHeaderBytes)} UTF-8 bytes.`,
      ),
    );
  return issues;
};

/** Byte length a body selection sends, without materializing it. */
export const replayBodyByteLength = (body: ReplayBody): number =>
  body.kind === "none"
    ? 0
    : body.kind === "text"
      ? utf8Length(body.text)
      : Math.floor((body.base64.length * 3) / 4);

const bodyIssues = (
  body: ReplayBody,
  path: readonly string[],
): readonly AnalysisInputIssue[] => {
  if (body.kind === "base64" && !isCanonicalBase64(body.base64))
    return [
      issue(
        [...path, "base64"],
        "invalid_format",
        "Request body bytes must be canonical base64.",
      ),
    ];
  const bytes = replayBodyByteLength(body);
  return bytes > REPLAY_LIMITS.maxRequestBodyBytes
    ? [
        issue(
          [...path, body.kind === "base64" ? "base64" : "text"],
          "out_of_range",
          `One request body is limited to ${String(REPLAY_LIMITS.maxRequestBodyBytes)} bytes.`,
        ),
      ]
    : [];
};

/** Resolve a body selection to the exact bytes the transport writes. */
export const replayBodyBytes = (body: ReplayBody): Uint8Array | undefined =>
  body.kind === "none"
    ? undefined
    : Buffer.from(
        body.kind === "text" ? body.text : body.base64,
        body.kind === "text" ? "utf8" : "base64",
      );

const normalizedMethod = (
  value: string,
  path: readonly string[],
): Result<string, readonly AnalysisInputIssue[]> => {
  const method = value.trim().toUpperCase();
  return method.length === 0 || method.length > 32 || !METHOD_TOKEN.test(method)
    ? err([
        issue(
          path,
          "invalid_format",
          "An HTTP method is a token of at most 32 characters.",
        ),
      ])
    : ok(method);
};

const urlIssues = (
  value: string,
  path: readonly string[],
): readonly AnalysisInputIssue[] => {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause: unknown) {
    void cause;
    return [issue(path, "invalid_format", "The request URL is not absolute.")];
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:")
    return [
      issue(path, "invalid_value", "Only http and https URLs are replayed."),
    ];
  if (parsed.username !== "" || parsed.password !== "")
    return [
      issue(
        path,
        "invalid_value",
        "A request URL cannot carry userinfo; supply credentials as headers.",
      ),
    ];
  return [];
};

/**
 * Apply one structured mutation to a selected request.
 *
 * Order is fixed: replace the method and URL, remove the named headers, then
 * set the supplied headers (a set replaces every earlier pair of that name),
 * then replace the body. Every field is optional, so an empty mutation is the
 * verbatim request.
 */
export const composeReplayRequest = (
  base: ReplayRequest,
  mutation: ReplayMutation,
): Result<ReplayRequest, readonly AnalysisInputIssue[]> => {
  const issues: AnalysisInputIssue[] = [];
  let method = base.method;
  if (mutation.method !== undefined) {
    const normalized = normalizedMethod(mutation.method, ["method"]);
    if (normalized.ok) method = normalized.value;
    else issues.push(...normalized.error);
  }
  const url = mutation.url ?? base.url;
  issues.push(...urlIssues(url, ["url"]));

  const removed = new Set(
    (mutation.removeHeaders ?? []).map((name) => name.toLowerCase()),
  );
  const headers = base.headers.filter(
    (header) => !removed.has(header.name.toLowerCase()),
  );
  for (const [index, header] of (mutation.setHeaders ?? []).entries()) {
    issues.push(...headerIssues(header, ["set_headers", index]));
    const name = header.name.toLowerCase();
    const existing = headers.findIndex(
      (candidate) => candidate.name.toLowerCase() === name,
    );
    if (existing === -1) headers.push(header);
    else headers[existing] = header;
  }
  const body = mutation.body ?? base.body;
  issues.push(...bodyIssues(body, ["body"]));
  if (method === "HEAD" && body.kind !== "none")
    issues.push(
      issue(["body"], "invalid_value", "A HEAD request cannot carry a body."),
    );
  if (issues.length > 0) return err(issues);
  return ok({ method, url, headers, body });
};

/**
 * Fix the wire framing for one hop.
 *
 * The boundary owns `Content-Length` and `Transfer-Encoding` because a
 * captured framing header describes the capture, not this body. Everything
 * else, including a caller-provided `Host`, travels unchanged: a replayed
 * request is evidence about a server, so silently rewriting its headers would
 * make the observation describe REA's choices instead.
 */
export const composeReplayWireRequest = (
  request: ReplayRequest,
): Result<ReplayWireRequest, readonly AnalysisInputIssue[]> => {
  const method = normalizedMethod(request.method, ["method"]);
  if (!method.ok) return err(method.error);
  const issues: AnalysisInputIssue[] = [...urlIssues(request.url, ["url"])];
  const headers: ReplayHeader[] = [];
  let headerBytes = 0;
  for (const [index, header] of request.headers.entries()) {
    issues.push(...headerIssues(header, ["headers", index]));
    if (OWNED_FRAMING_HEADERS.has(header.name.toLowerCase())) continue;
    headerBytes += utf8Length(header.name) + utf8Length(header.value);
    headers.push(header);
  }
  if (headers.length > REPLAY_LIMITS.maxHeaderCount)
    issues.push(
      issue(
        ["headers"],
        "out_of_range",
        `One request carries at most ${String(REPLAY_LIMITS.maxHeaderCount)} headers.`,
      ),
    );
  if (
    !headers.some((header) => header.name.toLowerCase() === "host") &&
    issues.length === 0
  ) {
    const host = { name: "host", value: new URL(request.url).host };
    headerBytes += host.name.length + host.value.length;
    headers.push(host);
  }
  const body = replayBodyBytes(request.body);
  if (body !== undefined) {
    const frame = { name: "content-length", value: String(body.byteLength) };
    headerBytes += frame.name.length + frame.value.length;
    headers.push(frame);
  }
  if (headerBytes > REPLAY_LIMITS.maxHeaderCount * REPLAY_LIMITS.maxHeaderBytes)
    issues.push(
      issue(
        ["headers"],
        "out_of_range",
        "The composed header block is too large.",
      ),
    );
  if (issues.length > 0) return err(issues);
  return ok({ method: method.value, url: request.url, headers, body });
};
