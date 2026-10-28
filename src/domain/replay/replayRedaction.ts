import {
  replayBodyByteLength,
  type ReplayHeader,
  type ReplayRequest,
} from "./replayRequest.js";

/**
 * Canonical credential headers whose values never enter an echoed form.
 *
 * This is a declared closed vocabulary, not a guess about a header's meaning:
 * AGENTS.md forbids inferring secrecy from names or text patterns, so the list
 * is owned here, reviewed as data, and never widened by a caller's label. The
 * exact wire bytes sent to the server are unaffected — redaction applies to
 * what REA reports, never to what the target receives.
 */
export const REPLAY_CREDENTIAL_HEADERS: readonly string[] = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "www-authenticate",
  "proxy-authenticate",
  "x-api-key",
  "x-auth-token",
  "x-access-token",
  "x-session-token",
  "x-csrf-token",
  "x-xsrf-token",
  "x-amz-security-token",
  "x-goog-api-key",
];

const credentialNames: ReadonlySet<string> = new Set(REPLAY_CREDENTIAL_HEADERS);

/** Whether one header name belongs to the declared credential vocabulary. */
export const isReplayCredentialHeader = (name: string): boolean =>
  credentialNames.has(name.trim().toLowerCase());

/**
 * Names of the credential headers a request carries, deduplicated
 * case-insensitively while preserving the observed spelling.
 */
export const replayCredentialHeaderNames = (
  headers: readonly ReplayHeader[],
): readonly string[] => {
  const seen = new Set<string>();
  const names: string[] = [];
  for (const header of headers) {
    const key = header.name.trim().toLowerCase();
    if (!credentialNames.has(key) || seen.has(key)) continue;
    seen.add(key);
    names.push(header.name);
  }
  return names;
};

/** Header names in first-observed order, deduplicated case-insensitively. */
export const replayHeaderNames = (
  headers: readonly ReplayHeader[],
): readonly string[] => {
  const seen = new Set<string>();
  const names: string[] = [];
  for (const header of headers) {
    const key = header.name.trim().toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    names.push(header.name);
  }
  return names;
};

/**
 * Remove `userinfo` from an echoed URL. The send boundary refuses to replay
 * such a URL, so this only exists to keep a refused or redirected location from
 * becoming a credential echo.
 */
export const redactedReplayUrl = (value: string, base?: string): string => {
  try {
    const parsed = base === undefined ? new URL(value) : new URL(value, base);
    if (parsed.username === "" && parsed.password === "") return parsed.href;
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch (cause: unknown) {
    void cause;
    return value;
  }
};

/**
 * Echo a redirect `Location` without letting a malformed value smuggle
 * `userinfo` into the report. Unparsable values keep their text with any
 * `//userinfo@` authority prefix reduced to `//`.
 */
export const redactedReplayLocation = (value: string, base: string): string => {
  if (URL.canParse(value, base)) return redactedReplayUrl(value, base);
  return value.replace(/\/\/[^/?#]*@/u, "//").slice(0, 512);
};

/** Value-free echo of the request REA dispatched (or refused to dispatch). */ export interface ReplayRequestEcho {
  readonly method: string;
  readonly url: string;
  readonly origin: string;
  readonly header_names: readonly string[];
  readonly credential_header_names: readonly string[];
  readonly body_bytes: number;
  readonly body_present: boolean;
}

/** Project one request into its echoed form: names and sizes only. */
export const replayRequestEcho = (
  request: ReplayRequest,
): ReplayRequestEcho => {
  const url = redactedReplayUrl(request.url);
  return {
    method: request.method,
    url,
    origin: new URL(url).origin,
    header_names: replayHeaderNames(request.headers),
    credential_header_names: replayCredentialHeaderNames(request.headers),
    body_bytes: replayBodyByteLength(request.body),
    body_present: request.body.kind !== "none",
  };
};
