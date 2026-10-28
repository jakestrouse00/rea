/** Fixed request-plane budgets shared by the replay tools and their transport. */
export const REPLAY_LIMITS = {
  /** Deadline applied when a caller omits timeout_ms. */
  defaultTimeoutMs: 10_000,
  /** Longest admitted caller-selected deadline for one send. */
  maxTimeoutMs: 60_000,
  /** Dispatched hops for one logical send, including the initial request. */
  maxRedirects: 5,
  /** Composed request headers, including headers the boundary owns. */
  maxHeaderCount: 128,
  /** One header name plus value, in UTF-8 bytes. */
  maxHeaderBytes: 8 * 1_024,
  /** Caller-supplied request body. */
  maxRequestBodyBytes: 8 * 1_024 * 1_024,
  /** Inspected HAR container, matching the capture lane's input budget. */
  maxCaptureBytes: 32 * 1_024 * 1_024,
  /** Response bytes read when no dump path is selected, then abandoned. */
  maxRetainedBodyBytes: 1 * 1_024 * 1_024,
  /** Response bytes written to a caller-selected dump path, then abandoned. */
  maxDumpBodyBytes: 64 * 1_024 * 1_024,
  /** Capture entries listed by session start and status. */
  maxListedEntries: 20,
} as const;

/** On-disk schema version of one replay session record. */
export const REPLAY_SESSION_FILE_VERSION = 1;

/** Response-body size buckets reported instead of body content. */
export const REPLAY_SIZE_CLASSES = [
  "empty",
  "up_to_1_kib",
  "up_to_64_kib",
  "up_to_1_mib",
  "up_to_8_mib",
  "over_8_mib",
] as const;
export type ReplaySizeClass = (typeof REPLAY_SIZE_CLASSES)[number];

/** Bucket one observed body length; truncated reads stay in the reached bucket. */
export const replaySizeClass = (bytes: number): ReplaySizeClass =>
  bytes === 0
    ? "empty"
    : bytes <= 1_024
      ? "up_to_1_kib"
      : bytes <= 64 * 1_024
        ? "up_to_64_kib"
        : bytes <= 1_024 * 1_024
          ? "up_to_1_mib"
          : bytes <= 8 * 1_024 * 1_024
            ? "up_to_8_mib"
            : "over_8_mib";

/** Response status classes; a 4xx challenge stays a client_error observation. */
export const REPLAY_STATUS_CLASSES = [
  "informational",
  "success",
  "redirect",
  "client_error",
  "server_error",
  "unknown",
] as const;
export type ReplayStatusClass = (typeof REPLAY_STATUS_CLASSES)[number];

/** Classify one observed HTTP status without inferring a challenge. */
export const replayStatusClass = (status: number): ReplayStatusClass =>
  status >= 100 && status < 200
    ? "informational"
    : status >= 200 && status < 300
      ? "success"
      : status >= 300 && status < 400
        ? "redirect"
        : status >= 400 && status < 500
          ? "client_error"
          : status >= 500 && status < 600
            ? "server_error"
            : "unknown";

/** Media-type classes reported instead of a `Content-Type` header value. */
export const REPLAY_CONTENT_TYPE_CLASSES = [
  "absent",
  "json",
  "html",
  "xml",
  "javascript",
  "css",
  "text",
  "image",
  "audio_video",
  "font",
  "multipart",
  "binary",
  "unknown",
] as const;
export type ReplayContentTypeClass =
  (typeof REPLAY_CONTENT_TYPE_CLASSES)[number];

/**
 * Classify a declared media type. Omission, a malformed value, and an
 * unrecognized subtype stay distinct from one another.
 */
export const replayContentTypeClass = (
  contentType: string | undefined,
): ReplayContentTypeClass => {
  if (contentType === undefined) return "absent";
  const mediaType = contentType.split(";")[0]?.trim().toLowerCase() ?? "";
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(mediaType))
    return "unknown";
  const [type, subtype] = mediaType.split("/") as [string, string];
  if (subtype === "json" || subtype.endsWith("+json")) return "json";
  if (type === "text") {
    if (subtype === "html") return "html";
    if (subtype === "xml" || subtype.endsWith("+xml")) return "xml";
    if (subtype === "javascript" || subtype === "ecmascript")
      return "javascript";
    if (subtype === "css") return "css";
    return "text";
  }
  if (type === "application") {
    if (subtype === "xml" || subtype.endsWith("+xml")) return "xml";
    if (subtype === "javascript" || subtype === "x-javascript")
      return "javascript";
    if (subtype === "x-www-form-urlencoded") return "text";
    return "binary";
  }
  if (type === "image") return "image";
  if (type === "audio" || type === "video") return "audio_video";
  if (type === "font") return "font";
  if (type === "multipart") return "multipart";
  return "unknown";
};
