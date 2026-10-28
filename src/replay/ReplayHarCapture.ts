import { createHash } from "node:crypto";
import { open } from "node:fs/promises";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { REPLAY_LIMITS } from "../domain/replay/replayLimits.js";
import type {
  ReplayBody,
  ReplayHeader,
  ReplayRequest,
} from "../domain/replay/replayRequest.js";
import { replayBodyByteLength } from "../domain/replay/replayRequest.js";
import {
  replayCredentialHeaderNames,
  replayHeaderNames,
} from "../domain/replay/replayRedaction.js";
import { err, ok, type Result } from "../domain/result.js";
import { captureObject } from "../browser/history/CaptureRedaction.js";
import { parseCaptureJson } from "../browser/history/CaptureJson.js";
import { CaptureFormatError } from "../browser/history/CaptureFormatError.js";
import { validateHarContainer } from "../browser/history/HarCapture.js";
import { readBoundedFileBytes } from "../process/BoundedFileBytes.js";

/** One capture entry, replayable or not, with its captured request facts. */
export interface ReplayCapturedEntry {
  readonly ordinal: number;
  readonly method: string;
  readonly url: string;
  readonly origin: string | null;
  readonly headerNames: readonly string[];
  readonly credentialHeaderNames: readonly string[];
  readonly bodyBytes: number;
  /** Present only when this entry can be dispatched verbatim. */
  readonly request: ReplayRequest | null;
  readonly unreplayableReason: string | null;
}

/** One validated HAR capture with its stable file identity. */
export interface ReplayCapture {
  readonly path: string;
  readonly sha256: string;
  readonly entries: readonly ReplayCapturedEntry[];
}

const inputError = (
  operation: string,
  pointer: string,
  message: string,
  cause?: unknown,
): AnalysisInputError =>
  new AnalysisInputError(
    operation,
    {
      ...(cause === undefined ? {} : { cause }),
      userMessage: `${message} (HAR pointer ${JSON.stringify(pointer)}).`,
      diagnostics: { capture_pointer: pointer },
    },
    [{ path: ["capture_path"], reason: "invalid_format", message }],
  );

const originOf = (url: string): string | null => {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:"
      ? parsed.origin
      : null;
  } catch (cause: unknown) {
    void cause;
    return null;
  }
};

const headerList = (value: unknown): readonly ReplayHeader[] | null => {
  if (!Array.isArray(value)) return value === undefined ? [] : null;
  const headers: ReplayHeader[] = [];
  for (const item of value) {
    if (!captureObject(item)) return null;
    const { name, value: headerValue } = item;
    if (typeof name !== "string" || name.length === 0) return null;
    if (typeof headerValue !== "string") return null;
    headers.push({ name, value: headerValue });
  }
  return headers;
};

const capturedBody = (
  postData: unknown,
): { readonly body: ReplayBody; readonly reason: string | null } => {
  if (postData === undefined || postData === null)
    return { body: { kind: "none" }, reason: null };
  if (!captureObject(postData))
    return { body: { kind: "none" }, reason: "postData is not an object" };
  const text = postData.text;
  if (text === null || text === undefined)
    return {
      body: { kind: "none" },
      reason:
        "postData carries no text, so the captured request body cannot be reconstructed",
    };
  if (typeof text !== "string")
    return {
      body: { kind: "none" },
      reason: "postData.text is not a string",
    };
  if (postData.encoding === "base64")
    return {
      body: { kind: "base64", base64: text },
      reason: null,
    };
  return { body: { kind: "text", text }, reason: null };
};

const entryOf = (
  raw: unknown,
  ordinal: number,
  adapted: boolean,
): ReplayCapturedEntry => {
  const unreplayable = (reason: string): ReplayCapturedEntry => ({
    ordinal,
    method: "",
    url: "",
    origin: null,
    headerNames: [],
    credentialHeaderNames: [],
    bodyBytes: 0,
    request: null,
    unreplayableReason: reason,
  });
  void adapted;
  if (!captureObject(raw) || !captureObject(raw.request))
    return unreplayable("the entry has no request object");
  const { method, url } = raw.request;
  if (typeof method !== "string" || method.length === 0)
    return unreplayable("the entry request has no method");
  if (typeof url !== "string" || url.length === 0)
    return unreplayable("the entry request has no url");
  const headers = headerList(raw.request.headers);
  if (headers === null)
    return unreplayable("the entry request headers are not name/value pairs");
  const body = capturedBody(raw.request.postData);
  const origin = originOf(url);
  const summary = {
    ordinal,
    method,
    url,
    origin,
    headerNames: replayHeaderNames(headers),
    credentialHeaderNames: replayCredentialHeaderNames(headers),
    bodyBytes: replayBodyByteLength(body.body),
  };
  const reason =
    origin === null
      ? "the entry url is not an absolute http or https URL"
      : body.reason;
  return reason === null
    ? {
        ...summary,
        request: { method, url, headers, body: body.body },
        unreplayableReason: null,
      }
    : {
        ...summary,
        request: null,
        unreplayableReason: reason,
      };
};

/** Decode the container and each entry's replayable request facts. */
const decodeCapture = (
  text: string,
  path: string,
  sha256: string,
  operation: string,
): Result<ReplayCapture, AnalysisError> => {
  let raw: unknown;
  try {
    raw = parseCaptureJson(text, "HAR");
  } catch (cause: unknown) {
    if (cause instanceof CaptureFormatError)
      return err(inputError(operation, "capture", cause.message, cause));
    return err(
      inputError(
        operation,
        "capture",
        "The capture is not valid HAR JSON.",
        cause,
      ),
    );
  }
  if (!captureObject(raw) || !captureObject(raw.log))
    return err(
      inputError(operation, "/log", "A HAR capture must have a log object."),
    );
  if (raw.log.version !== "1.2")
    return err(
      inputError(
        operation,
        "/log/version",
        "Only the pinned HAR 1.2 schema profile is replayed.",
      ),
    );
  const entries = raw.log.entries;
  if (!Array.isArray(entries))
    return err(
      inputError(operation, "/log/entries", "A HAR capture must list entries."),
    );
  // The capture lane owns HAR 1.2 validation; its adaptation of observed
  // producer representations (bracketed IPv6 server addresses, mitmproxy's null
  // body text) does not affect a replayed request.
  try {
    validateHarContainer(raw);
  } catch (cause: unknown) {
    if (cause instanceof CaptureFormatError)
      return err(
        inputError(operation, cause.pointer ?? "/log", cause.message, cause),
      );
    return err(
      inputError(
        operation,
        "/log",
        "The capture does not satisfy HAR 1.2.",
        cause,
      ),
    );
  }
  return ok({
    path,
    sha256,
    entries: entries.map((entry, ordinal) => entryOf(entry, ordinal, false)),
  });
};

/**
 * Read one caller-selected HAR container without contacting its destinations.
 *
 * The capture lane owns HAR validation; this reader reuses that schema owner
 * and adds only the replay projection: which entries can be dispatched
 * verbatim, and why the others cannot. Bodies stay in memory for the session's
 * lifetime and are never echoed.
 */
export const readReplayCapture = async (
  path: string,
  operation: string,
  signal: AbortSignal | undefined,
): Promise<Result<ReplayCapture, AnalysisError>> => {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(path, "r");
  } catch (cause: unknown) {
    return err(
      new AnalysisInputError(
        operation,
        {
          cause,
          userMessage: `REA could not read the capture at ${path}.`,
          diagnostics: { capture_path: path },
        },
        [
          {
            path: ["capture_path"],
            reason: "invalid_value",
            message: "The capture path could not be opened for reading.",
          },
        ],
      ),
    );
  }
  try {
    const stat = await handle.stat();
    if (stat.size > REPLAY_LIMITS.maxCaptureBytes)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "file-size",
          `The capture exceeds the ${String(REPLAY_LIMITS.maxCaptureBytes)}-byte HAR inspection budget.`,
          {
            capture_path: path,
            bytes: stat.size,
            max_bytes: REPLAY_LIMITS.maxCaptureBytes,
          },
          {
            remediationAction: `Select a capture within the ${String(REPLAY_LIMITS.maxCaptureBytes)}-byte HAR inspection budget, or export only the entries you need.`,
            retryable: false,
          },
        ),
      );
    let bytes: Buffer | undefined;
    try {
      bytes = await readBoundedFileBytes(
        handle,
        REPLAY_LIMITS.maxCaptureBytes,
        {
          signal,
          expectedSize: stat.size,
        },
      );
    } catch (cause: unknown) {
      if (signal?.aborted === true)
        return err(
          new AnalysisCancelledError(operation, { cause: signal.reason }),
        );
      throw cause;
    }
    if (bytes === undefined)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "file-size",
          `The capture exceeded the ${String(REPLAY_LIMITS.maxCaptureBytes)}-byte HAR inspection budget while being read.`,
          {
            capture_path: path,
            max_bytes: REPLAY_LIMITS.maxCaptureBytes,
          },
          { retryable: false },
        ),
      );
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (cause: unknown) {
      return err(
        inputError(
          operation,
          "capture",
          "The capture is not valid UTF-8 text. HAR 1.2 encodes its container as Unicode text; export the capture again instead of re-encoding it.",
          cause,
        ),
      );
    }
    return decodeCapture(text, path, sha256, operation);
  } finally {
    await handle.close().catch(() => undefined);
  }
};
