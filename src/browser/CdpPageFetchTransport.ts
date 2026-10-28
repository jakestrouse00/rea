import {
  BROWSER_MUTATION_LIMITS,
  isBrowserManagedRequestHeader,
} from "../domain/browserMutationLimits.js";
import { isCanonicalBase64 } from "../domain/stringPatterns.js";
import type {
  ReplayTransport,
  ReplayTransportRequest,
  ReplayTransportResponse,
} from "../replay/ReplayTransport.js";
import {
  recordValue,
  cdpStringValue,
  numberValue,
} from "./CdpCaptureValues.js";
import type { CdpConnection } from "./CdpConnection.js";

interface PageFetchSession {
  readonly connection: CdpConnection;
  readonly sessionId: string | undefined;
}

/** The page could not describe an answer REA may project as a response. */
export class CdpPageFetchFailure extends Error {
  constructor(
    message: string,
    readonly reason: "opaque-redirect" | "body-truncated" | "protocol" | "page",
  ) {
    super(message);
    this.name = "CdpPageFetchFailure";
  }
}

/**
 * The one dispatch seam of `browser_fetch`: a page-context fetch over CDP.
 *
 * It performs exactly one `Runtime.evaluate` per hop, so the send core keeps
 * ownership of the origin gate, the no-retry policy, and the redacted echo.
 * The browser, not this transport, composes the wire bytes: it supplies
 * `Host`, framing, and the page session's own `Cookie` header, and a
 * redirected page fetch is opaque, so `redirect: "manual"` guarantees REA
 * never follows a hop whose origin the core did not approve.
 */
export class CdpPageFetchTransport implements ReplayTransport {
  constructor(private readonly session: PageFetchSession) {}

  async send(
    request: ReplayTransportRequest,
  ): Promise<ReplayTransportResponse> {
    const evaluated = await this.session.connection.send(
      "Runtime.evaluate",
      {
        expression: fetchExpression(request),
        awaitPromise: true,
        returnByValue: true,
        userGesture: false,
        silent: true,
      },
      this.session.sessionId,
      request.signal,
    );
    const answer = pageAnswer(evaluated);
    const bytes = Buffer.from(answer.bodyBase64, "base64");
    return {
      status: answer.status,
      headers: answer.headers,
      body: bodyChunks(bytes, answer.bodyTruncated),
      cancel: () => Promise.resolve(),
    };
  }
}

/** Header pairs a caller may not set: the browser owns their values. */
export const pageManagedHeaderNames = (
  headers: ReplayTransportRequest["headers"],
): readonly string[] => [
  ...new Set(
    headers
      .filter((header) => isBrowserManagedRequestHeader(header.name))
      .map((header) => header.name),
  ),
];

const fetchExpression = (request: ReplayTransportRequest): string => {
  const headers = request.headers.filter(
    (header) => !isBrowserManagedRequestHeader(header.name),
  );
  const headerObject = Object.fromEntries(
    headers.map((header) => [header.name, header.value]),
  );
  const body =
    request.body === undefined
      ? "null"
      : `Uint8Array.from(atob(${JSON.stringify(
          Buffer.from(request.body).toString("base64"),
        )}), (c) => c.charCodeAt(0))`;
  return `(async () => {
  const response = await fetch(${JSON.stringify(request.url)}, {
    method: ${JSON.stringify(request.method)},
    headers: ${JSON.stringify(headerObject)},
    credentials: "include",
    redirect: "manual",
    cache: "no-store",${
      request.body === undefined
        ? ""
        : `
    body: ${body},`
    }
  });
  if (response.type === "opaqueredirect")
    return { state: "opaque-redirect" };
  const buffer = await response.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const kept = bytes.subarray(0, ${String(BROWSER_MUTATION_LIMITS.maxPageFetchBodyBytes)});
  let binary = "";
  for (let index = 0; index < kept.length; index += 8192)
    binary += String.fromCharCode.apply(null, kept.subarray(index, index + 8192));
  return {
    state: "response",
    status: response.status,
    headers: Array.from(response.headers.entries()),
    body_base64: btoa(binary),
    body_truncated: bytes.length > kept.length,
  };
})()`;
};

interface PageAnswer {
  readonly status: number;
  readonly headers: readonly {
    readonly name: string;
    readonly value: string;
  }[];
  readonly bodyBase64: string;
  readonly bodyTruncated: boolean;
}

const pageAnswer = (value: unknown): PageAnswer => {
  const envelope = recordValue(value);
  const exception = recordValue(envelope?.exceptionDetails);
  if (exception !== undefined) {
    const description =
      cdpStringValue(recordValue(exception.exception)?.description) ??
      cdpStringValue(exception.text) ??
      "the page rejected the request without a description";
    throw new CdpPageFetchFailure(truncate(description), "page");
  }
  const result = recordValue(recordValue(envelope?.result)?.value);
  if (result === undefined)
    throw new CdpPageFetchFailure(
      "the page returned no serializable fetch answer",
      "protocol",
    );
  if (result.state === "opaque-redirect")
    throw new CdpPageFetchFailure(
      "the page-context fetch was redirected; the browser reported an opaque response whose status, location, and headers the page cannot read",
      "opaque-redirect",
    );
  const status = numberValue(result.status);
  const bodyBase64 = cdpStringValue(result.body_base64);
  if (
    result.state !== "response" ||
    status === undefined ||
    !Number.isInteger(status) ||
    status < 100 ||
    status > 999 ||
    bodyBase64 === undefined ||
    !isCanonicalBase64(bodyBase64)
  )
    throw new CdpPageFetchFailure(
      "the page returned a malformed fetch answer",
      "protocol",
    );
  return {
    status,
    headers: headerPairs(result.headers),
    bodyBase64,
    bodyTruncated: result.body_truncated === true,
  };
};

const headerPairs = (
  value: unknown,
): readonly { readonly name: string; readonly value: string }[] =>
  Array.isArray(value)
    ? value.flatMap((entry) => {
        if (!Array.isArray(entry)) return [];
        const [name, headerValue] = entry;
        return typeof name === "string" && typeof headerValue === "string"
          ? [{ name, value: headerValue }]
          : [];
      })
    : [];

/** Bytes handed to the send core per iteration of one response stream. */
const BODY_CHUNK_BYTES = 64 * 1_024;

async function* bodyChunks(
  bytes: Uint8Array,
  truncated: boolean,
): AsyncIterable<Uint8Array> {
  for (let offset = 0; offset < bytes.byteLength; offset += BODY_CHUNK_BYTES)
    yield bytes.subarray(
      offset,
      Math.min(offset + BODY_CHUNK_BYTES, bytes.byteLength),
    );
  if (truncated)
    throw new CdpPageFetchFailure(
      `the page read stopped at ${String(BROWSER_MUTATION_LIMITS.maxPageFetchBodyBytes)} bytes, so this body is a partial observation`,
      "body-truncated",
    );
}

const truncate = (value: string): string =>
  value.length > 200 ? value.slice(0, 200) : value;
