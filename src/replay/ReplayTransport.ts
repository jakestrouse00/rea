import type { ReplayHeader } from "../domain/replay/replayRequest.js";

/** Exact bytes one hop hands to the transport; framing is already composed. */
export interface ReplayTransportRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: readonly ReplayHeader[];
  readonly body: Uint8Array | undefined;
  readonly signal: AbortSignal;
}

/** One live response, still streaming; the caller owns its body. */
export interface ReplayTransportResponse {
  readonly status: number;
  /** Header pairs in wire order, including duplicates. */
  readonly headers: readonly ReplayHeader[];
  readonly body: AsyncIterable<Uint8Array>;
  /** Release an unread body. Idempotent; never waits for the peer. */
  cancel(): Promise<void>;
}

/**
 * The single dispatch seam of the active request plane.
 *
 * Implementations perform exactly one request per call. Retrying, following a
 * redirect, re-solving a challenge, or rotating headers belongs to no layer:
 * the send core never re-dispatches, and a transport that retried internally
 * would break the one-shot discipline every consumer of this port relies on.
 */
export interface ReplayTransport {
  send(request: ReplayTransportRequest): Promise<ReplayTransportResponse>;
}

/** Pair Node's flat `rawHeaders` list without reordering or folding duplicates. */
export const replayHeaderPairs = (
  rawHeaders: readonly string[],
): readonly ReplayHeader[] => {
  const headers: ReplayHeader[] = [];
  for (let index = 0; index + 1 < rawHeaders.length; index += 2)
    headers.push({ name: rawHeaders[index]!, value: rawHeaders[index + 1]! });
  return headers;
};
