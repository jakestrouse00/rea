import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

import type {
  ReplayTransport,
  ReplayTransportRequest,
  ReplayTransportResponse,
} from "./ReplayTransport.js";
import { replayHeaderPairs } from "./ReplayTransport.js";

/**
 * One-shot HTTP dispatch over Node's built-in client.
 *
 * REA has no declared `undici` dependency, and the global `fetch` REA already
 * uses forbids replay-fidelity request headers (`Host`, `Connection`), folds
 * duplicate headers, and decodes content encodings. A replayed request must
 * describe the target's behavior, not the client's adjustments, so this
 * adapter uses the same `node:http`/`node:https` primitive the CDP endpoint
 * client uses: one connection, exact header lines, no redirect, no retry, and
 * no automatic decoding.
 */
export class NodeReplayTransport implements ReplayTransport {
  send(request: ReplayTransportRequest): Promise<ReplayTransportResponse> {
    const url = new URL(request.url);
    const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
    return new Promise<ReplayTransportResponse>((resolve, reject) => {
      let settled = false;
      const clientRequest = transport({
        protocol: url.protocol,
        hostname: url.hostname.replace(/^\[|\]$/gu, ""),
        ...(url.port === "" ? {} : { port: Number(url.port) }),
        path: `${url.pathname}${url.search}`,
        method: request.method,
        setHost: false,
        agent: false,
        signal: request.signal,
      });
      // Group duplicate names so every composed line reaches the wire; a
      // repeated name overwrites its earlier value otherwise.
      const grouped = new Map<string, { name: string; values: string[] }>();
      for (const { name, value } of request.headers) {
        const key = name.toLowerCase();
        const entry = grouped.get(key);
        if (entry === undefined) grouped.set(key, { name, values: [value] });
        else entry.values.push(value);
      }
      for (const { name, values } of grouped.values())
        clientRequest.setHeader(
          name,
          values.length === 1 ? values[0]! : values,
        );
      clientRequest.on("response", (response) => {
        settled = true;
        resolve({
          status: response.statusCode ?? 0,
          headers: replayHeaderPairs(response.rawHeaders),
          body: chunks(response),
          cancel: async () => {
            response.destroy();
          },
        });
      });
      clientRequest.on("error", (cause) => {
        if (settled) return;
        settled = true;
        reject(cause);
      });
      clientRequest.end(request.body);
    });
  }
}

/** Yield response bytes without buffering them, and stop on destroy. */
async function* chunks(
  response: AsyncIterable<Buffer>,
): AsyncGenerator<Uint8Array> {
  for await (const chunk of response) yield chunk;
}
