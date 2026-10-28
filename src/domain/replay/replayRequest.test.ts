import { describe, expect, it } from "vitest";

import { REPLAY_LIMITS } from "./replayLimits.js";
import {
  composeReplayRequest,
  composeReplayWireRequest,
  replayBodyByteLength,
  replayBodyBytes,
  type ReplayRequest,
} from "./replayRequest.js";

const base = (): ReplayRequest => ({
  method: "POST",
  url: "https://api.example.test/v1/items?x=1",
  headers: [
    { name: "content-type", value: "application/json" },
    { name: "Authorization", value: "Bearer secret" },
    { name: "x-trace", value: "a" },
    { name: "x-trace", value: "b" },
  ],
  body: { kind: "text", text: '{"a":1}' },
});

const issuePaths = (result: ReturnType<typeof composeReplayWireRequest>) =>
  result.ok ? [] : result.error.map(({ path }) => path.join("."));

describe("replay request composition", () => {
  it("sends the selected request verbatim when the mutation is empty", () => {
    const composed = composeReplayRequest(base(), {});
    expect(composed.ok).toBe(true);
    expect(composed.ok ? composed.value : null).toEqual(base());
  });

  it("applies remove then set with case-insensitive names", () => {
    const composed = composeReplayRequest(base(), {
      removeHeaders: ["AUTHORIZATION", "content-type"],
      setHeaders: [{ name: "Content-Type", value: "text/plain" }],
    });
    expect(composed.ok).toBe(true);
    if (!composed.ok) return;
    expect(composed.value.headers).toEqual([
      { name: "x-trace", value: "a" },
      { name: "x-trace", value: "b" },
      { name: "Content-Type", value: "text/plain" },
    ]);
  });

  it("replaces every pair of a duplicated name instead of the first", () => {
    const captured: ReplayRequest = {
      ...base(),
      headers: [
        { name: "Cookie", value: "session=stale" },
        { name: "x-trace", value: "a" },
        { name: "cookie", value: "refresh=stale" },
        { name: "x-trace", value: "b" },
      ],
    };
    const composed = composeReplayRequest(captured, {
      setHeaders: [{ name: "cookie", value: "session=new=1" }],
    });
    expect(composed.ok).toBe(true);
    if (!composed.ok) return;
    expect(composed.value.headers).toEqual([
      { name: "x-trace", value: "a" },
      { name: "x-trace", value: "b" },
      { name: "cookie", value: "session=new=1" },
    ]);
    const wire = composeReplayWireRequest(composed.value);
    expect(wire.ok).toBe(true);
    const cookiePairs = wire.ok
      ? wire.value.headers.filter(
          (header) => header.name.toLowerCase() === "cookie",
        )
      : [];
    expect(cookiePairs).toEqual([{ name: "cookie", value: "session=new=1" }]);
    expect(JSON.stringify(wire.ok ? wire.value.headers : [])).not.toContain(
      "stale",
    );
  });

  it("keeps one pair when a mutation repeats the same set name", () => {
    const composed = composeReplayRequest(base(), {
      setHeaders: [
        { name: "x-probe", value: "first" },
        { name: "X-Probe", value: "second" },
      ],
    });
    expect(composed.ok && composed.value.headers.at(-1)).toEqual({
      name: "X-Probe",
      value: "second",
    });
    expect(
      composed.ok
        ? composed.value.headers.filter(
            (header) => header.name.toLowerCase() === "x-probe",
          )
        : [],
    ).toHaveLength(1);
  });

  it("upper-cases the method and clears the body only when the caller asks", () => {
    const composed = composeReplayRequest(base(), {
      method: " get ",
      body: { kind: "none" },
    });
    expect(composed.ok && composed.value.method).toBe("GET");
    expect(composed.ok && composed.value.body).toEqual({ kind: "none" });
  });

  it("rejects malformed methods, header names, CRLF values, and bodies", () => {
    const method = composeReplayRequest(base(), { method: "GE T" });
    expect(method.ok).toBe(false);
    expect(method.ok ? [] : method.error[0]?.path).toEqual(["method"]);

    const headerName = composeReplayRequest(base(), {
      setHeaders: [{ name: "bad header", value: "1" }],
    });
    expect(headerName.ok).toBe(false);
    expect(headerName.ok ? [] : headerName.error[0]?.path).toEqual([
      "set_headers",
      0,
      "name",
    ]);

    const crlf = composeReplayRequest(base(), {
      setHeaders: [{ name: "x-a", value: "a\r\nb" }],
    });
    expect(crlf.ok).toBe(false);

    const base64 = composeReplayRequest(base(), {
      body: { kind: "base64", base64: "not base64!" },
    });
    expect(base64.ok).toBe(false);

    const head = composeReplayRequest(base(), { method: "HEAD" });
    expect(head.ok).toBe(false);
    expect(head.ok ? [] : head.error[0]?.path).toEqual(["body"]);
  });

  it("bounds one request body and one header value", () => {
    const oversized = composeReplayRequest(base(), {
      body: {
        kind: "text",
        text: "x".repeat(REPLAY_LIMITS.maxRequestBodyBytes + 1),
      },
    });
    expect(oversized.ok).toBe(false);

    const header = composeReplayRequest(base(), {
      setHeaders: [
        { name: "x-big", value: "y".repeat(REPLAY_LIMITS.maxHeaderBytes) },
      ],
    });
    expect(header.ok).toBe(false);
  });

  it("rejects URLs that are relative, non-http, or carry userinfo", () => {
    for (const url of ["/relative", "ftp://a.test/x", "https://u:p@a.test/x"]) {
      const composed = composeReplayRequest(base(), { url });
      expect(composed.ok).toBe(false);
      expect(composed.ok ? [] : composed.error[0]?.path).toEqual(["url"]);
    }
  });

  it("measures padded base64 bodies by their decoded bytes", () => {
    expect(replayBodyByteLength({ kind: "none" })).toBe(0);
    expect(replayBodyByteLength({ kind: "text", text: "é" })).toBe(2);
    expect(
      replayBodyByteLength({ kind: "base64", base64: "eyJhIjoxfQ==" }),
    ).toBe(7);
    expect(replayBodyByteLength({ kind: "base64", base64: "AAE=" })).toBe(2);
    expect(replayBodyByteLength({ kind: "base64", base64: "AAAA" })).toBe(3);
  });

  it("materializes text and base64 bodies to their exact bytes", () => {
    expect(replayBodyBytes({ kind: "none" })).toBeUndefined();
    expect(
      Buffer.from(replayBodyBytes({ kind: "text", text: "é" }) ?? []).toString(
        "hex",
      ),
    ).toBe("c3a9");
    expect(
      Buffer.from(
        replayBodyBytes({ kind: "base64", base64: "AAE=" }) ?? [],
      ).toString("hex"),
    ).toBe("0001");
  });
});

describe("replay wire framing", () => {
  it("owns framing headers and composes Host and Content-Length", () => {
    const composed = composeReplayWireRequest({
      method: "POST",
      url: "https://api.example.test:8443/x",
      headers: [
        { name: "Content-Length", value: "999" },
        { name: "Transfer-Encoding", value: "chunked" },
        { name: "Host", value: "virtual.example.test" },
      ],
      body: { kind: "text", text: "ab" },
    });
    expect(composed.ok).toBe(true);
    if (!composed.ok) return;
    expect(composed.value.headers).toEqual([
      { name: "Host", value: "virtual.example.test" },
      { name: "content-length", value: "2" },
    ]);
    expect(
      Buffer.from(composed.value.body ?? []).equals(Buffer.from("ab")),
    ).toBe(true);
  });

  it("adds the URL host when the capture did not fix one", () => {
    const composed = composeReplayWireRequest({
      method: "GET",
      url: "https://api.example.test:8443/x?y=1",
      headers: [],
      body: { kind: "none" },
    });
    expect(composed.ok && composed.value.headers).toEqual([
      { name: "host", value: "api.example.test:8443" },
    ]);
    expect(composed.ok && composed.value.body).toBeUndefined();
  });

  it("bounds the request body at the wire seam for every lane", () => {
    const composed = composeReplayWireRequest({
      method: "POST",
      url: "https://api.example.test/",
      headers: [],
      body: {
        kind: "base64",
        base64: Buffer.alloc(REPLAY_LIMITS.maxRequestBodyBytes + 1).toString(
          "base64",
        ),
      },
    });
    expect(issuePaths(composed)).toContain("body.base64");
  });

  it("refuses a HEAD body at the wire seam for every lane", () => {
    const composed = composeReplayWireRequest({
      method: "HEAD",
      url: "https://api.example.test/",
      headers: [],
      body: { kind: "text", text: "payload" },
    });
    expect(issuePaths(composed)).toContain("body");
  });

  it("bounds the composed header count", () => {
    const headersList = Array.from(
      { length: REPLAY_LIMITS.maxHeaderCount + 1 },
      (_, index) => ({ name: `x-${String(index)}`, value: "1" }),
    );
    const composed = composeReplayWireRequest({
      method: "GET",
      url: "https://api.example.test/",
      headers: headersList,
      body: { kind: "none" },
    });
    expect(issuePaths(composed)).toContain("headers");
  });
});
