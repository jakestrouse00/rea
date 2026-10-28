import { mkdtemp, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { REPLAY_LIMITS } from "../domain/replay/replayLimits.js";
import { readReplayCapture } from "./ReplayHarCapture.js";

const directories: string[] = [];

const captureDirectory = async (): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-replay-har-"));
  directories.push(directory);
  return directory;
};

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

const entry = (
  ordinal: number,
  request: Record<string, unknown>,
): Record<string, unknown> => ({
  startedDateTime: "2026-01-01T00:00:00.000Z",
  time: 1,
  request: {
    method: "GET",
    url: `https://api.example.test/v1/${String(ordinal)}`,
    httpVersion: "HTTP/1.1",
    headers: [{ name: "accept", value: "*/*" }],
    queryString: [],
    cookies: [],
    headersSize: -1,
    bodySize: -1,
    ...request,
  },
  response: {
    status: 200,
    statusText: "OK",
    httpVersion: "HTTP/1.1",
    headers: [],
    cookies: [],
    content: { size: 0, mimeType: "text/plain" },
    redirectURL: "",
    headersSize: -1,
    bodySize: -1,
  },
  cache: {},
  timings: { send: 0, wait: 0, receive: 0 },
});

const har = (entries: readonly unknown[]): string =>
  JSON.stringify({
    log: {
      version: "1.2",
      creator: { name: "fixture", version: "1" },
      entries,
    },
  });

const write = async (directory: string, text: string): Promise<string> => {
  const path = join(directory, "capture.har");
  await writeFile(path, text, "utf8");
  return path;
};

describe("replay HAR capture reader", () => {
  it("projects replayable requests and keeps credential header names", async () => {
    const directory = await captureDirectory();
    const path = await write(
      directory,
      har([
        entry(0, {
          method: "POST",
          url: "https://api.example.test/v1/items",
          headers: [
            { name: "Authorization", value: "Bearer sk-live" },
            { name: "content-type", value: "application/json" },
          ],
          postData: { mimeType: "application/json", text: '{"a":1}' },
        }),
      ]),
    );
    const read = await readReplayCapture(
      path,
      "http_replay_session_start",
      undefined,
    );
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    expect(read.value.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(read.value.entries).toHaveLength(1);
    expect(read.value.entries[0]).toMatchObject({
      ordinal: 0,
      method: "POST",
      origin: "https://api.example.test",
      headerNames: ["Authorization", "content-type"],
      credentialHeaderNames: ["Authorization"],
      bodyBytes: 7,
      unreplayableReason: null,
    });
    expect(read.value.entries[0]?.request).toEqual({
      method: "POST",
      url: "https://api.example.test/v1/items",
      headers: [
        { name: "Authorization", value: "Bearer sk-live" },
        { name: "content-type", value: "application/json" },
      ],
      body: { kind: "text", text: '{"a":1}' },
    });
  });

  it("reads a base64 postData body as bytes", async () => {
    const directory = await captureDirectory();
    const path = await write(
      directory,
      har([
        entry(0, {
          postData: {
            mimeType: "application/octet-stream",
            text: "AAEC",
            encoding: "base64",
          },
        }),
      ]),
    );
    const read = await readReplayCapture(path, "op", undefined);
    expect(read.ok).toBe(true);
    expect(read.ok ? read.value.entries[0]?.request?.body : null).toEqual({
      kind: "base64",
      base64: "AAEC",
    });
  });

  it("refuses an entry whose captured body cannot be reconstructed", async () => {
    const directory = await captureDirectory();
    const path = await write(
      directory,
      har([
        entry(0, {
          postData: {
            mimeType: "application/x-www-form-urlencoded",
            params: [{ name: "a", value: "1" }],
          },
        }),
      ]),
    );
    const read = await readReplayCapture(path, "op", undefined);
    expect(read.ok).toBe(true);
    expect(read.ok ? read.value.entries[0]?.request : undefined).toBeNull();
    expect(read.ok ? read.value.entries[0]?.unreplayableReason : "").toContain(
      "cannot be reconstructed",
    );
  });

  it("marks a schema-valid entry with a non-http URL unreplayable", async () => {
    const directory = await captureDirectory();
    const path = await write(
      directory,
      har([entry(0, { url: "wss://api.example.test/socket" }), entry(1, {})]),
    );
    const read = await readReplayCapture(path, "op", undefined);
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    expect(read.value.entries[0]?.request).toBeNull();
    expect(read.value.entries[0]?.origin).toBeNull();
    expect(read.value.entries[0]?.unreplayableReason).toContain("http");
    expect(read.value.entries[1]?.request).not.toBeNull();
  });

  it("rejects the whole container when an entry breaks the HAR profile", async () => {
    const directory = await captureDirectory();
    const path = await write(
      directory,
      har([entry(0, {}), entry(1, { headers: "not-a-list" })]),
    );
    const read = await readReplayCapture(path, "op", undefined);
    expect(read.ok).toBe(false);
    if (read.ok) return;
    expect(read.error._tag).toBe("AnalysisInputError");
    expect(String(read.error.diagnostics?.capture_pointer)).toContain(
      "/log/entries/1",
    );
  });

  it("lists a schema-valid entry with no method as unreplayable", async () => {
    const directory = await captureDirectory();
    const path = await write(directory, har([entry(0, { method: "" })]));
    const read = await readReplayCapture(path, "op", undefined);
    expect(read.ok).toBe(true);
    expect(read.ok ? read.value.entries[0]?.request : undefined).toBeNull();
    expect(read.ok ? read.value.entries[0]?.unreplayableReason : "").toContain(
      "method",
    );
  });
});

describe("replay HAR capture boundaries", () => {
  it("rejects malformed containers with a pointer", async () => {
    const directory = await captureDirectory();
    for (const [text, pointer] of [
      ['{"log":', "capture"],
      [JSON.stringify({ log: { version: "1.2" } }), "/log/entries"],
      [
        JSON.stringify({ log: { version: "1.1", entries: [] } }),
        "/log/version",
      ],
      [JSON.stringify({}), "/log"],
      ["[]", "/log"],
    ] as const) {
      const path = await write(directory, text);
      const read = await readReplayCapture(path, "op", undefined);
      expect(read.ok).toBe(false);
      if (read.ok) continue;
      expect(read.error.diagnostics?.capture_pointer).toBe(pointer);
      expect(read.error.userMessage).toContain(pointer);
    }
  });

  it("refuses a capture over the HAR inspection budget without reading it", async () => {
    const directory = await captureDirectory();
    const path = await write(directory, har([]));
    await truncate(path, REPLAY_LIMITS.maxCaptureBytes + 1);
    const read = await readReplayCapture(path, "op", undefined);
    expect(read.ok).toBe(false);
    if (read.ok) return;
    expect(read.error._tag).toBe("AnalysisResourceConstraintError");
  });

  it("refuses non-UTF-8 capture bytes and an unreadable path", async () => {
    const directory = await captureDirectory();
    const path = join(directory, "binary.har");
    await writeFile(path, Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x7d]));
    const invalid = await readReplayCapture(path, "op", undefined);
    expect(invalid.ok).toBe(false);
    expect(invalid.ok ? "" : invalid.error.userMessage).toContain("UTF-8");

    const missing = await readReplayCapture(
      join(directory, "absent.har"),
      "op",
      undefined,
    );
    expect(missing.ok).toBe(false);
    expect(missing.ok ? "" : missing.error._tag).toBe("AnalysisInputError");
  });

  it("refuses to read after the caller aborts", async () => {
    const directory = await captureDirectory();
    const path = await write(directory, har([entry(0, {})]));
    const controller = new AbortController();
    controller.abort(new Error("caller cancelled"));
    const read = await readReplayCapture(path, "op", controller.signal);
    expect(read.ok).toBe(false);
    expect(read.ok ? "" : read.error._tag).toBe("AnalysisCancelledError");
  });
});
