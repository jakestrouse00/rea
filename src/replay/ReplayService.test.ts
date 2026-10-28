import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  replaySendResultSchema,
  replaySessionCloseResultSchema,
  replaySessionStartResultSchema,
  replaySessionStatusResultSchema,
} from "../domain/replay/replayObservation.js";
import { REPLAY_ALLOWED_ORIGINS_ENV } from "../domain/replay/replayOrigins.js";
import { ReplayService } from "./ReplayService.js";
import { ReplaySessionFiles } from "./ReplaySessionFile.js";
import type {
  ReplayTransport,
  ReplayTransportRequest,
  ReplayTransportResponse,
} from "./ReplayTransport.js";

const OPERATOR_ORIGIN = "https://api.example.test";
const SECOND_ORIGIN = "https://second.example.test";
const SECRET = "Bearer sk-live-0123456789";

const directories: string[] = [];

const temporaryDirectory = async (): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-replay-"));
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

interface ControllableBody {
  readonly body: AsyncIterable<Uint8Array>;
  push(chunk: string | Uint8Array): void;
  end(): void;
}

const controllableBody = (): ControllableBody => {
  const queue: Uint8Array[] = [];
  let waiting: ((result: IteratorResult<Uint8Array>) => void) | undefined;
  let finished = false;
  const settle = (result: IteratorResult<Uint8Array>): void => {
    if (waiting === undefined) return;
    const resolve = waiting;
    waiting = undefined;
    resolve(result);
  };
  const iterator: AsyncIterator<Uint8Array> = {
    next: () =>
      new Promise<IteratorResult<Uint8Array>>((resolve) => {
        const value = queue.shift();
        if (value !== undefined) {
          resolve({ value, done: false });
          return;
        }
        if (finished) {
          resolve({ value: undefined, done: true });
          return;
        }
        waiting = resolve;
      }),
  };
  return {
    body: { [Symbol.asyncIterator]: () => iterator },
    push(chunk) {
      const value =
        typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
      if (waiting === undefined) queue.push(value);
      else settle({ value, done: false });
    },
    end() {
      finished = true;
      settle({ value: undefined, done: true });
    },
  };
};

const response = (init: {
  readonly status: number;
  readonly headers?: readonly (readonly [string, string])[];
  readonly body?: ControllableBody;
  readonly chunks?: readonly string[];
}): ReplayTransportResponse => {
  const controlled = init.body;
  const cancelled: (() => void)[] = [];
  const body: AsyncIterable<Uint8Array> =
    controlled === undefined
      ? (async function* () {
          for (const chunk of init.chunks ?? [])
            yield Buffer.from(chunk, "utf8");
        })()
      : controlled.body;
  return {
    status: init.status,
    headers: (init.headers ?? []).map(([name, value]) => ({ name, value })),
    body,
    cancel: async () => {
      for (const listener of cancelled.splice(0)) listener();
      controlled?.end();
    },
  };
};

const deferred = () => {
  let resolve!: (value: ReplayTransportResponse) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<ReplayTransportResponse>(
    (resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    },
  );
  return { promise, resolve, reject };
};

const scripted = () => {
  const requests: ReplayTransportRequest[] = [];
  const pending: {
    readonly promise: Promise<ReplayTransportResponse>;
    readonly settle: (response: ReplayTransportResponse) => void;
    readonly fail: (cause: unknown) => void;
  }[] = [];
  const transport: ReplayTransport = {
    send(request) {
      requests.push(request);
      const next = deferred();
      pending.push({
        promise: next.promise,
        settle: next.resolve,
        fail: next.reject,
      });
      return next.promise;
    },
  };
  return {
    transport,
    requests,
    next(): (typeof pending)[number] {
      const item = pending.shift();
      if (item === undefined) throw new Error("The transport was not called");
      return item;
    },
    get dispatched(): number {
      return requests.length;
    },
  };
};

/** Wait until the service has actually reached the transport seam. */
const nextDispatch = (fixture: Awaited<ReturnType<typeof service>>) =>
  vi.waitFor(() => fixture.transport.next());

const firstDispatch = (fixture: Awaited<ReturnType<typeof service>>) =>
  vi.waitFor(() => fixture.transport.next());

const captureText = (entries: readonly Record<string, unknown>[]): string =>
  JSON.stringify({
    log: {
      version: "1.2",
      creator: { name: "fixture", version: "1" },
      entries: entries.map((request, ordinal) => ({
        startedDateTime: "2026-01-01T00:00:00.000Z",
        time: 1,
        request: {
          method: "POST",
          url: `${OPERATOR_ORIGIN}/v1/items`,
          httpVersion: "HTTP/1.1",
          headers: [
            { name: "authorization", value: SECRET },
            { name: "content-type", value: "application/json" },
          ],
          queryString: [],
          cookies: [],
          headersSize: -1,
          bodySize: 7,
          postData: { mimeType: "application/json", text: '{"a":1}' },
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
        ordinal,
      })),
    },
  });

const service = async (
  options: {
    readonly origins?: readonly string[];
    readonly environment?: Readonly<Record<string, string | undefined>>;
  } = {},
) => {
  const directory = await temporaryDirectory();
  const transport = scripted();
  const files = new ReplaySessionFiles(join(directory, "state"));
  const replay = new ReplayService({
    environment:
      options.environment ??
      ({
        [REPLAY_ALLOWED_ORIGINS_ENV]: JSON.stringify(
          options.origins ?? [OPERATOR_ORIGIN],
        ),
      } as Readonly<Record<string, string | undefined>>),
    transport: transport.transport,
    sessionFiles: files,
  });
  const capture = join(directory, "capture.har");
  await writeFile(capture, captureText([{}]), "utf8");
  return { replay, transport, files, directory, capture };
};

const startCaptureSession = async (
  fixture: Awaited<ReturnType<typeof service>>,
  origins: readonly string[] = [OPERATOR_ORIGIN],
) => {
  const started = await fixture.replay.startSession({
    source: { kind: "har", path: fixture.capture, entryOrdinal: 0 },
    targetOrigins: origins,
  });
  if (!started.ok) throw started.error;
  return replaySessionStartResultSchema.parse(started.value.normalized_result);
};

const startDraftSession = async (
  fixture: Awaited<ReturnType<typeof service>>,
  origins: readonly string[] = [OPERATOR_ORIGIN],
) => {
  const started = await fixture.replay.startSession({
    source: {
      kind: "draft",
      request: {
        method: "POST",
        url: `${OPERATOR_ORIGIN}/v1/items`,
        headers: [
          { name: "authorization", value: SECRET },
          { name: "content-type", value: "application/json" },
        ],
        body: { kind: "text", text: '{"a":1}' },
      },
    },
    targetOrigins: origins,
  });
  if (!started.ok) throw started.error;
  return replaySessionStartResultSchema.parse(started.value.normalized_result);
};

describe("replay session authorization", () => {
  it("refuses to start while the operator allowlist is unset", async () => {
    const fixture = await service({ environment: {} });
    const started = await fixture.replay.startSession({
      source: { kind: "har", path: fixture.capture, entryOrdinal: 0 },
      targetOrigins: [OPERATOR_ORIGIN],
    });
    expect(started.ok).toBe(false);
    if (started.ok) return;
    expect(started.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(started.error.userMessage).toContain(REPLAY_ALLOWED_ORIGINS_ENV);
    await expect(stat(fixture.files.directory)).rejects.toThrow();
  });

  it("refuses a declared origin the operator did not approve", async () => {
    const fixture = await service();
    const started = await fixture.replay.startSession({
      source: { kind: "har", path: fixture.capture, entryOrdinal: 0 },
      targetOrigins: [SECOND_ORIGIN],
    });
    expect(started.ok).toBe(false);
    expect(started.ok ? "" : started.error.userMessage).toContain(
      "is not in the operator allowlist",
    );
  });

  it("refuses an unnormalizable declared origin and an outside capture entry", async () => {
    const fixture = await service();
    const malformed = await fixture.replay.startSession({
      source: { kind: "har", path: fixture.capture, entryOrdinal: 0 },
      targetOrigins: ["https://api.example.test/v1"],
    });
    expect(malformed.ok).toBe(false);
    expect(malformed.ok ? "" : malformed.error._tag).toBe("AnalysisInputError");

    const other = await writeFile(
      fixture.capture,
      captureText([{ url: `${SECOND_ORIGIN}/v1/items` }]),
      "utf8",
    );
    void other;
    const outside = await fixture.replay.startSession({
      source: { kind: "har", path: fixture.capture, entryOrdinal: 0 },
      targetOrigins: [OPERATOR_ORIGIN],
    });
    expect(outside.ok).toBe(true);
    const sent = await fixture.replay.send({
      sessionId: replaySessionStartResultSchema.parse(
        outside.ok ? outside.value.normalized_result : {},
      ).session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: undefined,
    });
    expect(sent.ok).toBe(false);
    expect(sent.ok ? "" : sent.error.userMessage).toContain(
      "outside this session's approved origins",
    );
    expect(fixture.transport.dispatched).toBe(0);
  });

  it("refuses a mutation that leaves the declared origins", async () => {
    const fixture = await service();
    const session = await startDraftSession(fixture);
    const sent = await fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: { url: `${SECOND_ORIGIN}/v1/items` },
      timeoutMs: 1_000,
      followRedirects: true,
      dump: undefined,
    });
    expect(sent.ok).toBe(false);
    expect(fixture.transport.dispatched).toBe(0);
  });
});

describe("replay session ownership", () => {
  it("writes an owner-only record, reports it, and removes it on close", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const recordPath = fixture.files.pathFor(session.session_id);
    expect(session.session_file).toEqual({
      path: recordPath,
      permissions: process.platform === "win32" ? "unverified" : "0600",
    });
    if (process.platform !== "win32")
      expect((await stat(recordPath)).mode & 0o777).toBe(0o600);
    const record = JSON.parse(await readFile(recordPath, "utf8")) as {
      owner: { process_id: number; server_started_at: string };
      source: { kind: string; sha256: string };
      target_origins: string[];
      selected_entry: number;
      draft: unknown;
    };
    expect(record.owner.process_id).toBe(process.pid);
    expect(record.owner.server_started_at).toMatch(/^\d{4}-/u);
    expect(record.source.kind).toBe("har");
    expect(record.source.sha256).toBe(
      session.source.kind === "har" ? session.source.sha256 : "",
    );
    expect(record.target_origins).toEqual([OPERATOR_ORIGIN]);
    expect(record.selected_entry).toBe(0);
    expect(record.draft).toBeNull();

    const status = await fixture.replay.sessionStatus({
      sessionId: session.session_id,
    });
    expect(status.ok).toBe(true);
    expect(
      replaySessionStatusResultSchema.parse(
        status.ok ? status.value.normalized_result : {},
      ),
    ).toMatchObject({
      session_id: session.session_id,
      state: "open",
      send_count: 0,
      last_send_at: null,
      entry_count: 1,
    });

    const closed = await fixture.replay.closeSession({
      sessionId: session.session_id,
    });
    expect(closed.ok).toBe(true);
    expect(
      replaySessionCloseResultSchema.parse(
        closed.ok ? closed.value.normalized_result : {},
      ),
    ).toEqual({
      session_id: session.session_id,
      state: "closed",
      send_count: 0,
      session_file: { path: recordPath, removed: true },
    });
    await expect(stat(recordPath)).rejects.toThrow();
    await expect(
      fixture.replay.closeSession({ sessionId: session.session_id }),
    ).resolves.toMatchObject({ ok: false });
  });

  it("never adopts, rewrites, or deletes a record it did not write", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const recordPath = fixture.files.pathFor(session.session_id);
    const foreign = {
      version: 1,
      session_id: session.session_id,
      owner: {
        process_id: process.pid + 1,
        server_started_at: "2020-01-01T00:00:00.000Z",
      },
      created_at: "2020-01-01T00:00:00.000Z",
      source: { kind: "draft" },
      selected_entry: null,
      target_origins: [SECOND_ORIGIN],
      draft: null,
      send_count: 9,
      last_send_at: null,
    };
    await fixture.replay.closeAll();
    await writeFile(recordPath, `${JSON.stringify(foreign)}\n`, {
      mode: 0o600,
    });
    const before = await readFile(recordPath, "utf8");

    const status = await fixture.replay.sessionStatus({
      sessionId: session.session_id,
    });
    expect(status.ok).toBe(false);
    expect(status.ok ? "" : status.error.userMessage).toContain(
      "did not write it",
    );
    await expect(
      fixture.replay.closeSession({ sessionId: session.session_id }),
    ).resolves.toMatchObject({ ok: false });
    expect(await readFile(recordPath, "utf8")).toBe(before);
    expect(fixture.transport.dispatched).toBe(0);
  });

  it("refuses a corrupt or stale-version record instead of treating it as absent", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const recordPath = fixture.files.pathFor(session.session_id);
    await fixture.replay.closeAll();
    await writeFile(recordPath, "{not json", "utf8");
    const status = await fixture.replay.sessionStatus({
      sessionId: session.session_id,
    });
    expect(status.ok).toBe(false);
    expect(status.ok ? "" : status.error.userMessage).toContain(
      "not valid JSON",
    );
  });
});

describe("replay send", () => {
  const verbatimSend = async (fixture: Awaited<ReturnType<typeof service>>) => {
    const session = await startDraftSession(fixture);
    const pending = fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: undefined,
    });
    (await firstDispatch(fixture)).settle(
      response({
        status: 403,
        headers: [
          ["content-type", "text/html"],
          ["set-cookie", "session=abc"],
        ],
        chunks: ["<html>forbidden</html>"],
      }),
    );
    const sent = await pending;
    if (!sent.ok) throw sent.error;
    return {
      fixture,
      session,
      sent,
      result: replaySendResultSchema.parse(sent.value.normalized_result),
    };
  };

  it("dispatches the selected request once with its exact wire bytes", async () => {
    const { fixture, sent, result } = await verbatimSend(await service());
    expect(fixture.transport.dispatched).toBe(1);
    expect(fixture.transport.requests[0]).toMatchObject({
      method: "POST",
      url: `${OPERATOR_ORIGIN}/v1/items`,
    });
    expect(fixture.transport.requests[0]?.headers).toEqual([
      { name: "authorization", value: SECRET },
      { name: "content-type", value: "application/json" },
      { name: "host", value: "api.example.test" },
      { name: "content-length", value: "7" },
    ]);
    expect(result).toMatchObject({
      entry_ordinal: null,
      outcome: "response",
      failure: null,
      retry: "none",
      request: {
        method: "POST",
        url: `${OPERATOR_ORIGIN}/v1/items`,
        origin: OPERATOR_ORIGIN,
        header_names: ["authorization", "content-type"],
        credential_header_names: ["authorization"],
        body_bytes: 7,
        body_present: true,
      },
    });
    const serialized = JSON.stringify(sent.value);
    expect(serialized).not.toContain("sk-live-0123456789");
    expect(serialized).not.toContain("forbidden");
    expect(serialized).not.toContain("session=abc");
  });

  it("reports a terminal 403 as a client-error observation", async () => {
    const { session, result } = await verbatimSend(await service());
    expect(result).toMatchObject({
      session_id: session.session_id,
      response: {
        status: 403,
        status_class: "client_error",
        content_type_class: "html",
        header_names: ["content-type", "set-cookie"],
        size_class: "up_to_1_kib",
        bytes_observed: 22,
        body_truncated: false,
        dump: null,
      },
    });
    expect(result.redirect_chain).toEqual([
      {
        step: 0,
        method: "POST",
        url: `${OPERATOR_ORIGIN}/v1/items`,
        origin: OPERATOR_ORIGIN,
        status: 403,
        status_class: "client_error",
        location: null,
      },
    ]);
  });

  it("applies a structured mutation to the wire bytes and keeps one dispatch", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const pending = fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {
        method: "PUT",
        setHeaders: [{ name: "x-probe", value: "1" }],
        removeHeaders: ["content-type"],
        body: { kind: "text", text: "hello" },
      },
      timeoutMs: 1_000,
      followRedirects: true,
      dump: undefined,
    });
    (await firstDispatch(fixture)).settle(response({ status: 204 }));
    const sent = await pending;
    expect(sent.ok).toBe(true);
    expect(fixture.transport.dispatched).toBe(1);
    expect(fixture.transport.requests[0]?.headers).toEqual([
      { name: "authorization", value: SECRET },
      { name: "x-probe", value: "1" },
      { name: "host", value: "api.example.test" },
      { name: "content-length", value: "5" },
    ]);
    const result = replaySendResultSchema.parse(
      sent.ok ? sent.value.normalized_result : {},
    );
    expect(result.request.method).toBe("PUT");
    expect(result.request.body_bytes).toBe(5);
    expect(result.response).toMatchObject({
      status: 204,
      status_class: "success",
      content_type_class: "absent",
      size_class: "empty",
      bytes_observed: 0,
    });
    expect(result.entry_ordinal).toBe(0);
  });
});

describe("replay redirects", () => {
  it("follows an approved redirect, rewrites the method, and drops credentials cross-origin", async () => {
    const fixture = await service({
      origins: [OPERATOR_ORIGIN, SECOND_ORIGIN],
    });
    const session = await startCaptureSession(fixture, [
      OPERATOR_ORIGIN,
      SECOND_ORIGIN,
    ]);
    const pending = fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 2_000,
      followRedirects: true,
      dump: undefined,
    });
    (await nextDispatch(fixture)).settle(
      response({
        status: 302,
        headers: [["location", `${SECOND_ORIGIN}/v1/next`]],
      }),
    );
    (await nextDispatch(fixture)).settle(
      response({ status: 200, chunks: ["ok"] }),
    );
    const sent = await pending;
    expect(sent.ok).toBe(true);
    expect(fixture.transport.dispatched).toBe(2);
    expect(fixture.transport.requests[1]).toMatchObject({
      method: "GET",
      url: `${SECOND_ORIGIN}/v1/next`,
      body: undefined,
    });
    expect(
      fixture.transport.requests[1]?.headers.map(({ name }) => name),
    ).not.toContain("authorization");
    const result = replaySendResultSchema.parse(
      sent.ok ? sent.value.normalized_result : {},
    );
    expect(result.outcome).toBe("response");
    expect(result.redirect_chain.map(({ status }) => status)).toEqual([
      302, 200,
    ]);
    expect(result.redirect_chain[0]?.location).toEqual({
      url: `${SECOND_ORIGIN}/v1/next`,
      origin: SECOND_ORIGIN,
      approved: true,
    });
  });

  it("stops a redirect that leaves the approved origins without a second dispatch", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const pending = fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: undefined,
    });
    (await firstDispatch(fixture)).settle(
      response({
        status: 301,
        headers: [["location", "https://evil.test/phish"]],
      }),
    );
    const sent = await pending;
    expect(sent.ok).toBe(true);
    expect(fixture.transport.dispatched).toBe(1);
    const result = replaySendResultSchema.parse(
      sent.ok ? sent.value.normalized_result : {},
    );
    expect(result.outcome).toBe("redirect_blocked");
    expect(result.response).toBeNull();
    expect(result.redirect_chain[0]?.location).toEqual({
      url: "https://evil.test/phish",
      origin: null,
      approved: false,
    });
  });

  it("treats a transport failure as a terminal observation with no retry", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const pending = fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: undefined,
    });
    (await firstDispatch(fixture)).fail(
      Object.assign(new Error("connect ECONNREFUSED"), {
        code: "ECONNREFUSED",
      }),
    );
    const sent = await pending;
    expect(sent.ok).toBe(true);
    expect(fixture.transport.dispatched).toBe(1);
    const result = replaySendResultSchema.parse(
      sent.ok ? sent.value.normalized_result : {},
    );
    expect(result.outcome).toBe("no_response");
    expect(result.failure).toEqual({
      kind: "connection",
      message: "connect ECONNREFUSED",
    });
    expect(result.response).toBeNull();
  });
});

describe("replay cancellation and deadlines", () => {
  it("returns typed cancellation while the response is still pending", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const controller = new AbortController();
    const pending = fixture.replay.send(
      {
        sessionId: session.session_id,
        entryOrdinal: undefined,
        mutation: {},
        timeoutMs: 5_000,
        followRedirects: true,
        dump: undefined,
      },
      { signal: controller.signal },
    );
    await Promise.resolve();
    expect(fixture.transport.dispatched).toBe(1);
    const reason = new Error("analyst stopped the send");
    controller.abort(reason);
    const sent = await pending;
    expect(sent.ok).toBe(false);
    if (sent.ok) return;
    expect(sent.error._tag).toBe("AnalysisCancelledError");
    expect(sent.error.cause).toBe(reason);
    expect(fixture.transport.dispatched).toBe(1);
    const status = await fixture.replay.sessionStatus({
      sessionId: session.session_id,
    });
    expect(
      replaySessionStatusResultSchema.parse(
        status.ok ? status.value.normalized_result : {},
      ),
    ).toMatchObject({ send_count: 0 });
  });

  it("returns typed cancellation during the body and removes a partial dump", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const body = controllableBody();
    const dumpPath = join(fixture.directory, "body.bin");
    const controller = new AbortController();
    const pending = fixture.replay.send(
      {
        sessionId: session.session_id,
        entryOrdinal: undefined,
        mutation: {},
        timeoutMs: 5_000,
        followRedirects: true,
        dump: { path: dumpPath, overwrite: false },
      },
      { signal: controller.signal },
    );
    (await firstDispatch(fixture)).settle(response({ status: 200, body }));
    body.push("partial");
    const reason = new Error("analyst cancelled during the body");
    controller.abort(reason);
    body.push("late");
    const sent = await pending;
    expect(sent.ok).toBe(false);
    if (sent.ok) return;
    expect(sent.error._tag).toBe("AnalysisCancelledError");
    expect(sent.error.cause).toBe(reason);
    await expect(stat(dumpPath)).rejects.toThrow();
  });

  it("expires at its bounded deadline without retrying", async () => {
    const fixture = await service();
    const session = await startCaptureSession(fixture);
    const sent = await fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 5,
      followRedirects: true,
      dump: undefined,
    });
    expect(sent.ok).toBe(false);
    if (sent.ok) return;
    expect(sent.error._tag).toBe("AnalysisTimeoutError");
    expect(sent.error.userMessage).toContain("No retry was attempted");
    expect(fixture.transport.dispatched).toBe(1);
  });
});

describe("replay response retention", () => {
  it("writes the raw body owner-only with its digest and refuses to overwrite", async () => {
    const fixture = await service();
    const session = await startDraftSession(fixture);
    const dumpPath = join(fixture.directory, "body.bin");
    const first = fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: { path: dumpPath, overwrite: false },
    });
    (await firstDispatch(fixture)).settle(
      response({ status: 200, chunks: ["raw", "-", "body"] }),
    );
    const sent = await first;
    expect(sent.ok).toBe(true);
    const result = replaySendResultSchema.parse(
      sent.ok ? sent.value.normalized_result : {},
    );
    expect(await readFile(dumpPath, "utf8")).toBe("raw-body");
    if (process.platform !== "win32")
      expect((await stat(dumpPath)).mode & 0o777).toBe(0o600);
    expect(result.response?.dump).toMatchObject({
      path: dumpPath,
      bytes: 8,
      truncated: false,
    });
    expect(sent.ok ? sent.value.locations : []).toContainEqual({
      kind: "artifact-path",
      path: dumpPath,
    });

    const again = await fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: { path: dumpPath, overwrite: false },
    });
    expect(again.ok).toBe(false);
    expect(again.ok ? "" : again.error.userMessage).toContain("already exists");
    expect(await readFile(dumpPath, "utf8")).toBe("raw-body");
    expect(fixture.transport.dispatched).toBe(1);

    const overwritten = fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: { path: dumpPath, overwrite: true },
    });
    (await nextDispatch(fixture)).settle(
      response({ status: 200, chunks: ["second"] }),
    );
    const replaced = await overwritten;
    expect(replaced.ok).toBe(true);
    expect(await readFile(dumpPath, "utf8")).toBe("second");
  });

  it("counts the retained prefix and marks a body over the inline budget truncated", async () => {
    const fixture = await service();
    const session = await startDraftSession(fixture);
    const pending = fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 5_000,
      followRedirects: true,
      dump: undefined,
    });
    (await firstDispatch(fixture)).settle(
      response({
        status: 200,
        body: (() => {
          const body = controllableBody();
          for (let index = 0; index < 17; index += 1)
            body.push(Buffer.alloc(64 * 1_024, 0x61));
          body.end();
          return body;
        })(),
      }),
    );
    const sent = await pending;
    expect(sent.ok).toBe(true);
    const result = replaySendResultSchema.parse(
      sent.ok ? sent.value.normalized_result : {},
    );
    expect(result.response).toMatchObject({
      bytes_observed: 1_024 * 1_024,
      body_truncated: true,
      size_class: "up_to_1_mib",
      dump: null,
    });
    expect(fixture.transport.dispatched).toBe(1);
  });
});

describe("replay session selection", () => {
  it("requires an entry when a capture session selected none", async () => {
    const fixture = await service();
    const started = await fixture.replay.startSession({
      source: { kind: "har", path: fixture.capture, entryOrdinal: undefined },
      targetOrigins: [OPERATOR_ORIGIN],
    });
    expect(started.ok).toBe(true);
    const session = replaySessionStartResultSchema.parse(
      started.ok ? started.value.normalized_result : {},
    );
    expect(session.selected).toBeNull();
    expect(session.entries).toHaveLength(1);
    expect(session.entry_count).toBe(1);
    const sent = await fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: undefined,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: undefined,
    });
    expect(sent.ok).toBe(false);
    expect(fixture.transport.dispatched).toBe(0);
  });

  it("refuses an unreplayable entry with its reason", async () => {
    const fixture = await service();
    await writeFile(
      fixture.capture,
      captureText([
        {
          postData: {
            mimeType: "application/x-www-form-urlencoded",
            params: [{ name: "a", value: "1" }],
          },
        },
      ]),
      "utf8",
    );
    const started = await fixture.replay.startSession({
      source: { kind: "har", path: fixture.capture, entryOrdinal: undefined },
      targetOrigins: [OPERATOR_ORIGIN],
    });
    expect(started.ok).toBe(true);
    const session = replaySessionStartResultSchema.parse(
      started.ok ? started.value.normalized_result : {},
    );
    expect(session.selected).toBeNull();
    const sent = await fixture.replay.send({
      sessionId: session.session_id,
      entryOrdinal: 0,
      mutation: {},
      timeoutMs: 1_000,
      followRedirects: true,
      dump: undefined,
    });
    expect(sent.ok).toBe(false);
    expect(sent.ok ? "" : sent.error.userMessage).toContain(
      "cannot be replayed",
    );
  });

  it("counts only its own sends and persists the counter", async () => {
    const fixture = await service();
    const session = await startDraftSession(fixture);
    for (const chunk of ["a", "b"]) {
      const pending = fixture.replay.send({
        sessionId: session.session_id,
        entryOrdinal: undefined,
        mutation: {},
        timeoutMs: 1_000,
        followRedirects: true,
        dump: undefined,
      });
      (await nextDispatch(fixture)).settle(
        response({ status: 200, chunks: [chunk] }),
      );
      const sent = await pending;
      expect(sent.ok).toBe(true);
    }
    const status = await fixture.replay.sessionStatus({
      sessionId: session.session_id,
    });
    const parsed = replaySessionStatusResultSchema.parse(
      status.ok ? status.value.normalized_result : {},
    );
    expect(parsed.send_count).toBe(2);
    expect(parsed.last_send_at).toMatch(/^\d{4}-/u);
    const record = JSON.parse(
      await readFile(fixture.files.pathFor(session.session_id), "utf8"),
    ) as { send_count: number };
    expect(record.send_count).toBe(2);
  });
});
