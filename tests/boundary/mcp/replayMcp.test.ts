import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { toolContract } from "../../../src/contracts/toolContracts.js";
import {
  replaySendResultSchema,
  replaySessionStartResultSchema,
} from "../../../src/domain/replay/replayObservation.js";
import { REPLAY_ALLOWED_ORIGINS_ENV } from "../../../src/domain/replay/replayOrigins.js";
import { ReplayService } from "../../../src/replay/ReplayService.js";
import { ReplaySessionFiles } from "../../../src/replay/ReplaySessionFile.js";
import type { ReplayTransport } from "../../../src/replay/ReplayTransport.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const OPERATOR_ORIGIN = "https://api.example.test";
const SECRET = "Bearer sk-live-mcp";
const untrusted = { provenance: { untrusted_content: true } };

const captureText = JSON.stringify({
  log: {
    version: "1.2",
    creator: { name: "fixture", version: "1" },
    entries: [
      {
        startedDateTime: "2026-01-01T00:00:00.000Z",
        time: 1,
        request: {
          method: "GET",
          url: `${OPERATOR_ORIGIN}/v1/items`,
          httpVersion: "HTTP/1.1",
          headers: [{ name: "authorization", value: SECRET }],
          queryString: [],
          cookies: [],
          headersSize: -1,
          bodySize: 0,
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
      },
    ],
  },
});

const connectClient = async (allowlist: string | undefined) => {
  const directory = await mkdtemp(join(tmpdir(), "rea-replay-mcp-"));
  const capture = join(directory, "capture.har");
  await writeFile(capture, captureText, "utf8");
  const transport: ReplayTransport = {
    async send() {
      return {
        status: 200,
        headers: [{ name: "content-type", value: "application/json" }],
        body: (async function* () {
          yield Buffer.from('{"ok":true}', "utf8");
        })(),
        cancel: async () => undefined,
      };
    },
  };
  const replay = new ReplayService({
    environment:
      allowlist === undefined
        ? {}
        : { [REPLAY_ALLOWED_ORIGINS_ENV]: allowlist },
    transport,
    sessionFiles: new ReplaySessionFiles(join(directory, "state")),
  });
  const session = createTestBinarySession(() => {
    throw new Error("Binary provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { replay, environment: { [REPLAY_ALLOWED_ORIGINS_ENV]: allowlist ?? "" } },
  );
  const client = new Client({ name: "replay", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    directory,
    capture,
    client,
    async close() {
      await client.close();
      await server.close();
      await session.close();
      await rm(directory, { recursive: true, force: true });
    },
  };
};

const active = {
  client: undefined as Awaited<ReturnType<typeof connectClient>> | undefined,
};

beforeAll(async () => {
  active.client = await connectClient(JSON.stringify([OPERATOR_ORIGIN]));
});

afterAll(async () => {
  await active.client?.close();
});

describe("replay MCP surface", () => {
  it("advertises the four replay tools with valid schemas", async () => {
    const client = active.client!;
    const tools = (await client.client.listTools()).tools;
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    for (const name of [
      "http_replay_session_start",
      "http_replay_send",
      "http_replay_session_status",
      "http_replay_session_close",
    ] as const) {
      const tool = tools.find((candidate) => candidate.name === name);
      if (tool?.inputSchema === undefined || tool.outputSchema === undefined)
        throw new Error(`Missing ${name} schemas`);
      expect(ajv.validateSchema(tool.inputSchema)).toBe(true);
      expect(ajv.validateSchema(tool.outputSchema as AnySchema)).toBe(true);
      expect(tool.annotations).toMatchObject({
        openWorldHint: name === "http_replay_send",
      });
    }
    const start = tools.find(
      (candidate) => candidate.name === "http_replay_session_start",
    )!;
    expect(
      ajv.validate(start.inputSchema as AnySchema, {
        capture_path: client.capture,
        target_origins: [],
      }),
    ).toBe(false);
    const send = tools.find(
      (candidate) => candidate.name === "http_replay_send",
    )!;
    expect(
      ajv.validate(send.inputSchema as AnySchema, {
        session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        timeout_ms: 0,
      }),
    ).toBe(false);
    expect(
      ajv.validate(send.inputSchema as AnySchema, {
        session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        timeout_ms: 60001,
      }),
    ).toBe(false);
  });

  it("starts, sends, reports, and closes through the public tools", async () => {
    const client = active.client!;
    const started = await client.client.callTool({
      name: "http_replay_session_start",
      arguments: {
        capture_path: client.capture,
        entry_ordinal: 0,
        target_origins: [OPERATOR_ORIGIN],
      },
    });
    expect(started.isError).not.toBe(true);
    expect(started._meta).toMatchObject(untrusted);
    const session = replaySessionStartResultSchema.parse(
      toolContract("http_replay_session_start").outputSchema.parse(
        started.structuredContent,
      ).normalized_result,
    );

    const sent = await client.client.callTool({
      name: "http_replay_send",
      arguments: { session_id: session.session_id },
    });
    expect(sent.isError).not.toBe(true);
    expect(sent._meta).toMatchObject(untrusted);
    const result = replaySendResultSchema.parse(
      toolContract("http_replay_send").outputSchema.parse(
        sent.structuredContent,
      ).normalized_result,
    );
    expect(result).toMatchObject({
      session_id: session.session_id,
      entry_ordinal: 0,
      outcome: "response",
      retry: "none",
    });
    expect(result.response).toMatchObject({
      status: 200,
      status_class: "success",
      content_type_class: "json",
      body_truncated: false,
    });
    expect(JSON.stringify(sent.structuredContent)).not.toContain("sk-live-mcp");
    expect(JSON.stringify(sent.structuredContent)).not.toContain('"ok":true');

    const status = await client.client.callTool({
      name: "http_replay_session_status",
      arguments: { session_id: session.session_id },
    });
    expect(status.isError).not.toBe(true);
    expect(status.structuredContent).toMatchObject({
      normalized_result: { send_count: 1, state: "open" },
    });

    const closed = await client.client.callTool({
      name: "http_replay_session_close",
      arguments: { session_id: session.session_id },
    });
    expect(closed.isError).not.toBe(true);
    const again = await client.client.callTool({
      name: "http_replay_session_status",
      arguments: { session_id: session.session_id },
    });
    expect(again.isError).toBe(true);

    // A declared origin with a path is refused by the owner, not by the
    // advertised schema, which cannot carry the origin grammar.
    const pathOrigin = await client.client.callTool({
      name: "http_replay_session_start",
      arguments: {
        capture_path: client.capture,
        target_origins: ["https://api.example.test/v1"],
      },
    });
    expect(pathOrigin.isError).toBe(true);

    // The cross-field "exactly one source" rule is not expressible in the
    // advertised JSON Schema; the handler refuses it before creating a session.
    const both = await client.client.callTool({
      name: "http_replay_session_start",
      arguments: {
        capture_path: client.capture,
        request: { method: "GET", url: `${OPERATOR_ORIGIN}/x` },
        target_origins: [OPERATOR_ORIGIN],
      },
    });
    expect(both.isError).toBe(true);
    expect(JSON.stringify(both.content)).toContain("exactly one source");
  });

  it("reports a disabled request plane as a typed configuration refusal", async () => {
    const disabled = await connectClient(undefined);
    try {
      const refused = await disabled.client.callTool({
        name: "http_replay_session_start",
        arguments: {
          capture_path: disabled.capture,
          entry_ordinal: 0,
          target_origins: [OPERATOR_ORIGIN],
        },
      });
      expect(refused.isError).toBe(true);
      expect(JSON.stringify(refused.content)).toContain(
        REPLAY_ALLOWED_ORIGINS_ENV,
      );
    } finally {
      await disabled.close();
    }
  });
});
