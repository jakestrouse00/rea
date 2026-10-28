import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  mitmExportResultSchema,
  mitmInventoryResultSchema,
  mitmReplaySendResultSchema,
  mitmRuleClearResultSchema,
  mitmRuleSetResultSchema,
  mitmStartResultSchema,
  mitmStopResultSchema,
} from "../../../src/domain/mitm/mitmInterception.js";
import {
  MITM_ADDON_DIR_ENV,
  MITM_ADDON_FILE_NAME,
  MITM_COMMAND_ENV,
} from "../../../src/domain/mitm/mitmLimits.js";
import { REPLAY_ALLOWED_ORIGINS_ENV } from "../../../src/domain/replay/replayOrigins.js";
import { MitmSessionManager } from "../../../src/mitm/MitmSessionManager.js";
import type { ReplayTransport } from "../../../src/replay/ReplayTransport.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const ORIGIN = "https://api.example.test";
const untrusted = { provenance: { untrusted_content: true } };

const flowLine = (sequence: number) => ({
  type: "flow",
  sequence,
  at: "2026-01-01T00:00:00.000Z",
  duration_ms: 2,
  request: {
    method: "GET",
    origin: ORIGIN,
    path_template: "/v1/items/{integer}",
    header_names: ["accept", "authorization"],
    parameters: [{ name: "path_2", location: "path", type: "integer" }],
    content_type_class: "absent",
    body_bytes: 0,
    body_hold: null,
  },
  response: {
    status: 200,
    header_names: ["content-type"],
    content_type_class: "json",
    body_bytes: 4,
    body_hold: null,
    shape: {
      kind: "object",
      keys: [{ name: "id", type: "string" }],
      truncated: false,
    },
  },
  entry: null,
});

const connectClient = async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-mitm-mcp-"));
  const capture = join(directory, "capture");
  const addonDirectory = join(directory, "addon");
  await Promise.all([
    mkdir(capture, { recursive: true, mode: 0o700 }),
    mkdir(addonDirectory, { recursive: true }),
  ]);
  await writeFile(join(addonDirectory, MITM_ADDON_FILE_NAME), "# addon\n");
  const scenario = join(directory, "scenario.json");
  await writeFile(
    scenario,
    JSON.stringify({
      mode: "linger",
      steps: [
        {
          kind: "entry",
          sequence: 1,
          request: {
            method: "GET",
            url: `${ORIGIN}/v1/items/7`,
            headers: [["authorization", "Bearer sk-live-mcp"]],
            body: "",
          },
          response: { status: 200, body: "{}" },
        },
        {
          kind: "emit",
          line: {
            ...flowLine(1),
            entry: {
              path: join(capture, "entries", "1.json"),
              bytes: 10,
              sha256: "0".repeat(64),
            },
          },
        },
      ],
    }),
    "utf8",
  );
  const command = join(directory, "mitmdump");
  await writeFile(
    command,
    `#!/bin/sh\nexec "${process.execPath}" "${join(process.cwd(), "tests/fixtures/mitmFakeDaemon.mjs")}" "${scenario}"\n`,
    { mode: 0o700 },
  );
  await chmod(command, 0o700);
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
  const mitm = new MitmSessionManager({
    environment: {
      ...process.env,
      [MITM_COMMAND_ENV]: command,
      [MITM_ADDON_DIR_ENV]: addonDirectory,
      [REPLAY_ALLOWED_ORIGINS_ENV]: JSON.stringify([ORIGIN]),
    },
    transport,
    createRuntimeRoot: async () => ({
      path: capture,
      close: async () => {
        await rm(capture, { recursive: true, force: true });
      },
    }),
  });
  const session = createTestBinarySession(() => {
    throw new Error("Binary provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    {
      mitm,
      environment: { [REPLAY_ALLOWED_ORIGINS_ENV]: JSON.stringify([ORIGIN]) },
    },
  );
  const client = new Client({ name: "mitm", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    directory,
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
  active.client = await connectClient();
});

afterAll(async () => {
  await active.client?.close();
});

const call = async (
  client: NonNullable<typeof active.client>,
  name: string,
  arguments_: Record<string, unknown>,
) => {
  const result = await client.client.callTool({ name, arguments: arguments_ });
  expect(result.isError, name).not.toBe(true);
  return {
    result,
    value: (result.structuredContent as { normalized_result: unknown })
      .normalized_result,
  };
};

describe("interception MCP surface", () => {
  it("advertises the seven interception tools with valid schemas", async () => {
    const client = active.client!;
    const tools = (await client.client.listTools()).tools;
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    const names = [
      "start_interception_session",
      "read_interception_inventory",
      "export_endpoint_inventory",
      "proxy_rule_set",
      "proxy_rule_clear",
      "proxy_replay_send",
      "stop_interception_session",
    ] as const;
    for (const name of names) {
      const tool = tools.find((candidate) => candidate.name === name);
      if (tool?.inputSchema === undefined || tool.outputSchema === undefined)
        throw new Error(`Missing ${name} schemas`);
      expect(ajv.validateSchema(tool.inputSchema), name).toBe(true);
      expect(ajv.validateSchema(tool.outputSchema as AnySchema), name).toBe(
        true,
      );
      expect(tool.annotations, name).toMatchObject({
        openWorldHint:
          name === "start_interception_session" || name === "proxy_replay_send",
      });
    }
    const start = tools.find(
      (candidate) => candidate.name === "start_interception_session",
    )!;
    expect(
      ajv.validate(start.inputSchema as AnySchema, {
        target_app: "browser",
        target_origins: [],
      }),
    ).toBe(false);
    const rule = tools.find(
      (candidate) => candidate.name === "proxy_rule_set",
    )!;
    // "At least one predicate" is a cross-field rule the advertised schema
    // cannot carry, so the handler enforces it and this call is refused.
    const emptyRule = await client.client.callTool({
      name: "proxy_rule_set",
      arguments: {
        session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        match: { origins: [], path_prefixes: [], methods: [] },
        action: { kind: "request" },
      },
    });
    expect(emptyRule.isError).toBe(true);
    expect(
      ajv.validate(rule.inputSchema as AnySchema, {
        session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        match: { origins: [], path_prefixes: [], methods: [] },
        action: { kind: "request" },
      }),
    ).toBe(true);
  });

  it("starts, reads, exports, rewrites, replays, and stops through the public tools", async () => {
    const client = active.client!;
    const started = await call(client, "start_interception_session", {
      target_app: "android-app",
      app_identifier: "com.example.app",
      listen_port: 8_082,
      target_origins: [ORIGIN],
    });
    expect(started.result._meta).toMatchObject(untrusted);
    const session = mitmStartResultSchema.parse(started.value);

    const inventory = await vi.waitFor(
      async () => {
        const read = mitmInventoryResultSchema.parse(
          (
            await call(client, "read_interception_inventory", {
              session_id: session.session_id,
            })
          ).value,
        );
        expect(read.totals.flows).toBe(1);
        return read;
      },
      { timeout: 5_000, interval: 20 },
    );
    expect(inventory.session_id).toBe(session.session_id);
    expect(inventory.listen.proxy_url).toContain("8082");

    const exported = mitmExportResultSchema.parse(
      (
        await call(client, "export_endpoint_inventory", {
          session_id: session.session_id,
        })
      ).value,
    );
    expect(exported.endpoints).toHaveLength(1);
    expect(exported.file).toBeNull();

    const ruleId = "0b4f5d4c-1a52-4f7f-9a0e-9f9a1a0b3c4d";
    const armed = mitmRuleSetResultSchema.parse(
      (
        await call(client, "proxy_rule_set", {
          session_id: session.session_id,
          rule_id: ruleId,
          match: { path_prefixes: ["/v1"] },
          action: {
            kind: "request",
            set_headers: [{ name: "x-probe", value: "1" }],
          },
        })
      ).value,
    );
    expect(armed.state).toBe("armed");
    const cleared = mitmRuleClearResultSchema.parse(
      (
        await call(client, "proxy_rule_clear", {
          session_id: session.session_id,
          rule_id: ruleId,
        })
      ).value,
    );
    expect(cleared.release_reason).toBe("cleared");

    const replay = await call(client, "proxy_replay_send", {
      session_id: session.session_id,
      sequence: 1,
    });
    expect(replay.result._meta).toMatchObject(untrusted);
    expect(mitmReplaySendResultSchema.parse(replay.value).retry).toBe("none");

    const stopped = mitmStopResultSchema.parse(
      (
        await call(client, "stop_interception_session", {
          session_id: session.session_id,
        })
      ).value,
    );
    expect(stopped.capture.removed).toBe(true);
  });

  it("refuses an unknown session identity as a typed failure", async () => {
    const client = active.client!;
    const result = await client.client.callTool({
      name: "read_interception_inventory",
      arguments: { session_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7" },
    });
    expect(result.isError).toBe(true);
  });
});
