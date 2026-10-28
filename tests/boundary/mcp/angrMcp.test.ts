import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AngrProvider } from "../../../src/angr/AngrProvider.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { writeFakeAngrBridge } from "../providers/angr/fakeAngrBridge.js";

const untrusted = { provenance: { untrusted_content: true } };
const NAMES = [
  "find_paths_to_target",
  "run_symbolic_function_exploration",
  "recover_control_flow_angr",
] as const;

const connectClient = async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-angr-mcp-"));
  const { environment } = await writeFakeAngrBridge(root, {});
  const target = join(root, "firmware.bin");
  await writeFile(target, Buffer.from("firmware-bytes", "utf8"));
  const angr = new AngrProvider({ environment });
  const session = createTestBinarySession(() => {
    throw new Error("Binary provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { angr, environment },
  );
  const client = new Client({ name: "angr", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    root,
    target,
    client,
    async close() {
      await client.close();
      await server.close();
      await session.close();
      await angr.close();
      await rm(root, { recursive: true, force: true });
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
  name: string,
  arguments_: Record<string, unknown>,
  client: NonNullable<typeof active.client>,
) => {
  const result = await client.client.callTool({ name, arguments: arguments_ });
  expect(result.isError, name).not.toBe(true);
  return {
    result,
    value: (result.structuredContent as { normalized_result: unknown })
      .normalized_result as Record<string, unknown>,
  };
};

describe("symbolic-execution MCP surface", () => {
  it("advertises all three tools with valid schemas", async () => {
    const client = active.client!;
    const tools = (await client.client.listTools()).tools;
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    for (const name of NAMES) {
      const tool = tools.find((candidate) => candidate.name === name);
      if (tool?.inputSchema === undefined || tool.outputSchema === undefined)
        throw new Error(`Missing ${name} schemas`);
      expect(ajv.validateSchema(tool.inputSchema), name).toBe(true);
      expect(ajv.validateSchema(tool.outputSchema as AnySchema), name).toBe(
        true,
      );
      expect(tool.annotations, name).toMatchObject({
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: true,
      });
      expect(tool.description, name).toContain("REA_ANGR_BRIDGE_DIR");
    }
    const find = tools.find(
      (candidate) => candidate.name === "find_paths_to_target",
    )!;
    expect(
      ajv.validate(find.inputSchema as AnySchema, {
        path: "/artifacts/firmware.bin",
        entry: "0x401000",
      }),
    ).toBe(false);
    expect(
      ajv.validate(find.inputSchema as AnySchema, {
        path: "/artifacts/firmware.bin",
        entry: "0x401000",
        find_addresses: ["0x4010a0"],
      }),
    ).toBe(true);
  });

  it("returns one path as structure and marks the result untrusted", async () => {
    const client = active.client!;
    const { result, value } = await call(
      "find_paths_to_target",
      {
        path: client.target,
        entry: "0x401000",
        stdin_bytes: 8,
        find_addresses: ["0x4010a0"],
      },
      client,
    );
    expect(value).toMatchObject({
      reachable: true,
      termination: "find_hit",
      values_redacted: true,
      target: { entry: "0x401000" },
    });
    expect(JSON.stringify(value)).not.toContain('"value":');
    expect(result._meta).toMatchObject(untrusted);
  });

  it("returns a CFG for cross-checking and marks it untrusted", async () => {
    const client = active.client!;
    const { result, value } = await call(
      "recover_control_flow_angr",
      { path: client.target },
      client,
    );
    expect(value).toMatchObject({
      function_count: 1,
      edge_count: 1,
      blocks: [
        { address: "0x401000", size: 4, successors: ["0x401004"] },
        { address: "0x401004", size: 4, successors: [] },
      ],
    });
    expect(result._meta).toMatchObject(untrusted);
  });

  it("refuses an unselected lane as a typed capability failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-angr-mcp-unset-"));
    const angr = new AngrProvider({ environment: {} });
    const session = createTestBinarySession(() => {
      throw new Error("Binary provider must not start");
    });
    const server = createServer({ kind: "session", session }, { angr });
    const client = new Client({ name: "angr-unset", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const result = await client.callTool({
        name: "recover_control_flow_angr",
        arguments: { path: join(root, "firmware.bin") },
      });
      const failure = parseMcpToolError(result);
      expect(failure.error.code).toBe("capability_unavailable");
      expect(failure.error.message).toContain("REA_ANGR_PYTHON");
    } finally {
      await client.close();
      await server.close();
      await session.close();
      await angr.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});
