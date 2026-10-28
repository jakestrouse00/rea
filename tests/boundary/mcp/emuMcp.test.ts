import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { EmuProvider } from "../../../src/emu/EmuProvider.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { writeFakeEmuBridge } from "../providers/emu/fakeUnicornBridge.js";

const untrusted = { provenance: { untrusted_content: true } };

const connectClient = async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-emu-mcp-"));
  const { environment } = await writeFakeEmuBridge(root, {});
  const emu = new EmuProvider({ environment });
  const session = createTestBinarySession(() => {
    throw new Error("Binary provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { emu, environment },
  );
  const client = new Client({ name: "emu", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    root,
    client,
    async close() {
      await client.close();
      await server.close();
      await session.close();
      await emu.close();
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

describe("emulation MCP surface", () => {
  it("advertises both emulation tools with valid schemas", async () => {
    const client = active.client!;
    const tools = (await client.client.listTools()).tools;
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    const names = ["emulate_function_isolated", "assemble_bytes"] as const;
    for (const name of names) {
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
    }
    const emulate = tools.find(
      (candidate) => candidate.name === "emulate_function_isolated",
    )!;
    expect(
      ajv.validate(emulate.inputSchema as AnySchema, { arch: "x86_64" }),
    ).toBe(false);
    expect(
      ajv.validate(emulate.inputSchema as AnySchema, {
        arch: "x86_64",
        source: { kind: "hex", hex: "c3" },
      }),
    ).toBe(true);
  });

  it("returns typed values and hashes for one bounded emulation", async () => {
    const { result, value } = await call(
      "emulate_function_isolated",
      {
        arch: "x86_64",
        source: { kind: "hex", hex: "4889f8c3" },
        observe_registers: ["rax"],
      },
      active.client!,
    );
    expect(value).toMatchObject({
      arch: "x86_64",
      entry: "0x100000",
      exit: "returned",
      call_count: 2,
      edges: ["0x100000->0x100000"],
      registers: [{ name: "rax", value: "0x2a" }],
      coverage: "complete",
    });
    expect(JSON.stringify(value)).not.toContain("4889f8c3");
    expect(result._meta).toMatchObject(untrusted);
  });

  it("returns the assembled bytes for one patch slice", async () => {
    const { value } = await call(
      "assemble_bytes",
      { arch: "x86_64", base_address: "0x401000", assembly: "ret" },
      active.client!,
    );
    expect(value).toMatchObject({
      arch: "x86_64",
      base_address: "0x401000",
      assembly: "ret",
      bytes_hex: "c3",
      size: 1,
    });
  });

  it("refuses an unselected lane as a typed capability failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-emu-mcp-unset-"));
    const emu = new EmuProvider({ environment: {} });
    const session = createTestBinarySession(() => {
      throw new Error("Binary provider must not start");
    });
    const server = createServer({ kind: "session", session }, { emu });
    const client = new Client({ name: "emu-unset", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const result = await client.callTool({
        name: "assemble_bytes",
        arguments: { arch: "x86_64", assembly: "ret" },
      });
      const failure = parseMcpToolError(result);
      expect(failure.error.code).toBe("capability_unavailable");
      expect(failure.error.message).toContain("REA_UNICORN_PYTHON");
    } finally {
      await client.close();
      await server.close();
      await session.close();
      await emu.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});
