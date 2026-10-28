import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import type { Device, DeviceManager, Script, Session } from "frida";
import { expect, it, onTestFinished } from "vitest";

import type { Evidence } from "../../../src/domain/evidence.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { FridaInstrumentationManager } from "../../../src/frida/FridaInstrumentationManager.js";
import { FRIDA_RPC_INVENTORY_EPILOGUE } from "../../../src/frida/fridaRpcInventory.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const gate = () => {
  let markEntered = () => {};
  let release = () => {};
  const entered = new Promise<void>((resolve) => {
    markEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    entered,
    release,
    async wait() {
      markEntered();
      await released;
    },
  };
};

const rpcFixture = () => {
  const loadedSources: string[] = [];
  const exports = new Map<
    string,
    Record<string, (...args: unknown[]) => Promise<unknown>>
  >();
  const controls = {
    inventory: undefined as readonly unknown[] | null | undefined,
    detached: false,
  };
  let onDetached: (() => void) | undefined;
  const nativeSession: Session = {
    pid: 512,
    detached: {
      connect(listener) {
        onDetached = listener;
      },
      disconnect() {
        onDetached = undefined;
      },
    },
    isDetached: () => controls.detached,
    async detach() {
      controls.detached = true;
      onDetached?.();
    },
    async createScript(source) {
      loadedSources.push(source);
      const surface: Record<string, (...args: unknown[]) => Promise<unknown>> =
        {};
      exports.set(source, surface);
      let destroyed = false;
      let listener:
        | ((message: { type: string; payload?: unknown }, data: null) => void)
        | undefined;
      const script: Script = {
        get isDestroyed() {
          return destroyed;
        },
        exports: new Proxy({} as Script["exports"], {
          get(_target, property) {
            return Reflect.get(surface, property);
          },
        }),
        message: {
          connect(handler) {
            listener = handler as typeof listener;
          },
          disconnect() {
            listener = undefined;
          },
        },
        async load() {
          if (controls.inventory !== undefined)
            listener?.(
              {
                type: "send",
                payload: { __rea_frida_rpc_inventory__: controls.inventory },
              },
              null,
            );
        },
        async unload() {
          destroyed = true;
        },
      };
      return script;
    },
  };
  const device: Device = {
    id: "local",
    name: "Local fixture",
    type: "local",
    async enumerateProcesses() {
      return [{ pid: 512, name: "fixture" }];
    },
    async getProcessByPid() {
      return { pid: 512, name: "fixture" };
    },
    async spawn() {
      return 512;
    },
    async resume() {},
    async attach() {
      return nativeSession;
    },
  };
  const deviceManager: DeviceManager = {
    async enumerateDevices() {
      return [device];
    },
    async getDeviceById() {
      return device;
    },
    async addRemoteDevice() {
      return device;
    },
    async removeRemoteDevice() {},
  };
  return { controls, loadedSources, exports, deviceManager };
};

const connectRpcClient = async () => {
  const native = rpcFixture();
  const manager = new FridaInstrumentationManager({
    deviceManager: native.deviceManager,
  });
  const session = createTestBinarySession(() => {
    throw new Error("Binary provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { fridaInstrumentation: manager },
  );
  const client = new Client({ name: "frida-rpc", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await manager.closeAll();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const start = async (mode: "attach" | "spawn" = "attach") => {
    const result = await client.callTool({
      name: "start_frida_session",
      arguments:
        mode === "attach"
          ? { mode, device_id: "local", pid: 512 }
          : { mode, device_id: "local", program: "/fixture" },
    });
    const parsed = toolContract("start_frida_session").outputSchema.parse(
      result.structuredContent,
    );
    return { sessionId: parsed.session_id, mode: parsed.mode };
  };
  const load = async (sessionId: string, source = "send(1)") => {
    const result = await client.callTool({
      name: "load_frida_script",
      arguments: { session_id: sessionId, source_kind: "inline", source },
    });
    const parsed = toolContract("load_frida_script").outputSchema.parse(
      result.structuredContent,
    );
    return parsed.normalized_result.script_id;
  };
  const surface = (source = "send(1)") => {
    const found = native.exports.get(
      `${source}${FRIDA_RPC_INVENTORY_EPILOGUE}`,
    );
    if (found === undefined) throw new Error("Missing script surface");
    return found;
  };
  return { ...native, manager, session, server, client, start, load, surface };
};

const untrusted = { provenance: { untrusted_content: true } };

it("lists and calls reported remote exports as untrusted target data", async () => {
  const fixture = await connectRpcClient();
  fixture.controls.inventory = [
    { name: "snapshot", parameters: 0 },
    { name: "mutate", parameters: 2 },
  ];
  const { sessionId, mode } = await fixture.start();
  const scriptId = await fixture.load(sessionId);
  expect(fixture.loadedSources.at(-1)).toBe(
    `send(1)${FRIDA_RPC_INVENTORY_EPILOGUE}`,
  );
  Object.assign(fixture.surface("send(1)"), {
    snapshot: async () => ({ threads: 4, names: ["main", "worker"] }),
  });

  const listed = await fixture.client.callTool({
    name: "frida_rpc_list",
    arguments: { session_id: sessionId, script_id: scriptId },
  });
  expect(listed.isError).not.toBe(true);
  expect(listed._meta).toMatchObject(untrusted);
  expect(
    toolContract("frida_rpc_list").outputSchema.parse(listed.structuredContent)
      .normalized_result,
  ).toEqual({
    session_id: sessionId,
    script_id: scriptId,
    state: "observed",
    exports: [
      { name: "snapshot", parameters: 0 },
      { name: "mutate", parameters: 2 },
    ],
    exports_truncated: false,
  });

  const called = await fixture.client.callTool({
    name: "frida_rpc_call",
    arguments: {
      session_id: sessionId,
      script_id: scriptId,
      method: "snapshot",
    },
  });
  expect(called.isError).not.toBe(true);
  expect(called._meta).toMatchObject(untrusted);
  const result = toolContract("frida_rpc_call").outputSchema.parse(
    called.structuredContent,
  ).normalized_result;
  expect(result).toMatchObject({
    session_id: sessionId,
    script_id: scriptId,
    method: "snapshot",
    mutation_authority: { kind: "session-grant", mode },
    value: { threads: 4, names: ["main", "worker"] },
    value_truncated: false,
    value_capture_limit: null,
  });
  expect(result.duration_ms).toBeGreaterThanOrEqual(0);

  const tools = (await fixture.client.listTools()).tools;
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  for (const name of ["frida_rpc_list", "frida_rpc_call"] as const) {
    const tool = tools.find((candidate) => candidate.name === name);
    if (tool?.inputSchema === undefined || tool.outputSchema === undefined)
      throw new Error(`Missing ${name} schemas`);
    expect(ajv.validateSchema(tool.inputSchema)).toBe(true);
    expect(ajv.validateSchema(tool.outputSchema as AnySchema)).toBe(true);
  }
  const callTool = tools.find(
    (candidate) => candidate.name === "frida_rpc_call",
  );
  if (
    callTool?.inputSchema === undefined ||
    callTool.outputSchema === undefined
  )
    throw new Error("Missing frida_rpc_call schema");
  expect(
    ajv.validate(callTool.inputSchema as AnySchema, {
      session_id: sessionId,
      script_id: scriptId,
      method: "snapshot",
    }),
  ).toBe(true);
  expect(
    ajv.validate(callTool.inputSchema as AnySchema, {
      session_id: sessionId,
      script_id: scriptId,
      method: "snapshot",
      timeout_ms: 0,
    }),
  ).toBe(false);
});

it("keeps spawn-granted rpc replies under the spawned session's authority", async () => {
  const fixture = await connectRpcClient();
  fixture.controls.inventory = [{ name: "ping", parameters: 0 }];
  const { sessionId, mode } = await fixture.start("spawn");
  const scriptId = await fixture.load(sessionId, "send(spawn)");
  Object.assign(fixture.surface("send(spawn)"), {
    ping: async () => "pong",
  });
  const called = await fixture.client.callTool({
    name: "frida_rpc_call",
    arguments: { session_id: sessionId, script_id: scriptId, method: "ping" },
  });
  expect(called.isError).not.toBe(true);
  expect(called._meta).toMatchObject(untrusted);
  expect(
    toolContract("frida_rpc_call").outputSchema.parse(called.structuredContent)
      .normalized_result,
  ).toMatchObject({
    method: "ping",
    mutation_authority: { kind: "session-grant", mode },
    value: "pong",
  });
  expect(mode).toBe("spawn");
});

it("discards an rpc reply that arrives after the client stops waiting", async () => {
  const fixture = await connectRpcClient();
  fixture.controls.inventory = [{ name: "slow", parameters: 0 }];
  const { sessionId } = await fixture.start();
  const scriptId = await fixture.load(sessionId, "send(slow)");
  const held = gate();
  onTestFinished(held.release);
  Object.assign(fixture.surface("send(slow)"), {
    async slow() {
      await held.wait();
      return { observed: "cancel-then-reply" };
    },
  });
  const controller = new AbortController();
  const call = fixture.client.callTool(
    {
      name: "frida_rpc_call",
      arguments: {
        session_id: sessionId,
        script_id: scriptId,
        method: "slow",
        timeout_ms: 60_000,
      },
    },
    { signal: controller.signal },
  );
  const rejected = expect(call).rejects.toThrow("cancel rpc wait");
  await held.entered;
  controller.abort(new Error("cancel rpc wait"));
  await rejected;
  held.release();
  await fixture.client.ping();
  const bundle = await fixture.client.callTool({
    name: "get_evidence_bundle",
    arguments: {},
  });
  expect(bundle.isError).not.toBe(true);
  expect(
    JSON.stringify(bundle.structuredContent),
    "a reply REA stopped waiting for is never reported as an observation",
  ).not.toContain("cancel-then-reply");
  expect(fixture.manager.status(sessionId)?.scripts).toHaveLength(1);
});

it("reports a typed ownership failure after the script unloads", async () => {
  const fixture = await connectRpcClient();
  fixture.controls.inventory = [{ name: "ping", parameters: 0 }];
  const { sessionId } = await fixture.start();
  const scriptId = await fixture.load(sessionId);
  const unloaded = await fixture.client.callTool({
    name: "unload_frida_script",
    arguments: { session_id: sessionId, script_id: scriptId },
  });
  expect(unloaded.isError).not.toBe(true);
  for (const [name, arguments_] of [
    ["frida_rpc_list", { session_id: sessionId, script_id: scriptId }],
    [
      "frida_rpc_call",
      { session_id: sessionId, script_id: scriptId, method: "ping" },
    ],
  ] as const) {
    const refused = await fixture.client.callTool({
      name,
      arguments: arguments_,
    });
    expect(refused.isError, name).toBe(true);
    expect(refused._meta, name).toMatchObject(untrusted);
    expect(JSON.stringify(refused.content)).toContain(
      "does not establish ownership after unload",
    );
  }
});

it("returns the rpc deadline as a typed timeout without claiming target cancellation", async () => {
  const fixture = await connectRpcClient();
  fixture.controls.inventory = [{ name: "never", parameters: 0 }];
  const { sessionId } = await fixture.start();
  const scriptId = await fixture.load(sessionId, "send(never)");
  Object.assign(fixture.surface("send(never)"), {
    never: () => new Promise(() => {}),
  });
  const called = await fixture.client.callTool({
    name: "frida_rpc_call",
    arguments: {
      session_id: sessionId,
      script_id: scriptId,
      method: "never",
      timeout_ms: 10,
    },
  });
  expect(called.isError).toBe(true);
  expect(called._meta).toMatchObject(untrusted);
  const text = JSON.stringify(called.content);
  expect(text).toContain("frida_rpc_call");
  expect(text).toContain("cannot cancel");
});

it("keeps an unreported rpc surface unknown rather than empty", async () => {
  const fixture = await connectRpcClient();
  const { sessionId } = await fixture.start();
  const scriptId = await fixture.load(sessionId, "send(quiet)");
  const listed = await fixture.client.callTool({
    name: "frida_rpc_list",
    arguments: { session_id: sessionId, script_id: scriptId },
  });
  expect(listed.isError).not.toBe(true);
  const evidence: Evidence = toolContract("frida_rpc_list").outputSchema.parse(
    listed.structuredContent,
  );
  expect(evidence.normalized_result).toMatchObject({
    state: "unreported",
    exports: [],
    exports_truncated: false,
  });
  expect(evidence.limitations.join("\n")).toContain("frida transport");
});
