import { createHash } from "node:crypto";
import { chmod, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, test } from "vitest";

import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  payloadDigest,
  payloadSketch,
  type ProtocolMessageFact,
} from "../domain/protolearn/protocolMessage.js";
import type { ProtocolMessageReadResult } from "../domain/protolearn/protocolMessageSource.js";
import type { ProtocolModel } from "../domain/protolearn/protocolModel.js";
import { protocolModelSchema } from "../domain/protolearn/protocolModel.js";
import { protocolProbeResultSchema } from "../domain/protolearn/protocolProbe.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  writeFakeProbeRunner,
  type FakeProbeRunnerBehavior,
} from "../../tests/fixtures/protolearn/fakeProbeRunner.js";
import {
  ProtocolLearningProvider,
} from "./ProtocolLearningProvider.js";
import {
  sandboxedProbeLaunch,
  type ProtocolProbeLaunchPlanner,
} from "./ProtocolProbeRunner.js";
import { PROTOCOL_MODEL_STORE_MODEL_FILE } from "./ProtocolModelStore.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const encode = (values: readonly string[]): string[] =>
  values.map((value) => Buffer.from(value, "utf8").toString("base64"));

const conversation = (requests: readonly string[], responses: readonly string[]) => {
  const messages = [];
  for (const [index, request] of requests.entries()) {
    messages.push({ session: "lab", direction: "request" as const, body: request });
    const response = responses[index];
    if (response !== undefined)
      messages.push({
        session: "lab",
        direction: "response" as const,
        body: response,
      });
  }
  return messages;
};

/** One scripted capture whose payload bytes never leave the learning lane. */
const fakePcapSource = (
  bodies: readonly { session: string; direction: "request" | "response"; body: string }[],
  options: { readonly format?: "pcap" | "pcapng" | "other" } = {},
) => ({
  closed: false,
  async read(): Promise<{ ok: true; value: ProtocolMessageReadResult }> {
    const sessions = new Map<
      string,
      { session: string; messages: ProtocolMessageFact[] }
    >();
    for (const [ordinal, body] of bodies.entries()) {
      const bytes = Buffer.from(body.body, "utf8");
      const session = sessions.get(body.session) ?? {
        session: body.session,
        messages: [],
      };
      session.messages.push({
        session: body.session,
        ordinal,
        direction: body.direction,
        byte_length: bytes.length,
        payload_sha256: payloadDigest(bytes),
        sketch: payloadSketch(bytes),
        payload: bytes,
      });
      sessions.set(body.session, session);
    }
    return {
      ok: true,
      value: {
        sessions: [...sessions.values()],
        sha256: "a".repeat(64),
        bytes: 128,
        format: options.format ?? "pcap",
        packets: bodies.length * 2,
        limitations: ["Fixture capture: scripted messages, not a real trace"],
      },
    };
  },
  async close(): Promise<void> {
    this.closed = true;
  },
});

interface Harness {
  readonly provider: ProtocolLearningProvider;
  readonly root: string;
  readonly callsPath: string;
  readonly environment: Readonly<Record<string, string>>;
}

/**
 * The fixture interpreter runs the scripted runner directly. The real planner
 * wraps a caller-managed interpreter in the deny-default profile, which this
 * test asserts on its own instead of by launching it.
 */
const scriptedPlanner = (
  interpreter: string,
): ProtocolProbeLaunchPlanner => () => ({
  executable: interpreter,
  args: [],
  limitations: [],
});

const providerFor = async (
  behavior: FakeProbeRunnerBehavior = {},
  options: {
    readonly environment?: Readonly<Record<string, string>>;
    readonly settings?: AnalysisSettingsReader;
    readonly pcap?: ReturnType<typeof fakePcapSource>;
  } = {},
): Promise<Harness> => {
  const root = await createTestTempDirectory("rea-protolearn-");
  const fake = await writeFakeProbeRunner(root, behavior);
  return {
    provider: new ProtocolLearningProvider({
      environment: { ...fake.environment, ...options.environment },
      ...(options.settings === undefined ? {} : { settings: options.settings }),
      ...(options.pcap === undefined ? {} : { pcapMessages: options.pcap }),
      probeLaunchPlanner: scriptedPlanner(fake.interpreter),
    }),
    root,
    callsPath: fake.callsPath,
    environment: { ...fake.environment, ...options.environment },
  };
};

const learntModel = async (
  harness: Harness,
  store: string | null,
): Promise<ProtocolModel> => {
  const source = fakePcapSource(
    conversation(["HELLO\n", "NEXT\n"], ["OK\n", "READY\n"]),
  );
  const provider = new ProtocolLearningProvider({
    environment: harness.environment,
    pcapMessages: source,
  });
  const result = await provider.execute({
    operation: "learn_protocol_model",
    input: {
      source: { kind: "pcap", path: join(harness.root, "lab.pcap") },
      max_states: 24,
      suffix_length: 2,
      ...(store === null ? {} : { model_directory: store }),
    },
  });
  if (!result.ok)
    throw new Error(`${result.error._tag}: ${result.error.message}`);
  return (result.value.result as { model: ProtocolModel }).model;
};

test("learns a finite-state model from a packet source without retaining payload values", async () => {
  const harness = await providerFor();
  const model = await learntModel(harness, null);
  expect(protocolModelSchema.safeParse(model).success).toBe(true);
  expect(model.source).toMatchObject({ kind: "pcap", format: "pcap", packets: 8 });
  expect(model.messages).toMatchObject({
    total: 4,
    retained: 4,
    omitted: 0,
    request: 2,
    response: 2,
  });
  expect(model.alphabet.class_count).toBe(2);
  expect(model.classes.map(({ direction, sketch }) => ({ direction, sketch }))).toEqual([
    { direction: "request", sketch: expect.objectContaining({ kind: "text", segments: 1 }) },
    { direction: "response", sketch: expect.objectContaining({ kind: "text", segments: 1 }) },
  ]);
  expect(model.states.map(({ state_id }) => state_id)).toEqual([
    "s0",
    "s1",
    "s2",
    "s3",
  ]);
  expect(model.transitions).toHaveLength(4);
  expect(model.coverage).toBe("complete");
  expect(model.model_store).toBeNull();
  const serialized = JSON.stringify(model);
  expect(serialized).not.toContain("HELLO");
  expect(serialized).not.toContain("READY");
  expect(serialized).toContain(sha256(Buffer.from("HELLO\n", "utf8")));
});

test("writes the model store and its class exemplars 0600", async () => {
  const harness = await providerFor();
  const store = join(harness.root, "model-store");
  const model = await learntModel(harness, store);
  expect(model.model_store).toEqual({
    directory: store,
    model_file: PROTOCOL_MODEL_STORE_MODEL_FILE,
    template_count: 2,
  });
  const modelFile = await stat(join(store, PROTOCOL_MODEL_STORE_MODEL_FILE));
  expect(modelFile.mode & 0o777).toBe(0o600);
  const exemplar = await stat(join(store, "class-c0.bin"));
  expect(exemplar.mode & 0o777).toBe(0o600);
  expect(await readFile(join(store, "class-c0.bin"), "utf8")).toBe("HELLO\n");
  const manifest = JSON.parse(
    await readFile(join(store, "manifest.json"), "utf8"),
  ) as { contract: string; files: { class_id: string }[] };
  expect(manifest.contract).toBe("rea.protolearn.model-store/v1");
  expect(manifest.files.map(({ class_id }) => class_id)).toEqual(["c0", "c1"]);
});

test("reduces the requested suffix length to fit the state cap", async () => {
  const harness = await providerFor();
  const source = fakePcapSource(
    conversation(["A\n", "B\n", "C\n"], ["A1\n", "B1\n", "C1\n"]),
  );
  const provider = new ProtocolLearningProvider({
    environment: harness.environment,
    pcapMessages: source,
  });
  const result = await provider.execute({
    operation: "learn_protocol_model",
    input: {
      source: { kind: "pcap", path: join(harness.root, "lab.pcap") },
      max_states: 1,
      suffix_length: 4,
    },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const model = (result.value.result as { model: ProtocolModel }).model;
  expect(model.states).toHaveLength(1);
  expect(model.merge).toMatchObject({
    requested_suffix_length: 4,
    retained_suffix_length: 0,
    suffix_reduced: true,
  });
  expect(model.coverage).toBe("partial");
  expect(model.transitions.every(({ from, to }) => from === "s0" && to === "s0")).toBe(
    true,
  );
});

test("refuses a qlog capture outside the owned decoder profile", async () => {
  const harness = await providerFor();
  const path = join(harness.root, "lab.qlog");
  await writeFile(path, JSON.stringify({ qlog_format: "JSON" }));
  const result = await harness.provider.execute({
    operation: "learn_protocol_model",
    input: { source: { kind: "qlog", path } },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
});

test("cancels before reading a capture when the caller aborts", async () => {
  const harness = await providerFor();
  const controller = new AbortController();
  controller.abort(new Error("caller stopped"));
  const result = await harness.provider.execute(
    {
      operation: "learn_protocol_model",
      input: { source: { kind: "qlog", path: join(harness.root, "lab.qlog") } },
    },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error).toBeInstanceOf(AnalysisCancelledError);
});

const probes = (label = "baseline") => [
  {
    label,
    steps: [{ template_hex: Buffer.from("HELLO\n", "utf8").toString("hex") }],
  },
];

const probeInput = (modelPath: string, overrides: Record<string, unknown> = {}) => ({
  endpoint: { host: "127.0.0.1", port: 9000 },
  model_path: modelPath,
  probes: probes(),
  repeats: 2,
  ...overrides,
});

test("reports a reply whose class the model expects as consistent", async () => {
  const harness = await providerFor({ calls: [encode(["OK\n"]), encode(["OK\n"])] });
  const model = await learntModel(harness, join(harness.root, "store"));
  const modelPath = join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE);
  const result = await harness.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(modelPath),
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  if (!result.ok) return;
  const value = protocolProbeResultSchema.parse(result.value.result);
  expect(value.endpoint).toEqual({
    host: "127.0.0.1",
    port: 9000,
    operator_allowlisted: true,
  });
  expect(value.sandbox).toEqual({
    confinement: "enforced",
    profile: "deny-default",
    limitation: null,
  });
  const step = value.probes[0]?.steps[0];
  expect(step?.sent_class).toBe(model.classes[0]?.class_id);
  expect(step?.model).toMatchObject({
    from: "s0",
    to: "s1",
    expected_response_classes: [model.classes[1]?.class_id],
  });
  expect(step?.verdict).toBe("consistent");
  expect(step?.observations).toHaveLength(2);
  expect(step?.observations[0]?.response_sha256).toBe(
    sha256(Buffer.from("OK\n", "utf8")),
  );
  expect(JSON.stringify(value)).not.toContain("OK");
});

test("reports a structurally different reply as divergent", async () => {
  const harness = await providerFor({
    calls: [encode(["ERR 5\n"]), encode(["ERR 5\n"])],
  });
  await learntModel(harness, join(harness.root, "store"));
  const result = await harness.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE)),
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = protocolProbeResultSchema.parse(result.value.result);
  expect(value.probes[0]?.steps[0]?.verdict).toBe("divergent");
  expect(value.probes[0]?.steps[0]?.observations[0]?.response_class).toBeNull();
  expect(value.counts).toMatchObject({ divergent: 1, steps: 1 });
});

test("reports repeats that disagree as unstable before judging the model", async () => {
  const harness = await providerFor({
    calls: [encode(["OK\n"]), encode(["ERR 5\n"])],
  });
  await learntModel(harness, join(harness.root, "store"));
  const result = await harness.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE)),
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = protocolProbeResultSchema.parse(result.value.result);
  expect(value.probes[0]?.stable).toBe(false);
  expect(value.probes[0]?.steps[0]?.verdict).toBe("unstable");
});

test("reports a template the model cannot classify as unmodeled", async () => {
  const harness = await providerFor({ calls: [encode(["OK\n"]), encode(["OK\n"])] });
  await learntModel(harness, join(harness.root, "store"));
  const result = await harness.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE), {
      probes: [
        { label: "binary", steps: [{ template_hex: "00010203" }] },
      ],
    }),
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = protocolProbeResultSchema.parse(result.value.result);
  expect(value.probes[0]?.steps[0]?.sent_class).toBeNull();
  expect(value.probes[0]?.steps[0]?.model).toBeNull();
  expect(value.probes[0]?.steps[0]?.verdict).toBe("unmodeled");
});

test("refuses to probe when the operator allowlist is unset", async () => {
  const harness = await providerFor({ calls: [encode(["OK\n"])] });
  await learntModel(harness, join(harness.root, "store"));
  const provider = new ProtocolLearningProvider({
    environment: {
      ...harness.environment,
      REA_PROTOLEARN_LAB_ENDPOINTS: "",
    },
  });
  const result = await provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE)),
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisCapabilityUnavailableError");
  expect(result.error.userMessage).toContain("REA_PROTOLEARN_LAB_ENDPOINTS");
});

test("refuses an endpoint the operator did not allowlist", async () => {
  const harness = await providerFor({ calls: [encode(["OK\n"])] });
  await learntModel(harness, join(harness.root, "store"));
  const result = await harness.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE), {
      endpoint: { host: "127.0.0.1", port: 9001 },
    }),
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.userMessage).toContain("127.0.0.1:9001");
  expect(result.error.userMessage).toContain("REA_PROTOLEARN_LAB_ENDPOINTS");
});

test("refuses a hostname endpoint because the sandbox matches addresses", async () => {
  const harness = await providerFor({ calls: [encode(["OK\n"])] });
  await learntModel(harness, join(harness.root, "store"));
  const result = await harness.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE), {
      endpoint: { host: "localhost", port: 9000 },
    }),
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.userMessage).toContain("IPv4 or IPv6 literal");
});

test("refuses a non-loopback endpoint because the profile cannot name it", async () => {
  const harness = await providerFor({ calls: [encode(["OK\n"])] });
  await learntModel(harness, join(harness.root, "store"));
  const provider = new ProtocolLearningProvider({
    environment: {
      ...harness.environment,
      REA_PROTOLEARN_LAB_ENDPOINTS: '["192.0.2.10:9000"]',
    },
  });
  const result = await provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE), {
      endpoint: { host: "192.0.2.10", port: 9000 },
    }),
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.userMessage).toContain("cannot be confined");
});

test("reports an answer frame above the transport budget as a protocol failure", async () => {
  const harness = await providerFor({ oversizedBytes: 2 * 1024 * 1024 });
  await learntModel(harness, join(harness.root, "store"));
  const result = await harness.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE)),
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
});

test("reports a malformed answer frame and a runner refusal", async () => {
  const malformed = await providerFor({ malformed: "not json\n" });
  await learntModel(malformed, join(malformed.root, "store"));
  const first = await malformed.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(
      join(malformed.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE),
    ),
  });
  expect(first.ok).toBe(false);
  if (!first.ok) expect(first.error._tag).toBe("AnalysisProtocolError");

  const refused = await providerFor({
    refuse: { code: "connect_failed", message: "the lab endpoint refused a connection" },
  });
  await learntModel(refused, join(refused.root, "store"));
  const second = await refused.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(refused.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE)),
  });
  expect(second.ok).toBe(false);
  if (!second.ok) expect(second.error._tag).toBe("AnalysisOutputError");
});

test("stops a runner that misses its deadline", async () => {
  const harness = await providerFor({ delayMs: 5_000 });
  await learntModel(harness, join(harness.root, "store"));
  const started = Date.now();
  const result = await harness.provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE), {
      timeout_ms: 150,
    }),
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisOutputError");
  expect(Date.now() - started).toBeLessThan(4_000);
  expect(await readFile(harness.callsPath, "utf8")).not.toBe("");
});

test("cancels a probe while the runner is working", async () => {
  const harness = await providerFor({ delayMs: 2_000 });
  await learntModel(harness, join(harness.root, "store"));
  const controller = new AbortController();
  const pending = harness.provider.execute(
    {
      operation: "probe_learned_model",
      input: probeInput(
        join(harness.root, "store", PROTOCOL_MODEL_STORE_MODEL_FILE),
      ),
    },
    { signal: controller.signal },
  );
  setTimeout(() => controller.abort(new Error("caller stopped")), 100);
  const result = await pending;
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
});

test("exports structure-aware seeds and the campaign handoff", async () => {
  const harness = await providerFor();
  const store = join(harness.root, "store");
  await learntModel(harness, store);
  const output = join(harness.root, "seeds");
  const result = await harness.provider.execute({
    operation: "export_protocol_grammar",
    input: {
      model_path: join(store, PROTOCOL_MODEL_STORE_MODEL_FILE),
      output_directory: output,
    },
  });
  expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as {
    contract: string;
    seeds: { file: string; bytes: number; sha256: string; covers_transitions: unknown[] }[];
    seed_count: number;
    covered_transitions: number;
    transition_count: number;
    campaign_handoff: { tool: string; seed_paths: string[] };
  };
  expect(value.contract).toBe("rea.fuzzing.campaign-seeds/v1");
  expect(value.seed_count).toBe(4);
  expect(value.transition_count).toBe(4);
  expect(value.covered_transitions).toBe(4);
  expect(value.campaign_handoff.tool).toBe("start_fuzzing_campaign");
  expect(value.campaign_handoff.seed_paths).toEqual(
    value.seeds.map(({ file }) => join(output, file)),
  );
  const first = value.seeds[0];
  if (first === undefined) throw new Error("no seed");
  const bytes = await readFile(join(output, first.file));
  expect(bytes.length).toBe(first.bytes);
  expect(sha256(bytes)).toBe(first.sha256);
  expect((await stat(join(output, first.file))).mode & 0o777).toBe(0o600);
});

test("refuses an export whose store no longer matches the model", async () => {
  const harness = await providerFor();
  const store = join(harness.root, "store");
  await learntModel(harness, store);
  await writeFile(join(store, "class-c0.bin"), "TAMPERED\n");
  await chmod(join(store, "class-c0.bin"), 0o600);
  const result = await harness.provider.execute({
    operation: "export_protocol_grammar",
    input: {
      model_path: join(store, PROTOCOL_MODEL_STORE_MODEL_FILE),
      output_directory: join(harness.root, "seeds"),
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
});

test("confines the probe child to the one declared lab socket", () => {
  const plan = sandboxedProbeLaunch({
    configuration: {
      python: "/usr/bin/python3",
      bridgeScript: "/opt/rea/bridge/protolearn/probe_runner.py",
      endpoints: [{ host: "127.0.0.1", port: 9000, literal: "127.0.0.1:9000" }],
      probeTimeoutMs: 1_000,
    },
    endpoint: { host: "127.0.0.1", port: 9000, literal: "127.0.0.1:9000" },
    workspaceRoot: "/tmp/rea-protolearn-job",
    environment: {},
  });
  expect(plan.executable).toBe("/usr/bin/sandbox-exec");
  const profile = plan.args[1] ?? "";
  expect(profile).toContain('(deny default)');
  // The kernel names only `localhost`, so the exact loopback destination is
  // written that way; a numeric literal would be refused at launch.
  expect(profile).toContain(
    '(allow network-outbound (remote ip "localhost:9000"))',
  );
  expect(profile).not.toContain('"127.0.0.1:9001"');
  expect(profile).toContain('(literal "/usr/bin/python3")');
  expect(plan.limitations).toEqual([]);
  expect(plan.args).toContain(
    "/opt/rea/bridge/protolearn/probe_runner.py",
  );
});

test("reports the emergency exit instead of claiming confinement", () => {
  const plan = sandboxedProbeLaunch({
    configuration: {
      python: "/usr/bin/python3",
      bridgeScript: "/opt/rea/bridge/protolearn/probe_runner.py",
      endpoints: [{ host: "127.0.0.1", port: 9000, literal: "127.0.0.1:9000" }],
      probeTimeoutMs: 1_000,
    },
    endpoint: { host: "127.0.0.1", port: 9000, literal: "127.0.0.1:9000" },
    workspaceRoot: "/tmp/rea-protolearn-job",
    environment: { REA_DISABLE_SANDBOX: "1" },
  });
  expect(plan.executable).toBe("/usr/bin/python3");
  expect(plan.limitations[0]).toContain("REA_DISABLE_SANDBOX=1");
});

test("refuses a relative probe interpreter before any socket opens", async () => {
  const harness = await providerFor();
  const provider = new ProtocolLearningProvider({
    environment: { ...harness.environment, REA_PROTOLEARN_PYTHON: "python3" },
    probeLaunchPlanner: scriptedPlanner("/usr/bin/false"),
  });
  const result = await provider.execute({
    operation: "probe_learned_model",
    input: probeInput(join(harness.root, "model.json")),
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisCapabilityUnavailableError");
  expect(result.error.userMessage).toContain("REA_PROTOLEARN_PYTHON");
});

test("reports the probe lane selection without opening a socket", async () => {
  const harness = await providerFor({ calls: [encode(["OK\n"])] });
  const availability = await harness.provider.inspectProbeAvailability();
  expect(availability.status).toBe("available");
  expect(await readFile(harness.callsPath, "utf8")).toBe("");
});

test("closes the packet source when the lane closes", async () => {
  const source = fakePcapSource([]);
  const harness = await providerFor({}, { pcap: source });
  await harness.provider.close();
  expect(source.closed).toBe(true);
  const result = await harness.provider.execute({
    operation: "learn_protocol_model",
    input: { source: { kind: "pcap", path: join(harness.root, "lab.pcap") } },
  });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
});

