import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import {
  mitmExportResultSchema,
  mitmInventoryResultSchema,
  mitmReplaySendResultSchema,
  mitmRuleClearResultSchema,
  mitmRuleSetResultSchema,
  mitmStartResultSchema,
  mitmStopResultSchema,
} from "../domain/mitm/mitmInterception.js";
import {
  MITM_ADDON_DIR_ENV,
  MITM_ADDON_FILE_NAME,
  MITM_COMMAND_ENV,
  MITM_LISTEN_HOST,
} from "../domain/mitm/mitmLimits.js";
import { REPLAY_ALLOWED_ORIGINS_ENV } from "../domain/replay/replayOrigins.js";
import type {
  ReplayTransport,
  ReplayTransportRequest,
  ReplayTransportResponse,
} from "../replay/ReplayTransport.js";
import { MitmSessionManager } from "./MitmSessionManager.js";

const ORIGIN = "https://api.example.test";
const SECOND_ORIGIN = "https://other.example.test";

const managers: MitmSessionManager[] = [];

afterEach(async () => {
  await Promise.all(managers.splice(0).map((manager) => manager.closeAll()));
});

const scripted = () => {
  const requests: ReplayTransportRequest[] = [];
  const responses: ReplayTransportResponse[] = [];
  const transport: ReplayTransport = {
    async send(request) {
      requests.push(request);
      const next = responses.shift();
      if (next === undefined)
        throw new Error("The scripted transport has no response queued");
      return next;
    },
  };
  return {
    transport,
    requests,
    respond(
      status: number,
      headers: readonly (readonly [string, string])[] = [],
      chunks: readonly string[] = [],
    ): void {
      responses.push({
        status,
        headers: headers.map(([name, value]) => ({ name, value })),
        body: (async function* () {
          for (const chunk of chunks) yield Buffer.from(chunk, "utf8");
        })(),
        cancel: async () => undefined,
      });
    },
    get dispatched(): number {
      return requests.length;
    },
  };
};

const flowLine = (
  sequence: number,
  overrides: Record<string, unknown> = {},
) => ({
  type: "flow",
  sequence,
  at: "2026-01-01T00:00:00.000Z",
  duration_ms: 5,
  request: {
    method: "GET",
    origin: ORIGIN,
    path_template: "/v1/users/{integer}",
    header_names: ["accept", "authorization"],
    parameters: [
      { name: "path_3", location: "path", type: "integer" },
      { name: "page", location: "query", type: "integer" },
    ],
    content_type_class: "absent",
    body_bytes: 0,
    body_hold: null,
  },
  response: {
    status: 200,
    header_names: ["content-type"],
    content_type_class: "json",
    body_bytes: 12,
    body_hold: null,
    shape: {
      kind: "object",
      keys: [{ name: "id", type: "string" }],
      truncated: false,
    },
  },
  entry: null,
  ...overrides,
});

const capturedEntry = (
  sequence: number,
  capturePath: string,
  overrides: Record<string, unknown> = {},
) => ({
  ...flowLine(sequence),
  entry: {
    path: join(capturePath, "entries", `${String(sequence)}.json`),
    bytes: 10,
    sha256: "0".repeat(64),
  },
  ...overrides,
});

const entryStep = (
  sequence: number,
  request: Record<string, unknown>,
  response: Record<string, unknown> | null,
) => ({ kind: "entry", sequence, request, response });

interface Harness {
  readonly root: string;
  readonly capture: string;
  readonly manager: MitmSessionManager;
  readonly transport: ReturnType<typeof scripted>;
}

interface HarnessOptions {
  readonly scenario: Record<string, unknown>;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly origins?: readonly string[];
  readonly closeRoot?: () => Promise<void>;
}

const harness = async (options: HarnessOptions): Promise<Harness> => {
  const root = await createTestTempDirectory("rea-mitm-");
  const capture = join(root, "capture");
  const addonDirectory = join(root, "addon");
  await Promise.all([
    mkdir(capture, { recursive: true, mode: 0o700 }),
    mkdir(addonDirectory, { recursive: true }),
  ]);
  await writeFile(join(addonDirectory, MITM_ADDON_FILE_NAME), "# generated\n", {
    mode: 0o644,
  });
  const scenarioPath = join(root, "scenario.json");
  await writeFile(
    scenarioPath,
    JSON.stringify(options.scenario).replaceAll("{{CAPTURE}}", capture),
    "utf8",
  );
  const command = join(root, "mitmdump");
  const fixture = join(process.cwd(), "tests/fixtures/mitmFakeDaemon.mjs");
  await writeFile(
    command,
    `#!/bin/sh\nexec "${process.execPath}" "${fixture}" "${scenarioPath}"\n`,
    { mode: 0o700 },
  );
  await chmod(command, 0o700);
  const transport = scripted();
  const manager = new MitmSessionManager({
    environment: {
      ...process.env,
      [MITM_COMMAND_ENV]: command,
      [MITM_ADDON_DIR_ENV]: addonDirectory,
      [REPLAY_ALLOWED_ORIGINS_ENV]: JSON.stringify(options.origins ?? [ORIGIN]),
      ...options.environment,
    },
    transport: transport.transport,
    createRuntimeRoot: async () => ({
      path: capture,
      close:
        options.closeRoot ??
        (async () => {
          await rm(capture, { recursive: true, force: true });
        }),
    }),
  });
  managers.push(manager);
  return { root, capture, manager, transport };
};

const start = async (
  fixture: Harness,
  overrides: Partial<{
    targetApp: "browser" | "android-app" | "ios-app" | "desktop-app" | "other";
    listenPort: number;
    targetOrigins: readonly string[];
    startTimeoutMs: number;
  }> = {},
) => {
  const started = await fixture.manager.start({
    targetApp: overrides.targetApp ?? "browser",
    appIdentifier: "com.example.app",
    listenPort: overrides.listenPort ?? 8_081,
    targetOrigins: overrides.targetOrigins ?? [ORIGIN],
    startTimeoutMs: overrides.startTimeoutMs ?? 10_000,
  });
  if (!started.ok) throw started.error;
  return mitmStartResultSchema.parse(started.value.normalized_result);
};

const readResult = async (fixture: Harness, sessionId: string) => {
  const read = await fixture.manager.readInventory({
    sessionId,
    offset: 0,
    limit: 20,
  });
  if (!read.ok) throw read.error;
  return mitmInventoryResultSchema.parse(read.value.normalized_result);
};

const waitForFlows = (fixture: Harness, sessionId: string, flows: number) =>
  vi.waitFor(
    async () => {
      expect((await readResult(fixture, sessionId)).totals.flows).toBe(flows);
    },
    { timeout: 5_000, interval: 20 },
  );

describe("interception session startup", () => {
  it("starts a loopback proxy and reports per-application guidance", async () => {
    const fixture = await harness({ scenario: { mode: "linger", steps: [] } });
    const started = await start(fixture);
    expect(started.session_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
    );
    expect(started.listen).toEqual({
      host: MITM_LISTEN_HOST,
      port: 8_081,
      proxy_url: "http://127.0.0.1:8081",
    });
    expect(started.daemon.mitmproxy_version).toBe("12.2.3");
    expect(started.daemon.running).toBe(true);
    expect(started.proxy_guidance.target_app).toBe("browser");
    expect(started.proxy_guidance.per_app_only).toBe(true);
    expect(started.proxy_guidance.steps.join(" ")).toContain("8081");
    expect(started.proxy_guidance.out_of_scope.join(" ")).toContain(
      "trust store",
    );
    expect(started.tls.trust_store_changes).toBe("out-of-scope");
    expect(started.tls.device_wide_interception).toBe("out-of-scope");
    expect(started.capture.directory).toBe(fixture.capture);
    expect(started.capture.permissions).toBe(
      process.platform === "win32" ? "unverified" : "0700",
    );
    const control = join(fixture.capture, "rules.json");
    expect(JSON.parse(await readFile(control, "utf8"))).toEqual({
      version: 1,
      revision: 0,
      rules: [],
    });
    if (process.platform !== "win32")
      expect((await stat(control)).mode & 0o777).toBe(0o600);
  });

  it("refuses to start without a selected mitmdump binary", async () => {
    const fixture = await harness({
      scenario: { mode: "linger", steps: [] },
      environment: { [MITM_COMMAND_ENV]: "" },
    });
    const started = await fixture.manager.start({
      targetApp: "browser",
      appIdentifier: undefined,
      listenPort: 8_081,
      targetOrigins: [ORIGIN],
      startTimeoutMs: 1_000,
    });
    expect(started.ok).toBe(false);
    expect(started.ok ? "" : started.error._tag).toBe(
      "AnalysisCapabilityUnavailableError",
    );
    expect(started.ok ? "" : started.error.userMessage).toContain(
      MITM_COMMAND_ENV,
    );
  });

  it("refuses a protocol the addon did not advertise", async () => {
    const fixture = await harness({
      scenario: {
        ready: {
          type: "ready",
          protocol: 9,
          addon: { id: "rea-mitm-addon", version: 1 },
          mitmproxy: { version: "12.2.3" },
          listen: { host: "127.0.0.1", port: 8_081 },
        },
        mode: "linger",
        steps: [],
      },
    });
    const started = await fixture.manager.start({
      targetApp: "browser",
      appIdentifier: undefined,
      listenPort: 8_081,
      targetOrigins: [ORIGIN],
      startTimeoutMs: 5_000,
    });
    expect(started.ok).toBe(false);
    expect(started.ok ? "" : started.error.message).toContain("protocol 9");
  });

  it("times out when the addon never advertises", async () => {
    const fixture = await harness({
      scenario: { ready: false, mode: "linger", steps: [] },
    });
    const started = await fixture.manager.start({
      targetApp: "other",
      appIdentifier: undefined,
      listenPort: 8_081,
      targetOrigins: [ORIGIN],
      startTimeoutMs: 150,
    });
    expect(started.ok).toBe(false);
    expect(started.ok ? "" : started.error._tag).toBe("AnalysisTimeoutError");
  });

  it("refuses a declared origin that is not an exact origin", async () => {
    const fixture = await harness({ scenario: { mode: "linger", steps: [] } });
    const started = await fixture.manager.start({
      targetApp: "browser",
      appIdentifier: undefined,
      listenPort: 8_081,
      targetOrigins: [`${ORIGIN}/v1`],
      startTimeoutMs: 1_000,
    });
    expect(started.ok).toBe(false);
    expect(started.ok ? "" : started.error._tag).toBe("AnalysisInputError");
  });
});

const twoFlowSteps = [
  { kind: "emit", line: flowLine(1) },
  {
    kind: "emit",
    line: flowLine(2, {
      response: {
        status: 404,
        header_names: [],
        content_type_class: "absent",
        body_bytes: 0,
        body_hold: null,
        shape: null,
      },
    }),
  },
];

describe("interception inventory", () => {
  it("streams endpoints, parameters, status counts, and shapes", async () => {
    const fixture = await harness({
      scenario: { mode: "linger", steps: twoFlowSteps },
    });
    const session = await start(fixture);
    await waitForFlows(fixture, session.session_id, 2);
    const read = await readResult(fixture, session.session_id);
    const first = read.endpoints.find((endpoint) => endpoint.method === "GET");
    expect(first).toMatchObject({
      origin: ORIGIN,
      method: "GET",
      path_template: "/v1/users/{integer}",
      occurrences: 2,
    });
    expect(first?.status_histogram).toEqual([
      { status: 200, status_class: "success", count: 1 },
      { status: 404, status_class: "client_error", count: 1 },
    ]);
    expect(first?.parameters.map(({ name, types }) => [name, types])).toEqual([
      ["page", ["integer"]],
      ["path_3", ["integer"]],
    ]);
    expect(first?.response_shape).toEqual({
      kind: "object",
      keys: [{ name: "id", type: "string" }],
      truncated: false,
    });
    expect(first?.request_header_names).toEqual(["accept", "authorization"]);
  });

  it("reports totals and stream health for the same page", async () => {
    const fixture = await harness({
      scenario: { mode: "linger", steps: twoFlowSteps },
    });
    const session = await start(fixture);
    await waitForFlows(fixture, session.session_id, 2);
    const read = await readResult(fixture, session.session_id);
    expect(read.totals).toMatchObject({
      flows: 2,
      endpoints: 1,
      endpoints_omitted: 0,
      facts_omitted: 0,
    });
    expect(read.stream).toMatchObject({
      events: 2,
      malformed: 0,
      oversized: 0,
      unknown_type: 0,
    });
    expect(read.next_offset).toBeNull();
  });

  it("counts refused frames instead of failing the session", async () => {
    const fixture = await harness({
      scenario: {
        mode: "linger",
        steps: [
          { kind: "raw", text: "not json\n" },
          { kind: "emit", line: { type: "mystery", value: 1 } },
          { kind: "emit", line: flowLine(1) },
        ],
      },
    });
    const session = await start(fixture);
    await waitForFlows(fixture, session.session_id, 1);
    const read = await readResult(fixture, session.session_id);
    expect(read.stream).toMatchObject({ malformed: 1, unknown_type: 1 });
    expect(read.state).not.toBe("stopped");
  });

  it("reports body parameters for a second endpoint", async () => {
    const fixture = await harness({
      scenario: {
        mode: "linger",
        steps: [
          {
            kind: "emit",
            line: flowLine(1, {
              request: {
                method: "POST",
                origin: ORIGIN,
                path_template: "/v1/users",
                header_names: ["content-type"],
                parameters: [
                  { name: "email", location: "body", type: "string" },
                ],
                content_type_class: "json",
                body_bytes: 9,
                body_hold: null,
              },
            }),
          },
        ],
      },
    });
    const session = await start(fixture);
    await waitForFlows(fixture, session.session_id, 1);
    const read = await readResult(fixture, session.session_id);
    expect(read.totals.endpoints).toBe(1);
    expect(read.endpoints[0]?.parameters[0]).toMatchObject({
      location: "body",
      name: "email",
    });
  });

  it("paginates endpoints deterministically", async () => {
    const steps = Array.from({ length: 4 }, (_, index) => ({
      kind: "emit",
      line: flowLine(index + 1, {
        request: {
          ...(flowLine(index + 1).request as Record<string, unknown>),
          path_template: `/v1/items/${String(index)}`,
        },
      }),
    }));
    const fixture = await harness({ scenario: { mode: "linger", steps } });
    const session = await start(fixture);
    await waitForFlows(fixture, session.session_id, 4);
    const page = await fixture.manager.readInventory({
      sessionId: session.session_id,
      offset: 1,
      limit: 2,
    });
    expect(page.ok).toBe(true);
    const parsed = mitmInventoryResultSchema.parse(
      page.ok ? page.value.normalized_result : {},
    );
    expect(parsed.endpoints).toHaveLength(2);
    expect(parsed.next_offset).toBe(3);
    expect(parsed.totals.endpoints).toBe(4);
  });

  it("refuses an unknown session identity", async () => {
    const fixture = await harness({ scenario: { mode: "linger", steps: [] } });
    const read = await fixture.manager.readInventory({
      sessionId: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      offset: 0,
      limit: 10,
    });
    expect(read.ok).toBe(false);
    expect(read.ok ? "" : read.error._tag).toBe("AnalysisInputError");
  });
});

describe("endpoint export", () => {
  it("writes an owner-only copy and keeps the inventory inline", async () => {
    const fixture = await harness({
      scenario: {
        mode: "linger",
        steps: [{ kind: "emit", line: flowLine(1) }],
      },
    });
    const session = await start(fixture);
    await waitForFlows(fixture, session.session_id, 1);
    const target = join(fixture.root, "inventory.json");
    const exported = await fixture.manager.exportInventory({
      sessionId: session.session_id,
      path: target,
      overwrite: false,
    });
    expect(exported.ok).toBe(true);
    const parsed = mitmExportResultSchema.parse(
      exported.ok ? exported.value.normalized_result : {},
    );
    expect(parsed.endpoints).toHaveLength(1);
    expect(parsed.file?.path).toBe(target);
    expect(parsed.file?.permissions).toBe(
      process.platform === "win32" ? "unverified" : "0600",
    );
    const bytes = await readFile(target);
    expect(bytes.byteLength).toBe(parsed.file?.bytes);
    if (process.platform !== "win32")
      expect((await stat(target)).mode & 0o777).toBe(0o600);
    const occupied = await fixture.manager.exportInventory({
      sessionId: session.session_id,
      path: target,
      overwrite: false,
    });
    expect(occupied.ok).toBe(false);
    expect(occupied.ok ? "" : occupied.error._tag).toBe("AnalysisInputError");
  });
});

const RULE_ID = "0b4f5d4c-1a52-4f7f-9a0e-9f9a1a0b3c4d";
const ruleMatchStep = {
  kind: "emit",
  line: {
    type: "rule_match",
    rule_id: RULE_ID,
    phase: "request",
    method: "GET",
    origin: ORIGIN,
    path_template: "/v1/users/{integer}",
    status_before: null,
    status_after: null,
    headers_changed: 1,
    query_changed: 1,
    body_replaced: false,
  },
};

const armedRule = (fixture: Harness, sessionId: string, ruleId = RULE_ID) =>
  fixture.manager.setRule({
    sessionId,
    ruleId,
    match: { origins: [ORIGIN], pathPrefixes: ["/v1"], methods: [] },
    action: {
      kind: "request",
      setHeaders: [{ name: "x-probe", value: "1" }],
      removeHeaders: [],
      setQuery: [{ name: "debug", value: "1" }],
      removeQuery: [],
      bodyBase64: undefined,
    },
    ttlMs: 60_000,
  });

const rulesFixture = (steps: readonly Record<string, unknown>[]) =>
  harness({ scenario: { mode: "linger", steps } });

describe("rewrite rules", () => {
  it("arms one rule and writes the control file", async () => {
    const fixture = await rulesFixture([ruleMatchStep]);
    const session = await start(fixture);
    const armed = await armedRule(fixture, session.session_id);
    expect(armed.ok).toBe(true);
    const parsed = mitmRuleSetResultSchema.parse(
      armed.ok ? armed.value.normalized_result : {},
    );
    expect(parsed.state).toBe("armed");
    expect(parsed.control.revision).toBe(1);
    expect(parsed.action).toMatchObject({
      kind: "request",
      set_header_names: ["x-probe"],
      set_query_names: ["debug"],
    });
    const control = JSON.parse(
      await readFile(join(fixture.capture, "rules.json"), "utf8"),
    ) as { revision: number; rules: Record<string, unknown>[] };
    expect(control.revision).toBe(1);
    expect(control.rules).toHaveLength(1);
    expect(control.rules[0]).toMatchObject({
      rule_id: RULE_ID,
      phase: "request",
      match: { origins: [ORIGIN], path_prefixes: ["/v1"], methods: [] },
    });
    if (process.platform !== "win32")
      expect(
        (await stat(join(fixture.capture, "rules.json"))).mode & 0o777,
      ).toBe(0o600);
  });

  it("counts matches and clears the rule with its ledger", async () => {
    const fixture = await rulesFixture([ruleMatchStep]);
    const session = await start(fixture);
    await armedRule(fixture, session.session_id);
    await vi.waitFor(
      async () => {
        const read = await readResult(fixture, session.session_id);
        expect(
          read.rules.find((candidate) => candidate.rule_id === RULE_ID)
            ?.counters.matched,
        ).toBe(1);
      },
      { timeout: 5_000, interval: 20 },
    );
    const cleared = await fixture.manager.clearRule({
      sessionId: session.session_id,
      ruleId: RULE_ID,
    });
    expect(cleared.ok).toBe(true);
    const clearedResult = mitmRuleClearResultSchema.parse(
      cleared.ok ? cleared.value.normalized_result : {},
    );
    expect(clearedResult).toMatchObject({
      state: "cleared",
      release_reason: "cleared",
      counters: {
        matched: 1,
        requests_rewritten: 1,
        headers_changed: 1,
        query_changed: 1,
      },
    });
    expect(clearedResult.decisions.items).toHaveLength(1);
    expect(clearedResult.decisions.items[0]).toMatchObject({
      phase: "request",
      method: "GET",
      path_template: "/v1/users/{integer}",
      headers_changed: 1,
    });
    const after = JSON.parse(
      await readFile(join(fixture.capture, "rules.json"), "utf8"),
    ) as { revision: number; rules: unknown[] };
    expect(after.revision).toBe(2);
    expect(after.rules).toHaveLength(0);
    const again = await fixture.manager.clearRule({
      sessionId: session.session_id,
      ruleId: RULE_ID,
    });
    expect(again.ok).toBe(false);
    expect(again.ok ? "" : again.error._tag).toBe("AnalysisInputError");
  });

  it("refuses a rule with no predicate", async () => {
    const fixture = await harness({ scenario: { mode: "linger", steps: [] } });
    const session = await start(fixture);
    const armed = await fixture.manager.setRule({
      sessionId: session.session_id,
      ruleId: undefined,
      match: { origins: [], pathPrefixes: [], methods: [] },
      action: {
        kind: "request",
        setHeaders: [],
        removeHeaders: [],
        setQuery: [],
        removeQuery: [],
        bodyBase64: undefined,
      },
      ttlMs: 1_000,
    });
    expect(armed.ok).toBe(false);
    expect(armed.ok ? "" : armed.error._tag).toBe("AnalysisInputError");
  });

  it("refuses a duplicate rule identity and an unknown rule", async () => {
    const fixture = await harness({ scenario: { mode: "linger", steps: [] } });
    const session = await start(fixture);
    const ruleId = "5d0e1a44-6b2f-4be1-8f0e-3f5f6a7b8c9d";
    const request = {
      sessionId: session.session_id,
      ruleId,
      match: { origins: [ORIGIN], pathPrefixes: [], methods: [] },
      action: {
        kind: "response" as const,
        setHeaders: [],
        removeHeaders: [],
        status: 418,
        bodyBase64: undefined,
      },
      ttlMs: 1_000,
    };
    expect((await fixture.manager.setRule(request)).ok).toBe(true);
    expect((await fixture.manager.setRule(request)).ok).toBe(false);
    const missing = await fixture.manager.clearRule({
      sessionId: session.session_id,
      ruleId: "9a9a9a9a-1b1b-4c4c-8d8d-1e1e1e1e1e1e",
    });
    expect(missing.ok ? false : missing.error._tag).toBe("AnalysisInputError");
  });
});

describe("captured-entry replay", () => {
  const scenario = {
    mode: "linger",
    steps: [
      entryStep(
        1,
        {
          method: "POST",
          url: `${ORIGIN}/v1/items?page=2`,
          headers: [
            ["authorization", "Bearer secret"],
            ["content-type", "application/json"],
          ],
          body: '{"a":1}',
        },
        { status: 201, body: "created" },
      ),
      { kind: "emit", line: capturedEntry(1, "{{CAPTURE}}") },
    ],
  };

  const ready = async (options: Partial<HarnessOptions> = {}) => {
    const fixture = await harness({ scenario, ...options });
    const session = await start(fixture);
    await waitForFlows(fixture, session.session_id, 1);
    return { fixture, session };
  };

  const replay = (
    fixture: Harness,
    sessionId: string,
    overrides: Partial<{
      sequence: number;
      mutation: Record<string, unknown>;
      dump: { path: string; overwrite: boolean } | undefined;
    }> = {},
  ) =>
    fixture.manager.replay({
      sessionId,
      sequence: overrides.sequence ?? 1,
      mutation: overrides.mutation ?? {},
      timeoutMs: 1_000,
      followRedirects: false,
      dump: overrides.dump,
    });

  it("writes an owner-only replayable entry record", async () => {
    const { fixture } = await ready();
    const record = join(fixture.capture, "entries", "1.json");
    const parsed = JSON.parse(await readFile(record, "utf8")) as {
      sequence: number;
      method: string;
      url: string;
      headers: [string, string][];
      body: { bytes: number };
    };
    expect(parsed).toMatchObject({
      sequence: 1,
      method: "POST",
      url: `${ORIGIN}/v1/items?page=2`,
      body: { bytes: 7 },
    });
    expect(parsed.headers).toContainEqual(["authorization", "Bearer secret"]);
    if (process.platform !== "win32")
      expect((await stat(record)).mode & 0o777).toBe(0o600);
  });

  it("re-sends one captured entry verbatim through the shared core", async () => {
    const { fixture, session } = await ready();
    fixture.transport.respond(
      200,
      [["content-type", "application/json"]],
      ['{"ok":true}'],
    );
    const sent = await replay(fixture, session.session_id);
    expect(sent.ok).toBe(true);
    const parsed = mitmReplaySendResultSchema.parse(
      sent.ok ? sent.value.normalized_result : {},
    );
    expect(parsed).toMatchObject({
      captured_sequence: 1,
      outcome: "response",
      retry: "none",
    });
    expect(parsed.request.credential_header_names).toEqual(["authorization"]);
    expect(parsed.request.header_names).toContain("content-type");
    expect(parsed.request.body_bytes).toBe(7);
    expect(parsed.response?.status).toBe(200);
    expect(fixture.transport.dispatched).toBe(1);
    const wire = fixture.transport.requests[0];
    expect(wire?.method).toBe("POST");
    expect(wire?.url).toBe(`${ORIGIN}/v1/items?page=2`);
    expect(wire?.body?.byteLength).toBe(7);
  });

  it("sends one mutated request with a raw dump", async () => {
    const { fixture, session } = await ready();
    fixture.transport.respond(418, [], ["short and stout"]);
    const dumpPath = join(fixture.root, "probe.bin");
    const sent = await replay(fixture, session.session_id, {
      mutation: {
        method: "PUT",
        setHeaders: [{ name: "x-probe", value: "1" }],
        removeHeaders: ["authorization"],
        body: { kind: "text", text: "{}" },
      },
      dump: { path: dumpPath, overwrite: false },
    });
    expect(sent.ok).toBe(true);
    const parsed = mitmReplaySendResultSchema.parse(
      sent.ok ? sent.value.normalized_result : {},
    );
    expect(parsed.request.method).toBe("PUT");
    expect(parsed.request.credential_header_names).toEqual([]);
    expect(parsed.response?.dump?.path).toBe(dumpPath);
    expect((await stat(dumpPath)).mode & 0o777).toBe(0o600);
    expect((await readFile(dumpPath, "utf8")).length).toBeGreaterThan(0);
    expect(fixture.transport.dispatched).toBe(1);
    expect(
      Buffer.from(
        fixture.transport.requests[0]?.body ?? new Uint8Array(),
      ).toString("utf8"),
    ).toBe("{}");
  });

  it("refuses a replay to an origin the operator did not approve", async () => {
    const { fixture, session } = await ready({ origins: [SECOND_ORIGIN] });
    const sent = await replay(fixture, session.session_id);
    expect(sent.ok).toBe(false);
    expect(sent.ok ? "" : sent.error._tag).toBe(
      "AnalysisCapabilityUnavailableError",
    );
    expect(fixture.transport.dispatched).toBe(0);
  });

  it("refuses an entry sequence this session does not track", async () => {
    const { fixture, session } = await ready();
    const sent = await replay(fixture, session.session_id, { sequence: 99 });
    expect(sent.ok).toBe(false);
    expect(sent.ok ? "" : sent.error._tag).toBe("AnalysisInputError");
    expect(fixture.transport.dispatched).toBe(0);
  });

  it("refuses a captured body whose bytes no longer match its record", async () => {
    const { fixture, session } = await ready();
    await writeFile(join(fixture.capture, "bodies", "1.req.bin"), "tampered");
    const sent = await replay(fixture, session.session_id);
    expect(sent.ok).toBe(false);
    expect(sent.ok ? "" : sent.error._tag).toBe("AnalysisInputError");
    expect(fixture.transport.dispatched).toBe(0);
  });
});

describe("session lifecycle", () => {
  it("stops the proxy and removes the capture directory", async () => {
    const fixture = await harness({ scenario: { mode: "linger", steps: [] } });
    const session = await start(fixture);
    const stopped = await fixture.manager.stop({
      sessionId: session.session_id,
    });
    expect(stopped.ok).toBe(true);
    expect(stopped.ok ? stopped.value.operation : "").toBe(
      "stop_interception_session",
    );
    const parsed = mitmStopResultSchema.parse(
      stopped.ok ? stopped.value.normalized_result : {},
    );
    expect(parsed.capture.removed).toBe(true);
    expect(parsed.daemon.exit.kind).not.toBe("running");
    await expect(stat(fixture.capture)).rejects.toThrow();
    const again = await fixture.manager.stop({ sessionId: session.session_id });
    expect(again.ok).toBe(false);
  });

  it("retains the session when the capture directory cannot be removed", async () => {
    let capturePath = "";
    let attempts = 0;
    const fixture = await harness({
      scenario: { mode: "linger", steps: [] },
      closeRoot: async () => {
        attempts += 1;
        if (attempts === 1) throw new Error("denied");
        await rm(capturePath, { recursive: true, force: true });
      },
    });
    capturePath = fixture.capture;
    const session = await start(fixture);
    const first = await fixture.manager.stop({ sessionId: session.session_id });
    expect(first.ok).toBe(false);
    expect(first.ok ? false : first.error.cleanupIncomplete).toBe(true);
    expect(attempts).toBe(1);
    const retried = await fixture.manager.stop({
      sessionId: session.session_id,
    });
    expect(retried.ok).toBe(true);
    expect(attempts).toBe(2);
  });

  it("reports cancellation before any dispatch", async () => {
    const fixture = await harness({ scenario: { mode: "linger", steps: [] } });
    const session = await start(fixture);
    const controller = new AbortController();
    controller.abort(new Error("caller cancelled"));
    const read = await fixture.manager.readInventory(
      { sessionId: session.session_id, offset: 0, limit: 10 },
      { signal: controller.signal },
    );
    expect(read.ok).toBe(false);
    expect(read.ok ? "" : read.error._tag).toBe("AnalysisCancelledError");
  });

  it("stops every owned proxy on close", async () => {
    const fixture = await harness({ scenario: { mode: "linger", steps: [] } });
    await start(fixture);
    const closed = await fixture.manager.closeAll();
    expect(closed.ok).toBe(true);
    await expect(stat(fixture.capture)).rejects.toThrow();
  });
});
