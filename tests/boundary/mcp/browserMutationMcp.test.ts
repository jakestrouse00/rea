import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, describe, expect, it } from "vitest";

import { createTestBinarySession } from "../../fixtures/binarySession.js";
import type { BrowserObservationPort } from "../../../src/application/BrowserObservationPort.js";
import { CDP_BROWSER_PROVIDER_IDENTITY } from "../../../src/browser/providerIdentities.js";
import { REPLAY_ALLOWED_ORIGINS_ENV } from "../../../src/domain/replay/replayOrigins.js";
import { AnalysisCapabilityUnavailableError } from "../../../src/domain/analysisErrorCore.js";
import { err, ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { expandToolAvailability } from "../../../src/contracts/toolOutputSchemaPrimitives.js";

const resources: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  await Promise.all(resources.splice(0).map((close) => close()));
});

const unselected = async () =>
  err(
    new AnalysisCapabilityUnavailableError(
      CDP_BROWSER_PROVIDER_IDENTITY.id,
      "unselected",
      "This fixture implements the mutation lane only",
    ),
  );

const mutationPort = (): BrowserObservationPort => ({
  identity: () => CDP_BROWSER_PROVIDER_IDENTITY,
  listTargets: unselected,
  inspectPage: unselected,
  analyzeBundle: unselected,
  observeSession: unselected,
  discoverWebMcpTools: unselected,
  compareCaptures: unselected,
  captureScreenshot: unselected,
  compareScreenshots: unselected,
  evaluatePage: async () =>
    ok({
      target: {
        target_id: "allowed-page",
        url: {
          url: "https://app.example.test/",
          origin: "https://app.example.test",
          query_parameter_names: [],
          redacted: false,
        },
        origin: "https://app.example.test",
      },
      expression_sha256: "0".repeat(64),
      expression_bytes: 14,
      outcome: "value",
      value_type: "string",
      value_text: "Example title",
      value_bytes: 13,
      value_truncated: false,
      exception_text: null,
      trust: "evaluated-untrusted",
      limitations: ["Evaluation result text is page-authored."],
    }),
  armRequestRule: unselected,
  clearRequestRule: unselected,
  fetchPage: unselected,
});

const connect = async (environment: Record<string, string> = {}) => {
  const session = createTestBinarySession(() => {
    throw new Error("unexpected binary admission");
  });
  const server = createServer(
    { kind: "session", session },
    { browserObservation: mutationPort(), environment },
  );
  const client = new Client({ name: "browser-mutation-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  resources.push(() =>
    Promise.all([client.close(), server.close(), session.close()]),
  );
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
};

const availabilityFor = async (client: Client) => {
  const identity = await client.callTool({
    name: "binary_session",
    arguments: {},
  });
  const status = identity.structuredContent as {
    readonly result: {
      readonly tool_availability: Parameters<typeof expandToolAvailability>[0];
    };
  };
  return new Map(
    expandToolAvailability(status.result.tool_availability).map((item) => [
      item.name,
      item,
    ]),
  );
};

describe("browser mutation MCP surface", () => {
  it("returns evaluation text as untrusted target content in Evidence", async () => {
    const client = await connect();
    const result = await client.callTool({
      name: "browser_evaluate",
      arguments: {
        cdp_endpoint: "http://127.0.0.1:9250",
        target_id: "allowed-page",
        expression: "document.title",
      },
    });
    expect(result.isError, JSON.stringify(result)).not.toBe(true);
    expect(result._meta).toEqual({
      provenance: { untrusted_content: true, source: "analysis_target" },
    });
    const evidence = result.structuredContent as {
      readonly operation: string;
      readonly authority: string;
      readonly predicate_type: string;
      readonly normalized_result: { readonly trust: string };
    };
    expect(evidence).toMatchObject({
      operation: "browser_evaluate",
      authority: "external-service",
      predicate_type: "rea.browser-evaluate",
      normalized_result: { trust: "evaluated-untrusted" },
    });
  });

  it("keeps browser_fetch unavailable until the operator allowlist exists", async () => {
    const disabled = await connect();
    const withoutAllowlist = await availabilityFor(disabled);
    expect(withoutAllowlist.get("browser_evaluate")).toMatchObject({
      available: true,
    });
    expect(withoutAllowlist.get("browser_fetch")).toMatchObject({
      available: false,
      reason: "provider_missing",
    });
    expect(withoutAllowlist.get("browser_fetch")?.remediation).toContain(
      REPLAY_ALLOWED_ORIGINS_ENV,
    );

    const enabled = await connect({
      [REPLAY_ALLOWED_ORIGINS_ENV]: '["https://app.example.test"]',
    });
    const allowed = await availabilityFor(enabled);
    for (const name of [
      "browser_evaluate",
      "browser_request_rule_set",
      "browser_request_rule_clear",
      "browser_fetch",
    ])
      expect(allowed.get(name), name).toMatchObject({ available: true });
  });
});
