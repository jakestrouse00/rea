import { describe, expect, it, vi } from "vitest";
import { WebSocket } from "ws";

import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import { BROWSER_MUTATION_LIMITS } from "../../../src/domain/browserMutationLimits.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import {
  browserRequestRuleSetInputSchema,
  type BrowserRequestRuleSetInput,
} from "../../../src/domain/browserMutation.js";
import {
  analyzeBrowserMutation,
  expectBrowserMutation,
} from "./cdpBrowserMutation.support.js";
import {
  startFakeCdpBrowser,
  type FakeCdpBrowser,
} from "../../fixtures/fakeCdpBrowser.js";
import type { AnalysisError } from "../../../src/domain/analysisErrorBase.js";
import { trackBrowser, waitFor } from "./cdpBrowserProvider.support.js";

const RULE_ID = "5c1f0a2e-8d4b-4f6a-9b1c-2d3e4f5a6b7c";

const parsedRule = (
  browser: FakeCdpBrowser,
  input: Record<string, unknown>,
): BrowserRequestRuleSetInput =>
  browserRequestRuleSetInputSchema.parse({
    cdp_endpoint: browser.endpoint,
    target_id: "allowed-page",
    rule_id: RULE_ID,
    ...input,
  });

const pausedEvent = (
  requestId: string,
  url: string,
  method = "GET",
  headers: Readonly<Record<string, string>> = {},
  resourceType = "Fetch",
  sessionId = "session-1",
) => ({
  method: "Fetch.requestPaused",
  sessionId,
  params: {
    requestId,
    request: { url, method, headers },
    resourceType,
  },
});

const failureText = (error: AnalysisError): string =>
  `${error.message} ${error.userMessage ?? ""}`;

const commandsFor = (browser: FakeCdpBrowser, method: string) =>
  browser.commands.filter((command) => command.method === method);

const continueOf = (browser: FakeCdpBrowser, requestId: string) =>
  commandsFor(browser, "Fetch.continueRequest").find(
    (command) => command.params.requestId === requestId,
  );

describe("browser request rule interception", () => {
  it("rewrites a matching request and continues unrelated traffic untouched", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      const armed = await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { url_prefixes: [`${browser.allowedOrigin}/api/`] },
            action: {
              kind: "modify",
              set_headers: [{ name: "x-rea-probe", value: "1" }],
            },
          }),
        ),
      );
      expect(armed).toMatchObject({
        rule_id: RULE_ID,
        state: "armed",
        action_kind: "modify",
        target: { target_id: "allowed-page", origin: browser.allowedOrigin },
      });
      expect(commandsFor(browser, "Fetch.enable")).toHaveLength(1);

      browser.emitEvent(
        pausedEvent(
          "req-api",
          `${browser.allowedOrigin}/api/session?token=1`,
          "GET",
          {
            accept: "application/json",
          },
        ),
      );
      browser.emitEvent(
        pausedEvent(
          "req-image",
          `${browser.allowedOrigin}/logo.png`,
          "GET",
          {},
          "Image",
        ),
      );
      await waitFor(
        () =>
          continueOf(browser, "req-api") !== undefined &&
          continueOf(browser, "req-image") !== undefined,
        "both paused requests were answered",
      );
      const rewritten = continueOf(browser, "req-api");
      expect(rewritten?.params.headers).toEqual(
        expect.arrayContaining([
          { name: "accept", value: "application/json" },
          { name: "x-rea-probe", value: "1" },
        ]),
      );
      expect(continueOf(browser, "req-image")?.params.headers).toBeUndefined();

      const cleared = await expectBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(cleared.counters).toMatchObject({
        paused: 2,
        continued: 1,
        modified: 1,
        blocked: 0,
        held: 0,
        held_released: 0,
      });
      expect(cleared.decisions.items.map(({ decision }) => decision)).toEqual([
        "modified",
      ]);
      expect(commandsFor(browser, "Fetch.disable")).toHaveLength(1);
    } finally {
      await provider.close();
    }
  });

  it("releases a held request before disabling the Fetch domain", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["POST"] },
            action: { kind: "hold" },
          }),
        ),
      );
      browser.emitEvent(
        pausedEvent(
          "req-held",
          `${browser.allowedOrigin}/api/checkout`,
          "POST",
        ),
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(continueOf(browser, "req-held")).toBeUndefined();

      const cleared = await expectBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(cleared.counters).toMatchObject({ held: 1, held_released: 1 });
      expect(cleared.decisions.items.map(({ decision }) => decision)).toEqual([
        "held",
        "released",
      ]);
      const released = browser.commands.findIndex(
        (command) =>
          command.method === "Fetch.continueRequest" &&
          command.params.requestId === "req-held",
      );
      const disabled = browser.commands.findIndex(
        (command) => command.method === "Fetch.disable",
      );
      expect(released).toBeGreaterThanOrEqual(0);
      expect(released).toBeLessThan(disabled);
    } finally {
      await provider.close();
    }
  });

  it("releases held traffic when the server shuts down mid-flight", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    await expectBrowserMutation(
      provider.armRequestRule(
        parsedRule(browser, {
          match: { url_prefixes: [browser.allowedOrigin] },
          action: { kind: "hold" },
        }),
      ),
    );
    browser.emitEvent(
      pausedEvent("req-shutdown", `${browser.allowedOrigin}/app`, "GET"),
    );
    await new Promise((resolve) => setTimeout(resolve, 25));
    await provider.close();
    expect(continueOf(browser, "req-shutdown")).toBeDefined();
    expect(commandsFor(browser, "Fetch.disable")).toHaveLength(1);
    await waitFor(
      () => browser.activeConnectionCount() === 0,
      "the rule transport closed",
    );
  });
});

describe("browser request rule ledger", () => {
  it("keeps enforcing a rewrite flood while the decision ledger stops", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { url_prefixes: [`${browser.allowedOrigin}/api/`] },
            action: { kind: "block" },
          }),
        ),
      );
      const total = BROWSER_MUTATION_LIMITS.maxRuleDecisions + 50;
      for (let index = 0; index < total; index += 1)
        browser.emitEvent(
          pausedEvent(
            `flood-${String(index)}`,
            `${browser.allowedOrigin}/api/items/${String(index)}`,
          ),
        );
      await waitFor(
        () => commandsFor(browser, "Fetch.failRequest").length === total,
        "every flooded request was blocked",
      );
      const cleared = await expectBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(cleared.counters.blocked).toBe(total);
      expect(cleared.decisions.retained).toBe(
        BROWSER_MUTATION_LIMITS.maxRuleDecisions,
      );
      expect(cleared.decisions.dropped).toBe(50);
      expect(cleared.decisions.omissions).toEqual([
        { decision: "blocked", count: 50, reasons: ["max-decisions"] },
      ]);
    } finally {
      await provider.close();
    }
  });

  it("retains no header or query values in its decisions", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { url_prefixes: [`${browser.allowedOrigin}/api/`] },
            action: {
              kind: "modify",
              set_headers: [
                { name: "authorization", value: "Bearer rule-secret" },
              ],
              set_query: [{ name: "debug", value: "rule-secret" }],
            },
          }),
        ),
      );
      browser.emitEvent(
        pausedEvent(
          "req-secret",
          `${browser.allowedOrigin}/api/session?token=query-secret`,
          "GET",
          {
            cookie: "session=header-secret",
            authorization: "Bearer header-secret",
          },
        ),
      );
      await waitFor(
        () => continueOf(browser, "req-secret") !== undefined,
        "the secret-bearing request was answered",
      );
      const cleared = await expectBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      const serialized = JSON.stringify(cleared);
      for (const secret of [
        "rule-secret",
        "query-secret",
        "header-secret",
        "Bearer",
        "session=",
      ])
        expect(serialized).not.toContain(secret);
      expect(cleared.decisions.items[0]).toMatchObject({
        query_parameter_names: ["token"],
        headers_changed: 1,
        query_changed: 1,
        decision: "modified",
      });
    } finally {
      await provider.close();
    }
  });
});

describe("browser request rule ownership", () => {
  it("refuses a foreign tab, a duplicate identity, and a ninth armed rule", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      const foreign = await analyzeBrowserMutation(
        provider.armRequestRule({
          ...parsedRule(browser, {
            match: { methods: ["GET"] },
            action: { kind: "block" },
          }),
          target_id: "disallowed-page",
          allowed_origins: [],
        }),
      );
      expect(failureText(foreign)).toContain("target_not_allowed");
      expect(commandsFor(browser, "Fetch.enable")).toHaveLength(0);

      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["GET"] },
            action: { kind: "block" },
          }),
        ),
      );
      const duplicate = await analyzeBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["GET"] },
            action: { kind: "block" },
          }),
        ),
      );
      expect(failureText(duplicate)).toContain("already armed");

      for (
        let index = 1;
        index < BROWSER_MUTATION_LIMITS.maxArmedRules;
        index += 1
      )
        await expectBrowserMutation(
          provider.armRequestRule(
            parsedRule(browser, {
              rule_id: `00000000-0000-4000-8000-0000000000${String(index).padStart(2, "0")}`,
              match: { methods: ["GET"] },
              action: { kind: "block" },
            }),
          ),
        );
      const overflow = await analyzeBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            rule_id: "ffffffff-0000-4000-8000-000000000000",
            match: { methods: ["GET"] },
            action: { kind: "block" },
          }),
        ),
      );
      expect(failureText(overflow)).toContain("At most");
    } finally {
      await provider.close();
    }
  });

  it("disarms without enabling interception when the caller cancels mid-arm", async () => {
    const cancelled = new AbortController();
    const browser = await startFakeCdpBrowser({
      commandEvents: (command) => {
        if (command.method === "Target.attachToTarget")
          cancelled.abort(new Error("caller cancelled the arm"));
        return undefined;
      },
    });
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      const refused = await analyzeBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["POST"] },
            action: { kind: "hold" },
          }),
          { signal: cancelled.signal },
        ),
      );
      expect(refused._tag).toBe("AnalysisCancelledError");
      expect(
        browser.commands.some((command) => command.method === "Fetch.enable"),
      ).toBe(false);
      await waitFor(
        () => browser.activeConnectionCount() === 0,
        "the cancelled arm closed its owned transport",
      );
      const leaked = await analyzeBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(failureText(leaked)).toContain("not armed");
    } finally {
      await provider.close();
    }
  });
});

describe("browser request rule release retention", () => {
  it("keeps the ledger of a rule whose release failed and retries it", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    const close = vi
      .spyOn(WebSocket.prototype, "close")
      .mockImplementationOnce(() => {
        throw new Error("controlled close failure");
      });
    const terminate = vi
      .spyOn(WebSocket.prototype, "terminate")
      .mockImplementation(() => undefined);
    try {
      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["POST"] },
            action: { kind: "hold" },
          }),
        ),
      );
      browser.emitEvent(
        pausedEvent(
          "req-retained",
          `${browser.allowedOrigin}/api/checkout`,
          "POST",
        ),
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
      const failed = await analyzeBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(failed).toBeInstanceOf(ProviderCleanupError);
      expect(failed.cleanupResources).toContain(
        `browser-request-rule:${RULE_ID}`,
      );
      expect(projectAnalysisError(failed).remediation.action).toContain(
        "browser_request_rule_clear",
      );

      close.mockRestore();
      terminate.mockRestore();
      const released = await expectBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(released.release_reason).toBe("cleared");
      expect(released.counters).toMatchObject({ paused: 1, held: 1 });
      expect(released.decisions.items.map(({ decision }) => decision)).toEqual([
        "held",
        "released",
      ]);
      expect(released.limitations.join(" ")).toContain(
        "An earlier release attempt",
      );
      expect(commandsFor(browser, "Fetch.disable")).toHaveLength(1);
    } finally {
      close.mockRestore();
      terminate.mockRestore();
      await provider.close();
    }
  });

  it("reports held traffic it could not continue instead of dropping it", async () => {
    let continueFailures = 1;
    const browser = await startFakeCdpBrowser({
      commandError: (command) => {
        if (
          command.method !== "Fetch.continueRequest" ||
          continueFailures === 0
        )
          return undefined;
        continueFailures -= 1;
        return { code: -32_603, message: "controlled continue failure" };
      },
    });
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["POST"] },
            action: { kind: "hold" },
          }),
        ),
      );
      browser.emitEvent(
        pausedEvent(
          "req-unconfirmed",
          `${browser.allowedOrigin}/api/checkout`,
          "POST",
        ),
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
      const cleared = await expectBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(cleared.counters).toMatchObject({ held: 1, held_released: 0 });
      expect(cleared.decisions.items.map(({ decision }) => decision)).toEqual([
        "held",
      ]);
      expect(cleared.limitations.join(" ")).toContain(
        "released only by closing the rule's transport",
      );
    } finally {
      await provider.close();
    }
  });
});

describe("browser request rule release cancellation", () => {
  it("still releases held traffic when the caller cancels the clear", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["POST"] },
            action: { kind: "hold" },
          }),
        ),
      );
      browser.emitEvent(
        pausedEvent(
          "req-cancelled",
          `${browser.allowedOrigin}/api/checkout`,
          "POST",
        ),
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
      const cancelled = new AbortController();
      cancelled.abort(new Error("caller cancelled the clear"));
      const cleared = await expectBrowserMutation(
        provider.clearRequestRule(
          { rule_id: RULE_ID },
          {
            signal: cancelled.signal,
          },
        ),
      );
      expect(cleared.counters).toMatchObject({ held: 1, held_released: 1 });
      expect(continueOf(browser, "req-cancelled")).toBeDefined();
      await waitFor(
        () => browser.activeConnectionCount() === 0,
        "the cancelled clear still closed the rule transport",
      );
    } finally {
      await provider.close();
    }
  });

  it("releases a rule when its declared lifetime elapses", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["GET"] },
            action: { kind: "block" },
            ttl_ms: 5,
          }),
        ),
      );
      await waitFor(
        () => commandsFor(browser, "Fetch.disable").length === 1,
        "the rule released at its deadline",
      );
      const cleared = await analyzeBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(failureText(cleared)).toContain("not armed");
    } finally {
      await provider.close();
    }
  });

  it("reports a failed expiry release instead of discarding its ledger", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    const close = vi
      .spyOn(WebSocket.prototype, "close")
      .mockImplementationOnce(() => {
        throw new Error("controlled close failure");
      });
    const terminate = vi
      .spyOn(WebSocket.prototype, "terminate")
      .mockImplementation(() => undefined);
    try {
      await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            match: { methods: ["POST"] },
            action: { kind: "hold" },
            ttl_ms: 5,
          }),
        ),
      );
      browser.emitEvent(
        pausedEvent(
          "req-expiry",
          `${browser.allowedOrigin}/api/checkout`,
          "POST",
        ),
      );
      await waitFor(
        () => commandsFor(browser, "Fetch.disable").length === 1,
        "the expiry release started at the deadline",
      );
      await new Promise((resolve) => setTimeout(resolve, 1_200));
      const armed = await expectBrowserMutation(
        provider.armRequestRule(
          parsedRule(browser, {
            rule_id: "00000000-0000-4000-8000-000000000007",
            match: { methods: ["GET"] },
            action: { kind: "block" },
          }),
        ),
      );
      expect(armed.limitations.join(" ")).toContain(
        "Release is still incomplete",
      );
      expect(armed.limitations.join(" ")).toContain(RULE_ID);
      close.mockRestore();
      terminate.mockRestore();
      const cleared = await expectBrowserMutation(
        provider.clearRequestRule({ rule_id: RULE_ID }),
      );
      expect(cleared.release_reason).toBe("expired");
      expect(cleared.counters).toMatchObject({ held: 1, held_released: 1 });
      expect(cleared.limitations.join(" ")).toContain(
        "An earlier release attempt",
      );
    } finally {
      close.mockRestore();
      terminate.mockRestore();
      await provider.close();
    }
  });
});
