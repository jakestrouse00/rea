import { describe, expect, it } from "vitest";

import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import { BROWSER_MUTATION_LIMITS } from "../../../src/domain/browserMutationLimits.js";
import {
  analyzeBrowserMutation,
  browserEndpoint,
  expectBrowserMutation,
} from "./cdpBrowserMutation.support.js";
import { startFakeCdpBrowser } from "../../fixtures/fakeCdpBrowser.js";
import { trackBrowser } from "./cdpBrowserProvider.support.js";

const evaluateReply = (value: unknown) => ({
  result: { type: typeof value, value },
});

const exceptionReply = (description: string) => ({
  result: { type: "object", subtype: "error" },
  exceptionDetails: {
    text: "Uncaught",
    exception: { type: "object", description },
  },
});

describe("browser_evaluate authorization", () => {
  it("evaluates in the authorized main frame and marks the answer untrusted", async () => {
    const browser = await startFakeCdpBrowser({
      commandResult: (command) =>
        command.method === "Runtime.evaluate"
          ? evaluateReply("Fake page title")
          : undefined,
    });
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      const result = await expectBrowserMutation(
        provider.evaluatePage({
          cdp_endpoint: browserEndpoint(browser),
          allowed_origins: [browser.allowedOrigin],
          target_id: "allowed-page",
          expression: "document.title",
          await_promise: true,
        }),
      );
      expect(result).toMatchObject({
        target: { target_id: "allowed-page", origin: browser.allowedOrigin },
        outcome: "value",
        value_text: "Fake page title",
        value_bytes: 15,
        value_truncated: false,
        trust: "evaluated-untrusted",
      });
      expect(result.expression_bytes).toBe(14);
      const evaluated = browser.commands.find(
        (command) => command.method === "Runtime.evaluate",
      );
      expect(evaluated?.params).toMatchObject({
        expression: "document.title",
        awaitPromise: true,
        returnByValue: true,
      });
    } finally {
      await provider.close();
    }
  });

  it("refuses a foreign tab before any evaluation command", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      const result = await analyzeBrowserMutation(
        provider.evaluatePage({
          cdp_endpoint: browserEndpoint(browser),
          allowed_origins: [],
          target_id: "disallowed-page",
          expression: "document.cookie",
          await_promise: true,
        }),
      );
      expect(`${result.message} ${result.userMessage ?? ""}`).toContain(
        "target_not_allowed",
      );
      expect(
        browser.commands.some(
          (command) => command.method === "Runtime.evaluate",
        ),
      ).toBe(false);
    } finally {
      await provider.close();
    }
  });

  it("refuses a target outside the declared origin scope", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      const result = await analyzeBrowserMutation(
        provider.evaluatePage({
          cdp_endpoint: browserEndpoint(browser),
          allowed_origins: ["https://other.example.test"],
          target_id: "allowed-page",
          expression: "document.title",
          await_promise: true,
        }),
      );
      expect(`${result.message} ${result.userMessage ?? ""}`).toContain(
        "target_not_allowed",
      );
    } finally {
      await provider.close();
    }
  });

  it("projects a page exception as an answer rather than a crash", async () => {
    const browser = await startFakeCdpBrowser({
      commandResult: (command) =>
        command.method === "Runtime.evaluate"
          ? exceptionReply("Error: page threw")
          : undefined,
    });
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      const result = await expectBrowserMutation(
        provider.evaluatePage({
          cdp_endpoint: browserEndpoint(browser),
          allowed_origins: [browser.allowedOrigin],
          target_id: "allowed-page",
          expression: "throw new Error('page threw')",
          await_promise: true,
        }),
      );
      expect(result).toMatchObject({
        outcome: "exception",
        exception_text: "Error: page threw",
        value_text: null,
      });
    } finally {
      await provider.close();
    }
  });

  it("truncates a larger result at the fixed byte budget", async () => {
    const oversized = "a".repeat(
      BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes + 32,
    );
    const browser = await startFakeCdpBrowser({
      commandResult: (command) =>
        command.method === "Runtime.evaluate"
          ? evaluateReply(oversized)
          : undefined,
    });
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    try {
      const result = await expectBrowserMutation(
        provider.evaluatePage({
          cdp_endpoint: browserEndpoint(browser),
          allowed_origins: [browser.allowedOrigin],
          target_id: "allowed-page",
          expression: "document.body.innerText",
          await_promise: true,
        }),
      );
      expect(result.value_truncated).toBe(true);
      expect(result.value_bytes).toBe(
        BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes,
      );
      expect(result.value_text?.length).toBe(
        BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes,
      );
    } finally {
      await provider.close();
    }
  });
});
