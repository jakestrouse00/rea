import { describe, expect, it } from "vitest";

import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import { inspectWebPageInputSchema } from "../../../src/domain/browserObservation.js";
import { analyzeWebBundleInputSchema } from "../../../src/domain/webBundleAnalysis.js";
import { startFakeCdpBrowser } from "../../fixtures/fakeCdpBrowser.js";
import { trackBrowser } from "./cdpBrowserProvider.support.js";

type FakeBrowser = Awaited<ReturnType<typeof startFakeCdpBrowser>>;

const inspectInput = (
  browser: FakeBrowser,
  extra: Record<string, unknown> = {},
) =>
  inspectWebPageInputSchema.parse({
    cdp_endpoint: browser.endpoint,
    allowed_origins: [browser.allowedOrigin],
    target_id: "allowed-page",
    observation_ms: 1,
    ...extra,
  });

const enabledCommands = (browser: FakeBrowser): string[] =>
  browser.commands
    .map(({ method }) => method)
    .filter((method) => method.endsWith(".enable"));

const debuggerRoutedCommands = (browser: FakeBrowser): string[] =>
  browser.commands
    .map(({ method }) => method)
    .filter(
      (method) =>
        method.startsWith("Runtime.") || method.startsWith("Debugger."),
    );

it("defaults to today's attach sequence when stealth_safe is absent or false", async () => {
  expect(
    inspectWebPageInputSchema.parse({
      cdp_endpoint: "http://127.0.0.1:9222",
      target_id: "target",
    }).stealth_safe,
  ).toBe(false);
  const browser = await startFakeCdpBrowser();
  trackBrowser(browser);
  const result = await new CdpBrowserProvider().inspectPage(
    inspectInput(browser, { stealth_safe: false }),
  );
  if (!result.ok) throw result.error;
  expect(enabledCommands(browser)).toEqual([
    "Page.enable",
    "Runtime.enable",
    "Debugger.enable",
    "Network.enable",
  ]);
  expect(result.value.limitations).not.toContainEqual(
    expect.stringContaining("Stealth-safe attach"),
  );
});

describe("stealth-safe CDP attach", () => {
  it("never sends Runtime or Debugger commands and reports their sections as missing with reasons", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const result = await new CdpBrowserProvider().inspectPage(
      inspectInput(browser, { stealth_safe: true }),
    );
    if (!result.ok) throw result.error;
    expect(enabledCommands(browser)).toEqual(["Page.enable", "Network.enable"]);
    expect(debuggerRoutedCommands(browser)).toEqual([]);
    expect(result.value.network.requests).toEqual([
      expect.objectContaining({
        request_id: "request-1",
        url: `${browser.allowedOrigin}/api?token=network-secret`,
        status: 200,
      }),
    ]);
    expect(result.value.network.websocket_connections).toHaveLength(1);
    expect(result.value.scripts).toEqual({ total: 0, items: [] });
    expect(result.value.console.events).toEqual([]);
    expect(result.value.completeness.status).toBe("policy_filtered");
    expect(result.value.completeness.policy_filtered_sections).toEqual(
      expect.arrayContaining(["scripts", "console_events"]),
    );
    expect(result.value.completeness.unavailable_sections).not.toContain(
      "scripts",
    );
    expect(result.value.completeness.unavailable_sections).not.toContain(
      "console_events",
    );
    expect(result.value.completeness.excluded).toContainEqual({
      section: "scripts",
      reason: "stealth_safe_requested",
      count: null,
    });
    expect(result.value.completeness.excluded).toContainEqual({
      section: "console_events",
      reason: "stealth_safe_requested",
      count: null,
    });
    expect(result.value.limitations).toContainEqual(
      expect.stringContaining(
        "Stealth-safe attach: Runtime and Debugger domains were not enabled",
      ),
    );
  });

  it("returns conflicting script and console requests as missing with reasons instead of silently enabling", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const result = await new CdpBrowserProvider().inspectPage(
      inspectInput(browser, {
        stealth_safe: true,
        include_script_sources: true,
        include_console_text: true,
      }),
    );
    if (!result.ok) throw result.error;
    expect(browser.commands.map(({ method }) => method)).not.toContain(
      "Debugger.getScriptSource",
    );
    expect(debuggerRoutedCommands(browser)).toEqual([]);
    expect(result.value.scripts).toEqual({ total: 0, items: [] });
    expect(result.value.completeness.excluded).toContainEqual({
      section: "script_sources",
      reason: "stealth_safe_requested",
      count: null,
    });
    expect(result.value.completeness.excluded).toContainEqual({
      section: "console_text",
      reason: "stealth_safe_requested",
      count: null,
    });
    expect(result.value.limitations).toContainEqual(
      expect.stringContaining("Stealth-safe attach"),
    );
  });

  it("accepts stealth_safe in the analyze_web_bundle contract with the same defaults", () => {
    expect(
      analyzeWebBundleInputSchema.parse({
        cdp_endpoint: "http://127.0.0.1:9222",
        target_id: "target",
        stealth_safe: true,
      }),
    ).toMatchObject({
      stealth_safe: true,
      include_script_sources: true,
      fetch_source_maps: false,
    });
    expect(
      analyzeWebBundleInputSchema.parse({
        cdp_endpoint: "http://127.0.0.1:9222",
        target_id: "target",
      }),
    ).toMatchObject({ stealth_safe: false });
  });
});
