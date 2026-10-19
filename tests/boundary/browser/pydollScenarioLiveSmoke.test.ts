import { describe, expect, test } from "vitest";

import { PydollBrowserScenarioProvider } from "../../../src/browser/PydollBrowserScenarioProvider.js";
import { browserScenarioSchema } from "../../../src/domain/browserScenario.js";

/**
 * Live smoke against a locally launched pydoll-keeper Chrome (port 9250) and a
 * local fixture server (port 8931). Gated: it launches nothing on its own, so
 * ordinary test runs stay offline.
 */
const SMOKE_ENV = process.env.REA_PYDOLL_SMOKE === "1";
/** The smoke never defaults a CDP endpoint: a missing explicit endpoint fails closed. */
const SMOKE_CDP_ENDPOINT = process.env.REA_PYDOLL_SMOKE_CDP ?? "";
/** The smoke never defaults a pydoll interpreter either. */
const SMOKE_PYDOLL_COMMAND = process.env.REA_PYDOLL_COMMAND ?? "";

describe.skipIf(
  !SMOKE_ENV || SMOKE_CDP_ENDPOINT === "" || SMOKE_PYDOLL_COMMAND === "",
)("pydoll scenario live smoke (connect)", () => {
  test("one connect-mode scenario over the real bridge", async () => {
    if (SMOKE_CDP_ENDPOINT === "")
      throw new Error(
        "REA_PYDOLL_SMOKE_CDP must name an isolated fixture browser",
      );
    if (SMOKE_PYDOLL_COMMAND === "")
      throw new Error(
        "REA_PYDOLL_COMMAND must name an absolute interpreter with pydoll installed",
      );
    const list = (await (
      await fetch(`${SMOKE_CDP_ENDPOINT}/json/list`, {
        signal: AbortSignal.timeout(5_000),
      })
    ).json()) as Array<{ id?: string; type?: string; url?: string }>;
    const page = list.find(
      (target: { type?: string; url?: string }) =>
        target.type === "page" &&
        (target.url ?? "").startsWith("http://127.0.0.1:8931"),
    );
    if (page === undefined)
      throw new Error(
        `no fixture page target found; targets=${JSON.stringify(list.map((target: { url?: string }) => target.url))}`,
      );
    const scenario = browserScenarioSchema.parse({
      browser: {
        mode: "connect",
        cdp_endpoint: SMOKE_CDP_ENDPOINT,
        target_id: page.id,
      },
      start_url: { url: "http://127.0.0.1:8931/index.html", query: [] },
      actions: [
        {
          action: "wait_for",
          step_id: "button_ready",
          locator: { kind: "css", selector: "[data-testid=go]" },
          state: "visible",
          timeout_ms: 15_000,
        },
        {
          action: "click",
          step_id: "press_go",
          locator: { kind: "test_id", value: "go" },
          timeout_ms: 15_000,
        },
      ],
      environment: {
        viewport: { width: 1200, height: 800, device_scale_factor: 1 },
      },
      capture: {
        after_each_step: ["url"],
        at_end: ["url", "screenshot"],
        events: ["network", "frames"],
      },
    });
    const provider = new PydollBrowserScenarioProvider({
      REA_PYDOLL_COMMAND: SMOKE_PYDOLL_COMMAND,
    });
    const result = await provider.captureScenario(scenario, {});
    if (!result.ok) {
      const error = result.error as unknown as Record<string, unknown>;
      throw new Error(
        `scenario failed: ${JSON.stringify(
          {
            message: error.message,
            reason: (error as { reason?: unknown }).reason,
            detail: (error as { detail?: unknown }).detail,
            cleanup: (error as { cleanup?: unknown }).cleanup,
            partialLimitations:
              (
                error as {
                  partialObservation?: { capture?: { limitations?: unknown } };
                }
              ).partialObservation?.capture?.limitations ?? undefined,
          },
          null,
          2,
        )}`,
      );
    }
    const capture = result.value;
    expect(capture.browser.mode).toBe("connect");
    expect(capture.browser.cleanup).toBe("disconnected-external");
    expect(capture.steps.every((step) => step.status === "completed")).toBe(
      true,
    );
    expect(capture.steps[1]!.after_url.url).toContain("127.0.0.1:8931");
    expect(
      capture.steps[capture.steps.length - 1]!.artifacts.screenshot.state,
    ).toBe("captured");
    const eventKinds = new Set(capture.events.items.map((event) => event.kind));
    expect(eventKinds.has("request")).toBe(true);
    expect(eventKinds.has("frame-navigated")).toBe(true);
  }, 120_000);
});
