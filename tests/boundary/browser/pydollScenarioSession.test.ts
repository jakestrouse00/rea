import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { browserScenarioSchema } from "../../../src/domain/browserScenario.js";
import { ProviderAdapterError } from "../../../src/domain/providerAdapterError.js";
import { BrowserObservationError } from "../../../src/domain/browserObservationError.js";
import { PydollScenarioSession } from "../../../src/browser/PydollScenarioSession.js";
import { browserScenarioEventSchema } from "../../../src/domain/browserScenarioCaptureValues.js";

const FIXTURE_PATH = resolve(
  fileURLToPath(new URL("./fixtures/pydollFakeBridge.mjs", import.meta.url)),
);
const BROKEN_FIXTURE = resolve(
  fileURLToPath(
    new URL("./fixtures/pydollFakeBridgeBroken.mjs", import.meta.url),
  ),
);
const DELAYED_CLOSE_FIXTURE = resolve(
  fileURLToPath(
    new URL("./fixtures/pydollFakeBridgeDelayedClose.mjs", import.meta.url),
  ),
);
const DENIED_CLOSE_FIXTURE = resolve(
  fileURLToPath(
    new URL("./fixtures/pydollFakeBridgeDeniedClose.mjs", import.meta.url),
  ),
);
const PROBE_FAIL_FIXTURE = resolve(
  fileURLToPath(
    new URL("./fixtures/pydollFakeBridgeProbeFail.mjs", import.meta.url),
  ),
);

const baseEnvironment = (script: string = FIXTURE_PATH) => ({
  REA_PYDOLL_COMMAND: process.execPath,
  REA_PYDOLL_SCRIPT: script,
});

const launchScenario = () =>
  browserScenarioSchema.parse({
    browser: {
      mode: "launch",
      executable_path: process.execPath,
      headless: true,
    },
    start_url: { url: "https://app.example.test/", query: [] },
    actions: [
      { action: "wait_for_timeout", step_id: "settle", duration_ms: 10 },
    ],
    capture: { after_each_step: [], at_end: ["url"], events: ["network"] },
  });

const connectScenario = () =>
  browserScenarioSchema.parse({
    browser: {
      mode: "connect",
      cdp_endpoint: "http://127.0.0.1:9250",
      target_id: "PYDOLL_ADMISSION_TARGET",
    },
    start_url: { url: "https://app.example.test/", query: [] },
    actions: [
      { action: "wait_for_timeout", step_id: "settle", duration_ms: 10 },
    ],
    capture: { after_each_step: [], at_end: ["url"], events: ["network"] },
  });

const interpreterPidFromNotes = (limitations: readonly string[]) =>
  limitations.flatMap((limitation) => {
    const match = /interpreter pid (\d+)/u.exec(limitation);
    return match === null ? [] : [Number(match[1])];
  })[0];

const pidMissingFromHost = async (pid: number): Promise<boolean> => {
  try {
    process.kill(pid, 0);
    return false;
  } catch {
    return true;
  }
};

describe("PydollScenarioSession lifecycle", () => {
  test("open, perform, capture, and close through the protocol", async () => {
    const session = await PydollScenarioSession.open(
      launchScenario(),
      baseEnvironment(),
      {},
    );
    try {
      expect(session.driver).toBe("pydoll");
      expect(session.mode).toBe("launch");
      expect(session.processOwnership).toBe("provider-owned");
      expect(session.version).toBe("Fake Chromium 140");
      expect(session.currentUrl()).toBe("https://app.example.test/after");
      await session.perform({
        action: "wait_for_timeout",
        step_id: "settle",
        duration_ms: 10,
      });
      session.setStep(1);
      const artifacts = await session.capture(new Set(["url"]));
      expect(artifacts.url.state).toBe("captured");
      const events = session.events();
      const validated = [...events.items].map((event) =>
        browserScenarioEventSchema.parse(event),
      );
      expect(validated.some((event) => event.kind === "request")).toBe(true);
      expect(
        validated.every(
          (event) => event.kind !== "response" || event.status === 200,
        ),
      ).toBe(true);
      expect(session.eventLimitations().length).toBeGreaterThan(0);
    } finally {
      expect(await session.close()).toBe("terminated-owned-process");
    }
  }, 30_000);

  test("a child that never advertises fails as a provider adapter error", async () => {
    const open = PydollScenarioSession.open(
      launchScenario(),
      baseEnvironment(BROKEN_FIXTURE),
      { signal: AbortSignal.timeout(20_000) },
    );
    await expect(open).rejects.toBeInstanceOf(ProviderAdapterError);
  }, 40_000);

  test("a failed open releases the connect-mode admission for a later scenario", async () => {
    const failed = await PydollScenarioSession.open(
      connectScenario(),
      baseEnvironment(BROKEN_FIXTURE),
      {},
    ).catch((cause: unknown) => cause);
    expect(failed).toBeInstanceOf(ProviderAdapterError);
    const session = await PydollScenarioSession.open(
      connectScenario(),
      baseEnvironment(),
      {
        signal: AbortSignal.timeout(20_000),
      },
    );
    try {
      expect(session.mode).toBe("connect");
    } finally {
      expect(await session.close()).toBe("disconnected-external");
    }
  }, 60_000);

  test("the bridge queue-overflow marker survives the event collector", async () => {
    const session = await PydollScenarioSession.open(
      launchScenario(),
      baseEnvironment(),
      {},
    );
    try {
      expect(
        session
          .eventLimitations()
          .some((limitation) =>
            limitation.includes(
              "The bridge dropped 3 queued events when its bounded event queue overflowed",
            ),
          ),
      ).toBe(true);
    } finally {
      expect(await session.close()).toBe("terminated-owned-process");
    }
  }, 30_000);

  test("history capture falls back to the tracked session URL without a url artifact", async () => {
    const session = await PydollScenarioSession.open(
      launchScenario(),
      baseEnvironment(),
      {},
    );
    try {
      expect(session.currentUrl()).toBe("https://app.example.test/after");
      const artifacts = await session.capture(new Set(["history"]));
      expect(artifacts.url.state).toBe("not_requested");
      expect(artifacts.history.state).toBe("captured");
      if (artifacts.history.state !== "captured")
        throw new Error("history capture must be present");
      expect(artifacts.history.value.current_url.url).toBe(
        "https://app.example.test/after",
      );
      expect(artifacts.history.value.navigation_entries).toHaveLength(2);
    } finally {
      expect(await session.close()).toBe("terminated-owned-process");
    }
  }, 30_000);
});

describe("PydollScenarioSession teardown", () => {
  test("cancellation arriving during teardown still settles the owned bridge", async () => {
    const controller = new AbortController();
    const session = await PydollScenarioSession.open(
      launchScenario(),
      baseEnvironment(DELAYED_CLOSE_FIXTURE),
      { signal: controller.signal },
    );
    controller.abort();
    expect(await session.close()).toBe("terminated-owned-process");
    expect(session.cleanupLease.released).toBe(true);
  }, 60_000);

  test("a denied close_session retains its cleanup failure with the owning session (connect)", async () => {
    const session = await PydollScenarioSession.open(
      connectScenario(),
      baseEnvironment(DENIED_CLOSE_FIXTURE),
      { signal: AbortSignal.timeout(30_000) },
    );
    await session.perform({
      action: "wait_for_timeout",
      step_id: "settle",
      duration_ms: 10,
    });
    const interpreterPid = interpreterPidFromNotes(session.eventLimitations());
    if (interpreterPid === undefined)
      throw new Error("fixture pid note missing");
    const cause = await session.close().catch((cause: unknown) => cause);
    if (!(cause instanceof BrowserObservationError))
      throw new Error("Expected a typed cleanup failure");
    expect(cause.reason).toBe("cleanup_failed");
    expect(cause.cleanupIncomplete).toBe(true);
    expect(cause.cleanup?.reason).toContain(
      "close denied by the bridge interpreter",
    );
    expect(cause.cleanup?.resources).toContain("browser_transport");
    expect(session.cleanupLease.released).toBe(false);
    await expect
      .poll(() => pidMissingFromHost(interpreterPid), { timeout: 10_000 })
      .toBe(true);
  }, 60_000);

  test("a denied close_session escalates through SIGTERM and the bridge goes away (launch)", async () => {
    const session = await PydollScenarioSession.open(
      launchScenario(),
      baseEnvironment(DENIED_CLOSE_FIXTURE),
      { signal: AbortSignal.timeout(30_000) },
    );
    await session.perform({
      action: "wait_for_timeout",
      step_id: "settle",
      duration_ms: 10,
    });
    const interpreterPid = interpreterPidFromNotes(session.eventLimitations());
    if (interpreterPid === undefined)
      throw new Error("fixture pid note missing");
    // The child never produced a close_session outcome; the mode-based
    // inference still reports the owned termination after escalation.
    expect(await session.close()).toBe("terminated-owned-process");
    expect(session.cleanupLease.released).toBe(true);
    await expect
      .poll(() => pidMissingFromHost(interpreterPid), { timeout: 10_000 })
      .toBe(true);
  }, 60_000);

  test("cancellation during an action releases the session cleanly with a stop request", async () => {
    const controller = new AbortController();
    const session = await PydollScenarioSession.open(
      launchScenario(),
      baseEnvironment(),
      { signal: controller.signal },
    );
    controller.abort();
    await expect(
      session.perform({
        action: "wait_for_timeout",
        step_id: "late",
        duration_ms: 60_000,
      }),
    ).rejects.toThrow();
    expect(await session.close()).toBe("terminated-owned-process");
  }, 40_000);

  test("a probe failure surfaces as a capability error when pydoll is missing", async () => {
    const open = PydollScenarioSession.open(
      launchScenario(),
      baseEnvironment(PROBE_FAIL_FIXTURE),
      {},
    );
    await expect(open).rejects.toThrow(/pydoll/);
  }, 40_000);
});
