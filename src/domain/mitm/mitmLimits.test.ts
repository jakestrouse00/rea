import { describe, expect, it } from "vitest";

import {
  MITM_LIMITS,
  MITM_TARGET_APPS,
  mitmProxyGuidance,
} from "./mitmLimits.js";

describe("per-application proxy guidance", () => {
  it("stays per-application and refuses every device-wide mode", () => {
    for (const targetApp of MITM_TARGET_APPS) {
      const guidance = mitmProxyGuidance(targetApp, 8_080, "com.example.app");
      expect(guidance.target_app, targetApp).toBe(targetApp);
      expect(guidance.per_app_only).toBe(true);
      expect(guidance.steps.length).toBeGreaterThan(0);
      for (const step of guidance.steps)
        expect(step, targetApp).toMatch(/profile|package|application|proxy/i);
      const outOfScope = guidance.out_of_scope.join(" ");
      expect(outOfScope).toContain("trust store");
      expect(outOfScope).toContain("system-wide");
      expect(outOfScope).toContain("pinning");
    }
  });

  it("names the port and the application's own switch", () => {
    const browser = mitmProxyGuidance("browser", 9_090, undefined);
    expect(browser.steps.join(" ")).toContain(
      "--proxy-server=http://127.0.0.1:9090",
    );
    const android = mitmProxyGuidance("android-app", 9_090, "com.example.app");
    expect(android.steps.join(" ")).toContain("adb reverse tcp:9090 tcp:9090");
    const desktop = mitmProxyGuidance("desktop-app", 9_090, undefined);
    expect(desktop.steps.join(" ")).toContain(
      "HTTPS_PROXY=http://127.0.0.1:9090",
    );
    const other = mitmProxyGuidance("other", 9_090, "harness");
    expect(other.steps.join(" ")).toContain("harness");
  });

  it("keeps the fixed lane bounds internally consistent", () => {
    expect(MITM_LIMITS.defaultListenPort).toBeLessThanOrEqual(
      MITM_LIMITS.maxListenPort,
    );
    expect(MITM_LIMITS.defaultRuleTtlMs).toBeLessThanOrEqual(
      MITM_LIMITS.maxRuleTtlMs,
    );
    expect(MITM_LIMITS.defaultStartTimeoutMs).toBeLessThanOrEqual(
      MITM_LIMITS.maxStartTimeoutMs,
    );
    expect(MITM_LIMITS.maxListedEndpoints).toBeLessThanOrEqual(
      MITM_LIMITS.maxEndpoints,
    );
  });
});
