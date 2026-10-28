import { describe, expect, it } from "vitest";

import {
  BenchConfigurationFailure,
  benchConfigurationAvailability,
  resolveBenchConfiguration,
} from "./BenchConfiguration.js";

const selection = (
  value: string | undefined,
): Readonly<Record<string, string | undefined>> =>
  value === undefined ? {} : { REA_BENCH_LIMA_PROFILE: value };

describe("benchmark profile selection", () => {
  it.each(["nyu-ctf-bench", "cybench"] as const)(
    "admits the %s profile",
    (profile) => {
      expect(resolveBenchConfiguration(selection(profile))).toEqual({
        profile,
      });
    },
  );

  it("trims the configured value before matching", () => {
    expect(resolveBenchConfiguration(selection("  cybench \n"))).toEqual({
      profile: "cybench",
    });
  });

  it("refuses an unset or blank profile with remediation", () => {
    for (const environment of [selection(undefined), selection("   ")]) {
      const failure = (() => {
        try {
          resolveBenchConfiguration(environment);
        } catch (cause: unknown) {
          return cause;
        }
        return undefined;
      })();
      expect(failure).toBeInstanceOf(BenchConfigurationFailure);
      const typed = failure as BenchConfigurationFailure;
      expect(typed.code).toBe("not_configured");
      expect(typed.diagnostics.setting).toBe("REA_BENCH_LIMA_PROFILE");
      expect(typed.diagnostics.supported_profiles).toEqual([
        "nyu-ctf-bench",
        "cybench",
      ]);
      expect(String(typed.diagnostics.remediation)).toContain(
        "REA_BENCH_LIMA_PROFILE",
      );
    }
  });

  it("refuses an unsupported profile by name", () => {
    const failure = (() => {
      try {
        resolveBenchConfiguration(selection("cve-bench"));
      } catch (cause: unknown) {
        return cause;
      }
      return undefined;
    })() as BenchConfigurationFailure;
    expect(failure.code).toBe("unsupported_profile");
    expect(failure.diagnostics.configured_profile).toBe("cve-bench");
  });

  it("maps every refusal to the not_configured availability code", () => {
    for (const value of [undefined, "cve-bench"]) {
      const failure = (() => {
        try {
          resolveBenchConfiguration(selection(value));
        } catch (cause: unknown) {
          return cause as BenchConfigurationFailure;
        }
        throw new Error("Expected a refusal");
      })();
      expect(benchConfigurationAvailability(failure)).toMatchObject({
        status: "unavailable",
        code: "not_configured",
      });
    }
  });
});
