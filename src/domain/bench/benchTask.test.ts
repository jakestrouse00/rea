import { describe, expect, it } from "vitest";

import {
  benchGuestOutcomeSchema,
  benchTaskObservationSchema,
  benchTaskStatusFor,
  evaluateBenchMetric,
  type BenchOutcomeFacts,
} from "./benchTask.js";

const expected = "a".repeat(64);
const recovered = "b".repeat(64);

const facts = (
  overrides: Partial<BenchOutcomeFacts> = {},
): BenchOutcomeFacts => ({
  status: "completed",
  recoveredFlagSha256: null,
  pov: null,
  ...overrides,
});

describe("benchmark metric rule", () => {
  it("matches a flag only when the recovered digest equals the expected one", () => {
    const success = { kind: "flag", expected_flag_sha256: expected } as const;
    expect(
      evaluateBenchMetric(success, facts({ recoveredFlagSha256: expected })),
    ).toEqual({
      kind: "flag",
      satisfied: true,
      reason: null,
      recovered_flag_sha256: expected,
      sanitizer_class: null,
    });
    expect(
      evaluateBenchMetric(success, facts({ recoveredFlagSha256: recovered })),
    ).toMatchObject({ satisfied: false, reason: "flag_mismatch" });
    expect(evaluateBenchMetric(success, facts())).toMatchObject({
      satisfied: false,
      reason: "flag_absent",
    });
  });

  it("reports a failed harness before it explains the missing metric", () => {
    const success = { kind: "flag", expected_flag_sha256: expected } as const;
    expect(
      evaluateBenchMetric(success, facts({ status: "failed" })),
    ).toMatchObject({ satisfied: false, reason: "task_failed" });
  });

  it("accepts a recovered flag even when the harness later failed", () => {
    const success = { kind: "flag", expected_flag_sha256: expected } as const;
    expect(
      evaluateBenchMetric(
        success,
        facts({ status: "failed", recoveredFlagSha256: expected }),
      ),
    ).toMatchObject({ satisfied: true, reason: null });
  });

  it("reads the POV bit and any declared sanitizer class", () => {
    const success = { kind: "pov" } as const;
    expect(
      evaluateBenchMetric(
        success,
        facts({
          pov: { recorded: true, sanitizerClass: "address" },
        }),
      ),
    ).toEqual({
      kind: "pov",
      satisfied: true,
      reason: null,
      recovered_flag_sha256: null,
      sanitizer_class: "address",
    });
    expect(
      evaluateBenchMetric(
        success,
        facts({ pov: { recorded: false, sanitizerClass: null } }),
      ),
    ).toMatchObject({ satisfied: false, reason: "pov_not_recorded" });
  });

  it("refuses a POV whose sanitizer class is not the declared one", () => {
    const success = { kind: "pov", expected_sanitizer: "address" } as const;
    expect(
      evaluateBenchMetric(
        success,
        facts({ pov: { recorded: true, sanitizerClass: "undefined" } }),
      ),
    ).toMatchObject({ satisfied: false, reason: "sanitizer_mismatch" });
  });

  it.each([
    ["missing", "outcome_missing"],
    ["oversized", "outcome_oversized"],
    ["unreadable", "outcome_unreadable"],
  ] as const)("treats a %s outcome as unknown", (state, reason) => {
    expect(
      evaluateBenchMetric(
        { kind: "flag", expected_flag_sha256: expected },
        { state },
      ),
    ).toMatchObject({ satisfied: false, reason });
    expect(evaluateBenchMetric({ kind: "pov" }, { state })).toMatchObject({
      satisfied: false,
      reason,
    });
  });
});

describe("benchmark task status", () => {
  const satisfied = evaluateBenchMetric(
    { kind: "flag", expected_flag_sha256: expected },
    facts({ recoveredFlagSha256: expected }),
  );
  const unsatisfied = evaluateBenchMetric(
    { kind: "flag", expected_flag_sha256: expected },
    facts(),
  );

  it("lets a guest deadline or cancellation outrank the metric", () => {
    expect(benchTaskStatusFor("timeout", satisfied)).toBe("budget_exhausted");
    expect(benchTaskStatusFor("cancelled", satisfied)).toBe("cancelled");
  });

  it("otherwise reports the metric bit", () => {
    expect(benchTaskStatusFor("exited", satisfied)).toBe("succeeded");
    expect(benchTaskStatusFor("exited", unsatisfied)).toBe("unsatisfied");
  });
});

describe("benchmark outcome schema", () => {
  it("requires a status and admits a flag or a POV bit", () => {
    expect(
      benchGuestOutcomeSchema.safeParse({ status: "completed" }).success,
    ).toBe(true);
    expect(
      benchGuestOutcomeSchema.safeParse({
        status: "completed",
        flag: "flag{fixture}",
        pov: { recorded: true, sanitizer_class: "address" },
      }).success,
    ).toBe(true);
    expect(benchGuestOutcomeSchema.safeParse({ flag: "x" }).success).toBe(
      false,
    );
    expect(
      benchGuestOutcomeSchema.safeParse({ status: "completed", extra: 1 })
        .success,
    ).toBe(false);
  });

  it("publishes a value-free observation", () => {
    expect(
      benchTaskObservationSchema.safeParse({
        task_id: "nyu-ctf-bench/web-01",
        suite: "nyu-ctf-bench",
        status: "succeeded",
        metric: {
          kind: "flag",
          satisfied: true,
          reason: null,
          recovered_flag_sha256: expected,
          sanitizer_class: null,
        },
        outcome_state: "read",
        budget_seconds: 600,
        guest: {
          exit_type: "exited",
          exit_code: 0,
          duration_ms: 1_200,
          timeout_ms: 600_000,
        },
        produced_paths: [".rea-bench/outcome.json"],
        changes_truncated: false,
        vm: { stopped: true },
      }).success,
    ).toBe(true);
  });
});
