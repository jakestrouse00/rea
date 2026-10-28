import { describe, expect, it } from "vitest";

import {
  evaluatePov,
  FUZZING_POV_DEFAULT_SANITIZERS,
} from "./povValidation.js";

const report = (
  stateHash: string,
  sanitizerClass: "address" | "none" = "address",
) => ({
  sanitizerClass,
  stateHash,
  frameCount: 3,
});

const evidence = (
  reports: ReturnType<typeof report>[],
  expectedSanitizer: "address" | "none" | "undefined" | "thread" | undefined,
  requestedReproductions = 2,
) => ({ reports, expectedSanitizer, requestedReproductions });

describe("POV acceptance", () => {
  it("accepts one stable sanitizer-identified crash state", () => {
    expect(
      evaluatePov(evidence([report("a"), report("a")], undefined)),
    ).toEqual({ accepted: true, reason: null });
  });

  it("refuses a candidate no reproduction parsed", () => {
    expect(evaluatePov(evidence([], undefined))).toEqual({
      accepted: false,
      reason: "report_unreadable",
    });
  });

  it("refuses a report whose class the caller did not expect", () => {
    expect(
      evaluatePov(evidence([report("a"), report("a")], "undefined")),
    ).toEqual({ accepted: false, reason: "unsupported_sanitizer" });
  });

  it("refuses a signal-only OS report unless the caller names that class", () => {
    expect(
      evaluatePov(
        evidence([report("a", "none"), report("a", "none")], undefined),
      ),
    ).toEqual({ accepted: false, reason: "unsupported_sanitizer" });
    expect(
      evaluatePov(evidence([report("a", "none"), report("a", "none")], "none")),
    ).toEqual({ accepted: true, reason: null });
    expect(FUZZING_POV_DEFAULT_SANITIZERS).not.toContain("none");
  });

  it("refuses a report with no frames", () => {
    expect(
      evaluatePov(
        evidence(
          [{ sanitizerClass: "address", stateHash: "a", frameCount: 0 }],
          undefined,
          1,
        ),
      ),
    ).toEqual({ accepted: false, reason: "no_frames" });
  });

  it("refuses a candidate that crashed in fewer runs than requested", () => {
    expect(evaluatePov(evidence([report("a")], undefined, 2))).toEqual({
      accepted: false,
      reason: "not_reproduced",
    });
  });

  it("refuses a candidate whose reproductions disagree on the crash state", () => {
    expect(
      evaluatePov(evidence([report("a"), report("b")], undefined)),
    ).toEqual({ accepted: false, reason: "unstable_state" });
  });
});
