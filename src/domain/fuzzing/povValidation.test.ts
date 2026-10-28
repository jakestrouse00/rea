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

describe("POV acceptance", () => {
  it("accepts one stable sanitizer-identified crash state", () => {
    expect(
      evaluatePov({
        reports: [report("a"), report("a")],
        expectedSanitizer: undefined,
      }),
    ).toEqual({ accepted: true, reason: null });
  });

  it("refuses a candidate no reproduction parsed", () => {
    expect(evaluatePov({ reports: [], expectedSanitizer: undefined })).toEqual({
      accepted: false,
      reason: "report_unreadable",
    });
  });

  it("refuses a report whose class the caller did not expect", () => {
    expect(
      evaluatePov({
        reports: [report("a"), report("a")],
        expectedSanitizer: "undefined",
      }),
    ).toEqual({ accepted: false, reason: "unsupported_sanitizer" });
  });

  it("refuses a signal-only OS report unless the caller names that class", () => {
    expect(
      evaluatePov({
        reports: [report("a", "none"), report("a", "none")],
        expectedSanitizer: undefined,
      }),
    ).toEqual({ accepted: false, reason: "unsupported_sanitizer" });
    expect(
      evaluatePov({
        reports: [report("a", "none"), report("a", "none")],
        expectedSanitizer: "none",
      }),
    ).toEqual({ accepted: true, reason: null });
    expect(FUZZING_POV_DEFAULT_SANITIZERS).not.toContain("none");
  });

  it("refuses a report with no frames", () => {
    expect(
      evaluatePov({
        reports: [{ sanitizerClass: "address", stateHash: "a", frameCount: 0 }],
        expectedSanitizer: undefined,
      }),
    ).toEqual({ accepted: false, reason: "no_frames" });
  });

  it("refuses a candidate whose reproductions disagree on the crash state", () => {
    expect(
      evaluatePov({
        reports: [report("a"), report("b")],
        expectedSanitizer: undefined,
      }),
    ).toEqual({ accepted: false, reason: "unstable_state" });
  });
});
