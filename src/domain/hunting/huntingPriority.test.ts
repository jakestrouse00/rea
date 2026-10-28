import { describe, expect, it } from "vitest";

import { createEvidenceCompletionLedger } from "../evidenceCompletionLedger.js";
import {
  createResidualUnknown,
  recordUnknownInputSchema,
  type ResidualUnknown,
} from "../residualUnknown.js";
import { huntingPriority } from "./huntingPriority.js";

const evidenceId = `ev_${"a".repeat(64)}`;

const ledgerOf = (
  ...statuses: readonly ("pass" | "fail" | "unknown" | "truncated")[]
) =>
  createEvidenceCompletionLedger(
    statuses.map((status, index) => ({
      claim_id: `claim-${String(index)}`,
      status,
      evidence_ids: [evidenceId],
    })),
  );

const unknownOf = (
  question: string,
  severity: ResidualUnknown["severity"],
  status: ResidualUnknown["status"] = "open",
): ResidualUnknown => {
  const created = createResidualUnknown(
    recordUnknownInputSchema.parse({
      question,
      severity,
      domain: "hunting",
      required_authority: null,
      required_confidence: "observed",
      required_environment: null,
      recommended_probes: [],
      relationships: [],
    }),
    evidenceId,
    null,
  );
  return status === "open" ? created : { ...created, status };
};

describe("hunting priority", () => {
  it("treats a missing ledger as missing coverage rather than complete", () => {
    const priority = huntingPriority({ coverage: null, unknowns: [] });
    expect(priority.score).toBe(5);
    expect(priority.reasons).toEqual([
      { kind: "coverage_missing", count: 1, weight: 5 },
    ]);
  });

  it("raises failing and truncated claims without counting passes", () => {
    const priority = huntingPriority({
      coverage: ledgerOf("fail", "truncated", "unknown", "pass"),
      unknowns: [],
    });
    expect(priority.reasons).toEqual([
      { kind: "coverage_fail", count: 1, weight: 40 },
      { kind: "coverage_truncated", count: 1, weight: 20 },
      { kind: "coverage_unknown", count: 1, weight: 10 },
    ]);
    expect(priority.score).toBe(70);
  });

  it("records complete coverage with a zero weight", () => {
    const priority = huntingPriority({
      coverage: ledgerOf("pass", "pass"),
      unknowns: [],
    });
    expect(priority.score).toBe(0);
    expect(priority.reasons).toEqual([
      { kind: "coverage_complete", count: 2, weight: 0 },
    ]);
  });

  it("weighs unresolved unknown heads by their severity and ignores resolved ones", () => {
    const priority = huntingPriority({
      coverage: null,
      unknowns: [
        unknownOf("Is the parser boundary covered?", "critical"),
        unknownOf("Is the string table complete?", "low", "blocked"),
        unknownOf("Was the entry point proven?", "high", "resolved"),
      ],
    });
    expect(priority.reasons).toContainEqual({
      kind: "unresolved_unknown",
      count: 1,
      weight: 80,
    });
    expect(priority.reasons).toContainEqual({
      kind: "unresolved_unknown",
      count: 1,
      weight: 5,
    });
    expect(priority.reasons).toContainEqual({
      kind: "resolved_unknown",
      count: 1,
      weight: 0,
    });
    expect(priority.score).toBe(90);
  });

  it("sums every counted reason and caps only at the fixed maximum", () => {
    const priority = huntingPriority({
      coverage: ledgerOf(...Array.from({ length: 40 }, () => "fail" as const)),
      unknowns: [],
    });
    expect(priority.score).toBe(1_600);
    const capped = huntingPriority({
      coverage: ledgerOf(
        ...Array.from({ length: 26_000 }, () => "fail" as const),
      ),
      unknowns: [],
    });
    expect(capped.score).toBe(1_000_000);
  });
});
