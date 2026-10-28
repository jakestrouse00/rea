import type { EvidenceCompletionLedger } from "../evidenceCompletionLedger.js";
import type { ResidualUnknown } from "../residualUnknown.js";
import { HUNTING_PRIORITY_WEIGHTS } from "./huntingLimits.js";

/** One counted reason the queue ordered a unit where it did. */
export const huntingPriorityReasons = [
  "coverage_fail",
  "coverage_truncated",
  "coverage_unknown",
  "coverage_complete",
  "coverage_missing",
  "unresolved_unknown",
  "resolved_unknown",
] as const;

export type HuntingPriorityReasonKind = (typeof huntingPriorityReasons)[number];

/** Counted, weighted reason; the weight is the exact contribution to the score. */
export interface HuntingPriorityReason {
  readonly kind: HuntingPriorityReasonKind;
  readonly count: number;
  readonly weight: number;
}

export interface HuntingPriority {
  readonly score: number;
  readonly reasons: readonly HuntingPriorityReason[];
}

const severityWeight = (severity: ResidualUnknown["severity"]): number =>
  severity === "critical"
    ? HUNTING_PRIORITY_WEIGHTS.unknownCritical
    : severity === "high"
      ? HUNTING_PRIORITY_WEIGHTS.unknownHigh
      : severity === "medium"
        ? HUNTING_PRIORITY_WEIGHTS.unknownMedium
        : HUNTING_PRIORITY_WEIGHTS.unknownLow;

const unresolved = (unknown: ResidualUnknown): boolean =>
  unknown.status === "open" ||
  unknown.status === "investigating" ||
  unknown.status === "blocked" ||
  unknown.status === "contradicted";

/**
 * Order one unit from the target's coverage ledger and its unknown heads.
 *
 * A ledger only records what the verifier examined: fail, truncated, and
 * unknown claims each raise the score, and pass records raise nothing because
 * finishing them again proves no more. With no ledger the coverage is missing
 * rather than complete, so the unit stays eligible at a lower weight. Unknown
 * heads weigh by their owner-reported severity, never by their text.
 */
export const huntingPriority = (input: {
  readonly coverage: EvidenceCompletionLedger | null;
  readonly unknowns: readonly ResidualUnknown[];
}): HuntingPriority => {
  const reasons: HuntingPriorityReason[] = [];
  const add = (
    kind: HuntingPriorityReasonKind,
    count: number,
    weight: number,
  ) => {
    if (count > 0) reasons.push({ kind, count, weight });
  };
  const coverage = input.coverage;
  if (coverage === null)
    add("coverage_missing", 1, HUNTING_PRIORITY_WEIGHTS.coverageMissing);
  else {
    add(
      "coverage_fail",
      coverage.summary.fail,
      HUNTING_PRIORITY_WEIGHTS.coverageFail,
    );
    add(
      "coverage_truncated",
      coverage.summary.truncated,
      HUNTING_PRIORITY_WEIGHTS.coverageTruncated,
    );
    add(
      "coverage_unknown",
      coverage.summary.unknown,
      HUNTING_PRIORITY_WEIGHTS.coverageUnknown,
    );
    if (coverage.summary.complete)
      add("coverage_complete", coverage.summary.total, 0);
  }
  // One counted reason per severity keeps the score exactly `count * weight`
  // without averaging severities into a number no head reported.
  const bySeverity: Record<ResidualUnknown["severity"], number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  let resolvedCount = 0;
  for (const unknown of input.unknowns)
    if (unresolved(unknown)) bySeverity[unknown.severity] += 1;
    else resolvedCount += 1;
  for (const severity of ["critical", "high", "medium", "low"] as const)
    add("unresolved_unknown", bySeverity[severity], severityWeight(severity));
  add("resolved_unknown", resolvedCount, 0);
  const score = Math.min(
    reasons.reduce((total, reason) => total + reason.count * reason.weight, 0),
    HUNTING_PRIORITY_WEIGHTS.maximumScore,
  );
  return { score, reasons };
};
