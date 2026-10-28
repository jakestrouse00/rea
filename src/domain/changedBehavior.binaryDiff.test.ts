import { describe, expect, it } from "vitest";

import { BINARY_DIFF_PROVIDER } from "./comparisonEvidenceIdentity.js";
import { binaryDiffResultSchema } from "./bindiff/binaryDiff.js";
import { findChangedBehavior } from "./changedBehavior.js";
import { createEvidence, type Evidence } from "./evidence.js";

const source = (digit: string): Evidence =>
  createEvidence(
    {
      path: `/tmp/sample-${digit}.bin`,
      sha256: digit.repeat(64),
      format: "elf",
      architecture: "x86_64",
    },
    { id: "rea-artifact-graph", name: "Fixture inventory", version: "1" },
    {
      operation: "inspect_artifact",
      predicateType: "rea.artifact",
      parameters: {},
      result: { ok: true },
    },
  );

const result = binaryDiffResultSchema.parse({
  status: "changed",
  function_match: {
    matched: 2,
    unmatched_primary: 1,
    unmatched_secondary: 0,
  },
  left_subject_sha256: "1".repeat(64),
  right_subject_sha256: "2".repeat(64),
  summary: { matched: 2, changed: 1, unresolved: 1 },
  matches: [
    {
      primary_address: "0x401000",
      primary_name: "old_name",
      secondary_address: "0x401020",
      secondary_name: "new_name",
      similarity: 1,
      confidence: 0.9,
      names_changed: true,
    },
    {
      primary_address: "0x401100",
      primary_name: "weak",
      secondary_address: "0x401140",
      secondary_name: "weak",
      similarity: 0.7,
      confidence: 0.4,
      names_changed: false,
    },
  ],
  changes: [
    {
      primary_address: "0x401000",
      primary_name: "old_name",
      secondary_address: "0x401020",
      secondary_name: "new_name",
      similarity: 1,
      confidence: 0.9,
      names_changed: true,
    },
  ],
  limitations: ["fixture limitation"],
});

describe("changed behavior over provider-backed binary diffs", () => {
  it("aggregates diff_binaries Evidence as static candidates", () => {
    const left = source("1");
    const right = source("2");
    const diff = createEvidence(undefined, BINARY_DIFF_PROVIDER, {
      predicateType: "rea.binary-diff",
      operation: "diff_binaries",
      parameters: {
        left_evidence_id: left.evidence_id,
        right_evidence_id: right.evidence_id,
      },
      result,
      confidence: "derived",
      authority: "analyst-inference",
      limitations: result.limitations,
      evidenceLinks: [left.evidence_id, right.evidence_id],
    });
    const aggregate = findChangedBehavior({ comparisons: [diff] });
    expect(aggregate.result.behavior_status).toBe("unknown");
    expect(aggregate.result.summary).toEqual({
      observed_changes: 0,
      static_candidates: 1,
      contradictions: 0,
      unresolved: 1,
    });
    expect(
      aggregate.result.findings.items.map(({ dimension }) => dimension),
    ).toEqual(["binary-diff:coverage", "binary-diff:old_name->new_name"]);
    expect(aggregate.comparisonEvidenceIds).toEqual([diff.evidence_id]);
  });
});
