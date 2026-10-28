import { z } from "zod";

import {
  sanitizerClassSchema,
  type SanitizerClass,
} from "../crashTriage/crashReport.js";

/**
 * Why a candidate crash was not accepted as a proof of vulnerability.
 *
 * The vocabulary is AIxCC/Buttercup-shaped: a candidate becomes a POV only
 * when the target reproduces it, the runtime names a sanitizer class, the
 * report carries frames, and repeated reproductions agree on the crash state.
 */
export const FUZZING_POV_REJECTIONS = [
  "missing_input",
  "not_reproduced",
  "report_unreadable",
  "report_too_large",
  "unsupported_sanitizer",
  "no_frames",
  "unstable_state",
] as const;

export const fuzzingPovRejectionSchema = z.enum(FUZZING_POV_REJECTIONS);
export type FuzzingPovRejection = z.infer<typeof fuzzingPovRejectionSchema>;

/**
 * Sanitizer classes a POV may carry when the caller names none.
 *
 * A signal-only OS crash report (`none`) describes a crash without a
 * sanitizer-identified defect, so a caller must declare that class explicitly
 * to accept it.
 */
export const FUZZING_POV_DEFAULT_SANITIZERS: readonly SanitizerClass[] = [
  "address",
  "thread",
  "undefined",
  "leak",
  "memory",
];

/** One candidate's reproduction evidence, in run order. */
export interface FuzzingPovEvidence {
  /** Parsed reports, one per completed reproduction, in run order. */
  readonly reports: readonly {
    readonly sanitizerClass: SanitizerClass;
    readonly stateHash: string;
    readonly frameCount: number;
  }[];
  /** Caller-declared class the reproduced report must equal. */
  readonly expectedSanitizer: SanitizerClass | undefined;
}

/** The acceptance decision for one candidate crash. */
export interface FuzzingPovDecision {
  readonly accepted: boolean;
  readonly reason: FuzzingPovRejection | null;
}

const rejected = (reason: FuzzingPovRejection): FuzzingPovDecision => ({
  accepted: false,
  reason,
});

/**
 * Decide whether one candidate is a validated POV.
 *
 * The rule is pattern-only and engine-agnostic: every reproduction must parse,
 * the caller's expected class (or the default sanitizer set) must be named,
 * frames must exist, and every repetition must agree on the crash state hash.
 * The hash already covers the sanitizer class, crash kind, and normalized top
 * frames, so agreement is a stable signature rather than an address match.
 */
export const evaluatePov = (
  evidence: FuzzingPovEvidence,
): FuzzingPovDecision => {
  if (evidence.reports.length === 0) return rejected("report_unreadable");
  const expected = evidence.expectedSanitizer;
  const classes = evidence.reports.map((report) => report.sanitizerClass);
  const acceptedClasses =
    expected === undefined ? FUZZING_POV_DEFAULT_SANITIZERS : [expected];
  if (classes.some((value) => !acceptedClasses.includes(value)))
    return rejected("unsupported_sanitizer");
  if (evidence.reports.some((report) => report.frameCount === 0))
    return rejected("no_frames");
  const states = new Set(evidence.reports.map((report) => report.stateHash));
  if (states.size !== 1) return rejected("unstable_state");
  return { accepted: true, reason: null };
};

/** Sanitizer class field shared by the campaign input and its observation. */
export const expectedSanitizerField = sanitizerClassSchema
  .optional()
  .describe(
    "Sanitizer class every reproduced report must name to be accepted as a POV (address, thread, undefined, leak, memory, or none). Omit to accept any sanitizer-identified class but refuse signal-only OS reports.",
  );
