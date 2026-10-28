/** Suffixes bytenode and similar packers use for V8 cached-data artifacts. */
const V8_BYTECODE_SUFFIXES = [".jsc", ".bytecode"] as const;

/** Instruction naming the exact next tool for one listed candidate. */
export const V8_BYTECODE_HANDOFF_INSTRUCTION =
  "Publish each candidate's bytes to an owner-only local path, then call decompile_v8_bytecode with that path and an absolute REA_VIEW8_COMMAND pointing at a locally built View8. Suffix-based candidates are hypotheses: a .jsc file may carry plain text or another container, and a header match does not prove that this V8 build produced the payload.";

/** Classify one archive member path as a V8 bytecode candidate by suffix. */
export const isV8BytecodeCandidatePath = (path: string): boolean => {
  const lower = path.toLowerCase();
  return V8_BYTECODE_SUFFIXES.some((suffix) => lower.endsWith(suffix));
};

/** Order candidates by path so repeated inspection of the same archive is stable. */
export const compareCandidatePaths = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;
