import { createHash } from "node:crypto";

import { prefixedDigestSchema } from "../digests.js";
import type { CrashFrame, SanitizerClass } from "./crashReport.js";

/** Frames hashed by default when a campaign does not choose a window. */
export const CRASH_STATE_DEFAULT_FRAMES = 3;

/** Widest caller-selectable frame window; wider windows stop merging regressions. */
export const CRASH_STATE_MAX_FRAMES = 8;

/** Characters retained from one normalized frame. */
export const CRASH_STATE_MAX_FRAME_CHARS = 160;

/** Placeholder function name when a report carried no symbol and no module. */
export const CRASH_STATE_UNKNOWN_FRAME = "<unknown>";

/** Digest-shaped identity of one crash state. */
export const crashDedupIdSchema = prefixedDigestSchema("dedup");

/** One crash state: the normalized frames and the identity derived from them. */
export interface CrashState {
  /** Lowercase SHA-256 over the sanitizer class, crash kind, and normalized frames. */
  readonly dedup_hash: string;
  /** `dedup_<hash>`, shaped like every other REA prefixed digest. */
  readonly dedup_id: string;
  /** Normalized frames joined by newlines, in report order. */
  readonly state: string;
  /** Every normalized frame the window considered, in report order. */
  readonly frames: readonly string[];
  /** Frames the hash covers. */
  readonly frames_used: number;
  /** Frames the report carried beyond the chosen window. */
  readonly frames_omitted: number;
}

const ADDRESS = /\b0x[0-9a-fA-F]+\b/gu;
const DECIMAL = /\d+/gu;
const WHITESPACE = /\s+/gu;

const basename = (value: string): string => {
  const parts = value.split(/[\\/]/u);
  return parts[parts.length - 1] ?? value;
};

/**
 * Replace a trailing argument list with `()` so `parse(int)` and `parse(long)`
 * are the same frame while the function identity survives.
 */
const withoutArguments = (symbol: string): string => {
  if (!symbol.endsWith(")")) return symbol;
  let depth = 0;
  for (let index = symbol.length - 1; index >= 0; index -= 1) {
    const character = symbol[index];
    if (character === ")") depth += 1;
    else if (character === "(") {
      depth -= 1;
      if (depth === 0) return `${symbol.slice(0, index)}()`;
    }
  }
  return symbol;
};

/**
 * Reduce one reported frame to the identity that survives a rebuild.
 *
 * Reported addresses, module offsets, paths, and line numbers are dropped, and
 * numeric parts of symbols become `N`, so the same defect hashes the same
 * after ASLR moves it, a different build directory compiles it, or a
 * generated name gains a new suffix.
 */
export const normalizeCrashFrame = (frame: CrashFrame): string => {
  const symbol = (frame.function ?? "").trim();
  const module = frame.module === null ? "" : basename(frame.module).trim();
  const identity =
    symbol === ""
      ? module === ""
        ? CRASH_STATE_UNKNOWN_FRAME
        : module
      : symbol;
  const normalized = withoutArguments(identity)
    .replace(ADDRESS, "0xADDR")
    .replace(DECIMAL, "N")
    .replace(WHITESPACE, " ")
    .trim();
  if (normalized === "") return CRASH_STATE_UNKNOWN_FRAME;
  return normalized.length <= CRASH_STATE_MAX_FRAME_CHARS
    ? normalized
    : normalized.slice(0, CRASH_STATE_MAX_FRAME_CHARS);
};

/** Bound a caller-selected frame window; out-of-range values are rejected earlier. */
export const crashStateWindow = (maxFrames: number): number =>
  Math.min(Math.max(Math.trunc(maxFrames), 1), CRASH_STATE_MAX_FRAMES);

/**
 * Compute the crash state used to deduplicate reports.
 *
 * ClusterFuzz-style: the identity is a digest over the sanitizer class, the
 * normalized crash kind, and a bounded window of the top frames. Frames beyond
 * the window are counted, never silently dropped from the record.
 */
export const crashStateFor = (input: {
  readonly sanitizerClass: SanitizerClass;
  readonly crashKind: string;
  readonly frames: readonly CrashFrame[];
  readonly maxFrames: number;
}): CrashState => {
  const window = crashStateWindow(input.maxFrames);
  const normalized = input.frames.map(normalizeCrashFrame);
  const used = normalized.slice(0, window);
  const dedup_hash = createHash("sha256")
    .update(
      JSON.stringify([input.sanitizerClass, input.crashKind, used]),
      "utf8",
    )
    .digest("hex");
  return {
    dedup_hash,
    dedup_id: `dedup_${dedup_hash}`,
    state: used.join("\n"),
    frames: normalized,
    frames_used: used.length,
    frames_omitted: Math.max(normalized.length - used.length, 0),
  };
};

/** Frames a report carried beyond the state window, for caller-facing detail. */
export const crashStateTopFrames = (state: CrashState): readonly string[] =>
  state.frames.slice(0, state.frames_used);
