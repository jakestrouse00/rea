import { V8_CACHED_DATA_MAGIC } from "./View8Release.js";

/** Largest header this lane inspects; every pinned layout fits inside it. */
export const MAX_V8_HEADER_BYTES = 32;

/**
 * Pinned cached-data header layouts. Each entry names the words REA will
 * interpret, so an artifact that matches none of them is reported without
 * interpreted words instead of being forced into the wrong map.
 *
 * The 32-byte layout is verified against artifacts produced by the Node 24
 * (V8 13.6) and Node 26 (V8 14.6) lines REA supports: the marker carries the
 * external-reference count in its low bits, word 2 tracks the source length,
 * words 3 and 4 are constant per build (word 3 changes with `--jitless` or
 * `--no-opt`), and word 5 equals the payload size. The 24-byte layout is a
 * documented assumption for the bytenode-era V8 10 lines, whose header keeps a
 * source hash instead of a source length and a payload checksum instead of a
 * read-only snapshot checksum.
 */
export const V8_CACHED_DATA_LAYOUTS = [
  {
    id: "v8-code-cache-32-byte-header",
    headerBytes: 32,
    versionHashWord: 1,
    sourceLengthWord: 2,
    flagHashWord: 3,
    snapshotChecksumWord: 4,
    payloadLengthWord: 5,
  },
  {
    id: "v8-code-cache-24-byte-header",
    headerBytes: 24,
    versionHashWord: 1,
    sourceHashWord: 2,
    flagHashWord: 3,
    payloadChecksumWord: 5,
    payloadLengthWord: 4,
  },
] as const;

export type V8CachedDataLayoutId =
  (typeof V8_CACHED_DATA_LAYOUTS)[number]["id"];

type Layout = (typeof V8_CACHED_DATA_LAYOUTS)[number];

/** Structural observation of one V8 cached-data (bytenode-style) container. */
export interface V8BytecodeContainerObservation {
  /**
   * `recognized` means one pinned layout declares exactly the observed payload
   * size. `layout_unverifiable` means the marker is present but no pinned
   * layout agrees with the file, so no word is interpreted.
   */
  readonly state: "recognized" | "layout_unverifiable" | "unrecognized";
  readonly layout: V8CachedDataLayoutId | null;
  readonly magic: "v8-cached-data" | "unknown";
  readonly magic_hex: string;
  readonly header_bytes: number | null;
  readonly prefix_words: number[];
  readonly version_hash: number | null;
  readonly flag_hash: number | null;
  readonly source_length: number | null;
  readonly source_hash: number | null;
  readonly snapshot_checksum: number | null;
  readonly payload_checksum: number | null;
  readonly declared_payload_bytes: number | null;
  readonly observed_payload_bytes: number | null;
}

const wordAt = (words: readonly number[], index: number): number | null =>
  words[index] ?? null;

const hex = (value: number | undefined): string =>
  (value ?? 0).toString(16).padStart(8, "0");

/**
 * Layouts whose declared payload length equals the bytes after their header.
 * The first eight words are reported as `prefix_words` because a 24-byte
 * header ends before them; naming them header words would misdescribe bytes.
 */
const consistentLayouts = (
  words: readonly number[],
  bytes: number,
): readonly Layout[] =>
  V8_CACHED_DATA_LAYOUTS.filter((layout) => {
    const declared = wordAt(words, layout.payloadLengthWord);
    return (
      declared !== null &&
      bytes > layout.headerBytes &&
      declared === bytes - layout.headerBytes
    );
  });

/**
 * Decode the fixed cached-data header REA can check on its own. The payload is
 * never interpreted, and an artifact whose header disagrees with every pinned
 * layout keeps its words uninterpreted.
 */
export const readV8BytecodeHeader = (
  prefix: Buffer,
  bytes: number,
): V8BytecodeContainerObservation => {
  const available = Math.min(prefix.length, MAX_V8_HEADER_BYTES);
  const words = Array.from({ length: available >>> 2 }, (_, index) =>
    prefix.readUInt32LE(index * 4),
  );
  const magicWord = words[0];
  const marked =
    magicWord !== undefined && magicWord >>> 16 === V8_CACHED_DATA_MAGIC >>> 16;
  const base = { magic_hex: hex(magicWord), prefix_words: words };
  if (!marked)
    return {
      ...base,
      state: "unrecognized",
      layout: null,
      magic: "unknown",
      header_bytes: null,
      version_hash: null,
      flag_hash: null,
      source_length: null,
      source_hash: null,
      snapshot_checksum: null,
      payload_checksum: null,
      declared_payload_bytes: null,
      observed_payload_bytes: null,
    };
  const consistent = consistentLayouts(words, bytes);
  const layout = consistent.length === 1 ? consistent[0] : undefined;
  if (layout === undefined)
    return {
      ...base,
      state: "layout_unverifiable",
      layout: null,
      magic: "v8-cached-data",
      header_bytes: null,
      version_hash: null,
      flag_hash: null,
      source_length: null,
      source_hash: null,
      snapshot_checksum: null,
      payload_checksum: null,
      declared_payload_bytes: null,
      observed_payload_bytes: null,
    };
  const observedPayload = bytes - layout.headerBytes;
  return {
    ...base,
    state: "recognized",
    layout: layout.id,
    magic: "v8-cached-data",
    header_bytes: layout.headerBytes,
    version_hash: wordAt(words, layout.versionHashWord),
    flag_hash: wordAt(words, layout.flagHashWord),
    source_length:
      "sourceLengthWord" in layout
        ? wordAt(words, layout.sourceLengthWord)
        : null,
    source_hash:
      "sourceHashWord" in layout ? wordAt(words, layout.sourceHashWord) : null,
    snapshot_checksum:
      "snapshotChecksumWord" in layout
        ? wordAt(words, layout.snapshotChecksumWord)
        : null,
    payload_checksum:
      "payloadChecksumWord" in layout
        ? wordAt(words, layout.payloadChecksumWord)
        : null,
    declared_payload_bytes: wordAt(words, layout.payloadLengthWord),
    observed_payload_bytes: observedPayload,
  };
};
