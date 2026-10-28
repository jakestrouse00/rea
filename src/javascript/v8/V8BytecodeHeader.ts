import {
  V8_CACHED_DATA_HEADER_BYTES,
  V8_CACHED_DATA_MAGIC,
} from "./View8Release.js";

/** Structural observation of one V8 cached-data (bytenode-style) container. */
export interface V8BytecodeContainerObservation {
  readonly state: "recognized" | "unrecognized";
  readonly magic: "v8-cached-data" | "unknown";
  readonly magic_hex: string;
  readonly version_hash: number | null;
  readonly source_hash: number | null;
  readonly flag_hash: number | null;
  readonly snapshot_checksum: number | null;
  readonly declared_payload_bytes: number | null;
  readonly observed_payload_bytes: number;
  readonly payload_length_matches: boolean | null;
}

const word = (prefix: Buffer, index: number): number | null => {
  const offset = index * 4;
  if (prefix.length < offset + 4) return null;
  return prefix.readUInt32LE(offset);
};

/**
 * Decode the fixed cached-data header REA can check on its own: marker,
 * version/source/flag hashes, snapshot checksum and declared payload length.
 * The payload is never interpreted, and a short prefix is unrecognized.
 */
export const readV8BytecodeHeader = (
  prefix: Buffer,
  bytes: number,
): V8BytecodeContainerObservation => {
  const magicWord = word(prefix, 0);
  const magicHex = (magicWord ?? 0).toString(16).padStart(8, "0");
  const marker = magicWord === null ? null : magicWord >>> 16;
  const matches = marker === V8_CACHED_DATA_MAGIC >>> 16;
  const observedPayload = Math.max(0, bytes - V8_CACHED_DATA_HEADER_BYTES);
  if (!matches || prefix.length < V8_CACHED_DATA_HEADER_BYTES)
    return {
      state: "unrecognized",
      magic: "unknown",
      magic_hex: magicHex,
      version_hash: null,
      source_hash: null,
      flag_hash: null,
      snapshot_checksum: null,
      declared_payload_bytes: null,
      observed_payload_bytes: observedPayload,
      payload_length_matches: null,
    };
  const declared = word(prefix, 5);
  return {
    state: "recognized",
    magic: "v8-cached-data",
    magic_hex: magicHex,
    version_hash: word(prefix, 1),
    source_hash: word(prefix, 2),
    flag_hash: word(prefix, 3),
    snapshot_checksum: word(prefix, 4),
    declared_payload_bytes: declared,
    observed_payload_bytes: observedPayload,
    payload_length_matches:
      declared === null ? null : declared === observedPayload,
  };
};
