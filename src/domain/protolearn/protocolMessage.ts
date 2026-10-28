import { createHash } from "node:crypto";
import { z } from "zod";

import { PROTOLEARN_LIMITS } from "./protolearnLimits.js";

/** Which side of the conversation a message travelled from. */
export const PROTOLEARN_DIRECTIONS = [
  "request",
  "response",
  "unattributed",
] as const;
export type ProtocolDirection = (typeof PROTOLEARN_DIRECTIONS)[number];

export const PROTOCOL_SKETCH_KINDS = [
  "empty",
  "text",
  "binary",
  "quic-packet",
] as const;
export type ProtocolSketchKind = (typeof PROTOCOL_SKETCH_KINDS)[number];

export const PROTOCOL_PRINTABLE_RATIOS = [
  "high",
  "mixed",
  "low",
  "unknown",
] as const;
export type ProtocolPrintableRatio = (typeof PROTOCOL_PRINTABLE_RATIOS)[number];

/** A derived field-type token; never text read out of a payload. */
export const protocolSegmentTokenSchema = z
  .string()
  .regex(/^[a-z][a-z0-9_]{0,31}$/u);

/**
 * Value-free shape of one message: its byte length class, whether it reads as
 * text, and the types of the fields a delimiter split exposes. No payload
 * byte, token, or field value is retained.
 */
export const protocolMessageSketchSchema = z.strictObject({
  kind: z.enum(PROTOCOL_SKETCH_KINDS),
  printable_ratio: z.enum(PROTOCOL_PRINTABLE_RATIOS),
  line_terminated: z.boolean(),
  /** Delimiter-separated segments observed; may exceed the retained types. */
  segments: z.int().nonnegative(),
  segment_types: z
    .array(protocolSegmentTokenSchema)
    .max(PROTOLEARN_LIMITS.maxSegmentTypes),
  /** Leading payload bytes the sketch examined; the digest covers all bytes. */
  examined_bytes: z.int().nonnegative(),
});

export type ProtocolMessageSketch = z.output<
  typeof protocolMessageSketchSchema
>;

/**
 * One observed message in a conversation. The payload bytes exist only while
 * learning runs: they feed the sketch, the digest, and at most one class
 * template, then leave memory.
 */
export interface ProtocolMessageFact {
  readonly session: string;
  readonly ordinal: number;
  readonly direction: ProtocolDirection;
  readonly byte_length: number;
  readonly payload_sha256: string | null;
  readonly sketch: ProtocolMessageSketch;
  /** Examined payload bytes; never serialized into Evidence. */
  readonly payload: Buffer | null;
}

const TEXT_DELIMITERS = /[ \t\r\n,;:|]+/u;
const DIGITS = /^[0-9]{1,20}$/u;
const HEX = /^[0-9a-fA-F]{2,64}$/u;
const ALPHA = /^[A-Za-z]{1,64}$/u;
const PUNCT = /^[!-/:-@[-`{-~]{1,64}$/u;

const segmentType = (segment: string): string => {
  if (DIGITS.test(segment)) return "numeric";
  if (segment.length >= 2 && HEX.test(segment) && /[a-fA-F]/u.test(segment))
    return "hex";
  if (ALPHA.test(segment)) return "alpha";
  if (PUNCT.test(segment)) return "punct";
  return "mixed";
};

const printableRatio = (
  examined: Buffer,
): ProtocolPrintableRatio => {
  if (examined.length === 0) return "unknown";
  let printable = 0;
  for (const byte of examined)
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d)
      printable += 1;
  if (printable * 10 >= examined.length * 9) return "high";
  if (printable * 2 >= examined.length) return "mixed";
  return "low";
};

/**
 * Derive one message's sketch from its examined bytes. Text is the only kind
 * whose delimiter split is meaningful, so an empty or binary message keeps a
 * zero segment count instead of inventing field boundaries.
 */
export const payloadSketch = (
  payload: Buffer | null,
): ProtocolMessageSketch => {
  if (payload === null || payload.length === 0)
    return {
      kind: "empty",
      printable_ratio: "unknown",
      line_terminated: false,
      segments: 0,
      segment_types: [],
      examined_bytes: 0,
    };
  const examined = payload.subarray(0, PROTOLEARN_LIMITS.maxPayloadBytes);
  const ratio = printableRatio(examined);
  const lineTerminated = examined.at(-1) === 0x0a;
  if (ratio === "low")
    return {
      kind: "binary",
      printable_ratio: ratio,
      line_terminated: lineTerminated,
      segments: 0,
      segment_types: [],
      examined_bytes: examined.length,
    };
  const segments = examined
    .toString("latin1")
    .split(TEXT_DELIMITERS)
    .filter((segment) => segment !== "");
  return {
    kind: "text",
    printable_ratio: ratio,
    line_terminated: lineTerminated,
    segments: segments.length,
    segment_types: segments
      .slice(0, PROTOLEARN_LIMITS.maxSegmentTypes)
      .map(segmentType),
    examined_bytes: examined.length,
  };
};

/**
 * Stable alphabet key for one message class. The key names the direction and
 * the bounded sketch; two messages agree as a class when their keys match, so
 * a class never depends on a payload value.
 */
export const messageClassKey = (
  direction: ProtocolDirection,
  sketch: ProtocolMessageSketch,
): string =>
  [
    direction,
    sketch.kind,
    sketch.printable_ratio,
    sketch.line_terminated ? "terminated" : "open",
    String(sketch.segments),
    sketch.segment_types.slice(0, PROTOLEARN_LIMITS.maxClassSegments).join("."),
  ].join("|");

/** Digest of one complete message payload. */
export const payloadDigest = (payload: Buffer): string =>
  createHash("sha256").update(payload).digest("hex");
