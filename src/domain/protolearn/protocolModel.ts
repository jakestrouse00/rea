import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";
import {
  PROTOCOL_SKETCH_KINDS,
  PROTOLEARN_DIRECTIONS,
  protocolMessageSketchSchema,
  protocolSegmentTokenSchema,
} from "./protocolMessage.js";
import {
  PROTOLEARN_LIMITS,
  PROTOLEARN_QLOG_PROFILE,
} from "./protolearnLimits.js";

export const protocolClassIdSchema = z.string().regex(/^c[0-9]{1,3}$/u);
export const protocolStateIdSchema = z.string().regex(/^s[0-9]{1,4}$/u);

/** One field position inside a message class, as a type vocabulary only. */
const protocolFieldPosition = z.strictObject({
  position: z.int().nonnegative().max(PROTOLEARN_LIMITS.maxFieldPositions),
  /** Sorted distinct segment types observed at this position. */
  types: z.array(protocolSegmentTokenSchema).min(1),
  observed: z.int().positive(),
});

/** One exemplar template written to the caller-declared store, by name only. */
const protocolClassTemplate = z.strictObject({
  file: z.string().regex(/^[a-z0-9._\x2d]{1,64}$/u),
  bytes: z.int().positive().max(PROTOLEARN_LIMITS.maxTemplateBytes),
  sha256: digestSchema,
});

/** One observed message class of the learned alphabet. */
export const protocolMessageClassSchema = z.strictObject({
  class_id: protocolClassIdSchema,
  direction: z.enum(PROTOLEARN_DIRECTIONS),
  sketch: protocolMessageSketchSchema,
  message_count: z.int().positive(),
  byte_length: z.strictObject({
    min: z.int().nonnegative(),
    max: z.int().nonnegative(),
    total: z.int().nonnegative(),
  }),
  segment_count: z.strictObject({
    min: z.int().nonnegative(),
    max: z.int().nonnegative(),
  }),
  positions: z
    .array(protocolFieldPosition)
    .max(PROTOLEARN_LIMITS.maxFieldPositions),
  /**
   * Digest of the first observed payload of this class, or null when the
   * evidence source reports no payload bytes for it (qlog). Null is unknown,
   * never an empty message: two classes with null exemplars make no claim that
   * their payloads are equal.
   */
  exemplar_sha256: digestSchema.nullable(),
  template: protocolClassTemplate.nullable(),
});

export type ProtocolMessageClass = z.output<
  typeof protocolMessageClassSchema
>;

/** One state of the learned machine: a suffix of message classes. */
export const protocolStateSchema = z.strictObject({
  state_id: protocolStateIdSchema,
  /** The retained last-message classes that identify this state. */
  context: z
    .array(protocolClassIdSchema)
    .max(PROTOLEARN_LIMITS.maxSuffixLength),
  message_count: z.int().nonnegative(),
  session_ends: z.int().nonnegative(),
  accepting: z.boolean(),
});

export type ProtocolState = z.output<typeof protocolStateSchema>;

/** One observed transition: from a state, one message class, to a state. */
export const protocolTransitionSchema = z.strictObject({
  from: protocolStateIdSchema,
  to: protocolStateIdSchema,
  class_id: protocolClassIdSchema,
  count: z.int().positive(),
  sessions: z.int().positive(),
});

export type ProtocolTransition = z.output<typeof protocolTransitionSchema>;

/** Where the learned messages came from, with the identity REA verified. */
export const protocolModelSourceSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("pcap"),
    path: localPathStringSchema,
    sha256: digestSchema,
    format: z.enum(["pcap", "pcapng", "other"]),
    packets: z.int().nonnegative().nullable(),
  }),
  z.strictObject({
    kind: z.literal("qlog"),
    path: localPathStringSchema,
    sha256: digestSchema,
    profile: z.literal(PROTOLEARN_QLOG_PROFILE),
    traces: z.int().nonnegative(),
  }),
]);

/** The caller-owned directory holding this model and its class exemplars. */
export const protocolModelStoreSchema = z.strictObject({
  directory: localPathStringSchema,
  /** Model file name inside the store; probe and export read this file. */
  model_file: z.string().regex(/^[a-z0-9._\x2d]{1,64}$/u),
  /** Exemplar files written beside the model, one per class that had one. */
  template_count: z.int().nonnegative(),
});

/**
 * The learned finite-state model. States are bounded suffixes of the message
 * class sequence, transitions are observed next messages, and every class
 * carries a field-type sketch instead of a payload. Coverage and omissions are
 * explicit, so a bounded model never reads as a complete protocol description.
 */
export const protocolModelSchema = z.strictObject({
  source: protocolModelSourceSchema,
  sessions: z.strictObject({
    total: z.int().nonnegative(),
    retained: z.int().nonnegative(),
    omitted: z.int().nonnegative(),
  }),
  messages: z.strictObject({
    total: z.int().nonnegative(),
    retained: z.int().nonnegative(),
    omitted: z.int().nonnegative(),
    request: z.int().nonnegative(),
    response: z.int().nonnegative(),
    unattributed: z.int().nonnegative(),
  }),
  alphabet: z.strictObject({
    class_count: z.int().nonnegative(),
    omitted: z.int().nonnegative(),
    sketch_kinds: z.array(z.enum(PROTOCOL_SKETCH_KINDS)),
  }),
  classes: z
    .array(protocolMessageClassSchema)
    .max(PROTOLEARN_LIMITS.maxClasses),
  states: z.array(protocolStateSchema).max(PROTOLEARN_LIMITS.maxStates),
  transitions: z.array(protocolTransitionSchema),
  merge: z.strictObject({
    requested_suffix_length: z
      .int()
      .min(0)
      .max(PROTOLEARN_LIMITS.maxSuffixLength),
    retained_suffix_length: z
      .int()
      .min(0)
      .max(PROTOLEARN_LIMITS.maxSuffixLength),
    max_states: z.int().min(1).max(PROTOLEARN_LIMITS.maxStates),
    /** True when the requested suffix length had to shrink to fit the cap. */
    suffix_reduced: z.boolean(),
  }),
  coverage: z.enum(["complete", "partial"]),
  model_store: protocolModelStoreSchema.nullable(),
  limitations: z.array(z.string().min(1)),
});

export type ProtocolModel = z.output<typeof protocolModelSchema>;
