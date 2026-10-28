import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  REPLAY_CONTENT_TYPE_CLASSES,
  REPLAY_STATUS_CLASSES,
} from "../replay/replayLimits.js";
import {
  MITM_ADDON_ID,
  MITM_LIMITS,
  MITM_PARAMETER_LOCATIONS,
  MITM_PARAMETER_TYPES,
  MITM_PROTOCOL_VERSION,
  MITM_RULE_PHASES,
} from "./mitmLimits.js";

/**
 * The structure stream is the addon's only channel: one JSON object per line on
 * its stdout. It carries structure, types, and digests — never a header value,
 * a query value, or a body. Bodies reach REA only as owner-only files the
 * addon already wrote, named by `body_hold`.
 */

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);

/** One body the addon retained in the session's private capture directory. */
export const mitmBodyHoldSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Owner-only file holding the exact producer bytes; the body itself is never in this stream.",
  ),
  bytes: z.int().min(0).max(MITM_LIMITS.maxHeldBodyBytes),
  sha256: sha256Schema,
});
export type MitmBodyHold = z.infer<typeof mitmBodyHoldSchema>;

/** Bounded response-shape sketch: names and types, never values. */
export type MitmShapeSketch =
  | {
      readonly kind: "object";
      readonly keys: readonly {
        readonly name: string;
        readonly type: string;
      }[];
      readonly truncated: boolean;
    }
  | {
      readonly kind: "array";
      readonly items: number | null;
      readonly item: MitmShapeSketch | null;
      readonly truncated: boolean;
    }
  | { readonly kind: "scalar"; readonly type: string }
  | {
      readonly kind: "truncated";
      readonly deeper: true;
    };

const shapeScalarSchema = z.strictObject({
  kind: z.literal("scalar"),
  type: z.string().min(1).max(32),
});

/** Where the addon stopped descending: names nothing beyond this bound. */
const shapeTruncationSchema = z.strictObject({
  kind: z.literal("truncated"),
  deeper: z.literal(true),
});

const shapeObjectSchema = z.strictObject({
  kind: z.literal("object"),
  keys: z
    .array(
      z.strictObject({
        name: z.string().min(1).max(256),
        type: z.string().min(1).max(32),
      }),
    )
    .max(MITM_LIMITS.maxShapeKeys),
  truncated: z.boolean(),
});

const shapeArraySchema = (item: z.ZodType<MitmShapeSketch>) =>
  z.strictObject({
    kind: z.literal("array"),
    items: z.int().min(0).nullable(),
    item: item.nullable(),
    truncated: z.boolean(),
  });

const shapeSketchLevel = (item: z.ZodType<MitmShapeSketch>) =>
  z.discriminatedUnion("kind", [
    shapeScalarSchema,
    shapeTruncationSchema,
    shapeObjectSchema,
    shapeArraySchema(item),
  ]);

/**
 * One level per retained nesting depth, ending at the truncation marker.
 *
 * The stream model is self-similar, so a lazy schema would export a
 * self-referential JSON Schema that strict clients refuse and whose size no
 * bound controls. Building each level once keeps the advertised schema acyclic
 * and bounded by `MITM_LIMITS.maxShapeDepth`.
 */
const shapeSketchAtDepth = (): z.ZodType<MitmShapeSketch> => {
  let level: z.ZodType<MitmShapeSketch> = shapeSketchLevel(
    shapeTruncationSchema,
  );
  for (let depth = 1; depth < MITM_LIMITS.maxShapeDepth; depth += 1)
    level = shapeSketchLevel(level);
  return level;
};

export const mitmShapeSketchSchema = shapeSketchAtDepth();

/** One parameter name observed in a request, classified but never valued. */
export const mitmParameterFactSchema = z.strictObject({
  name: z.string().min(1).max(256),
  location: z.enum(MITM_PARAMETER_LOCATIONS),
  type: z.enum(MITM_PARAMETER_TYPES),
});
export type MitmParameterFact = z.infer<typeof mitmParameterFactSchema>;

const headerNameListSchema = z.array(z.string().min(1).max(256)).max(64);

const mitmRequestStructureSchema = z.strictObject({
  method: z.string().min(1).max(32),
  origin: z.string().min(1).max(255),
  path_template: z.string().min(1).max(8_192),
  header_names: headerNameListSchema,
  parameters: z
    .array(mitmParameterFactSchema)
    .max(MITM_LIMITS.maxParametersPerEndpoint),
  content_type_class: z.enum(REPLAY_CONTENT_TYPE_CLASSES),
  body_bytes: z.int().min(0),
  body_hold: mitmBodyHoldSchema.nullable(),
});

const mitmResponseStructureSchema = z.strictObject({
  status: z.int().min(100).max(999),
  header_names: headerNameListSchema,
  content_type_class: z.enum(REPLAY_CONTENT_TYPE_CLASSES),
  body_bytes: z.int().min(0),
  body_hold: mitmBodyHoldSchema.nullable(),
  shape: mitmShapeSketchSchema.nullable(),
});

/** One completed exchange as the addon observed it. */
export const mitmFlowEventSchema = z.strictObject({
  type: z.literal("flow"),
  sequence: z.int().min(1),
  at: z.string().min(1),
  duration_ms: z.int().min(0),
  request: mitmRequestStructureSchema,
  response: mitmResponseStructureSchema.nullable(),
  entry: z
    .strictObject({
      path: absoluteLocalPathStringSchema,
      bytes: z.int().min(0).max(MITM_LIMITS.maxEntryRecordBytes),
      sha256: sha256Schema,
    })
    .nullable()
    .describe(
      "Owner-only replayable request record the addon wrote for proxy_replay_send.",
    ),
});
export type MitmFlowEvent = z.infer<typeof mitmFlowEventSchema>;

/** One rewrite rule application, counted without header, query, or body values. */
export const mitmRuleMatchEventSchema = z.strictObject({
  type: z.literal("rule_match"),
  rule_id: z.string().uuid(),
  phase: z.enum(MITM_RULE_PHASES),
  method: z.string().min(1).max(32),
  origin: z.string().min(1).max(255),
  path_template: z.string().min(1).max(8_192),
  status_before: z.int().min(100).max(999).nullable(),
  status_after: z.int().min(100).max(999).nullable(),
  headers_changed: z.int().min(0),
  query_changed: z.int().min(0),
  body_replaced: z.boolean(),
});
export type MitmRuleMatchEvent = z.infer<typeof mitmRuleMatchEventSchema>;

/** The addon's startup advertisement; REA refuses a mismatched protocol. */
export const mitmReadyEventSchema = z.strictObject({
  type: z.literal("ready"),
  protocol: z.int().min(1),
  addon: z.strictObject({
    id: z.literal(MITM_ADDON_ID),
    version: z.int().min(1),
  }),
  mitmproxy: z.strictObject({
    version: z.string().min(1).max(64),
  }),
  listen: z.strictObject({
    host: z.literal("127.0.0.1"),
    port: z.int().min(1).max(65_535),
  }),
});
export type MitmReadyEvent = z.infer<typeof mitmReadyEventSchema>;

/** A control-file or capture condition the addon reports once per revision. */
export const mitmNoticeEventSchema = z.strictObject({
  type: z.literal("notice"),
  reason: z.enum([
    "control-unreadable",
    "control-stale",
    "entry-unwritable",
    "body-unwritable",
    "shape-limit",
  ]),
  message: z.string().min(1).max(512),
});
export type MitmNoticeEvent = z.infer<typeof mitmNoticeEventSchema>;

/** A flow the addon could not complete; REA keeps the reason, not a body. */
export const mitmErrorEventSchema = z.strictObject({
  type: z.literal("error"),
  reason: z.string().min(1).max(64),
  message: z.string().min(1).max(512),
});
export type MitmErrorEvent = z.infer<typeof mitmErrorEventSchema>;

const knownEventTypes = new Set([
  "flow",
  "rule_match",
  "ready",
  "notice",
  "error",
]);

/** Parse one decoded stream line; unknown shapes stay distinguishable. */
export type MitmStreamEventParse =
  | { readonly kind: "event"; readonly event: MitmStreamEvent }
  | { readonly kind: "unknown-type" }
  | { readonly kind: "invalid" };

export type MitmStreamEvent =
  | MitmFlowEvent
  | MitmRuleMatchEvent
  | MitmNoticeEvent
  | MitmErrorEvent;

/** Parse one structure-stream line without ever throwing on producer content. */
export const parseMitmStreamEvent = (line: string): MitmStreamEventParse => {
  let decoded: unknown;
  try {
    decoded = JSON.parse(line);
  } catch {
    return { kind: "invalid" };
  }
  if (
    typeof decoded !== "object" ||
    decoded === null ||
    Array.isArray(decoded) ||
    typeof (decoded as { type?: unknown }).type !== "string"
  )
    return { kind: "invalid" };
  const type = (decoded as { type: string }).type;
  if (type === "ready") return { kind: "unknown-type" };
  if (!knownEventTypes.has(type)) return { kind: "unknown-type" };
  const schema =
    type === "flow"
      ? mitmFlowEventSchema
      : type === "rule_match"
        ? mitmRuleMatchEventSchema
        : type === "notice"
          ? mitmNoticeEventSchema
          : mitmErrorEventSchema;
  const parsed = schema.safeParse(decoded);
  return parsed.success
    ? { kind: "event", event: parsed.data as MitmStreamEvent }
    : { kind: "invalid" };
};

/** The protocol version this build parses. */
export const MITM_STREAM_PROTOCOL = MITM_PROTOCOL_VERSION;

/** Every event type the generated addon emits. */
export const MITM_STREAM_EVENT_TYPES = [
  "ready",
  "flow",
  "rule_match",
  "notice",
  "error",
] as const;

/** Status classification mirrors the replay lane's closed vocabulary. */
export const MITM_STATUS_CLASSES = REPLAY_STATUS_CLASSES;
