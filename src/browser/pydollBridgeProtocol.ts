import { z } from "zod";

export const PYDOLL_BRIDGE_PROTOCOL_VERSION = 1;

/** One JSON message; oversized messages are protocol failures, not truncations. */
export const MAX_BRIDGE_MESSAGE_BYTES = 1024 * 1024;

const bridgeAdvertisingSchema = z.strictObject({
  protocol: z.literal(PYDOLL_BRIDGE_PROTOCOL_VERSION),
  pydoll_version: z.string().min(1),
  capabilities: z.strictObject({
    emulation: z.boolean(),
    keyboard: z.boolean(),
    select_option: z.boolean(),
    downloads: z.boolean(),
    popups: z.boolean(),
    workers: z.boolean(),
  }),
});
export type PydollBridgeAdvertising = z.infer<typeof bridgeAdvertisingSchema>;

export const pydollOpenSessionResultSchema = z.strictObject({
  product: z.string().min(1),
  version: z.string().min(1),
  target_id: z.string().min(1),
  initial_url: z.string().nullable(),
  owned_browser_pid: z.number().int().positive().nullable(),
  applied_environment: z.array(z.string().min(1)),
  skipped_environment: z.array(z.string().min(1)),
  event_domains_enabled: z.array(z.string().min(1)),
});
export type PydollOpenSessionResult = z.infer<
  typeof pydollOpenSessionResultSchema
>;

export const pydollPerformResultSchema = z.strictObject({
  final_url: z.string().nullable(),
  notes: z.array(z.string().min(1)).default([]),
});
export type PydollPerformResult = z.infer<typeof pydollPerformResultSchema>;

export const pydollSeedStorageResultSchema = z.strictObject({
  applied: z.array(z.string().min(1)),
  notes: z.array(z.string().min(1)).default([]),
});

export const pydollCloseSessionResultSchema = z.strictObject({
  outcome: z.enum(["terminated-owned-process", "disconnected-external"]),
  profile_removed: z.boolean(),
  notes: z.array(z.string().min(1)).default([]),
});
export type PydollCloseSessionResult = z.infer<
  typeof pydollCloseSessionResultSchema
>;

const bridgeRawCookieSchema = z.strictObject({
  name: z.string(),
  value: z.string(),
  domain: z.string(),
  path: z.string(),
  secure: z.boolean(),
  http_only: z.boolean(),
  same_site: z.string(),
  same_site_raw: z.string().nullable(),
});

const bridgeStorageEntrySchema = z.strictObject({
  name: z.string(),
  value: z.string(),
});

const bridgeInlineStorageSchema = z.strictObject({
  kind: z.literal("storage"),
  cookies: z.array(bridgeRawCookieSchema),
  local_storage: z.array(
    z.strictObject({
      origin: z.string().min(1),
      entries: z.array(bridgeStorageEntrySchema),
    }),
  ),
  session_storage: z.array(
    z.strictObject({
      origin: z.string().min(1),
      entries: z.array(bridgeStorageEntrySchema),
    }),
  ),
});

const bridgeHistoryEntrySchema = z.strictObject({
  type: z.string().min(1),
  url: z.string().min(1),
});

const bridgeInlineHistorySchema = z.strictObject({
  kind: z.literal("history"),
  length: z.number().int().min(0).nullable(),
  raw_entries: z.array(bridgeHistoryEntrySchema),
});

const bridgeUrlArtifactSchema = z.strictObject({
  kind: z.literal("url"),
  raw_url: z.string().nullable(),
});

const bridgeFileArtifactSchema = z.strictObject({
  kind: z.enum(["screenshot", "dom", "accessibility", "history", "storage"]),
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.number().int().min(0),
  truncated: z.boolean().optional(),
  width: z.number().int().positive().nullable().optional(),
  height: z.number().int().positive().nullable().optional(),
  representation: z.string().min(1).optional(),
});

const bridgeCaptureArtifactSchema = z.union([
  bridgeUrlArtifactSchema,
  bridgeInlineStorageSchema,
  bridgeInlineHistorySchema,
  bridgeFileArtifactSchema,
]);

export const bridgeCaptureResultSchema = z.strictObject({
  artifacts: z.array(bridgeCaptureArtifactSchema),
  notes: z.array(z.string().min(1)).default([]),
});
export type PydollCaptureResult = z.infer<typeof bridgeCaptureResultSchema>;
export type PydollCaptureArtifact = z.infer<typeof bridgeCaptureArtifactSchema>;

/** Marker data for the bridge's bounded event queue reporting dropped queued events. */
export const bridgeQueueOverflowDataSchema = z.strictObject({
  kind: z.literal("event_queue_overflow"),
  count: z.number().int().min(1),
});
export type PydollQueueOverflowData = z.infer<
  typeof bridgeQueueOverflowDataSchema
>;

const bridgeEventSchema = z.strictObject({
  event: z.literal("scenario"),
  params: z.unknown(),
});
export type PydollBridgeEvent = z.infer<typeof bridgeEventSchema>;

export type PydollBridgeReply =
  | { readonly id: number; readonly ok: true; readonly result: unknown }
  | {
      readonly id: number;
      readonly ok: false;
      readonly error: { readonly reason: string; readonly message: string };
    };

const bridgeAdvertisingEnvelopeSchema = z.strictObject({
  advertising: bridgeAdvertisingSchema,
});
export type PydollBridgeAdvertisingEnvelope = z.infer<
  typeof bridgeAdvertisingEnvelopeSchema
>;

/** Parse one advertised-capabilities startup line. */
export const parseBridgeAdvertising = (
  line: string,
):
  | {
      readonly ok: true;
      readonly advertising: PydollBridgeAdvertising;
    }
  | { readonly ok: false } => {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return { ok: false };
  }
  const parsed = bridgeAdvertisingEnvelopeSchema.safeParse(value);
  if (!parsed.success) return { ok: false };
  return { ok: true, advertising: parsed.data.advertising };
};

/** Parse one unsolicited scenario event line; undefined for reply lines. */
export const parseBridgeEvent = (line: string) => {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new Error("Bridge emitted an unparseable protocol line");
  }
  const parsed = bridgeEventSchema.safeParse(value);
  if (!parsed.success) return undefined;
  const params = parsed.data.params;
  if (params === null || typeof params !== "object" || Array.isArray(params))
    return undefined;
  return {
    event: parsed.data.event,
    params: params as { readonly family?: unknown; readonly data?: unknown },
  };
};
