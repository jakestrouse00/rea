import { createHash } from "node:crypto";

import { err, ok, type Result } from "../../domain/result.js";

/**
 * Value-free payload accounting computed at the REA boundary from bytes a
 * caller-supplied GATT helper published: length and digest always, payload
 * hex only when the operation opted in.
 */
export interface GattPayloadAccounting {
  readonly len: number;
  readonly sha256: string;
  readonly payload_hex: string | null;
}

/** The terminal and stream event names the GATT helper line protocol uses. */
export type GattEventKind =
  | "connected"
  | "connection_failed"
  | "error"
  | "value"
  | "written"
  | "notification"
  | "window_end"
  | "disconnected"
  | "services";

/** One parsed helper line; unrecognized lines stay verbatim for the row. */
export interface ParsedGattLine {
  readonly kind: GattEventKind | "unrecognized";
  readonly id: string | null;
  readonly raw: string;
  readonly payload_hex: string | null;
  readonly ts: string | null;
  readonly message: string | null;
  readonly code: string | null;
  /** Present on window_end rows that stopped for a reason other than the deadline. */
  readonly stopReason: string | null;
}

const HEX_LINE = /^[0-9a-fA-F]*$/u;

const asStringOrNull = (value: unknown): string | null =>
  typeof value === "string" ? value : null;

const isHexPayload = (value: string): boolean =>
  value.length % 2 === 0 && HEX_LINE.test(value);

/** Parse one JSON protocol line without letting unknown fields drop. */
export const parseGattLine = (line: string): ParsedGattLine => {
  let record: unknown = null;
  try {
    record = JSON.parse(line) as unknown;
  } catch {
    return {
      kind: "unrecognized",
      id: null,
      raw: line,
      payload_hex: null,
      ts: null,
      message: null,
      code: null,
      stopReason: null,
    };
  }
  if (record === null || typeof record !== "object") {
    return {
      kind: "unrecognized",
      id: null,
      raw: line,
      payload_hex: null,
      ts: null,
      message: null,
      code: null,
      stopReason: null,
    };
  }
  const fields = record as Record<string, unknown>;
  const event = fields.event;
  const known =
    typeof event === "string" &&
    (GATT_EVENT_KINDS as ReadonlySet<string>).has(event);
  if (!known) {
    return {
      kind: "unrecognized",
      id: asStringOrNull(fields.id),
      raw: line,
      payload_hex: null,
      ts: null,
      message: null,
      code: null,
      stopReason: null,
    };
  }
  const rawPayload = fields.payload_hex;
  const payload =
    typeof rawPayload === "string" && isHexPayload(rawPayload)
      ? rawPayload.toLowerCase()
      : null;
  return {
    kind: event as GattEventKind,
    id: asStringOrNull(fields.id),
    raw: line,
    payload_hex: payload,
    ts: asStringOrNull(fields.ts),
    message: asStringOrNull(fields.message),
    code: asStringOrNull(fields.code),
    stopReason: asStringOrNull(fields.stop_reason),
  };
};

const GATT_EVENT_KINDS: ReadonlySet<string> = new Set<string>([
  "connected",
  "connection_failed",
  "error",
  "value",
  "written",
  "notification",
  "window_end",
  "disconnected",
  "services",
]);

/** Parse a bounded stdout line stream into events and unparsed rows. */
export const parseGattLines = (
  stdout: string,
): { readonly items: ParsedGattLine[]; readonly unparsedLines: string[] } => {
  const items: ParsedGattLine[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (line.trim().length === 0) continue;
    const parsed = parseGattLine(line);
    if (parsed.kind === "unrecognized") unparsedLines.push(line);
    else items.push(parsed);
  }
  return { items, unparsedLines };
};

/**
 * Digest the helper's published payload bytes at the REA boundary; the hex
 * form is dropped unless the operation opted in, so Evidence stays
 * value-free by default.
 */
export const gattPayloadAccounting = (
  payloadHex: string | null,
  includePayloadHex: boolean,
): GattPayloadAccounting | null => {
  if (payloadHex === null) return null;
  const bytes = Buffer.from(payloadHex, "hex");
  return {
    len: bytes.byteLength,
    sha256: createHash("sha256").update(payloadHex, "hex").digest("hex"),
    payload_hex: includePayloadHex ? payloadHex : null,
  };
};

/**
 * The helper's own line minus its payload bytes. Notification rows keep the
 * helper's framing so a reader can see how the peer published an event, but a
 * digest-only caller must not receive the bytes back through `raw`; payload
 * hex is retained only in the accounting field the caller opted into.
 */
export const gattLineWithoutPayload = (raw: string): string => {
  let record: unknown = null;
  try {
    record = JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
  if (record === null || typeof record !== "object" || Array.isArray(record))
    return raw;
  const fields = { ...(record as Record<string, unknown>) };
  if (!("payload_hex" in fields)) return raw;
  delete fields.payload_hex;
  return JSON.stringify(fields);
};

/**
 * Parse the services tree a helper published on its connected or services
 * event. Both events carry the same `services` array.
 */
export const parseGattServiceTree = (line: {
  readonly raw: string;
}): Result<ParsedGattService[], string> => {
  let record: unknown = null;
  try {
    record = JSON.parse(line.raw) as unknown;
  } catch {
    return err("The connected event is not readable JSON");
  }
  if (record === null || typeof record !== "object")
    return err("The connected event is not a JSON object");
  const raw = (record as Record<string, unknown>).services;
  if (raw === undefined || raw === null) return ok([]);
  if (!Array.isArray(raw)) return err("services is not an array");
  return ok((raw as unknown[]).map(parseGattServiceRow));
};

export interface ParsedGattService {
  readonly uuid: string;
  readonly characteristics: readonly {
    readonly uuid: string;
    readonly properties: readonly string[];
  }[];
}

const PROPERTY_NAMES = new Set<string>([
  "broadcast",
  "read",
  "write_without_response",
  "write",
  "notify",
  "indicate",
  "authenticated_signed_writes",
  "extended_properties",
]);

const parseGattServiceRow = (value: unknown): ParsedGattService => {
  const fields =
    value !== null && typeof value === "object"
      ? (value as Record<string, unknown>)
      : {};
  const uuid = asStringOrNull(fields.uuid) ?? "";
  const characteristics: ParsedGattService["characteristics"] = Array.isArray(
    fields.characteristics,
  )
    ? (fields.characteristics as unknown[]).map((characteristic) => {
        const row =
          characteristic !== null && typeof characteristic === "object"
            ? (characteristic as Record<string, unknown>)
            : {};
        const properties = Array.isArray(row.properties)
          ? (row.properties as unknown[]).filter(
              (property): property is string =>
                typeof property === "string" && PROPERTY_NAMES.has(property),
            )
          : [];
        return {
          uuid: asStringOrNull(row.uuid) ?? "",
          properties,
        };
      })
    : [];
  return { uuid, characteristics };
};
