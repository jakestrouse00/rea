import type { ListResult } from "../DiscoveryDeviceOutput.js";

/**
 * One advertisement event exactly as the helper reported it, unknowns null.
 */
export interface ParsedBleAdvertisement {
  readonly event: "discovered" | "updated";
  readonly ts: string | null;
  readonly address_or_uuid: string | null;
  readonly name: string | null;
  readonly rssi: number | null;
  readonly connectable: boolean | null;
  readonly manufacturer_hex: string | null;
  readonly service_uuids: string[];
  readonly raw: string;
}

const EMPTY_LINE = /^\s*$/u;

const asStringOrNull = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

const asRssiOrNull = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const asConnectableOrNull = (value: unknown): boolean | null =>
  typeof value === "boolean" ? value : null;

const asServiceUuids = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter(
        (entry): entry is string =>
          typeof entry === "string" && entry.length > 0,
      )
    : [];

/** Parse one JSON advertisement row; null means the row is unrecognized. */
const parseAdvertisementLine = (
  line: string,
): ParsedBleAdvertisement | null => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line) as unknown;
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
    return null;
  const record = parsed as Record<string, unknown>;
  if (record.event !== "discovered" && record.event !== "updated") return null;
  return {
    event: record.event,
    ts: asStringOrNull(record.ts),
    address_or_uuid: asStringOrNull(record.address_or_uuid),
    name: asStringOrNull(record.name),
    rssi: asRssiOrNull(record.rssi),
    connectable: asConnectableOrNull(record.connectable),
    manufacturer_hex: asStringOrNull(record.manufacturer_hex),
    service_uuids: asServiceUuids(record.service_uuids),
    raw: line,
  };
};

/**
 * Parse one helper scan window: one JSON object per line, one line per
 * advertisement event. Blank lines vanish; any non-JSON non-empty line —
 * including foreign tool stdout piped in — is preserved verbatim.
 */
export const parseBleScanLines = (
  stdout: string,
): ListResult<ParsedBleAdvertisement> => {
  const items: ParsedBleAdvertisement[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const parsed = parseAdvertisementLine(line);
    if (parsed === null) {
      unparsedLines.push(line);
      continue;
    }
    items.push(parsed);
  }
  return { items, unparsedLines };
};
