import { readdirSync } from "node:fs";

import type { ListResult } from "../DiscoveryDeviceOutput.js";
import type { SerialPortRow } from "./SerialAnalysis.js";

const DEV_SERIAL_ENTRY = /^(cu|tty)\.([^/]+)$/u;

/**
 * One port row from the SPPortsDataType JSON tree: every string the producer
 * stated, null where it states nothing. Joining happens downstream by name.
 */
export interface SystemProfilerPort {
  readonly name: string | null;
  readonly interface_type: string | null;
  readonly description: string | null;
}

/** One /dev serial device node the host filesystem exposes. */
export interface DevSerialEntry {
  readonly path: string;
  readonly name: string;
  readonly kind: "cu" | "tty";
}

const asString = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

/**
 * Walk the SPPortsDataType tree: every node is one row. The producer
 * serialises serial nodes with `_name` and sometimes related string fields;
 * whatever shape appears is kept verbatim, unnamed nodes still emit a row
 * with null facts, and only strings the tree states are carried.
 */
export const parseSystemProfilerPorts = (
  data: unknown,
): ListResult<SystemProfilerPort> => {
  const items: SystemProfilerPort[] = [];
  const unparsedLines: string[] = [];
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (node === null || typeof node !== "object") {
      const rendered =
        typeof node === "string"
          ? node
          : (JSON.stringify(node)?.slice(0, 256) ?? "");
      if (rendered.length > 0) unparsedLines.push(rendered);
      return;
    }
    const record = node as Record<string, unknown>;
    const nested = record["items"];
    items.push({
      name: asString(record["_name"]),
      interface_type:
        asString(record["interface_type"]) ?? asString(record["type"]),
      description:
        asString(record["description"]) ??
        asString(record["product"]) ??
        asString(record["_productName"]),
    });
    if (nested !== undefined && nested !== null) walk(nested);
  };
  const payload = Array.isArray(data)
    ? data
    : data !== null && typeof data === "object"
      ? ((data as Record<string, unknown>)["SPPortsDataType"] ?? [])
      : [data];
  walk(payload);
  return { items, unparsedLines };
};

/**
 * Filter one readdir listing to serial device node entries. /dev carries
 * hundreds of unrelated nodes (ptys like `ttys000`, pipes, sockets); only
 * `cu.*` and `tty.*` names are serial device nodes here, so other entries are
 * scope-filtered rather than treated as unparsed rows.
 */
export const parseDevEntries = (
  entries: readonly string[],
  directory: string = "/dev",
): DevSerialEntry[] =>
  [...entries]
    .filter((entry) => DEV_SERIAL_ENTRY.test(entry))
    .sort((left, right) => left.localeCompare(right))
    .map((entry) => {
      const match = DEV_SERIAL_ENTRY.exec(entry)!;
      return {
        path: `${directory.replace(/\/$/u, "")}/${entry}`,
        name: entry,
        kind: (match[1] ?? "cu") as "cu" | "tty",
      };
    });

/** Read one directory's serial device nodes; unreadable means none. */
export const parseDevList = (directory: string): DevSerialEntry[] => {
  try {
    return parseDevEntries(readdirSync(directory), directory);
  } catch {
    return [];
  }
};

/**
 * Join system_profiler port rows with the /dev listing, name-based only: a
 * port row whose name equals the `cu.X` / `tty.X` entry's basename
 * (case-insensitively, both sides of the pair join once) contributes its
 * fields to that device's row. An unmatched device keeps its own row with
 * null facts; a port row no device node matches surfaces in
 * `unmatchedPortNames` verbatim. A join is never invented, and `in_use` stays
 * null because no producer reports it.
 */
export const joinSerialPorts = (
  ports: readonly SystemProfilerPort[],
  devices: readonly DevSerialEntry[],
): { ports: SerialPortRow[]; unmatchedPortNames: string[] } => {
  const byName = new Map<string, SystemProfilerPort>();
  for (const port of ports) {
    if (port.name === null) continue;
    const key = port.name.toLowerCase();
    if (!byName.has(key)) byName.set(key, port);
  }
  const deviceNames = new Set(
    devices.map((device) =>
      device.name.slice(device.kind.length + 1).toLowerCase(),
    ),
  );
  const rows: SerialPortRow[] = devices.map((device) => {
    const basename = device.name.slice(device.kind.length + 1);
    const joined = byName.get(basename.toLowerCase()) ?? null;
    return {
      device_path: device.path,
      name: joined?.name ?? null,
      interface_type: joined?.interface_type ?? null,
      description: joined?.description ?? null,
      in_use: null,
    };
  });
  const unmatchedPortNames = ports.flatMap((port) =>
    port.name !== null && !deviceNames.has(port.name.toLowerCase())
      ? [port.name]
      : [],
  );
  return { ports: rows, unmatchedPortNames };
};

/** Preview byte budget per observation. */
export const SERIAL_PREVIEW_BYTE_LIMIT = 256;

/**
 * Render observed bytes as lowercase hex pairs separated by spaces — a
 * rendering of the bytes, not the bytes themselves; null when empty.
 */
export const renderHexPreview = (
  bytes: Buffer,
  limit: number = SERIAL_PREVIEW_BYTE_LIMIT,
): string | null => {
  if (bytes.byteLength === 0) return null;
  const bounded = bytes.subarray(0, limit);
  let out = "";
  for (const byte of bounded) {
    out += out.length === 0 ? "" : " ";
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
};

/**
 * Render observed bytes as printable text: ASCII 0x20..0x7E plus tab, LF and
 * CR pass through verbatim; every other byte is omitted from this rendering,
 * which the hex preview carries exactly.
 */
export const renderPrintablePreview = (
  bytes: Buffer,
  limit: number = SERIAL_PREVIEW_BYTE_LIMIT,
): string | null => {
  if (bytes.byteLength === 0) return null;
  const bounded = bytes.subarray(0, limit);
  let out = "";
  for (const byte of bounded)
    if (
      (byte >= 0x20 && byte <= 0x7e) ||
      byte === 0x09 ||
      byte === 0x0a ||
      byte === 0x0d
    )
      out += String.fromCharCode(byte);
  return out.length === 0 ? null : out;
};

/**
 * Render the bytes that fell outside the preview budget as text lines, so an
 * overflow window stays retrievable from the result; empty means everything
 * fit inside the budget.
 */
export const renderOverflowLines = (
  bytes: Buffer,
  limit: number = SERIAL_PREVIEW_BYTE_LIMIT,
): string[] => {
  if (bytes.byteLength <= limit) return [];
  const overflow = bytes.subarray(limit);
  const rendered = renderPrintablePreview(overflow, overflow.byteLength) ?? "";
  return rendered.split(/\r?\n/u).filter((line) => line.length > 0);
};
