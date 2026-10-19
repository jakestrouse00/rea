import type { JsonValue } from "../domain/jsonValue.js";

/**
 * Format-aware parsers at the owning boundary for pymobiledevice3 output.
 * Each parser reports unparsed lines instead of guessing; unknown device
 * fields stay unknown through `fields`/entries rather than being treated as
 * absent.
 */

/** Parse `pymobiledevice3 usbmux list` output as printed by the launcher. */
export const parseIdeviceDevicesOutput = (
  stdout: string,
): {
  devices: {
    udid: string;
    name: string | null;
    connection: "usb" | "network" | "unknown";
    pairing: "paired" | "unpaired" | "unknown";
    fields: { key: string; value: string | null }[];
  }[];
  unparsedLines: string[];
} => {
  const document = parseJsonPossiblyWrapped(stdout);
  if (document === undefined)
    return { devices: [], unparsedLines: stdout.split("\n").slice(0, 10) };
  const rows = Array.isArray(document)
    ? document
    : typeof document === "object" && document !== null
      ? rowsFromUsumuxObject(document as Record<string, JsonValue>)
      : [];
  const unparsedLines: string[] = [];
  const devices = rows.flatMap((row) => {
    if (typeof row !== "object" || row === null) {
      unparsedLines.push(JSON.stringify(row)?.slice(0, 256) ?? "");
      return [];
    }
    const record = row as Record<string, JsonValue>;
    const udid =
      stringField(record, ["DeviceID"]) ??
      stringField(record, ["udid"]) ??
      stringField(record, ["UniqueDeviceID"]);
    if (udid === null) {
      unparsedLines.push(JSON.stringify(record).slice(0, 256));
      return [];
    }
    return [
      {
        udid,
        name: stringField(record, ["DeviceName"]),
        connection: connectionFromRecord(record),
        pairing: pairingFromRecord(record),
        fields: fieldsFromRecord(record),
      },
    ];
  });
  return { devices, unparsedLines };
};

const rowsFromUsumuxObject = (
  document: Record<string, JsonValue>,
): JsonValue[] =>
  Array.isArray(document["deviceList"])
    ? document["deviceList"]
    : typeof document["message"] === "object" &&
        document["message"] !== null &&
        Array.isArray(
          (document["message"] as Record<string, JsonValue>)["deviceList"],
        )
      ? ((document["message"] as Record<string, JsonValue>)[
          "deviceList"
        ] as JsonValue[])
      : [document];

const stringField = (
  record: Record<string, JsonValue>,
  keys: readonly string[],
): string | null => {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.length > 0) return value;
  }
  return null;
};

const connectionFromRecord = (
  record: Record<string, JsonValue>,
): "usb" | "network" | "unknown" =>
  record["ConnectionType"] === "USB"
    ? "usb"
    : record["ConnectionType"] === "Network"
      ? "network"
      : record["connection_type"] === "network"
        ? "network"
        : "unknown";

const pairingFromRecord = (
  record: Record<string, JsonValue>,
): "paired" | "unpaired" | "unknown" => {
  const flag = record["paired"] ?? record["is_paired"];
  if (flag === true) return "paired";
  if (flag === false) return "unpaired";
  return "unknown";
};

const fieldsFromRecord = (
  record: Record<string, JsonValue>,
): { key: string; value: string | null }[] =>
  Object.entries(record)
    .filter(
      ([key]) =>
        key !== "DeviceID" && key !== "udid" && key !== "UniqueDeviceID",
    )
    .map(([key, value]) => ({
      key,
      value:
        value === undefined || value === null || typeof value === "object"
          ? null
          : String(value),
    }));

/** Parse `pymobiledevice3 lockdown info` output into preserved fields. */
export const parseLockdownDeviceInfo = (
  stdout: string,
): {
  deviceName: string | null;
  productType: string | null;
  iosVersion: string | null;
  connectionType: "usb" | "network" | "unknown";
  fields: { key: string; value: string | null }[];
  unparsedLines: string[];
} => {
  const document = parseJsonPossiblyWrapped(stdout);
  if (
    document === undefined ||
    typeof document !== "object" ||
    document === null
  )
    return {
      deviceName: null,
      productType: null,
      iosVersion: null,
      connectionType: "unknown",
      fields: [],
      unparsedLines: stdout.split("\n").slice(0, 10),
    };
  const record = document as Record<string, JsonValue>;
  return {
    deviceName: stringField(record, ["DeviceName", "device_name"]),
    productType: stringField(record, ["ProductType", "product_type"]),
    iosVersion:
      stringField(record, ["ProductVersion", "os_version", "iOSVersion"]) ??
      null,
    connectionType: connectionFromRecord(record),
    fields: fieldsFromRecord(record),
    unparsedLines: [],
  };
};

/**
 * Parse `pymobiledevice3 apps list` output as printed by the launcher:
 * a bare JSON array or the wrapped `{"apps": [...]}` document. Any other
 * parsed document is reported as an unparsed line so consumers cannot
 * mistake an unrecognized inventory shape for an empty one.
 */
export const parseIdeviceAppsOutput = (
  stdout: string,
): {
  apps: {
    bundle_id: string;
    name: string | null;
    version: string | null;
    signer_restricted: boolean | null;
    /** The launcher's per-row fields, owned here; provisioning reads these. */
    fields: { key: string; value: string | null }[];
  }[];
  unparsedLines: string[];
} => {
  const document = parseJsonPossiblyWrapped(stdout);
  if (document === undefined)
    return { apps: [], unparsedLines: stdout.split("\n").slice(0, 10) };
  const { rows, unparsedDocument } = appsRowsFromDocument(document);
  const unparsedLines: string[] = [];
  if (unparsedDocument !== undefined)
    unparsedLines.push(JSON.stringify(unparsedDocument)?.slice(0, 256) ?? "");
  const apps = rows.flatMap((row) => {
    if (typeof row !== "object" || row === null) {
      unparsedLines.push(JSON.stringify(row)?.slice(0, 256) ?? "");
      return [];
    }
    const record = row as Record<string, JsonValue>;
    const bundleId =
      stringField(record, [
        "CFBundleIdentifier",
        "bundle_id",
        "bundle_identifier",
      ]) ?? null;
    if (bundleId === null) {
      unparsedLines.push(JSON.stringify(record).slice(0, 256));
      return [];
    }
    return [
      {
        bundle_id: bundleId,
        name: stringField(record, [
          "CFBundleDisplayName",
          "CFBundleName",
          "name",
        ]),
        version: stringField(record, ["CFBundleShortVersionString", "version"]),
        signer_restricted:
          typeof record["signer_is_restricted"] === "boolean"
            ? record["signer_is_restricted"]
            : null,
        fields: appsFieldsFromRecord(record),
      },
    ];
  });
  return { apps, unparsedLines };
};

/** One inventory-shape decision: bare arrays and the wrapped apps document. */
const appsRowsFromDocument = (
  document: JsonValue,
): { rows: JsonValue[]; unparsedDocument: JsonValue | undefined } => {
  if (Array.isArray(document))
    return { rows: document, unparsedDocument: undefined };
  if (
    typeof document === "object" &&
    document !== null &&
    Array.isArray((document as Record<string, JsonValue>)["apps"])
  )
    return {
      rows: (document as Record<string, JsonValue>)["apps"] as JsonValue[],
      unparsedDocument: undefined,
    };
  return { rows: [], unparsedDocument: document };
};

const appsFieldsFromRecord = (
  record: Record<string, JsonValue>,
): { key: string; value: string | null }[] =>
  Object.entries(record)
    .filter(
      ([key]) =>
        key !== "CFBundleIdentifier" &&
        key !== "bundle_id" &&
        key !== "bundle_identifier",
    )
    .map(([key, value]) => ({
      key,
      value:
        value === undefined || value === null || typeof value === "object"
          ? null
          : String(value),
    }));

/** Parse `pymobiledevice3 crash list` line output. */
export const parseIdeviceCrashListOutput = (
  stdout: string,
): {
  reports: { name: string; date: string | null; bytes: number | null }[];
  unparsedLines: string[];
} => {
  const reports: { name: string; date: string | null; bytes: number | null }[] =
    [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    // Crash list rows are whitespace-separated `name ... date ... [bytes]`.
    const match =
      /^(\S+)(?:\s{2,}.*?\s(20\d{2}-\d{2}-\d{2}[T ]\S+))?(?:\s+(\d+))?\s*$/u.exec(
        trimmed,
      );
    if (match === null) {
      unparsedLines.push(trimmed);
      continue;
    }
    reports.push({
      name: match[1]!,
      date: match[2] ?? null,
      bytes: match[3] === undefined ? null : Number(match[3]),
    });
  }
  return { reports, unparsedLines };
};

/**
 * pmd3 versions print either a bare JSON document or a banner followed by
 * JSON. Recognize the first JSON value rather than inventing a banner rule.
 */
const parseJsonPossiblyWrapped = (stdout: string): JsonValue | undefined => {
  const trimmed = stdout.trim();
  if (trimmed === "") return undefined;
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.parse(trimmed) as JsonValue;
    } catch {
      return undefined;
    }
  }
  const start = findJsonStart(trimmed);
  if (start === -1) return undefined;
  try {
    return JSON.parse(trimmed.slice(start)) as JsonValue;
  } catch {
    return undefined;
  }
};

const findJsonStart = (text: string): number => {
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === "{" || text[index] === "[") return index;
    // Skip banner or log-prefix lines before the JSON document.
    if (text.startsWith("\n", index)) continue;
  }
  return -1;
};
