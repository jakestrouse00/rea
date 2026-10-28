import type { JsonValue } from "../domain/jsonValue.js";

/** One resolved tool path set, echoed into Results for provenance. */
export interface DiscoveryToolset {
  readonly arp: string;
  readonly ndp: string;
  readonly dnsSd: string;
  readonly systemProfiler: string;
  readonly ping: string;
  readonly ifconfig: string;
  readonly blueutil: string | null;
  readonly bleScanner: string | null;
  readonly wifiScanner: string | null;
  readonly stty: string | null;
  readonly packetCapture: string | null;
}

export interface ParsedNeighbor {
  readonly family: "ipv4" | "ipv6";
  readonly ip: string;
  readonly mac: string | null;
  readonly interface: string | null;
  readonly state: string | null;
  readonly permanent: boolean | null;
}

export interface ParsedServiceInstance {
  readonly instance: string;
  readonly interface_index: string | null;
  readonly event: string | null;
}

export interface ParsedServiceType {
  readonly service_type: string;
  readonly domain: string;
  readonly instances: ParsedServiceInstance[];
}

export interface ParsedUsbDevice {
  readonly name: string | null;
  readonly vendor_id: string | null;
  readonly product_id: string | null;
  readonly manufacturer: string | null;
  readonly serial_num: string | null;
  readonly location_id: string | null;
  readonly revision: string | null;
  readonly bcd_device: string | null;
}

export interface ParsedBluetoothDevice {
  readonly name: string | null;
  readonly address: string | null;
  readonly connected: boolean | null;
  readonly major_type: string | null;
  readonly minor_type: string | null;
  readonly firmware_version: string | null;
}

export interface ParsedInquiryDevice {
  readonly address: string | null;
  readonly name: string | null;
  readonly raw: string;
}

export interface ListResult<T> {
  readonly items: T[];
  readonly unparsedLines: string[];
}

const EMPTY_LINE = /^\s*$/u;

const isMac = (value: string): boolean =>
  /^(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}$/u.test(value) ||
  /^(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$/u.test(value);

const isIpV4 = (value: string): boolean =>
  /^(\d{1,3}\.){3}\d{1,3}$/u.test(value);

const isIpV6 = (value: string): boolean => value.includes(":");

const NULL_TOKENS = new Set(["(incomplete)", "incomplete", "?", "<none>"]);

/**
 * Parse macOS `arp -a -n` rows:
 *   `? (192.168.1.1) at a4:83:e7:12:34:56 on en0 ifscope [ethernet]`
 *   `? (10.0.0.5) at (incomplete) on en0 ifscope [ethernet]`
 * Unknown hostname prefixes are dropped; only facts the row states are kept.
 */
export const parseArpOutput = (stdout: string): ListResult<ParsedNeighbor> => {
  const items: ParsedNeighbor[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const match = /^(.*?)[ ]\(([^)]+)\) at (.+?) on ([^\s]+)(.*)$/u.exec(line);
    if (match === null) {
      unparsedLines.push(line);
      continue;
    }
    const [, _hostname, ip, at, netif, rest] = match;
    const ipValue = ip ?? "";
    const atValue = at ?? "";
    const restValue = rest ?? "";
    const macToken = atValue.split(/\s+/u)[0]?.trim() ?? "";
    const incomplete = NULL_TOKENS.has(atValue);
    const permanent = /\bpermanent\b/u.test(restValue);
    items.push({
      family: isIpV4(ipValue) ? "ipv4" : isIpV6(ipValue) ? "ipv6" : "ipv4",
      ip: ipValue,
      mac: !incomplete && isMac(macToken) ? macToken.toLowerCase() : null,
      interface: netif ?? null,
      state: restValue.trim().replace(/\s+/gu, " ") || null,
      permanent: incomplete ? null : permanent,
    });
  }
  return { items, unparsedLines };
};

/**
 * Parse macOS `ndp -a -n` rows:
 *   `fe80::1%en0      a4:83:e7:12:34:56  en0  23s  R`
 *   `ff02::2%en0      (incomplete)       en0  permanent  R`
 * Column counts vary; the parser keeps whitespace-split tokens and reports
 * unrecognized rows verbatim.
 */
export const parseNdpOutput = (stdout: string): ListResult<ParsedNeighbor> => {
  const items: ParsedNeighbor[] = [];
  const unparsedLines: string[] = [];
  const headerLike = /(Neighbor|Linklayer)\s+Address/u;
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line) || headerLike.test(line)) continue;
    const tokens = line.trim().split(/\s+/u);
    if (tokens.length < 2) {
      unparsedLines.push(line);
      continue;
    }
    const neighborToken = tokens[0] ?? "";
    const [ipPart, interfaceSuffix] = splitZone(neighborToken);
    if (!isIpV6(ipPart)) {
      unparsedLines.push(line);
      continue;
    }
    const macToken = tokens[1] ?? "";
    const hasMac = isMac(macToken);
    const restTokens = tokens
      .slice(hasMac ? 2 : 1)
      .filter((token) => !NULL_TOKENS.has(token));
    // netif is the first token that is neither an expiration nor a flag.
    const netif = restTokens[0] ?? null;
    const expire = restTokens[1] ?? null;
    const flags = restTokens.slice(2).join(" ").trim();
    const permanent =
      expire === "permanent" ||
      expire === "static" ||
      flags.includes("permanent");
    items.push({
      family: "ipv6",
      ip: ipPart,
      mac: hasMac ? macToken.toLowerCase() : null,
      interface: interfaceSuffix ?? netif,
      state: flags.length > 0 ? flags : null,
      permanent: permanent ? true : expire === null ? null : false,
    });
  }
  return { items, unparsedLines };
};

const splitZone = (token: string): [string, string | null] => {
  const index = token.indexOf("%");
  if (index === -1) return [token, null];
  return [token.slice(0, index), token.slice(index + 1) || null];
};

/** mDNS browse row: `H:MM:SS.micro  Add  2  5  local.  _ipp._tcp.local.  Printer` */
const BROWSE_ROW =
  /^\s*([\d:.]+)\s+(Add|RMV|Rm|Fnd)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)(?:\s+(.+?))?\s*$/u;

const stripDomainSuffix = (value: string, domain: string): string =>
  value.toLowerCase().endsWith(domain.toLowerCase())
    ? value.slice(0, value.length - domain.length).replace(/\.$/u, "")
    : value.replace(/\.$/u, "");

export type ParsedBrowseKind = "meta" | "instances";

export interface ParsedBrowse {
  readonly types: ParsedServiceType[];
  readonly unparsedLines: string[];
}

/**
 * Parse one dns-sd -B window. In meta browse the service type itself is the
 * queried name's record; in an instance browse the final column is the
 * service instance.
 */
export const parseBrowseOutput = (
  stdout: string,
  kind: ParsedBrowseKind,
  knownTypes: ParsedServiceType[] = [],
): ParsedBrowse => {
  const unparsedLines: string[] = [];
  const index = new Map<string, ParsedServiceType>();
  for (const type of knownTypes)
    index.set(typeKey(type.service_type, type.domain), {
      ...type,
      instances: [...type.instances],
    });
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const match = BROWSE_ROW.exec(line);
    if (match === null) {
      unparsedLines.push(line);
      continue;
    }
    const [, _time, event, _flags, ifIndex, domain, record, extra] = match;
    if (kind === "meta")
      index.set(typeKey(record ?? "", domain ?? ""), {
        service_type: record ?? "",
        domain: domain ?? "local.",
        instances: [],
      });
    else {
      const serviceType = normalizeBrowseType(record ?? "");
      const key = typeKey(serviceType, domain ?? "local.");
      const entry = index.get(key) ?? {
        service_type: serviceType,
        domain: domain ?? "local.",
        instances: [],
      };
      if (extra !== undefined && extra.length > 0)
        entry.instances.push({
          instance: extra.trim(),
          interface_index: ifIndex ?? null,
          event: event ?? null,
        });
      index.set(key, entry);
    }
  }
  return { types: [...index.values()], unparsedLines };
};

const typeKey = (serviceType: string, domain: string): string =>
  `${stripDomainSuffix(serviceType, domain).toLowerCase()}@${domain.toLowerCase()}`;

/** Canonical identity of one service type within its domain. */
export const serviceTypeKey = (serviceType: string, domain: string): string =>
  typeKey(serviceType, domain);

/** `_ipp._tcp.local.` -> `_ipp._tcp.local.`; used both for keying and args. */
const normalizeBrowseType = (serviceType: string): string => serviceType;

/** Parse one system_profiler JSON tree, flattening nested item lists. */
export const parseSystemProfilerJson = (
  stdout: string,
): {
  readonly ok: boolean;
  readonly reason: string | null;
  readonly data: JsonValue | null;
} => {
  const trimmed = stdout.trim();
  if (trimmed.length === 0)
    return { ok: false, reason: "system_profiler printed no JSON", data: null };
  try {
    const data: unknown = JSON.parse(trimmed);
    return { ok: true, reason: null, data: data as JsonValue };
  } catch (cause: unknown) {
    return {
      ok: false,
      reason: `system_profiler JSON was not parseable: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
      data: null,
    };
  }
};

/** Flatten the USB tree: every tree node (bus hub, hub or device) is one row. */
export const parseUsbTree = (data: JsonValue): ListResult<ParsedUsbDevice> => {
  const items: ParsedUsbDevice[] = [];
  const unparsedLines: string[] = [];
  const walk = (node: JsonValue): void => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (node === null || typeof node !== "object" || Array.isArray(node)) {
      unparsedLines.push(JSON.stringify(node)?.slice(0, 256) ?? "");
      return;
    }
    const record = node as Record<string, unknown>;
    const nested = record["items"];
    const name = typeof record["_name"] === "string" ? record["_name"] : null;
    // Every node of the SPUSBDataType tree is a bus hub, hub or device;
    // leaves without SP identity fields keep their name and null facts.
    items.push({
      name,
      vendor_id: asString(record["vendor_id"]),
      product_id: asString(record["product_id"]),
      manufacturer: asString(record["manufacturer"]),
      serial_num: asString(record["serial_num"]),
      location_id: asString(record["location_id"]),
      revision: asString(record["revision"]),
      bcd_device: asString(record["bcd_device"]),
    });
    if (nested !== undefined) walk(nested as JsonValue);
  };
  const payload = Array.isArray(data)
    ? data
    : (data as Record<string, unknown>)["SPUSBDataType"];
  walk((payload ?? []) as JsonValue);
  return { items, unparsedLines };
};

/** Flatten the Bluetooth JSON tree into paired/connected device rows. */
export const parseBluetoothTree = (
  data: JsonValue,
): ListResult<ParsedBluetoothDevice> => {
  const items: ParsedBluetoothDevice[] = [];
  const unparsedLines: string[] = [];
  // The macOS producer nests device dicts under container keys like
  // `device_connected` / `device_not_connected`, keyed by the device's
  // display name — not by `_name`.
  const walk = (node: JsonValue, connectedHint: boolean | null): void => {
    if (Array.isArray(node)) {
      node.forEach((entry) => walk(entry, connectedHint));
      return;
    }
    if (node === null || typeof node !== "object" || Array.isArray(node)) {
      unparsedLines.push(String(node));
      return;
    }
    const record = node as Record<string, JsonValue>;
    if (isBluetoothDeviceRecord(record)) {
      items.push({
        name: bluetoothName(record, ""),
        address: findBluetoothValue(record, /^device_address$/iu),
        connected: connectedHint ?? asConnected(record),
        major_type: findBluetoothValue(record, /^(device_)?majortype$/iu),
        minor_type: findBluetoothValue(record, /^(device_)?minortype$/iu),
        firmware_version: findBluetoothValue(record, /firmware/iu),
      });
      return;
    }
    let matchedValue = false;
    for (const [key, value] of Object.entries(record)) {
      if (value === null || typeof value !== "object") continue;
      if (Array.isArray(value)) {
        walk(value, nextConnectedHint(key, connectedHint));
        continue;
      }
      const child = value as Record<string, JsonValue>;
      if (!isBluetoothDeviceRecord(child)) {
        walk(value, nextConnectedHint(key, connectedHint));
        continue;
      }
      matchedValue = true;
      items.push({
        name: bluetoothName(child, key),
        address: findBluetoothValue(child, /^device_address$/iu),
        connected: nextConnectedHint(key, connectedHint) ?? asConnected(child),
        major_type: findBluetoothValue(child, /^(device_)?majortype$/iu),
        minor_type: findBluetoothValue(child, /^(device_)?minortype$/iu),
        firmware_version: findBluetoothValue(child, /firmware/iu),
      });
    }
    if (!matchedValue && Object.keys(record).length === 0)
      unparsedLines.push("{}");
  };
  const payload = Array.isArray(data)
    ? data
    : (data as Record<string, unknown>)["SPBluetoothDataType"];
  walk((payload ?? []) as JsonValue, null);
  return { items, unparsedLines };
};

const DEVICE_ATTRIBUTE =
  /^(device_(address|connectedStatus|majorType|minorType|firmware|rssi|battery|product|services|alias)|majorType|minorType)$/iu;

const isBluetoothDeviceRecord = (record: Record<string, JsonValue>): boolean =>
  Object.keys(record).some((key) => DEVICE_ATTRIBUTE.test(key));

const nextConnectedHint = (
  key: string,
  current: boolean | null,
): boolean | null => {
  if (/^device_(not_connected|notconnected)$/iu.test(key)) return false;
  if (/^device_connected(Status)?$/iu.test(key)) return true;
  return current;
};

const bluetoothName = (
  record: Record<string, JsonValue>,
  mapKey: string,
): string | null =>
  asString(record["_name"]) ?? (mapKey.length > 0 ? mapKey : null);

const findBluetoothValue = (
  record: Record<string, JsonValue>,
  pattern: RegExp,
): string | null => {
  const key = Object.keys(record).find((candidate) => pattern.test(candidate));
  return key === undefined ? null : asString(record[key]);
};

/** Direct device-record connected attribute when a producer supplies one. */
const asConnected = (record: Record<string, JsonValue>): boolean | null => {
  const key = Object.keys(record).find((candidate) =>
    /connected/iu.test(candidate),
  );
  if (key === undefined) return null;
  const value = record[key];
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (/yes\b/iu.test(value)) return true;
    if (/no\b/iu.test(value)) return false;
  }
  return null;
};

const asString = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

/**
 * Parse one blueutil --inquiry window. Rows are key/value runs whose exact
 * spelling varies across blueutil releases; raw rows are preserved.
 */
export const parseBlueutilInquiry = (
  stdout: string,
): ListResult<ParsedInquiryDevice> => {
  const items: ParsedInquiryDevice[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const address = /address:\s*([0-9A-Fa-f-]{14,17})/u.exec(line)?.[1] ?? null;
    const name = extractInquiryName(line);
    if (address === null && name === null) {
      unparsedLines.push(line);
      continue;
    }
    items.push({
      address: address === null ? null : address.toLowerCase(),
      name,
      raw: line.trim(),
    });
  }
  return { items, unparsedLines };
};

const extractInquiryName = (line: string): string | null => {
  const quoted =
    /name:\s*'([^']*)'/u.exec(line)?.[1] ??
    /name:\s*"([^"]*)"/u.exec(line)?.[1];
  if (quoted !== undefined) return quoted.length > 0 ? quoted : null;
  const unquoted =
    /name:\s*([^\n]*?)(?:\s+(?:not\s+)?(?:connected|paired)\b|\s+rssi\b|\s+[a-z][a-zA-Z-]*\s*:|\s*$)/iu.exec(
      line,
    )?.[1];
  const trimmed = unquoted?.trim() ?? "";
  return trimmed.length > 0 ? trimmed : null;
};

/** Extract one reply's latency from a ping transcript; null means none. */
export const parsePingLatencyMs = (stdout: string): number | null => {
  const match = /time[=<]\s*([0-9.]+)\s*ms/u.exec(stdout);
  if (match === null) return null;
  const value = Number.parseFloat(match[1] ?? "");
  return Number.isFinite(value) ? value : null;
};

/** IPv4 candidates of a /22.._/32 CIDR, excluding network and broadcast. */
export const cidrCandidates = (
  cidr: string,
): {
  readonly ok: boolean;
  readonly reason: string | null;
  readonly hosts: readonly string[];
} => {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/u.exec(
    cidr,
  );
  if (match === null)
    return { ok: false, reason: "The CIDR is not an IPv4 prefix", hosts: [] };
  const octets = match
    .slice(1, 5)
    .map((part) => Number.parseInt(part ?? "", 10));
  const prefix = Number.parseInt(match[5] ?? "", 10);
  if (
    octets.some((octet) => !Number.isInteger(octet) || octet > 255) ||
    prefix < 22 ||
    prefix > 32
  )
    return { ok: false, reason: "The CIDR is not an IPv4 prefix", hosts: [] };
  const [a, b, c, d] = octets as [number, number, number, number];
  const address = ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (address & mask) >>> 0;
  if (address !== network)
    return {
      ok: false,
      reason: "The address part must be the network address",
      hosts: [],
    };
  const size = 2 ** (32 - prefix);
  const hosts: string[] = [];
  for (let index = 1; index < size - 1; index += 1)
    hosts.push(formatAddress((network + index) >>> 0));
  return { ok: true, reason: null, hosts };
};

const formatAddress = (value: number): string =>
  `${(value >>> 24) & 0xff}.${(value >>> 16) & 0xff}.${(value >>> 8) & 0xff}.${value & 0xff}`;
