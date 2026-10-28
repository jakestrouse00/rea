import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { ListResult } from "../DiscoveryDeviceOutput.js";
import {
  runDiscoveryObservation,
  type DiscoveryProcessLauncher,
} from "../DiscoveryCommand.js";
import type { Result } from "../../domain/result.js";
import type {
  MdnsAddressRow,
  MdnsLookupRecord,
  MdnsResolveInput,
  MdnsResolveResult,
  MdnsTxtEntry,
  MdnsZoneRecord,
} from "./MdnsResolveAnalysis.js";

/** One window deadline grace beyond resolve_seconds, mirroring BROWSE_GRACE_MS. */
const RESOLVE_GRACE_MS = 250;
const EMPTY_LINE = /^\s*$/u;

const LOOKUP_ROW =
  /^\s*([\d:.]+)\s+(.+?)\s+can be reached at ([^\s:]+):(\d+)(\s.*)?$/u;
const INTERFACE_PAREN = /\(interface\s+([^)]+)\)/u;
const TXT_ROW_HINT = /=(?:[^"]*)"?$/u;

const ZONE_SRV_ROW =
  /^\s*(\S+)\s+SRV\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*(?:;\s*(.*))?$/u;
const ZONE_TXT_ROW = /^\s*(\S+)\s+TXT\s+(.*)$/u;
const ZONE_PTR_ROW = /^\s*(\S+)\s+PTR\s+(\S+)\s*$/u;
const ZONE_META_ROW = /^\s*lb\._dns-sd\._udp\s+PTR\s+@/u;

const ADDRESS_ROW =
  /^\s*([\d:.]+)\s+(Add|Rm|RMV)\s+([0-9A-Fa-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$/u;

const TXT_TOKEN = /^[^\s"]+$/u;

/**
 * Parse one dns-sd -L window. Each recognized row binds the SRV target and
 * port plus the interface index; macOS 27 moves the record's TXT payload to
 * a continuation line that begins with whitespace, which binds to the most
 * recent row. Framing rows stay in unparsedLines verbatim.
 */
export const parseResolveLine = (
  stdout: string,
): ListResult<MdnsLookupRecord> => {
  const items: MdnsLookupRecord[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const match = LOOKUP_ROW.exec(line);
    if (match !== null) {
      const [, _stamp, serviceName, target, port] = match;
      const parsedPort = Number.parseInt(port ?? "", 10);
      items.push({
        service_name: serviceName ?? "",
        target: target ?? null,
        port: Number.isInteger(parsedPort) ? parsedPort : null,
        interface_index: INTERFACE_PAREN.exec(line)?.[1]?.trim() ?? null,
        txt: [],
        txt_raw: null,
        raw: line,
      });
      continue;
    }
    const latest = items.at(-1);
    if (
      latest !== undefined &&
      /^\s+\S/u.test(line) &&
      TXT_ROW_HINT.test(line)
    ) {
      const trimmed = line.trim();
      items[items.length - 1] = {
        ...latest,
        txt: [...latest.txt, ...parseTxtTokens(trimmed)],
        txt_raw:
          latest.txt_raw === null ? trimmed : `${latest.txt_raw} ${trimmed}`,
      };
      continue;
    }
    unparsedLines.push(line);
  }
  return { items, unparsedLines };
};

/**
 * Zone TXT payloads print quoted strings on macOS 27, but other releases
 * print the record as `len hex`; the length token is framing, kept only
 * when its byte count matches the hex actually printed. Anything else is
 * left to the generic token reader so unknown spelling is not reinterpreted.
 */
const zoneTxtEntries = (payload: string): MdnsTxtEntry[] => {
  const binary = /^(\d+)\s+((?:[0-9a-fA-F]{2})+)\s*$/u.exec(payload);
  if (
    binary !== null &&
    Number.parseInt(binary[1] ?? "", 10) === (binary[2]?.length ?? 0) / 2
  )
    return [{ key: null, value: binary[2] ?? "" }];
  return parseTxtTokens(payload);
};

/** TXT payload tokens, in quoted zone spelling or an unquoted -L run. */
export const parseTxtTokens = (payload: string): MdnsTxtEntry[] => {
  const entries: MdnsTxtEntry[] = [];
  for (const match of payload.matchAll(/"([^"]*)"/gu)) {
    const content = match[1] ?? "";
    const index = content.indexOf("=");
    if (index <= -1) entries.push({ key: null, value: content });
    else
      entries.push({
        key: content.slice(0, index) || null,
        value: content.slice(index + 1),
      });
  }
  if (entries.length > 0) return entries;
  const tokens =
    payload.trim().length === 0 ? [] : payload.trim().split(/\s+/u);
  if (tokens.length === 0 || tokens.some((token) => !TXT_TOKEN.test(token)))
    return [];
  for (const token of tokens) {
    const index = token.indexOf("=");
    if (index <= -1) entries.push({ key: null, value: token });
    else
      entries.push({
        key: token.slice(0, index) || null,
        value: token.slice(index + 1),
      });
  }
  return entries;
};

/**
 * Parse one dns-sd -Z window: PTR/SRV/TXT rows in zone-file spelling.
 * `;` commentary, framing rows, and `lb._dns-sd._udp` meta rows are
 * preserved verbatim in unparsedLines.
 */
export const parseZoneOutput = (stdout: string): ListResult<MdnsZoneRecord> => {
  const items: MdnsZoneRecord[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const srv = ZONE_SRV_ROW.exec(line);
    if (srv !== null) {
      const [, name, _priority, _weight, port, target] = srv;
      const parsedPort = Number.parseInt(port ?? "", 10);
      items.push({
        kind: "srv",
        name: name ?? "",
        target: target ?? null,
        port: Number.isInteger(parsedPort) ? parsedPort : null,
        ttl: null,
        txt: [],
        raw: line,
      });
      continue;
    }
    const txt = ZONE_TXT_ROW.exec(line);
    if (txt !== null) {
      const [, name, payload] = txt;
      const printed = payload ?? "";
      items.push({
        kind: "txt",
        name: name ?? "",
        target: null,
        port: null,
        ttl: null,
        txt: zoneTxtEntries(printed),
        raw: line,
      });
      continue;
    }
    const ptr = ZONE_PTR_ROW.exec(line);
    if (ptr !== null) {
      const [, name, target] = ptr;
      items.push({
        kind: "ptr",
        name: name ?? "",
        target: target ?? null,
        port: null,
        ttl: null,
        txt: [],
        raw: line,
      });
      continue;
    }
    unparsedLines.push(line);
  }
  return { items, unparsedLines };
};

/**
 * Parse one dns-sd -G window. IPv6 prints fully zero-padded with a `%zone`
 * suffix (`%lo0`, `%en0`) or `%<0>` for no zone; the printed spelling is
 * kept verbatim. Framing and the column header stay in unparsedLines.
 */
export const parseGetAddress = (stdout: string): ListResult<MdnsAddressRow> => {
  const items: MdnsAddressRow[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const match = ADDRESS_ROW.exec(line);
    if (match === null) {
      unparsedLines.push(line);
      continue;
    }
    const [, _stamp, _event, _flags, ifIndex, hostname, address] = match;
    const printed = address ?? "";
    items.push({
      family: /^.*:.*$/.test(printed) ? "ipv6" : "ipv4",
      address: printed,
      interface_index: ifIndex ?? null,
      hostname: hostname ?? null,
      raw: line,
    });
  }
  return { items, unparsedLines };
};

/**
 * The -Z owner name is the instance label followed by the type (macOS 27
 * drops the domain and any trailing dot). The label may appear space-escaped
 * (zone-file `\032`) when the instance name contains spaces; both spellings
 * match. Anything else, including other instances of the same type, is not
 * this instance.
 */
const recordOnInstance = (
  name: string,
  instance: string,
  serviceType: string,
  domain: string,
): boolean => {
  const lower = name.toLowerCase();
  const bare = serviceType.replace(/\.$/u, "").toLowerCase();
  const suffixes = [
    `.${bare}`,
    `.${bare}.`,
    `.${serviceType}${domain}`.toLowerCase(),
    `.${serviceType}${domain}`.toLowerCase().replace(/\.$/u, ""),
  ];
  const labels = [
    instance.toLowerCase(),
    instance.replace(/ /gu, "\\032").toLowerCase(),
  ];
  return suffixes.some((suffix) =>
    labels.some((label) => label.length > 0 && lower === `${label}${suffix}`),
  );
};

const appendUniqueEntry = (
  target: MdnsTxtEntry[],
  entries: readonly MdnsTxtEntry[],
): void => {
  for (const entry of entries) {
    const duplicate = target.some(
      (row) => row.key === entry.key && row.value === entry.value,
    );
    if (!duplicate) target.push(entry);
  }
};

/**
 * Resolve one mDNS service instance with three dns-sd windows: -L lookup,
 * then -Z zone output when SRV or TXT stayed unknown, then -G v4v6 on the
 * resolved SRV target. A window deadline kill is observed silence, not a
 * failure; only a tool that cannot run at all is an error.
 */
export const executeMdnsResolve = async (
  dnsSdPath: string,
  input: MdnsResolveInput,
  signal?: AbortSignal,
  launcher?: DiscoveryProcessLauncher,
): Promise<Result<MdnsResolveResult, AnalysisError>> => {
  const started = Date.now();
  const timeoutMs = input.resolve_seconds * 1000 + RESOLVE_GRACE_MS;
  const observe = (args: readonly string[]) =>
    runDiscoveryObservation(
      "resolve_mdns_records",
      dnsSdPath,
      args,
      { timeoutMs },
      signal,
      launcher,
    );

  const lookupRun = await observe([
    "-L",
    input.instance,
    input.service_type.replace(/\.$/u, ""),
    input.domain,
  ]);
  if (!lookupRun.ok) return lookupRun;
  const lookup = parseResolveLine(lookupRun.value.stdout);
  const unparsedLines = [...lookup.unparsedLines];
  const srvRow =
    lookup.items.find((row) => row.target !== null && row.port !== null) ??
    lookup.items[0];
  const selected: MdnsLookupRecord | null = srvRow ?? null;
  let target = selected?.target ?? null;
  let port = selected?.port ?? null;
  let txt: MdnsTxtEntry[] = selected?.txt ?? [];
  let rawTxt = selected?.txt_raw ?? null;
  let interfaceIndex = selected?.interface_index ?? null;

  const zoneRan = target === null || port === null || txt.length === 0;
  if (zoneRan) {
    const zoneRun = await observe([
      "-Z",
      input.service_type.replace(/\.$/u, ""),
      input.domain,
    ]);
    if (!zoneRun.ok) return zoneRun;
    const zone = parseZoneOutput(zoneRun.value.stdout);
    unparsedLines.push(...zone.unparsedLines);
    const matched = zone.items.filter(
      (record) =>
        (record.kind === "srv" || record.kind === "txt") &&
        recordOnInstance(
          record.name,
          input.instance,
          input.service_type,
          input.domain,
        ),
    );
    if (target === null || port === null) {
      const zoneSrv = matched.find((record) => record.kind === "srv");
      target = zoneSrv?.target ?? target;
      port = zoneSrv?.port ?? port;
    }
    if (txt.length === 0)
      for (const record of matched.filter((row) => row.kind === "txt"))
        appendUniqueEntry(txt, record.txt);
    if (rawTxt === null)
      rawTxt =
        matched
          .filter((row) => row.kind === "txt")
          .map((row) => row.raw.split(/\s*TXT\s*/u).at(-1) ?? "")
          .join(" ") || null;
  }

  const addresses: MdnsAddressRow[] = [];
  const addressesRan = input.include_addresses && target !== null;
  if (addressesRan) {
    const addressRun = await observe(["-G", "v4v6", target!]);
    if (!addressRun.ok) return addressRun;
    const parsed = parseGetAddress(addressRun.value.stdout);
    unparsedLines.push(...parsed.unparsedLines);
    addresses.push(...parsed.items);
  }

  return {
    ok: true,
    value: {
      instance: input.instance,
      service_type: input.service_type,
      domain: input.domain,
      interface_index: interfaceIndex,
      srv: { target, port },
      txt,
      raw_txt: rawTxt,
      addresses,
      lookup_rows: lookup.items,
      zone_ran: zoneRan,
      addresses_ran: addressesRan,
      lookup_timed_out: lookupRun.value.timed_out,
      elapsed_ms: Date.now() - started,
      unparsed_lines: unparsedLines,
      coverage:
        unparsedLines.length > 0 ? ("partial" as const) : ("complete" as const),
    },
  };
};
