import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { ListResult } from "../DiscoveryDeviceOutput.js";
import {
  runDiscoveryCommand,
  type DiscoveryProcessLauncher,
} from "../DiscoveryCommand.js";
import { type Result, ok } from "../../domain/result.js";
import type {
  IfconfigIndexRow,
  IfconfigInterfaceRow,
  IfconfigPeerRow,
  NetworkInterfacesInput,
  NetworkInterfacesResult,
} from "./NetworkInterfacesAnalysis.js";

const EMPTY_LINE = /^\s*$/u;
const MAC_LIKE = /^(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}$/u;

const IFCONFIG_HEADER = /^([a-z][a-z0-9._-]*): flags=(\d+)<([^>]*)>(.*)$/u;
const IFCONFIG_INDEX = /\bindex\s+(\d+)\s*$/u;
const INET_ROW = /^\s*inet\s+(\d{1,3}(?:\.\d{1,3}){3})\b/u;
const INET6_ROW = /^\s*inet6\s+([^\s]+)\b/u;
const ETHER_ROW = /^\s*ether\s+(\S+)/u;
const STATUS_ROW = /^\s*status:\s*(\S+)\s*$/u;
const AWDL_ROLE_ROW = /^\s*awdl[-_]?role\s*[:=]\s*(.+\S)\s*$/u;
const AWDL_INTERFACES = new Set(["awdl0", "llw0"]);

/** Canonical MAC compare; the kernel trims leading zeros in ND rows. */
const canonicalMac = (mac: string): string =>
  mac
    .split(/[:-]/u)
    .map((group) => group.padStart(2, "0"))
    .join(":");

/**
 * Parse `ifconfig -a -v`. Each header line opens a block; `ether`, `inet`,
 * `inet6`, `status:` and `awdl-role` facts attach to the open block. Lines
 * the parser has no spelling for (`media:`, `agent domain:...`, and other
 * attribute rows) are preserved verbatim in unparsedLines rather than
 * dropped or guessed at.
 */
export const parseIfconfigOutput = (
  stdout: string,
): ListResult<IfconfigInterfaceRow> => {
  const items: IfconfigInterfaceRow[] = [];
  const unparsedLines: string[] = [];
  let current: {
    name: string;
    flags: string | null;
    status: string | null;
    mac: string | null;
    ipv4: string[];
    ipv6: string[];
    awdl_role: string | null;
  } | null = null;
  const push = (): void => {
    if (current === null) return;
    items.push({
      ...current,
      ipv4: [...current.ipv4],
      ipv6: [...current.ipv6],
    });
    current = null;
  };
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const header = IFCONFIG_HEADER.exec(line);
    if (header !== null) {
      push();
      current = {
        name: header[1] ?? "",
        flags: header[3] === undefined || header[3] === "" ? null : header[3],
        status: null,
        mac: null,
        ipv4: [],
        ipv6: [],
        awdl_role: null,
      };
      continue;
    }
    if (current === null) {
      unparsedLines.push(line);
      continue;
    }
    const mac = ETHER_ROW.exec(line);
    if (mac !== null) {
      current.mac = mac[1]?.toLowerCase() ?? null;
      continue;
    }
    const inet = INET_ROW.exec(line);
    if (inet !== null) {
      current.ipv4.push(inet[1] ?? "");
      continue;
    }
    const inet6 = INET6_ROW.exec(line);
    if (inet6 !== null) {
      current.ipv6.push(inet6[1] ?? "");
      continue;
    }
    const status = STATUS_ROW.exec(line);
    if (status !== null) {
      current.status = status[1] ?? null;
      continue;
    }
    const awdlRole = AWDL_ROLE_ROW.exec(line);
    if (awdlRole !== null) {
      current.awdl_role = awdlRole[1] ?? null;
      continue;
    }
    unparsedLines.push(line);
  }
  push();
  return { items, unparsedLines };
};

/**
 * Map numeric interface indexes to names from the same `ifconfig -a -v`
 * output; macOS 27 prints `index <n>` on each header line. dns-sd's
 * `(interface N)` and -G IF column are indexes in this numbering.
 */
export const parseInterfaceIndexes = (
  stdout: string,
): ListResult<IfconfigIndexRow> => {
  const items: IfconfigIndexRow[] = [];
  const unparsedLines: string[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line)) continue;
    const header = IFCONFIG_HEADER.exec(line);
    if (header === null) continue;
    const index = IFCONFIG_INDEX.exec(line);
    if (index === null) {
      unparsedLines.push(line);
      continue;
    }
    items.push({ index: index[1] ?? "", name: header[1] ?? "" });
  }
  return { items, unparsedLines };
};

/**
 * AWDL peer rows, filtered locally from an `ndp -a -n` window. This lane
 * keeps its own row discipline instead of reusing the arp/ndp lane's
 * neighbor parser: only rows whose netif or `%zone` interface is awdl0 or
 * llw0 become peers, with the `%zone` suffix removed from the peer address.
 * Rows whose link-layer address matches awdl0's own `ether` address are the
 * host itself, not peers, and are dropped; the wiring layer's limitation
 * text documents that exclusion.
 */
export const parseAwdlNeighbors = (
  stdout: string,
  selfMacs: readonly string[] = [],
): ListResult<IfconfigPeerRow> => {
  const items: IfconfigPeerRow[] = [];
  const unparsedLines: string[] = [];
  const headerLike = /^\s*Neighbor\s/u;
  const selfSet = new Set(
    selfMacs.map((mac) => canonicalMac(mac.toLowerCase())),
  );
  for (const line of stdout.split(/\r?\n/u)) {
    if (EMPTY_LINE.test(line) || headerLike.test(line)) continue;
    const tokens = line.trim().split(/\s+/u);
    if (tokens.length < 2) {
      unparsedLines.push(line);
      continue;
    }
    const addressToken = tokens[0] ?? "";
    const percent = addressToken.indexOf("%");
    const address =
      percent === -1 ? addressToken : addressToken.slice(0, percent);
    const zone =
      percent === -1 ? null : addressToken.slice(percent + 1) || null;
    if (!address.includes(":")) {
      unparsedLines.push(line);
      continue;
    }
    const macToken = tokens[1] ?? "";
    const mac = MAC_LIKE.test(macToken) ? macToken.toLowerCase() : null;
    const netif = tokens[2] ?? null;
    const owner = zone ?? netif;
    if (owner === null || !AWDL_INTERFACES.has(owner.toLowerCase())) continue;
    if (mac !== null && selfSet.size > 0 && selfSet.has(canonicalMac(mac)))
      continue;
    items.push({ peer: address, mac, interface: owner });
  }
  return { items, unparsedLines };
};

/** Read this host's interface inventory and, asked, awdl0/llw0 ND rows. */
export const executeInspectNetworkInterfaces = async (
  ifconfigPath: string,
  ndpPath: string,
  input: NetworkInterfacesInput,
  signal?: AbortSignal,
  launcher?: DiscoveryProcessLauncher,
): Promise<Result<NetworkInterfacesResult, AnalysisError>> => {
  const started = Date.now();
  const ifconfigRun = await runDiscoveryCommand(
    "inspect_network_interfaces",
    ifconfigPath,
    ["-a", "-v"],
    { timeoutMs: 5_000 },
    signal,
    launcher,
  );
  if (!ifconfigRun.ok) return ifconfigRun;
  const blocks = parseIfconfigOutput(ifconfigRun.value.stdout);
  const indexes = parseInterfaceIndexes(ifconfigRun.value.stdout);
  const unparsedLines = [...blocks.unparsedLines, ...indexes.unparsedLines];
  const interfaceIndexes: Record<string, string> = {};
  for (const row of indexes.items)
    if (row.index.length > 0 && row.name.length > 0)
      interfaceIndexes[row.index] = row.name;
  let peers: IfconfigPeerRow[] | null = null;
  if (input.include_neighbors) {
    const ndpRun = await runDiscoveryCommand(
      "inspect_network_interfaces",
      ndpPath,
      ["-a", "-n"],
      { timeoutMs: 5_000 },
      signal,
      launcher,
    );
    if (!ndpRun.ok) return ndpRun;
    const selfMacs = blocks.items
      .filter((row) => row.name === "awdl0" && row.mac !== null)
      .map((row) => row.mac!);
    const peersParsed = parseAwdlNeighbors(ndpRun.value.stdout, selfMacs);
    unparsedLines.push(...peersParsed.unparsedLines);
    peers = peersParsed.items;
  }
  return ok({
    interfaces: blocks.items,
    interface_indexes: interfaceIndexes,
    peers,
    elapsed_ms: Date.now() - started,
    unparsed_lines: unparsedLines,
    coverage:
      unparsedLines.length > 0 ? ("partial" as const) : ("complete" as const),
  });
};
