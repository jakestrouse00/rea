import { toolContractMetadata } from "../toolEffects.js";
import {
  discoveryInputSchemas,
  discoveryResultSchemas,
} from "../../domain/discovery/discoveryAnalysis.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/**
 * Local network/device discovery over host-provided macOS tools. Passive
 * sources read this host's own observation state; the active sweep is
 * separately gated by an explicit caller authorization input.
 */
export const DISCOVERY_TOOL_CONTRACTS = [
  {
    name: "list_network_neighbors",
    description:
      "Read this host's own neighbor tables (arp for IPv4, ndp for IPv6): link-layer addresses, interfaces and reachability states this Mac has recently observed. An empty table is an observation, not an error. Entries can be stale because kernels expire them; REA never probes the network to fill them. Read-only.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.list_network_neighbors,
    outputSchema: evidenceResultOf(
      discoveryResultSchemas.list_network_neighbors,
    ),
    ...toolContractMetadata("list_network_neighbors"),
    examples: [{ title: "Read the host's neighbor tables", input: {} }],
  },
  {
    name: "browse_lan_services",
    description:
      "Browse the local network for mDNS/Bonjour services the way Finder's network sidebar does: dns-sd meta-browse yields service types, then each type is browsed for instance names within bounded windows. Emits multicast queries on the LAN; respondents publish their own names. Read-only with respect to responding hosts.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.browse_lan_services,
    outputSchema: evidenceResultOf(discoveryResultSchemas.browse_lan_services),
    ...toolContractMetadata("browse_lan_services"),
    examples: [
      {
        title: "Browse service types and instances for ~22 s",
        input: { browse_seconds: 10, per_type_seconds: 3, max_types: 4 },
      },
    ],
  },
  {
    name: "list_usb_devices",
    description:
      "Read the host's USB/Thunderbolt device tree through system_profiler, with each device row preserved as reported (vendor/product ids, manufacturer, serial). Shows devices that exist on the bus even when adb or pymobiledevice3 tooling is not installed, making those lanes' readiness gaps visible. Read-only.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.list_usb_devices,
    outputSchema: evidenceResultOf(discoveryResultSchemas.list_usb_devices),
    ...toolContractMetadata("list_usb_devices"),
    examples: [{ title: "Inventory USB devices", input: {} }],
  },
  {
    name: "list_bluetooth_devices",
    description:
      "Read this host's paired and connected Bluetooth inventory, optionally adding a bounded discovery window through a caller-supplied blueutil (`REA_BLUEUTIL_PATH`) whose classic-inquiry rows are published verbatim. The inquiry emits short-range radio queries; paired reading is local. REA never installs blueutil and never pairs.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.list_bluetooth_devices,
    outputSchema: evidenceResultOf(
      discoveryResultSchemas.list_bluetooth_devices,
    ),
    ...toolContractMetadata("list_bluetooth_devices"),
    examples: [
      { title: "Read the paired inventory", input: {} },
      {
        title: "Run a 10 s discovery through caller-supplied blueutil",
        input: { source: "inquiry", inquiry_seconds: 10 },
      },
    ],
  },
  {
    name: "probe_subnet_reachability",
    description:
      "Send exactly one ICMP echo request to every candidate host of a caller-selected IPv4 CIDR (/22../32) at bounded concurrency, with optional TCP connect probes to caller-selected ports against responsive hosts. Requires `authorize_probe: true`: the packets originate from this host and are visible to network monitoring. No sweeping beyond the selected CIDR; no exploitation.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.probe_subnet_reachability,
    outputSchema: evidenceResultOf(
      discoveryResultSchemas.probe_subnet_reachability,
    ),
    ...toolContractMetadata("probe_subnet_reachability"),
    examples: [
      {
        title: "Probe one /24 with TCP probes for adb and frida defaults",
        input: {
          cidr: "192.168.1.0/24",
          authorize_probe: true,
          tcp_ports: [5555, 27042, 5000],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
