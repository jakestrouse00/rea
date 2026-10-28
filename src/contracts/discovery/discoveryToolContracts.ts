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
    name: "scan_ble_advertisements",
    description:
      "Run one bounded BLE advertisement observation window through a caller-supplied CoreBluetooth scanner (`REA_BLE_SCANNER_PATH`; REA never installs one). Receive-only: it listens for advertising packets and sends no connection requests. macOS reports peripherals by CoreBluetooth UUID, never by Bluetooth MAC address; rows are the scanner's own JSON publications, preserved verbatim within the window. Read-only with respect to advertising peers.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.scan_ble_advertisements,
    outputSchema: evidenceResultOf(
      discoveryResultSchemas.scan_ble_advertisements,
    ),
    ...toolContractMetadata("scan_ble_advertisements"),
    examples: [
      { title: "Observe BLE advertisements for 10 s", input: {} },
      {
        title: "Filter on one peripheral identifier",
        input: {
          scan_seconds: 10,
          address_filter: "6C9A1B2C-3D4E-5F60-8A7B-9C0D1E2F3A4B",
        },
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
  {
    name: "capture_radio_packets",
    description:
      "Run a caller-supplied packet-capture program (`REA_PACKET_CAPTURE_COMMAND`, or a per-call `command` override) for one bounded window and validate the retained output file's pcap/pcapng magic, bytes and SHA-256. REA never installs a capture binary and never elevates privileges; the program is preconfigured by the caller with its own interface and flags and receives exactly one argument, the output path. Requires `authorize_capture: true`. Retain the file for inspect_pcap_capture afterwards.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.capture_radio_packets,
    outputSchema: evidenceResultOf(
      discoveryResultSchemas.capture_radio_packets,
    ),
    ...toolContractMetadata("capture_radio_packets"),
    examples: [
      {
        title: "Capture one 10 s window to a caller-selected path",
        input: {
          output_path: "/tmp/rea-capture.pcap",
          duration_seconds: 10,
          authorize_capture: true,
        },
      },
    ],
  },
  {
    name: "scan_wifi_networks",
    description:
      "Scan the local Wi-Fi RF neighborhood through a caller-compiled CoreWLAN helper (`REA_WIFI_SCANNER_PATH`), falling back to this host's system_profiler airport scan cache when no helper is configured. macOS gates neighbor RF scans behind Location Services: a TCC denial is a structured failure and a withheld BSSID/SSID is preserved verbatim as null. Read-only observation of broadcast beacon frames.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.scan_wifi_networks,
    outputSchema: evidenceResultOf(discoveryResultSchemas.scan_wifi_networks),
    ...toolContractMetadata("scan_wifi_networks"),
    examples: [
      { title: "Observe neighbor RF facts with SSIDs withheld", input: {} },
      {
        title: "One 20 s helper window with SSIDs kept",
        input: { include_ssid: true, scan_seconds: 20 },
      },
    ],
  },
  {
    name: "resolve_mdns_records",
    description:
      "Resolve one mDNS service instance found by browse_lan_services: dns-sd -L yields the SRV target, port and TXT records within a bounded window, then -G v4v6 yields the target's addresses with their interface indexes. Emits multicast queries; an empty window is silence, never proof of absence. Read-only with respect to responding hosts.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.resolve_mdns_records,
    outputSchema: evidenceResultOf(discoveryResultSchemas.resolve_mdns_records),
    ...toolContractMetadata("resolve_mdns_records"),
    examples: [
      {
        title: "Resolve one printer instance",
        input: {
          instance: "Office Printer",
          service_type: "_ipp._tcp.",
          resolve_seconds: 5,
        },
      },
    ],
  },
  {
    name: "inspect_network_interfaces",
    description:
      "Read this host's interface table (ifconfig -a -v: names, status, addresses, MACs, AWDL roles) with a reliable ifIndex→name mapping, plus the kernel IPv6 neighbor rows on awdl0/llw0 as AWDL peers. Read-only; no radio transmission.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.inspect_network_interfaces,
    outputSchema: evidenceResultOf(
      discoveryResultSchemas.inspect_network_interfaces,
    ),
    ...toolContractMetadata("inspect_network_interfaces"),
    examples: [{ title: "Inspect interfaces and AWDL peers", input: {} }],
  },
  {
    name: "list_serial_ports",
    description:
      "Inventory this host's serial device nodes: system_profiler SPPortsDataType joined with the /dev/cu.* and /dev/tty.* listings by name, unmatched devices kept as their own row with null facts. Read-only.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.list_serial_ports,
    outputSchema: evidenceResultOf(discoveryResultSchemas.list_serial_ports),
    ...toolContractMetadata("list_serial_ports"),
    examples: [{ title: "List serial device nodes", input: {} }],
  },
  {
    name: "observe_serial_port",
    description:
      "Observe one serial device node's receive side for a bounded window: stty configures the line discipline, the node is opened O_RDONLY (never a byte is written), and the bytes observed are reported as bounded hex and printable previews. Reading is not neutral to all hardware: asserting the serial port while it is opened can toggle modem-control lines (for example DTR), which resets some devices.",
    kind: "runtime-provider",
    inputSchema: discoveryInputSchemas.observe_serial_port,
    outputSchema: evidenceResultOf(discoveryResultSchemas.observe_serial_port),
    ...toolContractMetadata("observe_serial_port"),
    examples: [
      {
        title: "Watch one device's receive side for 5 s at 9600 8N1",
        input: { device_path: "/dev/cu.usbserial-0001" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
