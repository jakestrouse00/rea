import { z } from "incur";

import { DiscoveryAnalysisService } from "../application/discovery/DiscoveryAnalysisService.js";
import type { DiscoveryAnalysisPort } from "../application/discovery/DiscoveryPort.js";
import { createDiscoveryAnalysisProvider } from "../composition/discovery.js";
import type { DiscoveryOperation } from "../domain/discovery/discoveryAnalysis.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";

const DISCOVERY_CLI_COMMANDS = CLI_COMMANDS;

/** Expose the discovery-lane operations through the CLI. */
export const registerDiscoveryCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
  provider: DiscoveryAnalysisPort = createDiscoveryAnalysisProvider(
    environment,
  ),
): void => {
  const service = new DiscoveryAnalysisService(provider);
  const execute = (
    name: string,
    operation: DiscoveryOperation,
    input: unknown,
  ) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, () =>
        finishAnalysisCommand(
          () => service.execute(operation, input, { signal }),
          { close: () => provider.close() },
          "discovery",
          operation,
          signal,
        ),
      ),
    );

  cli.command(DISCOVERY_CLI_COMMANDS.listNetworkNeighbors, {
    description:
      "Read this host's arp/ndp neighbor tables; an empty table is an observation, not an error",
    args: z.object({}),
    run: () =>
      execute(
        DISCOVERY_CLI_COMMANDS.listNetworkNeighbors,
        "list_network_neighbors",
        {},
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.browseLanServices, {
    description:
      "Browse the local network for mDNS/Bonjour service types and instances in bounded windows",
    options: z.object({
      "browse-seconds": z
        .number()
        .int()
        .min(1)
        .max(30)
        .default(10)
        .describe("Multicast browse window for the service-type meta query"),
      "per-type-seconds": z
        .number()
        .int()
        .min(1)
        .max(10)
        .default(3)
        .describe("Instance browse window per discovered service type"),
      "max-types": z
        .number()
        .int()
        .min(1)
        .max(32)
        .default(16)
        .describe("Maximum service types to browse for instances"),
    }),
    run: ({ options }) =>
      execute(DISCOVERY_CLI_COMMANDS.browseLanServices, "browse_lan_services", {
        browse_seconds: options["browse-seconds"],
        per_type_seconds: options["per-type-seconds"],
        max_types: options["max-types"],
      }),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.listUsbDevices, {
    description:
      "Inventory the USB/Thunderbolt device tree through system_profiler",
    args: z.object({}),
    run: () =>
      execute(DISCOVERY_CLI_COMMANDS.listUsbDevices, "list_usb_devices", {}),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.listBluetoothDevices, {
    description:
      "Read the host's paired Bluetooth inventory, optionally adding a bounded inquiry window via caller-supplied blueutil",
    options: z.object({
      source: z
        .enum(["paired", "inquiry"])
        .default("paired")
        .describe("paired reads the host inventory; inquiry runs blueutil"),
      "inquiry-seconds": z
        .number()
        .int()
        .min(2)
        .max(60)
        .default(10)
        .describe("Discovery window in seconds when source is inquiry"),
    }),
    run: ({ options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.listBluetoothDevices,
        "list_bluetooth_devices",
        {
          source: options.source,
          inquiry_seconds: options["inquiry-seconds"],
        },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.scanBleAdvertisements, {
    description:
      "Run one bounded BLE advertisement window via a caller-supplied CoreBluetooth scanner (receive-only; peripherals appear as CoreBluetooth UUIDs)",
    options: z.object({
      "scan-seconds": z
        .number()
        .int()
        .min(2)
        .max(60)
        .default(10)
        .describe("BLE advertisement observation window in seconds"),
      "address-filter": z
        .string()
        .min(1)
        .max(64)
        .optional()
        .describe("Optional peripheral identifier filter (CoreBluetooth UUID)"),
    }),
    run: ({ options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.scanBleAdvertisements,
        "scan_ble_advertisements",
        {
          scan_seconds: options["scan-seconds"],
          ...(options["address-filter"] === undefined
            ? {}
            : { address_filter: options["address-filter"] }),
        },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.connectBleGatt, {
    description:
      "Open one authorized CoreBluetooth GATT connection via a caller-supplied helper and discover its services (requires --authorize-gatt)",
    options: z.object({
      "peripheral-id": z
        .string()
        .min(1)
        .max(64)
        .describe("CoreBluetooth peripheral identifier (uppercase UUID)"),
      "authorize-gatt": z
        .boolean()
        .describe(
          "Must be true: the connection sends ATT protocol requests to the peer",
        ),
      "connect-timeout-ms": z
        .number()
        .int()
        .min(1000)
        .max(60000)
        .default(10000)
        .describe("Deadline for the connection and discovery handshake"),
    }),
    run: ({ options }) =>
      execute(DISCOVERY_CLI_COMMANDS.connectBleGatt, "connect_ble_gatt", {
        peripheral_id: options["peripheral-id"],
        authorize_gatt: options["authorize-gatt"] === true,
        connect_timeout_ms: options["connect-timeout-ms"],
      }),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.readGattCharacteristic, {
    description:
      "Read one characteristic value over an open GATT session (digest only unless --include-payload-hex)",
    options: z.object({
      "session-id": z.string().uuid().describe("Session from connect-ble-gatt"),
      "service-uuid": z
        .string()
        .min(1)
        .max(64)
        .describe("Service UUID as discovery reported it"),
      "characteristic-uuid": z
        .string()
        .min(1)
        .max(64)
        .describe("Characteristic UUID as discovery reported it"),
      "include-payload-hex": z
        .boolean()
        .default(false)
        .describe(
          "Retain the payload hex in Evidence; the default reports a digest and length only",
        ),
    }),
    run: ({ options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.readGattCharacteristic,
        "read_gatt_characteristic",
        {
          session_id: options["session-id"],
          service_uuid: options["service-uuid"],
          characteristic_uuid: options["characteristic-uuid"],
          include_payload_hex: options["include-payload-hex"],
        },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.writeGattCharacteristic, {
    description:
      "Send bytes to one characteristic over an open GATT session exactly once; changes device state (requires --authorize-write)",
    options: z.object({
      "session-id": z.string().uuid().describe("Session from connect-ble-gatt"),
      "service-uuid": z
        .string()
        .min(1)
        .max(64)
        .describe("Service UUID as discovery reported it"),
      "characteristic-uuid": z
        .string()
        .min(1)
        .max(64)
        .describe("Characteristic UUID as discovery reported it"),
      "payload-hex": z
        .string()
        .max(1024)
        .regex(/^(?:[0-9a-fA-F]{2})+$/u)
        .describe("Even-numbered hex bytes to send"),
      "without-response": z
        .boolean()
        .default(false)
        .describe("true uses the connectionless ATT write command"),
      "authorize-write": z
        .boolean()
        .describe(
          "Must be true: the peer can change device state, actuate hardware, or erase data",
        ),
    }),
    run: ({ options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.writeGattCharacteristic,
        "write_gatt_characteristic",
        {
          session_id: options["session-id"],
          service_uuid: options["service-uuid"],
          characteristic_uuid: options["characteristic-uuid"],
          payload_hex: options["payload-hex"],
          without_response: options["without-response"],
          authorize_write: options["authorize-write"] === true,
        },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.observeGattNotifications, {
    description:
      "Collect one bounded notification window over an open GATT session (CCCD control write within the session's own connection)",
    options: z.object({
      "session-id": z.string().uuid().describe("Session from connect-ble-gatt"),
      "service-uuid": z
        .string()
        .min(1)
        .max(64)
        .describe("Service UUID as discovery reported it"),
      "characteristic-uuid": z
        .string()
        .min(1)
        .max(64)
        .describe("Notifiable characteristic UUID as discovery reported it"),
      "observe-seconds": z
        .number()
        .int()
        .min(2)
        .max(60)
        .default(10)
        .describe("Notification observation window in seconds"),
      "include-payload-hex": z
        .boolean()
        .default(false)
        .describe(
          "Retain notification payload hex in Evidence; the default reports digests",
        ),
    }),
    run: ({ options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.observeGattNotifications,
        "observe_gatt_notifications",
        {
          session_id: options["session-id"],
          service_uuid: options["service-uuid"],
          characteristic_uuid: options["characteristic-uuid"],
          observe_seconds: options["observe-seconds"],
          include_payload_hex: options["include-payload-hex"],
        },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.closeBleGatt, {
    description:
      "Disconnect one named GATT session cleanly and report any cleanup uncertainty",
    options: z.object({
      "session-id": z.string().uuid().describe("Session from connect-ble-gatt"),
    }),
    run: ({ options }) =>
      execute(DISCOVERY_CLI_COMMANDS.closeBleGatt, "close_ble_gatt", {
        session_id: options["session-id"],
      }),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.captureRadioPackets, {
    description:
      "Run a caller-supplied packet-capture program for one bounded window and validate the retained pcap file (requires --authorize)",
    args: z.object({
      "output-path": z
        .string()
        .min(5)
        .describe("Absolute path ending .pcap or .pcapng for the capture file"),
    }),
    options: z.object({
      authorize: z
        .boolean()
        .describe(
          "Must be true to acknowledge that the capture originates packets and RxFrames from this host",
        ),
      "duration-seconds": z
        .number()
        .int()
        .min(1)
        .max(60)
        .default(10)
        .describe("How long the capture program runs before REA terminates it"),
      command: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Absolute capture command for this invocation instead of REA_PACKET_CAPTURE_COMMAND",
        ),
    }),
    run: ({ args, options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.captureRadioPackets,
        "capture_radio_packets",
        {
          output_path: args["output-path"],
          duration_seconds: options["duration-seconds"],
          authorize_capture: options.authorize === true,
          ...(options.command === undefined
            ? {}
            : { command: options.command }),
        },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.scanWifiNetworks, {
    description:
      "Scan the local Wi-Fi RF neighborhood via a caller-built CoreWLAN helper, or system_profiler's airport cache as a fallback",
    options: z.object({
      "include-ssid": z
        .boolean()
        .default(false)
        .describe(
          "Keep SSIDs on rows; default drops them at the parse boundary",
        ),
      "scan-seconds": z
        .number()
        .int()
        .min(2)
        .max(60)
        .default(10)
        .describe("Bounded scan window in seconds for the helper"),
    }),
    run: ({ options }) =>
      execute(DISCOVERY_CLI_COMMANDS.scanWifiNetworks, "scan_wifi_networks", {
        include_ssid: options["include-ssid"],
        scan_seconds: options["scan-seconds"],
      }),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.resolveMdnsRecords, {
    description:
      "Resolve one mDNS service instance: SRV target, port, TXT records and the target's addresses in bounded dns-sd windows",
    args: z.object({
      instance: z
        .string()
        .min(1)
        .describe("Service instance name from a browse"),
      service_type: z
        .string()
        .min(1)
        .describe("Service type with trailing dot, e.g. _http._tcp."),
    }),
    options: z.object({
      domain: z.string().default("local.").describe("Trailing-dot mDNS domain"),
      "resolve-seconds": z
        .number()
        .int()
        .min(2)
        .max(15)
        .default(5)
        .describe("Per dns-sd window deadline in seconds"),
      "include-addresses": z
        .boolean()
        .default(true)
        .describe("Run the -G v4v6 address window against the SRV target"),
    }),
    run: ({ args, options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.resolveMdnsRecords,
        "resolve_mdns_records",
        {
          instance: args.instance,
          service_type: args.service_type,
          domain: options.domain,
          resolve_seconds: options["resolve-seconds"],
          include_addresses: options["include-addresses"],
        },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.inspectNetworkInterfaces, {
    description:
      "Read the interface table with an ifIndex mapping and the kernel AWDL peer rows on awdl0/llw0",
    options: z.object({
      "include-neighbors": z
        .boolean()
        .default(true)
        .describe("Keep the awdl0/llw0 neighbor rows as AWDL peers"),
    }),
    run: ({ options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.inspectNetworkInterfaces,
        "inspect_network_interfaces",
        { include_neighbors: options["include-neighbors"] },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.listSerialPorts, {
    description:
      "Inventory serial device nodes: SPPortsDataType joined with the /dev listings by name; unmatched devices keep null facts",
    args: z.object({}),
    run: () =>
      execute(DISCOVERY_CLI_COMMANDS.listSerialPorts, "list_serial_ports", {}),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.observeSerialPort, {
    description:
      "Watch one serial device's receive side for a bounded window at a chosen baud rate (rx-only; asserts modem-control lines on open)",
    args: z.object({
      "device-path": z
        .string()
        .min(8)
        .describe("Absolute /dev/cu.* or /dev/tty.* device node"),
    }),
    options: z.object({
      "duration-seconds": z
        .number()
        .int()
        .min(1)
        .max(30)
        .default(5)
        .describe("Receive observation window in seconds"),
      "baud-rate": z
        .union([
          z.literal(1200),
          z.literal(2400),
          z.literal(4800),
          z.literal(9600),
          z.literal(19200),
          z.literal(38400),
          z.literal(57600),
          z.literal(115200),
        ])
        .default(9600)
        .describe("Baud rate stty configures before the window opens"),
    }),
    run: ({ args, options }) =>
      execute(DISCOVERY_CLI_COMMANDS.observeSerialPort, "observe_serial_port", {
        device_path: args["device-path"],
        duration_seconds: options["duration-seconds"],
        baud_rate: options["baud-rate"],
      }),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.probeSubnetReachability, {
    description:
      "Send exactly one ICMP echo per candidate host of a /22../32 CIDR at bounded concurrency, with optional TCP connect probes",
    args: z.object({
      cidr: z
        .string()
        .min(10)
        .describe("IPv4 network to probe, e.g. 192.168.1.0/24"),
    }),
    options: z.object({
      authorize: z
        .boolean()
        .describe(
          "Must be true to acknowledge the packets this host will send",
        ),
      concurrency: z
        .number()
        .int()
        .min(1)
        .max(64)
        .default(16)
        .describe("Maximum hosts probed in parallel"),
      "per-host-timeout": z
        .number()
        .int()
        .min(100)
        .max(5000)
        .default(1000)
        .describe("Deadline for one host's ICMP echo exchange, in ms"),
      "tcp-ports": z
        .string()
        .default("")
        .describe(
          "Comma-separated TCP ports to probe on responsive hosts, e.g. 5555,27042",
        ),
    }),
    run: ({ args, options }) => {
      const parsedPorts = options["tcp-ports"]
        .split(",")
        .map((part) => part.trim())
        .filter((part) => part.length > 0)
        .map(Number);
      return execute(
        DISCOVERY_CLI_COMMANDS.probeSubnetReachability,
        "probe_subnet_reachability",
        {
          cidr: args.cidr,
          authorize_probe: options.authorize === true,
          concurrency: options.concurrency,
          per_host_timeout_ms: options["per-host-timeout"],
          tcp_ports: parsedPorts,
        },
      );
    },
  });
};
