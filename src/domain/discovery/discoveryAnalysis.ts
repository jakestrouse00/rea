import { z } from "zod";

import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

/** MAC address as the host's own neighbor tables spell it (e.g. a4:83:e7:..). */
export const discoveryMacSchema = z
  .string()
  .min(5)
  .max(64)
  .describe("Link-layer address exactly as the host table reports it");

/** IPv4 CIDR for the active sweep; /22.._/32 bounds one call to <=1022 hosts. */
export const discoveryCidrSchema = z
  .string()
  .min(10)
  .max(18)
  .regex(
    /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(2[2-9]|3[0-2])$/u,
    "Use an IPv4 CIDR with prefix length 22..32, e.g. 192.168.1.0/24",
  )
  .describe(
    "IPv4 network to probe; prefix 22..32 bounds one invocation to <=1022 candidate hosts",
  );

/** One-shot network/device discovery operations over host-provided tools. */
export const discoveryInputSchemas = {
  list_network_neighbors: z.strictObject({}),
  browse_lan_services: z.strictObject({
    browse_seconds: z
      .number()
      .int()
      .min(1)
      .max(30)
      .default(10)
      .describe(
        "Multicast browse window for the service-type meta query, in seconds",
      ),
    per_type_seconds: z
      .number()
      .int()
      .min(1)
      .max(10)
      .default(3)
      .describe("Instance browse window per discovered service type"),
    max_types: z
      .number()
      .int()
      .min(1)
      .max(32)
      .default(16)
      .describe(
        "Maximum number of discovered service types to browse for instances",
      ),
  }),
  list_usb_devices: z.strictObject({}),
  list_bluetooth_devices: z.strictObject({
    source: z
      .enum(["paired", "inquiry"])
      .default("paired")
      .describe(
        "paired reads this host's paired/connected inventory; inquiry additionally runs a caller-supplied blueutil discovery window",
      ),
    inquiry_seconds: z
      .number()
      .int()
      .min(2)
      .max(60)
      .default(10)
      .describe("Discovery window in seconds when source is inquiry"),
  }),
  scan_ble_advertisements: z.strictObject({
    scan_seconds: z
      .number()
      .int()
      .min(2)
      .max(60)
      .default(10)
      .describe("BLE advertisement observation window in seconds"),
    address_filter: z
      .string()
      .min(1)
      .max(64)
      .optional()
      .describe(
        "Optional peripheral identifier filter; CoreBluetooth reports peripherals by UUID, not by Bluetooth MAC address",
      ),
  }),
  connect_ble_gatt: z.strictObject({
    peripheral_id: z
      .string()
      .min(1)
      .max(64)
      .describe(
        "CoreBluetooth peripheral identifier exactly as an advertisement reported it (uppercase UUID); macOS publishes rotating identifiers, not stable MAC addresses",
      ),
    authorize_gatt: z
      .literal(true)
      .describe(
        "Must be true: opening the connection sends ATT protocol requests to the peer and changes the peer's connection state; data changes additionally need authorize_write on write_gatt_characteristic",
      ),
    connect_timeout_ms: z
      .number()
      .int()
      .min(1000)
      .max(60000)
      .default(10000)
      .describe("Deadline for the peer's connection and discovery handshake"),
  }),
  read_gatt_characteristic: z.strictObject({
    session_id: z.string().uuid().describe("Session from connect_ble_gatt"),
    service_uuid: z
      .string()
      .min(1)
      .max(64)
      .describe("Service UUID exactly as discovery reported it"),
    characteristic_uuid: z
      .string()
      .min(1)
      .max(64)
      .describe("Characteristic UUID exactly as discovery reported it"),
    include_payload_hex: z
      .boolean()
      .default(false)
      .describe(
        "When false the value is reported as a SHA-256 digest and length only; when true the payload hex is retained in Evidence",
      ),
  }),
  write_gatt_characteristic: z.strictObject({
    session_id: z.string().uuid().describe("Session from connect_ble_gatt"),
    service_uuid: z
      .string()
      .min(1)
      .max(64)
      .describe("Service UUID exactly as discovery reported it"),
    characteristic_uuid: z
      .string()
      .min(1)
      .max(64)
      .describe("Characteristic UUID exactly as discovery reported it"),
    payload_hex: z
      .string()
      .max(1024)
      .regex(/^(?:[0-9a-fA-F]{2})+$/u, "Even-numbered hex bytes, e.g. 33101100")
      .describe(
        "Bytes to write to the characteristic, as hex; the write is sent exactly once and never retried",
      ),
    without_response: z
      .boolean()
      .default(false)
      .describe(
        "true uses the connectionless ATT write command; false awaits the peer's acknowledgment",
      ),
    authorize_write: z
      .literal(true)
      .describe(
        "Must be true: the bytes are sent to the peer and can change device state, actuate hardware, or erase data; REA sends them exactly once with no retry",
      ),
  }),
  observe_gatt_notifications: z.strictObject({
    session_id: z.string().uuid().describe("Session from connect_ble_gatt"),
    service_uuid: z
      .string()
      .min(1)
      .max(64)
      .describe("Service UUID exactly as discovery reported it"),
    characteristic_uuid: z
      .string()
      .min(1)
      .max(64)
      .describe(
        "Notifiable characteristic UUID exactly as discovery reported it",
      ),
    observe_seconds: z
      .number()
      .int()
      .min(2)
      .max(60)
      .default(10)
      .describe("Notification observation window in seconds"),
    include_payload_hex: z
      .boolean()
      .default(false)
      .describe(
        "When false notifications are reported as SHA-256 digests and lengths only; when true the payload hex is retained in Evidence",
      ),
  }),
  close_ble_gatt: z.strictObject({
    session_id: z.string().uuid().describe("Session from connect_ble_gatt"),
  }),
  scan_wifi_networks: z.strictObject({
    include_ssid: z
      .boolean()
      .default(false)
      .describe(
        "When true the SSID column is kept on rows; when false SSIDs are dropped before parsing so rows carry only RF/phy facts",
      ),
    scan_seconds: z
      .number()
      .int()
      .min(2)
      .max(60)
      .default(10)
      .describe(
        "Bounded scan window in seconds for the CoreWLAN helper; the system_profiler fallback ignores it",
      ),
  }),
  resolve_mdns_records: z.strictObject({
    instance: z
      .string()
      .min(1)
      .max(255)
      .describe("Service instance name exactly as a browse reported it"),
    service_type: z
      .string()
      .regex(
        /^_[a-z0-9-]+\._(?:tcp|udp)\.$/iu,
        "Use a service type with its trailing dot, e.g. _http._tcp.",
      )
      .describe(
        "One mDNS service type with its trailing dot, e.g. _http._tcp.",
      ),
    domain: z
      .string()
      .regex(
        /^(?:[a-z0-9_-]{1,63}\.)+$/iu,
        "Use a trailing-dot mDNS domain such as local.",
      )
      .default("local.")
      .describe("Trailing-dot mDNS domain of the service; local. is the norm"),
    resolve_seconds: z
      .number()
      .int()
      .min(2)
      .max(15)
      .default(5)
      .describe(
        "Per dns-sd window deadline in seconds (-L and any follow-up reads)",
      ),
    include_addresses: z
      .boolean()
      .default(true)
      .describe(
        "Whether to run the -G v4v6 address window against the resolved SRV target",
      ),
  }),
  inspect_network_interfaces: z.strictObject({
    include_neighbors: z
      .boolean()
      .default(true)
      .describe(
        "Whether to read the IPv6 neighbor table and keep the rows on awdl0/llw0 as AWDL peers",
      ),
  }),
  list_serial_ports: z.strictObject({}),
  observe_serial_port: z.strictObject({
    device_path: z
      .string()
      .min(8)
      .max(128)
      .regex(
        /^\/dev\/(cu|tty)\.[^/]+$/u,
        "Use an absolute /dev/cu.* or /dev/tty.* device node path",
      )
      .describe("Serial device node whose receive side is observed"),
    duration_seconds: z
      .number()
      .int()
      .min(1)
      .max(30)
      .default(5)
      .describe("Receive observation window in seconds"),
    baud_rate: z
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
      .describe("Baud rate stty configures before the receive window opens"),
  }),
  capture_radio_packets: z.strictObject({
    output_path: absoluteLocalPathStringSchema
      .min(5)
      .regex(/\.pcap(ng)?$/u, "Use an absolute path ending .pcap or .pcapng")
      .describe(
        "Absolute path where the caller-provided capture program writes the capture file; preserved exactly as given and never deleted, even when validation fails",
      ),
    duration_seconds: z
      .number()
      .int()
      .min(1)
      .max(60)
      .default(10)
      .describe("How long the capture program runs before REA terminates it"),
    authorize_capture: z
      .literal(true)
      .describe(
        "Must be true: acknowledge that the capture originates packets and RxFrames from this host and requires caller-provided privileges",
      ),
    command: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Absolute capture command used for this invocation instead of REA_PACKET_CAPTURE_COMMAND",
      ),
  }),
  probe_subnet_reachability: z.strictObject({
    cidr: discoveryCidrSchema.describe(
      "IPv4 network whose candidate addresses each receive one ICMP echo request",
    ),
    authorize_probe: z
      .literal(true)
      .describe(
        "Must be true: the probe sends packets this host originates and every responding host's monitoring can observe them",
      ),
    concurrency: z
      .number()
      .int()
      .min(1)
      .max(64)
      .default(16)
      .describe("Maximum hosts probed in parallel"),
    per_host_timeout_ms: z
      .number()
      .int()
      .min(100)
      .max(5000)
      .default(1000)
      .describe("Deadline for one host's ICMP echo exchange"),
    tcp_ports: z
      .array(z.number().int().min(1).max(65535))
      .max(8)
      .default([])
      .describe("Optional TCP connect probes run against each responsive host"),
  }),
} as const;

export type DiscoveryOperation = keyof typeof discoveryInputSchemas;

export type DiscoveryRequest = {
  [Name in DiscoveryOperation]: {
    operation: Name;
    input: z.infer<(typeof discoveryInputSchemas)[Name]>;
  };
}[DiscoveryOperation];

/** Validate operation and input together so their types remain correlated. */
export const discoveryRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("list_network_neighbors"),
    input: discoveryInputSchemas.list_network_neighbors,
  }),
  z.strictObject({
    operation: z.literal("browse_lan_services"),
    input: discoveryInputSchemas.browse_lan_services,
  }),
  z.strictObject({
    operation: z.literal("list_usb_devices"),
    input: discoveryInputSchemas.list_usb_devices,
  }),
  z.strictObject({
    operation: z.literal("list_bluetooth_devices"),
    input: discoveryInputSchemas.list_bluetooth_devices,
  }),
  z.strictObject({
    operation: z.literal("scan_ble_advertisements"),
    input: discoveryInputSchemas.scan_ble_advertisements,
  }),
  z.strictObject({
    operation: z.literal("connect_ble_gatt"),
    input: discoveryInputSchemas.connect_ble_gatt,
  }),
  z.strictObject({
    operation: z.literal("read_gatt_characteristic"),
    input: discoveryInputSchemas.read_gatt_characteristic,
  }),
  z.strictObject({
    operation: z.literal("write_gatt_characteristic"),
    input: discoveryInputSchemas.write_gatt_characteristic,
  }),
  z.strictObject({
    operation: z.literal("observe_gatt_notifications"),
    input: discoveryInputSchemas.observe_gatt_notifications,
  }),
  z.strictObject({
    operation: z.literal("close_ble_gatt"),
    input: discoveryInputSchemas.close_ble_gatt,
  }),
  z.strictObject({
    operation: z.literal("capture_radio_packets"),
    input: discoveryInputSchemas.capture_radio_packets,
  }),
  z.strictObject({
    operation: z.literal("resolve_mdns_records"),
    input: discoveryInputSchemas.resolve_mdns_records,
  }),
  z.strictObject({
    operation: z.literal("inspect_network_interfaces"),
    input: discoveryInputSchemas.inspect_network_interfaces,
  }),
  z.strictObject({
    operation: z.literal("list_serial_ports"),
    input: discoveryInputSchemas.list_serial_ports,
  }),
  z.strictObject({
    operation: z.literal("observe_serial_port"),
    input: discoveryInputSchemas.observe_serial_port,
  }),
  z.strictObject({
    operation: z.literal("scan_wifi_networks"),
    input: discoveryInputSchemas.scan_wifi_networks,
  }),
  z.strictObject({
    operation: z.literal("probe_subnet_reachability"),
    input: discoveryInputSchemas.probe_subnet_reachability,
  }),
]) as z.ZodType<DiscoveryRequest>;

/**
 * Resolved host-provided tool paths, as the readiness probe found them.
 * `blueutil` is the only optional tool: it is caller-supplied and required
 * only by the inquiry source of list_bluetooth_devices.
 */
const tools = z.strictObject({
  arp: z.string().min(1).nullable(),
  ndp: z.string().min(1).nullable(),
  dns_sd: z.string().min(1).nullable(),
  system_profiler: z.string().min(1).nullable(),
  ping: z.string().min(1).nullable(),
  ifconfig: z.string().min(1).nullable(),
  blueutil: z.string().min(1).nullable(),
  ble_scanner: z.string().min(1).nullable(),
  wifi_scanner: z.string().min(1).nullable(),
  ble_gatt: z.string().min(1).nullable(),
  stty: z.string().min(1).nullable(),
  packet_capture: z.string().min(1).nullable(),
});

/** One neighbor row as the host's arp/ndp table reports it. */
const neighbor = z.strictObject({
  family: z.enum(["ipv4", "ipv6"]),
  ip: z.string().min(1),
  mac: discoveryMacSchema.nullable(),
  interface: z.string().nullable(),
  state: z.string().nullable(),
  permanent: z.boolean().nullable(),
});

/** One mDNS service type with the instances observed for it. */
const serviceType = z.strictObject({
  service_type: z.string().min(1),
  domain: z.string().min(1),
  instances: z.array(
    z.strictObject({
      instance: z.string().min(1),
      interface_index: z.string().nullable(),
      event: z.string().nullable(),
    }),
  ),
});

/** One device row as system_profiler's USB tree reports it. */
const usbDevice = z.strictObject({
  name: z.string().nullable(),
  vendor_id: z.string().nullable(),
  product_id: z.string().nullable(),
  manufacturer: z.string().nullable(),
  serial_num: z.string().nullable(),
  location_id: z.string().nullable(),
  revision: z.string().nullable(),
  bcd_device: z.string().nullable(),
});

/** One paired/connected Bluetooth device as the host inventory reports it. */
const bluetoothDevice = z.strictObject({
  name: z.string().nullable(),
  address: discoveryMacSchema.nullable(),
  connected: z.boolean().nullable(),
  major_type: z.string().nullable(),
  minor_type: z.string().nullable(),
  firmware_version: z.string().nullable(),
});

/** One peer observed during a blueutil discovery window (classic Bluetooth). */
const inquiryDevice = z.strictObject({
  address: discoveryMacSchema.nullable(),
  name: z.string().nullable(),
  raw: z.string().min(1),
});

/**
 * One BLE advertisement event as the caller-supplied scanner's JSON stream
 * reported it. macOS CoreBluetooth publishes peripherals by UUID; a null
 * address_or_uuid is a row with no identifier, not a guessed one.
 */
const bleAdvertisement = z.strictObject({
  event: z.enum(["discovered", "updated"]),
  ts: z.string().min(1).nullable(),
  address_or_uuid: z.string().min(1).nullable(),
  name: z.string().nullable(),
  rssi: z.number().nullable(),
  connectable: z.boolean().nullable(),
  manufacturer_hex: z.string().min(1).nullable(),
  service_uuids: z.array(z.string().min(1)),
  raw: z.string().min(1),
});

/**
 * One GATT service as the per-peripheral discovery reported it; 16-bit
 * assignments keep their four-character spelling, vendor UUIDs stay verbatim.
 */
const gattService = z.strictObject({
  uuid: z.string().min(1),
  characteristics: z.array(
    z.strictObject({
      uuid: z.string().min(1),
      properties: z.array(
        z.enum([
          "broadcast",
          "read",
          "write_without_response",
          "write",
          "notify",
          "indicate",
          "authenticated_signed_writes",
          "extended_properties",
        ]),
      ),
    }),
  ),
});

/**
 * Value-free payload accounting shared by reads and notifications: length
 * and digest always; payload hex only when the caller opted in per call.
 */
const gattPayload = z.strictObject({
  len: z.number().int().nonnegative(),
  sha256: digestSchema,
  payload_hex: z
    .string()
    .max(4096)
    .regex(/^(?:[0-9a-f]{2})*$/u, "Lowercase hex byte pairs; empty is valid")
    .nullable(),
});

/** One notification event as the helper published it. */
const gattNotification = z.strictObject({
  ts: z.string().min(1).nullable(),
  len: z.number().int().nonnegative(),
  sha256: digestSchema,
  payload_hex: z.nullable(
    z
      .string()
      .max(4096)
      .regex(/^(?:[0-9a-f]{2})*$/u),
  ),
  raw: z.string().min(1),
});

/** One TXT key/value as the host's record spells it; key stays null untagged. */
const mdnsTxtEntry = z.strictObject({
  key: z.string().min(1).nullable(),
  value: z.string(),
});

/** One -L lookup row exactly as dns-sd emitted it. */
const mdnsLookupRecord = z.strictObject({
  service_name: z.string().min(1),
  target: z.string().min(1).nullable(),
  port: z.number().int().min(1).max(65535).nullable(),
  interface_index: z.string().min(1).nullable(),
  txt: z.array(mdnsTxtEntry),
  txt_raw: z.string().min(1).nullable(),
  raw: z.string().min(1),
});

/** One -G address row; family follows the record's rrtype. */
const mdnsAddressRow = z.strictObject({
  family: z.enum(["ipv4", "ipv6"]),
  address: z.string().min(1),
  interface_index: z.string().min(1).nullable(),
  hostname: z.string().min(1).nullable(),
  raw: z.string().min(1),
});

/** One Wi-Fi neighbor row; absent keys are absent facts, kept null. */
const wifiNetworkRow = z.strictObject({
  ts: z.number().int().nonnegative().nullable(),
  ssid: z.string().min(1).optional(),
  bssid: z.string().min(1).nullable(),
  rssi: z.number().min(-1000).max(200).nullable(),
  noise: z.number().min(-1000).max(200).nullable(),
  channel: z.number().int().min(1).max(2000).nullable(),
  band: z.enum(["2.4", "5", "6"]).nullable(),
  channel_width_mhz: z.number().int().min(1).max(4000).nullable(),
  phy_mode: z.string().min(1).nullable(),
  security: z.string().min(1).nullable(),
});

export const discoveryResultSchemas = {
  list_network_neighbors: z.strictObject({
    tools,
    hosts: z.array(neighbor),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  browse_lan_services: z.strictObject({
    tools,
    browse_seconds: z.number().int().positive(),
    per_type_seconds: z.number().int().positive(),
    types: z.array(serviceType),
    browsed_type_count: z.number().int().nonnegative(),
    window_exhausted: z.boolean(),
    elapsed_ms: z.number().int().nonnegative(),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  list_usb_devices: z.strictObject({
    tools,
    devices: z.array(usbDevice),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  list_bluetooth_devices: z.strictObject({
    tools,
    source: z.enum(["paired", "inquiry"]),
    paired: z.array(bluetoothDevice),
    inquiry: z.array(inquiryDevice).nullable(),
    inquiry_skipped: z.boolean(),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  scan_ble_advertisements: z.strictObject({
    tools,
    scan_seconds: z.number().int().positive(),
    address_filter: z.string().min(1).max(64).nullable(),
    scan_skipped: z.boolean(),
    skip_reason: z.string().min(1).nullable(),
    advertisements: z.array(bleAdvertisement),
    window_exhausted: z.boolean(),
    elapsed_ms: z.number().int().nonnegative(),
    exit_code: z.number().int().nullable(),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  connect_ble_gatt: z.strictObject({
    tools,
    session_id: z.string().uuid(),
    peripheral_id: z.string().min(1),
    name: z.string().min(1).nullable(),
    services: z.array(gattService),
    elapsed_ms: z.number().int().nonnegative(),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  read_gatt_characteristic: z.strictObject({
    tools,
    session_id: z.string().uuid(),
    peripheral_id: z.string().min(1),
    service_uuid: z.string().min(1),
    characteristic_uuid: z.string().min(1),
    len: z.number().int().nonnegative(),
    sha256: digestSchema,
    payload_hex: z.nullable(
      z
        .string()
        .max(4096)
        .regex(/^(?:[0-9a-f]{2})*$/u),
    ),
    elapsed_ms: z.number().int().nonnegative(),
    coverage: z.enum(["complete", "partial"]),
  }),
  write_gatt_characteristic: z.strictObject({
    tools,
    session_id: z.string().uuid(),
    peripheral_id: z.string().min(1),
    service_uuid: z.string().min(1),
    characteristic_uuid: z.string().min(1),
    bytes_written: z.number().int().nonnegative(),
    without_response: z.boolean(),
    elapsed_ms: z.number().int().nonnegative(),
    coverage: z.enum(["complete", "partial"]),
  }),
  observe_gatt_notifications: z.strictObject({
    tools,
    session_id: z.string().uuid(),
    peripheral_id: z.string().min(1),
    service_uuid: z.string().min(1),
    characteristic_uuid: z.string().min(1),
    observe_seconds: z.number().int().positive(),
    subscribed: z.boolean(),
    notifications: z.array(gattNotification),
    window_exhausted: z.boolean(),
    elapsed_ms: z.number().int().nonnegative(),
    stop_reason: z.enum(["deadline", "cancelled", "peer_disconnect", "error"]),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  close_ble_gatt: z.strictObject({
    tools,
    session_id: z.string().uuid(),
    peripheral_id: z.string().min(1),
    name: z.string().min(1).nullable(),
    clean: z.boolean(),
    detail: z.string().min(1).nullable(),
    elapsed_ms: z.number().int().nonnegative(),
    coverage: z.enum(["complete", "partial"]),
  }),
  probe_subnet_reachability: z.strictObject({
    tools,
    cidr: discoveryCidrSchema,
    tcp_ports: z.array(z.number().int().min(1).max(65535)),
    concurrency: z.number().int().positive(),
    per_host_timeout_ms: z.number().int().positive(),
    hosts: z.array(
      z.strictObject({
        ip: z.string().min(1),
        icmp_reachable: z.boolean().nullable(),
        icmp_latency_ms: z.number().nullable(),
        icmp_error: z.string().nullable(),
        tcp_open_ports: z.array(z.number().int().min(1).max(65535)),
      }),
    ),
    summary: z.strictObject({
      candidates: z.number().int().nonnegative(),
      reachable: z.number().int().nonnegative(),
      elapsed_ms: z.number().int().nonnegative(),
    }),
  }),
  capture_radio_packets: z.strictObject({
    tools,
    output_path: absoluteLocalPathStringSchema,
    file_bytes: z.number().int().nonnegative(),
    sha256: digestSchema,
    format: z.enum(["pcap", "pcapng", "unknown"]),
    magic_hex: z.string().min(1),
    capture_started_at: z.string().min(1),
    duration_seconds: z.number().int().min(1),
    command_stderr_tail: z.string(),
  }),
  resolve_mdns_records: z.strictObject({
    tools,
    instance: z.string().min(1),
    service_type: z.string().min(1),
    domain: z.string().min(1),
    interface_index: z.string().min(1).nullable(),
    srv: z.strictObject({
      target: z.string().min(1).nullable(),
      port: z.number().int().min(1).max(65535).nullable(),
    }),
    txt: z.array(mdnsTxtEntry),
    raw_txt: z.string().min(1).nullable(),
    addresses: z.array(mdnsAddressRow),
    lookup_rows: z.array(mdnsLookupRecord),
    zone_ran: z.boolean(),
    addresses_ran: z.boolean(),
    lookup_timed_out: z.boolean().nullable(),
    elapsed_ms: z.number().int().nonnegative(),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  inspect_network_interfaces: z.strictObject({
    tools,
    interfaces: z.array(
      z.strictObject({
        name: z.string().min(1),
        status: z.string().min(1).nullable(),
        flags: z.string().min(1).nullable(),
        mac: z.string().min(1).nullable(),
        ipv4: z.array(z.string().min(1)),
        ipv6: z.array(z.string().min(1)),
        awdl_role: z.string().min(1).nullable(),
      }),
    ),
    interface_indexes: z.record(z.string(), z.string()),
    peers: z
      .array(
        z.strictObject({
          peer: z.string().min(1),
          mac: z.string().min(1).nullable(),
          interface: z.string().min(1),
        }),
      )
      .nullable(),
    elapsed_ms: z.number().int().nonnegative(),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  scan_wifi_networks: z.strictObject({
    tools,
    source: z.enum(["scanner", "system_profiler"]),
    include_ssid: z.boolean(),
    scan_seconds: z.number().int().nonnegative(),
    networks: z.array(wifiNetworkRow),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  list_serial_ports: z.strictObject({
    tools,
    ports: z.array(
      z.strictObject({
        device_path: z.string().min(1).nullable(),
        name: z.string().min(1).nullable(),
        interface_type: z.string().min(1).nullable(),
        description: z.string().min(1).nullable(),
        in_use: z.boolean().nullable(),
      }),
    ),
    unmatched_port_names: z.array(z.string().min(1)),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  observe_serial_port: z.strictObject({
    tools,
    device_path: z.string().min(1),
    baud_rate: z.number().int(),
    duration_seconds: z.number().int().positive(),
    bytes_observed: z.number().int().nonnegative(),
    hex_preview: z.string().min(1).nullable(),
    printable_preview: z.string().min(1).nullable(),
    stop_reason: z.enum([
      "deadline",
      "closed",
      "read_error",
      "byte_bound",
      "cancelled",
    ]),
    stop_detail: z.string().min(1).nullable(),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
} as const;
