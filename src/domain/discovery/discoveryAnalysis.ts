import { z } from "zod";

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
  blueutil: z.string().min(1).nullable(),
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
} as const;
