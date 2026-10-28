import { expect, test } from "vitest";

import { DiscoveryProvider } from "../../../../src/discovery/DiscoveryProvider.js";
import { inspectDiscoveryProvider } from "../../../../src/discovery/DiscoveryDoctor.js";
import type { RetainedResourceScope } from "../../../../src/application/AnalysisProvider.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  writeFakeDiscovery,
  type FakeDiscoveryBehavior,
} from "./fakeDiscovery.js";

const doctorOptions = {
  resourceScope: {
    retain: () => undefined,
    run: (op: () => unknown) => op(),
  } as unknown as RetainedResourceScope,
};

const providerFor = async (
  behavior: FakeDiscoveryBehavior,
  options: { readonly withBlueutil?: boolean } = {},
): Promise<{
  provider: DiscoveryProvider;
  tools: Awaited<ReturnType<typeof writeFakeDiscovery>>;
  root: string;
}> => {
  const root = await createTestTempDirectory("rea-discovery-");
  const tools = await writeFakeDiscovery(
    root,
    options.withBlueutil === true
      ? { ...behavior, inquiryRaw: behavior.inquiryRaw ?? "" }
      : behavior,
  );
  return {
    provider: new DiscoveryProvider({ environment: tools.environment }),
    tools,
    root,
  };
};

const resultOf = async (
  provider: DiscoveryProvider,
  request: Parameters<DiscoveryProvider["execute"]>[0],
): Promise<Record<string, unknown>> => {
  const result = await provider.execute(request);
  if (!result.ok) throw new Error(result.error.message);
  return result.value.result as Record<string, unknown>;
};

test("doctor reports resolved host tools and the optional blueutil posture", async () => {
  const { tools } = await providerFor({});
  const inspection = await inspectDiscoveryProvider(
    tools.environment as unknown as NodeJS.ProcessEnv,
    process.platform,
    doctorOptions,
  );
  expect(inspection.id).toBe("discovery");
  expect(inspection.available).toBe(true);
  expect(inspection.providerVersion).toBeNull();
  expect(inspection.checks[0]?.detail).toContain("blueutil not configured");
  expect(inspection.registrationEnvironment).toEqual(tools.environment);
});

test("neighbor tables merge arp and ndp rows and preserve unparsed rows", async () => {
  const { provider } = await providerFor({
    arp: [
      "? (192.168.1.1) at a4:83:e7:12:34:56 on en0 ifscope [ethernet]",
      "? (10.0.0.5) at (incomplete) on en0 ifscope [ethernet]",
    ].join("\n"),
    ndp: [
      "Neighbor                             Linklayer Address  Netif Expire    S Flags",
      "fe80::1%en0                          04:5c:6c:aa:bb:cc  en0   23s       R",
      "unstructured ndp noise",
    ].join("\n"),
  });
  const result = (await resultOf(provider, {
    operation: "list_network_neighbors",
    input: {},
  })) as {
    hosts: {
      family: string;
      ip: string;
      mac: string | null;
      permanent: boolean | null;
    }[];
    unparsed_lines: string[];
    coverage: string;
  };
  expect(result.hosts.map((row) => row.ip)).toEqual([
    "192.168.1.1",
    "10.0.0.5",
    "fe80::1",
  ]);
  expect(result.hosts[0]?.mac).toBe("a4:83:e7:12:34:56");
  expect(result.hosts[1]?.mac).toBeNull();
  expect(result.hosts[2]?.family).toBe("ipv6");
  expect(result.unparsed_lines).toEqual(["unstructured ndp noise"]);
  expect(result.coverage).toBe("partial");
});

test("empty neighbor tables are an observation, not an error", async () => {
  const { provider } = await providerFor({ arp: "", ndp: "" });
  const result = (await resultOf(provider, {
    operation: "list_network_neighbors",
    input: {},
  })) as { hosts: unknown[]; coverage: string };
  expect(result.hosts).toEqual([]);
  expect(result.coverage).toBe("complete");
});

test("the USB tree flattens nested hubs into device rows", async () => {
  const { provider } = await providerFor({
    usbRaw: JSON.stringify({
      SPUSBDataType: [
        {
          _name: "USB31Bus",
          items: [
            {
              _name: "USB 10/100/1000 LAN",
              vendor_id: "usbvid_0b95",
              product_id: "usbpid_1790",
              serial_num: "000000001",
            },
          ],
        },
      ],
    }),
  });
  const result = (await resultOf(provider, {
    operation: "list_usb_devices",
    input: {},
  })) as { devices: { name: string | null; vendor_id: string | null }[] };
  expect(result.devices).toHaveLength(2);
  expect(result.devices[1]).toMatchObject({
    name: "USB 10/100/1000 LAN",
    vendor_id: "usbvid_0b95",
  });
});

test("the paired Bluetooth inventory reads without blueutil", async () => {
  const { provider } = await providerFor({
    bluetoothRaw: JSON.stringify({
      SPBluetoothDataType: [
        {
          _name: "BluetoothInformation",
          paired_devices: [
            {
              device_address: "04-5C-6C-11-22-33",
              device_connected: "attributeBool|Yes",
              _name: "Studio Buds",
            },
          ],
        },
      ],
    }),
  });
  const result = (await resultOf(provider, {
    operation: "list_bluetooth_devices",
    input: { source: "paired", inquiry_seconds: 10 },
  })) as {
    paired: { name: string | null; connected: boolean | null }[];
    inquiry: string[];
    inquiry_skipped: boolean;
  };
  expect(result.paired).toHaveLength(1);
  expect(result.paired[0]).toMatchObject({
    name: "Studio Buds",
    connected: true,
  });
  expect(result.inquiry).toBeNull();
  expect(result.inquiry_skipped).toBe(false);
});

test("an inquiry without configured blueutil is reported as skipped, not failed", async () => {
  const { provider } = await providerFor({});
  const result = (await resultOf(provider, {
    operation: "list_bluetooth_devices",
    input: { source: "inquiry", inquiry_seconds: 2 },
  })) as {
    inquiry: unknown;
    inquiry_skipped: boolean;
  };
  expect(result.inquiry).toBeNull();
  expect(result.inquiry_skipped).toBe(true);
});

test("a configured blueutil runs the inquiry window over the fake tool", async () => {
  const { provider, tools } = await providerFor(
    {
      bluetoothRaw: "{}",
      inquiryRaw: [
        "address: 8C-1D-96-AA-BB-CC name: 'TV Remote' not connected",
        "unstructured inquiry noise",
      ].join("\n"),
    },
    { withBlueutil: true },
  );
  const result = (await resultOf(provider, {
    operation: "list_bluetooth_devices",
    input: { source: "inquiry", inquiry_seconds: 2 },
  })) as {
    tools: { blueutil: string | null };
    inquiry: { address: string | null; name: string | null }[];
    unparsed_lines: string[];
    inquiry_skipped: boolean;
  };
  expect(result.tools.blueutil).toBe(tools.paths.blueutil);
  expect(result.inquiry_skipped).toBe(false);
  expect(result.inquiry[0]).toMatchObject({
    address: "8c-1d-96-aa-bb-cc",
    name: "TV Remote",
  });
  expect(result.unparsed_lines).toEqual(["unstructured inquiry noise"]);
});

test("a BLE scan without a configured scanner reports skipped, not failed", async () => {
  const { provider } = await providerFor({});
  const result = (await resultOf(provider, {
    operation: "scan_ble_advertisements",
    input: { scan_seconds: 2 },
  })) as {
    tools: { ble_scanner: string | null };
    scan_skipped: boolean;
    skip_reason: string | null;
    advertisements: unknown[];
  };
  expect(result.tools.ble_scanner).toBeNull();
  expect(result.scan_skipped).toBe(true);
  expect(result.skip_reason).toContain("REA_BLE_SCANNER_PATH");
  expect(result.advertisements).toEqual([]);
});

test("a configured BLE scanner runs the observation window over the fake tool", async () => {
  const { provider, tools } = await providerFor({
    bleRaw: [
      '{"event":"discovered","ts":"2026-10-27T12:00:00.000Z","address_or_uuid":"D2FC1D34-9BA1-4B0D-A6BE-C7E4F1C8A211","name":"Tile Mate","rssi":-62,"connectable":true,"manufacturer_hex":"4c0002151234","service_uuids":["180F"]}',
      "unstructured ble scan noise",
    ].join("\n"),
  });
  const result = (await resultOf(provider, {
    operation: "scan_ble_advertisements",
    input: { scan_seconds: 2 },
  })) as {
    tools: { ble_scanner: string | null };
    scan_skipped: boolean;
    advertisements: { address_or_uuid: string | null; rssi: number | null }[];
    unparsed_lines: string[];
  };
  expect(result.tools.ble_scanner).toBe(tools.paths.ble_scan);
  expect(result.scan_skipped).toBe(false);
  expect(result.advertisements).toHaveLength(1);
  expect(result.advertisements[0]).toMatchObject({
    address_or_uuid: "D2FC1D34-9BA1-4B0D-A6BE-C7E4F1C8A211",
    rssi: -62,
  });
  expect(result.unparsed_lines).toEqual(["unstructured ble scan noise"]);
});

test("packet capture without a configured command is refused with remediation", async () => {
  const { provider } = await providerFor({});
  const refusal = await provider.execute({
    operation: "capture_radio_packets",
    input: {
      output_path: "/tmp/rea-test-capture.pcap",
      duration_seconds: 1,
      authorize_capture: true,
    },
  } as unknown as Parameters<DiscoveryProvider["execute"]>[0]);
  expect(refusal.ok).toBe(false);
  if (refusal.ok) throw new Error("expected a configuration refusal");
  const projected = projectAnalysisError(refusal.error);
  expect(JSON.stringify(projected)).toContain("REA_PACKET_CAPTURE_COMMAND");
});

test("a configured capture program writes and the file magic validates", async () => {
  const { provider, tools } = await providerFor({
    captureHex: "d4c3b2a1020403000000000000000000ffff000001000000",
  });
  const result = (await resultOf(provider, {
    operation: "capture_radio_packets",
    input: {
      output_path: "/tmp/rea-test-capture.pcap",
      duration_seconds: 1,
      authorize_capture: true,
    },
  })) as {
    tools: { packet_capture: string | null };
    format: string;
    file_bytes: number;
    duration_seconds: number;
  };
  expect(result.tools.packet_capture).toBe(tools.paths.packet_capture);
  expect(result.format).toBe("pcap");
  expect(result.file_bytes).toBe(12);
  expect(result.duration_seconds).toBe(1);
});

test("the capture refuses without the explicit authorization", async () => {
  const { provider } = await providerFor({ captureHex: "d4c3b2a1" });
  const refusal = await provider.execute({
    operation: "capture_radio_packets",
    input: {
      output_path: "/tmp/rea-test-capture.pcap",
      duration_seconds: 1,
      authorize_capture: false,
    },
  } as unknown as Parameters<DiscoveryProvider["execute"]>[0]);
  expect(refusal.ok).toBe(false);
  if (refusal.ok) throw new Error("expected an authorization refusal");
  const projected = projectAnalysisError(refusal.error);
  expect(JSON.stringify(projected)).toContain("authorize_capture");
});

test("interfaces read from ifconfig with the ifIndex mapping and AWDL peers", async () => {
  const { provider } = await providerFor({
    ifconfigRaw: [
      "lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384 index 1",
      "\tenet 0:0:0:0:0:0",
      "en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500 index 11",
      "\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255",
      "\tether 04:5c:6c:aa:bb:cc",
      "awdl0: flags=8843<UP,BROADCAST,SMART,RUNNING> mtu 1484 index 13",
      "\tether 02:26:7e:d7:e1:cf",
      "\ttype: AWDL",
    ].join("\n"),
    ndp: [
      "Neighbor                             Linklayer Address  Netif Expire    S Flags",
      "fe80::26:7eff:fed7:e1cf%awdl0       2:26:7e:d7:e1:cf   awdl0 permanent  R",
      "fe80::1%lo0                          lo0                lo0   permanent  R",
    ].join("\n"),
  });
  const result = (await resultOf(provider, {
    operation: "inspect_network_interfaces",
    input: { include_neighbors: true },
  })) as {
    tools: { ifconfig: string };
    interfaces: { name: string; mac: string | null; ipv4: string[] }[];
    interface_indexes: Record<string, string>;
    peers: { peer: string; mac: string | null; interface: string }[] | null;
  };
  expect(result.interfaces.map((row) => row.name)).toEqual([
    "lo0",
    "en0",
    "awdl0",
  ]);
  expect(result.interfaces[1]).toMatchObject({
    mac: "04:5c:6c:aa:bb:cc",
    ipv4: ["192.168.1.20"],
  });
  expect(result.interface_indexes).toEqual({
    "1": "lo0",
    "11": "en0",
    "13": "awdl0",
  });
  expect(result.peers).toEqual([]);
});

test("mDNS resolution follows -L, -Z and -G windows over the fake dns-sd", async () => {
  const { provider } = await providerFor({
    resolveRaw: [
      "Lookup rea-test._http._tcp.local.",
      " 0:00:00.100  rea-test._http._tcp.local. can be reached at rea-host.local.:8099 (interface 11)",
    ].join("\n"),
    zoneRaw: [
      "Browsing for rea-test._http._tcp.local.",
      "rea-test._http._tcp.local. 120 IN SRV 0 0 8099 rea-host.local.",
    ].join("\n"),
    addressRaw: [" 0:00:00.300  Add  11  4  192.168.1.20 rea-host.local."].join(
      "\n",
    ),
  });
  const result = (await resultOf(provider, {
    operation: "resolve_mdns_records",
    input: {
      instance: "rea-test",
      service_type: "_http._tcp.",
      domain: "local.",
      resolve_seconds: 2,
      include_addresses: true,
    },
  })) as {
    tools: { dns_sd: string };
    srv: { target: string | null; port: number | null };
    addresses: { address: string }[];
    zone_ran: boolean;
    addresses_ran: boolean;
  };
  expect(result.tools.dns_sd).toBeTruthy();
  expect(result.zone_ran).toBe(true);
  expect(result.addresses_ran).toBe(true);
  expect(result.addresses).toEqual([{ address: "192.168.1.20" }]);
});

test("the Wi-Fi lane uses the configured helper and keeps RF rows", async () => {
  const { provider, tools } = await providerFor({
    wifiRaw: [
      '{"ts":1,"bssid":null,"rssi":-67,"noise":0,"channel":1,"band":"2.4","channel_width_mhz":20,"phy_mode":null,"security":null}',
    ].join("\n"),
  });
  const result = (await resultOf(provider, {
    operation: "scan_wifi_networks",
    input: { scan_seconds: 4, include_ssid: false },
  })) as {
    tools: { wifi_scanner: string | null; system_profiler: string | null };
    source: string;
    networks: {
      bssid: string | null;
      rssi: number | null;
      channel: number | null;
    }[];
  };
  expect(result.tools.wifi_scanner).toBe(tools.paths.wifi_scan);
  expect(result.source).toBe("scanner");
  expect(result.networks).toEqual([
    {
      ts: 1,
      bssid: null,
      rssi: -67,
      noise: 0,
      channel: 1,
      band: "2.4",
      channel_width_mhz: 20,
      phy_mode: null,
      security: null,
    },
  ]);
});

test("the Wi-Fi lane falls back to system_profiler's airport cache without a helper", async () => {
  const { provider, tools } = await providerFor({
    wifiProfilerRaw: JSON.stringify({
      SPAirPortDataType: [
        {
          _name: "Wi-Fi Information",
          spairport_airport_other_local_wireless_networks: [
            {
              _name: "Neighbor Net",
              spairport_network_channel: "52 (5GHz, 80MHz)",
              spairport_network_phymode: "802.11ac",
              spairport_security_mode: "unknown",
            },
          ],
        },
      ],
    }),
  });
  const result = (await resultOf(provider, {
    operation: "scan_wifi_networks",
    input: { include_ssid: false, scan_seconds: 10 },
  })) as {
    tools: { wifi_scanner: string | null };
    source: string;
    networks: {
      ssid?: string;
      channel: number | null;
      band: string | null;
      phy_mode: string | null;
    }[];
  };
  expect(result.tools.wifi_scanner).toBeNull();
  expect(result.source).toBe("system_profiler");
  expect(result.networks[0]).toEqual({
    channel: 52,
    band: "5",
    channel_width_mhz: 80,
    phy_mode: "802.11ac",
    security: "unknown",
  });
  expect(result.networks[0]).not.toHaveProperty("ssid");
  void tools;
});

test("serial ports list joins SPPortsDataType rows with device nodes", async () => {
  const { provider } = await providerFor({
    serialPortsRaw: JSON.stringify({
      SPPortsDataType: [
        {
          _name: "/dev/cu.usbserial-0001",
          product: "USB-serial controller",
          interface_type: "USB",
        },
      ],
    }),
  });
  const result = (await resultOf(provider, {
    operation: "list_serial_ports",
    input: {},
  })) as {
    ports: {
      device_path: string | null;
      name: string | null;
      in_use: boolean | null;
    }[];
    unmatched_port_names: string[];
  };
  const joined = result.ports.find(
    (row) => row.name === "/dev/cu.usbserial-0001",
  );
  expect(joined).toBeTruthy();
  expect(joined?.in_use).toBeNull();
  expect(Array.isArray(result.ports)).toBe(true);
});

test("a serial observe window reports its stop reason and never writes", async () => {
  const { provider } = await providerFor({});
  const result = (await resultOf(provider, {
    operation: "observe_serial_port",
    input: {
      device_path: "/dev/cu.Bluetooth-Incoming-Port",
      duration_seconds: 1,
      baud_rate: 9600,
    },
  })) as {
    device_path: string;
    bytes_observed: number;
    stop_reason: string;
  };
  expect(result.device_path).toBe("/dev/cu.Bluetooth-Incoming-Port");
  expect(result.bytes_observed).toBe(0);
  expect(["deadline", "closed", "read_error"]).toContain(result.stop_reason);
});

test("the bounded browse emits multicast queries and collects instances", async () => {
  const { provider, tools } = await providerFor({
    browseMeta: [
      " 5:31:00.000  Add  2  5  local.  _ipp._tcp.",
      " 5:31:00.100  Add  2  5  local.  _sftp-ssh._tcp.",
    ].join("\n"),
    browseType: [
      "Browsing for _ipp._tcp.local.",
      " 5:31:03.000  Add  2  5  local.  _ipp._tcp.local.  Office Printer",
    ].join("\n"),
  });
  const result = (await resultOf(provider, {
    operation: "browse_lan_services",
    input: { browse_seconds: 1, per_type_seconds: 1, max_types: 4 },
  })) as {
    types: {
      service_type: string;
      instances: { instance: string }[];
    }[];
    browsed_type_count: number;
    window_exhausted: boolean;
  };
  expect(result.browsed_type_count).toBe(2);
  expect(result.window_exhausted).toBe(false);
  const browsed = result.types.find(
    (type) => type.service_type === "_ipp._tcp.",
  );
  expect(browsed?.instances.map((row) => row.instance)).toEqual([
    "Office Printer",
  ]);
  const dnsSdCalls = (await tools.calls()).filter(
    (call) => call.role === "dns_sd",
  );
  expect(dnsSdCalls.length).toBe(3);
  expect(dnsSdCalls[0]?.argv).toEqual([
    "-B",
    "_services._dns-sd._udp",
    "local.",
  ]);
});

test("the authorized sweep probes each candidate once and preserves non-responses", async () => {
  const { provider, tools } = await providerFor({
    pingReplies: [{ ok: true, latencyMs: 1.5 }, { ok: false }],
  });
  const result = (await resultOf(provider, {
    operation: "probe_subnet_reachability",
    input: {
      cidr: "192.0.2.0/30",
      authorize_probe: true,
      concurrency: 2,
      per_host_timeout_ms: 200,
      tcp_ports: [],
    },
  })) as {
    hosts: {
      ip: string;
      icmp_reachable: boolean | null;
      icmp_latency_ms: number | null;
    }[];
    summary: { candidates: number; reachable: number };
  };
  expect(result.summary.candidates).toBe(2);
  expect(result.summary.reachable).toBe(1);
  const reachableRow = result.hosts.find(
    (row) => row.icmp_reachable === true,
  ) as
    | {
        ip: string;
        icmp_reachable: boolean | null;
        icmp_latency_ms: number | null;
        icmp_error: string | null;
      }
    | undefined;
  const silentRow = result.hosts.find((row) => row.icmp_reachable === false) as
    | {
        ip: string;
        icmp_reachable: boolean | null;
        icmp_latency_ms: number | null;
        icmp_error: string | null;
      }
    | undefined;
  expect(reachableRow?.icmp_latency_ms).toBe(1.5);
  expect(reachableRow?.icmp_error).toBeNull();
  expect(silentRow?.icmp_latency_ms).toBeNull();
  expect(silentRow?.icmp_error).toBeTruthy();
  const pingCalls = (await tools.calls()).filter(
    (call) => call.role === "ping",
  );
  expect(pingCalls).toHaveLength(2);
  expect(pingCalls[0]?.argv.slice(0, 6)).toEqual([
    "-c",
    "1",
    "-W",
    "200",
    "-t",
    "2",
  ]);
});

test("the sweep refuses without the explicit probe authorization", async () => {
  const { provider } = await providerFor({});
  const refusal = await provider.execute({
    operation: "probe_subnet_reachability",
    input: {
      cidr: "192.0.2.0/30",
      authorize_probe: false,
    },
  } as unknown as Parameters<DiscoveryProvider["execute"]>[0]);
  expect(refusal.ok).toBe(false);
  if (refusal.ok) throw new Error("expected an authorization refusal");
  const projected = projectAnalysisError(refusal.error);
  expect(JSON.stringify(projected)).toContain("authorize_probe");
});

test("an out-of-bound CIDR prefix is refused at admission", async () => {
  const { provider } = await providerFor({});
  const refusal = await provider.execute({
    operation: "probe_subnet_reachability",
    input: {
      cidr: "192.0.2.0/16" as never,
      authorize_probe: true,
      concurrency: 16,
      per_host_timeout_ms: 1000,
      tcp_ports: [],
    },
  });
  expect(refusal.ok).toBe(false);
  if (refusal.ok) throw new Error("expected a bound refusal");
});
