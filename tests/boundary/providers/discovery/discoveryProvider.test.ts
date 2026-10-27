import { expect, test } from "vitest";

import { DiscoveryProvider } from "../../../../src/discovery/DiscoveryProvider.js";
import { inspectDiscoveryProvider } from "../../../../src/discovery/DiscoveryDoctor.js";
import type { FileCloseResourceOwner } from "../../../../src/application/AnalysisProvider.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  writeFakeDiscovery,
  type FakeDiscoveryBehavior,
} from "./fakeDiscovery.js";

const doctorOptions = {
  fileCloseResources: {
    retain: () => undefined,
    run: (op: () => unknown) => op(),
  } as unknown as FileCloseResourceOwner,
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
