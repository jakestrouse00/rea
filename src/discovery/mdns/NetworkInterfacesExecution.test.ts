import { expect, test } from "vitest";

import {
  networkInterfacesInputSchema,
  type NetworkInterfacesResult,
} from "./NetworkInterfacesAnalysis.js";
import {
  executeInspectNetworkInterfaces,
  parseAwdlNeighbors,
  parseIfconfigOutput,
  parseInterfaceIndexes,
} from "./NetworkInterfacesExecution.js";
import type { DiscoveryProcessLauncher } from "../DiscoveryCommand.js";

const IFCONFIG_FIXTURE = [
  "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384 index 1",
  "\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>",
  "\tinet 127.0.0.1 netmask 0xff000000",
  "\tinet6 ::1 prefixlen 128 ",
  "\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 ",
  "\tnd6 options=201<PERFORMNUD,DAD>",
  "\tgeneration id: 1",
  "\tlink quality: 100 (good)",
  "\tqosmarking enabled: no mode: none",
  "\tlow power mode: disabled",
  "\troutermode4: disabled",
  "\troutermode6: disabled",
  "bridge0: flags=8863<UP,BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500 index 3",
  "stale0: flags=0<> mtu 1500 index 5",
  "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500 index 11",
  "\teflags=4000000<INBAND_WAKE_PKT>",
  "\tether 32:5d:6c:73:91:4c",
  "\tinet6 fe80::32:5d6c:7373:914c%en0 prefixlen 64 scopeid 0xb ",
  "\tinet 192.0.2.99 netmask 0xffffff00 broadcast 192.0.2.255",
  "\tmedia: autoselect",
  "\tstatus: active",
  "awdl0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500 index 13",
  "\teflags=443e0080<TXSTART,LOCALNET_PRIVATE,ND6ALT,RESTRICTED_RECV,AWDL,NOACKPRI,CHANNEL_DRV,FASTLN_ON>",
  "\tether 02:26:7e:d7:e1:cf",
  "\tinet6 fe80::26:7eff:fed7:e1cf%awdl0 prefixlen 64 scopeid 0xd ",
  "\tnetif: 2C6E1905-02F0-4B5A-A813-8741E5E6969F",
  "\tflowswitch: DB8B16E7-023A-4C35-8D48-58D6275FF5FF",
  "\tmedia: autoselect",
  "\tstatus: active",
  "\ttype: Wi-Fi",
  '\tagent domain:com.apple.wifip2pd type:AWDL flags:0x203 desc:"com.apple.wifip2pd AWDL"',
  "\tawdl-role: peer-to-peer",
  "llw0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500 index 14",
  "\teflags=443e0080<TXSTART,LOCALNET_PRIVATE,ND6ALT,RESTRICTED_RECV,AWDL,NOACKPRI,CHANNEL_DRV,FASTLN_ON>",
  "\tether 02:26:7e:d7:e1:cf",
  "\tstatus: active",
].join("\n");

const NDP_FIXTURE = [
  "Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs",
  "2600:0db8:500:420::a114                 e:c2:3b:9f:61:cc     en0 23h48m18s S      ",
  "fe80::1f6:7585:3a32:d475%awdl0          11:22:33:44:55:66  awdl0 3s       R  R   ",
  "fe80::26:7eff:fed7:e1cf%awdl0           2:26:7e:d7:e1:cf   awdl0 permanent R      ",
  "fe80::26:7eff:fed7:e1cf%llw0            2:26:7e:d7:e1:cf    llw0 permanent R      ",
  "fe80::1%lo0                             (incomplete)         lo0 permanent R      ",
  "2600:0db8:500:420::dad6                 32:5d:6c:73:91:4c    en0 permanent R      ",
  "short-row",
].join("\n");

test("input schema default keeps neighbors on", () => {
  expect(networkInterfacesInputSchema.parse({}).include_neighbors).toBe(true);
  expect(networkInterfacesInputSchema.safeParse({ other: true }).success).toBe(
    false,
  );
});

test("parseIfconfigOutput extracts interface blocks and preserves unmatched attributes", () => {
  const parsed = parseIfconfigOutput(IFCONFIG_FIXTURE);
  const byName = new Map(parsed.items.map((row) => [row.name, row]));
  expect(parsed.items).toHaveLength(6);
  expect(byName.get("lo0")).toMatchObject({
    flags: "UP,LOOPBACK,RUNNING,MULTICAST",
    status: null,
    mac: null,
    ipv4: ["127.0.0.1"],
    ipv6: ["::1", "fe80::1%lo0"],
    awdl_role: null,
  });
  expect(byName.get("stale0")).toMatchObject({ flags: null });
  expect(byName.get("en0")).toMatchObject({
    flags: "UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST",
    status: "active",
    mac: "32:5d:6c:73:91:4c",
    ipv4: ["192.0.2.99"],
    ipv6: ["fe80::32:5d6c:7373:914c%en0"],
  });
  expect(byName.get("awdl0")).toMatchObject({
    mac: "02:26:7e:d7:e1:cf",
    awdl_role: "peer-to-peer",
    ipv6: ["fe80::26:7eff:fed7:e1cf%awdl0"],
  });
  expect(parsed.unparsedLines.some((line) => line.includes("eflags="))).toBe(
    true,
  );
  expect(
    parsed.unparsedLines.some((line) => line.includes("agent domain:")),
  ).toBe(true);
});

test("parseInterfaceIndexes maps the -v header index column", () => {
  const parsed = parseInterfaceIndexes(IFCONFIG_FIXTURE);
  expect(
    Object.fromEntries(parsed.items.map((row) => [row.index, row.name])),
  ).toEqual({
    "1": "lo0",
    "3": "bridge0",
    "5": "stale0",
    "11": "en0",
    "13": "awdl0",
    "14": "llw0",
  });
  const withoutIndex = parseInterfaceIndexes(
    "utun9: flags=8051<UP,RUNNING> mtu 1380\n",
  );
  expect(withoutIndex.items).toEqual([]);
  expect(withoutIndex.unparsedLines).toEqual([
    "utun9: flags=8051<UP,RUNNING> mtu 1380",
  ]);
});

test("parseAwdlNeighbors keeps awdl0/llw0 rows and drops the host's own entry", () => {
  const parsed = parseAwdlNeighbors(NDP_FIXTURE, ["02:26:7e:d7:e1:cf"]);
  expect(parsed.items).toEqual([
    {
      peer: "fe80::1f6:7585:3a32:d475",
      mac: "11:22:33:44:55:66",
      interface: "awdl0",
    },
  ]);
  expect(parsed.unparsedLines).toEqual(["short-row"]);
});

test("parseAwdlNeighbors keeps every AWDL-interface row without a self hint", () => {
  const parsed = parseAwdlNeighbors(NDP_FIXTURE);
  expect(parsed.items).toHaveLength(3);
  expect(
    parsed.items.every((row) => ["awdl0", "llw0"].includes(row.interface)),
  ).toBe(true);
  expect(parsed.items[0]).toMatchObject({ mac: "11:22:33:44:55:66" });
});

const asLauncher = (
  responder: (executable: string, argv: readonly string[]) => string,
): {
  launcher: DiscoveryProcessLauncher;
  calls: [string, readonly string[]][];
} => {
  const calls: [string, readonly string[]][] = [];
  return {
    calls,
    launcher: async (request) => {
      calls.push([request.executable, request.arguments]);
      return {
        stdout: responder(request.executable, request.arguments),
        stderr: "",
      };
    },
  };
};

test("execution reads ifconfig -a -v and filters ND rows into AWDL peers", async () => {
  const { launcher, calls } = asLauncher((executable) =>
    executable.endsWith("ndp") ? NDP_FIXTURE : IFCONFIG_FIXTURE,
  );
  const run = await executeInspectNetworkInterfaces(
    "/sbin/ifconfig",
    "/usr/sbin/ndp",
    networkInterfacesInputSchema.parse({}),
    undefined,
    launcher,
  );
  expect(run.ok).toBe(true);
  if (!run.ok) throw new Error(run.error.message);
  const result = run.value as NetworkInterfacesResult;
  expect(calls.map(([executable, argv]) => [executable, ...argv])).toEqual([
    ["/sbin/ifconfig", "-a", "-v"],
    ["/usr/sbin/ndp", "-a", "-n"],
  ]);
  expect(result.interfaces).toHaveLength(6);
  expect(result.interface_indexes).toEqual({
    "1": "lo0",
    "3": "bridge0",
    "5": "stale0",
    "11": "en0",
    "13": "awdl0",
    "14": "llw0",
  });
  expect(result.peers).toEqual([
    {
      peer: "fe80::1f6:7585:3a32:d475",
      mac: "11:22:33:44:55:66",
      interface: "awdl0",
    },
  ]);
  expect(result.coverage).toBe("partial");
});

test("execution with include_neighbors false skips ndp and reports peers null", async () => {
  const { launcher, calls } = asLauncher(() => IFCONFIG_FIXTURE);
  const run = await executeInspectNetworkInterfaces(
    "/sbin/ifconfig",
    "/usr/sbin/ndp",
    networkInterfacesInputSchema.parse({ include_neighbors: false }),
    undefined,
    launcher,
  );
  if (!run.ok) throw new Error(run.error.message);
  const result = run.value as NetworkInterfacesResult;
  expect(calls).toHaveLength(1);
  expect(result.peers).toBeNull();
});

test("execution surfaces an ifconfig tool failure", async () => {
  const { launcher } = asLauncher(() => {
    throw new Error("ifconfig did not start");
  });
  const run = await executeInspectNetworkInterfaces(
    "/sbin/ifconfig",
    "/usr/sbin/ndp",
    networkInterfacesInputSchema.parse({}),
    undefined,
    launcher,
  );
  expect(run.ok).toBe(false);
});
