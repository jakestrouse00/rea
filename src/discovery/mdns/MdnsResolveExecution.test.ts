import { expect, test } from "vitest";

import {
  mdnsResolveInputSchema,
  type MdnsResolveResult,
} from "./MdnsResolveAnalysis.js";
import {
  executeMdnsResolve,
  parseGetAddress,
  parseResolveLine,
  parseTxtTokens,
  parseZoneOutput,
} from "./MdnsResolveExecution.js";
import type { DiscoveryProcessLauncher } from "../DiscoveryCommand.js";

export const LOOKUP_FIXTURE = [
  "Lookup rea-test._http._tcp.local.",
  "DATE: ---Tue 27 Oct 2026---",
  "23:49:00.304  ...STARTING...",
  "23:49:00.304  rea-test._http._tcp.local. can be reached at host-a.local.:8099 (interface 11) Flags: 1",
  " path=/index.txt note=hello-rea",
  "23:49:00.304  rea-test._http._tcp.local. can be reached at host-a.local.:8099 (interface 11)",
  " path=/index.txt note=hello-rea",
].join("\n");

export const ZONE_FIXTURE = [
  "Browsing for _http._tcp.local.",
  "DATE: ---Tue 27 Oct 2026---",
  "23:49:03.308  ...STARTING...",
  "",
  "; To direct clients to browse a different domain, substitute that domain in place of '@'",
  "lb._dns-sd._udp                                 PTR     @",
  "",
  "; In the list of services below, the SRV records will typically reference dot-local Multicast DNS names.",
  "When transferring this zone file data to your unicast DNS server, you'll need to replace those dot-local",
  "",
  "_http._tcp                                      PTR     OtherDevice._http._tcp",
  "OtherDevice._http._tcp                          SRV     0 0 21 localhost.local. ; Replace with unicast FQDN of target host",
  'OtherDevice._http._tcp                          TXT     ""',
  "",
  "_http._tcp                                      PTR     rea-test._http._tcp",
  "rea-test._http._tcp                             SRV     0 0 8099 host-a.local. ; Replace with unicast FQDN of target host",
  'rea-test._http._tcp                             TXT     "path=/index.txt" "note=hello-rea"',
  "",
].join("\n");

export const ADDRESS_FIXTURE = [
  "DATE: ---Tue 27 Oct 2026---",
  "23:49:06.318  ...STARTING...",
  "Timestamp     A/R  Flags         IF  Hostname                               Address                                      TTL",
  "23:49:06.319  Add  40000003       1  host-a.local.                  0000:0000:0000:0000:0000:0000:0000:0001%<0>  4500",
  "23:49:06.319  Add  40000003       1  host-a.local.                  FE80:0000:0000:0000:0000:0000:0000:0001%lo0  4500",
  "23:49:06.320  Add  40000003      11  host-a.local.                  2001:0DB8:0500:0420:180B:AC2D:9877:643B%<0>  4500",
  "23:49:06.320  Add  40000003      11  host-a.local.                  FE80:0000:0000:0000:007F:AAC4:4773:2FCD%en0  4500",
  "23:49:06.320  Add  40000003       1  host-a.local.                  127.0.0.1                                    4500",
  "23:49:06.320  Add  40000002      11  host-a.local.                  192.0.2.99                                   4500",
].join("\n");

test("input schema bounds and defaults", () => {
  const parsed = mdnsResolveInputSchema.parse({
    instance: "rea-test",
    service_type: "_http._tcp.",
  });
  expect(parsed.domain).toBe("local.");
  expect(parsed.resolve_seconds).toBe(5);
  expect(parsed.include_addresses).toBe(true);
  expect(
    mdnsResolveInputSchema.safeParse({
      instance: "x".repeat(256),
      service_type: "_http._tcp.",
    }).success,
  ).toBe(false);
  expect(
    mdnsResolveInputSchema.safeParse({
      instance: "rea-test",
      service_type: "_http",
    }).success,
  ).toBe(false);
  expect(
    mdnsResolveInputSchema.safeParse({
      instance: "rea-test",
      service_type: "_http._tcp.",
      resolve_seconds: 16,
    }).success,
  ).toBe(false);
});

test("parseResolveLine reads macOS 27 -L rows with TXT continuation lines", () => {
  const parsed = parseResolveLine(LOOKUP_FIXTURE);
  expect(parsed.items).toHaveLength(2);
  expect(parsed.items[0]).toMatchObject({
    service_name: "rea-test._http._tcp.local.",
    target: "host-a.local.",
    port: 8099,
    interface_index: "11",
    txt: [
      { key: "path", value: "/index.txt" },
      { key: "note", value: "hello-rea" },
    ],
    txt_raw: "path=/index.txt note=hello-rea",
  });
  expect(parsed.unparsedLines).toEqual([
    "Lookup rea-test._http._tcp.local.",
    "DATE: ---Tue 27 Oct 2026---",
    "23:49:00.304  ...STARTING...",
  ]);
});

test("parseResolveLine keeps malformed rows verbatim without inventing facts", () => {
  const parsed = parseResolveLine(
    ["23:49:00.304  ...STARTING...", "garbage row with no columns"].join("\n"),
  );
  expect(parsed.items).toEqual([]);
  expect(parsed.unparsedLines.length).toBe(2);
});

test("parseTxtTokens reads quoted zone spelling and unquoted runs", () => {
  expect(parseTxtTokens('"path=/index.txt" "note=hello-rea"')).toEqual([
    { key: "path", value: "/index.txt" },
    { key: "note", value: "hello-rea" },
  ]);
  expect(parseTxtTokens('""')).toEqual([{ key: null, value: "" }]);
  expect(parseTxtTokens("path=/index.txt note=hello-rea")).toEqual([
    { key: "path", value: "/index.txt" },
    { key: "note", value: "hello-rea" },
  ]);
  expect(parseTxtTokens("opaque-token")).toEqual([
    { key: null, value: "opaque-token" },
  ]);
  expect(parseTxtTokens("12 abcd ef01")).toEqual([
    { key: null, value: "12" },
    { key: null, value: "abcd" },
    { key: null, value: "ef01" },
  ]);
  expect(() => parseTxtTokens("")).not.toThrow();
  expect(parseTxtTokens("")).toEqual([]);
});

test("parseZoneOutput reads SRV/TXT/PTR rows and preserves commentary", () => {
  const parsed = parseZoneOutput(ZONE_FIXTURE);
  const srv = parsed.items.filter((record) => record.kind === "srv");
  const txt = parsed.items.filter((record) => record.kind === "txt");
  const ptr = parsed.items.filter((record) => record.kind === "ptr");
  expect(srv).toHaveLength(2);
  expect(srv[0]).toMatchObject({
    name: "OtherDevice._http._tcp",
    target: "localhost.local.",
    port: 21,
    ttl: null,
  });
  expect(txt[0]).toMatchObject({
    name: "OtherDevice._http._tcp",
    txt: [{ key: null, value: "" }],
  });
  expect(txt[1]).toMatchObject({
    name: "rea-test._http._tcp",
    txt: [
      { key: "path", value: "/index.txt" },
      { key: "note", value: "hello-rea" },
    ],
  });
  expect(ptr).toEqual([
    {
      kind: "ptr",
      name: "lb._dns-sd._udp",
      target: "@",
      port: null,
      ttl: null,
      txt: [],
      raw: expect.any(String),
    },
    {
      kind: "ptr",
      name: "_http._tcp",
      target: "OtherDevice._http._tcp",
      port: null,
      ttl: null,
      txt: [],
      raw: expect.any(String),
    },
    {
      kind: "ptr",
      name: "_http._tcp",
      target: "rea-test._http._tcp",
      port: null,
      ttl: null,
      txt: [],
      raw: expect.any(String),
    },
  ]);
  expect(parsed.unparsedLines.some((line) => line.startsWith(";"))).toBe(true);
  expect(parsed.unparsedLines).toContain("23:49:03.308  ...STARTING...");
});

test("parseZoneOutput treats a length-matched len-hex TXT row as binary data", () => {
  const parsed = parseZoneOutput("rea-test._http._tcp TXT 4 abcdef01");
  expect(parsed.items).toEqual([
    {
      kind: "txt",
      name: "rea-test._http._tcp",
      target: null,
      port: null,
      ttl: null,
      txt: [{ key: null, value: "abcdef01" }],
      raw: expect.any(String),
    },
  ]);
  const notConfident = parseZoneOutput("rea-test._http._tcp TXT 3 abcd");
  expect(notConfident.items[0]?.txt).toEqual([
    { key: null, value: "3" },
    { key: null, value: "abcd" },
  ]);
});

test("parseGetAddress reads -G rows with verbatim zone-suffixed addresses", () => {
  const parsed = parseGetAddress(ADDRESS_FIXTURE);
  expect(parsed.items).toHaveLength(6);
  expect(parsed.items[0]).toMatchObject({
    family: "ipv6",
    address: "0000:0000:0000:0000:0000:0000:0000:0001%<0>",
    interface_index: "1",
    hostname: "host-a.local.",
  });
  expect(parsed.items[3]).toMatchObject({
    family: "ipv6",
    address: "FE80:0000:0000:0000:007F:AAC4:4773:2FCD%en0",
  });
  expect(parsed.items[5]).toMatchObject({
    family: "ipv4",
    address: "192.0.2.99",
    interface_index: "11",
  });
  expect(parsed.unparsedLines).toEqual([
    "DATE: ---Tue 27 Oct 2026---",
    "23:49:06.318  ...STARTING...",
    "Timestamp     A/R  Flags         IF  Hostname                               Address                                      TTL",
  ]);
});

const asLauncher =
  (
    responder: (argv: readonly string[]) => string,
    record: { argv: (readonly string[])[]; timeoutMs: number[] } = {
      argv: [],
      timeoutMs: [],
    },
  ): DiscoveryProcessLauncher =>
  async (request) => {
    record.argv.push(request.arguments);
    record.timeoutMs.push(request.timeoutMs);
    return { stdout: responder(request.arguments), stderr: "" };
  };

test("execution runs -L, skips -Z when SRV/TXT are known, and follows -G on the target", async () => {
  const record = {
    argv: [] as (readonly string[])[],
    timeoutMs: [] as number[],
  };
  const run = await executeMdnsResolve(
    "/usr/bin/dns-sd",
    mdnsResolveInputSchema.parse({
      instance: "rea-test",
      service_type: "_http._tcp.",
      resolve_seconds: 3,
    }),
    undefined,
    asLauncher((argv) => {
      if (argv[0] === "-L") return LOOKUP_FIXTURE;
      if (argv[0] === "-Z") return ZONE_FIXTURE;
      if (argv[0] === "-G") return ADDRESS_FIXTURE;
      throw new Error(`unexpected argv ${argv.join(" ")}`);
    }, record),
  );
  expect(run.ok).toBe(true);
  if (!run.ok) throw new Error(run.error.message);
  const result = run.value as MdnsResolveResult;
  expect(record.argv.map((argv) => argv[0])).toEqual(["-L", "-G"]);
  expect(record.argv[0]).toEqual(["-L", "rea-test", "_http._tcp", "local."]);
  expect(record.argv[1]).toEqual(["-G", "v4v6", "host-a.local."]);
  expect(record.timeoutMs).toEqual([3_250, 3_250]);
  expect(result.srv).toEqual({ target: "host-a.local.", port: 8099 });
  expect(result.interface_index).toBe("11");
  expect(result.txt).toEqual([
    { key: "path", value: "/index.txt" },
    { key: "note", value: "hello-rea" },
  ]);
  expect(result.raw_txt).toBe("path=/index.txt note=hello-rea");
  expect(result.addresses.map((row) => row.address)).toContain("192.0.2.99");
  expect(result.lookup_rows).toHaveLength(2);
  expect(result.lookup_rows[0]?.raw).toContain("can be reached at");
  expect(result.zone_ran).toBe(false);
  expect(result.addresses_ran).toBe(true);
  expect(result.lookup_timed_out).toBe(false);
  expect(result.coverage).toBe("partial");
});

test("execution falls back to -Z when -L yields nothing, then addresses", async () => {
  const record = {
    argv: [] as (readonly string[])[],
    timeoutMs: [] as number[],
  };
  const run = await executeMdnsResolve(
    "/usr/bin/dns-sd",
    mdnsResolveInputSchema.parse({
      instance: "rea-test",
      service_type: "_http._tcp.",
    }),
    undefined,
    asLauncher((argv) => {
      if (argv[0] === "-L") return "";
      if (argv[0] === "-Z") return ZONE_FIXTURE;
      if (argv[0] === "-G") return ADDRESS_FIXTURE;
      throw new Error(`unexpected argv ${argv.join(" ")}`);
    }, record),
  );
  if (!run.ok) throw new Error(run.error.message);
  const result = run.value as MdnsResolveResult;
  expect(record.argv.map((argv) => argv[0])).toEqual(["-L", "-Z", "-G"]);
  expect(record.argv[1]).toEqual(["-Z", "_http._tcp", "local."]);
  expect(result.srv).toEqual({ target: "host-a.local.", port: 8099 });
  expect(result.txt.map((entry) => entry.key)).toEqual(["path", "note"]);
  expect(result.zone_ran).toBe(true);
});

test("execution skips the address window when include_addresses is false", async () => {
  const record = {
    argv: [] as (readonly string[])[],
    timeoutMs: [] as number[],
  };
  const run = await executeMdnsResolve(
    "/usr/bin/dns-sd",
    mdnsResolveInputSchema.parse({
      instance: "rea-test",
      service_type: "_http._tcp.",
      include_addresses: false,
      resolve_seconds: 2,
    }),
    undefined,
    asLauncher(() => LOOKUP_FIXTURE, record),
  );
  if (!run.ok) throw new Error(run.error.message);
  const result = run.value as MdnsResolveResult;
  expect(record.argv.map((argv) => argv[0])).toEqual(["-L"]);
  expect(result.addresses).toEqual([]);
  expect(result.addresses_ran).toBe(false);
  expect(result.zone_ran).toBe(false);
});

test("execution honors cancellation and surfaces a tool failure as an error", async () => {
  const cancelled = await executeMdnsResolve(
    "/usr/bin/dns-sd",
    mdnsResolveInputSchema.parse({
      instance: "rea-test",
      service_type: "_http._tcp.",
    }),
    AbortSignal.abort("stopped"),
  );
  expect(cancelled.ok).toBe(false);
  const failing = await executeMdnsResolve(
    "/usr/bin/dns-sd",
    mdnsResolveInputSchema.parse({
      instance: "rea-test",
      service_type: "_http._tcp.",
    }),
    undefined,
    asLauncher(() => {
      throw new Error("dns-sd did not start");
    }),
  );
  expect(failing.ok).toBe(false);
});
