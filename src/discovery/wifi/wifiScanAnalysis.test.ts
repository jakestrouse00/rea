import { expect, test } from "vitest";

import {
  isWifiAuthorizationDenial,
  parseWifiScanEvent,
  parseWifiScanLines,
  resolveWifiScanner,
  wifiScanResultSchema,
  WIFI_SCANNER_SETTING,
  type ParsedWifiNetwork,
} from "./WifiScanAnalysis.js";
import { parseSpairportChannel } from "./WifiScanExecution.js";

/**
 * Sanitized rows from the compiled helper's real run on this macOS 27 host
 * (`wifi-scan --seconds 10`, 42 rows): the host's verification scan carried
 * bssid/ssid withheld (null) behind TCC location authorization, so the
 * non-null identifying values below use RFC 7042 documentation values and a
 * synthetic SSID to exercise those parser paths.
 */
const HELPER_LINES = [
  `{"band":"5","channel_width_mhz":40,"rssi":-88,"bssid":null,"ssid":null,"noise":0,"channel":153,"phy_mode":null,"security":null,"ts":1793159553651}`,
  `{"security":null,"ssid":"Test Network","rssi":-67,"phy_mode":null,"band":"2.4","noise":0,"channel":11,"ts":1793159553651,"bssid":"02:5a:9b:1c:7e:04","channel_width_mhz":20}`,
  `{"band":"6","channel_width_mhz":80,"rssi":-89,"bssid":null,"ssid":null,"noise":0,"channel":197,"phy_mode":null,"security":null,"ts":1793159553651}`,
];

const parseAll = (lines: string, includeSsid: boolean): ParsedWifiNetwork[] =>
  parseWifiScanLines(lines, { includeSsid }).items;

test("the default drops the SSID column before parsing", () => {
  const rows = parseAll(HELPER_LINES.join("\n"), false);
  expect(rows).toHaveLength(3);
  expect(rows.some((row) => Object.hasOwn(row, "ssid"))).toBe(false);
});

test("keeping SSIDs preserves the helper's SSID column verbatim", () => {
  const rows = parseAll(HELPER_LINES.join("\n"), true);
  expect(rows[0]?.ssid).toBe(null);
  expect(rows[1]?.ssid).toBe("Test Network");
});

test("rows keep the helper's RF and channel facts verbatim", () => {
  const rows = parseAll(HELPER_LINES.join("\n"), false);
  expect(rows[0]).toBeTypeOf("object");
  expect(rows[0]).toMatchObject({
    ts: 1793159553651,
    bssid: null,
    rssi: -88,
    noise: 0,
    channel: 153,
    band: "5",
    channel_width_mhz: 40,
    phy_mode: null,
    security: null,
  });
});

test("non-JSON non-empty lines and event rows stay in unparsedLines", () => {
  const stdout = [
    ...HELPER_LINES,
    "Airport: Off",
    `{"event":"scan_error","reason":"CoreWLAN scan failed: boom"}`,
    "",
  ].join("\n");
  const parsed = parseWifiScanLines(stdout, { includeSsid: false });
  expect(parsed.items).toHaveLength(3);
  expect(parsed.unparsedLines).toEqual([
    "Airport: Off",
    `{"event":"scan_error","reason":"CoreWLAN scan failed: boom"}`,
  ]);
});

test("empties parse to a complete empty observation", () => {
  const parsed = parseWifiScanLines("", { includeSsid: false });
  expect(parsed.items).toEqual([]);
  expect(parsed.unparsedLines).toEqual([]);
});

test("the helper's structured TCC denial is recognized on stderr rows", () => {
  expect(
    isWifiAuthorizationDenial(
      `{"event":"authorization_required","reason":"Location Services authorization is denied"}`,
    ),
  ).toBe(true);
  expect(
    isWifiAuthorizationDenial(
      `{"event":"scan_error","reason":"CoreWLAN scan failed: boom"}`,
    ),
  ).toBe(false);
  expect(isWifiAuthorizationDenial("Location Services denied")).toBe(false);
  expect(parseWifiScanEvent(`{"event":"scan_error","reason":"x"}`)).toBe(
    "scan_error",
  );
  expect(parseWifiScanEvent("plain text")).toBe(null);
});

test("the result draft validates the parser's own rows", () => {
  const parsed = parseWifiScanLines(HELPER_LINES.join("\n"), {
    includeSsid: false,
  });
  const result = wifiScanResultSchema.parse({
    tools: { wifi_scanner: "/bin/wifi-scan", system_profiler: null },
    source: "scanner",
    include_ssid: false,
    scan_seconds: 10,
    networks: parsed.items,
    unparsed_lines: parsed.unparsedLines,
    coverage: "complete",
  });
  expect(result.networks).toHaveLength(3);
});

test("system_profiler's channel spelling parses into channel, band and width", () => {
  expect(parseSpairportChannel("52 (5GHz, 80MHz)")).toEqual({
    channel: 52,
    band: "5",
    width: 80,
  });
  expect(parseSpairportChannel("11 (2GHz, 20MHz)")).toEqual({
    channel: 11,
    band: "2.4",
    width: 20,
  });
  expect(parseSpairportChannel("97 (6GHz)")).toEqual({
    channel: 97,
    band: "6",
    width: null,
  });
  expect(parseSpairportChannel("(auto)")).toBe(null);
  expect(parseSpairportChannel(undefined)).toBe(null);
});

const darwinProbe = async (environment: Record<string, string>) =>
  resolveWifiScanner(environment, { platform: "darwin" });

test("readiness resolves the scanner env override and the shipped fallback", async () => {
  const profiler = await resolveWifiScanner({}, { platform: "darwin" });
  expect(profiler.ok).toBe(true);
  if (profiler.ok) {
    expect(profiler.value.scanner).toBe(null);
    expect(profiler.value.systemProfiler).toBe("/usr/sbin/system_profiler");
  }
});

test("readiness refuses a relative REA_WIFI_SCANNER_PATH fail-closed", async () => {
  const refusal = await darwinProbe({ [WIFI_SCANNER_SETTING]: "wifi-scan" });
  expect(refusal.ok).toBe(false);
  if (!refusal.ok) {
    expect(refusal.error.code).toBe("open_options_invalid");
    expect(refusal.error.setting).toBe(WIFI_SCANNER_SETTING);
    expect(refusal.error.reason).toContain("absolute path");
  }
});

test("a scanner path that is missing or not executable reports skipped, not failure", async () => {
  const missing = await darwinProbe({
    [WIFI_SCANNER_SETTING]: "/does/not/exist/wifi-scan",
  });
  expect(missing.ok).toBe(true);
  if (missing.ok) expect(missing.value.scanner).toBe(null);
});

test("a resolved scanner path is probed for executability", async () => {
  const resolved = await darwinProbe({
    [WIFI_SCANNER_SETTING]: process.execPath,
  });
  expect(resolved.ok).toBe(true);
  if (resolved.ok) expect(resolved.value.scanner).toBe(process.execPath);
});

test("non-darwin hosts are an unsupported-host readiness failure", async () => {
  const refusal = await resolveWifiScanner(
    { [WIFI_SCANNER_SETTING]: "/bin/wifi-scan" },
    { platform: "linux" },
  );
  expect(refusal.ok).toBe(false);
  if (!refusal.ok) expect(refusal.error.code).toBe("unsupported_host");
});
