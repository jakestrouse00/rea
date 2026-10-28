import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, test } from "vitest";

import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import type { DiscoveryProcessLauncher } from "../DiscoveryCommand.js";
import {
  executeWifiScan,
  executeWifiSystemProfiler,
} from "./WifiScanExecution.js";

/** Sanitized helper-output rows as in wifiScanAnalysis.test.ts. */
const HELPER_LINES = [
  `{"band":"5","channel_width_mhz":40,"rssi":-88,"bssid":null,"ssid":null,"noise":0,"channel":153,"phy_mode":null,"security":null,"ts":1793159553651}`,
  `{"security":null,"ssid":"Test Network","rssi":-67,"phy_mode":null,"band":"2.4","noise":0,"channel":11,"ts":1793159553651,"bssid":"02:5a:9b:1c:7e:04","channel_width_mhz":20}`,
  `{"band":"6","channel_width_mhz":80,"rssi":-89,"bssid":null,"ssid":null,"noise":0,"channel":197,"phy_mode":null,"security":null,"ts":1793159553651}`,
];

interface FakeLaunchBehavior {
  readonly stdout?: string;
  readonly stderr?: string;
  readonly killed?: boolean;
}

const fakeLaunch = (behavior: FakeLaunchBehavior) => {
  const calls: {
    readonly executable: string;
    readonly arguments: readonly string[];
    readonly timeoutMs: number;
  }[] = [];
  const launcher: DiscoveryProcessLauncher = async (request) => {
    calls.push(request);
    if (behavior.killed === true) {
      const failure = new Error("Command timed out after 0 ms");
      Object.assign(failure, {
        stdout: behavior.stdout ?? "",
        stderr: behavior.stderr ?? "",
        code: "ETIMEDOUT",
        signal: "SIGTERM",
        killed: true,
      });
      throw failure;
    }
    return { stdout: behavior.stdout ?? "", stderr: behavior.stderr ?? "" };
  };
  return { calls, launcher };
};

const resultOf = (
  result: Awaited<ReturnType<typeof executeWifiScan>>,
): Record<string, unknown> => {
  if (!result.ok)
    throw new Error(result.error.userMessage ?? result.error.message);
  return result.value.result as Record<string, unknown>;
};

const errorOf = (
  result: Awaited<ReturnType<typeof executeWifiScan>>,
): {
  readonly message: string;
  readonly userMessage: string | undefined;
  readonly projected: string;
} => {
  if (result.ok) throw new Error("expected an execution failure");
  return {
    message: result.error.message,
    userMessage: result.error.userMessage,
    projected: JSON.stringify(projectAnalysisError(result.error)),
  };
};

test("the scanner lane runs one bounded observation window and drops SSIDs by default", async () => {
  const { calls, launcher } = fakeLaunch({ stdout: HELPER_LINES.join("\n") });
  const result = await executeWifiScan(
    "/bin/wifi-scan",
    {},
    undefined,
    launcher,
  );
  expect(calls).toHaveLength(1);
  expect(calls[0]?.executable).toBe("/bin/wifi-scan");
  expect(calls[0]?.arguments).toEqual(["--seconds", "10"]);
  expect(calls[0]?.timeoutMs).toBe(30_000);
  const payload = resultOf(result) as {
    tools: { wifi_scanner: string | null; system_profiler: string | null };
    source: string;
    include_ssid: boolean;
    scan_seconds: number;
    networks: { ssid?: string | null; channel: number | null }[];
    unparsed_lines: string[];
    coverage: string;
  };
  expect(payload.tools.wifi_scanner).toBe("/bin/wifi-scan");
  expect(payload.tools.system_profiler).toBe(null);
  expect(payload.source).toBe("scanner");
  expect(payload.include_ssid).toBe(false);
  expect(payload.scan_seconds).toBe(10);
  expect(payload.networks).toHaveLength(3);
  expect(payload.networks.some((row) => Object.hasOwn(row, "ssid"))).toBe(
    false,
  );
  expect(payload.networks[0]?.channel).toBe(153);
  expect(payload.coverage).toBe("complete");
});

test("a custom scan window widens the deadline by the fixed grace only", async () => {
  const { calls, launcher } = fakeLaunch({ stdout: "" });
  await executeWifiScan("/bin/wifi-scan", {}, undefined, launcher, {
    scanSeconds: 3,
  });
  expect(calls[0]?.arguments).toEqual(["--seconds", "3"]);
  expect(calls[0]?.timeoutMs).toBe(23_000);
});

test("include_ssid keeps the helper's SSID column", async () => {
  const { launcher } = fakeLaunch({ stdout: HELPER_LINES.join("\n") });
  const payload = resultOf(
    await executeWifiScan(
      "/bin/wifi-scan",
      { include_ssid: true },
      undefined,
      launcher,
    ),
  ) as { networks: { ssid: string | null }[] };
  expect(payload.networks[1]?.ssid).toBe("Test Network");
});

test("the provider-shaped input carries scan_seconds into the helper window", async () => {
  const { calls, launcher } = fakeLaunch({ stdout: "" });
  await executeWifiScan(
    "/bin/wifi-scan",
    { include_ssid: true, scan_seconds: 20 },
    undefined,
    launcher,
  );
  expect(calls[0]?.arguments).toEqual(["--seconds", "20"]);
  expect(calls[0]?.timeoutMs).toBe(40_000);
});

test("the helper's TCC denial is a structured authorization failure", async () => {
  const { launcher } = fakeLaunch({
    stdout: "",
    stderr: `{"event":"authorization_required","reason":"Location Services authorization is denied"}`,
  });
  const failure = errorOf(
    await executeWifiScan("/bin/wifi-scan", {}, undefined, launcher),
  );
  expect(failure.userMessage).toContain("Location");
  expect(failure.projected).toContain("grant_macOS_location_authorization");
});

test("a helper scan_error event is a structured failure carrying the reason", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-wifi-"));
  const scriptPath = join(root, "failing-wifi-scan");
  await writeFile(
    scriptPath,
    `#!${process.execPath}\nprocess.stderr.write('{"event":"scan_error","reason":"CoreWLAN scan failed: internal error"}\\n');\nprocess.exit(1);\n`,
  );
  await chmod(scriptPath, 0o755);
  const failure = errorOf(await executeWifiScan(scriptPath, {}));
  expect(failure.userMessage).toContain("exit 1");
  expect(failure.userMessage).toContain("CoreWLAN scan failed: internal error");
});

test("a deadline-kill keeps the rows captured before the deadline as partial coverage", async () => {
  const { launcher } = fakeLaunch({
    stdout: HELPER_LINES.join("\n"),
    killed: true,
  });
  const payload = resultOf(
    await executeWifiScan("/bin/wifi-scan", {}, undefined, launcher),
  ) as { coverage: string; networks: unknown[] };
  expect(payload.coverage).toBe("partial");
  expect(payload.networks).toHaveLength(3);
});

/** Sanitized shape of the live SPAirPortDataType -json probe on this host. */
const AIRPORT_JSON = JSON.stringify({
  SPAirPortDataType: [
    {
      _name: "AirPort",
      spairport_airport_other_local_wireless_networks: [
        {
          _name: "Neighbor Network",
          spairport_network_channel: "52 (5GHz, 80MHz)",
          spairport_network_phymode: "802.11a/n/ac/ax",
          spairport_network_type: "spairport_network_type_station",
          spairport_security_mode: "spairport_security_mode_wpa2_personal",
        },
      ],
    },
  ],
});

test("the fallback lane reads the airport cache without the helper", async () => {
  const { calls, launcher } = fakeLaunch({ stdout: AIRPORT_JSON });
  const result = await executeWifiSystemProfiler(
    "/usr/sbin/system_profiler",
    {},
    undefined,
    launcher,
  );
  expect(calls[0]?.arguments).toEqual(["SPAirPortDataType", "-json"]);
  const payload = resultOf(result) as {
    tools: { wifi_scanner: string | null; system_profiler: string | null };
    source: string;
    networks: Record<string, unknown>[];
    coverage: string;
  };
  expect(payload.tools.wifi_scanner).toBe(null);
  expect(payload.source).toBe("system_profiler");
  expect(payload.networks).toHaveLength(1);
  expect(Object.hasOwn(payload.networks[0] ?? {}, "ssid")).toBe(false);
  expect(payload.networks[0]).toMatchObject({
    bssid: null,
    channel: 52,
    band: "5",
    channel_width_mhz: 80,
    phy_mode: "802.11a/n/ac/ax",
    security: "spairport_security_mode_wpa2_personal",
  });
  expect(payload.coverage).toBe("complete");
});

test("the fallback honors include_ssid and the literal producer key", async () => {
  const literalKey = JSON.stringify({
    SPAirPortDataType: [
      {
        _name: "AirPort",
        "Other Local Wi-Fi Networks": [
          {
            _name: "Neighbor Network",
            spairport_network_channel: "52 (5GHz, 80MHz)",
            spairport_network_phymode: "802.11a/n/ac/ax",
            spairport_network_type: "spairport_network_type_station",
            spairport_security_mode: "spairport_security_mode_wpa2_personal",
          },
        ],
      },
    ],
  });
  const { launcher } = fakeLaunch({ stdout: literalKey });
  const payload = resultOf(
    await executeWifiSystemProfiler(
      "/usr/sbin/system_profiler",
      { include_ssid: true },
      undefined,
      launcher,
    ),
  ) as { networks: { ssid: string | null; channel: number }[] };
  expect(payload.networks).toHaveLength(1);
  expect(payload.networks[0]?.ssid).toBe("Neighbor Network");
  expect(payload.networks[0]?.channel).toBe(52);
});

test("unrecognized neighbor records stay verbatim in unparsed_lines", async () => {
  const mixed = JSON.stringify({
    SPAirPortDataType: [
      {
        _name: "AirPort",
        spairport_airport_other_local_wireless_networks: [
          {
            _name: "Neighbor Network",
            spairport_network_channel: "108 (5GHz, 80MHz)",
            spairport_network_phymode: "802.11a/n/ac/ax",
          },
          { unexpected: true },
        ],
      },
    ],
  });
  const { launcher } = fakeLaunch({ stdout: mixed });
  const payload = resultOf(
    await executeWifiSystemProfiler(
      "/usr/sbin/system_profiler",
      {},
      undefined,
      launcher,
    ),
  ) as { networks: unknown[]; unparsed_lines: string[]; coverage: string };
  expect(payload.networks).toHaveLength(1);
  expect(payload.unparsed_lines).toEqual(['{"unexpected":true}']);
  expect(payload.coverage).toBe("partial");
});

test("non-JSON system_profiler output is a protocol failure", async () => {
  const { launcher } = fakeLaunch({ stdout: "not json" });
  const failure = errorOf(
    await executeWifiSystemProfiler(
      "/usr/sbin/system_profiler",
      {},
      undefined,
      launcher,
    ),
  );
  expect(failure.message).toContain("not recognizable");
  expect(failure.projected).toContain("unreadable_output");
});
