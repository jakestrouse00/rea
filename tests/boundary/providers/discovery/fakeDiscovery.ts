import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted behavior of the fake macOS discovery toolset for one test. Each
 * tool is a separate executable script that records one JSON line per
 * invocation into `<script>.calls` and answers the exact argv shapes REA
 * composes.
 */
export interface FakeDiscoveryBehavior {
  /** stdout for `arp -a -n`. */
  readonly arp?: string;
  /** stdout for `ndp -a -n`. */
  readonly ndp?: string;
  /** dns-sd stdout for the meta browse (the script then hangs). */
  readonly browseMeta?: string;
  /** dns-sd stdout for a per-type instance browse (the script then hangs). */
  readonly browseType?: string;
  /** stdout for `system_profiler SPUSBDataType -json`. */
  readonly usbRaw?: string;
  /** stdout for `system_profiler SPBluetoothDataType -json`. */
  readonly bluetoothRaw?: string;
  /**
   * Ping replies consumed in call order for the sweep; the last entry
   * repeats for additional calls when a /30 is probed.
   */
  readonly pingReplies?: readonly {
    readonly ok: boolean;
    readonly latencyMs?: number;
  }[];
  /** stdout for `blueutil --inquiry-timeout <s> --inquiry`. */
  readonly inquiryRaw?: string;
  /** stdout for the fake BLE scanner (`ble-scan --seconds <s> ...`). */
  readonly bleRaw?: string;
  /** Scripted behavior of the fake GATT helper (one persistent process). */
  readonly gatt?: {
    /** Connect handshake line; defaults to one read/notify service. */
    readonly connected?: string;
    /** Payload hex answered for reads. */
    readonly valueHex?: string;
    /** Notification payload hex list answered for observes. */
    readonly notifications?: readonly string[];
  };
  /** stdout for the fake CoreWLAN helper (`wifi-scan --seconds <s>`). */
  readonly wifiRaw?: string;
  /** Hex bytes the fake capture program writes to its first argument. */
  readonly captureHex?: string;
  /** stdout for `ifconfig -a -v`. */
  readonly ifconfigRaw?: string;
  /** stdout for `system_profiler SPAirPortDataType -json`. */
  readonly wifiProfilerRaw?: string;
  /** stdout for `system_profiler SPPortsDataType -json`. */
  readonly serialPortsRaw?: string;
  /** stdout for `dns-sd -L ...`. */
  readonly resolveRaw?: string;
  /** stdout for `dns-sd -Z ...`. */
  readonly zoneRaw?: string;
  /** stdout for `dns-sd -G ...`. */
  readonly addressRaw?: string;
}

export interface FakeDiscoveryTools {
  readonly environment: Record<string, string>;
  readonly paths: Readonly<Record<string, string>>;
  readonly calls: () => Promise<
    { readonly role: string; readonly argv: readonly string[] }[]
  >;
}

const SCRIPT = String.raw`#!__NODE__
const fs = require("node:fs");
const ROLE = "__ROLE__";
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
const callsPath = __filename + ".calls";
fs.appendFileSync(callsPath, JSON.stringify({ role: ROLE, argv: process.argv.slice(2) }) + "\n");
const roleCalls = () => fs.readFileSync(callsPath, "utf8").split("\n").filter(l => l.length > 0 && JSON.parse(l).role === ROLE).length;
if (ROLE === "arp") process.stdout.write(behavior.arp ?? "");
else if (ROLE === "ndp") process.stdout.write(behavior.ndp ?? "");
else if (ROLE === "dns_sd") {
  if (process.argv[2] === "-L") { process.stdout.write(behavior.resolveRaw ?? ""); process.exit(0); }
  else if (process.argv[2] === "-Z") { process.stdout.write(behavior.zoneRaw ?? ""); process.exit(0); }
  else if (process.argv[2] === "-G") { process.stdout.write(behavior.addressRaw ?? ""); process.exit(0); }
  if (process.argv[3] === "_services._dns-sd._udp") {
    process.stdout.write(behavior.browseMeta ?? "");
    setInterval(() => {}, 1000);
  } else {
    process.stdout.write(behavior.browseType ?? "");
    setInterval(() => {}, 1000);
  }
} else if (ROLE === "system_profiler") {
  if (process.argv.includes("SPUSBDataType")) process.stdout.write(behavior.usbRaw ?? "{}");
  else if (process.argv.includes("SPBluetoothDataType")) process.stdout.write(behavior.bluetoothRaw ?? "{}");
  else if (process.argv.includes("SPAirPortDataType")) process.stdout.write(behavior.wifiProfilerRaw ?? "{}");
  else if (process.argv.includes("SPPortsDataType")) process.stdout.write(behavior.serialPortsRaw ?? "[]");
  else process.stdout.write("{}");
} else if (ROLE === "ifconfig") process.stdout.write(behavior.ifconfigRaw ?? "");
else if (ROLE === "ping") {
  const replies = behavior.pingReplies ?? [];
  const reply = replies[Math.min(roleCalls() - 1, replies.length - 1)] ?? { ok: false };
  if (reply.ok) {
    process.stdout.write("64 bytes from " + process.argv.at(-1) + ": icmp_seq=0 ttl=57 time=" + String(reply.latencyMs) + " ms\n");
    process.exit(0);
  }
  process.stderr.write("ping: no reply\n");
  process.exit(2);
} else if (ROLE === "blueutil") process.stdout.write(behavior.inquiryRaw ?? "");
else if (ROLE === "ble_scan") process.stdout.write(behavior.bleRaw ?? "");
else if (ROLE === "gatt") {
  const gatt = behavior.gatt ?? {};
  const emit = (row) => process.stdout.write(JSON.stringify(row) + "\n");
  process.stdout.write(gatt.connected ?? JSON.stringify({
    event: "connected", name: "Fake Peripheral",
    services: [{ uuid: "180A", characteristics: [{ uuid: "2A29", properties: ["read"] }] }],
  }) + "\n");
  const lines = require("node:readline").createInterface({ input: process.stdin });
  lines.on("line", (text) => {
    const cmd = JSON.parse(text);
    if (cmd.op === "read") emit({ event: "value", id: cmd.id, payload_hex: gatt.valueHex ?? "" });
    else if (cmd.op === "write") emit({ event: "written", id: cmd.id });
    else if (cmd.op === "observe") {
      const notifications = gatt.notifications ?? [];
      for (const payload_hex of notifications)
        emit({ event: "notification", id: cmd.id, ts: "2026-10-28T05:00:00.000Z", payload_hex });
      emit({ event: "window_end", id: cmd.id });
    } else if (cmd.op === "disconnect") { emit({ event: "disconnected", id: cmd.id }); process.exit(0); }
    else emit({ event: "error", id: cmd.id, message: "unsupported op" });
  });
}
else if (ROLE === "wifi_scan") { process.stdout.write(behavior.wifiRaw ?? ""); process.exit(0); }
else if (ROLE === "packet_capture") {
  try {
    fs.writeFileSync(process.argv[2], Buffer.from(behavior.captureHex ?? "d4c3b2a10b4a2b3c", "hex"));
    process.exit(0);
  } catch (err) {
    process.stderr.write(String(err));
    process.exit(1);
  }
}
`;

const ROLES: Readonly<Record<string, string>> = {
  REA_ARP_PATH: "arp",
  REA_NDP_PATH: "ndp",
  REA_DNS_SD_PATH: "dns_sd",
  REA_SYSTEM_PROFILER_PATH: "system_profiler",
  REA_PING_PATH: "ping",
  REA_IFCONFIG_PATH: "ifconfig",
};

export const writeFakeDiscovery = async (
  root: string,
  behavior: FakeDiscoveryBehavior,
): Promise<FakeDiscoveryTools> => {
  const paths: Record<string, string> = {};
  const environment: Record<string, string> = {};
  for (const [setting, role] of Object.entries(ROLES)) {
    const path = join(root, `fake-${role}`);
    await writeFile(
      path,
      SCRIPT.replaceAll("__ROLE__", role).replaceAll(
        "__NODE__",
        process.execPath,
      ),
    );
    await chmod(path, 0o755);
    await writeFile(path + ".json", JSON.stringify(behavior));
    paths[role] = path;
    environment[setting] = path;
  }
  if (behavior.inquiryRaw !== undefined) {
    const path = join(root, "fake-blueutil");
    await writeFile(
      path,
      SCRIPT.replaceAll("__ROLE__", "blueutil").replaceAll(
        "__NODE__",
        process.execPath,
      ),
    );
    await chmod(path, 0o755);
    await writeFile(path + ".json", JSON.stringify(behavior));
    paths.blueutil = path;
    environment.REA_BLUEUTIL_PATH = path;
  }
  if (behavior.bleRaw !== undefined) {
    const path = join(root, "fake-ble-scan");
    await writeFile(
      path,
      SCRIPT.replaceAll("__ROLE__", "ble_scan").replaceAll(
        "__NODE__",
        process.execPath,
      ),
    );
    await chmod(path, 0o755);
    await writeFile(path + ".json", JSON.stringify(behavior));
    paths.ble_scan = path;
    environment.REA_BLE_SCANNER_PATH = path;
  }
  if (behavior.gatt !== undefined) {
    const path = join(root, "fake-gatt");
    await writeFile(
      path,
      SCRIPT.replaceAll("__ROLE__", "gatt").replaceAll(
        "__NODE__",
        process.execPath,
      ),
    );
    await chmod(path, 0o755);
    await writeFile(path + ".json", JSON.stringify(behavior));
    paths.ble_gatt = path;
    environment.REA_BLE_GATT_PATH = path;
  }
  if (behavior.wifiRaw !== undefined) {
    const path = join(root, "fake-wifi-scan");
    await writeFile(
      path,
      SCRIPT.replaceAll("__ROLE__", "wifi_scan").replaceAll(
        "__NODE__",
        process.execPath,
      ),
    );
    await chmod(path, 0o755);
    await writeFile(path + ".json", JSON.stringify(behavior));
    paths.wifi_scan = path;
    environment.REA_WIFI_SCANNER_PATH = path;
  }
  if (behavior.captureHex !== undefined) {
    const path = join(root, "fake-packet-capture");
    await writeFile(
      path,
      SCRIPT.replaceAll("__ROLE__", "packet_capture").replaceAll(
        "__NODE__",
        process.execPath,
      ),
    );
    await chmod(path, 0o755);
    await writeFile(path + ".json", JSON.stringify(behavior));
    paths.packet_capture = path;
    environment.REA_PACKET_CAPTURE_COMMAND = path;
  }
  return {
    environment,
    paths,
    calls: async () => {
      const rows: { role: string; argv: string[] }[] = [];
      for (const path of Object.values(paths)) {
        const raw = await readFileOrNull(path + ".calls");
        if (raw === null) continue;
        for (const line of raw.split("\n")) {
          if (line.length === 0) continue;
          rows.push(JSON.parse(line) as { role: string; argv: string[] });
        }
      }
      return rows;
    },
  };
};

const readFileOrNull = async (path: string): Promise<string | null> => {
  const { readFile } = await import("node:fs/promises");
  try {
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
};
