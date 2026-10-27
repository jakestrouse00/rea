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
  if (process.argv[3] === "_services._dns-sd._udp") {
    process.stdout.write(behavior.browseMeta ?? "");
    setInterval(() => {}, 1000);
  } else {
    process.stdout.write(behavior.browseType ?? "");
    setInterval(() => {}, 1000);
  }
} else if (ROLE === "system_profiler") {
  process.stdout.write(process.argv.includes("SPUSBDataType") ? (behavior.usbRaw ?? "{}") : (behavior.bluetoothRaw ?? "{}"));
} else if (ROLE === "ping") {
  const replies = behavior.pingReplies ?? [];
  const reply = replies[Math.min(roleCalls() - 1, replies.length - 1)] ?? { ok: false };
  if (reply.ok) {
    process.stdout.write("64 bytes from " + process.argv.at(-1) + ": icmp_seq=0 ttl=57 time=" + String(reply.latencyMs) + " ms\n");
    process.exit(0);
  }
  process.stderr.write("ping: no reply\n");
  process.exit(2);
} else if (ROLE === "blueutil") process.stdout.write(behavior.inquiryRaw ?? "");
`;

const ROLES: Readonly<Record<string, string>> = {
  REA_ARP_PATH: "arp",
  REA_NDP_PATH: "ndp",
  REA_DNS_SD_PATH: "dns_sd",
  REA_SYSTEM_PROFILER_PATH: "system_profiler",
  REA_PING_PATH: "ping",
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
