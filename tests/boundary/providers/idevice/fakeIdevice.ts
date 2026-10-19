import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted behavior of the fake `pymobiledevice3` launcher for one test.
 * The launcher records one JSON line per invocation into `<script>.calls`
 * and answers the exact argv shapes REA composes.
 */
export interface FakeIdeviceBehavior {
  /** Text printed by `--version`; `exit` fails the probe instead. */
  readonly version?: { readonly stdout: string } | { readonly exit: number };
  /** Device rows for `usbmux list`; [] models an unpaired host. */
  readonly devices?: readonly {
    readonly DeviceID?: string;
    readonly DeviceName?: string;
    readonly ConnectionType?: string;
    readonly paired?: boolean;
  }[];
  /** Raw stdout for `usbmux list`; overrides devices. */
  readonly devicesRaw?: string;
  /** Lockdown info JSON body for `-u <udid>`. */
  readonly lockdownInfo?: Record<string, unknown>;
  readonly syslog?:
    | { readonly lines: readonly string[] }
    | { readonly hang: true }
    | { readonly notJson: true };
  /** Bytes written for `developer dvt screenshot <path>`. */
  readonly screenshotBytes?: string;
  readonly screenshotMode?: "ok" | "missing" | "exit-failure";
  readonly crashList?: readonly string[];
  readonly crashCopy?:
    | { readonly fileName?: string; readonly bytes?: string }
    | { readonly empty: true };
  /** App rows for `apps list`; a row may carry provisioning keys. */
  readonly apps?:
    | readonly Record<string, unknown>[]
    | { readonly notJson: true };
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
const args = process.argv.slice(2);
const hang = () => setInterval(() => {}, 1000);
const udidFor = () => {
  const i = args.indexOf("-u");
  return i === -1 ? null : args[i + 1];
};
if (args[0] === "--version") {
  const version = behavior.version ?? { stdout: "pymobiledevice3 4.6.2\n" };
  if ("exit" in version) { process.stderr.write("probe failed\n"); process.exit(version.exit); }
  process.stdout.write(version.stdout);
} else if (args[0] === "usbmux" && args[1] === "list") {
  if (behavior.devicesRaw !== undefined) process.stdout.write(behavior.devicesRaw);
  else process.stdout.write(JSON.stringify({ deviceList: behavior.devices ?? [] }) + "\n");
} else if (args[0] === "lockdown" && args[1] === "info") {
  process.stdout.write(JSON.stringify(behavior.lockdownInfo ?? { DeviceID: udidFor(), DeviceName: "Fixture iPhone", ProductType: "iPhone17,1", ProductVersion: "18.3.1", ConnectionType: "USB" }) + "\n");
} else if (args[0] === "syslog") {
  if (behavior.syslog === undefined || "lines" in behavior.syslog) {
    const lines = behavior.syslog && "lines" in behavior.syslog ? behavior.syslog.lines : ["Oct 19 10:00:00 Fixture app[123]: fixture log line"];
    process.stdout.write(lines.join("\n") + "\n");
  } else if (behavior.syslog.notJson === true) {
    process.stdout.write("not syslog\n");
  } else if (behavior.syslog.hang === true) {
    hang();
  }
} else if (args[0] === "developer" && args[1] === "dvt" && args[2] === "screenshot") {
  const mode = behavior.screenshotMode ?? "ok";
  const out = args.at(-1) ?? "";
  if (!out || out.startsWith("-")) { process.stderr.write("screenshot output path missing\n"); process.exit(9); }
  if (mode === "exit-failure") { process.stderr.write("screenshot failed\n"); process.exit(1); }
  if (mode === "missing") { /* writes nothing */ }
  else fs.writeFileSync(out, (behavior.screenshotBytes ?? "PNG-FIXTURE") + "\n");
} else if (args[0] === "crash" && args[1] === "list") {
  const rows = behavior.crashList ?? [];
  process.stdout.write(rows.join("\n") + (rows.length ? "\n" : ""));
} else if (args[0] === "crash" && args[1] === "copy") {
  if (behavior.crashCopy && "empty" in behavior.crashCopy) { /* writes nothing */ }
  else {
    const outIndex = args.indexOf("--out");
    const out = args[outIndex + 1];
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(out + "/" + (behavior.crashCopy?.fileName ?? "fixture-app-2026-10-19-120000.ips"), (behavior.crashCopy?.bytes ?? "CRASH-FIXTURE") + "\n");
  }
} else if (args[0] === "apps" && args[1] === "list") {
  if (behavior.apps && "notJson" in behavior.apps) process.stdout.write("not apps json\n");
  else process.stdout.write(JSON.stringify(behavior.apps ?? []) + "\n");
} else {
  process.stderr.write("unmodeled invocation\n");
  process.exit(9);
}
`;

/** Materialize one fake launcher and return its path plus the call log path. */
export const writeFakeIdevice = async (
  root: string,
  behavior: FakeIdeviceBehavior,
): Promise<{
  readonly launcher: string;
  readonly callsPath: string;
}> => {
  const launcher = join(root, "pymobiledevice3-fixture");
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(
    join(root, "pymobiledevice3-fixture.json"),
    JSON.stringify(behavior),
  );
  const callsPath = join(root, "pymobiledevice3-fixture.calls");
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};

export const FIXTURE_UDID = "00008101-000A104E0123456789";
export const FIXTURE_APP_BUNDLE = "com.fixture.app";
