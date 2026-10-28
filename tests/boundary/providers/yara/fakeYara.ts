import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted behavior of the fake YARA-X `yr` executable for one test. The
 * script records one JSON line per invocation into `<script>.calls` and
 * answers the exact argv shapes REA composes.
 */
export interface FakeYaraBehavior {
  /** Text printed by `--version`; `exit` fails the probe instead. */
  readonly version?: { readonly stdout: string } | { readonly exit: number };
  /** Match array printed for a scan; a string is printed verbatim. */
  readonly matches?: unknown;
  /** Fails a scan after printing these bytes. */
  readonly failure?: {
    readonly exit: number;
    readonly stdout?: string;
    readonly stderr?: string;
  };
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
const args = process.argv.slice(2);
const out = (value) =>
  process.stdout.write(typeof value === "string" ? value : JSON.stringify(value) + "\n");
if (args[0] === "--version") {
  const version = behavior.version ?? { stdout: "yr 0.15.0\n" };
  if ("exit" in version) {
    process.stderr.write("probe failed\n");
    process.exit(version.exit);
  }
  process.stdout.write(version.stdout);
} else if (args[0] === "scan") {
  if (behavior.failure !== undefined) {
    if (behavior.failure.stdout !== undefined)
      process.stdout.write(behavior.failure.stdout);
    process.stderr.write(behavior.failure.stderr ?? "scan failed\n");
    process.exit(behavior.failure.exit);
  }
  out(behavior.matches ?? []);
} else {
  process.stderr.write("unmodeled invocation\n");
  process.exit(9);
}
`;

/** Materialize one fake executable and return its path plus the call log. */
export const writeFakeYara = async (
  root: string,
  behavior: FakeYaraBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, "yr-fixture");
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(join(root, "yr-fixture.json"), JSON.stringify(behavior));
  const callsPath = join(root, "yr-fixture.calls");
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
