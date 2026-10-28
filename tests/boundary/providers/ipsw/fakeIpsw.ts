import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted behavior of the fake `ipsw` executable for one test. The script
 * records one JSON line per invocation into `<script>.calls` and answers the
 * exact argv shapes REA composes.
 */
export interface FakeIpswBehavior {
  /** Text printed by `version`; `exit` fails the probe instead. */
  readonly version?: { readonly stdout: string } | { readonly exit: number };
  /** `ipsw info <archive> --json`; a string is printed verbatim. */
  readonly info?: unknown;
  /** `ipsw dyld info <cache> --json`; a string is printed verbatim. */
  readonly manifest?: unknown;
  /** Relative files `ipsw dyld extract` writes into its destination. */
  readonly extractFiles?: Readonly<Record<string, string>>;
  /** `ipsw macho class-dump` / `ipsw swift dump`; shared fixture body. */
  readonly classes?: unknown;
  /** `ipsw symbolicate <crash> --dsc <cache> --json`. */
  readonly symbolicated?: unknown;
  /** `ipsw macho info <image> --json --entitlements`. */
  readonly macho?: unknown;
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const path = require("node:path");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
const args = process.argv.slice(2);
const out = (value) =>
  process.stdout.write(typeof value === "string" ? value : JSON.stringify(value) + "\n");
if (args[0] === "version") {
  const version = behavior.version ?? { stdout: "ipsw version 3.1.575\n" };
  if ("exit" in version) {
    process.stderr.write("probe failed\n");
    process.exit(version.exit);
  }
  process.stdout.write(version.stdout);
} else if (args[0] === "info") {
  out(behavior.info ?? "not an inventory\n");
} else if (args[0] === "dyld" && args[1] === "info") {
  out(behavior.manifest ?? "not a manifest\n");
} else if (args[0] === "dyld" && args[1] === "extract") {
  const destination = args[3] ?? "";
  for (const [relativePath, contents] of Object.entries(behavior.extractFiles ?? {})) {
    const target = path.join(destination, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents);
  }
  out({ extracted: Object.keys(behavior.extractFiles ?? {}).length });
} else if (args[0] === "macho" && args[1] === "class-dump") {
  out(behavior.classes ?? { classes: [] });
} else if (args[0] === "swift" && args[1] === "dump") {
  out(behavior.classes ?? { types: [] });
} else if (args[0] === "symbolicate") {
  out(behavior.symbolicated ?? { threads: [] });
} else if (args[0] === "macho" && args[1] === "info") {
  out(behavior.macho ?? {});
} else {
  process.stderr.write("unmodeled invocation\n");
  process.exit(9);
}
`;

/** Materialize one fake executable and return its path plus the call log. */
export const writeFakeIpsw = async (
  root: string,
  behavior: FakeIpswBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, "ipsw-fixture");
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(join(root, "ipsw-fixture.json"), JSON.stringify(behavior));
  const callsPath = join(root, "ipsw-fixture.calls");
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};

export const FIXTURE_SHA256 = `${"a".repeat(32)}${"b".repeat(32)}`;
