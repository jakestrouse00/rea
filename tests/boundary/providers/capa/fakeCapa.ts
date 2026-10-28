import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted behavior of the fake `capa` executable for one test. The script
 * records one JSON line per invocation into `<script>.calls` and answers the
 * exact argv shapes REA composes.
 */
export interface FakeCapaBehavior {
  /** Text printed by `--version`; `exit` fails the probe instead. */
  readonly version?: { readonly stdout: string } | { readonly exit: number };
  /** Document printed for the `-j` analysis invocation; a string is verbatim. */
  readonly analysis?: unknown;
  /** Fails the analysis after printing these bytes. */
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
  const version = behavior.version ?? { stdout: "capa 9.0.0\n" };
  if ("exit" in version) {
    process.stderr.write("probe failed\n");
    process.exit(version.exit);
  }
  process.stdout.write(version.stdout);
} else if (args[0] === "-j") {
  if (behavior.failure !== undefined) {
    if (behavior.failure.stdout !== undefined)
      process.stdout.write(behavior.failure.stdout);
    process.stderr.write(behavior.failure.stderr ?? "analysis failed\n");
    process.exit(behavior.failure.exit);
  }
  out(behavior.analysis ?? {});
} else {
  process.stderr.write("unmodeled invocation\n");
  process.exit(9);
}
`;

/** Materialize one fake executable and return its path plus the call log. */
export const writeFakeCapa = async (
  root: string,
  behavior: FakeCapaBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, "capa-fixture");
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(join(root, "capa-fixture.json"), JSON.stringify(behavior));
  const callsPath = join(root, "capa-fixture.calls");
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
