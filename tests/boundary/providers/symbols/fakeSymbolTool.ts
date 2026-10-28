import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted behavior of one fake symbol tool for a test. The script records one
 * JSON line per invocation into `<script>.calls` and prints the configured
 * stdout.
 */
export interface FakeSymbolBehavior {
  readonly stdout: string;
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
if (behavior.failure !== undefined) {
  if (behavior.failure.stdout !== undefined)
    process.stdout.write(behavior.failure.stdout);
  process.stderr.write(behavior.failure.stderr ?? "tool failed\n");
  process.exit(behavior.failure.exit);
}
process.stdout.write(behavior.stdout);
`;

/** Materialize one fake executable and return its path plus the call log. */
export const writeFakeSymbolTool = async (
  root: string,
  name: string,
  behavior: FakeSymbolBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, name);
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(`${launcher}.json`, JSON.stringify(behavior));
  const callsPath = `${launcher}.calls`;
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
