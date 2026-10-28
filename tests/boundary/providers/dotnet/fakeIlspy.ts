import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Scripted behavior of the fake `ilspycmd` executable for one test. */
export interface FakeIlspyBehavior {
  readonly version?: { readonly stdout: string } | { readonly exit: number };
  readonly source?: unknown;
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
const args = process.argv.slice(2);
if (args[0] === "--version") {
  const version = behavior.version ?? { stdout: "ilspycmd: 8.2.0.7535\n" };
  if ("exit" in version) {
    process.stderr.write("probe failed\n");
    process.exit(version.exit);
  }
  process.stdout.write(version.stdout);
} else {
  const source = behavior.source ?? "";
  process.stdout.write(typeof source === "string" ? source : JSON.stringify(source));
}
`;

export const writeFakeIlspy = async (
  root: string,
  behavior: FakeIlspyBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, "ilspycmd-fixture");
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(`${launcher}.json`, JSON.stringify(behavior));
  const callsPath = `${launcher}.calls`;
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
