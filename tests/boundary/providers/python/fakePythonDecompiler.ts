import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Scripted behavior of the fake Python decompiler for one test. */
export interface FakePythonDecompilerBehavior {
  readonly source?: string;
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
process.stdout.write(behavior.source ?? "");
`;

export const writeFakePythonDecompiler = async (
  root: string,
  name: string,
  behavior: FakePythonDecompilerBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, name);
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(`${launcher}.json`, JSON.stringify(behavior));
  const callsPath = `${launcher}.calls`;
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
