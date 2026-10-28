import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Scripted behavior of the fake BinDiff adapter or BinExport exporter. */
export interface FakeBindiffBehavior {
  readonly stdout?: unknown;
  readonly exportFile?: { readonly name: string; readonly contents: string };
  readonly exit?: number;
  readonly stderr?: string;
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const path = require("node:path");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
const args = process.argv.slice(2);
if (behavior.exit !== undefined) {
  process.stderr.write(behavior.stderr ?? "adapter failed\n");
  process.exit(behavior.exit);
}
if (behavior.exportFile !== undefined) {
  const destination = args[args.length - 1];
  fs.mkdirSync(destination, { recursive: true });
  fs.writeFileSync(
    path.join(destination, behavior.exportFile.name),
    behavior.exportFile.contents,
  );
} else {
  const value = behavior.stdout ?? {};
  process.stdout.write(
    typeof value === "string" ? value : JSON.stringify(value) + "\n",
  );
}
`;

export const writeFakeBindiff = async (
  root: string,
  name: string,
  behavior: FakeBindiffBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, name);
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(`${launcher}.json`, JSON.stringify(behavior));
  const callsPath = `${launcher}.calls`;
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
