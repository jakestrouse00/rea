import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Scripted behavior of one fake protobuf recovery tool. */
export interface FakeProtoToolBehavior {
  readonly files?: Readonly<Record<string, string>>;
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
  process.stderr.write(behavior.stderr ?? "recovery failed\n");
  process.exit(behavior.exit);
}
const destination = args.includes("-o") ? args[args.indexOf("-o") + 1] : args[1];
for (const [relativePath, contents] of Object.entries(behavior.files ?? {})) {
  const target = path.join(destination, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}
`;

export const writeFakeProtoTool = async (
  root: string,
  name: string,
  behavior: FakeProtoToolBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, name);
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(`${launcher}.json`, JSON.stringify(behavior));
  const callsPath = `${launcher}.calls`;
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
