import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Scripted behavior of the fake grpcurl executable for one test. */
export interface FakeGrpcurlBehavior {
  readonly services?: readonly string[];
  readonly descriptions?: Readonly<Record<string, string>>;
  readonly failingServices?: readonly string[];
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
const args = process.argv.slice(2).filter((arg) => arg !== "-plaintext");
const action = args[args.length - 1];
if (action === "list") {
  process.stdout.write((behavior.services ?? []).join("\n") + "\n");
} else {
  const service = action;
  if ((behavior.failingServices ?? []).includes(service)) {
    process.stderr.write("service does not support reflection\n");
    process.exit(1);
  }
  const description = (behavior.descriptions ?? {})[service];
  if (description === undefined) {
    process.stderr.write("service not found\n");
    process.exit(1);
  }
  process.stdout.write(description);
}
`;

export const writeFakeGrpcurl = async (
  root: string,
  behavior: FakeGrpcurlBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, "grpcurl");
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(`${launcher}.json`, JSON.stringify(behavior));
  const callsPath = `${launcher}.calls`;
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
