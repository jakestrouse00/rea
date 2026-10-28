import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Scripted behavior of the fake `java` executable for one JVM test. */
export interface FakeJavaBehavior {
  readonly version?: string;
  readonly files?: Readonly<Record<string, string>>;
  readonly exit?: number;
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const path = require("node:path");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
const args = process.argv.slice(2);
if (args[0] === "-version") {
  process.stderr.write(behavior.version ?? 'openjdk version "17.0.1" 2024-04-16\n');
} else if (args[0] === "-jar") {
  if (behavior.exit !== undefined) {
    process.stderr.write("decompilation failed\n");
    process.exit(behavior.exit);
  }
  const destination = args[args.length - 1] ?? "";
  for (const [relativePath, contents] of Object.entries(behavior.files ?? {})) {
    const target = path.join(destination, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents);
  }
} else {
  process.stderr.write("unmodeled invocation\n");
  process.exit(9);
}
`;

export const writeFakeJava = async (
  root: string,
  behavior: FakeJavaBehavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, "java");
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(`${launcher}.json`, JSON.stringify(behavior));
  const callsPath = `${launcher}.calls`;
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};
