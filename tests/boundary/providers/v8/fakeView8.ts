import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Scripted behavior of the fake View8 launcher for one test. */
export interface FakeView8Behavior {
  readonly disassembly?: string;
  readonly exitCode?: number;
  readonly stderr?: string;
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({
  pid: process.pid, at: Date.now(), argv: process.argv.slice(2),
}) + "\n");
if (behavior.stderr) process.stderr.write(behavior.stderr);
process.stdout.write(behavior.disassembly ?? "");
process.exitCode = behavior.exitCode ?? 0;
`;

export const writeFakeView8 = async (
  root: string,
  behavior: FakeView8Behavior,
): Promise<{ readonly launcher: string; readonly callsPath: string }> => {
  const launcher = join(root, "view8");
  await writeFile(launcher, SCRIPT, { mode: 0o755 });
  await writeFile(`${launcher}.json`, JSON.stringify(behavior));
  const callsPath = `${launcher}.calls`;
  await writeFile(callsPath, "");
  return { launcher, callsPath };
};

/** Build one cached-data file: marker, version, source, flag, checksum, length, payload. */
export const cachedDataFixture = (
  payload: Buffer,
  options: {
    readonly versionHash?: number;
    readonly declaredLength?: number;
  } = {},
): Buffer => {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xc0de_0000, 0);
  header.writeUInt32LE(options.versionHash ?? 0x1234_5678, 4);
  header.writeUInt32LE(0x8765_4321, 8);
  header.writeUInt32LE(0x0000_0001, 12);
  header.writeUInt32LE(0xdead_beef, 16);
  header.writeUInt32LE(options.declaredLength ?? payload.byteLength, 20);
  return Buffer.concat([header, payload]);
};
