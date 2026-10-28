import vm from "node:vm";
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

/**
 * Produce a real V8 cached-data artifact with the Node running this test, so
 * the decode is checked against bytes V8 wrote rather than bytes the fixture
 * invented from the same assumption.
 */
export const realCachedData = (source: string): Buffer => {
  const script = new vm.Script(source, { produceCachedData: true });
  const data = script.cachedData;
  if (data === undefined || data.byteLength === 0)
    throw new Error("This Node did not produce cached data");
  return data;
};

/**
 * Build one artifact in the documented bytenode-era V8 10 layout: 24-byte
 * header with a source hash and a payload checksum instead of a source length
 * and a read-only snapshot checksum. No such V8 is installed here, so this
 * fixture only exercises that branch's word map.
 */
export const documentedCachedDataFixture = (payload: Buffer): Buffer => {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xc0de_0000, 0);
  header.writeUInt32LE(0x1122_3344, 4);
  header.writeUInt32LE(0x5566_7788, 8);
  header.writeUInt32LE(0x99aa_bbcc, 12);
  header.writeUInt32LE(payload.byteLength, 16);
  header.writeUInt32LE(0xdead_beef, 20);
  return Buffer.concat([header, payload]);
};
