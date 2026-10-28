import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { BenchSuccessMetric } from "../../../src/domain/bench/benchTask.js";
import { BENCH_OUTCOME_RELATIVE_PATH } from "../../../src/domain/bench/benchLimits.js";

/** Fixture inputs the three autonomy loops and the benchmark lane consume. */
export interface BenchLoopFixture {
  readonly target: string;
  readonly targetSha256: string;
  readonly qlog: string;
  readonly qlogSha256: string;
  readonly pcap: string;
  readonly pcapSha256: string;
  /** Owner-only directory the interception lane writes captured bodies into. */
  readonly captureDirectory: string;
  /** Body the fixture traffic carried; the flag value exists only here. */
  readonly capturedBody: string;
  readonly flag: string;
  readonly flagSha256: string;
  readonly modelStore: string;
  readonly modelFile: string;
  /** Workspace a benchmark task runs in. */
  readonly taskWorkspace: string;
  readonly taskSuccess: BenchSuccessMetric;
}

const sha256 = (value: Buffer | string): string =>
  createHash("sha256").update(value).digest("hex");

// A two-record aioquic JSON qlog: the loop learns from it, this eval only
// carries its identity into the model source.
const qlogFixture = `${JSON.stringify({
  qlog_version: "0.3",
  qlog_format: "JSON",
  traces: [{ title: "rea-bench-loop-b", events: [] }],
})}\n`;

// One pcap global header: this eval asserts the plumbing, not a decoder.
const pcapFixture = Buffer.from([
  0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
]);

const flag = "flag{loop-c-fixture-body}";
const targetFixture = Buffer.from(
  "REA benchmark loop A synthetic target: no real engine is launched.\n",
  "utf8",
);

/** Materialize the loop fixtures under one test-owned root. */
export const createBenchLoopFixture = async (
  root: string,
): Promise<BenchLoopFixture> => {
  const target = join(root, "loop-a/target.bin");
  const qlog = join(root, "loop-b/capture.qlog");
  const pcap = join(root, "loop-c/capture.pcap");
  const captureDirectory = join(root, "loop-c/session");
  const capturedBody = join(captureDirectory, "response-1.body");
  const modelStore = join(root, "loop-b/model-store");
  const taskWorkspace = join(root, "bench-task");
  await Promise.all([
    mkdir(join(root, "loop-a"), { recursive: true }),
    mkdir(join(root, "loop-b"), { recursive: true }),
    mkdir(modelStore, { recursive: true }),
    mkdir(captureDirectory, { recursive: true }),
    mkdir(join(taskWorkspace, ".rea-bench"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(target, targetFixture),
    writeFile(qlog, qlogFixture),
    writeFile(pcap, pcapFixture),
    writeFile(capturedBody, `${flag}\n`),
    writeFile(
      join(taskWorkspace, ".rea-bench", "task.json"),
      `${JSON.stringify({
        task_id: "nyu-ctf-bench/web-01",
        suite: "nyu-ctf-bench",
        entrypoint: "docker compose up --abort-on-container-exit harness",
      })}\n`,
    ),
  ]);
  return {
    target,
    targetSha256: sha256(targetFixture),
    qlog,
    qlogSha256: sha256(qlogFixture),
    pcap,
    pcapSha256: sha256(pcapFixture),
    captureDirectory,
    capturedBody,
    flag,
    flagSha256: sha256(`${flag}\n`),
    modelStore,
    modelFile: join(modelStore, "model.json"),
    taskWorkspace,
    taskSuccess: { kind: "flag", expected_flag_sha256: sha256(flag) },
  };
};

/** Write one benchmark-harness outcome into a task workspace. */
export const writeBenchOutcome = async (
  workspace: string,
  outcome: unknown,
): Promise<void> => {
  const path = join(workspace, BENCH_OUTCOME_RELATIVE_PATH);
  await mkdir(join(workspace, ".rea-bench"), { recursive: true });
  await writeFile(path, JSON.stringify(outcome));
};
