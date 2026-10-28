import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted answers of the fake protocol probe runner for one test.
 *
 * The fixture stands in for the caller-managed interpreter and the runner
 * script: it reads exactly one JSON request line on stdin and writes one JSON
 * answer line on stdout. Its replies repeat the shape the real runner promises,
 * so REA's framing, bounds, deadline, cancellation, and verdict rules are
 * exercised without any lab service. A canned reply makes no claim about a real
 * service's behaviour.
 */
export interface FakeProbeRunnerBehavior {
  /** Base64 replies per step for each successive call, cycled by call index. */
  readonly calls?: readonly (readonly (string | null)[])[];
  /** Milliseconds to wait before answering, to reach REA's deadline. */
  readonly delayMs?: number;
  /** Text written instead of a JSON answer line. */
  readonly malformed?: string;
  /** Bytes written without a trailing newline, to exceed the frame budget. */
  readonly oversizedBytes?: number;
  /** Exit before answering, so REA must report a missing frame. */
  readonly exitBeforeAnswer?: number;
  /** Answer a refusal frame with this code instead of a result. */
  readonly refuse?: { readonly code: string; readonly message: string };
  /** Protocol number the fake puts in its answer envelope. */
  readonly protocol?: number;
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));

const finish = (payload, code) => {
  process.stdout.write(payload, () => {
    process.stdin.destroy();
    if (code !== undefined) process.exitCode = code;
  });
};

const answer = (request, result) => {
  const frame = {
    protocol: "protocol" in behavior ? behavior.protocol : 1,
    job_id: request.job_id ?? "00000000-0000-4000-8000-000000000000",
    ok: true,
    result,
  };
  finish(JSON.stringify(frame) + "\n");
};

const refusal = (request) => {
  const frame = {
    protocol: "protocol" in behavior ? behavior.protocol : 1,
    job_id: request.job_id ?? "00000000-0000-4000-8000-000000000000",
    ok: false,
    error: behavior.refuse,
  };
  finish(JSON.stringify(frame) + "\n");
};

let line = "";
process.stdin.on("data", (chunk) => {
  line += chunk.toString("utf8");
  const boundary = line.indexOf("\n");
  if (boundary < 0) return;
  const request = JSON.parse(line.slice(0, boundary));
  fs.appendFileSync(
    __filename + ".calls",
    JSON.stringify({ pid: process.pid, argv: process.argv.slice(2), request }) + "\n",
  );
  if (behavior.delayMs !== undefined) {
    setTimeout(() => answer(request, resultFor(request)), behavior.delayMs);
    return;
  }
  if (behavior.exitBeforeAnswer !== undefined) {
    process.exit(behavior.exitBeforeAnswer);
  }
  if (behavior.malformed !== undefined) {
    finish(behavior.malformed);
    return;
  }
  if (behavior.oversizedBytes !== undefined) {
    finish("x".repeat(behavior.oversizedBytes));
    return;
  }
  if (behavior.refuse !== undefined) {
    refusal(request);
    return;
  }
  answer(request, resultFor(request));
});

function repliesFor(request) {
  const calls = behavior.calls ?? [[]];
  const callIndex = Math.max(
    0,
    fs.readFileSync(__filename + ".calls", "utf8").trim().split("\n").length - 1,
  );
  return calls[callIndex % calls.length] ?? [];
}

function resultFor(request) {
  const replies = repliesFor(request);
  let total = 0;
  const steps = (request.steps ?? []).map((step, ordinal) => {
    const reply = replies[ordinal] ?? null;
    const bytes = reply === null ? null : Buffer.from(reply, "base64");
    total += bytes === null ? 0 : bytes.length;
    return {
      ordinal,
      sent_bytes: Buffer.from(step.bytes_hex, "hex").length,
      response_bytes: bytes === null ? 0 : bytes.length,
      response_base64: reply,
      truncated: false,
      timed_out: reply === null,
      error_code: null,
    };
  });
  return { connected: true, steps, total_response_bytes: total };
}
`;

export const writeFakeProbeRunner = async (
  root: string,
  behavior: FakeProbeRunnerBehavior,
): Promise<{
  readonly environment: Readonly<Record<string, string>>;
  readonly callsPath: string;
  readonly bridgeDirectory: string;
  readonly interpreter: string;
}> => {
  const bridgeDirectory = join(root, "bridge");
  await mkdir(bridgeDirectory, { recursive: true });
  const interpreter = join(root, "python-fixture");
  await writeFile(interpreter, SCRIPT, { mode: 0o755 });
  await writeFile(join(root, "python-fixture.json"), JSON.stringify(behavior));
  await writeFile(
    join(bridgeDirectory, "probe_runner.py"),
    "# REA protocol probe runner fixture\n",
  );
  const callsPath = join(root, "python-fixture.calls");
  await writeFile(callsPath, "");
  return {
    environment: {
      REA_PROTOLEARN_PYTHON: interpreter,
      REA_PROTOLEARN_BRIDGE_DIR: bridgeDirectory,
      REA_PROTOLEARN_LAB_ENDPOINTS: '["127.0.0.1:9000"]',
    },
    callsPath,
    bridgeDirectory,
    interpreter,
  };
};
