import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted answers of the fake angr sidecar for one test.
 *
 * The fixture stands in for the caller-managed Python interpreter and the angr
 * imports: it reads exactly one JSON request line on stdin and writes one JSON
 * answer line on stdout, so REA's own framing, bounds, deadline, cancellation,
 * and refusal handling are exercised without angr. Its answers repeat the shape
 * the real bridge promises; they make no claim about angr's analysis results.
 */
export interface FakeAngrJobBehavior {
  /** Fields merged over the fixture result the fake synthesizes. */
  readonly result?: Readonly<Record<string, unknown>>;
  readonly error?: { readonly code: string; readonly message: string };
  /** Milliseconds to wait before answering, to reach REA's deadline. */
  readonly delayMs?: number;
}

export interface FakeAngrBridgeBehavior {
  readonly find_paths?: FakeAngrJobBehavior;
  readonly explore_function?: FakeAngrJobBehavior;
  readonly recover_cfg?: FakeAngrJobBehavior;
  readonly angrVersion?: string | null;
  /** Protocol number the fake puts in its answer envelope. */
  readonly protocol?: number;
  /** Text written instead of a JSON answer line. */
  readonly malformed?: string;
  /** Bytes written without a trailing newline, to exceed the frame budget. */
  readonly oversizedBytes?: number;
  /** Exit before answering, so REA must report a missing frame. */
  readonly exitBeforeAnswer?: number;
}

const SCRIPT = String.raw`#!${process.execPath}
const fs = require("node:fs");
const crypto = require("node:crypto");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
let buffered = "";
let answered = false;

const record = (request) =>
  fs.appendFileSync(
    __filename + ".calls",
    JSON.stringify({ pid: process.pid, at: Date.now(), argv: process.argv.slice(2), request }) + "\n",
  );

const finish = (payload) => {
  process.stdout.write(payload, () => {
    process.stdin.destroy();
  });
};

const digest = (value) =>
  crypto.createHash("sha256").update(String(value)).digest("hex");

const pathRecord = (request) => ({
  path_id: 0,
  found: true,
  steps: 3,
  block_count: 2,
  address: (request.find_addresses ?? ["0x401000"])[0],
  conditions: [
    { index: 0, depth: 0, kind: "operation", op: "__eq__", bits: 1, operand: null, constant_sha256: "0".repeat(64) },
    { index: 1, depth: 1, kind: "symbol", op: "bvs", bits: 64, operand: "rea_stdin", constant_sha256: null },
  ],
  conditions_truncated: false,
  model: [{ name: "rea_stdin", bits: 64, value_sha256: digest("model") }],
  model_truncated: false,
});

const base = (request) => {
  const bridge = {
    protocol: 1,
    angr_version:
      "angrVersion" in behavior ? behavior.angrVersion : "9.2.4",
  };
  const target = {
    path: request.path,
    entry: request.entry ?? null,
    sha256: request.binary_sha256,
  };
  if (request.kind === "find_paths")
    return {
      bridge,
      target,
      reachable: true,
      termination: "find_hit",
      assertion_count: (request.assertions ?? []).length,
      find_address_count: (request.find_addresses ?? []).length,
      avoid_address_count: (request.avoid_addresses ?? []).length,
      paths: [pathRecord(request)],
      paths_truncated: false,
      explored_states: 4,
      coverage: "complete",
      values_redacted: true,
    };
  if (request.kind === "explore_function")
    return {
      bridge,
      target,
      termination: "find_hit",
      explored_states: 6,
      active_states: 0,
      deadended_states: 1,
      found_states: 1,
      avoided_states: 0,
      errored_states: 0,
      find_address_count: (request.find_addresses ?? []).length,
      avoid_address_count: (request.avoid_addresses ?? []).length,
      visited_blocks: ["0x401000", "0x401010"],
      visited_blocks_truncated: false,
      found: [pathRecord(request)],
      coverage: "complete",
      values_redacted: true,
    };
  return {
    bridge,
    target,
    function_count: 1,
    functions: [{ address: "0x401000", block_count: 2 }],
    functions_truncated: false,
    block_count: 2,
    blocks: [
      { address: "0x401000", size: 4, successors: ["0x401004"] },
      { address: "0x401004", size: 4, successors: [] },
    ],
    blocks_truncated: false,
    edge_count: 1,
    coverage: "complete",
  };
};

const answer = (request, spec) => {
  const kind = request.kind;
  if (behavior.exitBeforeAnswer !== undefined) {
    process.stderr.write("fixture exited before answering\n");
    process.exit(behavior.exitBeforeAnswer);
  }
  if (behavior.malformed !== undefined) {
    finish(behavior.malformed + "\n");
    return;
  }
  if (behavior.oversizedBytes !== undefined) {
    process.stdout.write("x".repeat(behavior.oversizedBytes));
    return;
  }
  const frame = {
    protocol: behavior.protocol ?? 1,
    job_id: request.job_id,
    kind,
    ok: spec?.error === undefined,
    ...(spec?.error === undefined
      ? { result: { ...base(request), ...(spec?.result ?? {}) } }
      : { error: spec.error }),
  };
  finish(JSON.stringify(frame) + "\n");
};

const handle = (line) => {
  if (answered) return;
  answered = true;
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    finish("not json\n");
    return;
  }
  record(request);
  const spec = behavior[request.kind];
  if (spec?.delayMs !== undefined) {
    setTimeout(() => answer(request, spec), spec.delayMs);
    return;
  }
  answer(request, spec);
};

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffered += chunk;
  const boundary = buffered.indexOf("\n");
  if (boundary < 0) return;
  handle(buffered.slice(0, boundary));
});
process.stdin.on("end", () => {
  if (!answered) process.exit(3);
});
`;

/** Materialize one fake sidecar environment and its call log. */
export const writeFakeAngrBridge = async (
  root: string,
  behavior: FakeAngrBridgeBehavior,
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
    join(bridgeDirectory, "angr_bridge.py"),
    "# REA angr bridge fixture\n",
  );
  const callsPath = join(root, "python-fixture.calls");
  await writeFile(callsPath, "");
  return {
    environment: {
      REA_ANGR_PYTHON: interpreter,
      REA_ANGR_BRIDGE_DIR: bridgeDirectory,
    },
    callsPath,
    bridgeDirectory,
    interpreter,
  };
};
