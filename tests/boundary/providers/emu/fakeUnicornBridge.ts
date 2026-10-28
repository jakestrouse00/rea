import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Scripted answers of the fake emulation sidecar for one test.
 *
 * The fixture stands in for the caller-managed Python interpreter and the
 * Unicorn/Keystone imports: it reads exactly one JSON request line on stdin and
 * writes one JSON answer line on stdout, so REA's own framing, bounds, deadline,
 * cancellation, and refusal handling are exercised without an emulator.
 */
export interface FakeEmuJobBehavior {
  /** Fields merged over the fixture result the fake synthesizes. */
  readonly result?: Readonly<Record<string, unknown>>;
  readonly error?: { readonly code: string; readonly message: string };
  /** Milliseconds to wait before answering, to reach REA's deadline. */
  readonly delayMs?: number;
}

export interface FakeEmuBridgeBehavior {
  readonly emulate?: FakeEmuJobBehavior;
  readonly assemble?: FakeEmuJobBehavior;
  readonly unicornVersion?: string;
  readonly keystoneVersion?: string | null;
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
  const code = request.code_hex
    ? Buffer.from(request.code_hex, "hex")
    : Buffer.alloc(0);
  const base =
    kind === "emulate"
      ? {
          bridge: {
            protocol: 1,
            unicorn_version: behavior.unicornVersion ?? "2.1.4",
            keystone_version: behavior.keystoneVersion ?? "0.9.2",
          },
          arch: request.arch,
          endianness: request.endianness,
          code: {
            source: "hex",
            path: null,
            offset: null,
            length: code.length,
            sha256: crypto.createHash("sha256").update(code).digest("hex"),
          },
          code_base: request.code_base,
          entry: request.entry,
          exit: "returned",
          exit_detail: { code: "sentinel_return", address: null },
          executed_steps: 7,
          call_count: 2,
          call_targets: [{ address: "0x401040", count: 2 }],
          call_targets_truncated: false,
          edges: [request.entry + "->" + request.entry],
          edge_count: 1,
          edges_truncated: false,
          registers: (request.observe_registers ?? []).map((name) => ({
            name,
            value: "0x2a",
          })),
          unknown_registers: [],
          memory: (request.observe_memory ?? []).map((window) => ({
            address: window.address,
            length: window.length,
            sha256: "0".repeat(64),
          })),
          memory_omitted: 0,
          coverage: "complete",
        }
      : {
          bridge: {
            protocol: 1,
            unicorn_version: behavior.unicornVersion ?? "2.1.4",
            keystone_version: behavior.keystoneVersion ?? "0.9.2",
          },
          arch: request.arch,
          endianness: request.endianness,
          base_address: request.base_address,
          assembly: request.assembly,
          bytes_hex: "c3",
          size: 1,
          sha256: crypto.createHash("sha256").update(Buffer.from("c3", "hex")).digest("hex"),
          instruction_count: 1,
        };
  const frame = {
    protocol: behavior.protocol ?? 1,
    job_id: request.job_id,
    kind,
    ok: spec?.error === undefined,
    ...(spec?.error === undefined
      ? { result: { ...base, ...(spec?.result ?? {}) } }
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
export const writeFakeEmuBridge = async (
  root: string,
  behavior: FakeEmuBridgeBehavior,
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
    join(bridgeDirectory, "unicorn_bridge.py"),
    "# REA Unicorn bridge fixture\n",
  );
  const callsPath = join(root, "python-fixture.calls");
  await writeFile(callsPath, "");
  return {
    environment: {
      REA_UNICORN_PYTHON: interpreter,
      REA_UNICORN_BRIDGE_DIR: bridgeDirectory,
    },
    callsPath,
    bridgeDirectory,
    interpreter,
  };
};
