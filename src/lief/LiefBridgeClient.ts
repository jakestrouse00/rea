import { randomUUID } from "node:crypto";
import type { Readable } from "node:stream";

import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import { ProviderStartupDeadline } from "../process/ProviderDeadline.js";
import { LIEF_LIMITS } from "../domain/lief/liefLimits.js";

/** One bridge run's bounded output: the single frame line plus diagnostics. */
export interface LiefBridgeRunOutput {
  /** The frame line without its trailing newline, or undefined if none arrived. */
  readonly line: string | undefined;
  readonly exitCode: number | null;
  readonly stderr: string;
  readonly stderrTruncated: boolean;
}

/** Why one bounded bridge run could not produce a frame. */
export type LiefBridgeRunFailureReason =
  | "cancelled"
  | "timeout"
  | "spawn"
  | "process"
  | "protocol"
  | "output-limit";

/** A bridge run that failed at a named boundary, with bounded diagnostics. */
export class LiefBridgeRunError extends Error {
  readonly _tag = "LiefBridgeRunError";
  constructor(
    readonly reason: LiefBridgeRunFailureReason,
    message: string,
    readonly diagnostics: {
      readonly stderr: string;
      readonly exit_code: number | null;
    } = { stderr: "", exit_code: null },
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "LiefBridgeRunError";
  }
}

/** Spawn coordinates for one bounded request/response bridge run. */
export interface LiefBridgeRunInput {
  /** Caller-selected Python interpreter that has LIEF installed. */
  readonly command: string;
  /** Absolute path of the bridge script the caller placed in their directory. */
  readonly bridgePath: string;
  /** One UTF-8 JSON request line; the trailing newline is added here. */
  readonly request: string;
  readonly hostEnvironment: Readonly<NodeJS.ProcessEnv>;
  readonly signal?: AbortSignal;
}

/**
 * Retain the first stdout line within the frame budget.
 *
 * A line that grows past the budget before its newline is refused rather than
 * clipped, because a truncated frame cannot be reported as a complete answer.
 * Later lines are drained and ignored so the child is never blocked.
 */
class FrameLineCollector {
  #buffer: Buffer = Buffer.alloc(0);
  #line: string | undefined;
  #oversized = false;
  #failure: string | undefined;

  constructor(readonly stdout: Readable | null) {
    stdout?.on("data", this.#onData);
    stdout?.on("error", this.#onError);
  }

  get line(): string | undefined {
    return this.#line;
  }

  get oversized(): boolean {
    return this.#oversized;
  }

  get failure(): string | undefined {
    return this.#failure;
  }

  /** Whether nothing more can be learned from this stream. */
  get settled(): boolean {
    return (
      this.#oversized || this.#failure !== undefined || this.#line !== undefined
    );
  }

  close(): void {
    this.stdout?.off("data", this.#onData);
    this.stdout?.off("error", this.#onError);
  }

  readonly #onData = (chunk: Buffer | string): void => {
    if (this.#line !== undefined || this.#oversized) return;
    this.#buffer = Buffer.concat([
      this.#buffer,
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
    ]);
    const boundary = this.#buffer.indexOf(10);
    if (boundary < 0) {
      if (this.#buffer.byteLength > LIEF_LIMITS.maxResponseBytes) {
        this.#oversized = true;
        this.#buffer = Buffer.alloc(0);
      }
      return;
    }
    this.#line = this.#buffer
      .subarray(0, boundary)
      .toString("utf8")
      .replace(/\r$/u, "");
    this.#buffer = Buffer.alloc(0);
  };

  readonly #onError = (cause: Error): void => {
    this.#failure ??= cause.message;
  };
}

const interruptedFailure = (
  deadline: ProviderStartupDeadline,
  cause: unknown,
): LiefBridgeRunError =>
  deadline.interruption === "cancelled"
    ? new LiefBridgeRunError(
        "cancelled",
        "LIEF bridge run was cancelled.",
        undefined,
        {
          cause,
        },
      )
    : new LiefBridgeRunError(
        "timeout",
        `LIEF bridge run did not finish within ${String(deadline.timeoutMs)} ms.`,
        undefined,
        { cause },
      );

const writeRequest = (
  stdin: NodeJS.WritableStream | null | undefined,
  request: string,
): { failure(): string | undefined } => {
  if (stdin === null || stdin === undefined)
    return { failure: () => "the bridge has no writable stdin" };
  let failure: string | undefined;
  stdin.on("error", (cause: Error) => {
    failure ??= `request write failed: ${cause.message}`;
  });
  stdin.end(`${request}\n`);
  return { failure: () => failure };
};

/**
 * Run the caller-selected bridge once with one request frame and one response
 * frame, then stop the owned process group.
 *
 * Bounds: the request line, the retained response line, retained stderr and the
 * whole-run deadline.
 */
export const runLiefBridge = async (
  input: LiefBridgeRunInput,
): Promise<LiefBridgeRunOutput> => {
  const deadline = new ProviderStartupDeadline(
    LIEF_LIMITS.defaultDeadlineMs,
    input.signal,
  );
  try {
    if (input.signal?.aborted === true)
      throw interruptedFailure(deadline, undefined);
    const requestBytes = Buffer.byteLength(input.request, "utf8") + 1;
    if (requestBytes > LIEF_LIMITS.maxRequestBytes)
      throw new LiefBridgeRunError(
        "protocol",
        `The LIEF bridge request is ${String(requestBytes)} bytes and exceeds the ${String(LIEF_LIMITS.maxRequestBytes)}-byte frame budget.`,
      );
    const spawned = await spawnBridge(input, deadline);
    const supervisor = new ProviderProcessSupervisor(
      {
        process: spawned.process,
        ownsProcessLifetime: true,
        ownership: spawned.ownership,
        ...(spawned.cleanup === undefined ? {} : { cleanup: spawned.cleanup }),
      },
      { captureStdout: false, maxDiagnosticBytes: LIEF_LIMITS.maxStderrBytes },
    );
    const collector = new FrameLineCollector(spawned.process.stdout);
    const requestWrite = writeRequest(spawned.process.stdin, input.request);
    try {
      while (supervisor.observedExit() === undefined && !collector.settled) {
        if ((await deadline.wait(25)) === "aborted") break;
      }
    } finally {
      collector.close();
    }
    const stopped = await supervisor.stop();
    const snapshot = supervisor.snapshot();
    supervisor.dispose();
    const diagnostics = {
      stderr: snapshot.stderr.text.slice(0, LIEF_LIMITS.maxStderrBytes),
      exit_code: snapshot.exitCode ?? null,
    };
    if (stopped.status === "incomplete")
      throw new LiefBridgeRunError(
        "process",
        `The LIEF bridge's process group could not be confirmed stopped: ${stopped.reason}.`,
        diagnostics,
      );
    if (deadline.interruption !== undefined)
      throw interruptedFailure(deadline, undefined);
    if (collector.oversized)
      throw new LiefBridgeRunError(
        "output-limit",
        `The LIEF bridge emitted more than ${String(LIEF_LIMITS.maxResponseBytes)} bytes before its line ended; refusing to parse a clipped frame.`,
        diagnostics,
      );
    const failure = collector.failure ?? requestWrite.failure();
    if (failure !== undefined)
      throw new LiefBridgeRunError(
        "protocol",
        `The LIEF bridge stream failed: ${failure}.`,
        diagnostics,
      );
    if (collector.line === undefined || collector.line.trim() === "")
      throw new LiefBridgeRunError(
        "process",
        `The LIEF bridge exited (${String(diagnostics.exit_code)}) without emitting a response frame${diagnostics.stderr.length === 0 ? "" : `; stderr: ${diagnostics.stderr.slice(0, 512)}`}.`,
        diagnostics,
      );
    return {
      line: collector.line,
      exitCode: diagnostics.exit_code,
      stderr: diagnostics.stderr,
      stderrTruncated: snapshot.diagnosticTruncated === true,
    };
  } finally {
    deadline.dispose();
  }
};

const spawnBridge = async (
  input: LiefBridgeRunInput,
  deadline: ProviderStartupDeadline,
) => {
  try {
    return await spawnOwnedProviderProcess({
      command: input.command,
      arguments: ["-B", input.bridgePath],
      runId: randomUUID(),
      expectedCommand: null,
      hostEnvironment: input.hostEnvironment as NodeJS.ProcessEnv,
      env: { PYTHONDONTWRITEBYTECODE: "1" },
      stdin: "pipe",
      signal: deadline.signal,
    });
  } catch (cause: unknown) {
    if (deadline.interruption !== undefined)
      throw interruptedFailure(deadline, cause);
    throw new LiefBridgeRunError(
      "spawn",
      `The selected LIEF interpreter could not be launched: ${cause instanceof Error ? cause.message : String(cause)}`,
      undefined,
      { cause },
    );
  }
};
