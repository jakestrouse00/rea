import type { ChildProcess } from "node:child_process";
import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";

import {
  FUZZING_DIAGNOSTIC_EXCERPT_BYTES,
  FUZZING_MAX_OUTPUT_BYTES,
  FUZZING_STOP_GRACE_MS,
} from "../domain/fuzzing/fuzzingEngine.js";

/** How one engine run ended. */
export interface FuzzingProcessOutcome {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  /** Spawn failure code when no process ever existed. */
  readonly spawnError: string | null;
  readonly outputTruncated: boolean;
}

interface Retained {
  head: Buffer;
  tail: Buffer;
  total: number;
}

const retained = (): Retained => ({
  head: Buffer.alloc(0),
  tail: Buffer.alloc(0),
  total: 0,
});

const keep = (stream: Retained, chunk: Buffer, limit: number): void => {
  const headLimit = Math.ceil(limit / 2);
  const tailLimit = limit - headLimit;
  stream.total += chunk.length;
  const headCount = Math.min(
    chunk.length,
    Math.max(0, headLimit - stream.head.length),
  );
  if (headCount > 0)
    stream.head = Buffer.concat([stream.head, chunk.subarray(0, headCount)]);
  const rest = chunk.subarray(headCount);
  if (rest.length > 0 && tailLimit > 0)
    stream.tail = Buffer.concat([stream.tail, rest]).subarray(-tailLimit);
};

const text = (stream: Retained, limit: number): string =>
  stream.total > limit
    ? `${stream.head.toString("utf8")} … [output omitted] … ${stream.tail.toString("utf8")}`
    : Buffer.concat([stream.head, stream.tail]).toString("utf8");

/**
 * One owned engine process with bounded output retention.
 *
 * Complete lines reach the caller as they arrive, so a campaign can read its
 * stat stream while the engine runs. Both streams retain a bounded head and
 * tail for failure diagnostics; nothing else is published.
 */
export class FuzzingCampaignProcess {
  #outcome: Promise<FuzzingProcessOutcome>;
  #stopped = false;
  #grace: NodeJS.Timeout | undefined;
  #stdout = retained();
  #stderr = retained();
  #truncated = false;

  private constructor(
    private readonly child: ChildProcess,
    onStdoutLine: (line: string) => void,
  ) {
    const decoder = new StringDecoder("utf8");
    let pending = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      keep(this.#stdout, chunk, FUZZING_MAX_OUTPUT_BYTES);
      this.#truncated =
        this.#truncated || this.#stdout.total > FUZZING_MAX_OUTPUT_BYTES;
      pending += decoder.write(chunk);
      const lines = pending.split("\n");
      pending = lines.pop() ?? "";
      for (const line of lines) onStdoutLine(line);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      keep(this.#stderr, chunk, FUZZING_MAX_OUTPUT_BYTES);
      this.#truncated =
        this.#truncated || this.#stderr.total > FUZZING_MAX_OUTPUT_BYTES;
    });
    let spawnError: string | null = null;
    child.on("error", (error: NodeJS.ErrnoException) => {
      spawnError = error.code ?? error.message;
    });
    this.#outcome = new Promise((resolve) => {
      child.on("close", (code, signal) => {
        if (pending !== "") onStdoutLine(pending);
        resolve({
          code,
          signal,
          spawnError,
          outputTruncated: this.#truncated,
        });
      });
    });
  }

  static start(
    request: {
      readonly executable: string;
      readonly arguments: readonly string[];
      /** Launch environment the engine selection was resolved from. */
      readonly environment: Readonly<Record<string, string | undefined>>;
    },
    handlers: { readonly onStdoutLine: (line: string) => void },
  ): FuzzingCampaignProcess {
    const child = spawn(request.executable, [...request.arguments], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...request.environment },
    });
    if (child.stdout === null || child.stderr === null)
      throw new Error("The engine process started without output pipes");
    return new FuzzingCampaignProcess(child, handlers.onStdoutLine);
  }

  /** Stop the engine, escalating to SIGKILL after the grace period. */
  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.child.kill("SIGTERM");
    this.#grace = setTimeout(() => {
      this.child.kill("SIGKILL");
    }, FUZZING_STOP_GRACE_MS);
    this.#grace.unref();
  }

  get outcome(): Promise<FuzzingProcessOutcome> {
    return this.#outcome;
  }

  get outputTruncated(): boolean {
    return this.#truncated;
  }

  /** Bounded stderr tail, used only for a failure message. */
  get stderrExcerpt(): string {
    const value = text(this.#stderr, FUZZING_MAX_OUTPUT_BYTES).trim();
    return value.length <= FUZZING_DIAGNOSTIC_EXCERPT_BYTES
      ? value
      : `…${value.slice(-FUZZING_DIAGNOSTIC_EXCERPT_BYTES)}`;
  }

  /** Settle the process and clear the escalation timer. */
  async settled(): Promise<FuzzingProcessOutcome> {
    const outcome = await this.#outcome;
    if (this.#grace !== undefined) clearTimeout(this.#grace);
    this.#grace = undefined;
    return outcome;
  }
}
