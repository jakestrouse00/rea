import {
  spawnOwnedProviderProcess,
  ProviderProcessSupervisor,
  type ProviderProcessLaunch,
} from "../process/ProviderProcess.js";

import {
  MAX_BRIDGE_MESSAGE_BYTES,
  PYDOLL_BRIDGE_PROTOCOL_VERSION,
  parseBridgeAdvertising,
  parseBridgeEvent,
  type PydollBridgeAdvertising,
  type PydollBridgeReply,
} from "./pydollBridgeProtocol.js";

const ADVERTISING_DEADLINE_MS = 90_000;
const MAX_LATE_OUTPUT_BYTES = 64 * 1024;

export class PydollBridgeProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PydollBridgeProtocolError";
  }
}

export class PydollBridgeRequestError extends Error {
  constructor(
    readonly reason: string,
    message: string,
  ) {
    super(message);
    this.name = "PydollBridgeRequestError";
  }
}

type BridgeMessage =
  | PydollBridgeReply
  | { readonly event: string; readonly params: Record<string, unknown> };

interface PendingRequest {
  readonly resolve: (reply: PydollBridgeReply) => void;
  readonly reject: (error: unknown) => void;
}

interface PydollBridgeStartOptions {
  readonly command: string;
  readonly arguments: readonly string[];
  readonly scriptPath: string;
  readonly runId: string;
  readonly hostEnvironment: Readonly<Record<string, string | undefined>>;
  readonly extraEnvironment?: Readonly<Record<string, string>>;
  readonly check?: boolean;
  readonly onEvent?: (params: Record<string, unknown>) => Promise<void> | void;
  readonly signal?: AbortSignal;
}

const parseMessage = (line: string): BridgeMessage => {
  const event = parseBridgeEvent(line);
  if (event !== undefined) return event;
  const reply: unknown = JSON.parse(line);
  if (
    typeof reply === "object" &&
    reply !== null &&
    "id" in reply &&
    "ok" in reply &&
    typeof (reply as { id: unknown }).id === "number" &&
    typeof (reply as { ok: unknown }).ok === "boolean"
  )
    return reply as PydollBridgeReply;
  throw new PydollBridgeProtocolError(
    "The pydoll bridge emitted an unrecognized protocol line",
  );
};

/** One supervised pydoll bridge child with a serialized stdio request protocol. */
export class PydollBridgeProcess {
  #supervisor: ProviderProcessSupervisor | undefined;
  #running = false;
  #buffer = Buffer.alloc(0);
  #nextId = 1;
  #pending = new Map<number, PendingRequest>();
  #onEvent: (params: Record<string, unknown>) => Promise<void> | void;
  #exitObservation:
    | { readonly code: number | null; readonly signal: NodeJS.Signals | null }
    | undefined;
  #pumpDepth = 0;
  advertising: PydollBridgeAdvertising | undefined;

  private constructor() {
    this.#onEvent = () => undefined;
  }

  /** Spawn the interpreter with the bridge script and read the startup advertisement. */
  static async start(
    input: PydollBridgeStartOptions,
  ): Promise<PydollBridgeProcess> {
    input.signal?.throwIfAborted();
    const spawned = await spawnOwnedProviderProcess({
      command: input.command,
      arguments: [
        ...input.arguments,
        input.scriptPath,
        ...(input.check === true ? ["--check"] : []),
      ],
      runId: input.runId,
      expectedCommand: null,
      hostEnvironment: input.hostEnvironment as NodeJS.ProcessEnv,
      ...(input.extraEnvironment === undefined
        ? {}
        : { env: input.extraEnvironment }),
      stdin: "pipe",
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    });
    const supervisor = new ProviderProcessSupervisor(
      {
        process: spawned.process,
        ownsProcessLifetime: true,
        ownership: spawned.ownership,
      },
      { captureStdout: false, maxDiagnosticBytes: MAX_LATE_OUTPUT_BYTES },
    );
    const bridge = new PydollBridgeProcess();
    bridge.#supervisor = supervisor;
    if (input.onEvent !== undefined) bridge.#onEvent = input.onEvent;
    try {
      bridge.advertising = await bridge.#readAdvertising(input.signal);
    } catch (startupFailure: unknown) {
      // A child that never advertised a valid protocol is still owned; stop it before failing.
      await bridge.terminate().catch(() => undefined);
      throw startupFailure;
    }
    return bridge;
  }

  /** Read the startup line, then start the event pump; protocol violations stop the child. */
  async #readAdvertising(
    signal: AbortSignal | undefined,
  ): Promise<PydollBridgeAdvertising> {
    const line = await this.#readLine(ADVERTISING_DEADLINE_MS, signal);
    const parsed = parseBridgeAdvertising(line);
    if (!parsed.ok)
      throw new PydollBridgeProtocolError(
        "The pydoll bridge startup advertisement does not match the protocol contract",
      );
    if (parsed.advertising.protocol !== PYDOLL_BRIDGE_PROTOCOL_VERSION)
      throw new PydollBridgeProtocolError(
        `The pydoll bridge speaks protocol ${String(parsed.advertising.protocol)}; this REA build speaks ${PYDOLL_BRIDGE_PROTOCOL_VERSION}`,
      );
    this.#running = true;
    this.#launchProcess.stdout?.on("data", this.#onStdout);
    this.#launchProcess.once("close", this.#onClose);
    this.#drainBuffer();
    return parsed.advertising;
  }

  get #launchProcess() {
    if (this.#supervisor === undefined)
      throw new PydollBridgeProtocolError("The pydoll bridge is not spawned");
    return this.#supervisor.launch.process;
  }

  readonly #onStdout = (chunk: Buffer | string): void => {
    this.#buffer = Buffer.concat([
      this.#buffer,
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
    ]);
    this.#drainBuffer();
  };

  readonly #onClose = (
    code: number | null,
    signal: NodeJS.Signals | null,
  ): void => {
    this.#exitObservation = { code, signal };
    this.#running = false;
    for (const [, waiter] of [...this.#pending]) {
      waiter.reject(
        new PydollBridgeProtocolError(
          "The pydoll bridge exited before replying",
        ),
      );
    }
    this.#pending.clear();
  };

  #drainBuffer(): void {
    if (this.#pumpDepth > 0) return;
    try {
      this.#pumpDepth += 1;
      while (this.#running) {
        const boundary = this.#buffer.indexOf(10);
        if (boundary < 0) {
          if (this.#buffer.byteLength > MAX_BRIDGE_MESSAGE_BYTES)
            throw new PydollBridgeProtocolError(
              "The pydoll bridge emitted an oversized protocol line",
            );
          break;
        }
        const lineBuffer = this.#buffer.subarray(0, boundary);
        this.#buffer = this.#buffer.subarray(boundary + 1);
        const line = lineBuffer.toString("utf8").replace(/\r$/u, "");
        if (line.trim() === "") continue;
        this.#dispatch(parseMessage(line));
      }
    } catch (cause: unknown) {
      this.#running = false;
      const error = cause instanceof Error ? cause : new Error(String(cause));
      for (const [, waiter] of [...this.#pending]) waiter.reject(error);
      this.#pending.clear();
      this.#launchProcess.kill("SIGTERM");
    } finally {
      this.#pumpDepth -= 1;
    }
  }

  #dispatch(message: BridgeMessage): void {
    if ("event" in message) {
      this.#pumpDepth += 1;
      Promise.resolve(this.#onEvent(message.params))
        .catch((onEventError: unknown) => {
          this.#failAll(onEventError);
          this.#launchProcess.kill("SIGTERM");
        })
        .finally(() => {
          this.#pumpDepth -= 1;
          if (this.#running) setImmediate(() => this.#drainBuffer());
        });
      return;
    }
    const waiter = this.#pending.get(message.id);
    if (waiter === undefined)
      throw new PydollBridgeProtocolError(
        "The pydoll bridge replied to an unknown request id",
      );
    this.#pending.delete(message.id);
    waiter.resolve(message);
  }

  #failAll(cause: unknown): void {
    for (const [, waiter] of [...this.#pending])
      waiter.reject(cause instanceof Error ? cause : new Error(String(cause)));
    this.#pending.clear();
  }

  #readLine(
    deadlineMs: number,
    signal: AbortSignal | undefined,
  ): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const process = this.#launchProcess;
      const timer = setTimeout(() => {
        cleanup();
        reject(
          new PydollBridgeProtocolError(
            "The pydoll bridge never advertised its protocol",
          ),
        );
      }, deadlineMs);
      timer.unref();
      let settled = false;
      const onData = (chunk: Buffer | string): void => {
        this.#buffer = Buffer.concat([
          this.#buffer,
          Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
        ]);
        if (settled) return;
        const boundary = this.#buffer.indexOf(10);
        if (boundary < 0) {
          if (this.#buffer.byteLength > MAX_BRIDGE_MESSAGE_BYTES) {
            settled = true;
            cleanup();
            reject(
              new PydollBridgeProtocolError(
                "The pydoll bridge emitted an oversized protocol line",
              ),
            );
          }
          return;
        }
        const line = this.#buffer.subarray(0, boundary);
        this.#buffer = this.#buffer.subarray(boundary + 1);
        settled = true;
        cleanup();
        resolve(line.toString("utf8").replace(/\r$/u, ""));
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        process.stdout?.off("data", onData);
        process.off("close", onClose);
        signal?.removeEventListener("abort", onAbort);
      };
      const onClose = (): void => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(
          new PydollBridgeProtocolError(
            "The pydoll bridge exited before advertising",
          ),
        );
      };
      const onAbort = (): void => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(new PydollBridgeProtocolError("cancelled"));
      };
      process.stdout?.on("data", onData);
      process.once("close", onClose);
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted === true) onAbort();
    });
  }

  /** Send one serialized request and await its matching reply. */
  async request(
    method: string,
    params: Record<string, unknown>,
    options: {
      readonly deadlineMs?: number;
      readonly signal?: AbortSignal;
    } = {},
  ): Promise<unknown> {
    if (!this.#running)
      throw new PydollBridgeProtocolError("The pydoll bridge is not running");
    const id = this.#nextId++;
    const stdin = this.#launchProcess.stdin;
    if (stdin === undefined || stdin === null)
      throw new PydollBridgeProtocolError("The pydoll bridge has no stdin");
    let settled = false;
    return new Promise<unknown>((resolve, reject) => {
      const settle = (error: unknown, value?: unknown): void => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        this.#pending.delete(id);
        options.signal?.removeEventListener("abort", onAbort);
        if (error !== undefined) reject(error);
        else resolve(value);
      };
      const timer =
        options.deadlineMs === undefined
          ? undefined
          : setTimeout(() => {
              settle(
                new PydollBridgeProtocolError(
                  `The ${method} bridge request timed out`,
                ),
              );
            }, options.deadlineMs);
      timer?.unref();
      const onAbort = (): void => {
        settle(new PydollBridgeProtocolError("cancelled"));
      };
      this.#pending.set(id, {
        resolve: (reply) => {
          if (reply.ok === false) {
            settle(
              new PydollBridgeRequestError(
                reply.error.reason,
                reply.error.message,
              ),
            );
            return;
          }
          settle(undefined, reply.result);
        },
        reject: (error) => {
          settle(error);
        },
      });
      options.signal?.addEventListener("abort", onAbort, { once: true });
      if (options.signal?.aborted === true) {
        onAbort();
        return;
      }
      stdin.write(
        `${JSON.stringify({ id, method, params })}\n`,
        (writeError?: Error | null) => {
          if (writeError === null || writeError === undefined) return;
          settle(
            new PydollBridgeProtocolError(
              `The pydoll bridge rejected the ${method} request: ${writeError.message}`,
            ),
          );
        },
      );
    });
  }

  /** Bounded wait for child exit; true means the child already settled. */
  async waitForExit(timeoutMs: number): Promise<boolean> {
    if (this.#exitObservation !== undefined) return true;
    return (await this.#supervisor?.waitForExit(timeoutMs)) ?? false;
  }

  /** TERM→KILL escalation against the owned interpreter and its process group. */
  async terminate(): Promise<void> {
    const result = await this.#supervisor?.stop();
    if (result !== undefined && result.status === "incomplete")
      throw new PydollBridgeProtocolError(
        `The pydoll bridge did not stop cleanly: ${result.reason}`,
      );
  }

  snapshotExit() {
    if (this.#exitObservation !== undefined) return this.#exitObservation;
    const observed = this.#supervisor?.observedExit();
    return observed === undefined
      ? undefined
      : { code: observed.code, signal: observed.signal };
  }

  /** Owned process-group identity; undefined until spawned. */
  get ownership() {
    return this.#supervisor === undefined
      ? undefined
      : this.#supervisor.launch.ownership;
  }

  get stderrText(): string {
    return this.#supervisor?.snapshot().stderr.text ?? "";
  }
}
