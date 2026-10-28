import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
  type ProcessDiagnosticBudget,
  type ProviderProcessStopResult,
} from "../process/ProviderProcess.js";
import {
  MITM_ADDON_ID,
  MITM_LISTEN_HOST,
  MITM_PROTOCOL_VERSION,
} from "../domain/mitm/mitmLimits.js";
import {
  mitmReadyEventSchema,
  parseMitmStreamEvent,
  type MitmReadyEvent,
  type MitmStreamEvent,
} from "../domain/mitm/mitmStream.js";

/** Late output retained after a stop request, like other owned providers. */
const MAX_LATE_OUTPUT_BYTES: ProcessDiagnosticBudget = 64 * 1024;

/** A stream or startup frame violated the declared protocol. */
export class MitmDaemonProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MitmDaemonProtocolError";
  }
}

export type MitmStreamProblem = "malformed" | "oversized" | "unknown-type";

export interface MitmDaemonInput {
  readonly command: string;
  readonly addonPath: string;
  readonly listenPort: number;
  readonly runId: string;
  /** Session-private directory the addon retains bodies and entries in. */
  readonly captureDirectory: string;
  /** Session-private control file the addon reads rewrite rules from. */
  readonly controlPath: string;
  readonly hostEnvironment: Readonly<Record<string, string | undefined>>;
  readonly startTimeoutMs: number;
  readonly maxLineBytes: number;
  readonly onEvent: (event: MitmStreamEvent) => void;
  readonly onStreamProblem: (problem: MitmStreamProblem) => void;
  readonly signal?: AbortSignal;
}

/** One supervised `mitmdump` child speaking the REA structure stream on stdout. */
export class MitmDaemonProcess {
  #supervisor: ProviderProcessSupervisor | undefined;
  #running = false;
  #buffer: Buffer = Buffer.alloc(0);
  #discarding = false;
  readonly #maxLineBytes: number;
  readonly #onEvent: (event: MitmStreamEvent) => void;
  readonly #onStreamProblem: (problem: MitmStreamProblem) => void;
  #exitObservation:
    | { readonly code: number | null; readonly signal: NodeJS.Signals | null }
    | undefined;

  private constructor(input: MitmDaemonInput) {
    this.#maxLineBytes = input.maxLineBytes;
    this.#onEvent = input.onEvent;
    this.#onStreamProblem = input.onStreamProblem;
  }

  /** Spawn the proxy and require its startup advertisement before returning. */
  static async start(input: MitmDaemonInput): Promise<{
    readonly daemon: MitmDaemonProcess;
    readonly ready: MitmReadyEvent;
  }> {
    input.signal?.throwIfAborted();
    const spawned = await spawnOwnedProviderProcess({
      command: input.command,
      arguments: [
        "-q",
        "--listen-host",
        MITM_LISTEN_HOST,
        "--listen-port",
        String(input.listenPort),
        "-s",
        input.addonPath,
      ],
      runId: input.runId,
      expectedCommand: null,
      hostEnvironment: input.hostEnvironment as NodeJS.ProcessEnv,
      env: {
        REA_MITM_PROTOCOL: String(MITM_PROTOCOL_VERSION),
        REA_MITM_ADDON_ID: MITM_ADDON_ID,
        REA_MITM_LISTEN_HOST: MITM_LISTEN_HOST,
        REA_MITM_LISTEN_PORT: String(input.listenPort),
        REA_MITM_HOLD_DIR: input.captureDirectory,
        REA_MITM_CONTROL_PATH: input.controlPath,
      },
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
    const daemon = new MitmDaemonProcess(input);
    daemon.#supervisor = supervisor;
    try {
      const ready = await daemon.#readReady(input);
      daemon.#buffer = ready.remainder;
      daemon.#running = true;
      supervisor.launch.process.stdout?.on("data", daemon.#onStdout);
      supervisor.launch.process.once("close", daemon.#onClose);
      daemon.#drain();
      return { daemon, ready: ready.ready };
    } catch (cause: unknown) {
      await daemon.stop().catch(() => undefined);
      throw cause;
    }
  }

  get pid(): number | undefined {
    return this.#supervisor?.launch.process.pid;
  }

  get running(): boolean {
    return this.#running;
  }

  get exitObservation():
    | { readonly code: number | null; readonly signal: NodeJS.Signals | null }
    | undefined {
    return this.#exitObservation;
  }

  get #launchProcess() {
    if (this.#supervisor === undefined)
      throw new MitmDaemonProtocolError("The proxy is not spawned");
    return this.#supervisor.launch.process;
  }

  readonly #onStdout = (chunk: Buffer | string): void => {
    this.#buffer = Buffer.concat([
      this.#buffer,
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
    ]);
    this.#drain();
  };

  readonly #onClose = (
    code: number | null,
    signal: NodeJS.Signals | null,
  ): void => {
    this.#exitObservation = { code, signal };
    this.#running = false;
  };

  /** Split buffered stdout into frames; content problems never stop the proxy. */
  #drain(): void {
    for (;;) {
      const boundary = this.#buffer.indexOf(10);
      if (boundary < 0) {
        if (this.#buffer.byteLength <= this.#maxLineBytes) return;
        if (!this.#discarding) {
          this.#discarding = true;
          this.#onStreamProblem("oversized");
        }
        // An oversized frame is already refused; stop retaining it.
        this.#buffer = Buffer.alloc(0);
        return;
      }
      const frame = this.#buffer.subarray(0, boundary);
      this.#buffer = this.#buffer.subarray(boundary + 1);
      if (this.#discarding) {
        this.#discarding = false;
        continue;
      }
      if (frame.byteLength > this.#maxLineBytes) {
        this.#onStreamProblem("oversized");
        continue;
      }
      const line = frame.toString("utf8").replace(/\r$/u, "");
      if (line.trim() === "") continue;
      const parsed = parseMitmStreamEvent(line);
      if (parsed.kind === "invalid") {
        this.#onStreamProblem("malformed");
        continue;
      }
      if (parsed.kind === "unknown-type") {
        this.#onStreamProblem("unknown-type");
        continue;
      }
      try {
        this.#onEvent(parsed.event);
      } catch {
        this.#onStreamProblem("malformed");
      }
      if (!this.#running) return;
    }
  }

  /** Wait for the one startup frame; anything else is a refused startup. */
  #readReady(
    input: MitmDaemonInput,
  ): Promise<{ readonly ready: MitmReadyEvent; readonly remainder: Buffer }> {
    return new Promise((resolve, reject) => {
      const process = this.#launchProcess;
      let buffered = Buffer.alloc(0);
      let settled = false;
      const timer = setTimeout(() => {
        finish();
        reject(
          new MitmDaemonProtocolError(
            `The addon did not advertise its protocol within ${String(input.startTimeoutMs)} ms`,
          ),
        );
      }, input.startTimeoutMs);
      timer.unref();
      const finish = (): void => {
        clearTimeout(timer);
        process.stdout?.off("data", onData);
        process.off("close", onClose);
        input.signal?.removeEventListener("abort", onAbort);
      };
      const onData = (chunk: Buffer | string): void => {
        buffered = Buffer.concat([
          buffered,
          Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
        ]);
        if (settled) return;
        const boundary = buffered.indexOf(10);
        if (boundary < 0) {
          if (buffered.byteLength > input.maxLineBytes) {
            settled = true;
            finish();
            reject(
              new MitmDaemonProtocolError(
                "The addon emitted an oversized startup frame",
              ),
            );
          }
          return;
        }
        const frame = buffered.subarray(0, boundary);
        buffered = buffered.subarray(boundary + 1);
        settled = true;
        finish();
        let decoded: unknown;
        try {
          decoded = JSON.parse(frame.toString("utf8").replace(/\r$/u, ""));
        } catch {
          reject(
            new MitmDaemonProtocolError(
              "The addon's first line was not a JSON structure-stream frame",
            ),
          );
          return;
        }
        const ready = mitmReadyEventSchema.safeParse(decoded);
        if (!ready.success) {
          reject(
            new MitmDaemonProtocolError(
              "The addon's startup advertisement does not match the structure-stream contract",
            ),
          );
          return;
        }
        if (ready.data.protocol !== MITM_PROTOCOL_VERSION) {
          reject(
            new MitmDaemonProtocolError(
              `The addon speaks protocol ${String(ready.data.protocol)}; this REA build speaks ${String(MITM_PROTOCOL_VERSION)}`,
            ),
          );
          return;
        }
        if (ready.data.listen.port !== input.listenPort) {
          reject(
            new MitmDaemonProtocolError(
              `The addon reported port ${String(ready.data.listen.port)}; REA asked for ${String(input.listenPort)}`,
            ),
          );
          return;
        }
        resolve({ ready: ready.data, remainder: buffered });
      };
      const onClose = (): void => {
        if (settled) return;
        settled = true;
        finish();
        reject(
          new MitmDaemonProtocolError(
            "The proxy exited before advertising its protocol",
          ),
        );
      };
      const onAbort = (): void => {
        if (settled) return;
        settled = true;
        finish();
        reject(new MitmDaemonProtocolError("cancelled"));
      };
      process.stdout?.on("data", onData);
      process.once("close", onClose);
      input.signal?.addEventListener("abort", onAbort, { once: true });
      if (input.signal?.aborted === true) onAbort();
    });
  }

  /** Bounded wait for child exit; true means the child already settled. */
  async waitForExit(timeoutMs: number): Promise<boolean> {
    if (this.#exitObservation !== undefined) return true;
    return (await this.#supervisor?.waitForExit(timeoutMs)) ?? false;
  }

  /** TERM→KILL escalation against the owned proxy and its process group. */
  stop(): Promise<ProviderProcessStopResult> {
    this.#running = false;
    return this.#supervisor?.stop() ?? Promise.resolve({ status: "not-owned" });
  }
}
