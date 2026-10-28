import {
  constants as fsConstants,
  accessSync,
  closeSync,
  openSync,
  readSync,
} from "node:fs";

import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { DISCOVERY_PROVIDER_ID } from "../DiscoveryRelease.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  runDiscoveryCommand,
  type DiscoveryProcessLauncher,
} from "../DiscoveryCommand.js";
import { parseSystemProfilerJson } from "../DiscoveryDeviceOutput.js";
import {
  joinSerialPorts,
  parseDevList,
  parseSystemProfilerPorts,
  renderHexPreview,
  renderOverflowLines,
  renderPrintablePreview,
  SERIAL_PREVIEW_BYTE_LIMIT,
} from "./SerialDeviceOutput.js";
import {
  serialSttyArguments,
  type ObserveSerialPortInput,
  type SerialPortRow,
  type SerialStopReason,
  type SerialToolset,
} from "./SerialAnalysis.js";

/** Operation names the integrator wires into the provider switch. */
export const LIST_SERIAL_PORTS_OPERATION = "list_serial_ports";
export const OBSERVE_SERIAL_PORT_OPERATION = "observe_serial_port";

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Probe/read deadline shared with the discovery lane defaults. */
const LIST_TIMEOUT_MS = 30_000;
/** Line-discipline configuration deadline; tty.open can wait for carrier. */
const STTY_TIMEOUT_MS = 10_000;
/** stty is an Apple-shipped required host tool, like arp or ping. */
export const STTY_PATH = "/bin/stty";
export const STTY_CANDIDATES: readonly string[] = [
  "/bin/stty",
  "/usr/sbin/stty",
];
const OBSERVE_CHUNK_BYTES = 4096;
const OBSERVE_POLL_MS = 20;
/** Retained-byte bound for one receive window. */
const OBSERVE_MAX_BYTES = 1_048_576;

export const LIST_SERIAL_PORTS_LIMITATIONS = [
  "The port inventory joins system_profiler's port tree with the /dev listing by name only; a device node without a matching system_profiler row keeps null facts, and a system_profiler row without a device node appears in unmatched_port_names",
  "in_use is null: no producer reports whether another process holds the device open",
] as const;

export const OBSERVE_SERIAL_PORT_LIMITATIONS = [
  "rx-only window; no bytes were transmitted. stty opens the device and applies line-discipline settings, so carrier and flow-control side effects on external hardware are possible, but no data was written",
  "hex and printable previews are renderings of the first 256 observed bytes; printable drops non-ASCII bytes and overflow beyond the budget is preserved as text lines in unparsed_lines",
  "An open of the device raises carrier and flow-control lines even though no data was written; the window does not restore the previous line-discipline settings on exit",
] as const;

/** Stty resolution failure the integrator surfaces like a missing tool. */
export const STTY_REMEDIATION =
  "stty configures the line discipline before the receive window; set REA_STTY_PATH to its absolute path when it lives somewhere else";

const resolveSttyPath = (override: string | undefined): string | null => {
  if (override !== undefined) return override;
  const found = STTY_CANDIDATES.find((candidate) => {
    try {
      accessSync(candidate, fsConstants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
  return found ?? null;
};

/** Normalized payload the integrator passes to createAnalysisExecution verbatim. */
export interface SerialListNormalizedResult {
  readonly tools: SerialToolset;
  readonly ports: SerialPortRow[];
  readonly unmatched_port_names: string[];
  readonly unparsed_lines: string[];
  readonly coverage: "complete" | "partial";
}

/** Normalized payload the integrator passes to createAnalysisExecution verbatim. */
export interface SerialObservationNormalizedResult {
  readonly tools: SerialToolset;
  readonly device_path: string;
  readonly baud_rate: number;
  readonly duration_seconds: number;
  readonly bytes_observed: number;
  readonly hex_preview: string | null;
  readonly printable_preview: string | null;
  readonly stop_reason: SerialStopReason;
  readonly stop_detail: string | null;
  readonly unparsed_lines: string[];
  readonly coverage: "complete" | "partial";
}

export type OpenDeviceFailure = {
  readonly code: string | null;
  readonly message: string;
};

/**
 * Read-only device seam: the production implementation uses node:fs with
 * O_RDONLY|O_NOCTTY|O_NONBLOCK and the lane never exposes a write.
 */
export interface SerialDeviceIo {
  readonly open: (
    path: string,
    flags: number,
  ) => Result<number, OpenDeviceFailure>;
  /** "again" models the EAGAIN a non-blocking device read without data raises. */
  readonly read: (fd: number, buffer: Buffer) => number | "again";
  readonly close: (fd: number) => void;
}

const errnoOf = (cause: unknown): string | null =>
  cause instanceof Error &&
  typeof (cause as NodeJS.ErrnoException).code === "string"
    ? ((cause as NodeJS.ErrnoException).code as string)
    : null;

const messageOf = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const defaultDeviceIo: SerialDeviceIo = {
  open: (path, flags) => {
    try {
      return ok(openSync(path, flags));
    } catch (cause: unknown) {
      return err({ code: errnoOf(cause), message: messageOf(cause) });
    }
  },
  read: (fd, buffer) => {
    try {
      return readSync(fd, buffer, 0, buffer.byteLength, null);
    } catch (cause: unknown) {
      if (errnoOf(cause) === "EAGAIN") return "again";
      throw cause;
    }
  },
  close: (fd) => closeSync(fd),
};

export interface SerialExecutionOptions {
  /** Test seam mirroring DiscoveryProviderOptions; production runs the tool. */
  readonly launcher?: DiscoveryProcessLauncher;
  readonly sttyPath?: string;
  readonly deviceIo?: SerialDeviceIo;
  readonly devDirectory?: string;
}

/**
 * Run system_profiler SPPortsDataType and join its verbatim port rows with
 * the /dev serial device nodes into one normalized ports inventory.
 */
export const executeListSerialPorts = async (
  systemProfilerPath: string,
  signal?: AbortSignal,
  options: SerialExecutionOptions = {},
): Promise<Result<SerialListNormalizedResult, AnalysisError>> => {
  const ran = await runDiscoveryCommand(
    LIST_SERIAL_PORTS_OPERATION,
    systemProfilerPath,
    ["SPPortsDataType", "-json"],
    { timeoutMs: LIST_TIMEOUT_MS },
    signal,
    options.launcher,
  );
  if (!ran.ok) return ran;
  const parsed = parseSystemProfilerJson(ran.value.stdout);
  if (!parsed.ok)
    return err(
      new AnalysisProtocolError(
        `system_profiler SPPortsDataType was not recognizable: ${
          parsed.reason ?? "no JSON"
        }`,
      ),
    );
  const ports = parseSystemProfilerPorts(parsed.data);
  const devices = parseDevList(options.devDirectory ?? "/dev");
  const joined = joinSerialPorts(ports.items, devices);
  const unparsedLines = [...ports.unparsedLines];
  return ok({
    tools: { system_profiler: systemProfilerPath, stty: null },
    ports: joined.ports,
    unmatched_port_names: joined.unmatchedPortNames,
    unparsed_lines: unparsedLines,
    coverage:
      unparsedLines.length > 0 ? ("partial" as const) : ("complete" as const),
  });
};

/**
 * Configure the device's line discipline with stty, then observe its receive
 * side for the requested window: non-blocking bounded reads, stopping early
 * on close, read error or cancellation. The device is never written.
 */
export const executeObserveSerialPort = async (
  input: ObserveSerialPortInput,
  signal?: AbortSignal,
  options: SerialExecutionOptions = {},
): Promise<Result<SerialObservationNormalizedResult, AnalysisError>> => {
  if (signal?.aborted === true)
    return err(
      new AnalysisCancelledError(OBSERVE_SERIAL_PORT_OPERATION, {
        cause: signal.reason,
      }),
    );
  const sttyPath = resolveSttyPath(options.sttyPath);
  if (sttyPath === null)
    return err(
      new ProviderAdapterError(
        DISCOVERY_PROVIDER_ID,
        OBSERVE_SERIAL_PORT_OPERATION,
        {
          userMessage: `No stty was found at ${STTY_CANDIDATES.join(" or ")}. ${STTY_REMEDIATION}`,
        },
      ),
    );
  const deviceIo = options.deviceIo ?? defaultDeviceIo;
  const configured = await runDiscoveryCommand(
    OBSERVE_SERIAL_PORT_OPERATION,
    sttyPath,
    serialSttyArguments(input.device_path, input.baud_rate),
    { timeoutMs: STTY_TIMEOUT_MS },
    signal,
    options.launcher,
  );
  if (!configured.ok) return configured;

  const opened = deviceIo.open(
    input.device_path,
    fsConstants.O_RDONLY | fsConstants.O_NOCTTY | fsConstants.O_NONBLOCK,
  );
  if (!opened.ok)
    return err(
      new AnalysisInputError(OBSERVE_SERIAL_PORT_OPERATION, {
        userMessage: `The device ${input.device_path} could not be opened read-only${
          opened.error.code === null ? "" : ` (${opened.error.code})`
        }: ${opened.error.message}. No bytes were written to it.`,
      }),
    );

  const fd = opened.value;
  const chunks: Buffer[] = [];
  let bytesObserved = 0;
  let stopReason: SerialStopReason = "deadline";
  let stopDetail: string | null = null;
  const deadline = Date.now() + input.duration_seconds * 1000;
  const buffer = Buffer.allocUnsafe(OBSERVE_CHUNK_BYTES);
  const isAborted = (): boolean => signal?.aborted ?? false;
  try {
    readLoop: while (Date.now() < deadline) {
      if (bytesObserved >= OBSERVE_MAX_BYTES) {
        stopReason = "byte_bound";
        stopDetail = `The receive window exceeded the ${String(OBSERVE_MAX_BYTES)}-byte retained-byte bound`;
        break;
      }
      if (isAborted()) {
        stopReason = "cancelled";
        stopDetail = "The caller's signal aborted the receive window";
        break;
      }
      let read: number | "again";
      try {
        read = deviceIo.read(fd, buffer);
      } catch (cause: unknown) {
        stopReason = "read_error";
        stopDetail =
          errnoOf(cause) === null
            ? messageOf(cause)
            : `${errnoOf(cause)}: ${messageOf(cause)}`;
        break readLoop;
      }
      if (read === "again") {
        await sleep(OBSERVE_POLL_MS);
        continue;
      }
      if (read === 0) {
        stopReason = "closed";
        stopDetail = "The device was closed before the window elapsed";
        break;
      }
      if (read > 0) {
        chunks.push(Buffer.from(buffer.subarray(0, read)));
        bytesObserved += read;
      }
    }
  } finally {
    try {
      deviceIo.close(fd);
    } catch (cause: unknown) {
      if (stopDetail === null) stopDetail = `close failed: ${messageOf(cause)}`;
    }
  }
  if (stopReason === "cancelled")
    return err(
      new AnalysisCancelledError(OBSERVE_SERIAL_PORT_OPERATION, {
        cause: signal?.reason,
      }),
    );

  const observed = Buffer.concat(chunks, bytesObserved);
  const truncated = observed.byteLength > SERIAL_PREVIEW_BYTE_LIMIT;
  return ok({
    tools: { system_profiler: null, stty: sttyPath },
    device_path: input.device_path,
    baud_rate: input.baud_rate,
    duration_seconds: input.duration_seconds,
    bytes_observed: bytesObserved,
    hex_preview: renderHexPreview(observed),
    printable_preview: renderPrintablePreview(observed),
    stop_reason: stopReason,
    stop_detail: stopDetail,
    unparsed_lines: renderOverflowLines(observed),
    coverage:
      stopReason === "deadline" && !truncated
        ? ("complete" as const)
        : ("partial" as const),
  });
};
