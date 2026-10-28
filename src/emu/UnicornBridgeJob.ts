import {
  EMU_DIAGNOSTIC_EXCERPT_BYTES,
  EMU_LIMITS,
  EMU_PROTOCOL_VERSION,
  EMU_PROVIDER_ID,
} from "../domain/emu/emuLimits.js";
import { runSidecarBridgeJob } from "../process/SidecarBridgeJob.js";
import type { EmuConfiguration } from "./EmuConfiguration.js";

export {
  SidecarBridgeProtocolFailure as UnicornBridgeProtocolFailure,
  type SidecarBridgeJobInput,
} from "../process/SidecarBridgeJob.js";

export interface UnicornBridgeJobInput {
  readonly configuration: EmuConfiguration;
  readonly operation: string;
  /** One protocol request without the envelope REA adds. */
  readonly body: Readonly<Record<string, unknown>>;
  readonly timeoutMs: number;
  readonly hostEnvironment: Readonly<Record<string, string | undefined>>;
  readonly signal?: AbortSignal;
}

/** Run one bounded job through its own supervised Unicorn sidecar process. */
export const runUnicornBridgeJob = (
  input: UnicornBridgeJobInput,
): Promise<unknown> =>
  runSidecarBridgeJob({
    providerId: EMU_PROVIDER_ID,
    providerLabel: "Unicorn",
    operation: input.operation,
    command: input.configuration.python,
    arguments: ["-I", "-B", input.configuration.bridgeScript],
    protocol: EMU_PROTOCOL_VERSION,
    body: input.body,
    timeoutMs: input.timeoutMs,
    stopGraceMs: EMU_LIMITS.stopGraceMs,
    maxFrameBytes: EMU_LIMITS.maxBridgeLineBytes,
    diagnosticExcerptBytes: EMU_DIAGNOSTIC_EXCERPT_BYTES,
    resourceTag: "emu-bridge-job",
    hostEnvironment: input.hostEnvironment,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
