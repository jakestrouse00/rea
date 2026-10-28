import {
  ANGR_DIAGNOSTIC_EXCERPT_BYTES,
  ANGR_LIMITS,
  ANGR_PROTOCOL_VERSION,
  ANGR_PROVIDER_ID,
} from "../domain/angr/angrLimits.js";
import { runSidecarBridgeJob } from "../process/SidecarBridgeJob.js";
import type { AngrConfiguration } from "./AngrConfiguration.js";

export interface AngrBridgeJobInput {
  readonly configuration: AngrConfiguration;
  readonly operation: string;
  /** One protocol request without the envelope REA adds. */
  readonly body: Readonly<Record<string, unknown>>;
  readonly timeoutMs: number;
  readonly hostEnvironment: Readonly<Record<string, string | undefined>>;
  readonly signal?: AbortSignal;
}

/** Run one bounded job through its own supervised angr sidecar process. */
export const runAngrBridgeJob = (input: AngrBridgeJobInput): Promise<unknown> =>
  runSidecarBridgeJob({
    providerId: ANGR_PROVIDER_ID,
    providerLabel: "angr",
    operation: input.operation,
    command: input.configuration.python,
    arguments: ["-I", "-B", input.configuration.bridgeScript],
    protocol: ANGR_PROTOCOL_VERSION,
    body: input.body,
    timeoutMs: input.timeoutMs,
    stopGraceMs: ANGR_LIMITS.stopGraceMs,
    maxFrameBytes: ANGR_LIMITS.maxBridgeLineBytes,
    diagnosticExcerptBytes: ANGR_DIAGNOSTIC_EXCERPT_BYTES,
    resourceTag: "angr-bridge-job",
    hostEnvironment: input.hostEnvironment,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
