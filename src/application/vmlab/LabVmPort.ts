import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";

/** Caller-selected host directory that becomes the guest workspace. */
export interface LabVmStartRequest {
  readonly workspacePath: string;
}

/** One guest command in an already-started lab VM. */
export interface LabVmRunRequest {
  readonly sessionId: string;
  readonly command: string;
  readonly timeoutMs: number;
}

/** Stop one lab VM by its issued session identity. */
export interface LabVmStopRequest {
  readonly sessionId: string;
}

/**
 * Session-owned lab VM lifecycle.
 *
 * Each operation returns the Evidence it observed: boot and guest-command
 * exit facts, and the workspace paths the command created, modified, or
 * removed. Output text itself stays on the host and is never published.
 */
export interface LabVmPort {
  /** Deadline applied when the caller omits `command_timeout_ms`. */
  readonly defaultCommandTimeoutMs: number;
  inspectAvailability(signal?: AbortSignal): ProviderAvailability;
  start(
    request: LabVmStartRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  run(
    request: LabVmRunRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  stop(
    request: LabVmStopRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  /** Remove every owned instance during server shutdown. */
  closeAll(): Promise<Result<null, AnalysisError>>;
}
