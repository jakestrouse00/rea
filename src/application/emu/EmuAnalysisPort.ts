import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { EmuRequest } from "../../domain/emu/emuEmulation.js";
import type { Result } from "../../domain/result.js";

/**
 * Bounded Unicorn emulation and Keystone assembly through the caller-managed
 * sidecar. Each request owns one process; implementation details belong to the
 * provider adapter.
 */
export interface EmuAnalysisPort {
  /** Report the caller's selection without starting the sidecar. */
  inspectAvailability(): ProviderAvailability;
  /** Stop admission; every job owns its process, so nothing is retained. */
  close(): Promise<void>;
  execute(
    request: EmuRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
