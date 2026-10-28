import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { MobileToolchainRequest } from "../../domain/mobile/mobileToolchain.js";
import type { Result } from "../../domain/result.js";

/** The lanes this family can report readiness for. */
export type MobileToolchainLane = "objection" | "androguard" | "ileapp";

/**
 * Caller-supplied mobile runtime and forensics toolchain. Every lane is a
 * subprocess over a caller-selected launcher; REA never installs, links, or
 * upgrades these projects.
 */
export interface MobileToolchainPort {
  /** Probe one lane's selected launcher without reading a target. */
  inspectAvailability(
    lane: MobileToolchainLane,
    signal?: AbortSignal,
  ): Promise<ProviderAvailability>;
  /** Terminally stop admission and drain owned work. */
  close(): Promise<void>;
  execute(
    request: MobileToolchainRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
