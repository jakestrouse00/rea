import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { SymbolRecoveryRequest } from "../../domain/symbols/symbolRecovery.js";
import type { Result } from "../../domain/result.js";

/**
 * Symbol recovery over caller-selected GoReSym, rustfilt, and dump_syms
 * binaries. Implementation details belong to the provider adapter.
 */
export interface SymbolRecoveryPort {
  /** Probe every tool this provider can run without starting one. */
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  /** Probe one tool's exact executable selection when the adapter supports it. */
  inspectToolAvailability?(
    tool: "recover_go_symbols" | "demangle_rust_name" | "generate_symbol_table",
    signal?: AbortSignal,
  ): ProviderAvailability | Promise<ProviderAvailability>;
  /** Terminally stop admission, drain work, and release retained descriptors. */
  close(): Promise<void>;
  execute(
    request: SymbolRecoveryRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
