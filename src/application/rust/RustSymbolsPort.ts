import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  InspectRustSymbolsInput,
  RustSymbolsReport,
} from "../../domain/rust/rustBinary.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline symbol-table reader with no target-execution authority. */
export interface RustSymbolsPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  symbols(
    input: InspectRustSymbolsInput,
    options?: ExecutionOptions,
  ): Promise<Result<RustSymbolsReport, AnalysisError>>;
}
