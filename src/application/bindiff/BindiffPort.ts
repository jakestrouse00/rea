import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  BinaryDiffResult,
  ExportBinexportResult,
} from "../../domain/bindiff/binaryDiff.js";
import type { Result } from "../../domain/result.js";
import type {
  BinaryDiffRequest,
  BinexportRequest,
} from "../../bindiff/BindiffProvider.js";

/** Provider-backed binary comparison and BinExport export. */
export interface BindiffPort {
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  inspectDiffAvailability?(
    signal?: AbortSignal,
  ): ProviderAvailability | Promise<ProviderAvailability>;
  inspectExportAvailability?(
    signal?: AbortSignal,
  ): ProviderAvailability | Promise<ProviderAvailability>;
  close(): Promise<void>;
  diff(
    request: BinaryDiffRequest,
    options?: ExecutionOptions,
  ): Promise<Result<BinaryDiffResult, AnalysisError>>;
  exportBinexport(
    request: BinexportRequest,
    options?: ExecutionOptions,
  ): Promise<Result<ExportBinexportResult, AnalysisError>>;
}
