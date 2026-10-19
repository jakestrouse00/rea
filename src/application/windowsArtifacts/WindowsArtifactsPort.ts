import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";
import type {
  InspectPdbSymbolsInput,
  PdbSymbols,
} from "../../domain/windowsArtifacts/pdbSymbols.js";
import type {
  InspectWerReportInput,
  WerReport,
} from "../../domain/windowsArtifacts/werReport.js";
import type {
  InspectWindowsMinidumpInput,
  WindowsMinidump,
} from "../../domain/windowsArtifacts/windowsMinidump.js";

/** Replaceable offline Windows-artifact readers with no target-execution authority. */
export interface WindowsMinidumpPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectWindowsMinidumpInput,
    options?: ExecutionOptions,
  ): Promise<Result<WindowsMinidump, AnalysisError>>;
}

export interface WerReportPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectWerReportInput,
    options?: ExecutionOptions,
  ): Promise<Result<WerReport, AnalysisError>>;
}

export interface PdbSymbolsPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectPdbSymbolsInput,
    options?: ExecutionOptions,
  ): Promise<Result<PdbSymbols, AnalysisError>>;
}
