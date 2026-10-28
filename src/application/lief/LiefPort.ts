import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { BinaryDeepReport } from "../../domain/lief/binaryDeep.js";
import type {
  ExtractPdbDwarfInfoInput,
  PdbDwarfInfoReport,
} from "../../domain/lief/pdbDwarfInfo.js";
import type { Result } from "../../domain/result.js";

/** Provider-neutral seam for the LIEF deep-parse lane. */
export interface LiefPort {
  readonly identity: {
    readonly id: string;
    readonly name: string;
    readonly version: string | null;
  };
  inspectBinaryDeep(
    input: { readonly path: string },
    options?: ExecutionOptions,
  ): Promise<Result<BinaryDeepReport, AnalysisError>>;
  extractPdbDwarfInfo(
    input: ExtractPdbDwarfInfoInput,
    options?: ExecutionOptions,
  ): Promise<Result<PdbDwarfInfoReport, AnalysisError>>;
  close?(): Promise<void>;
}
