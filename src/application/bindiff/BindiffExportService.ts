import type { BindiffPort } from "./BindiffPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { exportBinexportRequestSchema } from "../../domain/bindiff/binaryDiff.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import { executeProviderOperation } from "../ProviderOperationExecution.js";
import { BINDIFF_PROVIDER_IDENTITY } from "../../bindiff/BindiffProvider.js";

/** Shared admission, execution, and Evidence composition for BinExport. */
export class BindiffExportService {
  constructor(readonly provider: BindiffPort) {}

  async execute(
    operation: string,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeProviderOperation(
      operation,
      input,
      options,
      exportBinexportRequestSchema,
      {
        execute: async (request, executionOptions) => {
          const exported = await this.provider.exportBinexport(
            {
              path: request.input.path,
              outputDirectory: request.input.output_directory,
            },
            executionOptions,
          );
          if (!exported.ok) return exported;
          return {
            ok: true as const,
            value: {
              result: exported.value,
              rawResult: null,
              provider: BINDIFF_PROVIDER_IDENTITY,
              limitations: [
                "The published .BinExport file is REA's structural digest of the exporter's output, not an attestation of the exporter build",
                "A BinExport file is a static function inventory; it is not behavioral equivalence",
              ],
              locations: [
                { kind: "artifact-path" as const, path: request.input.path },
              ],
            },
          };
        },
      },
      "observed",
    );
  }
}
