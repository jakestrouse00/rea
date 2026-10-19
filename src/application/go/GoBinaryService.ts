import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { GoBinaryPort } from "./GoBinaryPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { BINARY_ARCHITECTURES } from "../../domain/binaryTargetTypes.js";
import {
  goBinarySchema,
  goProcedureTableSchema,
  inspectGoBinaryInputSchema,
  inspectGoProcedureTableInputSchema,
} from "../../domain/go/goBinary.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const INSPECT_OPERATION = "inspect_go_binary";
const PROCEDURE_TABLE_OPERATION = "inspect_go_procedure_table";
const architectureForSubject = (architecture: string) => {
  switch (architecture) {
    case "386":
      return "x86";
    case "amd64":
      return "x86_64";
    default:
      return BINARY_ARCHITECTURES.find(
        (supported) => supported === architecture,
      );
  }
};

/** Shared exact input validation and artifact-bound Evidence for CLI and MCP. */
export class GoBinaryService {
  constructor(readonly provider: GoBinaryPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  /** Inspect one explicitly selected file without acquiring a binary session. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(INSPECT_OPERATION, {
          cause: options.signal.reason,
        }),
      );
    const input = inspectGoBinaryInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(
          INSPECT_OPERATION,
          input.error.issues,
          rawInput,
          {
            cause: input.error,
          },
        ),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(INSPECT_OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    const report = goBinarySchema.safeParse(inspected.value);
    if (!report.success || report.data.artifact.path !== input.data.path)
      return err(
        new AnalysisOutputError(
          INSPECT_OPERATION,
          "Go build-information reader returned malformed metadata or changed the selected artifact identity.",
        ),
      );
    const value = report.data;
    const architecture = architectureForSubject(value.architecture);
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: value.format === "macho" ? "mach-o" : value.format,
          ...(architecture === undefined ? {} : { architecture }),
        },
        this.provider.identity,
        {
          operation: INSPECT_OPERATION,
          parameters: input.data,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [
            { kind: "artifact-path", path: value.artifact.path },
            ...(value.build_info === null
              ? []
              : [
                  {
                    kind: "file-offset-range" as const,
                    start: value.build_info.header_offset,
                    end: value.build_info.header_offset + 32,
                  },
                ]),
          ],
        },
      ),
      options?.signal,
    );
  }

  /** Page the embedded pclntab procedure table without acquiring a binary session. */
  async procedureTable(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(PROCEDURE_TABLE_OPERATION, {
          cause: options.signal.reason,
        }),
      );
    const input = inspectGoProcedureTableInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(
          PROCEDURE_TABLE_OPERATION,
          input.error.issues,
          rawInput,
          { cause: input.error },
        ),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(PROCEDURE_TABLE_OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const paged = await this.provider.procedureTable(input.data, options);
    if (!paged.ok) return paged;
    const report = goProcedureTableSchema.safeParse(paged.value);
    if (!report.success || report.data.artifact.path !== input.data.path)
      return err(
        new AnalysisOutputError(
          PROCEDURE_TABLE_OPERATION,
          "Go procedure-table reader returned malformed metadata or changed the selected artifact identity.",
        ),
      );
    const value = report.data;
    const architecture = architectureForSubject(value.architecture);
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: value.format === "macho" ? "mach-o" : value.format,
          ...(architecture === undefined ? {} : { architecture }),
        },
        this.provider.identity,
        {
          operation: PROCEDURE_TABLE_OPERATION,
          parameters: input.data,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [
            { kind: "artifact-path", path: value.artifact.path },
            ...(value.pclntab === null
              ? []
              : [
                  {
                    kind: "file-offset-range" as const,
                    start: value.pclntab.location.file_offset,
                    end:
                      value.pclntab.location.file_offset +
                      value.pclntab.location.bytes,
                  },
                ]),
          ],
        },
      ),
      options?.signal,
    );
  }
}
