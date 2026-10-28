import { isAbsolute } from "node:path";
import type { z } from "zod";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import {
  binaryDeepReportSchema,
  inspectBinaryDeepInputSchema,
  type BinaryDeepReport,
} from "../../domain/lief/binaryDeep.js";
import {
  extractPdbDwarfInfoInputSchema,
  pdbDwarfInfoReportSchema,
  type PdbDwarfInfoReport,
} from "../../domain/lief/pdbDwarfInfo.js";
import { err, ok, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import type { LiefPort } from "./LiefPort.js";

const DEEP_PARSE_OPERATION = "inspect_binary_deep";
const PDB_DWARF_OPERATION = "extract_pdb_dwarf_info";

/**
 * Shared exact input validation and artifact-bound Evidence for CLI and MCP.
 * Every operation preserves the caller's path and treats the artifact digest as
 * binding identity.
 */
export class LiefService {
  constructor(readonly provider: LiefPort) {}

  close(): Promise<void> {
    return Promise.resolve(this.provider.close?.()).then(() => undefined);
  }

  /** Report one binary's LIEF-unique cross-format structure. */
  async inspectBinaryDeep(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = DEEP_PARSE_OPERATION;
    const input = validateInput(
      operation,
      inspectBinaryDeepInputSchema,
      rawInput,
      options,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspectBinaryDeep(
      { path: input.value.path },
      options,
    );
    if (!inspected.ok) return inspected;
    const report = binaryDeepReportSchema.safeParse(inspected.value);
    if (!report.success || report.data.artifact.path !== input.value.path)
      return malformedOutput(operation);
    const value: BinaryDeepReport = report.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: "file",
        },
        this.provider.identity,
        {
          operation,
          parameters: { path: input.value.path },
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [
            { kind: "artifact-path", path: value.artifact.path },
            ...value.architectures.flatMap((architecture) =>
              architecture.offset === null || architecture.size === null
                ? []
                : [
                    {
                      kind: "file-offset-range" as const,
                      start: architecture.offset,
                      end: architecture.offset + architecture.size,
                    },
                  ],
            ),
          ],
        },
      ),
      options?.signal,
    );
  }

  /** Report one artifact's PDB and DWARF surfaces plus bounded lookups. */
  async extractPdbDwarfInfo(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = PDB_DWARF_OPERATION;
    const input = validateInput(
      operation,
      extractPdbDwarfInfoInputSchema,
      rawInput,
      options,
    );
    if (!input.ok) return input;
    const inspected = await this.provider.extractPdbDwarfInfo(
      input.value,
      options,
    );
    if (!inspected.ok) return inspected;
    const report = pdbDwarfInfoReportSchema.safeParse(inspected.value);
    if (!report.success || report.data.artifact.path !== input.value.path)
      return malformedOutput(operation);
    const value: PdbDwarfInfoReport = report.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: "file",
        },
        this.provider.identity,
        {
          operation,
          parameters: {
            path: input.value.path,
            ...(input.value.queries === undefined
              ? {}
              : { queries: input.value.queries }),
          },
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
      options?.signal,
    );
  }
}

const validateInput = <Input extends { readonly path: string }>(
  operation: string,
  schema: z.ZodType<Input>,
  rawInput: unknown,
  options?: ExecutionOptions,
): Result<Input, AnalysisError> => {
  if (options?.signal?.aborted)
    return err(
      new AnalysisCancelledError(operation, { cause: options.signal.reason }),
    );
  const input = schema.safeParse(rawInput);
  if (!input.success)
    return err(
      analysisInputErrorFromIssues(operation, input.error.issues, rawInput, {
        cause: input.error,
      }),
    );
  if (!isAbsolute(input.data.path))
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: "Expected an absolute filesystem path on this host.",
        },
      ]),
    );
  return ok(input.data);
};

const malformedOutput = (operation: string): Result<never, AnalysisError> =>
  err(
    new AnalysisOutputError(
      operation,
      "Provider returned malformed metadata or changed the selected artifact identity.",
    ),
  );
