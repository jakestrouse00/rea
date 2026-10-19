import { isAbsolute } from "node:path";
import { z } from "zod";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectPdbSymbolsInputSchema,
  pdbSymbolsSchema,
  type PdbSymbols,
} from "../../domain/windowsArtifacts/pdbSymbols.js";
import {
  inspectWerReportInputSchema,
  werReportSchema,
  type WerReport,
} from "../../domain/windowsArtifacts/werReport.js";
import {
  inspectWindowsMinidumpInputSchema,
  windowsMinidumpSchema,
  type WindowsMinidump,
} from "../../domain/windowsArtifacts/windowsMinidump.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import type {
  PdbSymbolsPort,
  WerReportPort,
  WindowsMinidumpPort,
} from "./WindowsArtifactsPort.js";

const MINIDUMP_OPERATION = "inspect_windows_minidump";
const WER_OPERATION = "inspect_wer_report";
const PDB_OPERATION = "inspect_pdb_symbols";

type PathSchema = z.ZodType<{ path: string }>;

/**
 * Shared exact input validation and artifact-bound Evidence for CLI and MCP.
 * Every operation keeps the caller's selected path, records its own parser's
 * typed reports, and treats the artifact digest as binding identity.
 */
export class WindowsArtifactsService {
  constructor(
    readonly minidump: WindowsMinidumpPort,
    readonly wer: WerReportPort,
    readonly pdb: PdbSymbolsPort,
  ) {}

  close(): Promise<void> {
    return Promise.all([
      this.minidump.close?.(),
      this.wer.close?.(),
      this.pdb.close?.(),
    ]).then(() => undefined);
  }

  /** Inspect one explicitly selected minidump without acquiring any session. */
  async inspectMinidump(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = MINIDUMP_OPERATION;
    const path = validateInput(
      operation,
      inspectWindowsMinidumpInputSchema,
      rawInput,
      options,
    );
    if (typeof path !== "string") return path;
    const inspected = await this.minidump.inspect({ path }, options);
    if (!inspected.ok) return inspected;
    const report = windowsMinidumpSchema.safeParse(inspected.value);
    if (!report.success || report.data.artifact.path !== path)
      return malformedOutput(operation);
    const value: WindowsMinidump = report.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: "file",
        },
        this.minidump.identity,
        {
          operation,
          parameters: { path },
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [
            { kind: "artifact-path", path: value.artifact.path },
            ...value.streams.map((stream) => ({
              kind: "file-offset-range" as const,
              start: stream.location.rva,
              end: stream.location.rva + stream.location.data_size,
            })),
          ],
        },
      ),
      options?.signal,
    );
  }

  /** Inspect one explicitly selected WER report without redacting its text. */
  async inspectWerReport(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = WER_OPERATION;
    const path = validateInput(
      operation,
      inspectWerReportInputSchema,
      rawInput,
      options,
    );
    if (typeof path !== "string") return path;
    const inspected = await this.wer.inspect({ path }, options);
    if (!inspected.ok) return inspected;
    const report = werReportSchema.safeParse(inspected.value);
    if (!report.success || report.data.artifact.path !== path)
      return malformedOutput(operation);
    const value: WerReport = report.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: "file",
        },
        this.wer.identity,
        {
          operation,
          parameters: { path },
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
      options?.signal,
    );
  }

  /** Dump one explicitly selected PDB through the caller's llvm-pdbutil. */
  async inspectPdbSymbols(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = PDB_OPERATION;
    const path = validateInput(
      operation,
      inspectPdbSymbolsInputSchema,
      rawInput,
      options,
    );
    if (typeof path !== "string") return path;
    const inspected = await this.pdb.inspect({ path }, options);
    if (!inspected.ok) return inspected;
    const report = pdbSymbolsSchema.safeParse(inspected.value);
    if (!report.success || report.data.artifact.path !== path)
      return malformedOutput(operation);
    const value: PdbSymbols = report.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: "file",
        },
        this.pdb.identity,
        {
          operation,
          parameters: { path },
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

const validateInput = (
  operation: string,
  schema: PathSchema,
  rawInput: unknown,
  options?: ExecutionOptions,
): string | Result<never, AnalysisError> => {
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
  return input.data.path;
};

const malformedOutput = (operation: string): Result<never, AnalysisError> =>
  err(
    new AnalysisOutputError(
      operation,
      "Provider returned malformed metadata or changed the selected artifact identity.",
    ),
  );
