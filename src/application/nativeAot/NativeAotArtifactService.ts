import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { NativeAotPort } from "./NativeAotPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  BINARY_ARCHITECTURES,
  type BinaryArchitecture,
} from "../../domain/binaryTargetTypes.js";
import {
  inspectNativeAotTypesInputSchema,
  nativeAotArtifactInspectionSchema,
  type NativeAotArtifactInspection,
} from "../../domain/managed/nativeAotArtifact.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "inspect_nativeaot_types";
/** Bounded default page; callers override through the contract's offset/limit. */
const DEFAULT_PAGE_OFFSET = 0;
const DEFAULT_PAGE_LIMIT = 200;

/** Shared exact input validation, paging, and artifact-bound Evidence for CLI and MCP. */
export class NativeAotArtifactService {
  constructor(readonly provider: NativeAotPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  /**
   * Inspect one explicitly selected PE artifact for the documented
   * NativeAOT/ReadyToRun structures, returning one paged window of rows.
   */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const input = inspectNativeAotTypesInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const requested = input.data;
    const parameters: Readonly<Record<string, JsonValue>> = {
      path: requested.path,
      ...(requested.offset === undefined ? {} : { offset: requested.offset }),
      ...(requested.limit === undefined ? {} : { limit: requested.limit }),
    };
    const inspected = await this.provider.inspect(
      { path: requested.path },
      options,
    );
    if (!inspected.ok) return inspected;
    const paged = pageNativeAotRows(
      inspected.value,
      (value) => value.artifact.path === requested.path,
      requested.offset ?? DEFAULT_PAGE_OFFSET,
      requested.limit ?? DEFAULT_PAGE_LIMIT,
    );
    if (!paged.ok)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "NativeAOT structural reader returned malformed metadata or changed the selected artifact identity.",
          { cause: paged.error },
        ),
      );
    const value = paged.value;
    const architecture = BINARY_ARCHITECTURES.find(
      (candidate): candidate is BinaryArchitecture =>
        candidate === value.pe?.architecture,
    );
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: "pe",
          ...(architecture === undefined ? {} : { architecture }),
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [
            { kind: "artifact-path", path: value.artifact.path },
            ...(value.readytorun_header === null
              ? []
              : [
                  {
                    kind: "file-offset-range" as const,
                    start: value.readytorun_header.file_offset,
                    end: value.readytorun_header.file_offset + 16,
                  },
                ]),
          ],
        },
      ),
      options?.signal,
    );
  }
}

/**
 * Apply caller paging to one complete inspection, preserving exact rows,
 * row indexes, totals, and limitations from the owned parser output. While
 * coverage reports truncation (rows beyond the parser's row budget were
 * omitted), `paging.complete` stays false on every page, including the last
 * retained page.
 */
export const pageNativeAotRows = (
  inspection: unknown,
  identity: (value: NativeAotArtifactInspection) => boolean,
  offset: number,
  limit: number,
): Result<NativeAotArtifactInspection, unknown> => {
  const parsed = nativeAotArtifactInspectionSchema.safeParse(inspection);
  if (!parsed.success || !identity(parsed.data))
    return err(parsed.success ? "identity-changed" : parsed.error);
  const complete = parsed.data;
  if (offset < 0 || limit < 1) return err("invalid page bounds");
  const total = complete.paging.total_rows;
  const safeOffset = Math.max(0, Math.min(offset, total));
  const rows = complete.rows.slice(safeOffset, safeOffset + limit);
  return ok(
    nativeAotArtifactInspectionSchema.parse({
      ...complete,
      rows,
      paging: {
        offset: safeOffset,
        limit,
        total_rows: total,
        returned_rows: rows.length,
        complete:
          !complete.coverage.truncated && safeOffset + rows.length >= total,
      },
    }),
  );
};
