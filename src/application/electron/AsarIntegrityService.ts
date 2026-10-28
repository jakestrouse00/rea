import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AsarIntegrityPort } from "./AsarIntegrityPort.js";
import {
  asarIntegrityReportSchema,
  inspectAsarIntegrityInputSchema,
} from "../../domain/electron/asarIntegrity.js";
import { createAsarIntegrityEvidence } from "../../domain/electron/asarIntegrityEvidence.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

const OPERATION = "inspect_asar_integrity";

/** Shared exact input validation and artifact-bound Evidence for CLI and MCP. */
export class AsarIntegrityService {
  constructor(readonly provider: AsarIntegrityPort) {}

  /** Await and retry the reader's exact retained descriptor owners. */
  async close(): Promise<void> {
    await this.provider.close?.();
  }

  /** Check one explicitly selected archive without extracting or launching it. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const input = inspectAsarIntegrityInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    const report = asarIntegrityReportSchema.safeParse(inspected.value);
    if (
      !report.success ||
      report.data.path !== input.data.path ||
      report.data.sha256 !== inspected.value.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "ASAR integrity reader returned a malformed report or changed the selected artifact identity.",
        ),
      );
    return completeProviderEvidence(
      createAsarIntegrityEvidence(
        input.data,
        report.data,
        this.provider.identity,
      ),
      options?.signal,
    );
  }
}
