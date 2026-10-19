import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  inspectWerReportInputSchema,
  type InspectWerReportInput,
  type WerReport,
} from "../domain/windowsArtifacts/werReport.js";
import {
  WER_INPUT_BYTES,
  parseWindowsWerReport,
  WerFormatFailure,
} from "./WindowsWer.js";
import { windowsArtifactFailure } from "./WindowsArtifactFailures.js";

/** Bundled offline text reader identity; no target or report is executed. */
export const WINDOWS_WER_PROVIDER_IDENTITY = {
  id: "windows-wer-report",
  name: "REA Windows Error Reporting reader",
  version: "1",
} as const;
export const OPERATION = "inspect_wer_report";

/** Offline WER text reader; bounded, redaction-free, no value inference. */
export class WindowsWerProvider {
  readonly resources = new ArtifactResourceScope();

  get identity(): {
    readonly id: string;
    readonly name: string;
    readonly version: string;
  } {
    return WINDOWS_WER_PROVIDER_IDENTITY;
  }

  async inspect(
    input: InspectWerReportInput,
    options?: ExecutionOptions,
  ): Promise<Result<WerReport, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const inputCheck = inspectWerReportInputSchema.safeParse(input);
    if (!inputCheck.success)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: "Expected an absolute .wer report path.",
          },
        ]),
      );
    try {
      const snapshot = await readStableArtifact(
        inputCheck.data.path,
        WER_INPUT_BYTES,
        options?.signal,
        undefined,
        this.resources,
      );
      return ok(parseWindowsWerReport(snapshot, inputCheck.data));
    } catch (cause: unknown) {
      if (cause instanceof WerFormatFailure)
        return err(
          new AnalysisInputError(OPERATION, { cause }, [
            {
              path: ["path"],
              reason: "invalid_format",
              message: `Selected artifact ${inputCheck.data.path}: ${cause.message}`,
            },
          ]),
        );
      return err(
        windowsArtifactFailure(
          OPERATION,
          WINDOWS_WER_PROVIDER_IDENTITY.id,
          cause,
          inputCheck.data.path,
          WER_INPUT_BYTES,
        ),
      );
    }
  }

  close(): Promise<void> {
    return this.resources.close();
  }
}
