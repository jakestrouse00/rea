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
  inspectWindowsMinidumpInputSchema,
  type InspectWindowsMinidumpInput,
  type WindowsMinidump,
} from "../domain/windowsArtifacts/windowsMinidump.js";
import {
  MINIDUMP_INPUT_BYTES,
  parseWindowsMinidump,
} from "./WindowsMinidump.js";
import { windowsArtifactFailure } from "./WindowsArtifactFailures.js";

/** Bundled offline reader identity; no engine installation is involved. */
export const WINDOWS_MINIDUMP_PROVIDER_IDENTITY = {
  id: "windows-minidump",
  name: "REA Windows minidump reader",
  version: "1",
} as const;
export const OPERATION = "inspect_windows_minidump";

/** Offline minidump structural reader; bounded, no target execution. */
export class WindowsMinidumpProvider {
  readonly resources = new ArtifactResourceScope();

  get identity(): {
    readonly id: string;
    readonly name: string;
    readonly version: string;
  } {
    return WINDOWS_MINIDUMP_PROVIDER_IDENTITY;
  }

  async inspect(
    input: InspectWindowsMinidumpInput,
    options?: ExecutionOptions,
  ): Promise<Result<WindowsMinidump, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const inputCheck = inspectWindowsMinidumpInputSchema.safeParse(input);
    if (!inputCheck.success)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: "Expected an absolute minidump path.",
          },
        ]),
      );
    try {
      const snapshot = await readStableArtifact(
        inputCheck.data.path,
        MINIDUMP_INPUT_BYTES,
        options?.signal,
        undefined,
        this.resources,
      );
      return ok(parseWindowsMinidump(snapshot, inputCheck.data));
    } catch (cause: unknown) {
      return err(
        windowsArtifactFailure(
          OPERATION,
          WINDOWS_MINIDUMP_PROVIDER_IDENTITY.id,
          cause,
          inputCheck.data.path,
          MINIDUMP_INPUT_BYTES,
        ),
      );
    }
  }

  close(): Promise<void> {
    return this.resources.close();
  }
}
