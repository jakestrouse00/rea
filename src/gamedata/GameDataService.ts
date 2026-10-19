import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import { createAnalysisExecutionEvidence } from "../application/AnalysisProvider.js";
import { completeProviderEvidence } from "../application/ProviderOperationExecution.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import {
  gamedataInputSchemas,
  type GamedataOperation,
} from "../domain/gamedata/gamedataRequests.js";
import type { Evidence } from "../domain/evidence.js";
import { err, type Result } from "../domain/result.js";
import type { GamedataRequest } from "../domain/gamedata/gamedataRequests.js";
import type { GameDataPort } from "./GameDataPort.js";
import { isAbsolute } from "node:path";

/** Shared CLI/MCP admission, execution, and Evidence composition for game data. */
export class GameDataService {
  constructor(readonly provider: GameDataPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  /** Run one caller-selected game-data request and retain its Evidence. */
  async execute(
    operation: GamedataOperation,
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const schema = gamedataInputSchemas[operation];
    const input = schema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(operation, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const selected = input.data as {
      path?: string;
      directory?: string;
      extract?: { output_directory?: string };
    };
    const absoluteIssue = absolutePathIssue(operation, selected);
    if (absoluteIssue !== null) return err(absoluteIssue);
    const executed = await this.provider.execute(
      { operation, input: input.data } as unknown as GamedataRequest,
      options,
    );
    if (!executed.ok) return executed;
    const evidence = createAnalysisExecutionEvidence(
      operation,
      input.data,
      executed.value,
      "observed",
    );
    return completeProviderEvidence(evidence, options?.signal);
  }
}

const absolutePathIssue = (
  operation: GamedataOperation,
  selected: {
    path?: string;
    directory?: string;
    extract?: { output_directory?: string };
  },
): AnalysisInputError | null => {
  const target = selected.directory ?? selected.path;
  if (target !== undefined && !isAbsolute(target))
    return inputIssue(
      operation,
      "path",
      "Expected an absolute filesystem path on this host.",
    );
  if (selected.extract !== undefined) {
    if (selected.extract.output_directory === undefined)
      return inputIssue(
        operation,
        "extract.output_directory",
        "Extraction requires an absolute output directory.",
      );
    if (!isAbsolute(selected.extract.output_directory))
      return inputIssue(
        operation,
        "extract.output_directory",
        "Expected an absolute output directory on this host.",
      );
  }
  return null;
};

const inputIssue = (
  operation: GamedataOperation,
  path: string,
  message: string,
): AnalysisInputError =>
  new AnalysisInputError(operation, undefined, [
    { path: path.split("."), reason: "invalid_format", message },
  ]);
