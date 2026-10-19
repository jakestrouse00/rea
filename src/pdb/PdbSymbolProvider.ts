import { stat } from "node:fs/promises";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  inspectPdbSymbolsInputSchema,
  type InspectPdbSymbolsInput,
  type PdbSymbols,
  pdbSymbolsSchema,
} from "../domain/windowsArtifacts/pdbSymbols.js";
import {
  execFileOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { parsePdbDumpText, PdbDumpTextFailure } from "./PdbDumpText.js";
import { readPdbConfiguration } from "./PdbConfiguration.js";
import { PDB_DUMP_REMEDIATION, PDB_PROVIDER_ID } from "./PdbRelease.js";
import { pdbUnavailable } from "./PdbUnavailable.js";

/** Bundled BYO adapter identity; the llvm-pdbutil release is caller-owned. */
export const PDB_PROVIDER_IDENTITY = {
  id: PDB_PROVIDER_ID,
  name: "REA llvm-pdbutil dump reader",
  version: "1",
} as const;
export const OPERATION = "inspect_pdb_symbols";

/** The documented, stable dump face: bounded sections in one invocation. */
export const DUMP_ARGUMENTS = [
  "dump",
  "-summary",
  "-streams",
  "-modules",
  "-files",
  "-symbols",
  "-publics",
] as const;

/** Hash one bounded PDB file as caller evidence; bytes are never executed. */
const hashPdb = async (
  path: string,
): Promise<{ sha256: string; bytes: number }> => {
  const hash = createHash("sha256");
  let bytes = 0;
  const stream = createReadStream(path);
  for await (const chunk of stream) {
    bytes += (chunk as Buffer).length;
    hash.update(chunk as Buffer);
  }
  return { sha256: hash.digest("hex"), bytes };
};

interface DumpRun {
  readonly stdout: string;
  readonly stderr: string;
  readonly exit: number;
  readonly stdout_bytes: number;
  readonly stderr_bytes: number;
}

/** Replaceable command seam; production uses the owned process launcher. */
export type PdbCommandLauncher = (
  command: string,
  arguments_: readonly string[],
  options: {
    readonly timeoutMs: number;
    readonly maximumOutputBytes: number;
    readonly signal: AbortSignal | undefined;
  },
) => Promise<DumpRun>;

const defaultLauncher: PdbCommandLauncher = async (
  command,
  arguments_,
  { timeoutMs, maximumOutputBytes, signal },
) => {
  try {
    const result = await execFileOutput(command, [...arguments_], {
      timeout: timeoutMs,
      maxBuffer: maximumOutputBytes,
      ...(signal === undefined ? {} : { signal }),
    });
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exit: 0,
      stdout_bytes: result.stdoutBytes,
      stderr_bytes: result.stderrBytes,
    };
  } catch (cause: unknown) {
    if (cause instanceof Error && cause.name === "AbortError")
      throw new AnalysisCancelledError(OPERATION, { cause });
    const failure = execFileOutputFailure(cause);
    if (failure !== undefined && failure.outputTruncated)
      throw new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        `llvm-pdbutil output exceeded ${String(maximumOutputBytes)} bytes and was truncated; refusing to report an incomplete symbol table.`,
        { boundary: "memory", maximum_output_bytes: maximumOutputBytes },
        { cause, remediationAction: PDB_DUMP_REMEDIATION },
      );
    if (
      failure !== undefined &&
      typeof failure.code === "number" &&
      failure.code !== 0
    )
      throw pdbUnavailable(
        OPERATION,
        `llvm-pdbutil dump exited nonzero (${String(failure.code)}); stderr: ${failure.stderr.slice(0, 512)}`,
        PDB_DUMP_REMEDIATION,
      );
    const error = new Error(
      `llvm-pdbutil dump failed: ${cause instanceof Error ? cause.message : String(cause)}${
        failure === undefined
          ? ""
          : ` (exit ${failure.code}, stderr ${failure.stderr.length} bytes)`
      }`,
      { cause },
    );
    throw error;
  }
};

/** Offline BYO llvm-pdbutil adapter; bounded runs, no PDB content executed. */
export class PdbSymbolProvider {
  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv>,
    readonly launcher: PdbCommandLauncher = defaultLauncher,
  ) {}

  get identity(): {
    readonly id: string;
    readonly name: string;
    readonly version: string;
  } {
    return PDB_PROVIDER_IDENTITY;
  }

  async inspect(
    rawInput: InspectPdbSymbolsInput | unknown,
    options?: ExecutionOptions,
  ): Promise<Result<PdbSymbols, AnalysisError>> {
    const input = inspectPdbSymbolsInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: "Expected an absolute PDB path.",
          },
        ]),
      );
    const path = input.data.path;
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    const configuration = readPdbConfiguration(this.environment);
    if (!configuration.ok)
      return err(
        pdbUnavailable(
          OPERATION,
          `${configuration.error.reason} ${configuration.error.setting} must name a caller-supplied llvm-pdbutil executable.`,
        ),
      );
    let selected: { sha256: string; bytes: number };
    try {
      const stats = await stat(path);
      if (!stats.isFile())
        return err(
          new AnalysisInputError(OPERATION, undefined, [
            {
              path: ["path"],
              reason: "invalid_value",
              message: `Selected artifact is not a regular file: ${path}`,
            },
          ]),
        );
      selected = await hashPdb(path);
    } catch (cause: unknown) {
      return err(this.fileFailure(cause, path));
    }
    const run = await this.launcher(
      configuration.value.command,
      [...DUMP_ARGUMENTS, path],
      {
        timeoutMs: configuration.value.dumpTimeoutMs,
        maximumOutputBytes: configuration.value.maximumOutputBytes,
        signal: options?.signal,
      },
    ).then(
      (value): Result<DumpRun, AnalysisError> => ok(value),
      (cause: unknown): Result<DumpRun, AnalysisError> =>
        cause instanceof AnalysisError
          ? err(cause)
          : err(
              new ProviderAdapterError(PDB_PROVIDER_ID, OPERATION, { cause }),
            ),
    );
    if (!run.ok) return run;
    if (run.value.exit !== 0)
      return err(
        pdbUnavailable(
          OPERATION,
          `llvm-pdbutil dump exited nonzero (${String(run.value.exit)}); stderr: ${run.value.stderr.slice(0, 512)}`,
          PDB_DUMP_REMEDIATION,
        ),
      );
    let parsed;
    try {
      parsed = parsePdbDumpText(run.value.stdout);
    } catch (cause: unknown) {
      if (cause instanceof PdbDumpTextFailure)
        return err(
          new AnalysisOutputError(OPERATION, cause.message, { cause }),
        );
      throw cause;
    }
    const report = pdbSymbolsSchema.safeParse({
      artifact: { path, ...selected },
      invocation: {
        command: configuration.value.command,
        arguments: [...DUMP_ARGUMENTS, path],
        exit: run.value.exit,
        stdout_bytes: run.value.stdout_bytes,
        stderr_bytes: run.value.stderr_bytes,
      },
      ...parsed,
      srcsrv_executed: false,
      complete: parsed.complete,
    });
    if (!report.success || report.data.artifact.path !== path)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "llvm-pdbutil report does not satisfy its contract.",
          {},
        ),
      );
    return ok(report.data);
  }

  fileFailure(cause: unknown, path: string): AnalysisError {
    if (cause instanceof Error && "code" in cause) {
      if (cause.code === "EACCES" || cause.code === "EPERM")
        return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
          cause,
        });
      if (
        ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
          String(cause.code),
        )
      )
        return new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
          },
        ]);
    }
    return new ProviderAdapterError(PDB_PROVIDER_ID, OPERATION, {
      cause,
      diagnostics: { path },
    });
  }

  close(): Promise<void> {
    return Promise.resolve();
  }
}
