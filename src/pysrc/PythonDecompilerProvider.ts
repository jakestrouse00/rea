import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisError as AnalysisErrorClass } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import {
  decompilePythonBytecodeResultSchema,
  type DecompilePythonBytecodeResult,
  type PythonDecompilerRequest,
} from "../domain/pysrc/pythonSourceRecovery.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import {
  pythonDecompilerArguments,
  runPythonDecompilerCommand,
} from "./PythonDecompilerCommand.js";
import {
  pythonDecompilerConfigurationAvailability,
  PythonDecompilerConfigurationFailure,
  resolvePythonDecompilerConfiguration,
  type PythonDecompilerConfiguration,
} from "./PythonDecompilerConfiguration.js";
import { parsePythonSource } from "./PythonDecompilerOutput.js";
import {
  PYTHON_DECOMPILER_OUTPUT_REMEDIATION,
  PYTHON_DECOMPILER_PROVIDER_ID,
  PYTHON_DECOMPILER_PROVIDER_NAME,
  PYTHON_LANE_UNVERIFIED_NOTE,
} from "./PythonDecompilerRelease.js";

export const PYTHON_DECOMPILER_PROVIDER_IDENTITY = {
  id: PYTHON_DECOMPILER_PROVIDER_ID,
  name: PYTHON_DECOMPILER_PROVIDER_NAME,
  version: null,
} as const;

export interface PythonDecompilerProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

interface FileDigest {
  readonly bytes: number;
  readonly sha256: string;
}

/** Python source recovery over a caller-supplied PyLingual or pycdc binary. */
export class PythonDecompilerProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: PythonDecompilerProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
  }

  /** Probe the selected executable without reading bytecode. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    if (signal?.aborted === true)
      return {
        status: "unavailable",
        code: "not_configured",
        reason: "The availability probe was cancelled",
        diagnostics: {},
      };
    try {
      const configuration = resolvePythonDecompilerConfiguration(
        this.#environment,
      );
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          selected_tool: configuration.tool,
          version_probed: false,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof PythonDecompilerConfigurationFailure)
        return pythonDecompilerConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "not_configured",
        reason:
          cause instanceof Error
            ? cause.message
            : "The Python decompiler selection failed",
        diagnostics: {},
      };
    }
  }

  /** Stop admission, await active work, and release retained descriptors. */
  close(): Promise<void> {
    this.#closing = true;
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = (async () => {
      await Promise.all(this.#activeOperations);
      await this.#resources.close();
    })().finally(() => {
      if (this.#closePromise === closing) this.#closePromise = undefined;
    });
    this.#closePromise = closing;
    return this.#closePromise;
  }

  async execute(
    request: PythonDecompilerRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    if (this.#closing || signal?.aborted === true)
      return err(
        new AnalysisCancelledError(request.operation, {
          cause: signal?.reason,
        }),
      );
    let release!: () => void;
    const active = new Promise<void>((done) => {
      release = done;
    });
    this.#activeOperations.add(active);
    try {
      const configuration = this.#requireConfiguration(request.operation);
      if (!configuration.ok) return configuration;
      return await this.#decompile(
        configuration.value,
        request.input.path,
        request.input.max_functions ?? 5_000,
        signal,
        request.operation,
      );
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  #requireConfiguration(
    operation: string,
  ): Result<PythonDecompilerConfiguration, AnalysisError> {
    try {
      return ok(resolvePythonDecompilerConfiguration(this.#environment));
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof PythonDecompilerConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            PYTHON_DECOMPILER_PROVIDER_ID,
            operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `The Python decompiler selection failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #decompile(
    configuration: PythonDecompilerConfiguration,
    path: string,
    maxFunctions: number,
    signal: AbortSignal | undefined,
    operation: string,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await this.#digest(operation, path, signal);
    if (!digest.ok) return digest;
    const ran = await runPythonDecompilerCommand(
      operation,
      configuration.command,
      pythonDecompilerArguments.decompile(path),
      { timeoutMs: configuration.operationTimeoutMs },
      signal,
    );
    if (!ran.ok) return ran;
    const inventory = parsePythonSource(ran.value.stdout);
    if (inventory.functions.length === 0 && inventory.classes.length === 0)
      return err(
        new AnalysisProtocolError(
          `The selected Python decompiler did not return recognizable declarations. ${PYTHON_DECOMPILER_OUTPUT_REMEDIATION}`,
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const truncated = inventory.functions.length > maxFunctions;
    const functions = inventory.functions
      .slice(0, maxFunctions)
      .map((func) => ({
        name: func.name,
        qualified_name: func.qualifiedName,
        line_start: func.lineStart,
        line_end: func.lineEnd,
        parameter_count: func.parameterCount,
      }));
    const result: DecompilePythonBytecodeResult = {
      client: {
        command: configuration.command,
        version: null,
      },
      path,
      sha256: digest.value.sha256,
      bytes: digest.value.bytes,
      python_version: null,
      functions,
      classes: [...inventory.classes],
      imports: [...inventory.imports],
      function_count: functions.length,
      class_count: inventory.classes.length,
      import_count: inventory.imports.length,
      unparsed_lines: inventory.unparsedLines,
      truncated,
      coverage:
        inventory.unparsedLines > 0 || truncated
          ? ("partial" as const)
          : ("complete" as const),
    };
    decompilePythonBytecodeResultSchema.parse(result);
    return ok(
      createAnalysisExecution(
        result,
        {
          ...PYTHON_DECOMPILER_PROVIDER_IDENTITY,
          version: null,
        },
        {
          limitations: [
            PYTHON_LANE_UNVERIFIED_NOTE,
            "Recovered Python source stays out of Evidence; only declarations, line ranges, and import module names are reported",
            "Decompiler output is not guaranteed to be valid or faithful to the original source",
            ...(truncated
              ? ["max_functions capped the published function list"]
              : []),
          ],
          locations: [{ kind: "artifact-path", path }],
        },
      ),
    );
  }

  async #digest(
    operation: string,
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<FileDigest, AnalysisError>> {
    try {
      const digest = await hashStableFile(path, {
        ...(signal === undefined ? {} : { signal }),
        retainFailedClose: (handle) => {
          this.#resources.retain({
            kind: "lease",
            resource: path,
            lease: new AnalysisCleanupLease(() => handle.close(), [path]),
          });
        },
      });
      return ok({ bytes: digest.bytes, sha256: digest.sha256 });
    } catch (cause: unknown) {
      if (cause instanceof RegularFileOperationCancelled)
        return err(
          new AnalysisCancelledError(operation, { cause: cause.reason }),
        );
      return err(
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The selected bytecode artifact could not be read and digested: ${path}`,
        }),
      );
    }
  }
}
