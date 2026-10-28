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
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  demangleRustNameResultSchema,
  generateSymbolTableResultSchema,
  recoverGoSymbolsResultSchema,
  type RecoverGoSymbolsResult,
  type DemangleRustNameResult,
  type GenerateSymbolTableResult,
  type SymbolRecoveryRequestInput,
} from "../domain/symbols/symbolRecovery.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import { runSymbolCommand, symbolArguments } from "./SymbolRecoveryCommand.js";
import {
  resolveSymbolCommand,
  symbolConfigurationAvailability,
  SymbolConfigurationFailure,
  type SymbolCommandSelection,
  type SymbolTool,
} from "./SymbolRecoveryConfiguration.js";
import {
  parseBreakpadSymbols,
  parseDemangledNames,
  parseGoReSymJson,
} from "./SymbolRecoveryOutput.js";
import {
  SYMBOL_LANE_UNVERIFIED_NOTE,
  SYMBOL_PROVIDER_ID,
  SYMBOL_PROVIDER_NAME,
} from "./SymbolRecoveryRelease.js";

export const SYMBOL_PROVIDER_IDENTITY = {
  id: SYMBOL_PROVIDER_ID,
  name: SYMBOL_PROVIDER_NAME,
  version: null,
} as const;

export interface SymbolRecoveryProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

interface Selection {
  readonly command: string;
  readonly version: string | null;
}

interface FileDigest {
  readonly bytes: number;
  readonly sha256: string;
}

const toolOf = (request: SymbolRecoveryRequestInput): SymbolTool =>
  request.operation;

/** Symbol recovery over caller-supplied GoReSym, rustfilt, and dump_syms. */
export class SymbolRecoveryProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: SymbolRecoveryProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
  }

  /** Probe one tool's executable selection without starting it. */
  inspectToolAvailability(
    tool: SymbolTool,
    _signal?: AbortSignal,
  ): ProviderAvailability {
    try {
      const selection = resolveSymbolCommand(this.#environment, tool);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: selection.command,
          path_source: selection.pathSource,
          version_probed: false,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof SymbolConfigurationFailure)
        return symbolConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "not_configured",
        reason:
          cause instanceof Error
            ? cause.message
            : "The symbol tool selection failed",
        diagnostics: {},
      };
    }
  }

  /** Probe every tool this provider can run; the aggregate is conservative. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    const tools: readonly SymbolTool[] = [
      "recover_go_symbols",
      "demangle_rust_name",
      "generate_symbol_table",
    ];
    const results = tools.map((tool) =>
      this.inspectToolAvailability(tool, signal),
    );
    const firstUnavailable = results.find(
      (result) => result.status === "unavailable",
    );
    if (results.every((result) => result.status === "unavailable"))
      return firstUnavailable!;
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: Object.fromEntries(
        tools.map((tool, index) => [
          tool,
          results[index]?.status === "available",
        ]),
      ),
    };
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
    request: SymbolRecoveryRequestInput,
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
      const selection = this.#requireSelection(
        toolOf(request),
        request.operation,
      );
      if (!selection.ok) return selection;
      switch (request.operation) {
        case "recover_go_symbols":
          return await this.#recoverGoSymbols(
            request.operation,
            selection.value,
            request.input.path,
            request.input.max_functions ?? 5_000,
            signal,
          );
        case "demangle_rust_name":
          return await this.#demangleRustNames(
            request.operation,
            selection.value,
            request.input.names,
            signal,
          );
        case "generate_symbol_table":
          return await this.#generateSymbolTable(
            request.operation,
            selection.value,
            request.input.path,
            request.input.max_functions ?? 10_000,
            signal,
          );
      }
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  #requireSelection(
    tool: SymbolTool,
    operation: string,
  ): Result<Selection, AnalysisError> {
    try {
      const resolved = resolveSymbolCommand(this.#environment, tool);
      return ok({ command: resolved.command, version: null });
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof SymbolConfigurationFailure)
        return err(
          providerConfigurationRefusal(SYMBOL_PROVIDER_ID, operation, cause),
        );
      return err(
        new AnalysisProtocolError(
          `The ${tool} command selection failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #recoverGoSymbols(
    operation: string,
    selection: Selection,
    path: string,
    maxFunctions: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await this.#digest(operation, path, signal);
    if (!digest.ok) return digest;
    const ran = await runSymbolCommand(
      operation,
      "recover_go_symbols",
      selection.command,
      symbolArguments.recover_go_symbols(path),
      signal,
    );
    if (!ran.ok) return ran;
    const inventory = parseGoReSymJson(ran.value.stdout);
    if (inventory === null)
      return err(
        new AnalysisProtocolError(
          "GoReSym did not return a recognizable JSON symbol document",
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const truncated = inventory.functions.length > maxFunctions;
    const functions = inventory.functions
      .slice(0, maxFunctions)
      .map(({ name, entry, size }) => ({ name, entry, size }));
    const result: RecoverGoSymbolsResult = {
      client: clientOf(selection),
      path,
      sha256: digest.value.sha256,
      bytes: digest.value.bytes,
      go_version: inventory.goVersion,
      arch: inventory.arch,
      os: inventory.os,
      module_path: inventory.modulePath,
      functions,
      function_count: functions.length,
      truncated,
      unparsed_entries: inventory.unparsedEntries,
      coverage:
        inventory.unparsedEntries > 0 || truncated
          ? ("partial" as const)
          : ("complete" as const),
    };
    recoverGoSymbolsResultSchema.parse(result);
    return ok(
      createAnalysisExecution(result, providerOf(selection), {
        limitations: [
          SYMBOL_LANE_UNVERIFIED_NOTE,
          "Reported names and entries are recovered from the artifact's tables; a missing function is not proof it is absent",
          ...(truncated
            ? ["max_functions capped the published function list"]
            : []),
          ...(inventory.unparsedEntries > 0
            ? ["Unrecognized function rows were counted, not guessed"]
            : []),
        ],
        locations: [{ kind: "artifact-path", path }],
      }),
    );
  }

  async #demangleRustNames(
    operation: string,
    selection: Selection,
    names: readonly string[],
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const ran = await runSymbolCommand(
      operation,
      "demangle_rust_name",
      selection.command,
      symbolArguments.demangle_rust_name(names),
      signal,
    );
    if (!ran.ok) return ran;
    const parsed = parseDemangledNames(names, ran.value.stdout);
    const result: DemangleRustNameResult = {
      client: clientOf(selection),
      names: parsed.map(({ mangled, demangled }) => ({ mangled, demangled })),
      name_count: parsed.length,
      demangled_count: parsed.filter(({ demangled }) => demangled !== null)
        .length,
      coverage: parsed.every(({ demangled }) => demangled !== null)
        ? "complete"
        : "partial",
    };
    demangleRustNameResultSchema.parse(result);
    return ok(
      createAnalysisExecution(result, providerOf(selection), {
        limitations: [
          SYMBOL_LANE_UNVERIFIED_NOTE,
          "Lines the demangler leaves unchanged are reported as null, not as a successful demangle",
        ],
      }),
    );
  }

  async #generateSymbolTable(
    operation: string,
    selection: Selection,
    path: string,
    maxFunctions: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await this.#digest(operation, path, signal);
    if (!digest.ok) return digest;
    const ran = await runSymbolCommand(
      operation,
      "generate_symbol_table",
      selection.command,
      symbolArguments.generate_symbol_table(path),
      signal,
    );
    if (!ran.ok) return ran;
    const inventory = parseBreakpadSymbols(ran.value.stdout, maxFunctions);
    if (inventory.module === null && inventory.functions.length === 0)
      return err(
        new AnalysisProtocolError(
          "dump_syms did not return a recognizable Breakpad symbol table",
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const truncated =
      inventory.truncated || inventory.functions.length >= maxFunctions;
    const result: GenerateSymbolTableResult = {
      client: clientOf(selection),
      path,
      sha256: digest.value.sha256,
      bytes: digest.value.bytes,
      module: inventory.module,
      functions: inventory.functions.map((func) => ({
        name: func.name,
        address: func.address,
        size: func.size,
        parameter_size: func.parameterSize,
      })),
      function_count: inventory.functions.length,
      public_count: inventory.publicCount,
      file_count: inventory.fileCount,
      truncated,
      unparsed_entries: inventory.unparsedEntries,
      coverage:
        inventory.unparsedEntries > 0 || truncated
          ? ("partial" as const)
          : ("complete" as const),
    };
    generateSymbolTableResultSchema.parse(result);
    return ok(
      createAnalysisExecution(result, providerOf(selection), {
        limitations: [
          SYMBOL_LANE_UNVERIFIED_NOTE,
          "The full Breakpad symbol text stays out of Evidence; counts and bounded function rows are reported",
          ...(truncated
            ? ["max_functions capped the published function list"]
            : []),
          ...(inventory.unparsedEntries > 0
            ? ["Unrecognized symbol-table lines were counted, not guessed"]
            : []),
        ],
        locations: [{ kind: "artifact-path", path }],
      }),
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
          userMessage: `The selected artifact could not be read and digested: ${path}`,
        }),
      );
    }
  }
}

const clientOf = (selection: Selection) => ({
  command: selection.command,
  version: selection.version,
});

const providerOf = (selection: Selection) => ({
  ...SYMBOL_PROVIDER_IDENTITY,
  version: selection.version,
});
