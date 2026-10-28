import { stat } from "node:fs/promises";

import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { MobileToolchainLane } from "../application/mobile/MobileToolchainPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import type { MobileToolchainRequest } from "../domain/mobile/mobileToolchain.js";
import { err, ok, type Result } from "../domain/result.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import {
  MobileConfigurationFailure,
  mobileCommandError,
  mobileConfigurationAvailability,
  resolveAndroguardConfiguration,
  resolveIleappConfiguration,
  resolveObjectionConfiguration,
  runMobileCommand,
  type MobileCommandRunner,
  type MobileCommandRun,
} from "./MobileToolchainConfiguration.js";
import {
  androguardFindingsOf,
  androguardStructureOf,
  parseAndroguardDocument,
} from "./AndroguardOutput.js";
import { collectForensicTables } from "./IleappReport.js";
import {
  findObjectionRecipe,
  objectionArguments,
  scrubObjectionOutput,
} from "./ObjectionRecipes.js";
import {
  MOBILE_LIMITS,
  MOBILE_TOOLCHAIN_LANE_NOTE,
  MOBILE_TOOLCHAIN_PROVIDER_ID,
  MOBILE_TOOLCHAIN_PROVIDER_NAME,
} from "./MobileToolchainRelease.js";

export const MOBILE_TOOLCHAIN_PROVIDER_IDENTITY = {
  id: MOBILE_TOOLCHAIN_PROVIDER_ID,
  name: MOBILE_TOOLCHAIN_PROVIDER_NAME,
  version: null,
} as const;

const VERSION_PROBE_TIMEOUT_MS = 10_000;
const VERSION_PROBE_BYTES = 64 * 1024;
/** One androguard run's fixed deadline; the APK is local and already digested. */
const ANDROGUARD_TIMEOUT_MS = 300_000;

const OBJECTION_VERSION = /\b(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b/u;

type ObjectionRecipeInput = Extract<
  MobileToolchainRequest,
  { operation: "run_objection_recipe" }
>["input"];

type ApkInput = {
  readonly apk_path: string;
  readonly max_components?: number;
  readonly max_cross_references?: number;
  readonly max_findings?: number;
};

type ForensicsReportInput = Extract<
  MobileToolchainRequest,
  { operation: "run_mobile_forensics_report" }
>["input"];

export interface MobileToolchainProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  /** Test seam for every child run; production executes the launcher. */
  readonly run?: MobileCommandRunner;
}

/**
 * One provider over the three caller-supplied mobile launchers. Readiness is
 * per lane: each tool's selection is independent, and a missing launcher
 * refuses only the tools that need it.
 */
export class MobileToolchainProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #run: MobileCommandRunner;
  readonly #activeOperations = new Set<Promise<void>>();
  readonly #resources = new ArtifactResourceScope();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: MobileToolchainProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#run = options.run ?? runMobileCommand;
  }

  async inspectAvailability(
    lane: MobileToolchainLane,
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      if (lane === "objection") {
        const configuration = resolveObjectionConfiguration(this.#environment);
        const run = await this.#run({
          command: configuration.command,
          arguments: ["--version"],
          timeoutMs: VERSION_PROBE_TIMEOUT_MS,
          maxOutputBytes: VERSION_PROBE_BYTES,
          signal,
        });
        const version = OBJECTION_VERSION.exec(run.stdout)?.[1] ?? null;
        if (run.exit_code !== 0 || version === null)
          return {
            status: "unavailable",
            code: "version_unresolved",
            reason: `The selected objection launcher exited ${String(run.exit_code)} without reporting a recognizable version`,
            diagnostics: { selected_command: configuration.command },
          };
        return {
          status: "available",
          code: null,
          reason: null,
          diagnostics: {
            selected_command: configuration.command,
            version,
            version_probed: true,
          },
        };
      }
      if (lane === "androguard") {
        const configuration = resolveAndroguardConfiguration(this.#environment);
        const run = await this.#run({
          command: configuration.python,
          arguments: [
            "-c",
            "import androguard, sys; sys.stdout.write(str(getattr(androguard, '__version__', 'unknown')))",
          ],
          timeoutMs: VERSION_PROBE_TIMEOUT_MS,
          maxOutputBytes: VERSION_PROBE_BYTES,
          signal,
        });
        if (run.exit_code !== 0)
          return {
            status: "unavailable",
            code: "version_unresolved",
            reason: `The selected Python interpreter could not import androguard (exit ${String(run.exit_code)})`,
            diagnostics: {
              selected_python: configuration.python,
              bridge_script: configuration.bridgeScript,
            },
          };
        const version = run.stdout.trim();
        return {
          status: "available",
          code: null,
          reason: null,
          diagnostics: {
            selected_python: configuration.python,
            androguard_version: version === "" ? null : version,
            bridge_script: configuration.bridgeScript,
            version_probed: true,
          },
        };
      }
      const configuration = resolveIleappConfiguration(this.#environment);
      const run = await this.#run({
        command: configuration.command,
        arguments: ["--help"],
        timeoutMs: VERSION_PROBE_TIMEOUT_MS,
        maxOutputBytes: VERSION_PROBE_BYTES,
        signal,
      });
      if (run.exit_code === null)
        return {
          status: "unavailable",
          code: "executable_missing",
          reason: `The selected iLEAPP/ALEAPP launcher is missing or not executable: ${configuration.command}`,
          diagnostics: { selected_command: configuration.command },
        };
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          version: null,
          version_probed: false,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof MobileConfigurationFailure)
        return mobileConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The mobile toolchain readiness probe failed",
        diagnostics: {},
      };
    }
  }

  async close(): Promise<void> {
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
    request: MobileToolchainRequest,
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
      switch (request.operation) {
        case "run_objection_recipe":
          return await this.#runObjectionRecipe(request.input, signal);
        case "analyze_apk_structure":
          return await this.#analyzeApk(request.input, "structure", signal);
        case "scan_apk_vulnerabilities":
          return await this.#analyzeApk(
            request.input,
            "vulnerabilities",
            signal,
          );
        case "run_mobile_forensics_report":
          return await this.#runForensicsReport(request.input, signal);
      }
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  async #runObjectionRecipe(
    input: ObjectionRecipeInput,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const operation = "run_objection_recipe";
    const recipe = findObjectionRecipe(input.recipe);
    if (recipe === undefined)
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["recipe"],
            reason: "invalid_value",
            message: `Unknown objection recipe: ${String(input.recipe)}`,
          },
        ]),
      );
    const configuration = await this.#requireConfiguration(operation, () =>
      resolveObjectionConfiguration(this.#environment),
    );
    if (!configuration.ok) return configuration;
    const started = Date.now();
    const targetKind = input.target_kind ?? "bundle";
    const timeoutMs = input.timeout_ms ?? 60_000;
    const run = await this.#runOrCancelled(
      operation,
      {
        command: configuration.value.command,
        arguments: objectionArguments({
          recipe,
          targetKind,
          target: input.target,
          serial: input.serial,
        }),
        timeoutMs,
        maxOutputBytes: MOBILE_LIMITS.objectionStdoutBytes,
        signal,
      },
      signal,
    );
    if (!run.ok) return run;
    const failed = mobileCommandError(
      operation,
      configuration.value.command,
      run.value,
      timeoutMs,
    );
    if (failed !== undefined) return err(failed);
    if (run.value.exit_code !== 0)
      return err(
        new ProviderAdapterError(MOBILE_TOOLCHAIN_PROVIDER_ID, operation, {
          userMessage: `objection exited ${String(run.value.exit_code)} before the ${recipe.id} recipe produced its inventory; the target may not be attached or the recipe may not apply to this platform`,
        }),
      );
    const scrub = scrubObjectionOutput(
      recipe,
      run.value.stdout,
      input.max_rows ?? 200,
    );
    const result = {
      client: {
        command: configuration.value.command,
        version: null,
      },
      target: {
        kind: targetKind,
        value: input.target,
        serial: input.serial ?? null,
      },
      recipe: recipe.id,
      recipe_argv: [...recipe.argv],
      rows: scrub.rows,
      row_count: scrub.rowCount,
      rows_truncated: scrub.rowsTruncated,
      dropped_line_count: scrub.droppedLineCount,
      unparsed_line_count: scrub.unparsedLineCount,
      elapsed_ms: Date.now() - started,
      exit_code: run.value.exit_code,
      coverage:
        scrub.rowsTruncated || scrub.unparsedLineCount > 0
          ? ("partial" as const)
          : ("complete" as const),
    };
    return ok(
      createAnalysisExecution(result, MOBILE_TOOLCHAIN_PROVIDER_IDENTITY, {
        limitations: [
          MOBILE_TOOLCHAIN_LANE_NOTE,
          "objection is GPL-3.0 upstream; REA runs the caller-selected launcher as a subprocess and never links or installs it",
          "Only whitelisted recipes run: free-form objection commands are not assembled from caller input, and recipes that change device or app state are not offered",
          "The tool's printed text is reduced to structural rows and counters here; values, payloads, and free text are dropped instead of retained",
          "rows lists the names the recipe printed in this run; a name absent here was not printed, which does not establish that the structure is absent in the app",
        ],
      }),
    );
  }

  async #analyzeApk(
    input: ApkInput,
    mode: "structure" | "vulnerabilities",
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const operation =
      mode === "structure"
        ? "analyze_apk_structure"
        : "scan_apk_vulnerabilities";
    const configuration = await this.#requireConfiguration(operation, () =>
      resolveAndroguardConfiguration(this.#environment),
    );
    if (!configuration.ok) return configuration;
    const started = Date.now();
    const digest = await this.#digest(operation, input.apk_path, signal);
    if (!digest.ok) return digest;
    const run = await this.#runOrCancelled(
      operation,
      {
        command: configuration.value.python,
        arguments: [
          configuration.value.bridgeScript,
          "--apk",
          input.apk_path,
          "--operation",
          mode,
          "--max-components",
          String(input.max_components ?? 500),
          "--max-cross-references",
          String(input.max_cross_references ?? 500),
          "--max-findings",
          String(input.max_findings ?? 200),
        ],
        timeoutMs: ANDROGUARD_TIMEOUT_MS,
        maxOutputBytes: MOBILE_LIMITS.bridgeStdoutBytes,
        signal,
      },
      signal,
    );
    if (!run.ok) return run;
    const failed = mobileCommandError(
      operation,
      configuration.value.python,
      run.value,
      ANDROGUARD_TIMEOUT_MS,
    );
    if (failed !== undefined) return err(failed);
    const document = parseAndroguardDocument(run.value.stdout);
    if (!document.ok)
      return err(
        new AnalysisProtocolError(
          `The androguard bridge returned no usable ${mode} document: ${document.error}`,
          {
            diagnostics: {
              exit_code: run.value.exit_code,
              stderr_bytes: run.value.stderr.length,
            },
          },
        ),
      );
    const client = {
      python: configuration.value.python,
      androguard_version:
        typeof document.value.androguard_version === "string"
          ? document.value.androguard_version
          : null,
    };
    const apk = {
      path: input.apk_path,
      sha256: digest.value.sha256,
      bytes: digest.value.bytes,
    };
    if (mode === "structure") {
      const facts = androguardStructureOf(document.value, {
        maxComponents: input.max_components ?? 500,
        maxCrossReferences: input.max_cross_references ?? 500,
      });
      const result = {
        client,
        apk,
        ...facts,
        elapsed_ms: Date.now() - started,
        coverage:
          facts.components_truncated ||
          facts.cross_references_truncated ||
          facts.warnings.length > 0
            ? ("partial" as const)
            : ("complete" as const),
      };
      return ok(
        createAnalysisExecution(result, MOBILE_TOOLCHAIN_PROVIDER_IDENTITY, {
          limitations: [
            MOBILE_TOOLCHAIN_LANE_NOTE,
            "androguard parses the APK statically; REA never executes the application, its dex code, or its native libraries",
            "Declared components, permissions, and class cross references are androguard's reading of the manifest and dex metadata, not a runtime observation of what the app actually uses",
            "Cross references are sampled over a bounded class count; an absent pair means it was outside that sample",
            "Class names are retained as androguard spells them; bytecode, string values, and method bodies stay out of Evidence",
            ...(facts.warnings.length > 0
              ? [
                  "The bridge reported warnings; the affected facts are incomplete rather than empty",
                ]
              : []),
          ],
          locations: [{ kind: "artifact-path", path: input.apk_path }],
        }),
      );
    }
    const facts = androguardFindingsOf(
      document.value,
      input.max_findings ?? 200,
    );
    const result = {
      client,
      apk,
      ...facts,
      elapsed_ms: Date.now() - started,
      coverage: facts.findings_truncated
        ? ("partial" as const)
        : ("complete" as const),
    };
    return ok(
      createAnalysisExecution(result, MOBILE_TOOLCHAIN_PROVIDER_IDENTITY, {
        limitations: [
          MOBILE_TOOLCHAIN_LANE_NOTE,
          "Findings are this release's fixed structure rules over declared manifest facts; they are not a penetration test, and an unlisted rule is not proof the weakness is absent",
          "Each finding carries a stable rule id and the location it was observed at; the rule's text, matched values, and any exploit path stay out of Evidence",
          "REA never executes the application and never contacts the network on its behalf",
        ],
        locations: [{ kind: "artifact-path", path: input.apk_path }],
      }),
    );
  }

  async #runForensicsReport(
    input: ForensicsReportInput,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const operation = "run_mobile_forensics_report";
    const configuration = await this.#requireConfiguration(operation, () =>
      resolveIleappConfiguration(this.#environment),
    );
    if (!configuration.ok) return configuration;
    const started = Date.now();
    const platform = input.platform ?? "ios";
    const timeoutMs = input.timeout_ms ?? 300_000;
    const outputDirectory = await this.#requireOutputDirectory(
      operation,
      input.output_directory,
    );
    if (!outputDirectory.ok) return outputDirectory;
    const inputKind = await this.#inputKind(input.input_path);
    const run = await this.#runOrCancelled(
      operation,
      {
        command: configuration.value.command,
        arguments: [
          "-t",
          platform,
          "-i",
          input.input_path,
          "-o",
          input.output_directory,
        ],
        timeoutMs,
        maxOutputBytes: MOBILE_LIMITS.ileappStdoutBytes,
        signal,
      },
      signal,
    );
    if (!run.ok) return run;
    const failed = mobileCommandError(
      operation,
      configuration.value.command,
      run.value,
      timeoutMs,
    );
    if (failed !== undefined) return err(failed);
    const collected = await collectForensicTables(input.output_directory, {
      maxTables: input.max_tables ?? 48,
      maxRowsPerTable: input.max_rows_per_table ?? 200,
    });
    if (collected.tables.length === 0 && run.value.exit_code !== 0)
      return err(
        new ProviderAdapterError(MOBILE_TOOLCHAIN_PROVIDER_ID, operation, {
          userMessage: `The selected report tool exited ${String(run.value.exit_code)} and wrote no TSV tables into ${input.output_directory}; confirm the artifact family and that the output directory is writable`,
        }),
      );
    const result = {
      client: {
        command: configuration.value.command,
        platform,
      },
      input: { path: input.input_path, kind: inputKind },
      output_directory: input.output_directory,
      tables: collected.tables.map((table) => ({
        name: table.name,
        sha256: table.sha256,
        bytes: table.bytes,
        columns: [...table.columns],
        rows: table.rows.map((row) => [...row]),
        row_count: table.rowCount,
        retained_rows: table.retainedRows,
        truncated: table.truncated,
      })),
      table_count: collected.tables.length,
      total_rows: collected.totalRows,
      unparsed_files: [...collected.unparsedFiles],
      tables_truncated: collected.truncated,
      exit_code: run.value.exit_code,
      elapsed_ms: Date.now() - started,
      coverage: collected.truncated
        ? ("partial" as const)
        : ("complete" as const),
    };
    return ok(
      createAnalysisExecution(result, MOBILE_TOOLCHAIN_PROVIDER_IDENTITY, {
        limitations: [
          MOBILE_TOOLCHAIN_LANE_NOTE,
          "The report tool decides which artifacts it recognizes and how it names them; a table absent from the output directory is not evidence that the artifact was absent",
          "REA parses the tool's TSV tables as written, keeping original cell text within the per-cell bound; it does not re-derive the tool's findings",
          "The output directory is caller-owned: REA never creates, replaces, or deletes it, so tables from an earlier run can remain and are reported as read",
          "REA pairs this report with its own backup/import lanes; it never acquires the evidence itself",
          ...(collected.unparsedFiles.length > 0
            ? [
                "unparsed_files lists tables this run wrote that REA refused to read (unreadable, not a regular file, or over the per-table byte bound)",
              ]
            : []),
        ],
        locations: [{ kind: "artifact-path", path: input.input_path }],
      }),
    );
  }

  async #requireConfiguration<T>(
    operation: string,
    resolve: () => T,
  ): Promise<Result<T, AnalysisError>> {
    try {
      return ok(resolve());
    } catch (cause: unknown) {
      if (cause instanceof MobileConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            MOBILE_TOOLCHAIN_PROVIDER_ID,
            operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `The mobile toolchain selection could not be resolved for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #requireOutputDirectory(
    operation: string,
    path: string,
  ): Promise<Result<null, AnalysisError>> {
    try {
      const facts = await stat(path);
      if (facts.isDirectory()) return ok(null);
    } catch {
      // Reported below as one caller-facing refusal.
    }
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["output_directory"],
          reason: "invalid_value",
          message: `The selected output directory does not exist or is not a directory: ${path}`,
        },
      ]),
    );
  }

  async #inputKind(path: string): Promise<"file" | "directory"> {
    try {
      return (await stat(path)).isDirectory() ? "directory" : "file";
    } catch {
      return "file";
    }
  }

  async #runOrCancelled(
    operation: string,
    request: Parameters<MobileCommandRunner>[0],
    signal: AbortSignal | undefined,
  ): Promise<Result<MobileCommandRun, AnalysisError>> {
    try {
      const run = await this.#run(request);
      return signal?.aborted === true
        ? err(new AnalysisCancelledError(operation, { cause: signal.reason }))
        : ok(run);
    } catch (cause: unknown) {
      if (cause instanceof AnalysisCancelledError)
        return err(
          new AnalysisCancelledError(operation, { cause: cause.cause }),
        );
      if (
        cause instanceof Error &&
        "code" in cause &&
        (cause.code === "ENOENT" ||
          cause.code === "EACCES" ||
          cause.code === "EPERM")
      )
        return err(
          new ProviderAdapterError(MOBILE_TOOLCHAIN_PROVIDER_ID, operation, {
            userMessage: `The selected launcher could not be started (${String(cause.code)}): ${request.command}`,
          }),
        );
      return err(
        new AnalysisProtocolError(
          `The selected mobile tool failed to run for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #digest(
    operation: string,
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<
    Result<{ readonly bytes: number; readonly sha256: string }, AnalysisError>
  > {
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
        new AnalysisInputError(operation, { cause }, [
          {
            path: ["apk_path"],
            reason: "invalid_value",
            message: `The selected APK could not be read and digested: ${path}`,
          },
        ]),
      );
    }
  }
}
