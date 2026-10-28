import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type {
  BinaryDiffResult,
  ExportBinexportResult,
} from "../domain/bindiff/binaryDiff.js";
import {
  binaryDiffResultSchema,
  exportBinexportResultSchema,
} from "../domain/bindiff/binaryDiff.js";
import { parseJsonObject } from "../domain/jsonShape.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import {
  PrivateRuntimeRoot,
  type PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";
import { bindiffArguments, runBindiffCommand } from "./BindiffCommand.js";
import {
  BinDiffConfigurationFailure,
  bindiffConfigurationAvailability,
  resolveBinexportConfiguration,
  resolveBindiffConfiguration,
  type BinDiffCommandConfiguration,
} from "./BindiffConfiguration.js";
import { parseBinaryDiffJson } from "./BindiffOutput.js";
import {
  BINDIFF_COMMAND_ENV,
  BINDIFF_LANE_UNVERIFIED_NOTE,
  BINDIFF_OUTPUT_REMEDIATION,
  BINDIFF_PROVIDER_ID,
  BINDIFF_PROVIDER_NAME,
  BINEXPORT_MAGIC,
} from "./BindiffRelease.js";

export const BINDIFF_PROVIDER_IDENTITY = {
  id: BINDIFF_PROVIDER_ID,
  name: BINDIFF_PROVIDER_NAME,
  version: null,
} as const;

export interface BindiffProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly createRuntimeRoot?: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<Pick<PrivateRuntimeRoot, "path" | "close">>;
}

export interface BinaryDiffRequest {
  readonly primaryPath: string;
  readonly secondaryPath: string;
  readonly primarySha256: string;
  readonly secondarySha256: string;
  readonly maxMatches: number;
}

export interface BinexportRequest {
  readonly path: string;
  readonly outputDirectory: string;
}

interface FileDigest {
  readonly bytes: number;
  readonly sha256: string;
}

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;

const MAX_EXPORTED_BYTES = 256 * 1024 * 1024;

/** Provider-backed binary comparison and BinExport export. */
export class BindiffProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #createRuntimeRoot: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly #resources = new ArtifactResourceScope();

  constructor(options: BindiffProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      ((rootOptions) => PrivateRuntimeRoot.create(rootOptions));
  }

  async inspectAvailability(): Promise<ProviderAvailability> {
    const diff = this.inspectDiffAvailability();
    const exportAvailability = this.inspectExportAvailability();
    if (
      diff.status === "available" ||
      exportAvailability.status === "available"
    )
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          diff: diff.status === "available",
          export: exportAvailability.status === "available",
        },
      };
    return diff;
  }

  inspectDiffAvailability(_signal?: AbortSignal): ProviderAvailability {
    try {
      const configuration = resolveBindiffConfiguration(this.#environment);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          version_probed: false,
        },
      };
    } catch (cause: unknown) {
      return cause instanceof BinDiffConfigurationFailure
        ? bindiffConfigurationAvailability(cause)
        : {
            status: "unavailable",
            code: "not_configured",
            reason:
              cause instanceof Error
                ? cause.message
                : "The BinDiff selection failed",
            diagnostics: {},
          };
    }
  }

  inspectExportAvailability(_signal?: AbortSignal): ProviderAvailability {
    try {
      const configuration = resolveBinexportConfiguration(this.#environment);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          version_probed: false,
        },
      };
    } catch (cause: unknown) {
      return cause instanceof BinDiffConfigurationFailure
        ? bindiffConfigurationAvailability(cause)
        : {
            status: "unavailable",
            code: "not_configured",
            reason:
              cause instanceof Error
                ? cause.message
                : "The BinExport selection failed",
            diagnostics: {},
          };
    }
  }

  close(): Promise<void> {
    return this.#resources.close();
  }

  async diff(
    request: BinaryDiffRequest,
    options?: ExecutionOptions,
  ): Promise<Result<BinaryDiffResult, AnalysisError>> {
    const signal = options?.signal;
    const configuration = this.#diffConfiguration();
    if (!configuration.ok) return configuration;
    const primary = await this.#digest(
      "diff_binaries",
      request.primaryPath,
      signal,
    );
    if (!primary.ok) return primary;
    const secondary = await this.#digest(
      "diff_binaries",
      request.secondaryPath,
      signal,
    );
    if (!secondary.ok) return secondary;
    if (primary.value.sha256 !== request.primarySha256)
      return err(
        new AnalysisInputError("diff_binaries", {
          userMessage:
            "The left observation no longer matches the file on disk; reopen and inspect the artifact before diffing",
        }),
      );
    if (secondary.value.sha256 !== request.secondarySha256)
      return err(
        new AnalysisInputError("diff_binaries", {
          userMessage:
            "The right observation no longer matches the file on disk; reopen and inspect the artifact before diffing",
        }),
      );
    const ran = await runBindiffCommand(
      "diff_binaries",
      configuration.value.command,
      bindiffArguments.diff(request.primaryPath, request.secondaryPath),
      { timeoutMs: configuration.value.operationTimeoutMs },
      signal,
    );
    if (!ran.ok) return ran;
    const document = parseJsonObject(ran.value.stdout);
    const parsed = document === null ? null : parseBinaryDiffJson(document);
    if (
      parsed === null ||
      (parsed.matches.length === 0 && parsed.unparsedRows > 0)
    )
      return err(
        new AnalysisProtocolError(
          `The BinDiff adapter did not return a recognizable match table. ${BINDIFF_OUTPUT_REMEDIATION}`,
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const sorted = [...parsed.matches].sort((left, right) =>
      left.primaryAddress < right.primaryAddress
        ? -1
        : left.primaryAddress > right.primaryAddress
          ? 1
          : left.secondaryAddress < right.secondaryAddress
            ? -1
            : left.secondaryAddress > right.secondaryAddress
              ? 1
              : 0,
    );
    const truncated = sorted.length > request.maxMatches;
    const matches = sorted.slice(0, request.maxMatches).map((match) => ({
      primary_address: match.primaryAddress,
      primary_name: match.primaryName,
      secondary_address: match.secondaryAddress,
      secondary_name: match.secondaryName,
      similarity: match.similarity,
      confidence: match.confidence,
      names_changed: (match.primaryName ?? "") !== (match.secondaryName ?? ""),
    }));
    const changes = matches.filter(
      (match) => match.names_changed || match.similarity < 1,
    );
    const unresolved = matches.filter((match) => match.confidence < 0.5).length;
    const result: BinaryDiffResult = {
      status:
        matches.length === 0 &&
        parsed.unmatchedPrimary === 0 &&
        parsed.unmatchedSecondary === 0
          ? "unchanged"
          : changes.length > 0 ||
              parsed.unmatchedPrimary > 0 ||
              parsed.unmatchedSecondary > 0
            ? "changed"
            : "unchanged",
      function_match: {
        matched: matches.length,
        unmatched_primary: parsed.unmatchedPrimary,
        unmatched_secondary: parsed.unmatchedSecondary,
      },
      left_subject_sha256: primary.value.sha256,
      right_subject_sha256: secondary.value.sha256,
      summary: {
        matched: matches.length,
        changed: changes.length,
        unresolved,
      },
      matches,
      changes,
      limitations: [
        BINDIFF_LANE_UNVERIFIED_NOTE,
        "BinDiff matches are provider similarity heuristics, not behavioral equivalence; use analyze_function and compare_functions for selected pairs",
        "This is a provider-backed alternative to the bespoke compare_functions matcher, not a replacement",
        "Unmatched functions and low-confidence pairs are never treated as added or removed behavior",
        ...(truncated ? ["max_matches capped the published match table"] : []),
        ...(parsed.unparsedRows > 0
          ? ["Unrecognized adapter rows were counted, not guessed"]
          : []),
      ],
    };
    binaryDiffResultSchema.parse(result);
    return ok(result);
  }

  async exportBinexport(
    request: BinexportRequest,
    options?: ExecutionOptions,
  ): Promise<Result<ExportBinexportResult, AnalysisError>> {
    const signal = options?.signal;
    const configuration = this.#exportConfiguration();
    if (!configuration.ok) return configuration;
    const digest = await this.#digest(
      "export_binexport_protobuf",
      request.path,
      signal,
    );
    if (!digest.ok) return digest;
    const prepared = await this.#prepareOutputDirectory(
      "export_binexport_protobuf",
      request.outputDirectory,
    );
    if (!prepared.ok) return prepared;
    const root = await this.#createRoot("export_binexport_protobuf");
    if (!root.ok) return root;
    let outcome: Result<ExportBinexportResult, AnalysisError>;
    try {
      outcome = await this.#exportInto(
        root.value,
        configuration.value,
        request,
        digest.value,
        prepared.value,
        signal,
      );
    } catch (cause: unknown) {
      outcome = err(
        new AnalysisProtocolError(
          "The BinExport exporter failed in an unrecognized way",
          { cause },
        ),
      );
    }
    try {
      await root.value.close();
    } catch (cause: unknown) {
      return err(
        new ProviderCleanupError(
          BINDIFF_PROVIDER_ID,
          [root.value.path],
          { reason: cause instanceof Error ? cause.message : String(cause) },
          { operation: "export_binexport_protobuf", cause },
        ),
      );
    }
    return outcome;
  }

  async #exportInto(
    root: RuntimeRoot,
    configuration: BinDiffCommandConfiguration,
    request: BinexportRequest,
    digest: FileDigest,
    outputDirectory: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<ExportBinexportResult, AnalysisError>> {
    const staging = join(root.path, "export");
    await mkdir(staging, { mode: 0o700 });
    const ran = await runBindiffCommand(
      "export_binexport_protobuf",
      configuration.command,
      bindiffArguments.export(request.path, staging),
      { timeoutMs: configuration.operationTimeoutMs },
      signal,
    );
    if (!ran.ok) return ran;
    const exported = await findBinexportFile(staging);
    if (exported === null)
      return err(
        new AnalysisProtocolError(
          "The BinExport exporter wrote no recognizable .BinExport file",
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const contents = await readFile(exported.absolute);
    if (contents.byteLength > MAX_EXPORTED_BYTES)
      return err(
        new AnalysisProtocolError(
          `The exported BinExport file exceeds the ${String(MAX_EXPORTED_BYTES)}-byte publication budget`,
        ),
      );
    const format =
      contents.subarray(0, 4).toString("latin1") === BINEXPORT_MAGIC
        ? ("binexport" as const)
        : null;
    if (format === null)
      return err(
        new AnalysisProtocolError(
          "The exported file does not start with the BinExport BINE magic",
        ),
      );
    const destination = join(
      outputDirectory,
      `rea-binexport-${sanitize(basename(request.path))}-${digest.sha256.slice(0, 12)}`,
    );
    try {
      await mkdir(destination, { recursive: false });
    } catch (cause) {
      return err(
        new AnalysisOutputError(
          "export_binexport_protobuf",
          `The BinExport destination already exists or could not be created: ${destination}`,
          { cause },
        ),
      );
    }
    const relativePath =
      exported.absolute.slice(staging.length + 1) || "export.BinExport";
    const target = join(destination, relativePath);
    try {
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, contents, { mode: 0o600, flag: "wx" });
    } catch (cause) {
      return err(
        new AnalysisOutputError(
          "export_binexport_protobuf",
          `The BinExport file could not be published: ${relativePath}`,
          { cause },
        ),
      );
    }
    const result: ExportBinexportResult = {
      client: { command: configuration.command, version: null },
      path: request.path,
      sha256: digest.sha256,
      bytes: digest.bytes,
      output_directory: destination,
      file: {
        relative_path: relativePath,
        bytes: contents.byteLength,
        sha256: createHash("sha256").update(contents).digest("hex"),
        format: "binexport",
      },
      coverage: "complete",
    };
    exportBinexportResultSchema.parse(result);
    return ok(result);
  }

  #diffConfiguration(): Result<BinDiffCommandConfiguration, AnalysisError> {
    try {
      return ok(resolveBindiffConfiguration(this.#environment));
    } catch (cause: unknown) {
      if (cause instanceof BinDiffConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            BINDIFF_PROVIDER_ID,
            "diff_binaries",
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError("The BinDiff selection failed", { cause }),
      );
    }
  }

  #exportConfiguration(): Result<BinDiffCommandConfiguration, AnalysisError> {
    try {
      return ok(resolveBinexportConfiguration(this.#environment));
    } catch (cause: unknown) {
      if (cause instanceof BinDiffConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            BINDIFF_PROVIDER_ID,
            "export_binexport_protobuf",
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError("The BinExport selection failed", { cause }),
      );
    }
  }

  async #prepareOutputDirectory(
    operation: string,
    directory: string,
  ): Promise<Result<string, AnalysisError>> {
    try {
      await mkdir(directory, { recursive: true });
      return ok(directory);
    } catch (cause) {
      return err(
        new AnalysisOutputError(
          operation,
          `The output directory could not be created: ${directory}`,
          { cause },
        ),
      );
    }
  }

  async #createRoot(
    operation: string,
  ): Promise<Result<RuntimeRoot, AnalysisError>> {
    try {
      return ok(await this.#createRuntimeRoot({ prefix: "rea-bindiff-" }));
    } catch (cause: unknown) {
      return err(
        new AnalysisProtocolError(
          `A private BinDiff output directory could not be created for ${operation}`,
          { cause },
        ),
      );
    }
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

const sanitize = (value: string): string =>
  value.replaceAll(/[^\w.-]+/gu, "-").slice(0, 64) || "artifact";

const findBinexportFile = async (
  root: string,
): Promise<{ readonly absolute: string } | null> => {
  const walk = async (directory: string): Promise<string | null> => {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return null;
    }
    for (const entry of entries.sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        const nested = await walk(absolute);
        if (nested !== null) return nested;
      } else if (
        entry.isFile() &&
        entry.name.toLowerCase().endsWith(".binexport")
      )
        return absolute;
    }
    return null;
  };
  const absolute = await walk(root);
  return absolute === null ? null : { absolute };
};
