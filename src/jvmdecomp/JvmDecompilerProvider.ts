import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

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
import type { JvmDecompilerRequest } from "../domain/jvmdecomp/jvmDecompilation.js";
import { jvmDecompilationResultSchema } from "../domain/jvmdecomp/jvmDecompilation.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import {
  PrivateRuntimeRoot,
  type PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";
import { runJvmDecompilerCommand } from "./JvmDecompilerCommand.js";
import {
  jvmDecompilerConfigurationAvailability,
  JvmDecompilerConfigurationFailure,
  resolveJvmDecompilerConfiguration,
  type JvmDecompilerConfiguration,
} from "./JvmDecompilerConfiguration.js";
import { parseJavaSource } from "./JvmDecompilerOutput.js";
import {
  JVM_DECOMPILER_PROVIDER_ID,
  JVM_DECOMPILER_PROVIDER_NAME,
  JVM_LANE_UNVERIFIED_NOTE,
  VINEFLOWER_OUTPUT_REMEDIATION,
} from "./JvmDecompilerRelease.js";

export const JVM_DECOMPILER_PROVIDER_IDENTITY = {
  id: JVM_DECOMPILER_PROVIDER_ID,
  name: JVM_DECOMPILER_PROVIDER_NAME,
  version: null,
} as const;

export interface JvmDecompilerProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  /** Override runtime-root creation at the provider's owned-resource boundary. */
  readonly createRuntimeRoot?: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<Pick<PrivateRuntimeRoot, "path" | "close">>;
}

interface FileDigest {
  readonly bytes: number;
  readonly sha256: string;
}

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;

const MAX_RECOVERED_SOURCE_BYTES = 64 * 1024 * 1024;

const normalizeClassName = (value: string): string => {
  const trimmed = value.trim().replaceAll("/", ".");
  const withoutDescriptor =
    trimmed.startsWith("L") && trimmed.endsWith(";")
      ? trimmed.slice(1, -1)
      : trimmed;
  return withoutDescriptor;
};

/** JVM class decompilation over a caller-supplied Vineflower JAR. */
export class JvmDecompilerProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #createRuntimeRoot: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: JvmDecompilerProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      ((rootOptions) => PrivateRuntimeRoot.create(rootOptions));
  }

  /** Probe the JAR and JDK without reading a container. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const configuration = await resolveJvmDecompilerConfiguration(
        this.#environment,
        signal,
        "decompile_jar_archive",
      );
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_jar: configuration.jar,
          selected_java: configuration.java,
          java_major: configuration.javaMajor,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof JvmDecompilerConfigurationFailure)
        return jvmDecompilerConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The Vineflower readiness probe failed",
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
    request: JvmDecompilerRequest,
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
      const configuration = await this.#requireConfiguration(
        request.operation,
        signal,
      );
      if (!configuration.ok) return configuration;
      switch (request.operation) {
        case "decompile_jar_class": {
          const maxMembers = request.input.max_members ?? 500;
          return await this.#decompile(
            configuration.value,
            request.operation,
            request.input.path,
            normalizeClassName(request.input.class_name),
            maxMembers,
            1,
            signal,
          );
        }
        case "decompile_jar_archive":
          return await this.#decompile(
            configuration.value,
            request.operation,
            request.input.path,
            null,
            request.input.max_members ?? 200,
            request.input.max_classes ?? 200,
            signal,
          );
      }
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  async #requireConfiguration(
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<JvmDecompilerConfiguration, AnalysisError>> {
    try {
      return ok(
        await resolveJvmDecompilerConfiguration(
          this.#environment,
          signal,
          operation,
        ),
      );
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof JvmDecompilerConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            JVM_DECOMPILER_PROVIDER_ID,
            operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `Vineflower readiness probe failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #decompile(
    configuration: JvmDecompilerConfiguration,
    operation: string,
    path: string,
    className: string | null,
    maxMembers: number,
    maxClasses: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await this.#digest(operation, path, signal);
    if (!digest.ok) return digest;
    const root = await this.#createRoot();
    if (!root.ok) return root;
    let outcome: Result<AnalysisExecution, AnalysisError>;
    try {
      outcome = await this.#decompileInto(
        root.value,
        configuration,
        operation,
        path,
        digest.value,
        className,
        maxMembers,
        maxClasses,
        signal,
      );
    } catch (cause: unknown) {
      outcome =
        cause instanceof AnalysisErrorClass
          ? err(cause)
          : err(
              new AnalysisProtocolError(
                `Vineflower decompilation failed for ${operation}`,
                { cause },
              ),
            );
    }
    try {
      await root.value.close();
    } catch (cause: unknown) {
      return err(
        new ProviderCleanupError(
          JVM_DECOMPILER_PROVIDER_ID,
          [root.value.path],
          {
            reason: cause instanceof Error ? cause.message : String(cause),
          },
          { operation, cause },
        ),
      );
    }
    return outcome;
  }

  async #decompileInto(
    root: RuntimeRoot,
    configuration: JvmDecompilerConfiguration,
    operation: string,
    path: string,
    digest: FileDigest,
    className: string | null,
    maxMembers: number,
    maxClasses: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const outputDirectory = join(
      root.path,
      className === null ? "classes" : "class",
    );
    const ran = await runJvmDecompilerCommand(
      operation,
      configuration,
      path,
      outputDirectory,
      className,
      signal,
    );
    if (!ran.ok) return ran;
    const sources = await collectJavaSources(outputDirectory, maxClasses);
    if (sources.files.length === 0)
      return err(
        new AnalysisProtocolError(
          `Vineflower did not write any .java source. ${VINEFLOWER_OUTPUT_REMEDIATION}`,
          {
            diagnostics: {
              stdout_excerpt: ran.value.stdout.slice(0, 256),
              stderr_excerpt: ran.value.stderr.slice(0, 256),
            },
          },
        ),
      );
    const classes = [];
    let unparsedLines = 0;
    for (const file of sources.files) {
      const inventory = parseJavaSource(file.source, maxMembers);
      classes.push(...inventory.classes);
      unparsedLines += inventory.unparsedLines;
    }
    if (classes.length === 0)
      return err(
        new AnalysisProtocolError(
          `Vineflower sources carried no recognizable class declaration. ${VINEFLOWER_OUTPUT_REMEDIATION}`,
          { diagnostics: { source_files: sources.files.length } },
        ),
      );
    const truncated = sources.truncated || classes.length > maxClasses;
    const published = classes.slice(0, maxClasses).map((type) => ({
      binary_name: type.binaryName,
      package: type.packageName,
      name: type.name,
      kind: type.kind,
      members: type.members.map((member) => ({ ...member })),
    }));
    const memberCount = published.reduce(
      (total, type) => total + type.members.length,
      0,
    );
    const result = {
      client: {
        command: configuration.java,
        version: configuration.javaVersion,
      },
      java: {
        command: configuration.java,
        version: configuration.javaVersion,
      },
      path,
      sha256: digest.sha256,
      bytes: digest.bytes,
      decompiler_jar: configuration.jar,
      classes: published,
      class_count: published.length,
      member_count: memberCount,
      unparsed_lines: unparsedLines,
      truncated,
      coverage:
        sources.truncated || truncated || unparsedLines > 0
          ? ("partial" as const)
          : ("complete" as const),
    };
    jvmDecompilationResultSchema.parse(result);
    return ok(
      createAnalysisExecution(result, this.#providerOf(configuration), {
        limitations: [
          JVM_LANE_UNVERIFIED_NOTE,
          "Recovered Java source stays out of Evidence; only class and member declaration structure is reported",
          "Vineflower output is not guaranteed to be valid or faithful to the original source",
          ...(truncated || sources.truncated
            ? [
                "max_classes or the source-file bound capped the published class list",
              ]
            : []),
          ...(unparsedLines > 0
            ? ["Unrecognized declaration lines were counted, not guessed"]
            : []),
        ],
        locations: [{ kind: "artifact-path", path }],
      }),
    );
  }

  #providerOf(configuration: JvmDecompilerConfiguration) {
    return {
      ...JVM_DECOMPILER_PROVIDER_IDENTITY,
      version: configuration.javaVersion,
    };
  }

  async #createRoot(): Promise<Result<RuntimeRoot, AnalysisError>> {
    try {
      return ok(await this.#createRuntimeRoot({ prefix: "rea-vineflower-" }));
    } catch (cause: unknown) {
      return err(
        new AnalysisProtocolError(
          "A private decompilation output directory could not be created",
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
          userMessage: `The selected container could not be read and digested: ${path}`,
        }),
      );
    }
  }
}

interface CollectedSource {
  readonly relativePath: string;
  readonly source: string;
}

const collectJavaSources = async (
  root: string,
  limit: number,
): Promise<{
  readonly files: readonly CollectedSource[];
  readonly truncated: boolean;
}> => {
  const files: CollectedSource[] = [];
  let bytes = 0;
  let truncated = false;
  const walk = async (directory: string): Promise<void> => {
    if (truncated) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries.sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
      if (truncated) return;
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile() && entry.name.endsWith(".java")) {
        if (files.length >= limit) {
          truncated = true;
          return;
        }
        try {
          const source = await readFile(absolute, "utf8");
          bytes += Buffer.byteLength(source);
          if (bytes > MAX_RECOVERED_SOURCE_BYTES) {
            truncated = true;
            return;
          }
          files.push({ relativePath: relative(root, absolute), source });
        } catch {
          truncated = true;
          return;
        }
      }
    }
  };
  await walk(root);
  return { files, truncated };
};
