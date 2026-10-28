import { basename, extname } from "node:path";

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
  decompileDotnetAssemblyResultSchema,
  type DecompileDotnetAssemblyResult,
  type DotnetDecompilerRequest,
} from "../domain/manageddecomp/dotnetDecompilation.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import {
  dotnetDecompilerArguments,
  runDotnetDecompilerCommand,
} from "./DotnetDecompilerCommand.js";
import {
  dotnetDecompilerConfigurationAvailability,
  DotnetDecompilerConfigurationFailure,
  inspectDotnetDecompilerClient,
  resolveDotnetDecompilerConfiguration,
  type DotnetDecompilerClientIdentity,
  type DotnetDecompilerConfiguration,
} from "./DotnetDecompilerConfiguration.js";
import { parseDotnetDeclarations } from "./DotnetDecompilerOutput.js";
import {
  DOTNET_DECOMPILER_PROVIDER_ID,
  DOTNET_DECOMPILER_PROVIDER_NAME,
  DOTNET_LANE_UNVERIFIED_NOTE,
} from "./DotnetDecompilerRelease.js";

export const DOTNET_DECOMPILER_PROVIDER_IDENTITY = {
  id: DOTNET_DECOMPILER_PROVIDER_ID,
  name: DOTNET_DECOMPILER_PROVIDER_NAME,
  version: null,
} as const;

export interface DotnetDecompilerProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

interface Installation {
  readonly configuration: DotnetDecompilerConfiguration;
  readonly identity: DotnetDecompilerClientIdentity;
}

interface FileDigest {
  readonly bytes: number;
  readonly sha256: string;
}

const providerOf = (installation: Installation) => ({
  ...DOTNET_DECOMPILER_PROVIDER_IDENTITY,
  version: installation.identity.version,
});

const clientOf = (installation: Installation) => ({
  command: installation.configuration.command,
  version: installation.identity.version,
});

/** .NET decompilation over a caller-supplied ilspycmd binary. */
export class DotnetDecompilerProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: DotnetDecompilerProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
  }

  /** Probe the selected binary; never reads an assembly. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const configuration = resolveDotnetDecompilerConfiguration(
        this.#environment,
      );
      const identity = await inspectDotnetDecompilerClient(
        configuration,
        signal,
      );
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          version: identity.version,
          version_probed: true,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof DotnetDecompilerConfigurationFailure)
        return dotnetDecompilerConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The ilspycmd readiness probe failed",
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
    request: DotnetDecompilerRequest,
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
      const installation = await this.#requireInstallation(
        request.operation,
        signal,
      );
      if (!installation.ok) return installation;
      return await this.#decompile(
        installation.value,
        request.input.path,
        request.input.max_types ?? 500,
        signal,
        request.operation,
      );
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  async #requireInstallation(
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<Installation, AnalysisError>> {
    try {
      const configuration = resolveDotnetDecompilerConfiguration(
        this.#environment,
      );
      const identity = await inspectDotnetDecompilerClient(
        configuration,
        signal,
        operation,
      );
      return ok({ configuration, identity });
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof DotnetDecompilerConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            DOTNET_DECOMPILER_PROVIDER_ID,
            operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `ilspycmd readiness probe failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #decompile(
    installation: Installation,
    path: string,
    maxTypes: number,
    signal: AbortSignal | undefined,
    operation: string,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await this.#digest(operation, path, signal);
    if (!digest.ok) return digest;
    const ran = await runDotnetDecompilerCommand(
      operation,
      installation.configuration.command,
      dotnetDecompilerArguments.decompile(path),
      { timeoutMs: installation.configuration.operationTimeoutMs },
      signal,
    );
    if (!ran.ok) return ran;
    const inventory = parseDotnetDeclarations(ran.value.stdout, maxTypes);
    if (inventory.types.length === 0)
      return err(
        new AnalysisProtocolError(
          "ilspycmd did not return a recognizable C# declaration inventory",
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const truncated = inventory.types.length >= maxTypes;
    const types = inventory.types.slice(0, maxTypes).map((type) => ({
      namespace: type.namespace,
      name: type.name,
      kind: type.kind,
      base_type: type.baseType,
      members: type.members.map((member) => ({ ...member })),
    }));
    const memberCount = types.reduce(
      (total, type) => total + type.members.length,
      0,
    );
    const result: DecompileDotnetAssemblyResult = {
      client: clientOf(installation),
      path,
      sha256: digest.value.sha256,
      bytes: digest.value.bytes,
      assembly_name:
        basename(path, extname(path)) === ""
          ? null
          : basename(path, extname(path)),
      types,
      type_count: types.length,
      member_count: memberCount,
      unparsed_lines: inventory.unparsedLines,
      truncated,
      coverage:
        inventory.unparsedLines > 0 || truncated
          ? ("partial" as const)
          : ("complete" as const),
    };
    decompileDotnetAssemblyResultSchema.parse(result);
    return ok(
      createAnalysisExecution(result, providerOf(installation), {
        limitations: [
          DOTNET_LANE_UNVERIFIED_NOTE,
          "Decompiled C# text stays out of Evidence; only type and member declaration structure is reported",
          "Declaration scanning is shallow: nested scopes, attributes, and generated members can be under-reported",
          ...(truncated ? ["max_types capped the published type list"] : []),
          ...(inventory.unparsedLines > 0
            ? ["Unrecognized declaration lines were counted, not guessed"]
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
          userMessage: `The selected assembly could not be read and digested: ${path}`,
        }),
      );
    }
  }
}
