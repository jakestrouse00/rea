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
  analyzeBinaryCapabilitiesResultSchema,
  type AnalyzeBinaryCapabilitiesInput,
} from "../domain/capa/capaAnalysis.js";
import { parseJsonObject } from "../domain/jsonShape.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import { runCapaCommand, capaArguments } from "./CapaCommand.js";
import {
  CapaConfigurationFailure,
  capaConfigurationAvailability,
  inspectCapaClient,
  resolveCapaConfiguration,
  type CapaClientIdentity,
  type CapaConfiguration,
} from "./CapaConfiguration.js";
import { parseCapaJson } from "./CapaOutput.js";
import {
  CAPA_LANE_UNVERIFIED_NOTE,
  CAPA_PROVIDER_ID,
  CAPA_PROVIDER_NAME,
} from "./CapaRelease.js";

export const CAPA_PROVIDER_IDENTITY = {
  id: CAPA_PROVIDER_ID,
  name: CAPA_PROVIDER_NAME,
  version: null,
} as const;

export interface CapaProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

interface CapaInstallation {
  readonly configuration: CapaConfiguration;
  readonly identity: CapaClientIdentity;
}

const providerOf = (installation: CapaInstallation) => ({
  ...CAPA_PROVIDER_IDENTITY,
  version: installation.identity.version,
});

const clientOf = (installation: CapaInstallation) => ({
  command: installation.configuration.command,
  version: installation.identity.version,
});

/** Capability matching over a caller-supplied capa CLI. */
export class CapaProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: CapaProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
  }

  /** Probe the selected binary; never reads a target. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const configuration = resolveCapaConfiguration(this.#environment);
      const identity = await inspectCapaClient(configuration, signal);
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
      if (cause instanceof CapaConfigurationFailure)
        return capaConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The capa readiness probe failed",
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
    request: {
      readonly operation: "analyze_binary_capabilities";
      readonly input: AnalyzeBinaryCapabilitiesInput;
    },
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
      return await this.#analyze(
        installation.value,
        request.input,
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
  ): Promise<Result<CapaInstallation, AnalysisError>> {
    try {
      const configuration = resolveCapaConfiguration(this.#environment);
      const identity = await inspectCapaClient(
        configuration,
        signal,
        operation,
      );
      return ok({ configuration, identity });
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof CapaConfigurationFailure)
        return err(
          providerConfigurationRefusal(CAPA_PROVIDER_ID, operation, cause),
        );
      return err(
        new AnalysisProtocolError(
          `capa readiness probe failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #analyze(
    installation: CapaInstallation,
    input: AnalyzeBinaryCapabilitiesInput,
    signal: AbortSignal | undefined,
    operation: string,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const maxRules = input.max_rules ?? 1_000;
    const digest = await this.#digest(operation, input.path, signal);
    if (!digest.ok) return digest;
    const ran = await runCapaCommand(
      operation,
      installation.configuration.command,
      capaArguments.analyze(input.path, input.backend ?? "default"),
      { timeoutMs: installation.configuration.operationTimeoutMs },
      signal,
    );
    if (!ran.ok) return ran;
    const document = parseJsonObject(ran.value.stdout);
    const inventory = document === null ? null : parseCapaJson(document);
    if (inventory === null)
      return err(
        new AnalysisProtocolError(
          "capa did not return a recognizable JSON capability document",
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const truncated = inventory.truncated || inventory.rules.length > maxRules;
    const rules = inventory.rules.slice(0, maxRules).map((rule) => ({
      id: rule.id,
      namespace: rule.namespace,
      scope: rule.scope,
      authors: [...rule.authors],
      attack: rule.attack.map((entry) => ({ ...entry })),
      mbc: rule.mbc.map((entry) => ({ ...entry })),
      match_count: rule.matchCount,
      locations: [...rule.locations],
    }));
    const matchCount = rules.reduce(
      (total, rule) => total + rule.match_count,
      0,
    );
    const result = {
      client: clientOf(installation),
      path: input.path,
      sha256: digest.value.sha256,
      bytes: digest.value.bytes,
      format: inventory.format,
      arch: inventory.arch,
      os: inventory.os,
      rules,
      rule_count: rules.length,
      match_count: matchCount,
      truncated,
      unparsed_entries: inventory.unparsedEntries,
      coverage:
        inventory.unparsedEntries > 0 || truncated
          ? ("partial" as const)
          : ("complete" as const),
    };
    analyzeBinaryCapabilitiesResultSchema.parse(result);
    return ok(
      createAnalysisExecution(result, providerOf(installation), {
        limitations: [
          CAPA_LANE_UNVERIFIED_NOTE,
          "Capa matches are rule-driven: an absent rule is not proof the behavior is absent",
          "Decoded strings, matched bytes, and rule source stay out of Evidence",
          ...(inventory.unparsedEntries > 0
            ? ["Unrecognized rule entries were counted, not guessed"]
            : []),
          ...(truncated
            ? ["max_rules capped the published rule inventory"]
            : []),
        ],
        locations: [{ kind: "artifact-path", path: input.path }],
      }),
    );
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
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The selected artifact could not be read and digested: ${path}`,
        }),
      );
    }
  }
}
