import { stat } from "node:fs/promises";

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
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import type { YaraScanRequestInput } from "../domain/yara/yaraScan.js";
import { yaraScanResultSchema } from "../domain/yara/yaraScan.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import { runYaraCommand, yaraArguments } from "./YaraCommand.js";
import {
  inspectYaraClient,
  resolveCryptoRulePack,
  resolveYaraConfiguration,
  yaraConfigurationAvailability,
  YaraConfigurationFailure,
  YaraRulePackFailure,
  type CryptoRulePack,
  type YaraClientIdentity,
  type YaraConfiguration,
} from "./YaraConfiguration.js";
import { parseYaraJson } from "./YaraOutput.js";
import {
  YARA_CRYPTO_PACK,
  YARA_CRYPTO_PACK_REMEDIATION,
  YARA_PROVIDER_ID,
  YARA_PROVIDER_NAME,
  YARAX_LANE_UNVERIFIED_NOTE,
} from "./YaraRelease.js";

export const YARA_PROVIDER_IDENTITY = {
  id: YARA_PROVIDER_ID,
  name: YARA_PROVIDER_NAME,
  version: null,
} as const;

export interface YaraProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

interface YaraInstallation {
  readonly configuration: YaraConfiguration;
  readonly identity: YaraClientIdentity;
}

interface FileDigest {
  readonly bytes: number;
  readonly sha256: string;
}

const providerOf = (installation: YaraInstallation) => ({
  ...YARA_PROVIDER_IDENTITY,
  version: installation.identity.version,
});

const clientOf = (installation: YaraInstallation) => ({
  command: installation.configuration.command,
  version: installation.identity.version,
});

type RunFn = (
  args: readonly string[],
) => Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
>;

/** Rule scanning over a caller-supplied YARA-X `yr` binary. */
export class YaraProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: YaraProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
  }

  /** Probe the selected binary; never scans a target. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const configuration = resolveYaraConfiguration(this.#environment);
      const identity = await inspectYaraClient(configuration, signal);
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
      if (cause instanceof YaraConfigurationFailure)
        return yaraConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The YARA-X readiness probe failed",
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
    request: YaraScanRequestInput,
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
      const run: RunFn = (args) =>
        runYaraCommand(
          request.operation,
          installation.value.configuration.command,
          args,
          { timeoutMs: installation.value.configuration.operationTimeoutMs },
          signal,
        );
      switch (request.operation) {
        case "scan_artifact_with_rules":
          return await this.#scan(
            installation.value,
            request.input.path,
            request.input.rules_path,
            request.input.max_matches ?? 1_000,
            null,
            run,
            request.operation,
            signal,
          );
        case "scan_for_crypto_constants":
          return await this.#scanWithCryptoPack(
            installation.value,
            request.input.path,
            request.input.max_matches ?? 1_000,
            run,
            request.operation,
            signal,
          );
      }
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  async #requireInstallation(
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<YaraInstallation, AnalysisError>> {
    try {
      const configuration = resolveYaraConfiguration(this.#environment);
      const identity = await inspectYaraClient(
        configuration,
        signal,
        operation,
      );
      return ok({ configuration, identity });
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof YaraConfigurationFailure)
        return err(
          providerConfigurationRefusal(YARA_PROVIDER_ID, operation, cause),
        );
      return err(
        new AnalysisProtocolError(
          `YARA-X readiness probe failed for ${operation}`,
          {
            cause,
          },
        ),
      );
    }
  }

  async #scanWithCryptoPack(
    installation: YaraInstallation,
    path: string,
    maxMatches: number,
    run: RunFn,
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    let pack: CryptoRulePack;
    try {
      pack = await resolveCryptoRulePack();
    } catch (cause: unknown) {
      if (cause instanceof YaraRulePackFailure)
        return err(
          new AnalysisCapabilityUnavailableError(
            YARA_PROVIDER_ID,
            operation,
            `${cause.message}. ${YARA_CRYPTO_PACK_REMEDIATION}.`,
            {
              cause,
              userMessage: `${cause.message}. ${YARA_CRYPTO_PACK_REMEDIATION}.`,
              diagnostics: cause.diagnostics,
            },
          ),
        );
      return err(
        new AnalysisProtocolError(
          `The ${YARA_CRYPTO_PACK.id} rule pack could not be verified`,
          { cause },
        ),
      );
    }
    return await this.#scan(
      installation,
      path,
      pack.rulesPath,
      maxMatches,
      pack,
      run,
      operation,
      signal,
    );
  }

  async #scan(
    installation: YaraInstallation,
    path: string,
    rulesPath: string,
    maxMatches: number,
    pack: CryptoRulePack | null,
    run: RunFn,
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const target = await this.#digest(operation, path, "target", signal);
    if (!target.ok) return target;
    const rules = await this.#digest(operation, rulesPath, "rule file", signal);
    if (!rules.ok) return rules;
    const ran = await run(yaraArguments.scan(rulesPath, path));
    if (!ran.ok) return ran;
    const inventory = parseYaraJson(ran.value.stdout);
    if (inventory === null)
      return err(
        new AnalysisProtocolError(
          "YARA-X did not return a recognizable JSON match document",
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const matches = inventory.matches.map((match) => ({
      rule_id: match.ruleId,
      namespace: match.namespace,
      tags: [...match.tags],
      fields: match.fields.map((field) => ({ ...field })),
    }));
    const truncated =
      inventory.truncated || inventory.matches.length > maxMatches;
    const published = matches.slice(0, maxMatches);
    const result = {
      client: clientOf(installation),
      path,
      sha256: target.value?.sha256 ?? null,
      bytes: target.value?.bytes ?? null,
      rules_path: rulesPath,
      rules_sha256: rules.value?.sha256 ?? null,
      rule_pack: pack === null ? null : pack.pack,
      rule_pack_version: pack === null ? null : pack.version,
      matches: published,
      match_count: published.length,
      field_match_count: published.reduce(
        (total, match) => total + match.fields.length,
        0,
      ),
      truncated,
      unparsed_entries: inventory.unparsedEntries,
      coverage:
        inventory.unparsedEntries > 0 || truncated
          ? ("partial" as const)
          : ("complete" as const),
    };
    yaraScanResultSchema.parse(result);
    return ok(
      createAnalysisExecution(result, providerOf(installation), {
        limitations: [
          YARAX_LANE_UNVERIFIED_NOTE,
          "A rule match is an indicator, not proof of behavior or algorithm use",
          "Matched bytes and rule metadata values stay out of Evidence; only rule identity, tags, field names, offsets, and lengths are reported",
          ...(pack === null
            ? []
            : [
                "The crypto-constant pack is REA-owned and verified against its pinned manifest before every scan",
              ]),
          ...(target.value === null
            ? ["The target is a directory; no single target digest is reported"]
            : []),
          ...(inventory.unparsedEntries > 0
            ? ["Unrecognized match fields were counted, not guessed"]
            : []),
          ...(truncated
            ? ["max_matches capped the published rule inventory"]
            : []),
        ],
        locations: [{ kind: "artifact-path", path }],
      }),
    );
  }

  async #digest(
    operation: string,
    path: string,
    what: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<FileDigest | null, AnalysisError>> {
    let info;
    try {
      info = await stat(path);
    } catch (cause) {
      return err(
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The selected ${what} could not be read: ${path}`,
        }),
      );
    }
    if (!info.isFile()) return ok(null);
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
          userMessage: `The selected ${what} could not be read and digested: ${path}`,
        }),
      );
    }
  }
}
