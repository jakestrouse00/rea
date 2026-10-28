import { constants, type Dirent } from "node:fs";
import { access, copyFile, mkdir, readdir, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisError as AnalysisErrorClass } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { IpswRequest } from "../domain/iosipsw/ipswAnalysis.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import {
  PrivateRuntimeRoot,
  type PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";
import { ipswArguments, runIpswCommand } from "./IpswCommand.js";
import {
  inspectIpswClient,
  ipswConfigurationAvailability,
  resolveIpswConfiguration,
  type IpswClientIdentity,
  type IpswConfiguration,
  IpswConfigurationFailure,
} from "./IpswConfiguration.js";
import {
  parseClassMetadataOutput,
  parseCrashSymbolicationOutput,
  parseDscManifestOutput,
  parseIpswInfoOutput,
  parseIpswJson,
  parseMachoEntitlementsOutput,
} from "./IpswOutput.js";
import {
  IPSW_DEFAULT_DSC_DIRECTORY,
  IPSW_DSC_PATH_REMEDIATION,
  IPSW_LANE_UNVERIFIED_NOTE,
  IPSW_PROVIDER_ID,
  IPSW_PROVIDER_NAME,
} from "./IpswRelease.js";

export const IPSW_PROVIDER_IDENTITY = {
  id: IPSW_PROVIDER_ID,
  name: IPSW_PROVIDER_NAME,
  version: null,
} as const;

export interface IpswProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly platform?: NodeJS.Platform;
  /** Override runtime-root creation at the provider's owned-resource boundary. */
  readonly createRuntimeRoot?: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<Pick<PrivateRuntimeRoot, "path" | "close">>;
}

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;

interface IpswInstallation {
  readonly configuration: IpswConfiguration;
  readonly identity: IpswClientIdentity;
}

interface FileDigest {
  readonly bytes: number;
  readonly sha256: string;
}

const laneLimitation = [IPSW_LANE_UNVERIFIED_NOTE];

const providerOf = (installation: IpswInstallation) => ({
  ...IPSW_PROVIDER_IDENTITY,
  version: installation.identity.version,
});

const clientOf = (installation: IpswInstallation) => ({
  command: installation.configuration.command,
  version: installation.identity.version,
});

type RunFn = (
  args: readonly string[],
  timeoutMs: number,
) => Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
>;

/** iOS static-image inspection over a caller-supplied blacktop/ipsw CLI. */
export class IpswProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #platform: NodeJS.Platform;
  readonly #createRuntimeRoot: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly #resources = new ArtifactResourceScope();
  readonly #retainedRoots = new Set<RuntimeRoot>();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: IpswProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#platform = options.platform ?? process.platform;
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      ((rootOptions) => PrivateRuntimeRoot.create(rootOptions));
  }

  /** Probe the selected binary; never reads an archive or shared cache. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const configuration = resolveIpswConfiguration(this.#environment);
      const identity = await inspectIpswClient(configuration, signal);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          version: identity.version,
          version_probed: true,
          dsc_path: configuration.dscPath,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof IpswConfigurationFailure)
        return ipswConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The ipsw readiness probe failed",
        diagnostics: {},
      };
    }
  }

  /** Stop admission, await active work, retry staging roots, release descriptors. */
  close(): Promise<void> {
    this.#closing = true;
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = (async () => {
      await Promise.all(this.#activeOperations);
      await this.#retryStagingRoots();
      await this.#resources.close();
    })().finally(() => {
      if (this.#closePromise === closing) this.#closePromise = undefined;
    });
    this.#closePromise = closing;
    return this.#closePromise;
  }

  #retryStagingRoots(): Promise<void> {
    return (async () => {
      const failures: unknown[] = [];
      for (const root of [...this.#retainedRoots]) {
        try {
          await root.close();
          this.#retainedRoots.delete(root);
        } catch (cause: unknown) {
          failures.push(cause);
        }
      }
      if (failures.length > 0)
        throw new ProviderCleanupError(
          IPSW_PROVIDER_ID,
          [...this.#retainedRoots].map((root) => root.path),
          {
            reason: failures
              .map((cause) =>
                cause instanceof Error ? cause.message : String(cause),
              )
              .join("; "),
          },
          {
            operation: "close_binary",
            cause: new AggregateError(failures, "ipsw staging roots remain"),
          },
        );
    })();
  }

  async execute(
    request: IpswRequest,
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
      const { operation } = request;
      const run: RunFn = (args, timeoutMs) =>
        runIpswCommand(
          operation,
          installation.value.configuration.command,
          args,
          { timeoutMs },
          signal,
          {
            withholdOutput: operation === "inspect_macho_entitlements",
          },
        );
      switch (operation) {
        case "inspect_ipsw":
          return await this.#inspectIpsw(
            installation.value,
            request.input.path,
            run,
          );
        case "extract_dyld_shared_cache_images":
          return await this.#extractCacheImages(
            installation.value,
            request.input,
            signal,
            run,
          );
        case "dump_ios_class_metadata":
          return await this.#dumpClassMetadata(
            installation.value,
            request.input,
            signal,
            run,
          );
        case "symbolicate_ios_crash":
          return await this.#symbolicateCrash(
            installation.value,
            request.input,
            signal,
            run,
          );
        case "inspect_macho_entitlements":
          return await this.#inspectEntitlements(
            installation.value,
            request.input.path,
            signal,
            run,
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
  ): Promise<Result<IpswInstallation, AnalysisError>> {
    try {
      const configuration = resolveIpswConfiguration(this.#environment);
      const identity = await inspectIpswClient(
        configuration,
        signal,
        operation,
      );
      return ok({ configuration, identity });
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof IpswConfigurationFailure)
        return err(
          providerConfigurationRefusal(IPSW_PROVIDER_ID, operation, cause),
        );
      return err(
        new AnalysisProtocolError(
          `ipsw readiness probe failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #inspectIpsw(
    installation: IpswInstallation,
    path: string,
    run: RunFn,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const bytes = await fileBytes("inspect_ipsw", path, "The selected archive");
    if (!bytes.ok) return bytes;
    const ran = await run(
      ipswArguments.inspect_ipsw(path),
      installation.configuration.operationTimeoutMs,
    );
    if (!ran.ok) return ran;
    const info = parseIpswInfoOutput(parseIpswJson(ran.value.stdout));
    if (info === null)
      return err(
        new AnalysisProtocolError(
          "ipsw info did not return a recognizable archive inventory; its first bytes are preserved",
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          path,
          bytes: bytes.value,
          product: info.product,
          version: info.version,
          build: info.build,
          build_train: info.buildTrain,
          device_identifiers: [...info.deviceIdentifiers],
          partitions: info.partitions.map((partition) => ({
            name: partition.name,
            bytes: partition.bytes,
            sha256: partition.sha256,
          })),
          partition_count: info.partitions.length,
          coverage:
            info.unparsedEntries > 0 ||
            !info.devicesReported ||
            !info.partitionsReported
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          limitations: [
            ...laneLimitation,
            "REA does not verify the archive's signature or installability; ipsw reports the inventory",
            "The archive digest is not computed here because IPSW files commonly exceed a bounded scan",
            ...(info.unparsedEntries > 0
              ? [
                  "Unrecognized inventory rows were counted, not guessed, so this inventory is partial",
                ]
              : []),
            ...(info.devicesReported
              ? []
              : [
                  "The inventory did not report device identifiers; they remain unknown, not empty",
                ]),
            ...(info.partitionsReported
              ? []
              : [
                  "The inventory did not report partition rows; they remain unknown, not empty",
                ]),
          ],
          locations: [{ kind: "artifact-path", path }],
        },
      ),
    );
  }

  async #extractCacheImages(
    installation: IpswInstallation,
    input: {
      readonly cache?: string | undefined;
      readonly output_directory: string;
      readonly images?: readonly string[] | undefined;
      readonly max_images: number;
    },
    signal: AbortSignal | undefined,
    run: RunFn,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const cache = await this.#requireCache(
      "extract_dyld_shared_cache_images",
      installation.configuration.dscPath,
      input.cache,
    );
    if (!cache.ok) return cache;
    const info = await run(
      ipswArguments.dyld_info(cache.value.path),
      installation.configuration.operationTimeoutMs,
    );
    if (!info.ok) return info;
    const manifest = parseDscManifestOutput(parseIpswJson(info.value.stdout));
    if (manifest === null)
      return err(
        new AnalysisProtocolError(
          "ipsw dyld info did not return a recognizable cache manifest",
          { diagnostics: { stdout_excerpt: info.value.stdout.slice(0, 256) } },
        ),
      );
    const emptyManifest = manifest.images.length === 0;
    const manifestTruncated = manifest.images.length > input.max_images;
    const manifestRows = manifest.images.slice(0, input.max_images);
    const requested =
      input.images === undefined
        ? manifestRows.map(({ name }) => name)
        : [...input.images];
    const selected: { readonly name: string; readonly path: string | null }[] =
      [];
    const missing: string[] = [];
    for (const selector of requested) {
      const match = manifest.images.find(
        (image) =>
          image.name === selector ||
          image.path === selector ||
          (image.path !== null && image.path.endsWith(`/${selector}`)),
      );
      if (match === undefined) missing.push(selector);
      else if (!selected.some(({ name }) => name === match.name))
        selected.push({ name: match.name, path: match.path });
    }
    if (selected.length === 0 && (!emptyManifest || input.images !== undefined))
      return err(
        new AnalysisInputError(
          "extract_dyld_shared_cache_images",
          {
            userMessage: `None of the selected image names exist in the cache manifest for ${cache.value.path}`,
          },
          missing.map((selector) => ({
            path: ["images"],
            reason: "invalid_value" as const,
            message: `No manifest image matches ${selector}`,
          })),
        ),
      );
    if (selected.length > input.max_images)
      return err(
        new AnalysisInputError(
          "extract_dyld_shared_cache_images",
          {
            userMessage: `The request selects ${String(selected.length)} images but max_images is ${String(input.max_images)}`,
          },
          [
            {
              path: ["max_images"],
              reason: "out_of_range",
              message: "Raise max_images or narrow the image selectors",
            },
          ],
        ),
      );
    const prepared = await prepareOutputDirectory(
      "extract_dyld_shared_cache_images",
      input.output_directory,
    );
    if (!prepared.ok) return prepared;
    return await this.#withStagingRoot(
      "extract_dyld_shared_cache_images",
      async (root) => {
        const stagedDirectory = join(root.path, "images");
        let staged: {
          readonly files: readonly string[];
          readonly truncated: boolean;
        } = { files: [], truncated: false };
        if (!emptyManifest) {
          await mkdir(stagedDirectory, { mode: 0o700 });
          const extracted = await run(
            ipswArguments.dyld_extract(
              cache.value.path,
              stagedDirectory,
              selected.map(({ name }) => name),
            ),
            installation.configuration.extractionTimeoutMs,
          );
          if (!extracted.ok) return extracted;
          staged = await listStagedFiles(stagedDirectory, input.max_images);
        }
        const destination = join(
          prepared.value,
          `rea-ipsw-${basename(cache.value.path).replaceAll(/[^\w.-]+/gu, "-")}-images`,
        );
        const published = await this.#publishFiles(
          "extract_dyld_shared_cache_images",
          stagedDirectory,
          destination,
          staged.files,
          signal,
        );
        if (!published.ok) return published;
        return ok(
          createAnalysisExecution(
            {
              client: clientOf(installation),
              cache_path: cache.value.path,
              cache_bytes: cache.value.bytes,
              architecture: manifest.architecture,
              image_count: manifest.images.length,
              manifest: manifestRows.map(({ name, path, address, bytes }) => ({
                name,
                path,
                address,
                bytes,
              })),
              manifest_truncated: manifestTruncated,
              requested,
              missing,
              output_directory: destination,
              published: published.value.files,
              published_truncated: staged.truncated,
              coverage:
                missing.length > 0 ||
                staged.truncated ||
                manifestTruncated ||
                manifest.unparsedEntries > 0
                  ? ("partial" as const)
                  : ("complete" as const),
            },
            providerOf(installation),
            {
              limitations: [
                ...laneLimitation,
                "The manifest reports what ipsw recognized; unrecognized cache entries were counted, not guessed",
                ...(missing.length > 0
                  ? [
                      "Selectors the manifest did not contain are reported as missing, never substituted",
                    ]
                  : []),
                ...(staged.truncated
                  ? [
                      `Extraction produced more files than max_images (${String(input.max_images)}); only the first files are published`,
                    ]
                  : []),
                ...(manifestTruncated
                  ? [
                      `Only the first ${String(input.max_images)} manifest images are reported`,
                    ]
                  : []),
                "The shared cache itself is not digested; only each published image is",
              ],
              locations: [
                { kind: "artifact-path", path: cache.value.path },
                { kind: "artifact-path", path: destination },
              ],
            },
          ),
        );
      },
      signal,
    );
  }

  async #dumpClassMetadata(
    installation: IpswInstallation,
    input: {
      readonly path: string;
      readonly family: "objc" | "swift";
      readonly max_classes: number;
    },
    signal: AbortSignal | undefined,
    run: RunFn,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await this.#digestFile(
      "dump_ios_class_metadata",
      input.path,
      signal,
    );
    if (!digest.ok) return digest;
    const ran = await run(
      ipswArguments.dump_ios_class_metadata(input.path, input.family),
      installation.configuration.operationTimeoutMs,
    );
    if (!ran.ok) return ran;
    const table = parseClassMetadataOutput(parseIpswJson(ran.value.stdout));
    if (table === null)
      return err(
        new AnalysisProtocolError(
          `ipsw ${input.family} metadata output was not recognizable`,
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const classes = table.classes.slice(0, input.max_classes);
    const truncated = table.classes.length > classes.length;
    const methodCount = classes.reduce(
      (total, entry) => total + entry.methods.length,
      0,
    );
    const ivarCount = classes.reduce(
      (total, entry) => total + entry.ivars.length,
      0,
    );
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          path: input.path,
          sha256: digest.value.sha256,
          bytes: digest.value.bytes,
          family: input.family,
          classes: classes.map((entry) => ({
            name: entry.name,
            superclass: entry.superclass,
            protocols: [...entry.protocols],
            methods: entry.methods.map((method) => ({
              name: method.name,
              kind: method.kind,
              return_type: method.returnType,
              parameter_types: [...method.parameterTypes],
            })),
            ivars: entry.ivars.map((ivar) => ({
              name: ivar.name,
              type: ivar.type,
              offset: ivar.offset,
            })),
          })),
          class_count: classes.length,
          method_count: methodCount,
          ivar_count: ivarCount,
          truncated,
          unparsed_entries: table.unparsedEntries,
          coverage:
            truncated || table.unparsedEntries > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          subject: {
            path: input.path,
            format: "mach-o",
            sha256: digest.value.sha256,
          },
          limitations: [
            ...laneLimitation,
            "Type tables are structural: method bodies, field values, and property defaults are absent",
            ...(truncated
              ? [
                  `Only the first ${String(input.max_classes)} classes are reported`,
                ]
              : []),
            ...(table.unparsedEntries > 0
              ? ["Unrecognized metadata entries were counted, not guessed"]
              : []),
          ],
          locations: [{ kind: "artifact-path", path: input.path }],
        },
      ),
    );
  }

  async #symbolicateCrash(
    installation: IpswInstallation,
    input: { readonly crash: string; readonly cache?: string | undefined },
    signal: AbortSignal | undefined,
    run: RunFn,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const cache = await this.#requireCache(
      "symbolicate_ios_crash",
      installation.configuration.dscPath,
      input.cache,
    );
    if (!cache.ok) return cache;
    const digest = await this.#digestFile(
      "symbolicate_ios_crash",
      input.crash,
      signal,
    );
    if (!digest.ok) return digest;
    const ran = await run(
      ipswArguments.symbolicate_ios_crash(input.crash, cache.value.path),
      installation.configuration.operationTimeoutMs,
    );
    if (!ran.ok) return ran;
    const symbolic = parseCrashSymbolicationOutput(
      parseIpswJson(ran.value.stdout),
    );
    if (symbolic === null)
      return err(
        new AnalysisProtocolError(
          "ipsw symbolicate did not return a recognizable crash report",
          { diagnostics: { stdout_excerpt: ran.value.stdout.slice(0, 256) } },
        ),
      );
    const frameCount = symbolic.threads.reduce(
      (total, thread) => total + thread.frames.length,
      0,
    );
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          crash_path: input.crash,
          crash_bytes: digest.value.bytes,
          crash_sha256: digest.value.sha256,
          cache_path: cache.value.path,
          threads: symbolic.threads.map((thread) => ({
            id: thread.id,
            name: thread.name,
            crashed: thread.crashed,
            frames: thread.frames.map((frame) => ({
              index: frame.index,
              image: frame.image,
              symbol: frame.symbol,
              address: frame.address,
              offset: frame.offset,
              source_file: frame.sourceFile,
              source_line: frame.sourceLine,
            })),
          })),
          frame_count: frameCount,
          unparsed_entries: symbolic.unparsedEntries,
          coverage:
            symbolic.unparsedEntries > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          subject: {
            path: input.crash,
            format: "file",
            sha256: digest.value.sha256,
          },
          limitations: [
            ...laneLimitation,
            "Frames the symbolizer leaves unresolved keep null symbol and source fields; they are not inferred",
            "Symbolication depends on the selected cache matching the report's build",
            ...(symbolic.unparsedEntries > 0
              ? ["Unrecognized frame or thread rows were counted, not guessed"]
              : []),
          ],
          locations: [
            { kind: "artifact-path", path: input.crash },
            { kind: "artifact-path", path: cache.value.path },
          ],
        },
      ),
    );
  }

  async #inspectEntitlements(
    installation: IpswInstallation,
    path: string,
    signal: AbortSignal | undefined,
    run: RunFn,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await this.#digestFile(
      "inspect_macho_entitlements",
      path,
      signal,
    );
    if (!digest.ok) return digest;
    const ran = await run(
      ipswArguments.inspect_macho_entitlements(path),
      installation.configuration.operationTimeoutMs,
    );
    if (!ran.ok) return ran;
    const summary = parseMachoEntitlementsOutput(
      parseIpswJson(ran.value.stdout),
    );
    if (summary === null)
      return err(
        new AnalysisProtocolError(
          "ipsw macho info did not return recognizable entitlements or load commands; the raw document is withheld because it can embed entitlement values",
          { diagnostics: { stdout_bytes: ran.value.stdoutBytes } },
        ),
      );
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          path,
          sha256: digest.value.sha256,
          bytes: digest.value.bytes,
          architecture: summary.architecture,
          file_type: summary.fileType,
          entitlements: summary.entitlements.map(({ key, valueKind }) => ({
            key,
            value_kind: valueKind,
          })),
          entitlement_count: summary.entitlements.length,
          load_commands: summary.loadCommands.map(
            ({ command, size, offset }) => ({ command, size, offset }),
          ),
          load_command_count: summary.loadCommands.length,
          unparsed_entries: summary.unparsedEntries,
          coverage:
            summary.unparsedEntries > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          subject: {
            path,
            format: "mach-o",
            sha256: digest.value.sha256,
          },
          limitations: [
            ...laneLimitation,
            "Entitlement values, including team identifiers, are withheld; only keys and value kinds are reported",
            ...(summary.unparsedEntries > 0
              ? [
                  "Unrecognized entitlement or load-command rows were counted, not guessed",
                ]
              : []),
          ],
          locations: [{ kind: "artifact-path", path }],
        },
      ),
    );
  }

  /**
   * Select the shared cache requested by the caller, configured through
   * `REA_IPSW_DSC_PATH`, or found read-only at the macOS cryptex default.
   * A directory must contain exactly one cache; nothing is scanned deeply.
   */
  async #requireCache(
    operation: string,
    configured: string | null,
    explicit: string | undefined,
  ): Promise<
    Result<{ readonly path: string; readonly bytes: number }, AnalysisError>
  > {
    const requested =
      explicit ??
      configured ??
      (this.#platform === "darwin" ? IPSW_DEFAULT_DSC_DIRECTORY : undefined);
    if (requested === undefined)
      return err(
        providerConfigurationRefusal(
          IPSW_PROVIDER_ID,
          operation,
          new IpswConfigurationFailure(
            "not_configured",
            "No dyld shared cache is selected and this host has no default cache directory",
            { remediation: IPSW_DSC_PATH_REMEDIATION },
          ),
        ),
      );
    let info: Awaited<ReturnType<typeof stat>>;
    try {
      info = await stat(requested);
    } catch (cause) {
      const missing = (cause as NodeJS.ErrnoException).code === "ENOENT";
      if (missing && explicit !== undefined)
        return err(
          new AnalysisInputError(operation, {
            userMessage: `The selected shared cache does not exist: ${requested}`,
          }),
        );
      if (missing)
        return err(
          providerConfigurationRefusal(
            IPSW_PROVIDER_ID,
            operation,
            new IpswConfigurationFailure(
              "not_configured",
              `No dyld shared cache was found at ${requested}`,
              {
                configured_path: requested,
                remediation: IPSW_DSC_PATH_REMEDIATION,
              },
            ),
          ),
        );
      return err(
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The selected shared cache could not be inspected: ${requested}`,
        }),
      );
    }
    if (info.isFile()) return ok({ path: requested, bytes: info.size });
    if (!info.isDirectory())
      return err(
        new AnalysisInputError(operation, {
          userMessage: `The selected shared cache path is neither a file nor a directory: ${requested}`,
        }),
      );
    let names: string[];
    try {
      names = (await readdir(requested))
        .filter(
          (name) =>
            name.startsWith("dyld_shared_cache_") &&
            !name.endsWith(".map") &&
            !name.endsWith(".symbols") &&
            !name.endsWith(".json"),
        )
        .sort();
    } catch (cause) {
      return err(
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The selected shared cache directory could not be read: ${requested}`,
        }),
      );
    }
    if (names.length !== 1)
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage:
              names.length === 0
                ? `No dyld_shared_cache_* file exists in ${requested}`
                : `${requested} holds ${String(names.length)} shared caches; pass cache explicitly to choose one`,
          },
          names.length === 0
            ? []
            : [
                {
                  path: ["cache"],
                  reason: "invalid_value" as const,
                  message: `Available caches: ${names.join(", ")}`,
                },
              ],
        ),
      );
    const path = join(requested, names[0]!);
    const file = await fileBytes(operation, path, "The selected shared cache");
    return file.ok ? ok({ path, bytes: file.value }) : file;
  }

  /**
   * Run one operation inside a private runtime root that is removed at the
   * operation's exit; a root whose removal cannot be confirmed stays owned by
   * the provider for close-time retry.
   */
  async #withStagingRoot(
    operation: string,
    work: (
      root: RuntimeRoot,
    ) => Promise<Result<AnalysisExecution, AnalysisError>>,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (signal?.aborted === true)
      return err(new AnalysisCancelledError(operation));
    let root: RuntimeRoot;
    try {
      root = await this.#createRuntimeRoot();
    } catch (cause: unknown) {
      return err(
        new ProviderCleanupError(
          IPSW_PROVIDER_ID,
          ["the ipsw operation staging root"],
          {
            reason: `The private staging root could not be created: ${
              cause instanceof Error ? cause.message : String(cause)
            }`,
          },
          { operation, cause },
        ),
      );
    }
    const closeRoot = async (): Promise<
      | { readonly cleanupError: undefined }
      | { readonly cleanupError: AnalysisError }
    > => {
      try {
        await root.close();
        return { cleanupError: undefined };
      } catch (cause: unknown) {
        this.#retainedRoots.add(root);
        return {
          cleanupError: new ProviderCleanupError(
            IPSW_PROVIDER_ID,
            [root.path],
            { reason: cause instanceof Error ? cause.message : String(cause) },
            { operation, cause },
          ),
        };
      }
    };
    let result: Result<AnalysisExecution, AnalysisError>;
    try {
      result = await work(root);
    } catch (cause: unknown) {
      result = err(
        cause instanceof AnalysisErrorClass
          ? cause
          : new AnalysisProtocolError(`${operation} failed`, { cause }),
      );
    }
    const closed = await closeRoot();
    if (!result.ok) {
      if (closed.cleanupError === undefined) return result;
      return err(
        analysisErrorWithCleanupFailure(
          result.error,
          closed.cleanupError,
          operation,
        ),
      );
    }
    if (closed.cleanupError !== undefined) return err(closed.cleanupError);
    return result;
  }

  async #publishFiles(
    operation: string,
    stagingRoot: string,
    destinationRoot: string,
    relativePaths: readonly string[],
    signal: AbortSignal | undefined,
  ): Promise<
    Result<{ readonly files: readonly FileDigestEntry[] }, AnalysisError>
  > {
    try {
      await mkdir(destinationRoot, { mode: 0o700 });
    } catch (cause: unknown) {
      return err(
        new AnalysisOutputError(
          operation,
          `The extraction output directory already exists or could not be created: ${destinationRoot}`,
          { cause },
        ),
      );
    }
    const files: FileDigestEntry[] = [];
    const partialFailure = (
      cause: unknown,
      reason: string,
    ): AnalysisOutputError =>
      new AnalysisOutputError(operation, reason, {
        cause,
        diagnostics: {
          published_directory: destinationRoot,
          published_files: files.map(({ relative_path }) => relative_path),
          published_count: files.length,
        },
        userMessage:
          "The output directory was created exclusively for this request and already holds the listed images; REA does not replace caller artifacts, so remove it before retrying",
      });
    for (const relativePath of relativePaths) {
      const source = join(stagingRoot, relativePath);
      const destination = join(destinationRoot, relativePath);
      try {
        await mkdir(dirname(destination), { recursive: true });
        await copyFile(source, destination, constants.COPYFILE_EXCL);
      } catch (cause: unknown) {
        return err(
          partialFailure(
            cause,
            `An extracted image could not be published: ${destination}`,
          ),
        );
      }
      const digest = await this.#hashPublished(
        operation,
        destination,
        relativePath,
        signal,
      );
      if (!digest.ok)
        return err(
          partialFailure(
            digest.error,
            `A published image could not be fully digested after ${String(files.length)} successful publications: ${destination}`,
          ),
        );
      files.push({
        relative_path: relativePath,
        bytes: digest.value.bytes,
        sha256: digest.value.sha256,
      });
    }
    return ok({ files });
  }

  async #digestFile(
    operation: string,
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<FileDigest, AnalysisError>> {
    try {
      const digest = await hashStableFile(path, {
        ...(signal === undefined ? {} : { signal }),
        retainFailedClose: (handle) => this.#retainHandle(path, handle),
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
          userMessage: `The selected file could not be read and digested: ${path}`,
        }),
      );
    }
  }

  async #hashPublished(
    operation: string,
    path: string,
    label: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<FileDigest, AnalysisError>> {
    try {
      const digest = await hashStableFile(path, {
        ...(signal === undefined ? {} : { signal }),
        retainFailedClose: (handle) => this.#retainHandle(path, handle),
      });
      return ok({ bytes: digest.bytes, sha256: digest.sha256 });
    } catch (cause: unknown) {
      if (cause instanceof RegularFileOperationCancelled)
        return err(
          new AnalysisCancelledError(operation, { cause: cause.reason }),
        );
      return err(
        new AnalysisOutputError(
          operation,
          `The published image could not be fully digested: ${label}`,
          { cause },
        ),
      );
    }
  }

  #retainHandle(path: string, handle: { close(): Promise<void> }): void {
    this.#resources.retain({
      kind: "lease",
      resource: path,
      lease: new AnalysisCleanupLease(() => handle.close(), [path]),
    });
  }
}

interface FileDigestEntry {
  readonly relative_path: string;
  readonly bytes: number;
  readonly sha256: string;
}

const fileBytes = async (
  operation: string,
  path: string,
  what: string,
): Promise<Result<number, AnalysisError>> => {
  try {
    const info = await stat(path);
    if (!info.isFile())
      return err(
        new AnalysisInputError(operation, {
          userMessage: `${what} is not a regular file: ${path}`,
        }),
      );
    return ok(info.size);
  } catch (cause) {
    return err(
      new AnalysisInputError(operation, {
        cause,
        userMessage: `${what} could not be read: ${path}`,
      }),
    );
  }
};

/** Materialize the caller's output directory, refusing unwritable targets. */
const prepareOutputDirectory = async (
  operation: string,
  directory: string,
): Promise<Result<string, AnalysisError>> => {
  const root = resolve(directory);
  try {
    await mkdir(root, { recursive: true });
    await access(root, constants.W_OK);
  } catch (cause) {
    return err(
      new AnalysisOutputError(
        operation,
        `The output directory is not writable or could not be created: ${root}`,
        { cause },
      ),
    );
  }
  return ok(root);
};

/**
 * Collect regular files under one staging directory in stable relative-path
 * order, stopping at the publication bound.
 */
const listStagedFiles = async (
  root: string,
  limit: number,
): Promise<{
  readonly files: readonly string[];
  readonly truncated: boolean;
}> => {
  const files: string[] = [];
  let truncated = false;
  const walk = async (directory: string, prefix: string): Promise<void> => {
    if (truncated) return;
    let entries: Dirent[];
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries.sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
      if (truncated) return;
      const relativePath =
        prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory())
        await walk(join(directory, entry.name), relativePath);
      else if (entry.isFile()) {
        if (files.length >= limit) {
          truncated = true;
          return;
        }
        files.push(relativePath);
      }
    }
  };
  await walk(root, "");
  return { files, truncated };
};
