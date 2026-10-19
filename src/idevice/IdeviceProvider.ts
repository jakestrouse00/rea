import { constants } from "node:fs";
import { access, copyFile, mkdir, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";

import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisError as AnalysisErrorClass } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  stableFileHashCause,
  hashStableFile,
} from "../filesystem/StableFileHash.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  PrivateRuntimeRoot,
  type PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";
import type { IdeviceRequest } from "../domain/idevice/ideviceDeviceAnalysis.js";
import {
  IDEVICE_MAX_OUTPUT_BYTES,
  runIdeviceCommand,
  type IdeviceProcessLauncher,
} from "./IdeviceCommand.js";
import {
  parseIdeviceAppsOutput,
  parseIdeviceCrashListOutput,
  parseIdeviceDevicesOutput,
  parseLockdownDeviceInfo,
} from "./IdeviceDeviceOutput.js";
import {
  inspectIdeviceInstallation,
  type IdeviceInstallation,
  type IdeviceReadinessFailure,
} from "./IdeviceInstallation.js";
import {
  IDEVICE_COMMAND_REMEDIATION,
  IDEVICE_LANE_UNVERIFIED_NOTE,
  IDEVICE_PROVIDER_ID,
  IDEVICE_UNSUPPORTED_HOST_REMEDIATION,
  IDEVICE_VERSION_PROBE_REMEDIATION,
} from "./IdeviceRelease.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";

export const IDEVICE_PROVIDER_IDENTITY = {
  id: IDEVICE_PROVIDER_ID,
  name: "pymobiledevice3 (iOS device plane)",
  version: null,
} as const;

export interface IdeviceProviderOptions {
  readonly environment?: Readonly<NodeJS.ProcessEnv>;
  readonly platform?: NodeJS.Platform;
  /** Override runtime-root creation at the provider's owned-resource boundary. */
  readonly createRuntimeRoot?: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<Pick<PrivateRuntimeRoot, "path" | "close">>;
  /** Test seam for the owned child launcher; production runs the executable. */
  readonly launcher?: IdeviceProcessLauncher;
}

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;

interface ArtifactDigest {
  readonly bytes: number;
  readonly sha256: string;
}

const providerOf = (installation: IdeviceInstallation) => ({
  ...IDEVICE_PROVIDER_IDENTITY,
  version: installation.version,
});

const clientOf = (installation: IdeviceInstallation) => ({
  command: installation.executable,
  version: installation.version,
  verified: installation.verified,
});

const laneLimitation = [IDEVICE_LANE_UNVERIFIED_NOTE];

/** pmd3 reads the device UDID from this global flag in every device-group command. */
const UDIFF_FLAG = "-u";

type RunFn = (
  args: readonly string[],
  timeoutMs?: number,
) => Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
>;

export class IdeviceProvider {
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #platform: NodeJS.Platform;
  readonly #createRuntimeRoot: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly #launcher: IdeviceProcessLauncher | undefined;
  readonly #resources = new ArtifactResourceScope();
  readonly #retainedRoots = new Set<RuntimeRoot>();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: IdeviceProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#platform = options.platform ?? process.platform;
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      ((rootOptions) => PrivateRuntimeRoot.create(rootOptions));
    this.#launcher = options.launcher;
  }

  /** Probe the selected launcher; never contacts usbmuxd or devices. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const installation = await inspectIdeviceInstallation(this.#environment, {
        platform: this.#platform,
        ...(signal === undefined ? {} : { signal }),
      });
      if (!installation.ok)
        return {
          status: "unavailable",
          code: installation.error.code,
          reason: installation.error.reason,
          diagnostics: { ...installation.error.diagnostics },
        };
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: installation.value.executable,
          version: installation.value.version,
          version_probed: true,
        },
      };
    } catch (cause: unknown) {
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The launcher readiness probe failed",
        diagnostics: {},
      };
    }
  }

  /** Stop admission, await active work, retry retained staging roots, release descriptors. */
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
          IDEVICE_PROVIDER_ID,
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
            cause: new AggregateError(failures, "iOS staging roots remain"),
          },
        );
    })();
  }

  async execute(
    request: IdeviceRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    if (this.#closing || signal?.aborted === true)
      return err(new AnalysisCancelledError(request.operation));
    let release!: () => void;
    const active = new Promise<void>((resolve) => {
      release = resolve;
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
        runIdeviceCommand(
          operation,
          installation.value.executable,
          args,
          {
            timeoutMs:
              timeoutMs ?? installation.value.configuration.operationTimeoutMs,
          },
          signal,
          this.#launcher,
        );
      switch (operation) {
        case "list_ios_devices":
          return this.#listDevices(
            installation.value,
            await run(["usbmux", "list"]),
          );
        case "inspect_ios_device":
          return this.#inspectDevice(
            installation.value,
            request.input.udid,
            await run(["lockdown", "info", UDIFF_FLAG, request.input.udid]),
          );
        case "read_ios_syslog":
          return this.#readSyslog(
            installation.value,
            request.input,
            signal,
            run,
          );
        case "capture_ios_screenshot":
          return this.#captureScreenshot(
            installation.value,
            request.input.udid,
            request.input.output_directory,
            signal,
            run,
          );
        case "list_ios_crash_reports":
          return this.#listCrashReports(
            installation.value,
            request.input.udid,
            await run(["crash", "list", UDIFF_FLAG, request.input.udid]),
          );
        case "inspect_ios_crash":
          return this.#pullCrashReport(
            installation.value,
            request.input,
            signal,
            run,
          );
        case "list_ios_apps":
          return this.#listApps(
            installation.value,
            request.input.udid,
            await run(["apps", "list", UDIFF_FLAG, request.input.udid]),
          );
        case "inspect_ios_provisioning":
          return this.#inspectProvisioning(
            installation.value,
            request.input,
            await run(["apps", "list", UDIFF_FLAG, request.input.udid]),
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
  ): Promise<Result<IdeviceInstallation, AnalysisError>> {
    try {
      const inspected = await inspectIdeviceInstallation(this.#environment, {
        platform: this.#platform,
        ...(signal === undefined ? {} : { signal }),
      });
      if (!inspected.ok)
        return err(
          providerConfigurationRefusal(
            IDEVICE_PROVIDER_ID,
            operation,
            readinessRefusal(inspected.error),
          ),
        );
      return ok(inspected.value);
    } catch (cause: unknown) {
      // An aborted readiness probe is caller cancellation, not a protocol
      // violation; the typed cancellation reason carries the abort cause.
      if (signal?.aborted)
        return err(
          new AnalysisCancelledError(operation, { cause: signal.reason }),
        );
      return err(
        cause instanceof AnalysisErrorClass
          ? cause
          : new AnalysisProtocolError(
              `pymobiledevice3 readiness probe failed for ${operation}`,
              { cause },
            ),
      );
    }
  }

  #listDevices(
    installation: IdeviceInstallation,
    ran: Awaited<ReturnType<RunFn>>,
  ): Result<AnalysisExecution, AnalysisError> {
    if (!ran.ok) return ran;
    const { devices, unparsedLines } = parseIdeviceDevicesOutput(
      ran.value.stdout,
    );
    if (devices.length === 0 && !looksLikeInventory(ran.value.stdout))
      return err(unparseable(ran.value.stdout, "device inventory"));
    // An empty inventory is an unpaired host, not an error.
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          devices,
          unparsed_lines: unparsedLines,
          coverage:
            unparsedLines.length > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          limitations: [
            ...laneLimitation,
            "Pairing status is unknown unless the launcher reports it explicitly",
            ...(unparsedLines.length > 0
              ? [
                  "unparsed_lines preserves launcher inventory entries REA did not recognize",
                ]
              : []),
          ],
        },
      ),
    );
  }

  #inspectDevice(
    installation: IdeviceInstallation,
    udid: string,
    ran: Awaited<ReturnType<RunFn>>,
  ): Result<AnalysisExecution, AnalysisError> {
    if (!ran.ok) return ran;
    const info = parseLockdownDeviceInfo(ran.value.stdout);
    if (info.fields.length === 0)
      return err(unparseable(ran.value.stdout, "lockdown info"));
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          udid,
          device_name: info.deviceName,
          product_type: info.productType,
          ios_version: info.iosVersion,
          connection_type: info.connectionType,
          fields: info.fields,
          unparsed_lines: info.unparsedLines,
          coverage:
            info.unparsedLines.length > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          limitations: [
            ...laneLimitation,
            "fields preserves the launcher's own lockdown record; structured values stay unknown rather than being stringified guesses",
          ],
        },
      ),
    );
  }

  async #readSyslog(
    installation: IdeviceInstallation,
    input: {
      readonly udid: string;
      readonly timeout_seconds: number;
      readonly process_filter?: string | undefined;
    },
    signal: AbortSignal | undefined,
    run: RunFn,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const ran = await run(
      [
        "syslog",
        UDIFF_FLAG,
        input.udid,
        "--timeout",
        String(input.timeout_seconds),
      ],
      (input.timeout_seconds + 1) * 1000 + SYSLOG_GRACE_MS,
    );
    if (!ran.ok) return ran;
    const kept = ran.value.stdout
      .split(/\r?\n/u)
      .filter(
        (line) =>
          line.trim() !== "" &&
          (input.process_filter === undefined ||
            line.toLowerCase().includes(input.process_filter.toLowerCase())),
      );
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          udid: input.udid,
          timeout_seconds: input.timeout_seconds,
          process_filter: input.process_filter ?? null,
          lines: kept,
          total_bytes: ran.value.stdoutBytes,
          coverage:
            ran.value.stdoutBytes >= IDEVICE_MAX_OUTPUT_BYTES
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          limitations: [
            ...laneLimitation,
            "This is a bounded one-shot dump; the stream ends when the requested timeout elapses",
            "process_filter matches raw line text, not structured syslog fields",
          ],
        },
      ),
    );
  }

  async #captureScreenshot(
    installation: IdeviceInstallation,
    udid: string,
    outputDirectory: string,
    signal: AbortSignal | undefined,
    run: RunFn,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const prepared = await prepareOutputDirectory(
      "capture_ios_screenshot",
      outputDirectory,
    );
    if (!prepared.ok) return prepared;
    return await this.#withStagingRoot(
      "capture_ios_screenshot",
      async (root) => {
        const staged = join(root.path, "idevice-screenshot.png");
        // `developer` is a device-group command like `lockdown`/`crash`: the
        // caller-selected UDID must reach the launcher.
        const ran = await run([
          "developer",
          "dvt",
          "screenshot",
          UDIFF_FLAG,
          udid,
          staged,
        ]);
        if (!ran.ok) return ran;
        const publishedPath = join(prepared.value, `rea-idevice-${udid}.png`);
        const digest = await this.#publishAndHash(
          "capture_ios_screenshot",
          staged,
          publishedPath,
          signal,
        );
        if (!digest.ok) return digest;
        return ok(
          createAnalysisExecution(
            {
              client: clientOf(installation),
              udid,
              local_path: publishedPath,
              bytes: digest.value.bytes,
              sha256: digest.value.sha256,
            },
            providerOf(installation),
            {
              limitations: [
                ...laneLimitation,
                "The capture is one frame at read time; no recording or interaction occurred",
              ],
            },
          ),
        );
      },
      signal,
    );
  }

  #listCrashReports(
    installation: IdeviceInstallation,
    udid: string,
    ran: Awaited<ReturnType<RunFn>>,
  ): Result<AnalysisExecution, AnalysisError> {
    if (!ran.ok) return ran;
    const { reports, unparsedLines } = parseIdeviceCrashListOutput(
      ran.value.stdout,
    );
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          udid,
          reports,
          unparsed_lines: unparsedLines,
          coverage:
            unparsedLines.length > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          limitations: [
            ...laneLimitation,
            "Report names are preserved verbatim; dates and sizes stay unknown when the row omits them",
          ],
        },
      ),
    );
  }

  async #pullCrashReport(
    installation: IdeviceInstallation,
    input: {
      readonly udid: string;
      readonly report: string;
      readonly output_directory: string;
    },
    signal: AbortSignal | undefined,
    run: RunFn,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const prepared = await prepareOutputDirectory(
      "inspect_ios_crash",
      input.output_directory,
    );
    if (!prepared.ok) return prepared;
    return await this.#withStagingRoot(
      "inspect_ios_crash",
      async (root) => {
        const stagedDirectory = join(root.path, "crash");
        const ran = await run([
          "crash",
          "copy",
          input.report,
          UDIFF_FLAG,
          input.udid,
          "--out",
          stagedDirectory,
        ]);
        if (!ran.ok) return ran;
        const stagedFiles = await readdir(stagedDirectory).catch(
          () => [] as string[],
        );
        if (stagedFiles.length !== 1)
          return err(
            new AnalysisProtocolError(
              `crash copy produced ${String(stagedFiles.length)} files in its private staging directory; REA requires exactly one`,
            ),
          );
        const stagedName = stagedFiles[0]!;
        const publishedPath = join(
          prepared.value,
          `rea-idevice-crash-${stagedName}`,
        );
        const digest = await this.#publishAndHash(
          "inspect_ios_crash",
          join(stagedDirectory, stagedName),
          publishedPath,
          signal,
        );
        if (!digest.ok) return digest;
        return ok(
          createAnalysisExecution(
            {
              client: clientOf(installation),
              udid: input.udid,
              report: input.report,
              local_path: publishedPath,
              bytes: digest.value.bytes,
              sha256: digest.value.sha256,
            },
            providerOf(installation),
            {
              limitations: [
                ...laneLimitation,
                "The report is the device's own crash document; REA publishes it uninterpreted",
              ],
            },
          ),
        );
      },
      signal,
    );
  }

  #listApps(
    installation: IdeviceInstallation,
    udid: string,
    ran: Awaited<ReturnType<RunFn>>,
  ): Result<AnalysisExecution, AnalysisError> {
    if (!ran.ok) return ran;
    const { apps, unparsedLines } = parseIdeviceAppsOutput(ran.value.stdout);
    if (apps.length === 0 && !looksLikeInventory(ran.value.stdout))
      return err(unparseable(ran.value.stdout, "apps inventory"));
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          udid,
          apps: apps.map(({ fields: _fields, ...row }) => row),
          unparsed_lines: unparsedLines,
          coverage:
            unparsedLines.length > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        providerOf(installation),
        {
          limitations: [
            ...laneLimitation,
            "signer_restricted is unknown when the inventory does not report signer_is_restricted",
          ],
        },
      ),
    );
  }

  #inspectProvisioning(
    installation: IdeviceInstallation,
    input: { readonly udid: string; readonly bundle_id: string },
    ran: Awaited<ReturnType<RunFn>>,
  ): Result<AnalysisExecution, AnalysisError> {
    if (!ran.ok) return ran;
    const { apps, unparsedLines } = parseIdeviceAppsOutput(ran.value.stdout);
    const selected = apps.find((app) => app.bundle_id === input.bundle_id);
    if (selected === undefined)
      return ok(
        createAnalysisExecution(
          {
            client: clientOf(installation),
            udid: input.udid,
            bundle_id: input.bundle_id,
            app_found: false,
            name: null,
            version: null,
            team_name: null,
            team_identifier: null,
            provision_fields: [],
            unparsed_lines: unparsedLines,
            coverage: "partial" as const,
          },
          providerOf(installation),
          {
            limitations: [
              ...laneLimitation,
              "The selected bundle id is absent from this inventory; absence is a partial observation, not a device-wide claim",
              ...provisionUnavailableLimitations(),
            ],
          },
        ),
      );
    const provisionFields = provisionFieldsFor(selected.fields);
    return ok(
      createAnalysisExecution(
        {
          client: clientOf(installation),
          udid: input.udid,
          bundle_id: input.bundle_id,
          app_found: true,
          name: selected.name,
          version: selected.version,
          team_name:
            provisionFields.find((field) => field.key === "team_name")?.value ??
            null,
          team_identifier:
            provisionFields.find((field) => field.key === "team_identifier")
              ?.value ?? null,
          provision_fields: provisionFields,
          unparsed_lines: unparsedLines,
          coverage: "partial" as const,
        },
        providerOf(installation),
        {
          limitations: [
            ...laneLimitation,
            ...provisionUnavailableLimitations(),
          ],
        },
      ),
    );
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
          IDEVICE_PROVIDER_ID,
          ["the iOS device operation staging root"],
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
            IDEVICE_PROVIDER_ID,
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

  async #publishAndHash(
    operation: string,
    source: string,
    destination: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<ArtifactDigest, AnalysisError>> {
    try {
      await copyFile(source, destination, constants.COPYFILE_EXCL);
    } catch (cause: unknown) {
      if (cause instanceof Error && "code" in cause && cause.code === "EEXIST")
        return err(
          new AnalysisInputError(operation, {
            userMessage: `The output file already exists; REA does not replace caller artifacts: ${destination}`,
          }),
        );
      return err(
        new AnalysisProtocolError(
          `The captured artifact could not be published: ${destination}`,
          { cause },
        ),
      );
    }
    try {
      const digest = await hashStableFile(destination, {
        ...(signal === undefined ? {} : { signal }),
        retainFailedClose: (handle) => {
          const lease = new AnalysisCleanupLease(
            () => handle.close(),
            [destination],
          );
          this.#resources.retain({
            kind: "lease",
            resource: destination,
            lease,
          });
        },
      });
      return ok({ bytes: digest.bytes, sha256: digest.sha256 });
    } catch (cause: unknown) {
      // An abort observed at the digest's own cancellation checkpoint is
      // caller cancellation, not a protocol violation.
      if (cause instanceof RegularFileOperationCancelled)
        return err(
          new AnalysisCancelledError(operation, { cause: cause.reason }),
        );
      return err(
        new AnalysisProtocolError(
          `The published artifact could not be fully digested: ${destination}`,
          { cause: stableFileHashCause(cause) },
        ),
      );
    }
  }
}

/**
 * Materialize the caller's output directory, refusing unwritable targets.
 * Mirrors the ADB publication boundary: a fresh or missing directory is
 * created and validated before any staging work runs.
 */
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

const SYSLOG_GRACE_MS = 10_000;

/** Project one readiness failure into the shared provider refusal shape. */
const readinessRefusal = (
  failure: IdeviceReadinessFailure,
): Error & { readonly diagnostics?: Record<string, string> } => {
  const remediation =
    failure.code === "unsupported_host"
      ? IDEVICE_UNSUPPORTED_HOST_REMEDIATION
      : failure.code === "version_unresolved"
        ? IDEVICE_VERSION_PROBE_REMEDIATION
        : failure.code === "not_configured" ||
            failure.code === "open_options_invalid" ||
            failure.code === "executable_missing"
          ? IDEVICE_COMMAND_REMEDIATION
          : null;
  const error = new Error(failure.reason);
  return Object.assign(error, {
    diagnostics: remediation === null ? {} : { remediation },
  });
};

const provisionUnavailableLimitations = (): string[] => [
  "Embedded mobileprovision content comes from the launcher's app inventory; absent provisioning keys are unknown, never empty",
];

/** Select the launcher-reported provisioning/signing fields for one app. */
const provisionFieldsFor = (
  fields: readonly { key: string; value: string | null }[],
): { key: string; value: string | null }[] =>
  fields.filter((field) =>
    /provision|profile|entitlement|team|signer/iu.test(field.key),
  );

const unparseable = (stdout: string, what: string): AnalysisError =>
  new AnalysisProtocolError(
    `pymobiledevice3 ${what} was not recognizable; its first bytes are preserved: ${stdout.slice(0, 256)}`,
  );

/** Distinguish an absent inventory from output REA could not parse. */
const looksLikeInventory = (stdout: string): boolean => {
  const trimmed = stdout.trim();
  return trimmed.startsWith("{") || trimmed.startsWith("[");
};
