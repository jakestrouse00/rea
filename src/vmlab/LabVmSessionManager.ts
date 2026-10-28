import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import type {
  LabVmPort,
  LabVmRunRequest,
  LabVmStartRequest,
  LabVmStopRequest,
} from "../application/vmlab/LabVmPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import type { Evidence } from "../domain/evidence.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  LAB_VM_DEFAULT_COMMAND_TIMEOUT_MS,
  LAB_VM_DRIVER,
  LAB_VM_GUEST_WORKSPACE,
  LAB_VM_LIVE_CAPACITY,
  LAB_VM_MAX_WORKSPACE_CHANGES,
  LAB_VM_PROVIDER,
  LAB_VM_ROSETTA_ENABLED,
  LAB_VM_SANDBOX_NOTE,
  LAB_VM_UNSUPPORTED_HOST_REASON,
  LAB_VM_UNVERIFIED_NOTE,
  labVmHostSupported,
} from "../domain/vmlab/labVm.js";
import type {
  LabVmCall,
  LabVmCommandResult,
} from "../domain/vmlab/labVmObservation.js";
import { labVmTemplate } from "../domain/vmlab/labVmTemplate.js";
import {
  PrivateRuntimeRoot,
  type PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";
import {
  LabVmConfigurationFailure,
  labVmConfigurationAvailability,
  resolveLabVmConfiguration,
  type LabVmConfiguration,
} from "./LabVmConfiguration.js";
import {
  labVmArguments,
  runLabVmCommand,
  type LabVmCommandObservation,
} from "./LabVmCommand.js";
import {
  createLabVmCommandEvidence,
  createLabVmStartEvidence,
  createLabVmStopEvidence,
} from "./LabVmEvidence.js";
import {
  inventoryWorkspace,
  resolveWorkspacePath,
  workspaceChange,
  type WorkspaceChange,
} from "./LabVmWorkspace.js";

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;

export interface LabVmSessionManagerOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly createRuntimeRoot?: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
}

interface LabVmOwner {
  readonly sessionId: string;
  readonly vmName: string;
  readonly root: RuntimeRoot;
}

interface LiveLabVm extends LabVmOwner {
  readonly workspacePath: string;
  queue: Promise<unknown>;
}

const REMEDIATION =
  "Stop and remove the retained instance with the selected limactl, then retry stop_lab_vm or restart REA.";

const isLabVmFailure = (value: unknown): value is LabVmConfigurationFailure =>
  value instanceof LabVmConfigurationFailure;

const outputLimitLimitations = (
  observation: LabVmCommandObservation,
): readonly string[] =>
  observation.outputTruncated
    ? [
        "limactl output reached the retained byte budget; later bytes were discarded and only structural facts are reported.",
      ]
    : [];

const callOf = (observation: LabVmCommandObservation): LabVmCall => ({
  exit_type: observation.exitType,
  exit_code: observation.exitCode,
  duration_ms: observation.durationMs,
});

/**
 * Owns the caller-supplied Lima instances this process started.
 *
 * A session identity is issued only after `limactl start` observed a clean
 * exit, and it is released only after both stop and instance removal are
 * observed. Failed cleanup keeps the identity for retry, so a later call can
 * never mistake a retained instance for a released one.
 */
export class LabVmSessionManager implements LabVmPort {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #createRuntimeRoot: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly #platform: NodeJS.Platform;
  readonly #arch: string;
  readonly defaultCommandTimeoutMs = LAB_VM_DEFAULT_COMMAND_TIMEOUT_MS;
  readonly #live = new Map<string, LiveLabVm>();
  readonly #retained = new Map<string, LabVmOwner>();
  #closing = false;

  constructor(options: LabVmSessionManagerOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      ((rootOptions) => PrivateRuntimeRoot.create(rootOptions));
    this.#platform = options.platform ?? process.platform;
    this.#arch = options.arch ?? process.arch;
  }

  inspectAvailability(_signal?: AbortSignal): ProviderAvailability {
    if (!labVmHostSupported(this.#platform, this.#arch))
      return {
        status: "unavailable",
        code: "unsupported_host",
        reason: LAB_VM_UNSUPPORTED_HOST_REASON,
        diagnostics: {
          platform: this.#platform,
          architecture: this.#arch,
          required_driver: LAB_VM_DRIVER,
        },
      };
    try {
      const configuration = resolveLabVmConfiguration(this.#environment);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          version_probed: false,
          driver: LAB_VM_DRIVER,
          rosetta: LAB_VM_ROSETTA_ENABLED,
        },
      };
    } catch (cause: unknown) {
      return isLabVmFailure(cause)
        ? labVmConfigurationAvailability(cause)
        : {
            status: "unavailable",
            code: "not_configured",
            reason:
              cause instanceof Error
                ? cause.message
                : "The limactl selection failed",
            diagnostics: {},
          };
    }
  }

  async start(
    request: LabVmStartRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "start_lab_vm";
    const signal = options?.signal;
    if (this.#closing)
      return err(
        new AnalysisCapabilityUnavailableError(
          LAB_VM_PROVIDER.id,
          operation,
          "The REA server is shutting down and no longer starts lab VMs.",
        ),
      );
    if (!labVmHostSupported(this.#platform, this.#arch))
      return err(
        new AnalysisCapabilityUnavailableError(
          LAB_VM_PROVIDER.id,
          operation,
          LAB_VM_UNSUPPORTED_HOST_REASON,
          {
            diagnostics: {
              platform: this.#platform,
              architecture: this.#arch,
            },
          },
        ),
      );
    const configuration = this.#configuration(operation);
    if (!configuration.ok) return configuration;
    const owned = this.#ownedSessions();
    if (owned.size >= LAB_VM_LIVE_CAPACITY)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "capacity",
          `This REA server already owns ${String(owned.size)} lab VM; stop it with stop_lab_vm before starting another.`,
          {
            max_live_lab_vms: LAB_VM_LIVE_CAPACITY,
            live_sessions: this.#live.size,
            retained_cleanup: this.#retained.size,
          },
          {
            retryable: true,
            remediationAction:
              "Call stop_lab_vm for the live session, or retry a retained instance's cleanup, before starting another lab VM.",
          },
        ),
      );
    const workspace = await resolveWorkspacePath(
      request.workspacePath,
      operation,
    );
    if (!workspace.ok) return workspace;
    const sessionId = randomUUID();
    const vmName = `rea-lab-${sessionId.slice(0, 8)}`;
    const root = await this.#createRoot(operation);
    if (!root.ok) return root;
    const templatePath = join(root.value.path, `${vmName}.yaml`);
    try {
      await mkdir(root.value.path, { recursive: true, mode: 0o700 });
      await writeFile(templatePath, labVmTemplate(workspace.value), {
        mode: 0o600,
        flag: "wx",
      });
    } catch (cause: unknown) {
      return err(
        analysisErrorWithCleanupFailure(
          new AnalysisInputError(operation, {
            cause,
            userMessage: `The lab VM template could not be written for ${workspace.value}`,
          }),
          this.#cleanupError(vmName, operation, cause, [
            `lab-vm-template:${templatePath}`,
          ]),
          operation,
        ),
      );
    }
    const boot = await runLabVmCommand(
      operation,
      configuration.value.command,
      labVmArguments.start(vmName, templatePath),
      {
        timeoutMs: configuration.value.startTimeoutMs,
        maxOutputBytes: configuration.value.maxOutputBytes,
      },
      signal,
    );
    if (!boot.ok) {
      const rollback = await this.#removeInstance(
        configuration.value,
        { sessionId: `rollback-${vmName}`, vmName, root: root.value },
        operation,
        undefined,
      );
      if (rollback === null) return err(boot.error);
      return err(
        analysisErrorWithCleanupFailure(boot.error, rollback, operation),
      );
    }
    const live: LiveLabVm = {
      sessionId,
      vmName,
      workspacePath: workspace.value,
      root: root.value,
      queue: Promise.resolve(),
    };
    this.#live.set(sessionId, live);
    return ok(
      createLabVmStartEvidence(
        {
          workspace_path: workspace.value,
          guest_workspace: LAB_VM_GUEST_WORKSPACE,
          driver: LAB_VM_DRIVER,
          rosetta: LAB_VM_ROSETTA_ENABLED,
        },
        {
          session_id: sessionId,
          vm_name: vmName,
          workspace_path: workspace.value,
          guest_workspace: LAB_VM_GUEST_WORKSPACE,
          driver: LAB_VM_DRIVER,
          rosetta: LAB_VM_ROSETTA_ENABLED,
          boot: callOf(boot.value),
        },
        [
          LAB_VM_UNVERIFIED_NOTE,
          LAB_VM_SANDBOX_NOTE,
          "A clean limactl exit proves the start command returned, not that every guest startup script completed.",
          ...outputLimitLimitations(boot.value),
        ],
      ),
    );
  }

  async run(
    request: LabVmRunRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "run_lab_vm_command";
    const live = this.#live.get(request.sessionId);
    if (live === undefined)
      return err(
        unknownSession(
          operation,
          request.sessionId,
          this.#retained.has(request.sessionId),
        ),
      );
    return this.#enqueue(live, () =>
      this.#runOwned(live, operation, request, options?.signal),
    );
  }

  async stop(
    request: LabVmStopRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "stop_lab_vm";
    const live = this.#live.get(request.sessionId);
    if (live === undefined) {
      const retained = this.#retained.get(request.sessionId);
      if (retained === undefined)
        return err(unknownSession(operation, request.sessionId, false));
      const configuration = this.#configuration(operation);
      if (!configuration.ok) return configuration;
      return this.#retryOwner(
        configuration.value,
        retained,
        operation,
        options?.signal,
      );
    }
    return this.#enqueue(live, () =>
      this.#stopOwned(live, operation, options?.signal),
    );
  }

  async closeAll(): Promise<Result<null, AnalysisError>> {
    this.#closing = true;
    const failures = new Map<string, AnalysisError>();
    for (const live of Array.from(this.#live.values())) {
      const stopped = await this.#enqueue(live, () =>
        this.#stopOwned(live, "stop_lab_vm", undefined),
      );
      if (!stopped.ok) failures.set(live.sessionId, stopped.error);
    }
    for (const retained of Array.from(this.#retained.values())) {
      const configuration = this.#configuration("stop_lab_vm");
      if (!configuration.ok) {
        failures.set(retained.sessionId, configuration.error);
        continue;
      }
      const retried = await this.#retryOwner(
        configuration.value,
        retained,
        "stop_lab_vm",
        undefined,
      );
      if (!retried.ok) failures.set(retained.sessionId, retried.error);
    }
    if (failures.size === 0) return ok(null);
    const errors = [...failures.values()];
    return err(
      new ProviderCleanupError(
        LAB_VM_PROVIDER.id,
        [...new Set(errors.flatMap((error) => [...error.cleanupResources]))],
        {
          reason:
            "REA could not confirm removing every lab VM instance it started.",
          retained_sessions: [...failures.keys()],
        },
        {
          operation: "stop_lab_vm",
          cause: new AggregateError(
            errors,
            "Lab VM cleanup remains incomplete.",
          ),
          remediationAction: REMEDIATION,
        },
      ),
    );
  }

  async #runOwned(
    live: LiveLabVm,
    operation: string,
    request: LabVmRunRequest,
    signal: AbortSignal | undefined,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    const configuration = this.#configuration(operation);
    if (!configuration.ok) return configuration;
    const before = await inventoryWorkspace(
      live.workspacePath,
      operation,
      signal,
    );
    if (!before.ok) return before;
    const startedAt = Date.now();
    const executed = await runLabVmCommand(
      operation,
      configuration.value.command,
      labVmArguments.shell(
        live.vmName,
        LAB_VM_GUEST_WORKSPACE,
        request.command,
      ),
      {
        timeoutMs: request.timeoutMs,
        maxOutputBytes: configuration.value.maxOutputBytes,
      },
      signal,
    );
    const elapsedMs = Date.now() - startedAt;
    const after = await inventoryWorkspace(
      live.workspacePath,
      operation,
      undefined,
    );
    const result = commandFacts({
      sessionId: live.sessionId,
      command: request.command,
      timeoutMs: request.timeoutMs,
      elapsedMs,
      executed,
      changes: after.ok
        ? workspaceChange(
            before.value,
            after.value,
            LAB_VM_MAX_WORKSPACE_CHANGES,
          )
        : { produced: [], modified: [], removed: [], truncated: true },
    });
    const observed = executed.ok ? executed.value : undefined;
    const evidence = createLabVmCommandEvidence(
      {
        vm_name: live.vmName,
        workspace_path: live.workspacePath,
        guest_workspace: LAB_VM_GUEST_WORKSPACE,
        command: request.command,
        timeout_ms: request.timeoutMs,
      },
      live.workspacePath,
      result,
      [
        LAB_VM_UNVERIFIED_NOTE,
        LAB_VM_SANDBOX_NOTE,
        "Guest output bytes stay in the VM; this observation retains exit structure and workspace paths only.",
        "produced_paths and modified_paths compare two bounded inventories of the mounted workspace; a change inside the guest that never touches the mount is not observed.",
        ...(result.changes_truncated
          ? [
              "The workspace inventory or its change list reached its bound, so unreported paths may also have changed.",
            ]
          : []),
        ...(after.ok
          ? []
          : [
              "The workspace could not be inventoried after the command, so produced and removed paths are unknown.",
            ]),
        ...(observed === undefined ? [] : outputLimitLimitations(observed)),
      ],
    );
    return executed.ok
      ? ok(evidence)
      : err(executed.error.retainPartialObservation(evidence));
  }

  async #stopOwned(
    live: LiveLabVm,
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<Evidence, AnalysisError>> {
    const configuration = this.#configuration(operation);
    if (!configuration.ok) return configuration;
    const stopped = await runLabVmCommand(
      operation,
      configuration.value.command,
      labVmArguments.stop(live.vmName),
      {
        timeoutMs: configuration.value.defaultCommandTimeoutMs,
        maxOutputBytes: configuration.value.maxOutputBytes,
      },
      signal,
    );
    if (!stopped.ok)
      return err(this.#retainOwner(live, operation, stopped.error));
    const removed = await this.#removeInstance(
      configuration.value,
      live,
      operation,
      signal,
    );
    const evidence = createLabVmStopEvidence(
      { vm_name: live.vmName, workspace_path: live.workspacePath },
      {
        session_id: live.sessionId,
        vm_name: live.vmName,
        stop: callOf(stopped.value),
        deleted: removed === null,
      },
      [
        LAB_VM_UNVERIFIED_NOTE,
        LAB_VM_SANDBOX_NOTE,
        ...outputLimitLimitations(stopped.value),
      ],
    );
    if (removed === null) return ok(evidence);
    this.#retainOwner(live, operation, removed);
    return err(
      (removed.cause instanceof AnalysisCancelledError
        ? cancelledWithCleanup(operation, removed.cause, removed)
        : removed
      ).retainPartialObservation(evidence),
    );
  }

  async #retryOwner(
    configuration: LabVmConfiguration,
    owner: LabVmOwner,
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<Evidence, AnalysisError>> {
    const removed = await this.#removeInstance(
      configuration,
      owner,
      operation,
      signal,
    );
    if (removed !== null) {
      this.#retainOwner(owner, operation, removed);
      return err(
        removed.cause instanceof AnalysisCancelledError
          ? cancelledWithCleanup(operation, removed.cause, removed)
          : removed,
      );
    }
    return ok(
      createLabVmStopEvidence(
        { vm_name: owner.vmName },
        {
          session_id: owner.sessionId,
          vm_name: owner.vmName,
          stop: null,
          deleted: true,
        },
        [
          LAB_VM_UNVERIFIED_NOTE,
          "This call removed an instance whose stop observation was retained earlier; no stop call was re-observed here.",
        ],
      ),
    );
  }

  /** Remove one owned instance and its template root; null means released. */
  async #removeInstance(
    configuration: LabVmConfiguration,
    owner: LabVmOwner,
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<ProviderCleanupError | null> {
    const removed = await runLabVmCommand(
      operation,
      configuration.command,
      labVmArguments.delete(owner.vmName),
      {
        timeoutMs: configuration.defaultCommandTimeoutMs,
        maxOutputBytes: configuration.maxOutputBytes,
      },
      signal,
    );
    if (!removed.ok) {
      return this.#cleanupError(owner.vmName, operation, removed.error, [
        `lab-vm:${owner.vmName}`,
      ]);
    }
    try {
      await owner.root.close();
    } catch (cause: unknown) {
      return this.#cleanupError(owner.vmName, operation, cause, [
        `lab-vm-template:${owner.root.path}`,
      ]);
    }
    this.#live.delete(owner.sessionId);
    this.#retained.delete(owner.sessionId);
    return null;
  }

  /**
   * Keep the instance owned and project the failure with its cleanup status.
   *
   * A cancellation keeps its typed identity and exposes the retained owner as
   * a cleanup dependency, so callers never read cancellation as confirmed
   * cleanup, and a later retry resolves this exact error.
   */
  #retainOwner(
    owner: LabVmOwner,
    operation: string,
    cause: AnalysisError,
  ): AnalysisError {
    // A requested stop leaves the live registry: guest work is no longer
    // admitted, but the instance stays owned until removal is observed.
    this.#live.delete(owner.sessionId);
    this.#retained.set(owner.sessionId, {
      sessionId: owner.sessionId,
      vmName: owner.vmName,
      root: owner.root,
    });
    const cleanup =
      cause instanceof ProviderCleanupError
        ? cause
        : this.#cleanupError(owner.vmName, operation, cause, [
            `lab-vm:${owner.vmName}`,
          ]);
    if (!(cause instanceof AnalysisCancelledError))
      return cause instanceof ProviderCleanupError
        ? cause
        : analysisErrorWithCleanupFailure(cause, cleanup, operation);
    return cancelledWithCleanup(operation, cause, cleanup);
  }

  #cleanupError(
    vmName: string,
    operation: string,
    cause: unknown,
    resources: readonly string[],
  ): ProviderCleanupError {
    const reason = cause instanceof Error ? cause.message : String(cause);
    return new ProviderCleanupError(
      LAB_VM_PROVIDER.id,
      [...resources],
      {
        vm_name: vmName,
        reason,
        ...(cause instanceof Error && "code" in cause
          ? { system_code: String(cause.code) }
          : {}),
      },
      {
        operation,
        cause,
        remediationAction: REMEDIATION,
      },
    );
  }

  #configuration(operation: string): Result<LabVmConfiguration, AnalysisError> {
    try {
      return ok(resolveLabVmConfiguration(this.#environment));
    } catch (cause: unknown) {
      if (isLabVmFailure(cause))
        return err(
          providerConfigurationRefusal(LAB_VM_PROVIDER.id, operation, cause),
        );
      return err(
        new AnalysisCapabilityUnavailableError(
          LAB_VM_PROVIDER.id,
          operation,
          "The limactl selection failed.",
          { cause },
        ),
      );
    }
  }

  async #createRoot(
    operation: string,
  ): Promise<Result<RuntimeRoot, AnalysisError>> {
    try {
      return ok(await this.#createRuntimeRoot({ prefix: "rea-lab-vm-" }));
    } catch (cause: unknown) {
      return err(
        new AnalysisCapabilityUnavailableError(
          LAB_VM_PROVIDER.id,
          operation,
          "A private lab VM runtime directory could not be created on this host.",
          { cause },
        ),
      );
    }
  }

  #ownedSessions(): ReadonlySet<string> {
    return new Set([...this.#live.keys(), ...this.#retained.keys()]);
  }

  #enqueue<T>(live: LiveLabVm, work: () => Promise<T>): Promise<T> {
    const next = live.queue.then(work, work);
    live.queue = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }
}

/** Keep a typed cancellation beside the cleanup that still owns the instance. */
const cancelledWithCleanup = (
  operation: string,
  cause: AnalysisCancelledError,
  cleanup: ProviderCleanupError,
): AnalysisError =>
  new AnalysisCancelledError(operation, {
    cause: cause.cause ?? cause,
    cleanup: { reason: cleanup.message, resources: cleanup.cleanupResources },
    ...(cause.partialObservation === undefined
      ? {}
      : { partialObservation: cause.partialObservation }),
  })
    .retainSecondaryFailure(cleanup)
    .bindCleanupDependencies([cleanup]);

/** Structural exit facts from the completed call or its captured failure. */
const callFacts = (
  executed: Result<LabVmCommandObservation, AnalysisError>,
  elapsedMs: number,
): Omit<
  LabVmCommandResult,
  | "session_id"
  | "command"
  | "timeout_ms"
  | "produced_paths"
  | "modified_paths"
  | "removed_paths"
  | "changes_truncated"
> => {
  const observed = executed.ok ? executed.value : undefined;
  const captured = executed.ok ? undefined : executed.error.capturedOutput;
  return {
    exit_type: observed?.exitType ?? exitTypeOf(executed),
    exit_code: observed?.exitCode ?? captured?.exit_code ?? null,
    duration_ms: observed?.durationMs ?? elapsedMs,
    stdout_bytes: byteCount(
      observed?.stdoutBytes,
      captured?.stdout_bytes,
      captured?.stdout.length,
    ),
    stderr_bytes: byteCount(
      observed?.stderrBytes,
      captured?.stderr_bytes,
      captured?.stderr.length,
    ),
    output_truncated: observed?.outputTruncated ?? captured?.truncated ?? false,
  };
};

const byteCount = (
  observed: number | undefined,
  captured: number | undefined,
  textLength: number | undefined,
): number => observed ?? captured ?? textLength ?? 0;

/** Reduce one limactl call and its workspace diff to structural result facts. */
const commandFacts = (input: {
  readonly sessionId: string;
  readonly command: string;
  readonly timeoutMs: number;
  readonly elapsedMs: number;
  readonly executed: Result<LabVmCommandObservation, AnalysisError>;
  readonly changes: WorkspaceChange;
}): LabVmCommandResult => ({
  session_id: input.sessionId,
  command: input.command,
  timeout_ms: input.timeoutMs,
  ...callFacts(input.executed, input.elapsedMs),
  produced_paths: [...input.changes.produced],
  modified_paths: [...input.changes.modified],
  removed_paths: [...input.changes.removed],
  changes_truncated: input.changes.truncated,
});

const exitTypeOf = (
  executed: Result<LabVmCommandObservation, AnalysisError>,
): "exited" | "signalled" | "timeout" | "cancelled" => {
  if (executed.ok) return "exited";
  const error = executed.error;
  if (error instanceof AnalysisCancelledError) return "cancelled";
  if (error instanceof AnalysisTimeoutError) return "timeout";
  if (error.capturedOutput?.signal != null) return "signalled";
  return "exited";
};

const unknownSession = (
  operation: string,
  sessionId: string,
  retained: boolean,
): AnalysisInputError =>
  new AnalysisInputError(
    operation,
    {
      userMessage: retained
        ? `The lab VM session ${sessionId} still owns an instance whose cleanup failed; call stop_lab_vm again to retry it.`
        : `No live lab VM owns the session identity ${sessionId}; call start_lab_vm first.`,
    },
    [
      {
        path: ["session_id"],
        reason: "invalid_value",
        message:
          "Expected the session_id returned by this server's start_lab_vm.",
      },
    ],
  );
