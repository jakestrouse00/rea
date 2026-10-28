import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import type {
  BenchTaskPort,
  RunBenchTaskRequest,
} from "../application/bench/BenchTaskPort.js";
import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import {
  benchTaskStatusFor,
  evaluateBenchMetric,
  type BenchTaskDescriptor,
  type BenchTaskObservation,
} from "../domain/bench/benchTask.js";
import { BENCH_LIMITS, BENCH_PROVIDER } from "../domain/bench/benchLimits.js";
import type { BenchProfile } from "../domain/bench/benchLimits.js";
import type { Evidence } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import { LAB_VM_MAX_TIMER_MS } from "../domain/vmlab/labVm.js";
import {
  labVmCommandResultSchema,
  labVmStartResultSchema,
  type LabVmCommandResult,
} from "../domain/vmlab/labVmObservation.js";
import {
  BenchConfigurationFailure,
  benchConfigurationAvailability,
  resolveBenchConfiguration,
  type BenchConfiguration,
} from "./BenchConfiguration.js";
import { createBenchTaskEvidence } from "./BenchEvidence.js";
import { benchOutcomeLimitations, readBenchOutcome } from "./BenchOutcome.js";
import { benchGuestCommand } from "./BenchTaskCommand.js";

export interface BenchTaskAdapterOptions {
  readonly labVm: LabVmPort;
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

const isBenchFailure = (value: unknown): value is BenchConfigurationFailure =>
  value instanceof BenchConfigurationFailure;

const operation = "run_bench_task";

const stopFailureLimitation =
  "This run did not release its lab VM. The lab-VM lane keeps the instance identity, so stop_lab_vm must be retried before another benchmark task or lab VM can start.";

interface BenchAdmission {
  readonly profile: BenchProfile;
  readonly budgetSeconds: number;
  readonly timeoutMs: number;
}

/**
 * Drive one containerized benchmark task inside the caller's Lima lab VM.
 *
 * VM lifecycle belongs to the lab-VM lane: this adapter boots one instance,
 * runs the task command under the declared budget, reads the harness outcome
 * from the mounted workspace, and releases the instance before replying. It
 * never downloads a benchmark corpus or a container runtime.
 */
export class BenchTaskAdapter implements BenchTaskPort {
  readonly #labVm: LabVmPort;
  readonly #environment: Readonly<Record<string, string | undefined>>;

  constructor(options: BenchTaskAdapterOptions) {
    this.#labVm = options.labVm;
    this.#environment = options.environment ?? process.env;
  }

  #configuration(): Result<BenchConfiguration, AnalysisError> {
    try {
      return ok(resolveBenchConfiguration(this.#environment));
    } catch (cause: unknown) {
      if (isBenchFailure(cause))
        return err(
          providerConfigurationRefusal(BENCH_PROVIDER.id, operation, cause),
        );
      return err(
        new AnalysisCapabilityUnavailableError(
          BENCH_PROVIDER.id,
          operation,
          cause instanceof Error
            ? cause.message
            : "The benchmark profile selection failed",
          { cause },
        ),
      );
    }
  }

  inspectAvailability(signal?: AbortSignal): ProviderAvailability {
    let configuration: BenchConfiguration;
    try {
      configuration = resolveBenchConfiguration(this.#environment);
    } catch (cause: unknown) {
      return isBenchFailure(cause)
        ? benchConfigurationAvailability(cause)
        : {
            status: "unavailable",
            code: "not_configured",
            reason:
              cause instanceof Error
                ? cause.message
                : "The benchmark profile selection failed",
            diagnostics: {},
          };
    }
    const labVm = this.#labVm.inspectAvailability(signal);
    return {
      ...labVm,
      diagnostics: {
        profile: configuration.profile,
        ...labVm.diagnostics,
      },
    };
  }

  /** Admit the profile, suite, host, and budget before any VM exists. */
  #admit(
    request: RunBenchTaskRequest,
    signal: AbortSignal | undefined,
  ): Result<BenchAdmission, AnalysisError> {
    const configuration = this.#configuration();
    if (!configuration.ok) return configuration;
    const profile = configuration.value.profile;
    if (request.suite !== profile)
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage: `This REA process runs the ${profile} benchmark profile; a ${request.suite} task is not admitted.`,
          },
          [
            {
              path: ["suite"],
              reason: "invalid_value",
              message: `Select ${profile}, or restart REA with REA_BENCH_LIMA_PROFILE set to ${request.suite}.`,
              expected: profile,
            },
          ],
        ),
      );
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    const availability = this.#labVm.inspectAvailability(signal);
    if (availability.status !== "available")
      return err(
        new AnalysisCapabilityUnavailableError(
          BENCH_PROVIDER.id,
          operation,
          availability.reason ?? "The lab-VM lane is unavailable",
          { diagnostics: { ...availability.diagnostics } },
        ),
      );
    const budgetSeconds = Math.min(
      request.budgetSeconds,
      BENCH_LIMITS.maxTaskSeconds,
    );
    return ok({
      profile,
      budgetSeconds,
      timeoutMs: Math.min(budgetSeconds * 1_000, LAB_VM_MAX_TIMER_MS),
    });
  }

  /** Boot the run's instance and return the identity the lane issued. */
  async #boot(
    workspacePath: string,
    options: ExecutionOptions | undefined,
  ): Promise<Result<string, AnalysisError>> {
    const started = await this.#labVm.start({ workspacePath }, options);
    if (!started.ok) return started;
    const parsed = labVmStartResultSchema.safeParse(
      started.value.normalized_result,
    );
    return parsed.success
      ? ok(parsed.data.session_id)
      : err(
          new AnalysisCapabilityUnavailableError(
            BENCH_PROVIDER.id,
            operation,
            "The lab-VM lane issued a boot result this release cannot read, so its instance identity is unknown",
            { cause: parsed.error },
          ),
        );
  }

  /** Run the task command, then release the instance this run owns. */
  async #execute(
    sessionId: string,
    descriptor: BenchTaskDescriptor,
    admission: BenchAdmission,
    options: ExecutionOptions | undefined,
  ): Promise<
    | { readonly guest: LabVmCommandResult; readonly stopped: boolean }
    | { readonly failure: AnalysisError }
  > {
    const executed = await this.#labVm.run(
      {
        sessionId,
        command: benchGuestCommand(descriptor),
        timeoutMs: admission.timeoutMs,
      },
      options,
    );
    const stopped = await this.#labVm.stop({ sessionId }, {});
    if (!executed.ok)
      return {
        failure: stopped.ok
          ? executed.error
          : analysisErrorWithCleanupFailure(
              executed.error,
              stopped.error,
              operation,
            ),
      };
    const guest = labVmCommandResultSchema.safeParse(
      executed.value.normalized_result,
    );
    return guest.success
      ? { guest: guest.data, stopped: stopped.ok }
      : {
          failure: new AnalysisCapabilityUnavailableError(
            BENCH_PROVIDER.id,
            operation,
            "The lab-VM lane returned a guest observation this release cannot read",
            { cause: guest.error },
          ),
        };
  }

  async run(
    request: RunBenchTaskRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const signal = options?.signal;
    const admission = this.#admit(request, signal);
    if (!admission.ok) return admission;
    const sessionId = await this.#boot(request.workspacePath, options);
    if (!sessionId.ok) return sessionId;
    const descriptor: BenchTaskDescriptor = {
      taskId: request.taskId,
      suite: request.suite,
      workspacePath: request.workspacePath,
      entrypoint: request.entrypoint,
      success: request.success,
      budgetSeconds: admission.value.budgetSeconds,
    };
    const executed = await this.#execute(
      sessionId.value,
      descriptor,
      admission.value,
      options,
    );
    if ("failure" in executed) return err(executed.failure);
    const outcome = await readBenchOutcome(request.workspacePath);
    const metric = evaluateBenchMetric(
      request.success,
      outcome.state === "read" ? outcome.facts : { state: outcome.state },
    );
    const observation: BenchTaskObservation = {
      task_id: request.taskId,
      suite: request.suite,
      status: benchTaskStatusFor(executed.guest.exit_type, metric),
      metric,
      outcome_state: outcome.state,
      budget_seconds: admission.value.budgetSeconds,
      guest: {
        exit_type: executed.guest.exit_type,
        exit_code: executed.guest.exit_code,
        duration_ms: executed.guest.duration_ms,
        timeout_ms: executed.guest.timeout_ms,
      },
      produced_paths: executed.guest.produced_paths,
      changes_truncated: executed.guest.changes_truncated,
      vm: { stopped: executed.stopped },
    };
    return ok(
      createBenchTaskEvidence(
        {
          task_id: request.taskId,
          suite: request.suite,
          profile: admission.value.profile,
          entrypoint: request.entrypoint,
          budget_seconds: admission.value.budgetSeconds,
          success: successParameters(request.success),
        },
        request.workspacePath,
        observation,
        [
          ...benchOutcomeLimitations(outcome),
          ...(executed.stopped ? [] : [stopFailureLimitation]),
        ],
      ),
    );
  }
}

const successParameters = (
  success: RunBenchTaskRequest["success"],
): Readonly<Record<string, JsonValue>> =>
  success.kind === "flag"
    ? { kind: "flag", expected_flag_sha256: success.expected_flag_sha256 }
    : {
        kind: "pov",
        ...(success.expected_sanitizer === undefined
          ? {}
          : { expected_sanitizer: success.expected_sanitizer }),
      };
