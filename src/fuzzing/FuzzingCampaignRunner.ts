import { copyFile, mkdir, readdir, readFile, stat } from "node:fs/promises";
import { isAbsolute, join, posix, relative, sep } from "node:path";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  CrashTriagePort,
  RegisteredFuzzingCampaign,
} from "../application/crashTriage/CrashTriagePort.js";
import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import {
  CRASH_MINIMIZE_DEFAULT_MAX_TOTAL_SECONDS,
  CRASH_MINIMIZE_DEFAULT_TIMEOUT_MS,
  type CrashMinimizeEngine,
} from "../domain/crashTriage/crashMinimization.js";
import {
  CrashReportParseFailure,
  parseCrashReport,
  type SanitizerClass,
} from "../domain/crashTriage/crashReport.js";
import { crashStateFor } from "../domain/crashTriage/crashStateHash.js";
import {
  FUZZING_DEFAULT_MAX_CAMPAIGN_SECONDS,
  FUZZING_DIAGNOSTIC_EXCERPT_BYTES,
  FUZZING_LAB_VM_ENGINE_LOG,
  FUZZING_LAB_VM_REPORT_FILE,
  FUZZING_MAX_CRASH_ARTIFACTS,
  FUZZING_MAX_CRASH_ROWS,
  FUZZING_MAX_OUTPUT_BYTES,
  FUZZING_MAX_REPORTED_ARGUMENTS,
  FUZZING_MAX_STATS_SAMPLES,
  FUZZING_POV_TIMEOUT_MS,
  FUZZING_PROVIDER,
  FUZZING_STATS_INTERVAL_MS,
  type FuzzingCampaignOutcome,
  type FuzzingEngine,
  type FuzzingRoute,
  type FuzzingStopReason,
} from "../domain/fuzzing/fuzzingEngine.js";
import {
  fuzzingBudgetLimitsSchema,
  fuzzingCampaignObservationSchema,
  type FuzzingBudgetLimits,
  type FuzzingCampaignObservation,
  type FuzzingIngestedCrash,
  type FuzzingLabVmObservation,
  type FuzzingMinimizationRow,
  type FuzzingRejectedCrash,
} from "../domain/fuzzing/fuzzingCampaignObservation.js";
import {
  FuzzingStatSeries,
  parseAflFuzzerStats,
  parseJackalopeStatLine,
  parseLibFuzzerStatLine,
  type FuzzingStatReading,
} from "../domain/fuzzing/fuzzingStats.js";
import {
  evaluatePov,
  type FuzzingPovRejection,
} from "../domain/fuzzing/povValidation.js";
import {
  LAB_VM_GUEST_WORKSPACE,
  LAB_VM_MAX_TIMER_MS,
} from "../domain/vmlab/labVm.js";
import { labVmCommandResultSchema } from "../domain/vmlab/labVmObservation.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  SandboxProfileRejection,
  sandboxLaunchPlan,
} from "../domain/sandboxProfiles.js";
import {
  ExecFileOutputCancelledError,
  execFileBytes,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import { fuzzingEngineAdapter } from "./FuzzingEngineAdapters.js";
import type {
  FuzzingCampaignWorkspace,
  FuzzingEngineAdapter,
  FuzzingLaunchPlan,
  FuzzingReproducePlan,
} from "./FuzzingEngineAdapter.js";
import {
  FuzzingEngineConfigurationFailure,
  resolveFuzzingEngineConfiguration,
  type FuzzingEngineConfiguration,
} from "./FuzzingEngineConfiguration.js";
import { FuzzingCampaignProcess } from "./FuzzingCampaignProcess.js";

/** One campaign launch, with everything the caller already chose. */
export interface FuzzingCampaignRunRequest {
  readonly campaign: RegisteredFuzzingCampaign;
  readonly engine: FuzzingEngine;
  readonly povRepeats: number;
  readonly expectedSanitizer: SanitizerClass | undefined;
  readonly minimizeCrashes: boolean;
  readonly route: FuzzingRoute;
  /** Absolute campaign root REA may write into for this run. */
  readonly workspaceRoot: string;
  readonly labVm: {
    readonly sessionId: string;
    readonly workspacePath: string;
  } | null;
}

export interface FuzzingCampaignRunnerOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly crashTriage: Pick<CrashTriagePort, "recordCrash" | "minimizeCrash">;
  readonly labVm?: LabVmPort;
  readonly settings?: AnalysisSettingsReader;
  readonly now?: () => string;
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly statsIntervalMs?: number;
}

interface CampaignWorkspace extends FuzzingCampaignWorkspace {
  readonly povDirectory: string;
  readonly minimizeDirectory: string;
}

interface FuzzingRunWatch {
  readonly status: FuzzingCampaignOutcome;
  readonly stopReason: FuzzingStopReason;
  readonly sandbox: {
    readonly confined: boolean;
    readonly limitations: string[];
  };
  readonly labVm: FuzzingLabVmObservation | null;
  readonly limitations: readonly string[];
}

interface CrashCollection {
  readonly observed: number;
  readonly crashes: {
    readonly observed: number;
    readonly inspected: number;
    readonly accepted: number;
    readonly rejected: number;
    readonly ingested: readonly FuzzingIngestedCrash[];
    readonly rejected_rows: readonly FuzzingRejectedCrash[];
    readonly truncated: boolean;
  };
  readonly minimization: {
    readonly requested: boolean;
    readonly attempted: number;
    readonly succeeded: number;
    readonly rows: readonly FuzzingMinimizationRow[];
  };
  readonly limitations: readonly string[];
}

interface ReproductionCapture {
  readonly reportBody: string | null;
  readonly rejection: FuzzingPovRejection | null;
}

const operation = "start_fuzzing_campaign";

const workspaceOf = (root: string): CampaignWorkspace => ({
  root,
  corpusDirectory: join(root, "corpus"),
  artifactDirectory: join(root, "artifacts"),
  outputDirectory: join(root, "output"),
  povDirectory: join(root, "pov"),
  minimizeDirectory: join(root, "minimized"),
});

const SPAWN_FAILURE_CODES = new Set([
  "ENOENT",
  "EACCES",
  "EPERM",
  "ENOTDIR",
  "ENOEXEC",
]);

const spawnFailureCode = (cause: unknown): string | undefined => {
  if (!(cause instanceof Error) || !("code" in cause)) return undefined;
  const code = cause.code;
  return typeof code === "string" && SPAWN_FAILURE_CODES.has(code)
    ? code
    : undefined;
};

const excerpt = (value: string): string => {
  const trimmed = value.trim();
  return trimmed.length <= FUZZING_DIAGNOSTIC_EXCERPT_BYTES
    ? trimmed
    : `…${trimmed.slice(-FUZZING_DIAGNOSTIC_EXCERPT_BYTES)}`;
};

const configurationError = (
  failure: FuzzingEngineConfigurationFailure,
): AnalysisError =>
  new AnalysisCapabilityUnavailableError(
    FUZZING_PROVIDER.id,
    operation,
    failure.message,
    {
      cause: failure,
      userMessage: failure.message,
      remediationAction: failure.remediation,
      diagnostics: { setting: failure.setting, ...failure.diagnostics },
    },
  );

const mergeReading = (
  previous: FuzzingStatReading | null,
  next: FuzzingStatReading,
): FuzzingStatReading => ({
  executions: next.executions ?? previous?.executions ?? null,
  executionsPerSecond:
    next.executionsPerSecond ?? previous?.executionsPerSecond ?? null,
  edges: next.edges ?? previous?.edges ?? null,
  corpusEntries: next.corpusEntries ?? previous?.corpusEntries ?? null,
});

const crashArtifacts = async (
  adapter: FuzzingEngineAdapter,
  directory: string,
): Promise<readonly string[]> => {
  const entries = await readdir(directory, { withFileTypes: true }).catch(
    () => [],
  );
  return entries
    .filter((entry) => entry.isFile() && adapter.isCrashArtifact(entry.name))
    .map((entry) => entry.name)
    .sort();
};

const shellQuote = (value: string): string =>
  `'${value.replaceAll("'", `'\\''`)}'`;

const guestCommand = (
  directory: string,
  argv: readonly string[],
  logFile: string,
): string =>
  `mkdir -p ${shellQuote(directory)} && cd ${shellQuote(directory)} && ${argv
    .map(shellQuote)
    .join(" ")} > ${shellQuote(logFile)} 2>&1`;

const guestPath = (
  hostRoot: string,
  workspacePath: string,
  value: string,
): string | null => {
  const relativePath = relative(workspacePath, value);
  if (
    relativePath === "" ||
    relativePath.startsWith(`..${sep}`) ||
    relativePath === ".." ||
    isAbsolute(relativePath)
  )
    return null;
  return posix.join(LAB_VM_GUEST_WORKSPACE, ...relativePath.split(sep));
};

const hostPathOf = (workspacePath: string, value: string): string => {
  const prefix = `${LAB_VM_GUEST_WORKSPACE}/`;
  if (!value.startsWith(prefix)) return value;
  return join(workspacePath, ...value.slice(prefix.length).split("/"));
};

const guestWorkspaceOf = (
  hostRoot: string,
  workspacePath: string,
): FuzzingCampaignWorkspace => {
  const relativeRoot = relative(workspacePath, hostRoot);
  const root = posix.join(
    LAB_VM_GUEST_WORKSPACE,
    ...(relativeRoot === "" ? [] : relativeRoot.split(sep)),
  );
  return {
    root,
    corpusDirectory: posix.join(root, "corpus"),
    artifactDirectory: posix.join(root, "artifacts"),
    outputDirectory: posix.join(root, "output"),
  };
};

const reachedBudget = (
  limits: FuzzingBudgetLimits,
  secondsBound: "declared" | "runtime_cap",
  runs: number | null,
  seconds: number,
  observedCrashes: number,
): FuzzingStopReason | null => {
  if (limits.max_crashes !== null && observedCrashes >= limits.max_crashes)
    return "budget_crashes";
  if (limits.max_runs !== null && runs !== null && runs >= limits.max_runs)
    return "budget_runs";
  if (limits.max_seconds !== null && seconds >= limits.max_seconds)
    return secondsBound === "declared"
      ? "budget_seconds"
      : "runtime_cap_seconds";
  return null;
};

/**
 * Run one registered campaign through one engine adapter.
 *
 * The runner owns the launch, the budget watch, and the hand-off to crash
 * triage: engine crash artifacts become POV candidates, only validated
 * candidates reach `recordCrash`, and minimization goes through the same
 * minimizer seam the crash-triage lane already owns. It never parses a report
 * twice and never publishes a report body.
 */
export class FuzzingCampaignRunner {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #crashTriage: FuzzingCampaignRunnerOptions["crashTriage"];
  readonly #labVm: LabVmPort | undefined;
  readonly #settings: AnalysisSettingsReader | undefined;
  readonly #now: () => string;
  readonly #platform: NodeJS.Platform;
  readonly #arch: string;
  readonly #statsIntervalMs: number;

  constructor(options: FuzzingCampaignRunnerOptions) {
    this.#environment = options.environment ?? process.env;
    this.#crashTriage = options.crashTriage;
    this.#labVm = options.labVm;
    this.#settings = options.settings;
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#platform = options.platform ?? process.platform;
    this.#arch = options.arch ?? process.arch;
    this.#statsIntervalMs =
      options.statsIntervalMs ?? FUZZING_STATS_INTERVAL_MS;
  }

  async run(
    request: FuzzingCampaignRunRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<FuzzingCampaignObservation, AnalysisError>> {
    if (options.signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const adapter = fuzzingEngineAdapter(request.engine);
    const configuration = this.#configuration(request);
    if (!configuration.ok) return configuration;
    const route = this.#route(request);
    if (!route.ok) return route;
    const workspace = workspaceOf(request.workspaceRoot);
    const prepared = await this.#prepare(request, workspace, options.signal);
    if (!prepared.ok) return prepared;
    const budget = this.#effectiveBudget(request.campaign);
    const launch = this.#launch(
      request,
      workspace,
      adapter,
      configuration.value,
      budget,
    );
    if (!launch.ok) return launch;
    const artifactDirectory =
      request.labVm === null
        ? launch.value.artifactDirectory
        : hostPathOf(
            request.labVm.workspacePath,
            launch.value.artifactDirectory,
          );
    const startedAt = this.#now();
    const startedClock = Date.now();
    const stats = new FuzzingStatSeries();
    const watched =
      request.route === "lab_vm"
        ? await this.#runInLabVm(
            request,
            workspace,
            adapter,
            launch.value,
            budget,
            stats,
            startedClock,
            options.signal,
          )
        : await this.#runOnHost(
            request,
            workspace,
            adapter,
            launch.value,
            budget,
            stats,
            startedClock,
            options.signal,
          );
    if (!watched.ok) return watched;
    const finishedAt = this.#now();
    const durationMs = Date.now() - startedClock;
    const collected = await this.#collectCrashes(
      request,
      workspace,
      adapter,
      artifactDirectory,
      configuration.value,
      options.signal,
    );
    if (!collected.ok) return collected;
    const last = stats.last;
    return ok(
      fuzzingCampaignObservationSchema.parse({
        campaign_id: request.campaign.campaignId,
        engine: request.engine,
        route: request.route,
        status: watched.value.status,
        stop_reason: watched.value.stopReason,
        started_at: startedAt,
        finished_at: finishedAt,
        duration_ms: durationMs,
        target: {
          path: request.campaign.targetPath,
          sha256: request.campaign.targetSha256,
        },
        budget: {
          declared: request.campaign.budget,
          effective: budget.limits,
          runtime_cap_seconds: budget.runtimeCapSeconds,
          seconds_bound: budget.secondsBound,
        },
        consumed: {
          runs: last?.executions ?? null,
          seconds: Math.floor(durationMs / 1_000),
          observed_crashes: collected.value.observed,
        },
        stats: {
          samples: [...stats.samples].slice(0, FUZZING_MAX_STATS_SAMPLES),
          sample_stride_ms: stats.strideMs,
          first: stats.first,
          last,
          peak_executions_per_second: stats.peakExecutionsPerSecond,
          edges: last?.edges ?? null,
          corpus_entries: last?.corpus_entries ?? null,
        },
        crashes: collected.value.crashes,
        minimization: collected.value.minimization,
        engine_selection: {
          engine: request.engine,
          command: launch.value.executable,
          target_path: request.campaign.targetPath,
          argv: launch.value.arguments.slice(0, FUZZING_MAX_REPORTED_ARGUMENTS),
          stats_source: launch.value.statsSource.kind,
          artifact_directory: launch.value.artifactDirectory,
        },
        workspace: {
          root: workspace.root,
          corpus_directory: workspace.corpusDirectory,
          artifact_directory: workspace.artifactDirectory,
          output_directory: workspace.outputDirectory,
        },
        sandbox: watched.value.sandbox,
        lab_vm: watched.value.labVm,
        limitations: [
          ...watched.value.limitations,
          ...collected.value.limitations,
        ],
      }),
    );
  }

  #configuration(
    request: FuzzingCampaignRunRequest,
  ): Result<FuzzingEngineConfiguration, AnalysisError> {
    try {
      return ok(
        resolveFuzzingEngineConfiguration(
          this.#environment,
          request.engine,
          request.route === "lab_vm"
            ? { platform: "linux", arch: "aarch64", probe: false }
            : { platform: this.#platform, arch: this.#arch },
        ),
      );
    } catch (cause: unknown) {
      if (!(cause instanceof FuzzingEngineConfigurationFailure)) throw cause;
      return err(configurationError(cause));
    }
  }

  #route(request: FuzzingCampaignRunRequest): Result<null, AnalysisError> {
    if (request.route !== "lab_vm") return ok(null);
    if (this.#labVm === undefined)
      return err(
        new AnalysisCapabilityUnavailableError(
          FUZZING_PROVIDER.id,
          operation,
          "The lab-VM route is selected but this server has no Lima lane",
          {
            userMessage:
              "Start REA with its lab-VM lane available, or omit lab_vm_session_id to run on this host.",
            remediationAction:
              "Set REA_LIMACTL_COMMAND to a caller-supplied limactl binary and restart REA.",
          },
        ),
      );
    if (request.engine === "jackalope")
      return err(
        new AnalysisInputError(operation, {
          userMessage:
            "The lab-VM route documents libFuzzer and AFL++ FRIDA only; a Jackalope build targets the host platform it was compiled for.",
        }),
      );
    return ok(null);
  }

  async #prepare(
    request: FuzzingCampaignRunRequest,
    workspace: CampaignWorkspace,
    signal: AbortSignal | undefined,
  ): Promise<Result<null, AnalysisError>> {
    try {
      for (const directory of [
        workspace.root,
        workspace.corpusDirectory,
        workspace.artifactDirectory,
        workspace.outputDirectory,
        workspace.povDirectory,
        workspace.minimizeDirectory,
      ])
        await mkdir(directory, { recursive: true, mode: 0o700 });
      const copied = new Set<string>();
      for (const seed of request.campaign.seedPaths) {
        if (signal?.aborted === true)
          return err(
            new AnalysisCancelledError(operation, { cause: signal.reason }),
          );
        const name = seed.split(/[\\/]/u).pop() ?? "seed";
        const destination = join(workspace.corpusDirectory, name);
        if (copied.has(destination))
          return err(
            new AnalysisInputError(operation, {
              userMessage: `Two registered seeds share the file name ${name}; one corpus copy cannot hold both. Rename a seed before registering the campaign.`,
            }),
          );
        const observed = await stat(seed).catch(() => null);
        if (observed === null || !observed.isFile())
          return err(
            new AnalysisInputError(operation, {
              userMessage: `The registered seed is not a regular file: ${seed}`,
            }),
          );
        await copyFile(seed, destination);
        copied.add(destination);
      }
      return ok(null);
    } catch (cause: unknown) {
      return err(
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The campaign workspace could not be prepared: ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
        }),
      );
    }
  }

  #effectiveBudget(campaign: RegisteredFuzzingCampaign): {
    readonly limits: FuzzingBudgetLimits;
    readonly runtimeCapSeconds: number;
    readonly secondsBound: "declared" | "runtime_cap";
  } {
    const runtimeCapSeconds =
      this.#settings?.().overrides["fuzzing.max_campaign_seconds"] ??
      FUZZING_DEFAULT_MAX_CAMPAIGN_SECONDS;
    const declared = campaign.budget.max_seconds ?? null;
    return {
      limits: fuzzingBudgetLimitsSchema.parse({
        max_runs: campaign.budget.max_runs ?? null,
        max_seconds:
          declared === null
            ? runtimeCapSeconds
            : Math.min(declared, runtimeCapSeconds),
        max_crashes: campaign.budget.max_crashes ?? null,
      }),
      runtimeCapSeconds,
      secondsBound:
        declared !== null && declared <= runtimeCapSeconds
          ? "declared"
          : "runtime_cap",
    };
  }

  #launch(
    request: FuzzingCampaignRunRequest,
    workspace: CampaignWorkspace,
    adapter: FuzzingEngineAdapter,
    configuration: FuzzingEngineConfiguration,
    budget: { readonly limits: FuzzingBudgetLimits },
  ): Result<FuzzingLaunchPlan, AnalysisError> {
    const labVm = request.labVm;
    if (request.route === "lab_vm" && labVm === null)
      return err(
        new AnalysisInputError(operation, {
          userMessage:
            "lab_vm_workspace_path is required with lab_vm_session_id.",
        }),
      );
    const guest =
      labVm === null
        ? null
        : guestWorkspaceOf(workspace.root, labVm.workspacePath);
    const target =
      labVm === null
        ? request.campaign.targetPath
        : guestPath(
            workspace.root,
            labVm.workspacePath,
            request.campaign.targetPath,
          );
    if (target === null)
      return err(
        new AnalysisInputError(operation, {
          userMessage: `The campaign target is outside the lab-VM workspace, so the guest cannot execute it: ${request.campaign.targetPath}`,
        }),
      );
    return ok(
      adapter.launch({
        targetPath: target,
        configuration,
        workspace: guest ?? workspace,
        budget: {
          maxRuns: budget.limits.max_runs,
          maxSeconds: budget.limits.max_seconds,
        },
      }),
    );
  }

  async #runOnHost(
    request: FuzzingCampaignRunRequest,
    workspace: CampaignWorkspace,
    adapter: FuzzingEngineAdapter,
    launch: FuzzingLaunchPlan,
    budget: {
      readonly limits: FuzzingBudgetLimits;
      readonly secondsBound: "declared" | "runtime_cap";
    },
    stats: FuzzingStatSeries,
    startedClock: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<FuzzingRunWatch, AnalysisError>> {
    let plan;
    try {
      plan = sandboxLaunchPlan({
        executable: launch.executable,
        args: launch.arguments,
        profile: {
          workspace_root: workspace.root,
          writable_paths: [...launch.writablePaths],
          readable_paths: [...launch.readablePaths],
          executable_paths: [launch.executable, request.campaign.targetPath],
        },
        environment: this.#environment,
      });
    } catch (cause: unknown) {
      if (!(cause instanceof SandboxProfileRejection)) throw cause;
      return err(
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The engine launch cannot be expressed as a deny-default sandbox profile: ${cause.message}. Select absolute target and engine paths, or set REA_DISABLE_SANDBOX=1 to run the engine unconfined.`,
        }),
      );
    }
    const confined =
      plan.executable !== launch.executable && plan.limitations.length === 0;
    const limitations =
      this.#platform === "darwin"
        ? [...plan.limitations]
        : [
            `No deny-default seatbelt profile applies on ${this.#platform}; the engine writes only where its argv points, without kernel confinement.`,
          ];
    const parser =
      adapter.engine === "libfuzzer"
        ? parseLibFuzzerStatLine
        : adapter.engine === "jackalope"
          ? parseJackalopeStatLine
          : null;
    const pending: FuzzingStatReading[] = [];
    let engine: FuzzingCampaignProcess;
    try {
      engine = FuzzingCampaignProcess.start(
        {
          executable: plan.executable,
          arguments: plan.args,
          environment: this.#environment,
        },
        {
          onStdoutLine: (line) => {
            if (parser === null) return;
            const reading = parser(line);
            if (reading !== null) pending.push(reading);
          },
        },
      );
    } catch (cause: unknown) {
      return err(
        new AnalysisCapabilityUnavailableError(
          FUZZING_PROVIDER.id,
          operation,
          `The selected engine could not be started: ${launch.executable}`,
          { cause, diagnostics: { selected_binary: launch.executable } },
        ),
      );
    }
    const reading: { current: FuzzingStatReading | null } = { current: null };
    let observedCrashes = 0;
    let stopReason: FuzzingStopReason | null = null;
    let ticking = false;
    const sample = async (): Promise<FuzzingStopReason | null> => {
      if (ticking) return null;
      ticking = true;
      try {
        for (const next of pending.splice(0))
          reading.current = mergeReading(reading.current, next);
        const statsPath = launch.statsSource.path;
        if (launch.statsSource.kind === "file" && statsPath !== null) {
          const text = await readFile(statsPath, "utf8").catch(() => null);
          if (text !== null) {
            const parsed = parseAflFuzzerStats(text);
            if (parsed !== null)
              reading.current = mergeReading(reading.current, parsed);
          }
        }
        observedCrashes = (
          await crashArtifacts(adapter, launch.artifactDirectory)
        ).length;
        stats.append({
          at_ms: Date.now() - startedClock,
          executions: reading.current?.executions ?? null,
          executions_per_second: reading.current?.executionsPerSecond ?? null,
          edges: reading.current?.edges ?? null,
          corpus_entries: reading.current?.corpusEntries ?? null,
          observed_crashes: observedCrashes,
        });
        return reachedBudget(
          budget.limits,
          budget.secondsBound,
          reading.current?.executions ?? null,
          Math.floor((Date.now() - startedClock) / 1_000),
          observedCrashes,
        );
      } finally {
        ticking = false;
      }
    };
    const seconds = budget.limits.max_seconds;
    const deadline =
      seconds === null
        ? undefined
        : setTimeout(() => {
            if (stopReason !== null) return;
            stopReason =
              budget.secondsBound === "declared"
                ? "budget_seconds"
                : "runtime_cap_seconds";
            engine.stop();
          }, seconds * 1_000);
    const ticker = setInterval(() => {
      if (engine.outputTruncated && stopReason === null) {
        stopReason = "output_truncated";
        engine.stop();
        return;
      }
      void sample().then((reason) => {
        if (reason === null || stopReason !== null) return;
        stopReason = reason;
        engine.stop();
      });
    }, this.#statsIntervalMs);
    const onAbort = (): void => {
      stopReason ??= "cancelled";
      engine.stop();
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    const outcome = await engine.settled();
    signal?.removeEventListener("abort", onAbort);
    clearInterval(ticker);
    if (deadline !== undefined) clearTimeout(deadline);
    if (stopReason === null) await sample();
    const cleanExit =
      outcome.spawnError === null &&
      outcome.code === 0 &&
      outcome.signal === null;
    if (stopReason === null && outcome.outputTruncated) {
      stopReason = "output_truncated";
    }
    const observed = reachedBudget(
      budget.limits,
      budget.secondsBound,
      reading.current?.executions ?? null,
      Math.floor((Date.now() - startedClock) / 1_000),
      observedCrashes,
    );
    return ok({
      status:
        stopReason !== null ? "stopped" : cleanExit ? "finished" : "failed",
      stopReason:
        stopReason ??
        (cleanExit ? (observed ?? "engine_exit") : "engine_failure"),
      sandbox: { confined, limitations: [...limitations] },
      labVm: null,
      limitations: [
        ...limitations,
        ...(outcome.spawnError === null
          ? []
          : [`The engine process never started (${outcome.spawnError}).`]),
        ...(engine.stderrExcerpt === "" || outcome.spawnError !== null
          ? []
          : [`Engine stderr tail: ${excerpt(engine.stderrExcerpt)}`]),
      ],
    });
  }

  async #runInLabVm(
    request: FuzzingCampaignRunRequest,
    workspace: CampaignWorkspace,
    adapter: FuzzingEngineAdapter,
    launch: FuzzingLaunchPlan,
    budget: {
      readonly limits: FuzzingBudgetLimits;
      readonly secondsBound: "declared" | "runtime_cap";
    },
    stats: FuzzingStatSeries,
    startedClock: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<FuzzingRunWatch, AnalysisError>> {
    const labVm = request.labVm;
    const port = this.#labVm;
    if (labVm === null || port === undefined)
      return err(
        new AnalysisInputError(operation, {
          userMessage: "The lab-VM route needs a started lab VM session.",
        }),
      );
    const guest = guestWorkspaceOf(workspace.root, labVm.workspacePath);
    const logFile = posix.join(guest.root, FUZZING_LAB_VM_ENGINE_LOG);
    const seconds =
      budget.limits.max_seconds ?? FUZZING_DEFAULT_MAX_CAMPAIGN_SECONDS;
    const observed = await port.run(
      {
        sessionId: labVm.sessionId,
        command: guestCommand(
          guest.root,
          [launch.executable, ...launch.arguments],
          logFile,
        ),
        timeoutMs: Math.min(seconds * 1_000, LAB_VM_MAX_TIMER_MS),
      },
      optionsOf(signal),
    );
    if (!observed.ok) return observed;
    let call;
    try {
      call = labVmCommandResultSchema.parse(observed.value.normalized_result);
    } catch (cause: unknown) {
      return err(
        new AnalysisCapabilityUnavailableError(
          FUZZING_PROVIDER.id,
          operation,
          "The lab-VM lane returned a guest observation this campaign cannot read",
          { cause },
        ),
      );
    }
    const reading: { current: FuzzingStatReading | null } = { current: null };
    const log = await readFile(
      join(workspace.root, FUZZING_LAB_VM_ENGINE_LOG),
      "utf8",
    ).catch(() => null);
    const parser =
      adapter.engine === "libfuzzer"
        ? parseLibFuzzerStatLine
        : parseJackalopeStatLine;
    if (log !== null)
      for (const line of log.split("\n")) {
        const parsed = parser(line);
        if (parsed !== null)
          reading.current = mergeReading(reading.current, parsed);
      }
    const statsPath =
      launch.statsSource.path === null
        ? null
        : hostPathOf(labVm.workspacePath, launch.statsSource.path);
    if (launch.statsSource.kind === "file" && statsPath !== null) {
      const text = await readFile(statsPath, "utf8").catch(() => null);
      if (text !== null) {
        const parsed = parseAflFuzzerStats(text);
        if (parsed !== null)
          reading.current = mergeReading(reading.current, parsed);
      }
    }
    const artifacts = await crashArtifacts(adapter, launch.artifactDirectory);
    stats.append({
      at_ms: Date.now() - startedClock,
      executions: reading.current?.executions ?? null,
      executions_per_second: reading.current?.executionsPerSecond ?? null,
      edges: reading.current?.edges ?? null,
      corpus_entries: reading.current?.corpusEntries ?? null,
      observed_crashes: artifacts.length,
    });
    const timedOut = call.exit_type === "timeout";
    const afterRun =
      reachedBudget(
        budget.limits,
        budget.secondsBound,
        reading.current?.executions ?? null,
        Math.floor(call.duration_ms / 1_000),
        artifacts.length,
      ) ?? null;
    const stopReason: FuzzingStopReason | null = timedOut
      ? budget.secondsBound === "declared"
        ? "budget_seconds"
        : "runtime_cap_seconds"
      : call.exit_type === "cancelled"
        ? "cancelled"
        : call.exit_type === "output_truncated"
          ? "output_truncated"
          : call.exit_type === "not_started"
            ? "engine_failure"
            : afterRun;
    const cleanExit = call.exit_type === "exited" && call.exit_code === 0;
    return ok({
      status:
        stopReason !== null ? "stopped" : cleanExit ? "finished" : "failed",
      stopReason: stopReason ?? (cleanExit ? "engine_exit" : "engine_failure"),
      sandbox: {
        confined: false,
        limitations: [
          "The engine ran inside the caller's Lima guest, so the host seatbelt profile does not apply; the virtual machine is the isolation boundary.",
        ],
      },
      labVm: {
        session_id: labVm.sessionId,
        workspace_path: labVm.workspacePath,
        guest_directory: guest.root,
        exit_type: call.exit_type,
        exit_code: call.exit_code,
        duration_ms: call.duration_ms,
        timeout_ms: call.timeout_ms,
        stdout_bytes: call.stdout_bytes,
        stderr_bytes: call.stderr_bytes,
        output_truncated: call.output_truncated,
        produced_paths: [...call.produced_paths],
        modified_paths: [...call.modified_paths],
        changes_truncated: call.changes_truncated,
      },
      limitations: [
        "REA observed the guest campaign on the host through the shared workspace: progress counters came from the engine's own log file, and run and crash budgets were checked after the guest command returned rather than while it ran.",
        ...(afterRun === null
          ? []
          : [
              "The guest command reached a run or crash budget before it returned; only the time budget stopped it in the guest.",
            ]),
      ],
    });
  }

  async #collectCrashes(
    request: FuzzingCampaignRunRequest,
    workspace: CampaignWorkspace,
    adapter: FuzzingEngineAdapter,
    artifactDirectory: string,
    configuration: FuzzingEngineConfiguration,
    signal: AbortSignal | undefined,
  ): Promise<Result<CrashCollection, AnalysisError>> {
    const names = await crashArtifacts(adapter, artifactDirectory);
    const inspected = names.slice(0, FUZZING_MAX_CRASH_ARTIFACTS);
    const ingested: FuzzingIngestedCrash[] = [];
    const rejectedRows: FuzzingRejectedCrash[] = [];
    const minimizationRows: FuzzingMinimizationRow[] = [];
    const limitations: string[] = [];
    let attempted = 0;
    let succeeded = 0;
    let cancelled = false;
    for (const [index, name] of inspected.entries()) {
      if (signal?.aborted === true) {
        cancelled = true;
        break;
      }
      const inputPath = join(artifactDirectory, name);
      const evidence = await this.#reproduce(
        request,
        workspace,
        adapter,
        configuration,
        inputPath,
        index,
        signal,
      );
      if (!evidence.ok) return evidence;
      const decision =
        evidence.value.reports.length === 0
          ? { accepted: false, reason: evidence.value.rejection }
          : evaluatePov({
              reports: evidence.value.reports,
              expectedSanitizer: request.expectedSanitizer,
            });
      if (!decision.accepted || decision.reason !== null) {
        rejectedRows.push({
          input_path: inputPath,
          reason: decision.reason ?? "report_unreadable",
        });
        continue;
      }
      const reportBody = evidence.value.reportBody;
      if (reportBody === null) {
        rejectedRows.push({
          input_path: inputPath,
          reason: "report_unreadable",
        });
        continue;
      }
      const stored = await this.#crashTriage.recordCrash(
        {
          campaignId: request.campaign.campaignId,
          reportBody,
          reproPath: inputPath,
        },
        optionsOf(signal),
      );
      if (!stored.ok) return stored;
      ingested.push({
        input_path: inputPath,
        crash_id: stored.value.crashId,
        dedup_id: stored.value.dedupId,
        dedup_is_new: stored.value.dedupIsNew,
        sanitizer_class: stored.value.sanitizerClass,
        crash_kind: stored.value.crashKind,
        frame_count: stored.value.frameCount,
        occurrence_count: stored.value.occurrenceCount,
      });
      if (request.minimizeCrashes && adapter.minimizerEngine !== null) {
        attempted += 1;
        const row = await this.#minimize(
          adapter.minimizerEngine,
          stored.value.crashId,
          inputPath,
          workspace,
          request.campaign.targetPath,
          signal,
        );
        if (row.status === "succeeded") succeeded += 1;
        minimizationRows.push(row);
      }
    }
    if (cancelled)
      limitations.push(
        "The caller cancelled during POV validation; later crash candidates were not inspected.",
      );
    if (names.length > inspected.length)
      limitations.push(
        `${String(names.length - inspected.length)} crash artifacts were observed beyond the ${String(FUZZING_MAX_CRASH_ARTIFACTS)}-artifact inspection budget and were not validated.`,
      );
    if (request.minimizeCrashes && adapter.minimizerEngine === null)
      limitations.push(
        `No crash-triage minimizer adapter is documented for the ${adapter.engine} engine, so accepted crashes were not minimized.`,
      );
    return ok({
      observed: names.length,
      crashes: {
        observed: names.length,
        inspected: inspected.length,
        accepted: ingested.length,
        rejected: rejectedRows.length,
        ingested: ingested.slice(0, FUZZING_MAX_CRASH_ROWS),
        rejected_rows: rejectedRows.slice(0, FUZZING_MAX_CRASH_ROWS),
        truncated:
          names.length > inspected.length ||
          ingested.length + rejectedRows.length > FUZZING_MAX_CRASH_ROWS,
      },
      minimization: {
        requested: request.minimizeCrashes,
        attempted,
        succeeded,
        rows: minimizationRows.slice(0, FUZZING_MAX_CRASH_ROWS),
      },
      limitations,
    });
  }

  async #reproduce(
    request: FuzzingCampaignRunRequest,
    workspace: CampaignWorkspace,
    adapter: FuzzingEngineAdapter,
    configuration: FuzzingEngineConfiguration,
    inputPath: string,
    index: number,
    signal: AbortSignal | undefined,
  ): Promise<
    Result<
      {
        readonly reports: readonly {
          readonly sanitizerClass: SanitizerClass;
          readonly stateHash: string;
          readonly frameCount: number;
        }[];
        readonly reportBody: string | null;
        readonly rejection: FuzzingPovRejection | null;
      },
      AnalysisError
    >
  > {
    const labVm = request.labVm;
    const guest =
      labVm === null
        ? null
        : guestWorkspaceOf(workspace.root, labVm.workspacePath);
    const guestInput =
      labVm === null
        ? inputPath
        : guestPath(workspace.root, labVm.workspacePath, inputPath);
    if (guestInput === null)
      return err(
        new AnalysisInputError(operation, {
          userMessage: `The crash artifact is outside the lab-VM workspace: ${inputPath}`,
        }),
      );
    const singleInputCorpus =
      guest === null
        ? join(workspace.povDirectory, `input-${String(index)}`, "corpus")
        : posix.join(guest.root, "pov", `input-${String(index)}`, "corpus");
    const outputDirectory =
      guest === null
        ? join(workspace.povDirectory, `input-${String(index)}`, "output")
        : posix.join(guest.root, "pov", `input-${String(index)}`, "output");
    const plan = adapter.reproduce({
      targetPath:
        labVm === null
          ? request.campaign.targetPath
          : (guestPath(
              workspace.root,
              labVm.workspacePath,
              request.campaign.targetPath,
            ) ?? request.campaign.targetPath),
      configuration,
      inputPath: guestInput,
      workspace: guest ?? workspace,
      singleInputCorpus,
      outputDirectory,
    });
    if (adapter.engine === "jackalope" && labVm === null) {
      await mkdir(singleInputCorpus, { recursive: true, mode: 0o700 });
      await copyFile(
        inputPath,
        join(singleInputCorpus, inputPath.split(/[\\/]/u).pop() ?? "input"),
      );
    }
    const reports: {
      sanitizerClass: SanitizerClass;
      stateHash: string;
      frameCount: number;
    }[] = [];
    let reportBody: string | null = null;
    let rejection: FuzzingPovRejection | null = null;
    for (let attempt = 0; attempt < request.povRepeats; attempt += 1) {
      if (signal?.aborted === true) break;
      const captured =
        labVm === null
          ? await this.#reproduceOnHost(plan, signal)
          : await this.#reproduceInLabVm(
              labVm,
              workspace,
              plan,
              index,
              attempt,
              signal,
            );
      if (!captured.ok) return captured;
      if (captured.value.rejection !== null) {
        rejection ??= captured.value.rejection;
        continue;
      }
      const body = captured.value.reportBody;
      if (body === null) {
        rejection ??= "report_unreadable";
        continue;
      }
      let facts;
      try {
        facts = parseCrashReport(body);
      } catch (cause: unknown) {
        if (!(cause instanceof CrashReportParseFailure)) throw cause;
        rejection ??= "report_unreadable";
        continue;
      }
      const state = crashStateFor({
        sanitizerClass: facts.sanitizer_class,
        crashKind: facts.crash_kind,
        frames: facts.frames,
        maxFrames: request.campaign.dedupFrames,
      });
      reports.push({
        sanitizerClass: facts.sanitizer_class,
        stateHash: state.dedup_hash,
        frameCount: facts.frames.length,
      });
      reportBody ??= body;
    }
    return ok({ reports, reportBody, rejection });
  }

  async #reproduceOnHost(
    plan: FuzzingReproducePlan,
    signal: AbortSignal | undefined,
  ): Promise<Result<ReproductionCapture, AnalysisError>> {
    try {
      await execFileBytes(plan.executable, plan.arguments, {
        timeout: FUZZING_POV_TIMEOUT_MS,
        maxBuffer: FUZZING_MAX_OUTPUT_BYTES,
        stopSignal: "SIGTERM",
        env: { ...this.#environment },
        ...(signal === undefined ? {} : { signal }),
      });
      return ok({ reportBody: null, rejection: "not_reproduced" });
    } catch (cause: unknown) {
      if (cause instanceof ExecFileOutputCancelledError)
        return err(
          new AnalysisCancelledError(operation, { cause: cause.cause }),
        );
      const spawnCode = spawnFailureCode(cause);
      if (spawnCode !== undefined)
        return err(
          new AnalysisCapabilityUnavailableError(
            FUZZING_PROVIDER.id,
            operation,
            `The POV reproducer could not be started (${spawnCode}): ${plan.executable}`,
            {
              cause,
              diagnostics: {
                boundary: "provider-launch",
                selected_binary: plan.executable,
                system_code: spawnCode,
              },
            },
          ),
        );
      const failure = execFileOutputFailure(cause);
      if (failure === undefined)
        return err(
          new AnalysisCapabilityUnavailableError(
            FUZZING_PROVIDER.id,
            operation,
            `Cannot run the POV reproducer: ${plan.executable}`,
            { cause },
          ),
        );
      if (failure.outputTruncated)
        return ok({ reportBody: null, rejection: "report_too_large" });
      const body =
        failure.stderr.trim() === "" ? failure.stdout : failure.stderr;
      return ok({ reportBody: body, rejection: null });
    }
  }

  async #reproduceInLabVm(
    labVm: NonNullable<FuzzingCampaignRunRequest["labVm"]>,
    workspace: CampaignWorkspace,
    plan: FuzzingReproducePlan,
    index: number,
    attempt: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<ReproductionCapture, AnalysisError>> {
    const port = this.#labVm;
    if (port === undefined)
      return err(
        new AnalysisInputError(operation, {
          userMessage: "The lab-VM route needs a started lab VM session.",
        }),
      );
    const guest = guestWorkspaceOf(workspace.root, labVm.workspacePath);
    const directory = posix.join(
      guest.root,
      "pov",
      `input-${String(index)}`,
      `run-${String(attempt)}`,
    );
    const reportFile = posix.join(directory, FUZZING_LAB_VM_REPORT_FILE);
    const observed = await port.run(
      {
        sessionId: labVm.sessionId,
        command: guestCommand(
          directory,
          [plan.executable, ...plan.arguments],
          reportFile,
        ),
        timeoutMs: FUZZING_POV_TIMEOUT_MS,
      },
      optionsOf(signal),
    );
    if (!observed.ok) return observed;
    const hostReport = join(
      workspace.povDirectory,
      `input-${String(index)}`,
      `run-${String(attempt)}`,
      FUZZING_LAB_VM_REPORT_FILE,
    );
    const body = await readFile(hostReport, "utf8").catch(() => null);
    if (body === null || body.trim() === "")
      return ok({ reportBody: null, rejection: "not_reproduced" });
    return ok({ reportBody: body, rejection: null });
  }

  async #minimize(
    engine: CrashMinimizeEngine,
    crashId: string,
    inputPath: string,
    workspace: CampaignWorkspace,
    targetPath: string,
    signal: AbortSignal | undefined,
  ): Promise<FuzzingMinimizationRow> {
    const outputPath = join(workspace.minimizeDirectory, `${crashId}.min`);
    const minimized = await this.#crashTriage.minimizeCrash(
      {
        engine,
        inputPath,
        outputPath,
        targetPath,
        timeoutMs: CRASH_MINIMIZE_DEFAULT_TIMEOUT_MS,
        maxTotalSeconds: CRASH_MINIMIZE_DEFAULT_MAX_TOTAL_SECONDS,
      },
      optionsOf(signal),
    );
    if (!minimized.ok)
      return {
        crash_id: crashId,
        engine,
        status: "failed",
        input_bytes: null,
        output_bytes: null,
        output_path: null,
        failure: minimized.error._tag,
      };
    return {
      crash_id: crashId,
      engine,
      status: minimized.value.output === null ? "failed" : "succeeded",
      input_bytes: minimized.value.input.bytes,
      output_bytes: minimized.value.output?.bytes ?? null,
      output_path: minimized.value.output?.path ?? null,
      failure:
        minimized.value.output === null ? "minimized_artifact_missing" : null,
    };
  }
}

const optionsOf = (signal: AbortSignal | undefined): ExecutionOptions =>
  signal === undefined ? {} : { signal };
