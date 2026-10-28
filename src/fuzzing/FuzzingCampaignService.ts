import { isAbsolute, join } from "node:path";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { CrashTriagePort } from "../application/crashTriage/CrashTriagePort.js";
import type {
  FuzzingCampaignPort,
  StartFuzzingCampaignRequest,
} from "../application/fuzzing/FuzzingCampaignPort.js";
import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import {
  FUZZING_LAB_VM_DIRECTORY,
  FUZZING_MAX_ACTIVE_CAMPAIGNS,
  FUZZING_MAX_RETAINED_CAMPAIGNS,
  FUZZING_PROVIDER,
} from "../domain/fuzzing/fuzzingEngine.js";
import type { Evidence } from "../domain/evidence.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  PrivateRuntimeRoot,
  type PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";
import {
  createFuzzingCampaignEvidence,
  FUZZING_RETENTION_LIMITATION,
} from "./FuzzingEvidence.js";
import { FuzzingCampaignRunner } from "./FuzzingCampaignRunner.js";

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;

export interface FuzzingCampaignServiceOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  /** Crash-triage bookkeeping the campaign feeds. */
  readonly crashTriage: Pick<
    CrashTriagePort,
    "campaignRecord" | "recordCrash" | "minimizeCrash"
  >;
  readonly labVm?: LabVmPort;
  readonly settings?: AnalysisSettingsReader;
  readonly createRuntimeRoot?: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly now?: () => string;
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly statsIntervalMs?: number;
}

const operation = "start_fuzzing_campaign";

/**
 * Owns the fuzz loop: one running campaign, the private roots it retains, and
 * the hand-off to crash triage.
 *
 * A second campaign cannot start while one runs, because each engine owns the
 * host's cores. Campaign roots stay until the server closes so the reproducer
 * paths a crash record names still exist.
 */
export class FuzzingCampaignService implements FuzzingCampaignPort {
  readonly #crashTriage: FuzzingCampaignServiceOptions["crashTriage"];
  readonly #runner: FuzzingCampaignRunner;
  readonly #createRuntimeRoot: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly #roots: {
    readonly path: string;
    readonly close: () => Promise<void>;
  }[] = [];
  #active = false;

  constructor(options: FuzzingCampaignServiceOptions) {
    this.#crashTriage = options.crashTriage;
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      ((rootOptions) => PrivateRuntimeRoot.create(rootOptions));
    this.#runner = new FuzzingCampaignRunner({
      crashTriage: options.crashTriage,
      ...(options.environment === undefined
        ? {}
        : { environment: options.environment }),
      ...(options.labVm === undefined ? {} : { labVm: options.labVm }),
      ...(options.settings === undefined ? {} : { settings: options.settings }),
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.platform === undefined ? {} : { platform: options.platform }),
      ...(options.arch === undefined ? {} : { arch: options.arch }),
      ...(options.statsIntervalMs === undefined
        ? {}
        : { statsIntervalMs: options.statsIntervalMs }),
    });
  }

  async startCampaign(
    request: StartFuzzingCampaignRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options.signal?.aborted === true)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    if (this.#active)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "cpu",
          "Another fuzzing campaign is already running in this REA server",
          { max_active_campaigns: FUZZING_MAX_ACTIVE_CAMPAIGNS },
          {
            remediationAction:
              "Campaigns run one at a time because each engine owns every host core. Wait for the running campaign to finish, or stop it by cancelling that call.",
          },
        ),
      );
    const campaign = await this.#crashTriage.campaignRecord(
      { campaignId: request.campaignId },
      options,
    );
    if (!campaign.ok) return campaign;
    const root = await this.#workspaceRoot(request);
    if (!root.ok) return root;
    this.#active = true;
    try {
      const observation = await this.#runner.run(
        {
          campaign: campaign.value,
          engine: request.engine,
          povRepeats: request.povRepeats,
          expectedSanitizer: request.expectedSanitizer,
          minimizeCrashes: request.minimizeCrashes,
          route: request.labVm === null ? "host" : "lab_vm",
          workspaceRoot: root.value.path,
          labVm: request.labVm,
        },
        options,
      );
      if (!observation.ok) {
        if (root.value.retain)
          try {
            await root.value.close();
          } catch {
            this.#retain(root.value.path, root.value.close);
          }
        return observation;
      }
      if (root.value.retain) this.#retain(root.value.path, root.value.close);
      return ok(createFuzzingCampaignEvidence(observation.value));
    } finally {
      this.#active = false;
    }
  }

  async closeAll(): Promise<Result<null, AnalysisError>> {
    const failures: { readonly path: string; readonly cause: unknown }[] = [];
    for (const root of this.#roots.splice(0))
      try {
        await root.close();
      } catch (cause: unknown) {
        failures.push({ path: root.path, cause });
        this.#retain(root.path, root.close);
      }
    if (failures.length === 0) return ok(null);
    return err(
      new ProviderCleanupError(
        FUZZING_PROVIDER.id,
        failures.map((failure) => failure.path),
        {},
        {
          cause: failures[0]?.cause,
          operation: "close_fuzzing_campaign_roots",
          remediationAction:
            "Remove the reported private runtime roots by hand; they hold campaign corpora, crash artifacts, and minimized inputs.",
        },
      ),
    );
  }

  async #workspaceRoot(
    request: StartFuzzingCampaignRequest,
  ): Promise<
    Result<
      { path: string; retain: boolean; close: () => Promise<void> },
      AnalysisError
    >
  > {
    if (request.labVm !== null) {
      if (!isAbsolute(request.labVm.workspacePath))
        return err(
          new AnalysisInputError(operation, {
            userMessage: `lab_vm_workspace_path must be absolute: ${request.labVm.workspacePath}`,
          }),
        );
      return ok({
        path: join(
          request.labVm.workspacePath,
          FUZZING_LAB_VM_DIRECTORY,
          request.campaignId,
        ),
        retain: false,
        close: async () => undefined,
      });
    }
    if (this.#roots.length >= FUZZING_MAX_RETAINED_CAMPAIGNS)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `${String(this.#roots.length)} campaign roots are retained; the ${String(FUZZING_MAX_RETAINED_CAMPAIGNS)}-root bound is full`,
          { max_retained_campaigns: FUZZING_MAX_RETAINED_CAMPAIGNS },
          {
            remediationAction: `${FUZZING_RETENTION_LIMITATION} Restart the REA server to start with no retained campaign roots.`,
          },
        ),
      );
    try {
      const root = await this.#createRuntimeRoot({ prefix: "rea-fuzzing-" });
      return ok({
        path: root.path,
        retain: true,
        close: () => root.close(),
      });
    } catch (cause: unknown) {
      return err(
        new ProviderCleanupError(
          FUZZING_PROVIDER.id,
          ["private campaign runtime root"],
          {},
          {
            cause,
            operation,
            remediationAction:
              "REA could not allocate a private runtime root for the campaign; check the temporary-directory permissions of this host.",
          },
        ),
      );
    }
  }

  #retain(path: string, close: () => Promise<void>): void {
    this.#roots.push({ path, close });
  }
}
