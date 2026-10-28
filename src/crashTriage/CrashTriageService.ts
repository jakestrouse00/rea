import { randomUUID } from "node:crypto";
import { stat } from "node:fs/promises";
import { join } from "node:path";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  CrashIngestSummary,
  CrashTriagePort,
  MinimizeCrashRequest,
  RecordCrashRequest,
  RegisterFuzzingCampaignRequest,
} from "../application/crashTriage/CrashTriagePort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { digestCanonicalValue } from "../domain/canonicalDigest.js";
import type { CrashMinimizationObservation } from "../domain/crashTriage/crashMinimization.js";
import { groupCrashesByDedup } from "../domain/crashTriage/crashDedup.js";
import {
  CrashReportParseFailure,
  CRASH_REPORT_MAX_BYTES,
  CRASH_TRIAGE_PROVIDER,
  parseCrashReport,
  type CrashReportFacts,
} from "../domain/crashTriage/crashReport.js";
import {
  crashDedupIdSchema,
  crashStateFor,
} from "../domain/crashTriage/crashStateHash.js";
import {
  CRASH_TRIAGE_MAX_CAMPAIGNS,
  CRASH_TRIAGE_MAX_CAMPAIGN_CRASHES,
  CRASH_TRIAGE_MAX_SEEDS,
  crashDedupListSchema,
  crashEvidenceSchema,
  fuzzingCampaignBudgetIsBounded,
  fuzzingCampaignRegistrationSchema,
  fuzzingCampaignStatusResultSchema,
  type CampaignArtifact,
} from "../domain/crashTriage/fuzzingCampaign.js";
import type { Evidence } from "../domain/evidence.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  PrivateRuntimeRoot,
  type PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";
import { digestCampaignArtifact } from "./CrashTriageArtifacts.js";
import {
  boundedDedupLimit,
  crashTriageAborted,
  crashTriageCancelled,
  reportBytes,
  storeFailure,
  unknownCampaign,
} from "./CrashTriageFailures.js";
import {
  createCampaignRegistrationEvidence,
  createCampaignStatusEvidence,
  createCrashDedupListEvidence,
  createCrashEvidence,
} from "./CrashTriageEvidence.js";
import { CrashMinimizer } from "./CrashMinimizer.js";
import {
  CrashTriageStore,
  CrashTriageStoreFailure,
  type StoredCampaign,
  type StoredCrash,
} from "./CrashTriageStore.js";

export interface CrashTriageServiceOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly createRuntimeRoot?: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<Pick<PrivateRuntimeRoot, "path" | "close">>;
  readonly store?: CrashTriageStore;
  readonly minimizer?: CrashMinimizer;
  readonly now?: () => string;
}

/**
 * Owns the crash-triage store and the minimization seam.
 *
 * Nothing here starts a fuzzing engine, writes to a target, or publishes
 * report bodies. Registration digests the caller's target and seeds; the
 * three read tools report stored identity, counters, and structural crash
 * facts; recording and minimization are the seams the fuzz loop uses.
 */
export class CrashTriageService implements CrashTriagePort {
  readonly #store: CrashTriageStore;
  readonly #minimizer: CrashMinimizer;
  readonly #now: () => string;

  constructor(options: CrashTriageServiceOptions = {}) {
    this.#store =
      options.store ??
      new CrashTriageStore(
        options.createRuntimeRoot ??
          ((rootOptions) => PrivateRuntimeRoot.create(rootOptions)),
      );
    this.#minimizer =
      options.minimizer ??
      new CrashMinimizer(options.environment ?? process.env);
    this.#now = options.now ?? (() => new Date().toISOString());
  }

  /** Private directory that holds the store, once one exists. */
  get storePath(): string | null {
    return this.#store.opened ? this.#store.path : null;
  }

  async registerCampaign(
    request: RegisterFuzzingCampaignRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "register_fuzzing_campaign";
    if (crashTriageAborted(options.signal))
      return err(crashTriageCancelled(operation, options.signal));
    if (!fuzzingCampaignBudgetIsBounded(request.budget))
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage:
              "Declare at least one of max_runs, max_seconds, or max_crashes; a campaign without a stop condition is not registered.",
          },
          [{ path: ["budget"], reason: "missing_argument" }],
        ),
      );
    const uniqueSeeds = [...new Set(request.seedPaths)];
    if (uniqueSeeds.length !== request.seedPaths.length)
      return err(
        new AnalysisInputError(
          operation,
          { userMessage: "Each seed path may be listed once." },
          [{ path: ["seed_paths"], reason: "invalid_value" }],
        ),
      );
    if (uniqueSeeds.length > CRASH_TRIAGE_MAX_SEEDS)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `${String(uniqueSeeds.length)} seeds exceed the ${String(CRASH_TRIAGE_MAX_SEEDS)}-seed campaign budget`,
          { max_seeds: CRASH_TRIAGE_MAX_SEEDS, seed_count: uniqueSeeds.length },
          {
            remediationAction:
              "Split the corpus across campaigns; the seed count is a fixed registration bound.",
          },
        ),
      );
    const target = await digestCampaignArtifact(request.targetPath, operation, {
      label: "target",
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (!target.ok) return target;
    const seeds: CampaignArtifact[] = [];
    for (const seedPath of uniqueSeeds) {
      const seed = await digestCampaignArtifact(seedPath, operation, {
        label: "seed",
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (!seed.ok) return seed;
      seeds.push(seed.value);
    }
    if (crashTriageAborted(options.signal))
      return err(crashTriageCancelled(operation, options.signal));
    try {
      await this.#store.ensure();
      const existing = this.#store.campaignCount();
      if (existing >= CRASH_TRIAGE_MAX_CAMPAIGNS)
        return err(
          new AnalysisResourceConstraintError(
            operation,
            "memory",
            `${String(existing)} campaigns already exist in this server; the ${String(CRASH_TRIAGE_MAX_CAMPAIGNS)}-campaign bound is full`,
            {
              max_campaigns: CRASH_TRIAGE_MAX_CAMPAIGNS,
              campaign_count: existing,
            },
            {
              remediationAction:
                "Campaign identity is server-lifetime. Restart the REA server to start with an empty store.",
            },
          ),
        );
      const campaignId = randomUUID();
      const registeredAt = this.#now();
      this.#store.registerCampaign({
        campaignId,
        target: target.value,
        seeds,
        budget: request.budget,
        dedupFrames: request.dedupFrames,
        registeredAt,
      });
      const result = fuzzingCampaignRegistrationSchema.parse({
        campaign_id: campaignId,
        status: "registered",
        target: target.value,
        seeds,
        budget: request.budget,
        dedup_frames: request.dedupFrames,
        registered_at: registeredAt,
        report_store_path: this.#store.path,
      });
      return ok(
        createCampaignRegistrationEvidence(
          { target: target.value, seeds, dedupFrames: request.dedupFrames },
          result,
        ),
      );
    } catch (cause: unknown) {
      return err(storeFailure(operation, cause));
    }
  }

  async campaignStatus(
    request: { readonly campaignId: string },
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "read_campaign_status";
    if (crashTriageAborted(options.signal))
      return err(crashTriageCancelled(operation, options.signal));
    try {
      const campaign = this.#campaign(operation, request.campaignId);
      if (!campaign.ok) return campaign;
      const summary = this.#store.campaignSummary(request.campaignId);
      const result = fuzzingCampaignStatusResultSchema.parse({
        campaign_id: campaign.value.campaignId,
        status: campaign.value.status,
        target: campaign.value.target,
        seed_count: campaign.value.seeds.length,
        seed_bytes: campaign.value.seeds.reduce(
          (total, seed) => total + seed.bytes,
          0,
        ),
        budget: campaign.value.budget,
        dedup_frames: campaign.value.dedupFrames,
        crash_count: summary.crashCount,
        dedup_count: summary.dedupCount,
        last_crash_at: summary.lastCrashAt,
        registered_at: campaign.value.registeredAt,
        report_store_path: this.#store.path,
      });
      return ok(createCampaignStatusEvidence(result));
    } catch (cause: unknown) {
      return err(storeFailure(operation, cause));
    }
  }

  async listDedups(
    request: { readonly campaignId: string; readonly limit: number },
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "list_crash_dedups";
    if (crashTriageAborted(options.signal))
      return err(crashTriageCancelled(operation, options.signal));
    try {
      const campaign = this.#campaign(operation, request.campaignId);
      if (!campaign.ok) return campaign;
      const grouping = groupCrashesByDedup(
        this.#store
          .crashes(request.campaignId, CRASH_TRIAGE_MAX_CAMPAIGN_CRASHES)
          .map((record: StoredCrash) => ({
            crashId: record.crashId,
            dedupId: record.dedupId,
            dedupHash: record.state.dedup_hash,
            crashKind: record.facts.crash_kind,
            sanitizerClass: record.facts.sanitizer_class,
            frames: record.state.frames,
            frameCount: record.state.frame_count,
            occurrenceCount: record.occurrenceCount,
            firstSeenAt: record.firstSeenAt,
            lastSeenAt: record.lastSeenAt,
          })),
        boundedDedupLimit(request.limit),
      );
      const result = crashDedupListSchema.parse({
        campaign_id: campaign.value.campaignId,
        dedup_count: this.#store.campaignSummary(request.campaignId).dedupCount,
        dedup_frames: campaign.value.dedupFrames,
        dedups: grouping.groups.map((group) => ({
          dedup_id: crashDedupIdSchema.parse(group.dedupId),
          dedup_hash: group.dedupHash,
          crash_kind: group.crashKind,
          sanitizer_class: group.sanitizerClass,
          top_frames: [...group.topFrames],
          frame_count: group.frameCount,
          occurrence_count: group.occurrenceCount,
          crash_ids: [...group.crashIds],
          first_seen_at: group.firstSeenAt,
          last_seen_at: group.lastSeenAt,
        })),
        truncated: grouping.truncated,
      });
      return ok(createCrashDedupListEvidence(campaign.value.target, result));
    } catch (cause: unknown) {
      return err(storeFailure(operation, cause));
    }
  }

  async fetchCrashEvidence(
    request: { readonly campaignId: string; readonly crashId: string },
    options: ExecutionOptions = {},
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "fetch_crash_evidence";
    if (crashTriageAborted(options.signal))
      return err(crashTriageCancelled(operation, options.signal));
    try {
      const campaign = this.#campaign(operation, request.campaignId);
      if (!campaign.ok) return campaign;
      const record = this.#store.crash(request.crashId);
      if (record === null || record.campaignId !== request.campaignId)
        return err(
          new AnalysisInputError(
            operation,
            {
              userMessage: `No crash ${request.crashId} is recorded for campaign ${request.campaignId} in this REA server process.`,
            },
            [{ path: ["crash_id"], reason: "invalid_value" }],
          ),
        );
      const reportPath = join(this.#store.path, record.report.relative_path);
      const existsNow = await stat(record.repro.path).then(
        (observed) => observed.isFile(),
        (cause: unknown) =>
          (cause as NodeJS.ErrnoException).code === "ENOENT" ? false : null,
      );
      const result = crashEvidenceSchema.parse({
        crash_id: record.crashId,
        campaign_id: record.campaignId,
        dedup_id: crashDedupIdSchema.parse(record.dedupId),
        dedup_hash: record.state.dedup_hash,
        crash_kind: record.facts.crash_kind,
        sanitizer_class: record.facts.sanitizer_class,
        access: record.facts.access,
        signal: record.facts.signal,
        exception_type: record.facts.exception_type,
        termination_reason: record.facts.termination_reason,
        summary: record.facts.summary,
        frames: [...record.facts.frames],
        frames_truncated: record.facts.frames_truncated,
        frame_count: record.state.frame_count,
        state_hash: record.state.dedup_hash,
        top_frames: [...record.state.frames],
        occurrence_count: record.occurrenceCount,
        crash_report: {
          format: record.facts.format,
          path: reportPath,
          sha256: record.report.sha256,
          bytes: record.report.bytes,
        },
        repro_input: {
          path: record.repro.path,
          bytes: record.repro.bytes,
          exists_now: existsNow,
        },
        recorded_at: record.recordedAt,
        first_seen_at: record.firstSeenAt,
        last_seen_at: record.lastSeenAt,
      });
      return ok(
        createCrashEvidence({
          target: campaign.value.target,
          result,
          reportPath,
          reproPath: record.repro.path,
        }),
      );
    } catch (cause: unknown) {
      return err(storeFailure(operation, cause));
    }
  }

  async recordCrash(
    request: RecordCrashRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<CrashIngestSummary, AnalysisError>> {
    const operation = "record_crash_report";
    if (crashTriageAborted(options.signal))
      return err(crashTriageCancelled(operation, options.signal));
    const reportByteLength = Buffer.byteLength(request.reportBody, "utf8");
    if (reportByteLength > CRASH_REPORT_MAX_BYTES)
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "memory",
          `The report is ${String(reportByteLength)} bytes, above the ${String(CRASH_REPORT_MAX_BYTES)}-byte parsing budget`,
          {
            max_report_bytes: CRASH_REPORT_MAX_BYTES,
            report_bytes: reportByteLength,
          },
          {
            remediationAction:
              "Retain the sanitizer report without its shadow-byte and memory-map dump; the parsing budget has no runtime override.",
          },
        ),
      );
    let facts: CrashReportFacts;
    try {
      facts = parseCrashReport(request.reportBody);
    } catch (cause: unknown) {
      if (!(cause instanceof CrashReportParseFailure)) throw cause;
      return err(
        new AnalysisOutputError(operation, cause.reason, {
          cause,
          userMessage: cause.message,
          diagnostics: { ...cause.diagnostics },
        }),
      );
    }
    const repro = await stat(request.reproPath).catch(() => null);
    if (repro === null || !repro.isFile())
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage: `The reproducer input is not a regular file: ${request.reproPath}`,
          },
          [{ path: ["repro_path"], reason: "invalid_value" }],
        ),
      );
    try {
      await this.#store.ensure();
      const campaign = this.#campaign(operation, request.campaignId);
      if (!campaign.ok) return campaign;
      const state = crashStateFor({
        sanitizerClass: facts.sanitizer_class,
        crashKind: facts.crash_kind,
        frames: facts.frames,
        maxFrames: campaign.value.dedupFrames,
      });
      const report = reportBytes(request.reportBody);
      const crashId = `crash_${digestCanonicalValue(
        {
          campaign_id: request.campaignId,
          report_sha256: report.sha256,
        },
        "Crash",
      )}`;
      const existing = this.#store.crash(crashId);
      if (
        existing === null &&
        this.#store.crashCount(request.campaignId) >=
          CRASH_TRIAGE_MAX_CAMPAIGN_CRASHES
      )
        return err(
          new AnalysisResourceConstraintError(
            operation,
            "memory",
            `Campaign ${request.campaignId} already retains ${String(CRASH_TRIAGE_MAX_CAMPAIGN_CRASHES)} crash records`,
            { max_campaign_crashes: CRASH_TRIAGE_MAX_CAMPAIGN_CRASHES },
            {
              remediationAction:
                "Register another campaign for a wider run; the retained-crash bound is fixed.",
            },
          ),
        );
      const dedupIsNew = !this.#store.hasDedup(
        request.campaignId,
        state.dedup_id,
      );
      const written =
        existing === null
          ? await this.#store.writeReport(crashId, request.reportBody)
          : {
              relativePath: existing.report.relative_path,
              sha256: existing.report.sha256,
              bytes: existing.report.bytes,
            };
      const observedAt = this.#now();
      this.#store.recordCrash({
        crashId,
        campaignId: request.campaignId,
        dedupId: state.dedup_id,
        recordedAt: existing?.recordedAt ?? observedAt,
        observedAt,
        document: {
          facts,
          state: {
            dedup_hash: state.dedup_hash,
            frames: state.frames.slice(0, state.frames_used),
            frame_count: facts.frames.length,
          },
          report: {
            format: facts.format,
            relative_path: written.relativePath,
            sha256: written.sha256,
            bytes: written.bytes,
          },
          repro: { path: request.reproPath, bytes: repro.size },
        },
      });
      const stored = this.#store.crash(crashId);
      return ok({
        crashId,
        campaignId: request.campaignId,
        dedupId: state.dedup_id,
        dedupIsNew,
        crashKind: facts.crash_kind,
        sanitizerClass: facts.sanitizer_class,
        frameCount: facts.frames.length,
        occurrenceCount: stored?.occurrenceCount ?? 1,
      });
    } catch (cause: unknown) {
      return err(storeFailure(operation, cause));
    }
  }

  async minimizeCrash(
    request: MinimizeCrashRequest,
    options: ExecutionOptions = {},
  ): Promise<Result<CrashMinimizationObservation, AnalysisError>> {
    return this.#minimizer.minimize(request, options);
  }

  async closeAll(): Promise<Result<null, AnalysisError>> {
    const storePath = this.storePath;
    try {
      await this.#store.close();
      return ok(null);
    } catch (cause: unknown) {
      const diagnostics: Record<string, JsonValue> =
        cause instanceof CrashTriageStoreFailure
          ? { ...cause.diagnostics }
          : {};
      return err(
        new ProviderCleanupError(
          CRASH_TRIAGE_PROVIDER.id,
          [storePath ?? "crash-triage store"],
          diagnostics,
          {
            cause,
            operation: "close_crash_triage_store",
            remediationAction:
              "Remove the reported private directory by hand; it holds retained crash reports and the campaign database.",
          },
        ),
      );
    }
  }

  #campaign(
    operation: string,
    campaignId: string,
  ): Result<StoredCampaign, AnalysisError> {
    if (!this.#store.opened) return err(unknownCampaign(operation, campaignId));
    const campaign = this.#store.campaign(campaignId);
    if (campaign === null) return err(unknownCampaign(operation, campaignId));
    return ok(campaign);
  }
}
