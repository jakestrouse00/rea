import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  CrashMinimizationObservation,
  CrashMinimizeEngine,
} from "../../domain/crashTriage/crashMinimization.js";
import type { SanitizerClass } from "../../domain/crashTriage/crashReport.js";
import type {
  FuzzingCampaignBudget,
  FuzzingCampaignStatus,
} from "../../domain/crashTriage/fuzzingCampaign.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";

/** Caller-selected fuzz target, seeds, and stop condition. */
export interface RegisterFuzzingCampaignRequest {
  readonly targetPath: string;
  readonly seedPaths: readonly string[];
  readonly budget: FuzzingCampaignBudget;
  readonly dedupFrames: number;
}

/** One crash report a caller-run engine produced, with its reproducer path. */
export interface RecordCrashRequest {
  readonly campaignId: string;
  readonly reportBody: string;
  readonly reproPath: string;
}

/** One registered campaign as the store retained it, in caller terms. */
export interface RegisteredFuzzingCampaign {
  readonly campaignId: string;
  readonly status: FuzzingCampaignStatus;
  readonly targetPath: string;
  readonly targetSha256: string;
  readonly targetBytes: number;
  readonly seedPaths: readonly string[];
  readonly budget: FuzzingCampaignBudget;
  readonly dedupFrames: number;
  readonly registeredAt: string;
}

/** What recording one crash established, without the report body. */
export interface CrashIngestSummary {
  readonly crashId: string;
  readonly campaignId: string;
  readonly dedupId: string;
  readonly dedupIsNew: boolean;
  readonly crashKind: string;
  readonly sanitizerClass: SanitizerClass;
  readonly frameCount: number;
  readonly occurrenceCount: number;
}

/** One minimization attempt the later fuzz loop can request. */
export interface MinimizeCrashRequest {
  readonly engine: CrashMinimizeEngine;
  readonly inputPath: string;
  readonly outputPath: string;
  readonly targetPath?: string;
  readonly timeoutMs: number;
  readonly maxTotalSeconds: number;
}

/**
 * Server-lifetime fuzzing-campaign bookkeeping.
 *
 * The four tool-facing reads and writes report what REA recorded: campaign
 * identity, stored counters, deduplicated crash groups, and one crash's
 * structural facts. Crash reports come from a caller-run engine, so
 * `recordCrash` and `minimizeCrash` are the seams the fuzz loop uses; neither
 * is a public tool in this release, and no engine is started here.
 */
export interface CrashTriagePort {
  registerCampaign(
    request: RegisterFuzzingCampaignRequest,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  campaignStatus(
    request: { readonly campaignId: string },
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  listDedups(
    request: { readonly campaignId: string; readonly limit: number },
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  fetchCrashEvidence(
    request: { readonly campaignId: string; readonly crashId: string },
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>>;
  /** The registered campaign a launch needs: identity, paths, budget, window. */
  campaignRecord(
    request: { readonly campaignId: string },
    options?: ExecutionOptions,
  ): Promise<Result<RegisteredFuzzingCampaign, AnalysisError>>;
  recordCrash(
    request: RecordCrashRequest,
    options?: ExecutionOptions,
  ): Promise<Result<CrashIngestSummary, AnalysisError>>;
  minimizeCrash(
    request: MinimizeCrashRequest,
    options?: ExecutionOptions,
  ): Promise<Result<CrashMinimizationObservation, AnalysisError>>;
  /** Remove the private store; a failed removal reports the retained path. */
  closeAll(): Promise<Result<null, AnalysisError>>;
}
