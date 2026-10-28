import {
  crashDedupListSchema,
  crashEvidenceSchema,
  fuzzingCampaignRegistrationSchema,
  fuzzingCampaignStatusResultSchema,
} from "../../domain/crashTriage/fuzzingCampaign.js";
import {
  fetchCrashEvidenceInputSchema,
  listCrashDedupsInputSchema,
  readCampaignStatusInputSchema,
  registerFuzzingCampaignInputSchema,
} from "../../domain/crashTriage/crashTriageInputs.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

const dedupFramesExample = 3;

/**
 * Campaign bookkeeping over crash reports a caller-run engine produced.
 *
 * Registration digests the caller's target and seeds and issues a
 * server-lifetime campaign identity. The reads report stored counters,
 * deduplicated groups, and one crash's structural facts. No engine is started,
 * no target is executed, and report bodies stay on disk.
 */
export const CRASH_TRIAGE_TOOL_CONTRACTS = [
  {
    name: "register_fuzzing_campaign",
    ...toolContractMetadata("register_fuzzing_campaign"),
    description:
      "Book-keep one fuzzing campaign before any engine runs: digest the absolute target path and up to 32 seed paths, record the caller's stop condition (at least one of max_runs, max_seconds, or max_crashes), and choose the crash-state window (1-8 top frames, default 3). Returns a server-lifetime campaign_id, the observed identities, and the private directory that will hold retained crash reports. Campaigns live in a private runtime root that this REA server removes when it closes, so a later process cannot resume them. This tool registers bookkeeping only: it starts no fuzzer, executes no target, and downloads nothing. Crash report bodies are recorded separately by the fuzz loop that owns the engine.",
    kind: "crash-triage",
    inputSchema: registerFuzzingCampaignInputSchema,
    outputSchema: evidenceResultOf(fuzzingCampaignRegistrationSchema),
    examples: [
      {
        title: "Register a time-bounded campaign with one seed",
        input: {
          target_path: "/artifacts/fuzz_target",
          seed_paths: ["/artifacts/seeds/empty"],
          budget: { max_seconds: 600 },
          dedup_frames: dedupFramesExample,
        },
      },
      {
        title: "Register a run-bounded campaign without seeds",
        input: {
          target_path: "/artifacts/fuzz_target",
          budget: { max_runs: 100000, max_crashes: 50 },
        },
      },
    ],
  },
  {
    name: "read_campaign_status",
    ...toolContractMetadata("read_campaign_status"),
    description:
      "Report one campaign's registered identity, declared budget, crash-state window, and stored counters: crash_count, dedup_count, last_crash_at, and the retained report directory. Counters describe records REA retained, not executions an engine performed; this release starts no engine, so a campaign nobody fed reports zero crashes rather than a run outcome. An unknown campaign_id is an input error because identity is server-lifetime.",
    kind: "crash-triage",
    inputSchema: readCampaignStatusInputSchema,
    outputSchema: evidenceResultOf(fuzzingCampaignStatusResultSchema),
    examples: [
      {
        title: "Read counters for a registered campaign",
        input: { campaign_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7" },
      },
    ],
  },
  {
    name: "list_crash_dedups",
    ...toolContractMetadata("list_crash_dedups"),
    description:
      "Group one campaign's stored crashes by crash state: the sanitizer class, the normalized crash kind, and a bounded window of de-symbolized top frames hashed ClusterFuzz-style. Each group reports its dedup_id, crash kind, sanitizer class, normalized top frames, total frame count, summed occurrence count, member crash ids, and first/last observation times. Reported addresses, module offsets, build paths, and line numbers never enter the hash, so the same defect groups across runs of one build. A shared group is an observation about frames, not proof of one root cause; groups that differ below the window stay separate. limit bounds the listing and truncated marks a cut result.",
    kind: "crash-triage",
    inputSchema: listCrashDedupsInputSchema,
    outputSchema: evidenceResultOf(crashDedupListSchema),
    examples: [
      {
        title: "List deduplicated crashes in one campaign",
        input: {
          campaign_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          limit: 20,
        },
      },
    ],
  },
  {
    name: "fetch_crash_evidence",
    ...toolContractMetadata("fetch_crash_evidence"),
    description:
      "Return one stored crash's structural facts: crash kind, dedup identity, sanitizer class, access kind and signal when the runtime named them, the parsed frame list with reported symbols and source locations, the normalized top frames and state hash, occurrence count, the retained report path with its digest and size, and the caller-owned reproducer path with the size observed at recording and whether it exists now. The report body itself is never inlined; only the sanitizer's own summary line, bounded to 200 characters, appears, and it can name a source path from the crashing build. REA did not observe the target process, so these facts describe what the engine reported.",
    kind: "crash-triage",
    inputSchema: fetchCrashEvidenceInputSchema,
    outputSchema: evidenceResultOf(crashEvidenceSchema),
    examples: [
      {
        title: "Fetch one crash of a campaign",
        input: {
          campaign_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
          crash_id: `crash_${"0".repeat(64)}`,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
