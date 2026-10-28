import { z } from "zod";

/** Provider identity for the caller-selected fuzzing engines. */
export const FUZZING_PROVIDER = {
  id: "rea-fuzzing-campaign",
  name: "REA fuzzing campaign lane",
  version: "1",
} as const;

/** Engines one campaign can drive behind the shared adapter contract. */
export const FUZZING_ENGINES = [
  "libfuzzer",
  "aflpp_frida",
  "jackalope",
] as const;

export const fuzzingEngineSchema = z.enum(FUZZING_ENGINES);
export type FuzzingEngine = z.infer<typeof fuzzingEngineSchema>;

/** Caller-supplied libFuzzer-instrumented target. REA never builds one. */
export const FUZZING_LFZ_COMMAND_ENV = "REA_LFZ_FUZZER_COMMAND";

/** Caller-supplied afl-fuzz binary launched in FRIDA mode (`-O`). */
export const FUZZING_AFLFRIDA_COMMAND_ENV = "REA_AFLFRIDA_FUZZER_COMMAND";

/** Directory of a caller-built Jackalope/TinyInst tree. */
export const FUZZING_JACKALOPE_DIR_ENV = "REA_JACKALOPE_DIR";

/** Executable a Jackalope build tree must provide. */
export const FUZZING_JACKALOPE_FUZZER_FILE = "fuzzer";

/** TinyInst instrumentation module a Jackalope build tree must provide. */
export const FUZZING_JACKALOPE_INSTRUMENTATION_FILE = "instrumentation";

export const FUZZING_LFZ_REMEDIATION = `Set ${FUZZING_LFZ_COMMAND_ENV} to the absolute path of a caller-supplied libFuzzer-instrumented fuzz target and restart REA. REA never builds, downloads, or installs a fuzz target. See docs/fuzzing-libfuzzer.md.`;

export const FUZZING_AFLFRIDA_REMEDIATION = `Set ${FUZZING_AFLFRIDA_COMMAND_ENV} to the absolute path of a caller-supplied afl-fuzz binary and restart REA. REA never installs or upgrades AFL++ tooling; FRIDA mode needs AFL++ 4.x on a macOS arm64 host. See docs/fuzzing-aflpp-frida.md.`;

export const FUZZING_JACKALOPE_REMEDIATION = `Set ${FUZZING_JACKALOPE_DIR_ENV} to the absolute path of a caller-built Jackalope/TinyInst directory containing ${FUZZING_JACKALOPE_FUZZER_FILE} and ${FUZZING_JACKALOPE_INSTRUMENTATION_FILE}, then restart REA. REA never downloads or builds Jackalope. See docs/fuzzing-jackalope.md.`;

/** One remediation sentence naming every engine selection. */
export const FUZZING_TOOL_REMEDIATION = `Select at least one caller-supplied engine: ${FUZZING_LFZ_COMMAND_ENV} (libFuzzer target), ${FUZZING_AFLFRIDA_COMMAND_ENV} (afl-fuzz in FRIDA mode), or ${FUZZING_JACKALOPE_DIR_ENV} (Jackalope/TinyInst build directory). REA does not build, download, or install an engine. See docs/fuzzing-campaigns.md.`;

/** Retained stdout, and separately stderr, from one engine or reproduction. */
export const FUZZING_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/** Retained tail of one engine failure message. */
export const FUZZING_DIAGNOSTIC_EXCERPT_BYTES = 512;

/** Wall clock between two observations of the engine's stat stream. */
export const FUZZING_STATS_INTERVAL_MS = 500;

/** Samples one campaign retains; older ones compact into a wider stride. */
export const FUZZING_MAX_STATS_SAMPLES = 240;

/** Crash artifacts one campaign inspects; later files are counted only. */
export const FUZZING_MAX_CRASH_ARTIFACTS = 64;

/** Accepted or rejected rows one campaign reports inline. */
export const FUZZING_MAX_CRASH_ROWS = 64;

/** Reproductions per candidate crash when the caller omits `pov_repeats`. */
export const FUZZING_DEFAULT_POV_REPEATS = 2;

/** Widest repetition count a caller may request for POV validation. */
export const FUZZING_MAX_POV_REPEATS = 3;

/** One reproduction run's deadline. */
export const FUZZING_POV_TIMEOUT_MS = 60_000;

/** How long a stopped engine may take to exit before it is killed. */
export const FUZZING_STOP_GRACE_MS = 5_000;

/** Campaign workspaces one REA server retains for its lifetime. */
export const FUZZING_MAX_RETAINED_CAMPAIGNS = 8;

/** Arguments of one engine command line that reach Evidence. */
export const FUZZING_MAX_REPORTED_ARGUMENTS = 32;

/** Campaigns one REA server runs at once; each engine owns every host core. */
export const FUZZING_MAX_ACTIVE_CAMPAIGNS = 1;

/** Wall-clock cap one campaign enforces when the runtime setting is unset. */
export const FUZZING_DEFAULT_MAX_CAMPAIGN_SECONDS = 900;

/** Guest directory prefix the Linux route writes under the VM workspace. */
export const FUZZING_LAB_VM_DIRECTORY = "rea-fuzzing";

/** Output file the guest route redirects the engine's streams into. */
export const FUZZING_LAB_VM_ENGINE_LOG = "engine.log";

/** Output file one guest reproduction redirects its sanitizer report into. */
export const FUZZING_LAB_VM_REPORT_FILE = "report.log";

/** Why one campaign stopped; every reason names an observed bound. */
export const FUZZING_STOP_REASONS = [
  "budget_seconds",
  "budget_runs",
  "budget_crashes",
  "runtime_cap_seconds",
  "engine_exit",
  "cancelled",
  "output_truncated",
  "engine_failure",
] as const;

export const fuzzingStopReasonSchema = z.enum(FUZZING_STOP_REASONS);
export type FuzzingStopReason = z.infer<typeof fuzzingStopReasonSchema>;

/** Terminal outcome of one campaign run. */
export const FUZZING_CAMPAIGN_STATUSES = [
  "finished",
  "stopped",
  "failed",
] as const;

export const fuzzingCampaignOutcomeSchema = z.enum(FUZZING_CAMPAIGN_STATUSES);
export type FuzzingCampaignOutcome = z.infer<
  typeof fuzzingCampaignOutcomeSchema
>;

/** How a campaign reached an engine: on this host or through a lab VM. */
export const FUZZING_ROUTES = ["host", "lab_vm"] as const;

export const fuzzingRouteSchema = z.enum(FUZZING_ROUTES);
export type FuzzingRoute = z.infer<typeof fuzzingRouteSchema>;
