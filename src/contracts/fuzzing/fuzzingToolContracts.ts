import { fuzzingCampaignObservationSchema } from "../../domain/fuzzing/fuzzingCampaignObservation.js";
import { startFuzzingCampaignInputSchema } from "../../domain/fuzzing/fuzzingCampaignInputs.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

const campaignIdExample = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

/**
 * The fuzz loop over one registered crash-triage campaign.
 *
 * A launch consumes the campaign's own target, seeds, and declared budget,
 * drives exactly one caller-selected engine, reports the counters it observed,
 * and hands only POV-validated crashes to crash triage. No engine, target, or
 * corpus is acquired by REA.
 */
export const FUZZING_TOOL_CONTRACTS = [
  {
    name: "start_fuzzing_campaign",
    ...toolContractMetadata("start_fuzzing_campaign"),
    description:
      "Run one registered campaign through one caller-selected engine: libFuzzer (REA_LFZ_FUZZER_COMMAND), afl-fuzz in FRIDA mode (REA_AFLFRIDA_FUZZER_COMMAND), or a caller-built Jackalope/TinyInst tree (REA_JACKALOPE_DIR). REA copies the campaign's seeds into a private corpus, launches the engine under a deny-default seatbelt profile on macOS (or inside an existing lab VM when lab_vm_session_id is given), stops it when the declared max_runs, max_seconds, or max_crashes budget is reached, and reports the observed execs/sec, coverage, and corpus counters as Evidence samples. A campaign's wall clock is also capped by the `fuzzing.max_campaign_seconds` runtime setting, and the reported budget says which bound applied. Every crash artifact is reproduced pov_repeats times; only candidates whose reproductions agree on the crash-state hash and name an accepted sanitizer class are recorded into the campaign, where list_crash_dedups groups them and fetch_crash_evidence reports their facts. Report bodies and engine output never enter the result; the engine stderr tail is bounded and marked untrusted. The engine itself is never installed, built, or downloaded, and no target bytes are modified.",
    kind: "fuzzing-provider",
    inputSchema: startFuzzingCampaignInputSchema,
    outputSchema: evidenceResultOf(fuzzingCampaignObservationSchema),
    examples: [
      {
        title: "Fuzz a registered campaign with the libFuzzer adapter",
        input: {
          campaign_id: campaignIdExample,
          engine: "libfuzzer",
          pov_repeats: 2,
        },
      },
      {
        title: "Accept and minimize crashes from AFL++ FRIDA",
        input: {
          campaign_id: campaignIdExample,
          engine: "aflpp_frida",
          expected_sanitizer: "address",
          minimize_crashes: true,
        },
      },
      {
        title: "Run the libFuzzer adapter inside a started lab VM",
        input: {
          campaign_id: campaignIdExample,
          engine: "libfuzzer",
          lab_vm_session_id: "2f1c9d4e-0b6a-4c8f-9e37-5a1f0d2b7c33",
          lab_vm_workspace_path: "/artifacts/linux-fuzz-build",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
