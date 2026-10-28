import { z } from "zod";

import { campaignIdInputShape } from "../crashTriage/crashTriageInputs.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  FUZZING_DEFAULT_POV_REPEATS,
  FUZZING_MAX_POV_REPEATS,
  fuzzingEngineSchema,
} from "./fuzzingEngine.js";
import { expectedSanitizerField } from "./povValidation.js";

/** One campaign launch against a registered crash-triage campaign. */
export const startFuzzingCampaignInputSchema = z.strictObject({
  ...campaignIdInputShape,
  engine: fuzzingEngineSchema.describe(
    "Engine adapter to drive: libfuzzer (a caller-supplied libFuzzer target), aflpp_frida (afl-fuzz in FRIDA mode), or jackalope (a caller-built Jackalope/TinyInst tree). Each adapter selects its own absolute command from the launch environment and documents its argv.",
  ),
  pov_repeats: z
    .int()
    .min(1)
    .max(FUZZING_MAX_POV_REPEATS)
    .optional()
    .describe(
      `Reproductions per candidate crash before its report is accepted as a POV; ${String(FUZZING_DEFAULT_POV_REPEATS)} when omitted, at most ${String(FUZZING_MAX_POV_REPEATS)}. Every repetition must agree on the crash-state hash.`,
    ),
  expected_sanitizer: expectedSanitizerField,
  minimize_crashes: z
    .boolean()
    .optional()
    .describe(
      "When true, each accepted crash is also minimized through the crash-triage minimizer seam (libFuzzer `-minimize_crash=1` for the libFuzzer adapter, afl-tmin for AFL++, unsupported for Jackalope). Default false.",
    ),
  lab_vm_session_id: z
    .string()
    .uuid()
    .optional()
    .describe(
      "Run the engine inside an already-started lab VM (`start_lab_vm`). Omit to run on this host.",
    ),
  lab_vm_workspace_path: absoluteLocalPathStringSchema
    .optional()
    .describe(
      "Host directory that lab VM mounts at /workspace, as `start_lab_vm` reported it. Required with lab_vm_session_id; the campaign writes under rea-fuzzing/<campaign_id>/ there.",
    ),
});
