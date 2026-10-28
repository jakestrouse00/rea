import { z } from "zod";

import {
  PROTOLEARN_LIMITS,
  PROTOLEARN_PROTOCOL_VERSION,
} from "./protolearnLimits.js";

const errorCodeSchema = z.string().regex(/^[a-z0-9_]{1,64}$/u);

/** One step's outcome, as lengths and bytes the runner actually read. */
export const probeRunnerStepSchema = z.strictObject({
  ordinal: z.int().nonnegative(),
  sent_bytes: z.int().nonnegative(),
  response_bytes: z.int().nonnegative(),
  /** Base64 of at most maxProbeResponseBytes; REA hashes it and drops it. */
  response_base64: z
    .string()
    .max(Math.ceil((PROTOLEARN_LIMITS.maxProbeResponseBytes * 4) / 3) + 4)
    .nullable(),
  truncated: z.boolean(),
  timed_out: z.boolean(),
  error_code: errorCodeSchema.nullable(),
});

export const probeRunnerResultSchema = z.strictObject({
  connected: z.boolean(),
  steps: z
    .array(probeRunnerStepSchema)
    .min(1)
    .max(PROTOLEARN_LIMITS.maxProbeSteps),
  total_response_bytes: z.int().nonnegative(),
});

/** One answer frame from the probe runner. */
export const probeRunnerResponseSchema = z.strictObject({
  protocol: z.literal(PROTOLEARN_PROTOCOL_VERSION),
  job_id: z.string().uuid(),
  ok: z.boolean(),
  result: probeRunnerResultSchema.optional(),
  error: z
    .strictObject({
      code: errorCodeSchema,
      message: z.string().max(4_096),
    })
    .optional(),
});

export type ProbeRunnerResult = z.output<typeof probeRunnerResultSchema>;
export type ProbeRunnerStep = z.output<typeof probeRunnerStepSchema>;
export type ProbeRunnerResponse = z.output<typeof probeRunnerResponseSchema>;
