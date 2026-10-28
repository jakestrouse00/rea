import { z } from "zod";

import { ANGR_PROTOCOL_VERSION } from "./angrLimits.js";

/** Job kinds one sidecar process accepts. */
export const ANGR_JOB_KINDS = [
  "find_paths",
  "explore_function",
  "recover_cfg",
] as const;

export type AngrJobKind = (typeof ANGR_JOB_KINDS)[number];

/**
 * One answer frame on the bridge's stdout. A refusal carries a bounded
 * machine code plus text REA never treats as caller input.
 */
export const angrBridgeResponseSchema = z.strictObject({
  protocol: z.literal(ANGR_PROTOCOL_VERSION),
  job_id: z.string().uuid(),
  kind: z.enum(ANGR_JOB_KINDS),
  ok: z.boolean(),
  result: z.unknown().optional(),
  error: z
    .strictObject({
      code: z.string().regex(/^[a-z0-9_]{1,64}$/u),
      message: z.string().max(4_096),
    })
    .optional(),
});

export type AngrBridgeResponse = z.infer<typeof angrBridgeResponseSchema>;
