import { z } from "zod";

import { EMU_PROTOCOL_VERSION } from "./emuLimits.js";

/** Job kinds one sidecar process accepts. */
export const EMU_JOB_KINDS = ["emulate", "assemble"] as const;

/**
 * One answer frame on the bridge's stdout. A refusal carries a bounded
 * machine code plus text REA never treats as caller input.
 */
export const emuBridgeResponseSchema = z.strictObject({
  protocol: z.literal(EMU_PROTOCOL_VERSION),
  job_id: z.string().uuid(),
  kind: z.enum(EMU_JOB_KINDS),
  ok: z.boolean(),
  result: z.unknown().optional(),
  error: z
    .strictObject({
      code: z.string().regex(/^[a-z0-9_]{1,64}$/u),
      message: z.string().max(4_096),
    })
    .optional(),
});

export type EmuBridgeResponse = z.infer<typeof emuBridgeResponseSchema>;
