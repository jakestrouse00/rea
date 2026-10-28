import { z } from "zod";

import {
  FRIDA_OWNED_CAPTURE_LIMITS,
  type FridaOwnedCaptureLimit,
} from "./fridaCaptureLimitVocabulary.js";
import { jsonValueSchema } from "./jsonValue.js";

/** REA stops waiting for one remote-export call after this default deadline. */
export const FRIDA_RPC_DEFAULT_TIMEOUT_MS = 5_000;

/** Upper bound on a caller-selected RPC deadline. This release has no override. */
export const FRIDA_RPC_MAX_TIMEOUT_MS = 60_000;

/** Bound positional RPC arguments before target dispatch. */
export const FRIDA_RPC_MAX_ARGUMENTS = 32;

/** Bound one remote-export method name before target dispatch. */
export const FRIDA_RPC_METHOD_MAX_CHARACTERS = 128;

/** One caller-declared remote-export entry reported by the target. */
export const fridaRpcExportSchema = z.strictObject({
  name: z.string(),
  /** Declared function arity, or null when the export is not a function. */
  parameters: z.int().nonnegative().nullable(),
});

/**
 * `unreported` means the target never reported its export map, so the exports
 * are unknown rather than an observed empty surface.
 */
export const fridaRpcInventorySchema = z.strictObject({
  state: z.enum(["observed", "unreported"]),
  exports: z.array(fridaRpcExportSchema),
  exports_truncated: z.boolean(),
});

export const fridaRpcListResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  script_id: z.string().uuid(),
  ...fridaRpcInventorySchema.shape,
});

/** The session's start mode is the only authority an RPC call inherits. */
export const fridaRpcMutationAuthoritySchema = z.strictObject({
  kind: z.literal("session-grant"),
  mode: z.enum(["attach", "spawn"]),
});

export const fridaRpcCallResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  script_id: z.string().uuid(),
  method: z.string(),
  mutation_authority: fridaRpcMutationAuthoritySchema,
  value: jsonValueSchema,
  value_truncated: z.boolean(),
  value_capture_limit: z.enum(FRIDA_OWNED_CAPTURE_LIMITS).nullable(),
  duration_ms: z.int().nonnegative(),
});

export type FridaRpcExport = z.output<typeof fridaRpcExportSchema>;
export type FridaRpcValueCaptureLimit = FridaOwnedCaptureLimit;
