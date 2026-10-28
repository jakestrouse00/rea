import { z } from "zod";

import { digestSchema } from "./digests.js";

/**
 * Named Frida script presets REA ships as its own minimal reference agents.
 * The names are the caller-visible vocabulary; each preset declares the
 * pinning/detection surfaces it addresses so Evidence can report methods
 * without carrying script text.
 */
export const FRIDA_SCRIPT_PRESET_NAMES = [
  "ssl-unpinning",
  "jail-root-detect-bypass",
  "keystore-dump-structure",
] as const;

export type FridaScriptPresetName = (typeof FRIDA_SCRIPT_PRESET_NAMES)[number];

export const fridaScriptPresetNameSchema = z.enum(FRIDA_SCRIPT_PRESET_NAMES);

/** One preset as this release declares it, before its bytes are read. */
export interface FridaScriptPresetDeclaration {
  readonly name: FridaScriptPresetName;
  readonly title: string;
  readonly description: string;
  /** The pinning or detection surfaces the preset addresses. */
  readonly detectedMethods: readonly string[];
  /** File name under `bridge/frida/presets/`; the source of truth. */
  readonly fileName: string;
}

/** A preset whose authored bytes were read at this call. */
export interface FridaScriptPresetSource extends FridaScriptPresetDeclaration {
  readonly source: string;
  readonly bytes: number;
  readonly sha256: string;
}

/** Result rows of load_frida_script_preset: identity and structure only. */
export const loadFridaScriptPresetResultSchema = z.strictObject({
  session_id: z.string().uuid(),
  script_id: z.string().uuid(),
  preset: fridaScriptPresetNameSchema,
  preset_title: z.string().min(1),
  script_sha256: digestSchema,
  script_bytes: z.number().int().positive(),
  detected_methods: z.array(z.string().min(1)),
  message_count: z.number().int().nonnegative(),
  messages_truncated: z.boolean(),
});
