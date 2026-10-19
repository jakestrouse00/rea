import { z } from "zod";

import { inspectGodotPckInputSchema } from "./godotPck.js";
import { inspectVpkArchiveInputSchema } from "./vpkArchive.js";
import { inspectGamemakerDataInputSchema } from "./gamemakerData.js";
import { inspectRpaArchiveInputSchema } from "./rpaArchive.js";
import { inspectRpgmakerAssetPrefixesInputSchema } from "./rpgmakerAssets.js";

/** The five public game-data operations and their exact inputs. */
export const gamedataOperationNames = [
  "inspect_godot_pck",
  "inspect_vpk_archive",
  "inspect_gamemaker_data",
  "inspect_rpa_archive",
  "inspect_rpgmaker_asset_prefixes",
] as const;

export type GamedataOperation = (typeof gamedataOperationNames)[number];

/** One caller-selected game-data request. */
export const gamedataRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("inspect_godot_pck"),
    input: inspectGodotPckInputSchema,
  }),
  z.strictObject({
    operation: z.literal("inspect_vpk_archive"),
    input: inspectVpkArchiveInputSchema,
  }),
  z.strictObject({
    operation: z.literal("inspect_gamemaker_data"),
    input: inspectGamemakerDataInputSchema,
  }),
  z.strictObject({
    operation: z.literal("inspect_rpa_archive"),
    input: inspectRpaArchiveInputSchema,
  }),
  z.strictObject({
    operation: z.literal("inspect_rpgmaker_asset_prefixes"),
    input: inspectRpgmakerAssetPrefixesInputSchema,
  }),
]);
export type GamedataRequest = z.infer<typeof gamedataRequestSchema>;

/** Per-operation input schemas, keyed for the shared service admission. */
export const gamedataInputSchemas: Readonly<
  Record<GamedataOperation, z.ZodType>
> = {
  inspect_godot_pck: inspectGodotPckInputSchema,
  inspect_vpk_archive: inspectVpkArchiveInputSchema,
  inspect_gamemaker_data: inspectGamemakerDataInputSchema,
  inspect_rpa_archive: inspectRpaArchiveInputSchema,
  inspect_rpgmaker_asset_prefixes: inspectRpgmakerAssetPrefixesInputSchema,
};
