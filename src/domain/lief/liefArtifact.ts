import { z } from "zod";
import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

/** Selected artifact and the digest that binds every fact below it. */
export const liefArtifactSchema = z.strictObject({
  path: localPathStringSchema,
  sha256: digestSchema,
  bytes: z.number().int().nonnegative(),
});

/** Container kinds the lane classifies; `unknown` is never fabricated as a parse. */
export const liefFormatSchema = z.enum([
  "elf",
  "pe",
  "macho",
  "macho-fat",
  "pdb",
  "unknown",
]);

export type LiefFormat = z.infer<typeof liefFormatSchema>;

/** A CodeView PDB reference recorded in a PE debug directory entry. */
export const pdbReferenceSchema = z.strictObject({
  path: z.string().min(1).nullable(),
  guid: z.string().min(1).nullable(),
  age: z.number().int().nonnegative().nullable(),
  signature_kind: z.string().min(1).nullable(),
});
