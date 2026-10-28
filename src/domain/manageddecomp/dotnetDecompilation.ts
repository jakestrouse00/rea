import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Maximum types one result may publish. */
export const MAX_DOTNET_TYPES = 2_000;

/** Maximum members one result may publish. */
export const MAX_DOTNET_MEMBERS = 20_000;

const coverageSchema = z.enum(["complete", "partial"]);

/**
 * Caller intent for .NET assembly decompilation over a caller-supplied
 * ilspycmd binary. Decompiled C# text stays out of Evidence: only type and
 * member structure is reported.
 */
export const decompileDotnetAssemblyInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a local .NET assembly or executable",
  ),
  max_types: z
    .int()
    .min(1)
    .max(MAX_DOTNET_TYPES)
    .default(500)
    .describe("Upper bound on reported types"),
});

export type DecompileDotnetAssemblyInput = z.input<
  typeof decompileDotnetAssemblyInputSchema
>;

export const dotnetDecompilerClientSchema = z.strictObject({
  command: z.string().min(1),
  version: z.string().min(1).nullable(),
});

/** Closed set of C# declaration kinds this lane recognizes. */
export const DOTNET_TYPE_KINDS = [
  "class",
  "struct",
  "interface",
  "enum",
  "record",
  "delegate",
] as const;

export const DOTNET_MEMBER_KINDS = [
  "constructor",
  "method",
  "property",
  "field",
  "event",
  "operator",
  "unknown",
] as const;

const dotnetMemberSchema = z.strictObject({
  kind: z.enum(DOTNET_MEMBER_KINDS),
  name: z.string().min(1),
  signature: z.string().min(1),
});

const dotnetTypeSchema = z.strictObject({
  namespace: z.string().min(1).nullable(),
  name: z.string().min(1),
  kind: z.enum(DOTNET_TYPE_KINDS),
  base_type: z.string().min(1).nullable(),
  members: z.array(dotnetMemberSchema),
});

/** Structural .NET member inventory returned by the adapter. */
export const decompileDotnetAssemblyResultSchema = z.strictObject({
  client: dotnetDecompilerClientSchema,
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.int().nonnegative(),
  assembly_name: z.string().min(1).nullable(),
  types: z.array(dotnetTypeSchema),
  type_count: z.int().nonnegative(),
  member_count: z.int().nonnegative(),
  unparsed_lines: z.int().nonnegative(),
  truncated: z.boolean(),
  coverage: coverageSchema,
});

export type DecompileDotnetAssemblyResult = z.infer<
  typeof decompileDotnetAssemblyResultSchema
>;

/** One validated .NET decompilation request. */
export const dotnetDecompilerRequestSchema = z.strictObject({
  operation: z.literal("decompile_dotnet_assembly"),
  input: decompileDotnetAssemblyInputSchema,
});

export type DotnetDecompilerRequest = z.input<
  typeof dotnetDecompilerRequestSchema
>;
