import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Maximum functions one result may publish. */
export const MAX_PYTHON_FUNCTIONS = 10_000;

/** Maximum imports one result may publish. */
export const MAX_PYTHON_IMPORTS = 2_000;

const coverageSchema = z.enum(["complete", "partial"]);

/**
 * Caller intent for recovering Python source shape from bytecode through a
 * caller-supplied PyLingual or pycdc binary. Recovered source text stays out of
 * Evidence: only declarations, line ranges, and import module names are
 * reported.
 */
export const decompilePythonBytecodeInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a local .pyc file or Python bytecode archive",
  ),
  max_functions: z
    .int()
    .min(1)
    .max(MAX_PYTHON_FUNCTIONS)
    .default(5_000)
    .describe("Upper bound on reported functions"),
});

export type DecompilePythonBytecodeInput = z.input<
  typeof decompilePythonBytecodeInputSchema
>;

export const pythonDecompilerClientSchema = z.strictObject({
  command: z.string().min(1),
  version: z.string().min(1).nullable(),
});

const pythonFunctionSchema = z.strictObject({
  name: z.string().min(1),
  qualified_name: z.string().min(1),
  line_start: z.int().nonnegative(),
  line_end: z.int().nonnegative(),
  parameter_count: z.int().nonnegative(),
});

/** Structural Python source inventory returned by the adapter. */
export const decompilePythonBytecodeResultSchema = z.strictObject({
  client: pythonDecompilerClientSchema,
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.int().nonnegative(),
  python_version: z.string().min(1).nullable(),
  functions: z.array(pythonFunctionSchema),
  classes: z.array(z.string().min(1)),
  imports: z.array(z.string().min(1)),
  function_count: z.int().nonnegative(),
  class_count: z.int().nonnegative(),
  import_count: z.int().nonnegative(),
  unparsed_lines: z.int().nonnegative(),
  truncated: z.boolean(),
  coverage: coverageSchema,
});

export type DecompilePythonBytecodeResult = z.infer<
  typeof decompilePythonBytecodeResultSchema
>;

/** One validated Python decompilation request. */
export const pythonDecompilerRequestSchema = z.strictObject({
  operation: z.literal("decompile_python_bytecode"),
  input: decompilePythonBytecodeInputSchema,
});

export type PythonDecompilerRequest = z.input<
  typeof pythonDecompilerRequestSchema
>;
