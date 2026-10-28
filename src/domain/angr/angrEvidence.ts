import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";
import {
  ANGR_LIMITS,
  ANGR_OPERATION_TIMEOUT_ENV,
  ANGR_OPERATION_TIMEOUT_SETTING,
  ANGR_PROTOCOL_VERSION,
} from "./angrLimits.js";

const hexAddressSchema = z.string().regex(/^0x[0-9a-f]{1,16}$/u);
const hexValueSchema = z
  .string()
  .regex(/^0x[0-9a-f]{1,32}$/u)
  .describe("Unsigned hexadecimal value, including the 0x prefix");
const digestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const registerNameSchema = z.string().regex(/^[a-z][a-z0-9]{1,15}$/u);
/** REA-owned operand name the bridge assigns; never text read from the target. */
const operandNameSchema = z.string().regex(/^[a-z][a-z0-9_.]{0,63}$/u);
const operatorNameSchema = z.string().regex(/^[a-z0-9_]{1,32}$/u);

/** One caller-declared constraint on a symbolic input of the job. */
export const angrAssertionSchema = z.strictObject({
  operand: z.discriminatedUnion("kind", [
    z.strictObject({
      kind: z.literal("register"),
      name: registerNameSchema.describe(
        "Register named as symbolic input by this request",
      ),
    }),
    z.strictObject({
      kind: z.literal("stdin"),
      offset: z
        .int()
        .min(0)
        .max(ANGR_LIMITS.maxStdinBytes - 1)
        .describe("Byte offset inside the symbolic stdin window"),
      width_bytes: z.int().min(1).max(16),
    }),
  ]),
  relation: z.enum(["eq", "ne", "lt", "le", "gt", "ge"]),
  value: hexValueSchema,
});

const angrJobTargetFields = {
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to the local artifact angr loads and analyses",
  ),
  entry: hexAddressSchema.describe(
    "Entry address of the function or block the job starts from",
  ),
  stdin_bytes: z
    .int()
    .min(0)
    .max(ANGR_LIMITS.maxStdinBytes)
    .default(0)
    .describe("Bytes of standard input modelled as symbolic, zero for none"),
  symbolic_registers: z
    .array(registerNameSchema)
    .max(8)
    .default([])
    .describe("Entry registers whose values are symbolic inputs of the job"),
};

const angrBudgetFields = {
  max_states: z
    .int()
    .min(1)
    .max(ANGR_LIMITS.maxStates)
    .default(ANGR_LIMITS.defaultMaxStates)
    .describe("Upper bound on states the job keeps alive at once"),
  max_steps: z
    .int()
    .min(1)
    .max(ANGR_LIMITS.maxSteps)
    .default(ANGR_LIMITS.defaultSteps)
    .describe("Upper bound on explored instruction steps"),
  timeout_ms: z
    .int()
    .min(1)
    .max(ANGR_LIMITS.maxTimeoutMs)
    .optional()
    .describe(
      `Upper bound on the job's wall time; omitted means ${ANGR_OPERATION_TIMEOUT_SETTING} or ${ANGR_OPERATION_TIMEOUT_ENV}`,
    ),
};

const findAddressesSchema = z
  .array(hexAddressSchema)
  .min(1)
  .max(ANGR_LIMITS.maxFindAddresses)
  .describe("Addresses whose arrival counts as reaching the target");

const avoidAddressesSchema = z
  .array(hexAddressSchema)
  .max(ANGR_LIMITS.maxAvoidAddresses)
  .default([])
  .describe("Addresses that end a path without it reaching the target");

/** Caller intent for one constraint-solving run to a target address. */
export const findPathsToTargetInputSchema = z.strictObject({
  ...angrJobTargetFields,
  assertions: z
    .array(angrAssertionSchema)
    .max(ANGR_LIMITS.maxAssertions)
    .default([])
    .describe(
      "Constraints the caller asserts over the job's symbolic inputs before exploration",
    ),
  find_addresses: findAddressesSchema,
  avoid_addresses: avoidAddressesSchema,
  max_paths: z
    .int()
    .min(1)
    .max(ANGR_LIMITS.maxPaths)
    .default(ANGR_LIMITS.defaultMaxPaths)
    .describe("Upper bound on satisfying paths retained"),
  ...angrBudgetFields,
});

/** Caller intent for one bounded symbolic exploration of a function. */
export const runSymbolicFunctionExplorationInputSchema = z.strictObject({
  ...angrJobTargetFields,
  find_addresses: findAddressesSchema,
  avoid_addresses: avoidAddressesSchema,
  ...angrBudgetFields,
});

/** Caller intent for one control-flow recovery pass over a whole artifact. */
export const recoverControlFlowAngrInputSchema = z.strictObject({
  path: angrJobTargetFields.path,
  max_functions: z
    .int()
    .min(1)
    .max(ANGR_LIMITS.maxFunctions)
    .default(ANGR_LIMITS.maxFunctions)
    .describe("Upper bound on recovered functions retained"),
  max_blocks: z
    .int()
    .min(1)
    .max(ANGR_LIMITS.maxBlocks)
    .default(ANGR_LIMITS.maxBlocks)
    .describe("Upper bound on recovered basic blocks retained"),
  timeout_ms: angrBudgetFields.timeout_ms,
});

export const angrBridgeIdentitySchema = z.strictObject({
  protocol: z.literal(ANGR_PROTOCOL_VERSION),
  angr_version: z.string().min(1).nullable(),
});

/** Why a bounded job stopped exploring. */
export const ANGR_TERMINATIONS = [
  "find_hit",
  "avoid_hit",
  "deadended",
  "state_bound",
  "step_bound",
  "deadline",
  "no_viable_state",
  "unsupported",
] as const;

/** What one entry of a path condition is, without its value. */
export const ANGR_CONDITION_KINDS = [
  "operation",
  "symbol",
  "constant",
  "unknown",
] as const;

/**
 * One node of a path condition, structurally. A constant carries the SHA-256
 * of its value instead of the value, so a condition that constrains bytes
 * recovered from the target cannot be read back out of Evidence.
 */
export const angrPathConditionSchema = z.strictObject({
  index: z.int().min(0),
  depth: z.int().min(0),
  kind: z.enum(ANGR_CONDITION_KINDS),
  op: operatorNameSchema,
  bits: z.int().min(0).max(4_096),
  operand: operandNameSchema.nullable(),
  constant_sha256: digestSchema.nullable(),
});

/** One symbolic solution value, reported only as a digest. */
export const angrModelValueSchema = z.strictObject({
  name: operandNameSchema,
  bits: z.int().min(1).max(4_096),
  value_sha256: digestSchema,
});

/** One satisfying or explored path: its shape, its conditions, no values. */
export const angrPathSchema = z.strictObject({
  path_id: z.int().min(0),
  found: z.boolean(),
  steps: z.int().min(0),
  block_count: z.int().min(0),
  address: hexAddressSchema.nullable(),
  conditions: z.array(angrPathConditionSchema),
  conditions_truncated: z.boolean(),
  model: z.array(angrModelValueSchema),
  model_truncated: z.boolean(),
});

/** The artifact REA selected, identified by its own digest. */
export const angrTargetFactsSchema = z.strictObject({
  path: z.string().min(1),
  entry: hexAddressSchema.nullable(),
  sha256: digestSchema,
});

/** Structural result of one constraint-solving run to a target address. */
export const findPathsToTargetResultSchema = z.strictObject({
  bridge: angrBridgeIdentitySchema,
  target: angrTargetFactsSchema,
  reachable: z.boolean(),
  termination: z.enum(ANGR_TERMINATIONS),
  assertion_count: z.int().min(0),
  find_address_count: z.int().min(0),
  avoid_address_count: z.int().min(0),
  paths: z.array(angrPathSchema),
  paths_truncated: z.boolean(),
  explored_states: z.int().min(0),
  coverage: z.enum(["complete", "partial"]),
  values_redacted: z.literal(true),
});

export type FindPathsToTargetResult = z.infer<
  typeof findPathsToTargetResultSchema
>;

/** Structural result of one bounded symbolic exploration. */
export const runSymbolicFunctionExplorationResultSchema = z.strictObject({
  bridge: angrBridgeIdentitySchema,
  target: angrTargetFactsSchema,
  termination: z.enum(ANGR_TERMINATIONS),
  explored_states: z.int().min(0),
  active_states: z.int().min(0),
  deadended_states: z.int().min(0),
  found_states: z.int().min(0),
  avoided_states: z.int().min(0),
  errored_states: z.int().min(0),
  find_address_count: z.int().min(0),
  avoid_address_count: z.int().min(0),
  visited_blocks: z.array(hexAddressSchema),
  visited_blocks_truncated: z.boolean(),
  found: z.array(angrPathSchema),
  coverage: z.enum(["complete", "partial"]),
  values_redacted: z.literal(true),
});

export type RunSymbolicFunctionExplorationResult = z.infer<
  typeof runSymbolicFunctionExplorationResultSchema
>;

const angrFunctionSchema = z.strictObject({
  address: hexAddressSchema,
  block_count: z.int().min(0),
});

const angrBlockSchema = z.strictObject({
  address: hexAddressSchema,
  size: z.int().min(1),
  successors: z.array(hexAddressSchema),
});

/** Structural result of one control-flow recovery pass. */
export const recoverControlFlowAngrResultSchema = z.strictObject({
  bridge: angrBridgeIdentitySchema,
  target: angrTargetFactsSchema,
  function_count: z.int().min(0),
  functions: z.array(angrFunctionSchema),
  functions_truncated: z.boolean(),
  block_count: z.int().min(0),
  blocks: z.array(angrBlockSchema),
  blocks_truncated: z.boolean(),
  edge_count: z.int().min(0),
  coverage: z.enum(["complete", "partial"]),
});

export type RecoverControlFlowAngrResult = z.infer<
  typeof recoverControlFlowAngrResultSchema
>;

/** One validated symbolic-lane request. */
export const angrRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("find_paths_to_target"),
    input: findPathsToTargetInputSchema,
  }),
  z.strictObject({
    operation: z.literal("run_symbolic_function_exploration"),
    input: runSymbolicFunctionExplorationInputSchema,
  }),
  z.strictObject({
    operation: z.literal("recover_control_flow_angr"),
    input: recoverControlFlowAngrInputSchema,
  }),
]);

export type AngrRequest = z.output<typeof angrRequestSchema>;
export type AngrRequestInput = z.input<typeof angrRequestSchema>;
