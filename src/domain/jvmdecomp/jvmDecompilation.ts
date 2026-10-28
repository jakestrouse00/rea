import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Maximum classes one result may publish. */
export const MAX_JVM_CLASSES = 5_000;

/** Maximum members one class may publish. */
export const MAX_JVM_MEMBERS = 2_000;

const coverageSchema = z.enum(["complete", "partial"]);

/**
 * Caller intent for JVM class decompilation over a caller-supplied Vineflower
 * JAR. Recovered Java source stays out of Evidence: only declarations are
 * reported.
 */
export const decompileJarClassInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to the JAR or class container",
  ),
  class_name: z
    .string()
    .min(1)
    .max(1_024)
    .regex(
      /^[A-Za-z_$][\w$]*(?:[./][A-Za-z_$][\w$]*)*$/u,
      "Class names use Java package segments separated by . or /",
    )
    .describe(
      "Binary class name, for example com/example/Foo or com.example.Foo",
    ),
  max_members: z
    .int()
    .min(1)
    .max(MAX_JVM_MEMBERS)
    .default(500)
    .describe("Upper bound on reported members per class"),
});

export const decompileJarArchiveInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a local JAR, WAR, or directory of classes",
  ),
  max_classes: z
    .int()
    .min(1)
    .max(MAX_JVM_CLASSES)
    .default(200)
    .describe("Upper bound on reported classes"),
  max_members: z
    .int()
    .min(1)
    .max(MAX_JVM_MEMBERS)
    .default(200)
    .describe("Upper bound on reported members per class"),
});

export type DecompileJarClassInput = z.input<
  typeof decompileJarClassInputSchema
>;
export type DecompileJarArchiveInput = z.input<
  typeof decompileJarArchiveInputSchema
>;

export const jvmDecompilerClientSchema = z.strictObject({
  command: z.string().min(1),
  version: z.string().min(1).nullable(),
});

export const JVM_CLASS_KINDS = [
  "class",
  "interface",
  "enum",
  "record",
  "annotation",
] as const;

export const JVM_MEMBER_KINDS = [
  "constructor",
  "method",
  "field",
  "unknown",
] as const;

const jvmMemberSchema = z.strictObject({
  kind: z.enum(JVM_MEMBER_KINDS),
  name: z.string().min(1),
  signature: z.string().min(1),
});

const jvmClassSchema = z.strictObject({
  binary_name: z.string().min(1),
  package: z.string().min(1).nullable(),
  name: z.string().min(1),
  kind: z.enum(JVM_CLASS_KINDS),
  members: z.array(jvmMemberSchema),
});

/** Structural JVM inventory shared by both tools. */
export const jvmDecompilationResultSchema = z.strictObject({
  client: jvmDecompilerClientSchema,
  java: z.strictObject({
    command: z.string().min(1),
    version: z.string().min(1).nullable(),
  }),
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.int().nonnegative(),
  decompiler_jar: z.string().min(1),
  classes: z.array(jvmClassSchema),
  class_count: z.int().nonnegative(),
  member_count: z.int().nonnegative(),
  unparsed_lines: z.int().nonnegative(),
  truncated: z.boolean(),
  coverage: coverageSchema,
});

export type JvmDecompilationResult = z.infer<
  typeof jvmDecompilationResultSchema
>;

/** One validated JVM decompilation request. */
export const jvmDecompilerRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("decompile_jar_class"),
    input: decompileJarClassInputSchema,
  }),
  z.strictObject({
    operation: z.literal("decompile_jar_archive"),
    input: decompileJarArchiveInputSchema,
  }),
]);

export type JvmDecompilerRequest = z.input<typeof jvmDecompilerRequestSchema>;
