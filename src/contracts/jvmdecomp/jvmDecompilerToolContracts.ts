import {
  decompileJarArchiveInputSchema,
  decompileJarClassInputSchema,
  jvmDecompilationResultSchema,
} from "../../domain/jvmdecomp/jvmDecompilation.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * JVM class decompilation over a caller-supplied Vineflower JAR and JDK.
 *
 * Recovered Java source stays out of Evidence; class and member declaration
 * structure is reported.
 */
export const JVM_DECOMPILER_TOOL_CONTRACTS = [
  {
    name: "decompile_jar_class",
    ...toolContractMetadata("decompile_jar_class"),
    description:
      "Decompile one selected class from an explicit local JAR or class container through a caller-supplied Vineflower JAR and JDK 11 or newer. Returns the class's binary name, package, kind, and bounded member signatures, plus the container SHA-256 and Java version. Recovered Java source stays out of Evidence. Select the JAR with an absolute REA_VINEFLOWER_JAR and the runtime with JAVA_HOME or PATH; REA never downloads Vineflower or Java and never runs the decompiled classes. Output is not guaranteed to be valid or faithful source.",
    kind: "jvm-decompiler-provider",
    inputSchema: decompileJarClassInputSchema,
    outputSchema: evidenceResultOf(jvmDecompilationResultSchema),
    examples: [
      {
        title: "Decompile one class from a JAR",
        input: { path: "/artifacts/app.jar", class_name: "com.example.Main" },
      },
    ],
  },
  {
    name: "decompile_jar_archive",
    ...toolContractMetadata("decompile_jar_archive"),
    description:
      "Decompile every class in an explicit local JAR, WAR, or class directory through a caller-supplied Vineflower JAR and JDK 11 or newer, then report each class's binary name, package, kind, and bounded member signatures. Recovered Java source stays out of Evidence. Select the JAR with an absolute REA_VINEFLOWER_JAR and the runtime with JAVA_HOME or PATH; REA never downloads Vineflower or Java and never runs the decompiled classes. Output is bounded by max_classes and a recovered-source byte budget, and is not guaranteed to be valid or faithful source.",
    kind: "jvm-decompiler-provider",
    inputSchema: decompileJarArchiveInputSchema,
    outputSchema: evidenceResultOf(jvmDecompilationResultSchema),
    examples: [
      {
        title: "List declarations across a JAR",
        input: { path: "/artifacts/app.jar", max_classes: 50 },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
