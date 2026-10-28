import {
  decompileV8BytecodeInputSchema,
  decompileV8BytecodeResultSchema,
} from "../../domain/javascript/v8Bytecode.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * V8 cached-data disassembly over a caller-supplied View8 build.
 *
 * Disassembly text stays out of Evidence; the container header and bounded
 * digest/size facts are reported.
 */
export const V8_BYTECODE_TOOL_CONTRACTS = [
  {
    name: "decompile_v8_bytecode",
    ...toolContractMetadata("decompile_v8_bytecode"),
    description:
      "Disassemble one explicit local V8 cached-data file, such as a bytenode .jsc, through a caller-supplied View8 build that carries its own patched V8 disassembler. Returns the artifact SHA-256, the matched cached-data header layout and its interpreted words (version hash, flag hash, source length or source hash, snapshot checksum or payload checksum, declared and observed payload size), and the disassembly SHA-256, byte count and line count. An artifact whose header matches no pinned layout is reported as layout_unverifiable with uninterpreted leading words rather than mislabeled fields. Disassembly text and recovered source stay out of Evidence, so reproduce them locally with the same launcher. Select the launcher with an absolute REA_VIEW8_COMMAND; REA never builds, downloads, or installs View8, and refuses when the selected launcher is absent or unusable. A matched layout does not prove that this V8 build produced the payload or that the embedded source is recoverable.",
    kind: "v8-decompiler-provider",
    inputSchema: decompileV8BytecodeInputSchema,
    outputSchema: evidenceResultOf(decompileV8BytecodeResultSchema),
    examples: [
      {
        title: "Disassemble one bytenode cached-data file",
        input: { path: "/artifacts/app/main.jsc" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
