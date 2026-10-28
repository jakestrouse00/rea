import {
  decompilePythonBytecodeInputSchema,
  decompilePythonBytecodeResultSchema,
} from "../../domain/pysrc/pythonSourceRecovery.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * Python source recovery over a caller-supplied PyLingual or pycdc binary.
 *
 * Recovered source text stays out of Evidence; declarations, line ranges, and
 * import module names are reported.
 */
export const PYTHON_DECOMPILER_TOOL_CONTRACTS = [
  {
    name: "decompile_python_bytecode",
    ...toolContractMetadata("decompile_python_bytecode"),
    description:
      "Recover Python source shape from one explicit local .pyc or bytecode archive through a caller-supplied PyLingual or pycdc binary. Returns each function's name, qualified name, line range, and parameter count, plus class names, import module names, and the artifact SHA-256. Recovered source text stays out of Evidence. PyLingual wins when both settings are present; select the tool with an absolute REA_PYLINGUAL_COMMAND or REA_PYCDC_COMMAND. REA never installs a decompiler and never invokes CPython on the artifact. Decompiler output is not guaranteed to be valid or faithful source.",
    kind: "python-decompiler-provider",
    inputSchema: decompilePythonBytecodeInputSchema,
    outputSchema: evidenceResultOf(decompilePythonBytecodeResultSchema),
    examples: [
      {
        title: "List declarations recovered from a .pyc file",
        input: { path: "/artifacts/module.pyc" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
