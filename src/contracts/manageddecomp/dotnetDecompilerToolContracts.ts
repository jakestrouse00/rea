import {
  decompileDotnetAssemblyInputSchema,
  decompileDotnetAssemblyResultSchema,
} from "../../domain/manageddecomp/dotnetDecompilation.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * .NET decompilation over a caller-supplied ilspycmd binary.
 *
 * Only type and member declaration structure reaches Evidence; decompiled C#
 * text never does.
 */
export const DOTNET_DECOMPILER_TOOL_CONTRACTS = [
  {
    name: "decompile_dotnet_assembly",
    ...toolContractMetadata("decompile_dotnet_assembly"),
    description:
      "Decompile one explicit local .NET assembly through a caller-supplied ilspycmd binary and report only its declaration structure: namespaces, type kinds, base types, and bounded member signatures. Decompiled C# text stays out of Evidence. The artifact is digested before the read. Select the tool with the existing absolute REA_ILSPY_CMD_PATH setting; REA never installs or updates ilspycmd and never runs the assembly. Declaration scanning is shallow, so nested scopes and generated members can be under-reported; unrecognized lines are counted and the result is marked partial.",
    kind: "managed-decompiler-provider",
    inputSchema: decompileDotnetAssemblyInputSchema,
    outputSchema: evidenceResultOf(decompileDotnetAssemblyResultSchema),
    examples: [
      {
        title: "List an assembly's types and member signatures",
        input: { path: "/artifacts/App.dll" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
