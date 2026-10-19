import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import { nativeAotArtifactInspectionSchema } from "../../domain/managed/nativeAotArtifact.js";
import { inspectNativeAotTypesInputSchema } from "../../domain/managed/nativeAotArtifact.js";

/**
 * Local audited effects for inspect_nativeaot_types.
 *
 * `toolEffects.ts` owns the authoritative TOOL_EFFECTS audit; the canonical
 * entry `inspect_nativeaot_types: evidence` is used through
 * `toolContractMetadata`.
 */
const inputSchema = inspectNativeAotTypesInputSchema;
const outputSchema = evidenceResultOf(nativeAotArtifactInspectionSchema);

/** Read-only NativeAOT structural inspection contract. */
export const NATIVE_AOT_TOOL_CONTRACTS = [
  {
    name: "inspect_nativeaot_types",
    description:
      "Inspect one PE artifact for .NET NativeAOT / ReadyToRun structural metadata without loading or executing target code. Recovery follows the publicly documented subset: the RTR ReadyToRun directory header and section table (dotnet/runtime ModuleHeaders.cs and readytorun.h) with its detected-version hint, PE .managed/__managed__ sections, the DotNetRuntimeDebugHeader export, MethodTable-shaped structures validated by the documented MethodTable.h field set, and frozen String objects in the documented FrozenStringNode layout (MethodTable reference, int32 length, UTF-16 characters, NUL terminator). Rows are page-sliced with offset and limit and carry exact artifact-relative file offsets plus virtual addresses where a PE mapping exists. Original managed type names, dehydrated-data (runtime-hydrated metadata), native-layout blobs, and ELF/Mach-O images are explicit unknowns reported through limitation strings; multiple validated directories are reported as ambiguous rather than guessed. Detection observes absence separately from uncertainty.",
    kind: "managed-provider",
    inputSchema,
    outputSchema,
    ...toolContractMetadata("inspect_nativeaot_types"),
    examples: [
      {
        title: "Inspect NativeAOT structures with the default page",
        input: { path: "/tmp/App.exe" },
      },
      {
        title: "Read the second page of recovered rows",
        input: { path: "/tmp/App.exe", offset: 200, limit: 200 },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
