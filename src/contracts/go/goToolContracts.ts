import {
  goBinarySchema,
  goProcedureTableSchema,
  inspectGoBinaryInputSchema,
  inspectGoProcedureTableInputSchema,
} from "../../domain/go/goBinary.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static Go metadata is independent of active native-analysis providers and host toolchains. */
export const GO_TOOL_CONTRACTS = [
  {
    name: "inspect_go_binary",
    ...toolContractMetadata("inspect_go_binary"),
    kind: "artifact-provider",
    description:
      "Inspect embedded Go compiler version, main module, dependency/replacement versions and build settings in an explicit local ELF, PE or thin Mach-O image. Returns original artifact SHA-256, exact build-info source ranges, raw framed module bytes and unparsed module-text lines inline as observed Evidence. Supports inline and historical pointer encodings without installing Go, opening a disassembler, executing the target, writing temporary files or accessing the network. Missing metadata is reported as unknown, not proof that an image is not Go. Embedded procedure names are recovered by the separate inspect_go_procedure_table reader; this tool does not recover source mappings, types or runtime behavior. Resource guards bound files to 256 MiB, aggregate embedded strings to 1 MiB, structural table decoding to 16 MiB and complete inline metadata to 8 MiB; malformed, unsupported and oversized inputs receive typed failures rather than partial success.",
    inputSchema: inspectGoBinaryInputSchema,
    outputSchema: evidenceResultOf(goBinarySchema),
    examples: [
      {
        title: "Inspect embedded build provenance",
        input: { path: "/artifacts/application" },
      },
    ],
  },
  {
    name: "inspect_go_procedure_table",
    ...toolContractMetadata("inspect_go_procedure_table"),
    kind: "artifact-provider",
    description:
      "Page the embedded Go pclntab procedure table of an explicit local ELF, PE or thin Mach-O image: function-name-table row names, entry and exclusive ends (next-entry or table-sentinel derived), and per-table header facts (magic, runtime era, textStart or moduledata-recovered text base, nfunc) inline as observed Evidence. Locates the table through a declared gopclntab section first, otherwise searches bounded read-only data spans; recognizes go1.16-1.17, go1.18-1.19 and go1.20+ layouts and reports go1.2-1.15 as recognized but undecoded. Returns offset/limit pages (default 50 rows, maximum 500; next_offset is null when the page exhausts the total). Missing or unresolved values are reported as null, not inference; source files and line mappings follow filetab/pcvalue records and are not decoded. Reads without installing Go, executing the target, writing temporary files or accessing the network. Resource guards bound files and discovery searches to 256 MiB each, structural table decoding to 16 MiB and complete pages to 500 rows. Malformed, unsupported and oversized inputs receive typed failures rather than partial success.",
    inputSchema: inspectGoProcedureTableInputSchema,
    outputSchema: evidenceResultOf(goProcedureTableSchema),
    examples: [
      {
        title: "Page the first Go procedure names",
        input: { path: "/artifacts/application", offset: 0, limit: 50 },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
