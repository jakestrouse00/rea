import {
  exportBinexportInputSchema,
  exportBinexportResultSchema,
} from "../../domain/bindiff/binaryDiff.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * BinExport protobuf export over a caller-supplied exporter command.
 *
 * The exporter writes one .BinExport file; REA publishes it with a digest and
 * reports only its structural identity.
 */
export const BINDIFF_TOOL_CONTRACTS = [
  {
    name: "export_binexport_protobuf",
    ...toolContractMetadata("export_binexport_protobuf"),
    description:
      "Export one explicit local executable or library to a BinExport protobuf through a caller-supplied exporter command. The exporter writes one .BinExport file into one new output subdirectory with its SHA-256, and the result reports the source digest, size, and published file identity. Select the exporter with an absolute REA_BINEXPORT_COMMAND. REA does not download or build the BinExport Ghidra extension and never calls the exported binary; the documented build recipe is in docs/binary-diffing.md. A file without the BINE magic is a protocol error, not a partial success.",
    kind: "bindiff-provider",
    inputSchema: exportBinexportInputSchema,
    outputSchema: evidenceResultOf(exportBinexportResultSchema),
    examples: [
      {
        title: "Export a binary to BinExport",
        input: {
          path: "/artifacts/libnative.so",
          output_directory: "/tmp/rea-binexport",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
