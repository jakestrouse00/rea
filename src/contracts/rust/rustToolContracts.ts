import {
  rustBinarySchema,
  inspectRustSymbolsInputSchema,
  rustSymbolsReportSchema,
} from "../../domain/rust/rustBinary.js";
import { inspectRustBinaryRequestSchema } from "../../domain/rust/rustBinaryQuery.js";
import { z } from "zod";
import {
  rustBinarySummaryViewResultSchema,
  rustBinaryPageViewResultSchema,
} from "../../domain/analysisView/analysisView.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static Rust dependency metadata is independent of active native-analysis providers. */
export const RUST_TOOL_CONTRACTS = [
  {
    name: "inspect_rust_binary",
    ...toolContractMetadata("inspect_rust_binary"),
    kind: "artifact-provider",
    requiresActiveTarget: true,
    description:
      "Inspect the cargo-auditable crate dependency list embedded in an explicit local ELF, PE or thin Mach-O image, or the slice of a universal Mach-O named by architecture (read without lipo; artifact stays the universal file, selected_slice records the slice and offsets stay file offsets). Returns the artifact SHA-256, the .dep-v0 section file offset and size, compressed and uncompressed sizes, format version, packages in their original order, the root package index, and dependency edges by index. Omitted or explicit complete detail preserves the full report. Optional detail summary retains that complete Evidence and returns source ranges, counts and parent_evidence_id. Optional view directly selects packages or edges in this call; it cannot be combined with explicit complete detail. Query the same retained facts with inspect_analysis_view kind rust: exact names/versions or package indices, edge from_indices/to_indices, fields and matching-row pagination. Row indices are original and scoped to the parent Evidence; empty filters select none. Default package fields omit dependency vectors; explicitly select dependencies for direct index references. Every matching observed version is retained. No current runtime state is inferred from historical reads. Reads zlib-compressed JSON without installing Rust, opening a disassembler, executing the target, writing temporary files or accessing the network. A missing section is null metadata with a limitation and is not proof that the binary has no dependencies. A rustc commit hash is reported only as an inference when a /rustc/<40-hex>/ path is present in read-only data. Resource guards bound files to 256 MiB, compressed dependency streams to 1 MiB, inflated JSON to the smaller of 8 MiB and 64 times the consumed compressed-stream length, and the complete report to 8 MiB. Malformed, unsupported and oversized inputs receive typed failures rather than partial success.",
    inputSchema: inspectRustBinaryRequestSchema,
    outputSchema: evidenceResultOf(
      z.union([
        rustBinarySchema,
        rustBinarySummaryViewResultSchema,
        rustBinaryPageViewResultSchema,
      ]),
    ),
    examples: [
      {
        title: "Inspect an embedded Rust dependency list",
        input: { path: "/artifacts/application" },
      },
    ],
  },
  {
    name: "inspect_rust_symbols",
    ...toolContractMetadata("inspect_rust_symbols"),
    kind: "artifact-provider",
    description:
      "Inspect paged symbol-table entries of an explicit local ELF or thin Mach-O image with inline Rust name demangling. Reads ELF symtab (preferred) or dynsym, or the Mach-O LC_SYMTAB nlist entries, without installing Rust, opening a disassembler, executing the target, writing temporary files or accessing the network. Each entry keeps the exact mangled name, the detected mangling format (legacy _ZN, v0 _R, or other for names that use no Rust scheme), the demangled path or a per-entry failure reason, the symbol value in hexadecimal, the declared size when the table stores one, the binding class (local, global, weak, unknown), the section index for defined symbols, and a file offset mapped from the symbol value or null when the value is unmapped or ambiguous. Returns the requested page in the table's named-symbol order with offset and limit, plus summary counts over the full table (declared, named, mangled by format, examined completeness) and the returned page (demangled success and failure). Pages are bounded to 500 entries and every table is admitted to 200000 symbols with oversized tables reported incomplete rather than truncated silently. Symbol names are file content and do not authenticate the compiler or prove which source built the binary. PE symbol tables are not read and keep the table null. Malformed tables receive typed failures rather than partial success.",
    inputSchema: inspectRustSymbolsInputSchema,
    outputSchema: evidenceResultOf(rustSymbolsReportSchema),
    examples: [
      {
        title: "Inspect the first page of a Rust symbol table",
        input: { path: "/artifacts/application", offset: 0, limit: 50 },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
