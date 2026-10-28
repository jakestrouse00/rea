import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  binaryDeepReportSchema,
  inspectBinaryDeepInputSchema,
} from "../../domain/lief/binaryDeep.js";
import {
  extractPdbDwarfInfoInputSchema,
  pdbDwarfInfoReportSchema,
} from "../../domain/lief/pdbDwarfInfo.js";
import { LIEF_LIMITS } from "../../domain/lief/liefLimits.js";

/**
 * Effects for the LIEF lane are audited in the canonical
 * `toolEffects.ts#TOOL_EFFECTS` registry (`nativeEvidence` for both tools,
 * because each run launches the caller-selected interpreter).
 */

/** LIEF deep-parse contracts; a complement to the owning layout and symbol tools. */
export const LIEF_TOOL_CONTRACTS = [
  {
    name: "inspect_binary_deep",
    ...toolContractMetadata("inspect_binary_deep"),
    kind: "native-provider",
    description:
      "Report the LIEF-unique cross-format structure of one explicit local ELF, PE or Mach-O through a caller-supplied Python interpreter and bridge script (BYO: REA_LIEF_COMMAND must name an absolute interpreter with LIEF >= 0.14 and < 0.17 installed, REA_LIEF_BRIDGE_DIR must hold an unmodified lief_bridge.py from this release). REA runs exactly one bounded bridge request per inspection: it hashes the artifact first, the bridge re-hashes it and refuses a digest mismatch, and one bounded JSON frame returns the artifact bound to its SHA-256. Returns the classified container, section and segment counts, per-architecture CPU, bit width, endianness, entry point, image base and fat-slice file spans, ELF soname, DT_RPATH, DT_RUNPATH, typed dynamic-tag/value rows and a DT_NEEDED count, Mach-O universal flag with dylib and load-command counts, PE machine, subsystem, characteristics, data-directory declarations and debug-directory entries with any CodeView PDB identity, plus the DWARF section inventory. Every fact another lane owns stays there and is named in delegated_facts with its owning tool: section and segment layout, relocations, the program interpreter and DT_NEEDED names (inspect_binary_layout), exports and imports (inspect_native_exports), ELF notes (inspect_elf_notes), Mach-O header, sections, symbol table, UUID, dylib identities and load-command inventory (inspect_macho), PE imports, TLS and load configuration, certificates, and code signatures. This report therefore carries counts, never a second copy of an owned list. A PDB is refused here because extract_pdb_dwarf_info owns its symbol surface. Structure only: no raw bytes, no string dumps, no target content inlined. Fixed bounds cap architectures, dynamic entries, data directories, debug entries and debug sections; exceeding one sets that truncation row and complete stays false, so a truncated report is never presented as complete. Unset or unusable configuration, an unsupported container, an oversized frame and a deadline return typed failures with remediation. The selected LIEF release's interpretation is not re-derived by REA.",
    inputSchema: inspectBinaryDeepInputSchema,
    outputSchema: evidenceResultOf(binaryDeepReportSchema),
    examples: [
      {
        title: "Report an ELF's dynamic surface and debug inventory",
        input: { path: "/artifacts/application.elf" },
      },
      {
        title: "Report a universal Mach-O's slices and dylibs",
        input: {
          path: "/artifacts/Application.app/Contents/MacOS/Application",
        },
      },
    ],
  },
  {
    name: "extract_pdb_dwarf_info",
    ...toolContractMetadata("extract_pdb_dwarf_info"),
    kind: "native-provider",
    description:
      "Report one explicit local artifact's PDB and DWARF debug surfaces and answer bounded lookups through the same caller-supplied LIEF bridge (BYO REA_LIEF_COMMAND and REA_LIEF_BRIDGE_DIR; REA never installs LIEF). Accepts a PDB, ELF, PE or Mach-O. Returns the artifact kind and SHA-256, the DWARF section inventory with compilation-unit and function counts where the reader exposes them, the CodeView PDB path/GUID/age/signature recorded by a PE debug directory, and whether the selected LIEF release can read a PDB symbol table at all. Up to " +
      String(LIEF_LIMITS.maxQueries) +
      " exact-name symbol or virtual-address lookups return found, not_found or unsupported matches with the address, size, RVA and compilation unit that were actually established; a fact the reader could not establish stays null and an unanswerable lookup is unsupported with its reason rather than not_found. Public-symbol PDB lookups match names exactly and never claim private or local symbols. Fixed bounds cap the queries admitted, matches per lookup, scanned DWARF functions, scanned PDB public symbols and listed debug sections; each overrun is reported as its own truncation row and complete stays false, so a lookup past a scan budget is never reported as not_found. Configuration gaps, unsupported containers, digest mismatches, oversized frames and deadlines return typed failures with remediation.",
    inputSchema: extractPdbDwarfInfoInputSchema,
    outputSchema: evidenceResultOf(pdbDwarfInfoReportSchema),
    examples: [
      {
        title: "Attribute two addresses to DWARF functions",
        input: {
          path: "/artifacts/application.elf",
          queries: [
            { kind: "address", address: 4198400 },
            { kind: "address", address: 4198464 },
          ],
        },
      },
      {
        title: "Look up a public symbol in a PDB",
        input: {
          path: "/artifacts/application.pdb",
          queries: [{ kind: "symbol", name: "main" }],
        },
      },
      {
        title: "Inventory the debug surfaces without lookups",
        input: { path: "/artifacts/application.exe" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
