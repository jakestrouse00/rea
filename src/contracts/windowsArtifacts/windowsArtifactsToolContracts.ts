import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import {
  inspectPdbSymbolsInputSchema,
  pdbSymbolsSchema,
} from "../../domain/windowsArtifacts/pdbSymbols.js";
import {
  inspectWerReportInputSchema,
  werReportSchema,
} from "../../domain/windowsArtifacts/werReport.js";
import {
  inspectWindowsMinidumpInputSchema,
  windowsMinidumpSchema,
} from "../../domain/windowsArtifacts/windowsMinidump.js";

/**
 * Effects for the Windows-artifact tools are audited in the canonical
 * `toolEffects.ts#TOOL_EFFECTS` registry (`evidence`, `evidence`,
 * `nativeEvidence`).
 */

/** Offline Windows crash-artifact contracts, independent of active providers. */
export const WINDOWS_ARTIFACTS_TOOL_CONTRACTS = [
  {
    name: "inspect_windows_minidump",
    ...toolContractMetadata("inspect_windows_minidump"),
    kind: "artifact-provider",
    description:
      "Inspect one explicit local Windows minidump's structure without executing it or launching any process. Returns the MDMP header version, flags and timestamp, the complete stream directory with every declared stream typed and located, module list entries with their name strings, base addresses, sizes, checksums, timestamps and full VS_FIXEDFILEINFO fields, per-thread addresses (TEB, stack range, context-record location), the exception record's code, flags, address, thread id and parameter vector, the system-info numeric identity, the recorded memory-range inventories from MemoryList and Memory64 lists, and MemoryInfoList region facts when present. Unrecognized stream types remain unparsed directory entries and are never fabricated. Thread CONTEXT register values, the CSD string contents and stream payload bytes stay unknown. Bound to a stable snapshot with SHA-256 Evidence; malformed structure, budget-exceeding tables or oversized inputs return typed failures rather than partial success.",
    inputSchema: inspectWindowsMinidumpInputSchema,
    outputSchema: evidenceResultOf(windowsMinidumpSchema),
    examples: [
      {
        title: "Inspect a minidump's crash structure",
        input: { path: "/artifacts/crash.dmp" },
      },
    ],
  },
  {
    name: "inspect_wer_report",
    ...toolContractMetadata("inspect_wer_report"),
    kind: "artifact-provider",
    description:
      "Parse one explicit local Windows Error Reporting (.wer) file's exact UTF-16LE key/value text without any tool installation or target execution. Returns every field verbatim in file order, Sig[N] and DynamicSig[N] module-signature groups, unparsed lines, the observed encoding and byte-order-mark facts, and the artifact SHA-256. Values — including paths, usernames and version strings — are preserved exactly as written: REA applies no secrecy inference and no redaction, so sensitive values reach the caller for its own policy decisions. No fault meaning or module identity is derived beyond the recorded text.",
    inputSchema: inspectWerReportInputSchema,
    outputSchema: evidenceResultOf(werReportSchema),
    examples: [
      {
        title: "Read a WER report's recorded fields",
        input: { path: "/artifacts/AppCrash_report.wer" },
      },
    ],
  },
  {
    name: "inspect_pdb_symbols",
    ...toolContractMetadata("inspect_pdb_symbols"),
    kind: "native-provider",
    description:
      "Inspect one explicit local PDB through a caller-configured llvm-pdbutil (BYO via REA_LLVM_PDBUTIL_COMMAND; REA never installs LLVM tooling) by running one bounded `llvm-pdbutil dump -summary -streams -modules -files -symbols -publics` command. Returns the exact invocation, modules and compilands as printed headings, parsed CodeView symbol records (S_* kinds, names, record offsets, sizes, segment:offset addresses and code sizes for procs and publics), named-stream names observed in the dump, every unmatched line preserved verbatim as unparsed text, and SHA-256 Evidence. Source-server content (named streams under /src/) is recorded as inert stream names only: never parsed as configuration, never fetched, and never executed. No command, path or script embedded in the PDB is executed or resolved. A zero-sized output budget, truncation, timeouts and nonzero exits return typed failures rather than partial symbol tables.",
    inputSchema: inspectPdbSymbolsInputSchema,
    outputSchema: evidenceResultOf(pdbSymbolsSchema),
    examples: [
      {
        title: "Dump a PDB's modules and symbol records",
        input: { path: "/artifacts/application.pdb" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
