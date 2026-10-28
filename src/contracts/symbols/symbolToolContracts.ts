import {
  demangleRustNameInputSchema,
  demangleRustNameResultSchema,
  generateSymbolTableInputSchema,
  generateSymbolTableResultSchema,
  recoverGoSymbolsInputSchema,
  recoverGoSymbolsResultSchema,
} from "../../domain/symbols/symbolRecovery.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * Symbol recovery over caller-supplied GoReSym, rustfilt, and dump_syms.
 *
 * Each tool resolves its own executable and fails closed with the exact
 * setting and remediation. REA never installs or downloads a toolchain.
 */
export const SYMBOL_TOOL_CONTRACTS = [
  {
    name: "recover_go_symbols",
    ...toolContractMetadata("recover_go_symbols"),
    description:
      "Recover Go function names, entry offsets, and sizes from one explicit local executable or stripped binary through a caller-supplied GoReSym binary, without executing it. Returns the Go version, architecture, operating system, module path, and a bounded function table, plus the artifact SHA-256 and client command. Missing functions are not proof of absence. Select the tool with an absolute REA_GORESYM_COMMAND; REA never installs or updates it.",
    kind: "symbol-provider",
    inputSchema: recoverGoSymbolsInputSchema,
    outputSchema: evidenceResultOf(recoverGoSymbolsResultSchema),
    examples: [
      {
        title: "Recover Go symbols from a stripped binary",
        input: { path: "/artifacts/server.bin" },
      },
    ],
  },
  {
    name: "demangle_rust_name",
    ...toolContractMetadata("demangle_rust_name"),
    description:
      "Demangle caller-supplied Rust symbol names through rustfilt, returning each input name paired with its demangled form or null when the demangler leaves it unchanged. No target is read or executed. Select the tool with an absolute REA_RUSTFILT_COMMAND, or leave it unset to resolve rustfilt from PATH; REA never installs it.",
    kind: "symbol-provider",
    inputSchema: demangleRustNameInputSchema,
    outputSchema: evidenceResultOf(demangleRustNameResultSchema),
    examples: [
      {
        title: "Demangle two Rust symbols",
        input: {
          names: [
            "_ZN4core3fmt5write17h1234567890abcdefE",
            "_RNvNtCs1234_7mycrate3foo",
          ],
        },
      },
    ],
  },
  {
    name: "generate_symbol_table",
    ...toolContractMetadata("generate_symbol_table"),
    description:
      "Parse a Breakpad symbol table produced for one explicit local executable by a caller-supplied dump_syms binary, without executing the target. Returns the MODULE identity, bounded FUNC rows with address, size, and parameter size, and PUBLIC and FILE counts, plus the artifact SHA-256 and client command. The full symbol text stays out of Evidence. Select the tool with an absolute REA_DUMP_SYMS_COMMAND; REA never installs or updates it.",
    kind: "symbol-provider",
    inputSchema: generateSymbolTableInputSchema,
    outputSchema: evidenceResultOf(generateSymbolTableResultSchema),
    examples: [
      {
        title: "Generate a symbol table for a stripped binary",
        input: { path: "/artifacts/libnative.so" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
