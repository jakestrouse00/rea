import {
  analyzeBinaryCapabilitiesInputSchema,
  analyzeBinaryCapabilitiesResultSchema,
} from "../../domain/capa/capaAnalysis.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * Capability matching over a caller-supplied capa CLI.
 *
 * The target is a local executable the caller already holds; REA never
 * installs capa, downloads rules, or executes the target.
 */
export const CAPA_TOOL_CONTRACTS = [
  {
    name: "analyze_binary_capabilities",
    ...toolContractMetadata("analyze_binary_capabilities"),
    description:
      "Match capa rules against one explicit local executable, library, or .NET assembly without executing it. Returns each matched rule's identity, namespace, scope, ATT&CK and MBC references, match count, and bounded match locations, plus the target SHA-256 and capa client version. Decoded strings, matched bytes, and rule source stay out of Evidence. Select the CLI with an absolute REA_CAPA_COMMAND; an optional backend override follows capa's own names. Unrecognized rule rows are counted rather than guessed, so the inventory can be partial.",
    kind: "capa-provider",
    inputSchema: analyzeBinaryCapabilitiesInputSchema,
    outputSchema: evidenceResultOf(analyzeBinaryCapabilitiesResultSchema),
    examples: [
      {
        title: "Match capabilities in a local executable",
        input: { path: "/artifacts/sample.exe" },
      },
      {
        title: "Use the Ghidra backend with a bounded rule list",
        input: {
          path: "/artifacts/sample.exe",
          backend: "ghidra",
          max_rules: 200,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
