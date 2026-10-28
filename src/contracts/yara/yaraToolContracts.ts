import {
  scanArtifactWithRulesInputSchema,
  scanForCryptoConstantsInputSchema,
  yaraScanResultSchema,
} from "../../domain/yara/yaraScan.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * YARA-X rule scanning over a caller-supplied `yr` binary.
 *
 * Generic rules are caller-supplied; the crypto-constant pack is REA-owned and
 * hash-pinned. Matched bytes never reach Evidence.
 */
export const YARA_TOOL_CONTRACTS = [
  {
    name: "scan_artifact_with_rules",
    ...toolContractMetadata("scan_artifact_with_rules"),
    description:
      "Scan one explicit local file or directory with a caller-supplied YARA rule file or directory, without executing the scanned bytes. Returns each matching rule's identity, namespace, tags, and matched field names with offsets and lengths, plus target and rule-file SHA-256 values and the YARA-X client version. Matched bytes and rule metadata values stay out of Evidence. Select the CLI with an absolute REA_YARAX_COMMAND. Unrecognized match rows are counted rather than guessed, so the inventory can be partial.",
    kind: "yara-provider",
    inputSchema: scanArtifactWithRulesInputSchema,
    outputSchema: evidenceResultOf(yaraScanResultSchema),
    examples: [
      {
        title: "Scan a sample with a local rule file",
        input: {
          path: "/artifacts/sample.bin",
          rules_path: "/rules/malware.yar",
        },
      },
    ],
  },
  {
    name: "scan_for_crypto_constants",
    ...toolContractMetadata("scan_for_crypto_constants"),
    description:
      "Scan one explicit local file or directory with REA's own curated crypto-constant YARA pack, verifying the pack against its pinned SHA-256 manifest before the scan. Returns each matching algorithm rule's identity, namespace, tags, and matched field names with offsets and lengths, plus the target SHA-256 and YARA-X client version. Matches are indicators, not proof of algorithm use; matched bytes stay out of Evidence. Select the CLI with an absolute REA_YARAX_COMMAND; REA never downloads a replacement pack.",
    kind: "yara-provider",
    inputSchema: scanForCryptoConstantsInputSchema,
    outputSchema: evidenceResultOf(yaraScanResultSchema),
    examples: [
      {
        title: "Find crypto constants in a firmware blob",
        input: { path: "/artifacts/blob.bin" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
