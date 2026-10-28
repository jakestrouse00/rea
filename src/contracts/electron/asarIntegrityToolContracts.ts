import {
  asarIntegrityReportSchema,
  inspectAsarIntegrityInputSchema,
} from "../../domain/electron/asarIntegrity.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * ASAR header-declared member checksums plus the V8 bytecode handoff.
 *
 * Member payload bytes never enter Evidence; only extents, counts, member paths
 * and verification outcomes are reported.
 */
export const ASAR_INTEGRITY_TOOL_CONTRACTS = [
  {
    name: "inspect_asar_integrity",
    ...toolContractMetadata("inspect_asar_integrity"),
    kind: "artifact-provider",
    description:
      "Check one local Electron ASAR archive's header-declared SHA-256 member checksums over its packed content and list V8 bytecode candidates for decompile_v8_bytecode. Returns the archive digest, member counts, per-member verification outcomes (verified, mismatched, not declared, unverified), the bounded list of mismatched member paths, the bytes actually checked, and any V8 bytecode candidates by path suffix with an explicit decompile_v8_bytecode handoff. Unpacked companions, members outside max_verify_bytes, and members without declared checksums stay unverified rather than assumed valid. Nothing is extracted, published, or executed, and no member payload bytes or payload checksums reach Evidence. A verified archive does not establish that Electron loaded it or that its fuse policy enforced integrity.",
    inputSchema: inspectAsarIntegrityInputSchema,
    outputSchema: evidenceResultOf(asarIntegrityReportSchema),
    examples: [
      {
        title: "Check one packaged app.asar and list bytecode candidates",
        input: {
          path: "/Applications/Example.app/Contents/Resources/app.asar",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
