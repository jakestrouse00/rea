import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import {
  correlateDeviceEvidenceInputSchema,
  deviceCorrelationReportSchema,
} from "../domain/correlation/deviceCorrelationSchemas.js";

/**
 * Query-only device-identity correlation across retained Evidence records.
 * The workflow reads the session's ledger synchronously and never launches a
 * provider, probes a device, or records new Evidence.
 */
export const CORRELATION_TOOL_CONTRACTS = [
  {
    name: "correlate_device_evidence",
    description:
      "Cross-match address-like endpoints extracted from 2..16 caller-selected retained Evidence records: MAC/Bluetooth 48-bit values (all spellings normalized), IPv4/IPv6, and USB (vendor_id,product_id) pairs, with a curated non-exhaustive IEEE OUI prefix attribution. A match reports exactly which records carried that address (observed); no same-device claims are made, because Bluetooth peripheral addresses can rotate. Pure query over the session ledger; records nothing new.",
    kind: "application",
    inputSchema: correlateDeviceEvidenceInputSchema,
    outputSchema: deviceCorrelationReportSchema,
    ...toolContractMetadata("correlate_device_evidence"),
    examples: [
      {
        title: "Correlate endpoints across two retained records",
        input: {
          evidence_ids: ["ev_" + "a".repeat(64), "ev_" + "b".repeat(64)],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
