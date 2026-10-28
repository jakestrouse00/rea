import { z } from "zod";

/** One retained evidence id, as the session's ledger mints them (ev_ + sha256). */
const evidenceId = z.string().regex(/^ev_[a-f0-9]{64}$/u);

/** Correlation input: 2..16 distinct retained evidence ids. */
export const correlateDeviceEvidenceInputSchema = z.strictObject({
  evidence_ids: z
    .array(evidenceId)
    .min(2)
    .max(16)
    .superRefine((ids, context) => {
      if (new Set(ids).size !== ids.length)
        context.addIssue({
          code: "custom",
          message: "evidence_ids must name distinct records",
        });
    }),
});

export type CorrelateDeviceEvidenceInput = z.infer<
  typeof correlateDeviceEvidenceInputSchema
>;

export type DetectedDeviceEndpointKind =
  | "mac"
  | "bluetooth"
  | "ipv4"
  | "ipv6"
  | "usb_pair";

/** One extracted endpoint fact: identity normalized, spellings preserved. */
export const deviceEndpointSchema = z.strictObject({
  kind: z.enum(["mac", "bluetooth", "ipv4", "ipv6", "usb_pair"]),
  value: z.string().min(1),
  normalized: z.string().min(1),
  original_spellings: z.array(z.string().min(1)),
  locations: z.number().int().nonnegative(),
});

/** One correlation match observed across at least two distinct records. */
export const deviceCorrelationMatchSchema = z.strictObject({
  normalized: z.string().min(1),
  kind: z.enum(["mac", "bluetooth", "ipv4", "ipv6", "usb_pair"]),
  evidence_ids: z.array(evidenceId),
  confidence: z.literal("observed"),
  note: z.string().min(1).nullable(),
});

/** One OUI prefix attribution; vendor stays null when the table does not know. */
export const deviceCorrelationOuiSchema = z.strictObject({
  prefix: z.string().min(1),
  vendor: z.string().min(1).nullable(),
  confidence: z.enum(["observed", "derived"]),
});

/** One record id that could not be read; reported, never an error. */
export const deviceCorrelationUnparsedSchema = z.strictObject({
  evidence_id: z.string().min(1),
  reason: z.string().min(1),
});

/** One read record's extracted endpoints, subject and per-kind counts. */
export const deviceCorrelationRecordSchema = z.strictObject({
  evidence_id: evidenceId,
  subject: z.strictObject({ name: z.string(), sha256: z.string() }).nullable(),
  endpoints: z.array(deviceEndpointSchema),
  counts: z.record(
    z.enum(["mac", "bluetooth", "ipv4", "ipv6", "usb_pair"]),
    z.number().int().nonnegative(),
  ),
});

/** Correlation report: read records, cross-record matches, OUI facts. */
export const deviceCorrelationReportSchema = z.strictObject({
  records: z.array(deviceCorrelationRecordSchema),
  matches: z.array(deviceCorrelationMatchSchema),
  oui: z.array(deviceCorrelationOuiSchema),
  unparsed: z.array(deviceCorrelationUnparsedSchema),
  limitations: z.array(z.string().min(1)),
});
