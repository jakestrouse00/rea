import { z } from "zod";
import { jsonValueSchema } from "../jsonValue.js";
import {
  LIEF_BRIDGE_ERROR_CODES,
  LIEF_PROTOCOL_VERSION,
} from "./liefLimits.js";

/** Operations the bundled bridge answers. */
export const liefOperationSchema = z.enum([
  "inspect_binary_deep",
  "extract_pdb_dwarf_info",
]);

/** What the bridge reports about its own runtime and available surfaces. */
export const liefBridgeAdvertisementSchema = z.strictObject({
  lief_version: z.string().min(1),
  python_version: z.string().min(1),
  capabilities: z.strictObject({
    /** A DWARF reader entry point is present and importable. */
    dwarf: z.boolean(),
    /** A PDB reader entry point is present. */
    pdb: z.boolean(),
    /** A universal/fat Mach-O reader entry point is present. */
    fat: z.boolean(),
  }),
});

export type LiefBridgeAdvertisement = z.infer<
  typeof liefBridgeAdvertisementSchema
>;

/** One typed refusal frame: the bridge names its own bound or failure. */
export const liefBridgeErrorFrameSchema = z.strictObject({
  kind: z.literal("lief_error"),
  protocol: z.number().int().positive(),
  code: z.enum(LIEF_BRIDGE_ERROR_CODES),
  message: z.string().min(1),
});

export type LiefBridgeErrorFrame = z.infer<typeof liefBridgeErrorFrameSchema>;

/** One report frame; the payload is validated by the owning operation schema. */
export const liefBridgeReportFrameSchema = z.strictObject({
  kind: z.literal("lief_report"),
  protocol: z.number().int().positive(),
  operation: liefOperationSchema,
  bridge: liefBridgeAdvertisementSchema,
  report: jsonValueSchema,
});

export type LiefBridgeReportFrame = z.infer<typeof liefBridgeReportFrameSchema>;

/** Outcome of reading one stdout line as a bridge frame. */
export type LiefFrameParse =
  | { readonly kind: "report"; readonly frame: LiefBridgeReportFrame }
  | { readonly kind: "error"; readonly frame: LiefBridgeErrorFrame }
  | {
      readonly kind: "protocol-mismatch";
      readonly protocol: number;
      readonly raw: unknown;
    }
  | { readonly kind: "invalid"; readonly reason: string };

/** Read exactly one trailing-LF-free line as a closed frame vocabulary. */
export const parseLiefFrame = (line: string): LiefFrameParse => {
  let decoded: unknown;
  try {
    decoded = JSON.parse(line);
  } catch {
    return { kind: "invalid", reason: "the bridge's line is not JSON" };
  }
  const error = liefBridgeErrorFrameSchema.safeParse(decoded);
  const report = liefBridgeReportFrameSchema.safeParse(decoded);
  const protocol =
    error.success === true
      ? error.data.protocol
      : report.success === true
        ? report.data.protocol
        : undefined;
  if (protocol !== undefined && protocol !== LIEF_PROTOCOL_VERSION)
    return { kind: "protocol-mismatch", protocol, raw: decoded };
  if (error.success) return { kind: "error", frame: error.data };
  if (report.success) return { kind: "report", frame: report.data };
  return {
    kind: "invalid",
    reason: "the bridge's line matches neither a report nor a refusal frame",
  };
};
