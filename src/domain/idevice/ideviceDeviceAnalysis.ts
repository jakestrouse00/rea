import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";

/**
 * Device UDIDs as usbmuxd and lockdown report them (e.g. 00008101-000A104E...)
 * or 40/64-hex legacy UDIDs. The pattern keeps argv positional hygiene; pmd3
 * argument construction never quotes caller values.
 */
export const ideviceUdidSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(
    /^[0-9a-fA-F-]+$/u,
    "A UDID contains hexadecimal digits and dashes only",
  );

/** One-shot iOS-device operations over a caller-supplied pymobiledevice3 CLI. */
export const ideviceInputSchemas = {
  list_ios_devices: z.strictObject({}),
  inspect_ios_device: z.strictObject({
    udid: ideviceUdidSchema.describe("Device UDID to inspect over lockdown"),
  }),
  read_ios_syslog: z.strictObject({
    udid: ideviceUdidSchema.describe("Device UDID whose syslog stream is read"),
    timeout_seconds: z
      .number()
      .int()
      .min(1)
      .max(120)
      .default(10)
      .describe(
        "Bounded one-shot window; pmd3 exits the stream when it elapses",
      ),
    process_filter: z
      .string()
      .min(1)
      .max(256)
      .optional()
      .describe(
        "Keep only lines whose text contains this case-insensitive process or message substring",
      ),
  }),
  capture_ios_screenshot: z.strictObject({
    udid: ideviceUdidSchema.describe("Device UDID to capture"),
    output_directory: localPathStringSchema.describe(
      "Local directory for the screenshot; REA writes exactly one new PNG into it",
    ),
  }),
  list_ios_crash_reports: z.strictObject({
    udid: ideviceUdidSchema.describe(
      "Device UDID whose crash reports are listed",
    ),
  }),
  inspect_ios_crash: z.strictObject({
    udid: ideviceUdidSchema.describe("Device UDID holding the crash report"),
    report: z
      .string()
      .min(1)
      .max(256)
      .regex(
        /^[^\x00\s"']+$/u,
        "Crash report names cannot contain whitespace, quotes, or NUL",
      )
      .describe(
        "Crash report name exactly as list_ios_crash_reports reports it",
      ),
    output_directory: localPathStringSchema.describe(
      "Local directory for the pulled report; REA writes exactly one new file into it",
    ),
  }),
  list_ios_apps: z.strictObject({
    udid: ideviceUdidSchema.describe(
      "Device UDID whose installed apps are listed",
    ),
  }),
  inspect_ios_provisioning: z.strictObject({
    udid: ideviceUdidSchema.describe("Device UDID holding the installed app"),
    bundle_id: z
      .string()
      .min(1)
      .max(256)
      .regex(
        /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$/u,
        "Bundle id must be dot-separated Java identifiers",
      )
      .describe("Installed app to inspect for embedded provisioning metadata"),
  }),
} as const;

export type IdeviceOperation = keyof typeof ideviceInputSchemas;

export type IdeviceRequest = {
  [Name in IdeviceOperation]: {
    operation: Name;
    input: z.infer<(typeof ideviceInputSchemas)[Name]>;
  };
}[IdeviceOperation];

/** Validate operation and input together so their types remain correlated. */
export const ideviceRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("list_ios_devices"),
    input: ideviceInputSchemas.list_ios_devices,
  }),
  z.strictObject({
    operation: z.literal("inspect_ios_device"),
    input: ideviceInputSchemas.inspect_ios_device,
  }),
  z.strictObject({
    operation: z.literal("read_ios_syslog"),
    input: ideviceInputSchemas.read_ios_syslog,
  }),
  z.strictObject({
    operation: z.literal("capture_ios_screenshot"),
    input: ideviceInputSchemas.capture_ios_screenshot,
  }),
  z.strictObject({
    operation: z.literal("list_ios_crash_reports"),
    input: ideviceInputSchemas.list_ios_crash_reports,
  }),
  z.strictObject({
    operation: z.literal("inspect_ios_crash"),
    input: ideviceInputSchemas.inspect_ios_crash,
  }),
  z.strictObject({
    operation: z.literal("list_ios_apps"),
    input: ideviceInputSchemas.list_ios_apps,
  }),
  z.strictObject({
    operation: z.literal("inspect_ios_provisioning"),
    input: ideviceInputSchemas.inspect_ios_provisioning,
  }),
]) as z.ZodType<IdeviceRequest>;

/** Identity of the caller-selected pymobiledevice3 CLI, as probed by REA. */
const client = z.strictObject({
  command: z.string().min(1),
  version: z.string().min(1).nullable(),
  verified: z.boolean(),
});

/** A paired or connectable device as the device inventory reports it. */
export const ideviceResultSchemas = {
  list_ios_devices: z.strictObject({
    client,
    devices: z.array(
      z.strictObject({
        udid: z.string().min(1),
        name: z.string().nullable(),
        connection: z.enum(["usb", "network", "unknown"]),
        pairing: z.enum(["paired", "unpaired", "unknown"]),
        fields: z.array(
          z.strictObject({ key: z.string(), value: z.string().nullable() }),
        ),
      }),
    ),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  inspect_ios_device: z.strictObject({
    client,
    udid: z.string().min(1),
    device_name: z.string().nullable(),
    product_type: z.string().nullable(),
    ios_version: z.string().nullable(),
    connection_type: z.enum(["usb", "network", "unknown"]),
    fields: z.array(
      z.strictObject({ key: z.string(), value: z.string().nullable() }),
    ),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  read_ios_syslog: z.strictObject({
    client,
    udid: z.string().min(1),
    timeout_seconds: z.number().int().positive(),
    process_filter: z.string().min(1).nullable(),
    lines: z.array(z.string().min(1)),
    total_bytes: z.number().int().nonnegative(),
    coverage: z.enum(["complete", "partial"]),
  }),
  capture_ios_screenshot: z.strictObject({
    client,
    udid: z.string().min(1),
    local_path: z.string().min(1),
    bytes: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  }),
  list_ios_crash_reports: z.strictObject({
    client,
    udid: z.string().min(1),
    reports: z.array(
      z.strictObject({
        name: z.string().min(1),
        date: z.string().nullable(),
        bytes: z.number().int().nonnegative().nullable(),
      }),
    ),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  inspect_ios_crash: z.strictObject({
    client,
    udid: z.string().min(1),
    report: z.string().min(1),
    local_path: z.string().min(1),
    bytes: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  }),
  list_ios_apps: z.strictObject({
    client,
    udid: z.string().min(1),
    apps: z.array(
      z.strictObject({
        bundle_id: z.string().min(1),
        name: z.string().nullable(),
        version: z.string().nullable(),
        signer_restricted: z.boolean().nullable(),
      }),
    ),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
  inspect_ios_provisioning: z.strictObject({
    client,
    udid: z.string().min(1),
    bundle_id: z.string().min(1),
    app_found: z.boolean(),
    name: z.string().nullable(),
    version: z.string().nullable(),
    team_name: z.string().nullable(),
    team_identifier: z.string().nullable(),
    provision_fields: z.array(
      z.strictObject({ key: z.string(), value: z.string().nullable() }),
    ),
    unparsed_lines: z.array(z.string().min(1)),
    coverage: z.enum(["complete", "partial"]),
  }),
} as const;
