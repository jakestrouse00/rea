import { toolContractMetadata } from "../toolEffects.js";
import {
  ideviceInputSchemas,
  ideviceResultSchemas,
} from "../../domain/idevice/ideviceDeviceAnalysis.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** iOS device inventory and read-only inspection over a caller-provided launcher. */
export const IDEVICE_TOOL_CONTRACTS = [
  {
    name: "list_ios_devices",
    description:
      "Inventory devices visible through the caller's usbmuxd (lockdown pairing status included when the launcher reports it). An unpaired host is an empty inventory, not an error. Read-only.",
    kind: "runtime-provider",
    inputSchema: ideviceInputSchemas.list_ios_devices,
    outputSchema: evidenceResultOf(ideviceResultSchemas.list_ios_devices),
    ...toolContractMetadata("list_ios_devices"),
    examples: [{ title: "List paired devices", input: {} }],
  },
  {
    name: "inspect_ios_device",
    description:
      "Inspect one device through `pymobiledevice3 lockdown info`: model identity, iOS version, and connection type as the device reports them, with every unrecognized field preserved in fields rather than guessed. Read-only.",
    kind: "runtime-provider",
    inputSchema: ideviceInputSchemas.inspect_ios_device,
    outputSchema: evidenceResultOf(ideviceResultSchemas.inspect_ios_device),
    ...toolContractMetadata("inspect_ios_device"),
    examples: [
      {
        title: "Inspect one device",
        input: { udid: "00008101-000A104E0123456789" },
      },
    ],
  },
  {
    name: "read_ios_syslog",
    description:
      "Read a bounded one-shot dump of the device syslog stream for a caller-selected window (<=120 s), optionally filtering lines by a case-insensitive substring. No streaming, no clearing; the stream ends when the window elapses. Read-only.",
    kind: "runtime-provider",
    inputSchema: ideviceInputSchemas.read_ios_syslog,
    outputSchema: evidenceResultOf(ideviceResultSchemas.read_ios_syslog),
    ...toolContractMetadata("read_ios_syslog"),
    examples: [
      {
        title: "Read a bounded syslog slice",
        input: { udid: "00008101-000A104E0123456789", timeout_seconds: 10 },
      },
    ],
  },
  {
    name: "capture_ios_screenshot",
    description:
      "Capture one frame of the device screen as a PNG through the developer instrumentation service, staged in an REA-private runtime root, published exactly once with its SHA-256. No recording or interaction. REA never installs the Xcode DDI on the host beyond what the caller's pymobiledevice3 itself requires.",
    kind: "runtime-provider",
    inputSchema: ideviceInputSchemas.capture_ios_screenshot,
    outputSchema: evidenceResultOf(ideviceResultSchemas.capture_ios_screenshot),
    ...toolContractMetadata("capture_ios_screenshot"),
    examples: [
      {
        title: "Capture a screenshot to a local directory",
        input: {
          udid: "00008101-000A104E0123456789",
          output_directory: "/tmp/rea-captures",
        },
      },
    ],
  },
  {
    name: "list_ios_crash_reports",
    description:
      "List the device's retained crash reports with their names; dates and sizes stay unknown when the rows omit them. Read-only.",
    kind: "runtime-provider",
    inputSchema: ideviceInputSchemas.list_ios_crash_reports,
    outputSchema: evidenceResultOf(ideviceResultSchemas.list_ios_crash_reports),
    ...toolContractMetadata("list_ios_crash_reports"),
    examples: [
      {
        title: "List crash reports",
        input: { udid: "00008101-000A104E0123456789" },
      },
    ],
  },
  {
    name: "inspect_ios_crash",
    description:
      "Pull one crash report by its exact name into a caller-selected directory, staged by the launcher in an REA-private runtime root and published exactly once with its SHA-256. The report is the device's own document and is published uninterpreted. Read-only with respect to the device.",
    kind: "runtime-provider",
    inputSchema: ideviceInputSchemas.inspect_ios_crash,
    outputSchema: evidenceResultOf(ideviceResultSchemas.inspect_ios_crash),
    ...toolContractMetadata("inspect_ios_crash"),
    examples: [
      {
        title: "Pull one crash report",
        input: {
          udid: "00008101-000A104E0123456789",
          report: "AppName-2026-10-19-121500.ips",
          output_directory: "/tmp/rea-captures",
        },
      },
    ],
  },
  {
    name: "list_ios_apps",
    description:
      "List apps installed on the device with bundle identifiers and the display metadata the launcher reports. Read-only; no install, removal, or data access.",
    kind: "runtime-provider",
    inputSchema: ideviceInputSchemas.list_ios_apps,
    outputSchema: evidenceResultOf(ideviceResultSchemas.list_ios_apps),
    ...toolContractMetadata("list_ios_apps"),
    examples: [
      {
        title: "List installed apps",
        input: { udid: "00008101-000A104E0123456789" },
      },
    ],
  },
  {
    name: "inspect_ios_provisioning",
    description:
      "Display the provisioning and signing metadata the launcher's app inventory reports for one installed app's bundle id. The opset has no install or removal path at all; absent provisioning keys stay unknown rather than empty. Read-only.",
    kind: "runtime-provider",
    inputSchema: ideviceInputSchemas.inspect_ios_provisioning,
    outputSchema: evidenceResultOf(
      ideviceResultSchemas.inspect_ios_provisioning,
    ),
    ...toolContractMetadata("inspect_ios_provisioning"),
    examples: [
      {
        title: "Inspect one app's provisioning profile",
        input: {
          udid: "00008101-000A104E0123456789",
          bundle_id: "com.example.app",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
