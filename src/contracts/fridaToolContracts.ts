import { z } from "zod";

import { localPathStringSchema } from "../domain/localPath.js";
import type { ToolContract } from "./toolContractTypes.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";
import { analysisDetailOutputSchemaOf } from "./analysisDetail.js";
import { toolContractMetadata } from "./toolEffects.js";
import { isValidFridaRemoteAddress } from "./fridaRemoteAddress.js";
import {
  fridaSessionObservationSchema,
  fridaSessionStatusInputSchema,
  fridaSessionStatusSchema,
} from "../domain/fridaSessionStatus.js";
import { fridaSessionStatusSummaryViewResultSchema } from "../domain/analysisView/analysisView.js";
import {
  fridaDeviceListSchema,
  fridaProcessListSchema,
} from "../domain/fridaDiscovery.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import {
  fridaScriptPresetNameSchema,
  loadFridaScriptPresetResultSchema,
} from "../domain/fridaScriptPreset.js";
import {
  FRIDA_RPC_DEFAULT_TIMEOUT_MS,
  FRIDA_RPC_MAX_ARGUMENTS,
  FRIDA_RPC_MAX_TIMEOUT_MS,
  FRIDA_RPC_METHOD_MAX_CHARACTERS,
  fridaRpcCallResultSchema,
  fridaRpcListResultSchema,
} from "../domain/fridaRpc.js";

export const FRIDA_KEEPALIVE_INTERVAL_DESCRIPTION =
  "Remote keepalive interval in seconds";

const remoteConnection = z.strictObject({
  address: z.string().min(1).max(2048).refine(isValidFridaRemoteAddress, {
    message: "Expected a Frida host address, optionally followed by a port",
  }),
  token: z.string().min(1).optional(),
  certificate: z.string().min(1).optional(),
  origin: z.string().min(1).optional(),
  keepalive_interval: z
    .int()
    .positive()
    .describe(FRIDA_KEEPALIVE_INTERVAL_DESCRIPTION)
    .optional(),
});

const deviceSelector = z.strictObject({
  device_id: z.string().min(1).optional(),
  remote: remoteConnection.optional(),
});

const exclusiveDeviceSelector = <Schema extends z.ZodTypeAny>(schema: Schema) =>
  schema.refine(
    (value) =>
      !(
        typeof value === "object" &&
        value !== null &&
        "device_id" in value &&
        "remote" in value &&
        value.device_id !== undefined &&
        value.remote !== undefined
      ),
    "Choose either device_id or remote, not both",
  );

const sessionId = z.string().uuid();

const scriptOutput = z.strictObject({
  script_id: z.string().uuid(),
  source_kind: z.enum(["inline", "file"]),
  source_path: z.string().nullable(),
  source_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  messages: z.array(z.unknown()),
  messages_truncated: z.boolean(),
});

/** Caller-facing Frida device, process, and instrumentation-session contracts. */
export const FRIDA_TOOL_CONTRACTS = [
  {
    name: "list_frida_devices",
    ...toolContractMetadata("list_frida_devices"),
    kind: "native-provider",
    description:
      "List Frida devices currently available to this host, optionally connecting to the caller-selected remote Frida endpoint. Remote authentication options are used for this call only and are never returned or recorded.",
    inputSchema: z.strictObject({ remote: remoteConnection.optional() }),
    outputSchema: fridaDeviceListSchema,
    examples: [{ title: "List Frida devices", input: {} }],
  },
  {
    name: "list_frida_processes",
    ...toolContractMetadata("list_frida_processes"),
    kind: "native-provider",
    description:
      "List processes observed on a selected Frida device or caller-supplied remote endpoint. A remote connection is closed after discovery; authentication values are never returned or recorded.",
    inputSchema: exclusiveDeviceSelector(deviceSelector)
      .refine(
        (value) => value.device_id !== undefined || value.remote !== undefined,
        "Select a device_id or a remote endpoint",
      )
      .describe(
        'Provide exactly one of device_id or remote. device_id selects a device (use "local" for this host); remote requires an address.',
      ),
    outputSchema: fridaProcessListSchema,
    examples: [
      {
        title: "List local Frida processes",
        input: { device_id: "local" },
      },
    ],
  },
  {
    name: "start_frida_session",
    ...toolContractMetadata("start_frida_session"),
    kind: "native-provider",
    description:
      "Attach Frida to one selected process or spawn one selected target. Spawned targets remain paused until resume_frida_session, allowing scripts to load before execution. Closing a session detaches instrumentation; it does not kill the target.",
    inputSchema: z
      .strictObject({
        mode: z.enum(["attach", "spawn"]),
        ...deviceSelector.shape,
        pid: z.int().positive().optional(),
        program: localPathStringSchema.optional(),
        argv: z.array(z.string()).optional(),
      })
      .refine(
        (value) =>
          ((value.mode === "attach" &&
            value.pid !== undefined &&
            value.program === undefined &&
            value.argv === undefined) ||
            (value.mode === "spawn" &&
              value.program !== undefined &&
              value.pid === undefined)) &&
          !(value.device_id !== undefined && value.remote !== undefined),
        "Select one device; attach requires pid; spawn requires program and rejects pid",
      ),
    outputSchema: fridaSessionObservationSchema,
    examples: [
      {
        title: "Attach to a process",
        input: { mode: "attach", device_id: "local", pid: 1234 },
      },
    ],
  },
  {
    name: "load_frida_script",
    ...toolContractMetadata("load_frida_script"),
    kind: "native-provider",
    description:
      "Load caller-supplied JavaScript into a Frida session. Scripts can read or change target memory and behavior and can access the target process's capabilities. Messages and script errors are returned inline as Evidence; source content is not persisted.",
    inputSchema: z
      .strictObject({
        session_id: sessionId,
        source_kind: z.enum(["inline", "file"]),
        source: z.string().optional(),
        path: localPathStringSchema.optional(),
      })
      .refine(
        (value) =>
          (value.source_kind === "inline" &&
            value.source !== undefined &&
            value.path === undefined) ||
          (value.source_kind === "file" &&
            value.path !== undefined &&
            value.source === undefined),
        "Inline source requires source; file source requires path",
      ),
    outputSchema: evidenceResultOf(scriptOutput),
    examples: [
      {
        title: "Load an inline Frida script",
        input: {
          session_id: "00000000-0000-4000-8000-000000000001",
          source_kind: "inline",
          source: "send(Process.id);",
        },
      },
    ],
  },
  {
    name: "load_frida_script_preset",
    ...toolContractMetadata("load_frida_script_preset"),
    kind: "native-provider",
    description:
      "Load one named REA Frida preset into a live session: ssl-unpinning (certificate pinning), jail-root-detect-bypass, or keystore-dump-structure. The preset is REA's own minimal reference agent over publicly documented checks, not a vendored upstream script, and it hooks only the surfaces this release documents. The preset can read or change target behavior exactly as any loaded script can. Evidence carries the loaded source's SHA-256 and the preset's declared detection surfaces; the script text and any payload the target emits are never returned or recorded.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      preset: fridaScriptPresetNameSchema,
    }),
    outputSchema: evidenceResultOf(loadFridaScriptPresetResultSchema),
    examples: [
      {
        title: "Load the TLS pinning bypass preset",
        input: {
          session_id: "00000000-0000-4000-8000-000000000001",
          preset: "ssl-unpinning",
        },
      },
    ],
  },
  {
    name: "resume_frida_session",
    ...toolContractMetadata("resume_frida_session"),
    kind: "native-provider",
    description:
      "Resume the process created by a paused Frida spawn session. Attached processes are already running and cannot be resumed through this operation.",
    inputSchema: z.strictObject({ session_id: sessionId }),
    outputSchema: z.strictObject({ state: z.literal("running") }),
    examples: [
      {
        title: "Resume an instrumented process",
        input: { session_id: "00000000-0000-4000-8000-000000000001" },
      },
    ],
  },
  {
    name: "unload_frida_script",
    ...toolContractMetadata("unload_frida_script"),
    kind: "native-provider",
    description:
      "Unload one caller-selected Frida script from a live session. This removes that script's instrumentation from the target.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      script_id: z.string().uuid(),
    }),
    outputSchema: z.strictObject({ unloaded: z.literal(true) }),
    examples: [
      {
        title: "Unload a script",
        input: {
          session_id: "00000000-0000-4000-8000-000000000001",
          script_id: "00000000-0000-4000-8000-000000000002",
        },
      },
    ],
  },
  {
    name: "frida_session_status",
    ...toolContractMetadata("frida_session_status"),
    kind: "native-provider",
    description:
      "Read observed Frida session state on each call. Default detail=complete returns queued script messages and capture truncation. detail=summary retains the complete observation in this session and returns identity, state, scripts, retained message count and truncation without payloads. Export the complete parent with export_evidence_bundle; retained summaries are historical and never refresh live state.",
    inputSchema: fridaSessionStatusInputSchema,
    outputSchema: analysisDetailOutputSchemaOf(
      fridaSessionStatusSchema,
      fridaSessionStatusSummaryViewResultSchema,
    ),
    examples: [
      {
        title: "Check Frida session",
        input: { session_id: "00000000-0000-4000-8000-000000000001" },
      },
    ],
  },
  {
    name: "close_frida_session",
    ...toolContractMetadata("close_frida_session"),
    kind: "native-provider",
    description:
      "Unload session scripts and attempt to detach REA's Frida session. Then resume a still-paused spawned process if script cleanup or session detach confirms instrumentation was released. Cleanup failures are reported. REA never kills the target; its final state is reported as unknown.",
    inputSchema: z.strictObject({ session_id: sessionId }),
    outputSchema: z.strictObject({ target_state: z.literal("unknown") }),
    examples: [
      {
        title: "Close Frida session",
        input: { session_id: "00000000-0000-4000-8000-000000000001" },
      },
    ],
  },
  {
    name: "instrument_with_frida",
    ...toolContractMetadata("instrument_with_frida"),
    kind: "native-provider",
    description:
      "Run one caller-authored Frida script against an explicitly selected process and detach when the observation window ends. The CLI and MCP share this ephemeral workflow; use MCP session operations for persistent sessions. Remote authentication is used only for this call and excluded from Evidence. The local frida Node binding is REA's transport layer: its reported release is disclosed in Evidence limitations and rea doctor, with the REA-verified release recorded in src/frida/FridaRelease.ts.",
    inputSchema: z
      .strictObject({
        mode: z.enum(["attach", "spawn"]),
        ...deviceSelector.shape,
        pid: z.int().positive().optional(),
        program: localPathStringSchema.optional(),
        argv: z.array(z.string()).optional(),
        source_kind: z.enum(["inline", "file"]),
        source: z.string().optional(),
        path: localPathStringSchema.optional(),
        duration_ms: z.int().min(0).max(60_000).default(1_000),
      })
      .refine(
        (value) =>
          !(value.device_id !== undefined && value.remote !== undefined) &&
          ((value.mode === "attach" &&
            value.pid !== undefined &&
            value.program === undefined &&
            value.argv === undefined) ||
            (value.mode === "spawn" &&
              value.program !== undefined &&
              value.pid === undefined)) &&
          ((value.source_kind === "inline" &&
            value.source !== undefined &&
            value.path === undefined) ||
            (value.source_kind === "file" &&
              value.path !== undefined &&
              value.source === undefined)),
        "Select one device and provide fields matching the mode and source_kind",
      ),
    outputSchema: evidenceResultOf(
      fridaSessionStatusSchema.extend({
        source_kind: z.enum(["inline", "file"]),
        source_path: z.string().nullable(),
        source_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
        cleanup_error: z.string().nullable(),
      }),
    ),
    examples: [
      {
        title: "Instrument a selected process briefly",
        input: {
          mode: "attach",
          device_id: "local",
          pid: 1234,
          source_kind: "inline",
          source: "send(Process.id);",
          duration_ms: 1_000,
        },
      },
    ],
  },
  {
    name: "frida_rpc_list",
    ...toolContractMetadata("frida_rpc_list"),
    kind: "native-provider",
    description:
      "Report the remote-export surface a loaded Frida script declared to its target, with each export name and declared parameter count. The target reports this inventory once the script's own top-level code has finished, so state=unreported means the exports are unknown rather than an observed empty surface. Reads REA's recorded observation; it does not contact the target.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      script_id: z.string().uuid(),
    }),
    outputSchema: evidenceResultOf(fridaRpcListResultSchema),
    examples: [
      {
        title: "List a loaded script's reported exports",
        input: {
          session_id: "00000000-0000-4000-8000-000000000001",
          script_id: "00000000-0000-4000-8000-000000000002",
        },
      },
    ],
  },
  {
    name: "frida_rpc_call",
    ...toolContractMetadata("frida_rpc_call"),
    kind: "native-provider",
    description:
      "Invoke one remote export of a loaded Frida script and return its bounded JSON reply. The call inherits only the mutation authority established by start_frida_session: attach acts inside the selected process and spawn acts inside the process REA created. REA spawns, resumes, or attaches to nothing here, so this operation never widens that grant. Both the arguments and the reply are caller- and target-derived data, and a returned reply is marked untrusted. timeout_ms bounds how long REA waits for a reply; REA cannot cancel the call inside the target, so a later reply is discarded rather than reported. Invoking an export after its script was unloaded fails with a typed ownership error.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      script_id: z.string().uuid(),
      method: z
        .string()
        .min(1)
        .max(FRIDA_RPC_METHOD_MAX_CHARACTERS)
        .describe("One export name the script reported through frida_rpc_list"),
      arguments: z
        .array(jsonValueSchema)
        .max(FRIDA_RPC_MAX_ARGUMENTS)
        .default([])
        .describe("Positional JSON arguments passed to that export"),
      timeout_ms: z
        .int()
        .min(1)
        .max(FRIDA_RPC_MAX_TIMEOUT_MS)
        .default(FRIDA_RPC_DEFAULT_TIMEOUT_MS)
        .describe("How long REA waits for a reply"),
    }),
    outputSchema: evidenceResultOf(fridaRpcCallResultSchema),
    examples: [
      {
        title: "Call a reported export",
        input: {
          session_id: "00000000-0000-4000-8000-000000000001",
          script_id: "00000000-0000-4000-8000-000000000002",
          method: "snapshot",
          arguments: [],
          timeout_ms: 5_000,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
