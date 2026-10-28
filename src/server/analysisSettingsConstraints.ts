import { getHeapStatistics } from "node:v8";
import { MAX_JSON_DEPTH } from "../domain/jsonValue.js";
import { DEFAULT_VIEW8_OPERATION_TIMEOUT_MS as VIEW8_OPERATION_TIMEOUT_MS } from "../javascript/v8/View8Release.js";
import { CRASH_MINIMIZE_DEFAULT_TIMEOUT_MS } from "../domain/crashTriage/crashMinimization.js";
import type { ToolResultDelivery } from "./ToolResultDelivery.js";

/** Transport and host facts stay distinct from the agent-editable policy registry. */
export const analysisSettingsConstraints = (delivery: ToolResultDelivery) => [
  {
    control: "REA_MCP_MAX_RESPONSE_BYTES",
    authority: "operator" as const,
    value: delivery.maximumResponseBytes,
    unit: "bytes",
    observation: "known" as const,
    recovery:
      "Change the launch environment and restart REA with a matching client receive buffer. Prefer retained Evidence, paging or export for completed results.",
  },
  {
    control: "mcp.client_deadline",
    authority: "external" as const,
    value: null,
    unit: "ms",
    observation: "unknown" as const,
    recovery:
      "The MCP host owns its tool-call deadline. REA cannot observe or raise it. Allow execution, cleanup and delivery headroom.",
  },
  {
    control: "mcp.client_receive_buffer",
    authority: "external" as const,
    value: null,
    unit: "bytes",
    observation: "unknown" as const,
    recovery:
      "The MCP host owns its receive buffer; raising a REA output budget alone does not raise it.",
  },
  {
    control: "node.parent_heap",
    authority: "operator" as const,
    value: getHeapStatistics().heap_size_limit,
    unit: "bytes",
    observation: "known" as const,
    recovery:
      "This is the current process heap ceiling, not available memory. On Node, change --max-old-space-size at launch and restart REA. Worker heap settings do not raise it.",
  },
  {
    control: "json.maximum_depth",
    authority: "fixed" as const,
    value: MAX_JSON_DEPTH,
    unit: "levels",
    observation: "known" as const,
    recovery:
      "REA's JSON representation has this fixed nesting policy. This release has no runtime override; increasing byte or worker budgets does not change it.",
  },
  {
    control: "REA_VIEW8_COMMAND",
    authority: "operator" as const,
    value: null,
    unit: "path",
    observation: "unknown" as const,
    recovery:
      "Select a locally built View8 launcher by absolute path in the launch environment and restart REA. REA never installs or builds it and cannot observe the selected patched V8 revision; decompile_v8_bytecode refuses until a usable absolute path is present. See docs/v8-bytecode.md.",
  },
  {
    control: "view8.operation_timeout",
    authority: "fixed" as const,
    value: VIEW8_OPERATION_TIMEOUT_MS,
    unit: "ms",
    observation: "known" as const,
    recovery:
      "One View8 run has this fixed deadline. This release has no runtime override; keep the client call deadline above it and reduce the selected artifact rather than raising host memory. A longer budget would not make the launcher's patched V8 revision match the artifact.",
  },
  {
    control: "REA_LFZ_MINIMIZE_COMMAND",
    authority: "operator" as const,
    value: null,
    unit: "path",
    observation: "unknown" as const,
    recovery:
      "Select the libFuzzer-instrumented target binary by absolute path in the launch environment and restart REA. REA never builds or downloads a fuzz target, so minimization refuses until a usable absolute path is present. See docs/crash-triage.md.",
  },
  {
    control: "REA_AFLTMIN_COMMAND",
    authority: "operator" as const,
    value: null,
    unit: "path",
    observation: "unknown" as const,
    recovery:
      "Select a caller-supplied afl-tmin binary by absolute path in the launch environment and restart REA. REA never installs or upgrades AFL++ tooling. See docs/crash-triage.md.",
  },
  {
    control: "crash_triage.minimizer_timeout",
    authority: "fixed" as const,
    value: CRASH_MINIMIZE_DEFAULT_TIMEOUT_MS,
    unit: "ms",
    observation: "known" as const,
    recovery:
      "One minimizer run has this default deadline; a caller may pass timeout_ms from 1 to 2147483647, and the retained 4194304-byte per-stream output budget has no runtime override. Raising the deadline does not make a target minimize faster.",
  },
];
