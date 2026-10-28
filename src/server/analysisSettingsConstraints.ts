import { getHeapStatistics } from "node:v8";
import { MAX_JSON_DEPTH } from "../domain/jsonValue.js";
import { DEFAULT_VIEW8_OPERATION_TIMEOUT_MS } from "../domain/javascript/v8Bytecode.js";
import { CRASH_MINIMIZE_DEFAULT_TIMEOUT_MS } from "../domain/crashTriage/crashMinimization.js";
import {
  FRIDA_RPC_DEFAULT_TIMEOUT_MS,
  FRIDA_RPC_MAX_TIMEOUT_MS,
} from "../domain/fridaRpc.js";
import { BROWSER_MUTATION_LIMITS } from "../domain/browserMutationLimits.js";
import { REPLAY_LIMITS } from "../domain/replay/replayLimits.js";
import {
  REPLAY_ALLOWED_ORIGINS_ENV,
  REPLAY_ALLOWED_ORIGINS_REMEDIATION,
} from "../domain/replay/replayOrigins.js";
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
    value: DEFAULT_VIEW8_OPERATION_TIMEOUT_MS,
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
  {
    control: "frida.rpc_timeout",
    authority: "fixed" as const,
    value: FRIDA_RPC_MAX_TIMEOUT_MS,
    unit: "ms",
    observation: "known" as const,
    recovery: `A frida_rpc_call waits for the caller's timeout_ms, default ${String(FRIDA_RPC_DEFAULT_TIMEOUT_MS)} ms and at most ${String(FRIDA_RPC_MAX_TIMEOUT_MS)} ms. This release has no runtime override for that bound. REA stops waiting at the deadline but cannot cancel the call inside the target, so the target may still complete it; raising the host tool-call deadline does not make the target reply sooner.`,
  },
  {
    control: REPLAY_ALLOWED_ORIGINS_ENV,
    authority: "operator" as const,
    value: null,
    unit: "origins",
    observation: "unknown" as const,
    recovery: REPLAY_ALLOWED_ORIGINS_REMEDIATION,
  },
  {
    control: "browser.evaluate_result_bytes",
    authority: "fixed" as const,
    value: BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes,
    unit: "bytes",
    observation: "known" as const,
    recovery: `browser_evaluate retains at most ${String(BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes)} UTF-8 bytes of the page's answer and reports value_truncated when it stops. This release has no runtime override, and the result text is page-authored untrusted data.`,
  },
  {
    control: "browser.request_rule_ttl",
    authority: "fixed" as const,
    value: BROWSER_MUTATION_LIMITS.maxRuleTtlMs,
    unit: "ms",
    observation: "known" as const,
    recovery: `A browser_request_rule_set rule stays armed for its ttl_ms, default ${String(BROWSER_MUTATION_LIMITS.defaultRuleTtlMs)} ms and at most ${String(BROWSER_MUTATION_LIMITS.maxRuleTtlMs)} ms, then REA releases it. At most ${String(BROWSER_MUTATION_LIMITS.maxArmedRules)} rules stay armed at once and at most ${String(BROWSER_MUTATION_LIMITS.maxHeldRequestsPerRule)} requests stay paused per hold rule, after which the rule fails closed. This release has no runtime override.`,
  },
  {
    control: "browser.request_rule_decisions",
    authority: "fixed" as const,
    value: BROWSER_MUTATION_LIMITS.maxRuleDecisions,
    unit: "decisions",
    observation: "known" as const,
    recovery: `One armed rule reports at most ${String(BROWSER_MUTATION_LIMITS.maxRuleDecisions)} retained interception decisions. Rewriting or blocking continues after the ledger is full; only the observation is dropped and reported as an omission, so the counters stay complete.`,
  },
  {
    control: "browser.page_fetch_body_bytes",
    authority: "fixed" as const,
    value: BROWSER_MUTATION_LIMITS.maxPageFetchBodyBytes,
    unit: "bytes",
    observation: "known" as const,
    recovery: `browser_fetch reads at most ${String(BROWSER_MUTATION_LIMITS.maxPageFetchBodyBytes)} response bytes inside the page, because one CDP frame carries the whole answer. A larger body ends as a partial observation instead of a complete capture.`,
  },
  {
    control: "replay.request_timeout",
    authority: "fixed" as const,
    value: REPLAY_LIMITS.maxTimeoutMs,
    unit: "ms",
    observation: "known" as const,
    recovery: `One http_replay_send waits for the caller's timeout_ms, default ${String(REPLAY_LIMITS.defaultTimeoutMs)} ms and at most ${String(REPLAY_LIMITS.maxTimeoutMs)} ms. This release has no runtime override for that bound. REA dispatches once and never retries, so a timed-out request is a terminal observation; raising the host tool-call deadline does not make the target answer sooner.`,
  },
];
