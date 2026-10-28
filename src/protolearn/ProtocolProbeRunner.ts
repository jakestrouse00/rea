import { realpath } from "node:fs/promises";
import { dirname } from "node:path";

import {
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { LabEndpoint } from "../domain/protolearn/labEndpoints.js";
import {
  probeRunnerResponseSchema,
  type ProbeRunnerStep,
} from "../domain/protolearn/probeRunnerProtocol.js";
import {
  PROTOLEARN_DIAGNOSTIC_EXCERPT_BYTES,
  PROTOLEARN_LIMITS,
  PROTOLEARN_PROVIDER_ID,
  PROTOLEARN_PROTOCOL_VERSION,
} from "../domain/protolearn/protolearnLimits.js";
import {
  sandboxLaunchPlan,
  type SandboxProfileRequest,
} from "../domain/sandboxProfiles.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import { runSidecarBridgeJob } from "../process/SidecarBridgeJob.js";
import type { ProtolearnProbeConfiguration } from "./ProtocolLearningConfiguration.js";

/** One step as REA sends it; the runner never sees a caller label. */
export interface ProtocolProbeStepInput {
  readonly bytes: Buffer;
  readonly waitForResponse: boolean;
}

/** The argv one probe connection runs, plus the confinement it reports. */
export interface ProtocolProbeLaunch {
  readonly executable: string;
  readonly args: readonly string[];
  readonly limitations: readonly string[];
}

export interface ProtocolProbeLaunchRequest {
  readonly configuration: ProtolearnProbeConfiguration;
  readonly endpoint: LabEndpoint;
  /** Canonical owner-only directory the child may write. */
  readonly workspaceRoot: string;
  /** Launch environment, including the REA_DISABLE_SANDBOX emergency exit. */
  readonly environment: Readonly<Record<string, string | undefined>>;
}

/** How one probe child is launched; tests inject a scripted planner. */
export type ProtocolProbeLaunchPlanner = (
  request: ProtocolProbeLaunchRequest,
) => ProtocolProbeLaunch;

/**
 * Confine the probe child to the declared lab socket.
 *
 * The profile admits exactly one outbound destination, the runner script and
 * interpreter as executables, and the job's own workspace as writable, so a
 * probe that strayed to another host or port would be refused by the kernel.
 */
export const sandboxedProbeLaunch: ProtocolProbeLaunchPlanner = (request) => {
  const profile: SandboxProfileRequest = {
    workspace_root: request.workspaceRoot,
    executable_paths: [request.configuration.python],
    readable_paths: [
      dirname(dirname(request.configuration.python)),
      dirname(request.configuration.bridgeScript),
      request.workspaceRoot,
    ],
    network_allowlist: [
      { host: request.endpoint.host, port: request.endpoint.port },
    ],
  };
  const plan = sandboxLaunchPlan({
    executable: request.configuration.python,
    args: ["-I", "-B", request.configuration.bridgeScript],
    profile,
    environment: request.environment,
  });
  return {
    executable: plan.executable,
    args: plan.args,
    limitations: plan.limitations,
  };
};

export interface ProtocolProbeJobOptions {
  readonly configuration: ProtolearnProbeConfiguration;
  readonly endpoint: LabEndpoint;
  readonly steps: readonly ProtocolProbeStepInput[];
  readonly timeoutMs: number;
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly launchPlanner?: ProtocolProbeLaunchPlanner;
  readonly signal?: AbortSignal;
}

/**
 * Run one probe connection through one bounded, confined child process.
 *
 * The child owns the socket; REA never connects from its own process, so the
 * deny-default profile is what bounds the network side effect.
 */
export const runProtocolProbeConnection = async (
  options: ProtocolProbeJobOptions,
): Promise<{
  readonly steps: readonly ProbeRunnerStep[];
  readonly connected: boolean;
  readonly limitations: readonly string[];
}> => {
  const workspace = await PrivateRuntimeRoot.create({
    prefix: "rea-protolearn-",
  });
  let failure: unknown;
  let result:
    | {
        readonly steps: readonly ProbeRunnerStep[];
        readonly connected: boolean;
        readonly limitations: readonly string[];
      }
    | undefined;
  try {
    result = await exchange(options, workspace.path);
  } catch (cause: unknown) {
    failure = cause;
  }
  const cleanupFailure = await closeWorkspace(workspace);
  if (cleanupFailure !== undefined) {
    if (failure instanceof AnalysisError)
      failure.retainSecondaryFailure(cleanupFailure);
    else throw cleanupFailure;
  }
  if (failure !== undefined) throw failure;
  if (result === undefined)
    throw new AnalysisProtocolError("The protocol probe produced no result");
  return result;
};

/** Remove the probe workspace, reporting a removal failure as owned cleanup. */
const closeWorkspace = async (
  workspace: PrivateRuntimeRoot,
): Promise<ProviderCleanupError | undefined> => {
  try {
    await workspace.close();
    return undefined;
  } catch (cause: unknown) {
    return new ProviderCleanupError(
      PROTOLEARN_PROVIDER_ID,
      [workspace.path],
      { reason: "The probe workspace could not be removed" },
      { operation: "probe_learned_model", cause },
    );
  }
};

/** Run the confined child and read its one answer frame. */
const exchange = async (
  options: ProtocolProbeJobOptions,
  workspacePath: string,
): Promise<{
  readonly steps: readonly ProbeRunnerStep[];
  readonly connected: boolean;
  readonly limitations: readonly string[];
}> => {
  const workspaceRoot = await realpath(workspacePath);
  const plan = (options.launchPlanner ?? sandboxedProbeLaunch)({
    configuration: options.configuration,
    endpoint: options.endpoint,
    workspaceRoot,
    environment: options.environment,
  });
  const frame = await runSidecarBridgeJob({
    providerId: PROTOLEARN_PROVIDER_ID,
    providerLabel: "protocol probe",
    operation: "probe_learned_model",
    command: plan.executable,
    arguments: plan.args,
    protocol: PROTOLEARN_PROTOCOL_VERSION,
    body: {
      endpoint: {
        host: options.endpoint.host,
        port: options.endpoint.port,
      },
      steps: options.steps.map((step, ordinal) => ({
        ordinal,
        bytes_hex: step.bytes.toString("hex"),
        wait_for_response: step.waitForResponse,
      })),
      connect_timeout_ms: options.timeoutMs,
      read_timeout_ms: options.timeoutMs,
      max_response_bytes: PROTOLEARN_LIMITS.maxProbeResponseBytes,
      max_total_response_bytes: PROTOLEARN_LIMITS.maxProbeConnectionBytes,
    },
    timeoutMs: options.timeoutMs,
    stopGraceMs: PROTOLEARN_LIMITS.stopGraceMs,
    maxFrameBytes: PROTOLEARN_LIMITS.maxProbeRequestBytes,
    diagnosticExcerptBytes: PROTOLEARN_DIAGNOSTIC_EXCERPT_BYTES,
    resourceTag: "protolearn-probe",
    hostEnvironment: {
      ...options.environment,
      TMPDIR: workspaceRoot,
      TEMP: workspaceRoot,
      TMP: workspaceRoot,
    },
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  const parsed = probeRunnerResponseSchema.safeParse(frame);
  if (!parsed.success)
    throw new AnalysisProtocolError(
      "The protocol probe returned a frame that does not match its contract",
      { cause: parsed.error },
    );
  if (!parsed.data.ok || parsed.data.result === undefined)
    throw new AnalysisOutputError(
      "probe_learned_model",
      `The probe runner refused the connection: ${parsed.data.error?.code ?? "no_code"} ${parsed.data.error?.message ?? ""}`.trim(),
      {
        diagnostics: {
          code: parsed.data.error?.code ?? null,
          job_id: parsed.data.job_id,
        },
      },
    );
  return {
    steps: parsed.data.result.steps,
    connected: parsed.data.result.connected,
    limitations: plan.limitations,
  };
};
