import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import {
  angrRequestSchema,
  findPathsToTargetResultSchema,
  recoverControlFlowAngrResultSchema,
  runSymbolicFunctionExplorationResultSchema,
  type AngrRequest,
  type AngrRequestInput,
} from "../domain/angr/angrEvidence.js";
import { angrBridgeResponseSchema } from "../domain/angr/angrBridgeProtocol.js";
import {
  ANGR_LIMITS,
  ANGR_OPERATION_TIMEOUT_SETTING,
  ANGR_PROTOCOL_VERSION,
  ANGR_PROVIDER_ID,
  ANGR_PROVIDER_NAME,
} from "../domain/angr/angrLimits.js";
import { analysisOperationInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  resolveAngrConfiguration,
  AngrConfigurationFailure,
  angrConfigurationAvailability,
  type AngrConfiguration,
} from "./AngrConfiguration.js";
import { runAngrBridgeJob } from "./AngrBridgeJob.js";
import { AngrJobQueue } from "./AngrJobQueue.js";
import { angrJobFailure } from "./AngrRefusal.js";
import { digestAngrTarget } from "./AngrTargetDigest.js";

export const ANGR_PROVIDER_IDENTITY = {
  id: ANGR_PROVIDER_ID,
  name: ANGR_PROVIDER_NAME,
  version: null,
} as const;

export interface AngrProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly settings?: AnalysisSettingsReader;
}

const SYMBOLIC_SCOPE_NOTE =
  "The job explores angr's loader-derived memory model with no operating system, loader runtime, import resolution, or syscall semantics beyond what angr substitutes, so a path is a model of the code rather than a claim about a real process";

const BRIDGE_STDOUT_SCHEMA_ERROR =
  "The angr bridge returned a frame that does not match the symbolic-execution contract";

const providerOf = (angrVersion: string | null) => ({
  ...ANGR_PROVIDER_IDENTITY,
  version: angrVersion,
});

/** Read the runtime deadline override the lane accepts at acceptance time. */
const settingTimeout = (
  settings: AnalysisSettingsReader | undefined,
): number | undefined => settings?.().overrides[ANGR_OPERATION_TIMEOUT_SETTING];

/** Bounded symbolic exploration and CFG recovery over one angr sidecar lane. */
export class AngrProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #settings: AnalysisSettingsReader | undefined;
  readonly #shutdown = new AbortController();
  #queue: AngrJobQueue | undefined;
  #closing = false;

  constructor(options: AngrProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#settings = options.settings;
  }

  /** Report the caller's selection without starting the sidecar. */
  inspectAvailability(): ProviderAvailability {
    try {
      const configuration = resolveAngrConfiguration(
        this.#environment,
        settingTimeout(this.#settings),
      );
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          bridge_script: configuration.bridgeScript,
          interpreter: configuration.python,
          admitted_jobs: configuration.jobs,
          operation_timeout_ms: configuration.operationTimeoutMs,
          pinned_angr_version: "9.2.x",
          probe: "selection_only",
          angr_version_unverified: true,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof AngrConfigurationFailure)
        return angrConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The angr bridge selection could not be read",
        diagnostics: {},
      };
    }
  }

  /** Stop admission, cancel queued and running jobs, and drain them. */
  async close(): Promise<void> {
    this.#closing = true;
    this.#shutdown.abort(new Error("REA is closing the angr lane"));
    await this.#queue?.close();
  }

  async execute(
    request: AngrRequestInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const caller = options?.signal;
    if (this.#closing || caller?.aborted === true)
      return err(
        new AnalysisCancelledError(request.operation, {
          cause: caller?.reason,
        }),
      );
    const parsed = angrRequestSchema.safeParse(request);
    if (!parsed.success)
      return err(
        analysisOperationInputErrorFromIssues(
          request.operation,
          parsed.error.issues,
          (request as { input?: unknown }).input,
          parsed.error,
        ),
      );
    const normalized = parsed.data;
    let configuration: AngrConfiguration;
    try {
      configuration = resolveAngrConfiguration(
        this.#environment,
        settingTimeout(this.#settings),
      );
    } catch (cause: unknown) {
      if (cause instanceof AngrConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            ANGR_PROVIDER_ID,
            normalized.operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `The angr bridge selection failed for ${normalized.operation}`,
          { cause },
        ),
      );
    }
    const signal = this.#signal(caller);
    const timeoutMs =
      normalized.input.timeout_ms ?? configuration.operationTimeoutMs;
    return await this.#queueFor(configuration).run(
      normalized.operation,
      signal,
      async () => {
        switch (normalized.operation) {
          case "find_paths_to_target":
            return await this.#findPaths(
              configuration,
              normalized.input,
              normalized.operation,
              signal,
              timeoutMs,
            );
          case "run_symbolic_function_exploration":
            return await this.#explore(
              configuration,
              normalized.input,
              normalized.operation,
              signal,
              timeoutMs,
            );
          case "recover_control_flow_angr":
            return await this.#recoverControlFlow(
              configuration,
              normalized.input,
              normalized.operation,
              signal,
              timeoutMs,
            );
        }
      },
    );
  }

  #signal(caller: AbortSignal | undefined): AbortSignal {
    return caller === undefined
      ? this.#shutdown.signal
      : AbortSignal.any([caller, this.#shutdown.signal]);
  }

  #queueFor(configuration: AngrConfiguration): AngrJobQueue {
    this.#queue ??= new AngrJobQueue(configuration.jobs);
    return this.#queue;
  }

  async #findPaths(
    configuration: AngrConfiguration,
    input: Extract<AngrRequest, { operation: "find_paths_to_target" }>["input"],
    operation: string,
    signal: AbortSignal,
    timeoutMs: number,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await digestAngrTarget(operation, input.path, signal);
    if (!digest.ok) return digest;
    const frame = await this.#job(configuration, operation, signal, timeoutMs, {
      kind: "find_paths",
      path: input.path,
      binary_sha256: digest.value.sha256,
      entry: input.entry,
      stdin_bytes: input.stdin_bytes,
      symbolic_registers: input.symbolic_registers,
      assertions: input.assertions,
      find_addresses: input.find_addresses,
      avoid_addresses: input.avoid_addresses,
      max_paths: input.max_paths,
      max_states: input.max_states,
      max_steps: input.max_steps,
      limits: {
        max_conditions: ANGR_LIMITS.maxConditions,
        max_condition_nodes: ANGR_LIMITS.maxConditionNodes,
        max_model_values: ANGR_LIMITS.maxModelValues,
      },
    });
    if (!frame.ok) return frame;
    const parsed = findPathsToTargetResultSchema.safeParse(frame.value);
    if (!parsed.success)
      return err(this.#schemaFailure(operation, parsed.error));
    const mismatch = this.#targetMismatch(
      operation,
      parsed.data.target.sha256,
      digest.value.sha256,
    );
    if (mismatch !== null) return err(mismatch);
    const result = {
      ...parsed.data,
      target: {
        path: input.path,
        entry: input.entry,
        sha256: digest.value.sha256,
      },
    };
    return ok(
      createAnalysisExecution(result, providerOf(result.bridge.angr_version), {
        limitations: [
          SYMBOLIC_SCOPE_NOTE,
          result.reachable
            ? "A satisfying path was found for the assertions as given; the constraints describe the model, not a verified real-world input"
            : "No path satisfied the request within its bounds, which does not establish that the target address is unreachable",
          "Path conditions are reported as an operator tree with constant digests, and model values as SHA-256 digests only, so no symbolic solution can be read back from Evidence",
          ...(result.paths_truncated
            ? [
                `Satisfying paths retained at most ${String(ANGR_LIMITS.maxPaths)}`,
              ]
            : []),
          ...(result.termination === "step_bound" ||
          result.termination === "state_bound" ||
          result.termination === "deadline"
            ? [
                `The job stopped at its ${result.termination === "step_bound" ? "step" : result.termination === "state_bound" ? "state" : "deadline"} bound, so coverage is partial`,
              ]
            : []),
        ],
        locations: [
          { kind: "artifact-path", path: input.path },
          { kind: "address", address: input.entry },
        ],
      }),
    );
  }

  async #explore(
    configuration: AngrConfiguration,
    input: Extract<
      AngrRequest,
      { operation: "run_symbolic_function_exploration" }
    >["input"],
    operation: string,
    signal: AbortSignal,
    timeoutMs: number,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await digestAngrTarget(operation, input.path, signal);
    if (!digest.ok) return digest;
    const frame = await this.#job(configuration, operation, signal, timeoutMs, {
      kind: "explore_function",
      path: input.path,
      binary_sha256: digest.value.sha256,
      entry: input.entry,
      stdin_bytes: input.stdin_bytes,
      symbolic_registers: input.symbolic_registers,
      find_addresses: input.find_addresses,
      avoid_addresses: input.avoid_addresses,
      max_states: input.max_states,
      max_steps: input.max_steps,
      limits: {
        max_conditions: ANGR_LIMITS.maxConditions,
        max_condition_nodes: ANGR_LIMITS.maxConditionNodes,
        max_model_values: ANGR_LIMITS.maxModelValues,
        max_visited_blocks: ANGR_LIMITS.maxVisitedBlocks,
        max_paths: ANGR_LIMITS.maxPaths,
      },
    });
    if (!frame.ok) return frame;
    const parsed = runSymbolicFunctionExplorationResultSchema.safeParse(
      frame.value,
    );
    if (!parsed.success)
      return err(this.#schemaFailure(operation, parsed.error));
    const mismatch = this.#targetMismatch(
      operation,
      parsed.data.target.sha256,
      digest.value.sha256,
    );
    if (mismatch !== null) return err(mismatch);
    const result = {
      ...parsed.data,
      target: {
        path: input.path,
        entry: input.entry,
        sha256: digest.value.sha256,
      },
    };
    return ok(
      createAnalysisExecution(result, providerOf(result.bridge.angr_version), {
        limitations: [
          SYMBOLIC_SCOPE_NOTE,
          "Counts describe the states this one exploration kept alive; they are not a count of the function's real control-flow paths",
          "Visited and found addresses are model observations, not a decoded control-flow graph",
          ...(result.visited_blocks_truncated
            ? [
                `Visited blocks retained at most ${String(ANGR_LIMITS.maxVisitedBlocks)} addresses`,
              ]
            : []),
          ...(result.termination === "step_bound" ||
          result.termination === "state_bound" ||
          result.termination === "deadline"
            ? [
                `The job stopped at its ${result.termination === "step_bound" ? "step" : result.termination === "state_bound" ? "state" : "deadline"} bound, so coverage is partial`,
              ]
            : []),
        ],
        locations: [
          { kind: "artifact-path", path: input.path },
          { kind: "address", address: input.entry },
        ],
      }),
    );
  }

  async #recoverControlFlow(
    configuration: AngrConfiguration,
    input: Extract<
      AngrRequest,
      { operation: "recover_control_flow_angr" }
    >["input"],
    operation: string,
    signal: AbortSignal,
    timeoutMs: number,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const digest = await digestAngrTarget(operation, input.path, signal);
    if (!digest.ok) return digest;
    const frame = await this.#job(configuration, operation, signal, timeoutMs, {
      kind: "recover_cfg",
      path: input.path,
      binary_sha256: digest.value.sha256,
      max_functions: input.max_functions,
      max_blocks: input.max_blocks,
      limits: { max_successors: ANGR_LIMITS.maxSuccessors },
    });
    if (!frame.ok) return frame;
    const parsed = recoverControlFlowAngrResultSchema.safeParse(frame.value);
    if (!parsed.success)
      return err(this.#schemaFailure(operation, parsed.error));
    const mismatch = this.#targetMismatch(
      operation,
      parsed.data.target.sha256,
      digest.value.sha256,
    );
    if (mismatch !== null) return err(mismatch);
    const result = {
      ...parsed.data,
      target: { path: input.path, entry: null, sha256: digest.value.sha256 },
    };
    return ok(
      createAnalysisExecution(result, providerOf(result.bridge.angr_version), {
        limitations: [
          "Functions, blocks, and edges are angr's loader-derived recovery of one artifact, not a decoded instruction listing; cross-check them against rizin or Ghidra before treating either as ground truth",
          "No function, block, or symbol name is reported: names can carry text read from the target, and addresses are enough to line the result up with another engine",
          "An unresolved indirect branch keeps its block and contributes no successor, so a missing edge is not evidence that no edge exists",
          ...(result.blocks_truncated || result.functions_truncated
            ? [
                `Retained at most ${String(ANGR_LIMITS.maxFunctions)} functions and ${String(ANGR_LIMITS.maxBlocks)} blocks`,
              ]
            : []),
        ],
        locations: [{ kind: "artifact-path", path: input.path }],
      }),
    );
  }

  #schemaFailure(operation: string, cause: unknown): AnalysisError {
    return new AnalysisProtocolError(BRIDGE_STDOUT_SCHEMA_ERROR, {
      cause,
      diagnostics: {
        operation,
        bridge_protocol: ANGR_PROTOCOL_VERSION,
      },
    });
  }

  #targetMismatch(
    operation: string,
    observed: string,
    selected: string,
  ): AnalysisError | null {
    if (observed === selected) return null;
    return new AnalysisProtocolError(
      "The angr bridge analysed other bytes than the artifact REA selected",
      { diagnostics: { operation, selected_sha256: selected } },
    );
  }

  async #job(
    configuration: AngrConfiguration,
    operation: string,
    signal: AbortSignal,
    timeoutMs: number,
    body: Readonly<Record<string, unknown>>,
  ): Promise<Result<unknown, AnalysisError>> {
    try {
      const frame = await runAngrBridgeJob({
        configuration,
        operation,
        body: { ...body, timeout_ms: timeoutMs },
        timeoutMs,
        hostEnvironment: this.#environment,
        signal,
      });
      const envelope = angrBridgeResponseSchema.safeParse(frame);
      if (!envelope.success)
        return err(
          new AnalysisProtocolError(BRIDGE_STDOUT_SCHEMA_ERROR, {
            cause: envelope.error,
            diagnostics: {
              operation,
              issue_count: envelope.error.issues.length,
              bridge_protocol: ANGR_PROTOCOL_VERSION,
            },
          }),
        );
      if (envelope.data.kind !== body.kind)
        return err(
          new AnalysisProtocolError(
            `The angr bridge answered a ${envelope.data.kind} job for a ${String(body.kind)} request`,
            { diagnostics: { operation } },
          ),
        );
      if (!envelope.data.ok) {
        const failure = envelope.data.error ?? {
          code: "bridge_error",
          message: "The angr bridge refused the job without a reason",
        };
        return err(angrJobFailure(operation, failure.code, failure.message));
      }
      if (envelope.data.result === undefined)
        return err(
          new AnalysisProtocolError(
            "The angr bridge reported success without a result",
            { diagnostics: { operation } },
          ),
        );
      return ok(envelope.data.result);
    } catch (cause: unknown) {
      if (cause instanceof AnalysisError) return err(cause);
      return err(
        new AnalysisProtocolError(
          `The angr bridge failed outside its own contract for ${operation}`,
          { cause },
        ),
      );
    }
  }
}
