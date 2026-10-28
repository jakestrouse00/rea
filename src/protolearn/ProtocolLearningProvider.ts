import { readFile, stat } from "node:fs/promises";

import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
  type ProviderAvailability,
} from "../application/AnalysisProvider.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { analysisOperationInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import { CaptureFormatError } from "../browser/history/CaptureFormatError.js";
import {
  isLoopbackLabHost,
  labEndpointApproval,
  ProtolearnConfigurationFailure,
} from "../domain/protolearn/labEndpoints.js";
import {
  learnProtocolModel,
  type ProtocolSessionFact,
} from "../domain/protolearn/protocolModelLearner.js";
import {
  messageClassKey,
  payloadDigest,
  payloadSketch,
} from "../domain/protolearn/protocolMessage.js";
import {
  protolearnRequestSchema,
  type ProtolearnRequest,
} from "../domain/protolearn/protocolLearningInputs.js";
import { protocolModelSchema, type ProtocolModel } from "../domain/protolearn/protocolModel.js";
import {
  diagnoseProbeStep,
  protocolModelIndex,
  protocolProbeResultSchema,
  type ProbeStepObservation,
  type ProtocolProbeResult,
} from "../domain/protolearn/protocolProbe.js";
import { protocolGrammarExportSchema } from "../domain/protolearn/grammarExport.js";
import {
  PROTOLEARN_LIMITS,
  PROTOLEARN_PROVIDER_ID,
  PROTOLEARN_PROVIDER_NAME,
  PROTOLEARN_PROBE_TIMEOUT_SETTING,
  PROTOLEARN_QLOG_PROFILE,
} from "../domain/protolearn/protolearnLimits.js";
import type { ProtocolMessageSourcePort } from "../domain/protolearn/protocolMessageSource.js";
import {
  ProtolearnProbeConfigurationFailure,
  inspectProtolearnProbeConfiguration,
  resolveProtolearnProbeConfiguration,
  type ProtolearnProbeConfiguration,
} from "./ProtocolLearningConfiguration.js";
import {
  runProtocolProbeConnection,
  type ProtocolProbeLaunchPlanner,
} from "./ProtocolProbeRunner.js";
import {
  exportProtocolGrammar,
  PROTOCOL_GRAMMAR_LIMITATIONS,
} from "./ProtocolGrammarExporter.js";
import { qlogMessageSessions } from "./QlogMessageSource.js";
import {
  PROTOCOL_MODEL_STORE_MODEL_FILE,
  readProtocolModelFile,
  writeProtocolModelStore,
} from "./ProtocolModelStore.js";

export const PROTOLEARN_PROVIDER_IDENTITY = {
  id: PROTOLEARN_PROVIDER_ID,
  name: PROTOLEARN_PROVIDER_NAME,
  version: null,
} as const;

/** A result this lane assembled that its own declared contract rejects. */
const outputSchemaFailure = (
  operation: string,
  cause: unknown,
): AnalysisOutputError =>
  new AnalysisOutputError(
    operation,
    "The protocol learning lane assembled a result its declared contract rejects",
    { cause },
  );

const PROTOCOL_LEARNING_EXECUTION_LIMITATIONS = [
  "A learned model describes the messages this one capture showed; a state it never observed is absent, not impossible",
  "States are bounded suffixes of the observed message-class sequence, so the model is deterministic by construction rather than a proven protocol grammar",
  "Field-type sketches keep only delimiter-separated type tokens and byte counts; no payload value, token text, or header field is retained",
];

const MAX_QLOG_BYTES = 32 * 1024 * 1024;

export interface ProtocolLearningProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly settings?: AnalysisSettingsReader;
  /** Packet-file message projection; omitted means the pcap lane reads it. */
  readonly pcapMessages?: ProtocolMessageSourcePort;
  /** How one probe child is launched; tests inject a scripted planner. */
  readonly probeLaunchPlanner?: ProtocolProbeLaunchPlanner;
}

const settingTimeout = (
  settings: AnalysisSettingsReader | undefined,
): number | undefined =>
  settings?.().overrides[PROTOLEARN_PROBE_TIMEOUT_SETTING];

/** Learn protocol models, probe them in a lab, and export their seeds. */
export class ProtocolLearningProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #settings: AnalysisSettingsReader | undefined;
  readonly #pcapMessages: ProtocolMessageSourcePort | undefined;
  readonly #probeLaunchPlanner: ProtocolProbeLaunchPlanner | undefined;
  readonly #shutdown = new AbortController();

  constructor(options: ProtocolLearningProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#settings = options.settings;
    this.#pcapMessages = options.pcapMessages;
    this.#probeLaunchPlanner = options.probeLaunchPlanner;
  }

  /** Report the probe lane's selection without opening a socket. */
  async inspectProbeAvailability(): Promise<ProviderAvailability> {
    let configuration: ProtolearnProbeConfiguration;
    try {
      configuration = resolveProtolearnProbeConfiguration(
        this.#environment,
        settingTimeout(this.#settings),
      );
    } catch (cause: unknown) {
      if (cause instanceof ProtolearnProbeConfigurationFailure) {
        if (cause.code === "unsupported_host")
          return {
            status: "unavailable",
            code: "unsupported_host",
            reason: cause.message,
            diagnostics: {},
          };
        return {
          status: "unavailable",
          code: "not_configured",
          reason: cause.message,
          diagnostics: {
            remediation: cause.diagnostics.remediation ?? null,
          },
        };
      }
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The probe lane selection could not be read",
        diagnostics: {},
      };
    }
    return await inspectProtolearnProbeConfiguration(configuration);
  }

  async close(): Promise<void> {
    this.#shutdown.abort(new Error("REA is closing the protocol learning lane"));
    if (this.#pcapMessages !== undefined) await this.#pcapMessages.close();
  }

  async execute(
    request: ProtolearnRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const caller = options?.signal;
    if (this.#shutdown.signal.aborted || caller?.aborted === true)
      return err(
        new AnalysisCancelledError(request.operation, {
          cause: caller?.reason ?? this.#shutdown.signal.reason,
        }),
      );
    const parsed = protolearnRequestSchema.safeParse(request);
    if (!parsed.success)
      return err(
        analysisOperationInputErrorFromIssues(
          request.operation,
          parsed.error.issues,
          (request as { input?: unknown }).input,
          parsed.error,
        ),
      );
    const signal =
      caller === undefined
        ? this.#shutdown.signal
        : AbortSignal.any([caller, this.#shutdown.signal]);
    switch (parsed.data.operation) {
      case "learn_protocol_model":
        return await this.#learn(parsed.data.input, signal);
      case "probe_learned_model":
        return await this.#probe(parsed.data.input, signal);
      case "export_protocol_grammar":
        return await this.#export(parsed.data.input, signal);
    }
  }

  async #learn(
    input: Extract<
      ProtolearnRequest,
      { operation: "learn_protocol_model" }
    >["input"],
    signal: AbortSignal,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const operation = "learn_protocol_model";
    let sessions: readonly ProtocolSessionFact[];
    let source: ProtocolModel["source"];
    let sourceLimitations: readonly string[];
    if (input.source.kind === "qlog") {
      const read = await this.#readQlog(input.source.path, signal);
      if (!read.ok) return read;
      let decoded: ReturnType<typeof qlogMessageSessions>;
      try {
        decoded = qlogMessageSessions(read.value.text, input.sensitive_values);
      } catch (cause: unknown) {
        if (cause instanceof CaptureFormatError)
          return err(
            cause.reason === "unsupported"
              ? new AnalysisUnsupportedTargetError(
                  operation,
                  input.source.path,
                  cause.message,
                  { cause },
                )
              : new AnalysisProtocolError(
                  `The selected qlog capture is outside this decoder's bounds: ${cause.message}`,
                  { cause },
                ),
          );
        return err(
          new AnalysisProtocolError(
            `The selected qlog capture could not be decoded: ${cause instanceof Error ? cause.message : String(cause)}`,
            { cause },
          ),
        );
      }
      sessions = decoded.sessions;
      sourceLimitations = decoded.limitations;
      source = {
        kind: "qlog",
        path: input.source.path,
        sha256: read.value.sha256,
        profile: PROTOLEARN_QLOG_PROFILE,
        traces: decoded.traces,
      };
    } else {
      if (this.#pcapMessages === undefined)
        return err(
          new AnalysisCapabilityUnavailableError(
            PROTOLEARN_PROVIDER_ID,
            operation,
            "The packet-capture lane is not available in this composition, so a pcap source cannot be read",
          ),
        );
      const read = await this.#pcapMessages.read(input.source.path, {
        signal,
        timeoutMs: 300_000,
      });
      if (!read.ok) return read;
      sessions = read.value.sessions;
      sourceLimitations = read.value.limitations;
      source = {
        kind: "pcap",
        path: input.source.path,
        sha256: read.value.sha256,
        format: read.value.format,
        packets: read.value.packets,
      };
    }
    const learned = learnProtocolModel(sessions, {
      max_states: input.max_states,
      suffix_length: input.suffix_length,
    });
    let modelStore: ProtocolModel["model_store"] = null;
    let classes = learned.classes;
    if (input.model_directory !== undefined) {
      modelStore = {
        directory: input.model_directory,
        model_file: PROTOCOL_MODEL_STORE_MODEL_FILE,
        template_count: learned.classes.filter(
          ({ template }) => template !== null,
        ).length,
      };
    } else {
      classes = learned.classes.map((messageClass) => ({
        ...messageClass,
        template: null,
      }));
    }
    const parsedModel = protocolModelSchema.safeParse({
      source,
      sessions: learned.sessions,
      messages: learned.messages,
      alphabet: learned.alphabet,
      classes,
      states: learned.states,
      transitions: learned.transitions,
      merge: learned.merge,
      coverage: learned.coverage,
      model_store: modelStore,
      limitations: [
        ...PROTOCOL_LEARNING_EXECUTION_LIMITATIONS,
        ...sourceLimitations,
        ...(learned.merge.suffix_reduced
          ? [
              `The requested ${String(learned.merge.requested_suffix_length)}-message suffix exceeded ${String(learned.merge.max_states)} states, so ${String(learned.merge.retained_suffix_length)} was retained`,
            ]
          : []),
        ...(learned.coverage === "partial"
          ? [
              `Coverage is partial: ${String(learned.messages.omitted)} message(s) and ${String(learned.alphabet.omitted)} class(es) were not admitted`,
            ]
          : []),
        ...(input.model_directory === undefined
          ? [
              "No model store was written, so probe_learned_model and export_protocol_grammar cannot read this model back",
            ]
          : []),
      ],
    });
    if (!parsedModel.success)
      return err(
        outputSchemaFailure("learn_protocol_model", parsedModel.error),
      );
    const model = parsedModel.data;
    if (modelStore !== null)
      await writeProtocolModelStore({
        operation,
        directory: modelStore.directory,
        model,
        templates: learned.templates,
        signal,
      });
    return ok(
      createAnalysisExecution(
        { model },
        PROTOLEARN_PROVIDER_IDENTITY,
        {
          subject: {
            path: input.source.path,
            format: "file",
            sha256: source.sha256,
          },
          limitations: model.limitations,
          locations: [{ kind: "artifact-path", path: input.source.path }],
        },
      ),
    );
  }

  async #readQlog(
    path: string,
    signal: AbortSignal,
  ): Promise<Result<{ text: string; sha256: string }, AnalysisError>> {
    const operation = "learn_protocol_model";
    try {
      const stats = await stat(path);
      if (stats.size > MAX_QLOG_BYTES)
        return err(
          new AnalysisResourceConstraintError(
            operation,
            "memory",
            `The selected qlog capture exceeds ${String(MAX_QLOG_BYTES)} bytes`,
            { max_bytes: MAX_QLOG_BYTES, bytes: stats.size },
          ),
        );
      const bytes = await readFile(path, { signal });
      return ok({ text: bytes.toString("utf8"), sha256: payloadDigest(bytes) });
    } catch (cause: unknown) {
      if (cause instanceof AnalysisCancelledError) return err(cause);
      const code =
        cause instanceof Error && "code" in cause ? String(cause.code) : null;
      if (code === "EACCES" || code === "EPERM")
        return err(
          new AnalysisAccessDeniedError(operation, path, code, { cause }),
        );
      return err(
        new AnalysisInputError(
          operation,
          { cause },
          [
            {
              path: ["source", "path"],
              reason: "invalid_value",
              message: `Cannot read the selected qlog capture ${path}: ${cause instanceof Error ? cause.message : String(cause)}`,
            },
          ],
        ),
      );
    }
  }

  async #probe(
    input: Extract<
      ProtolearnRequest,
      { operation: "probe_learned_model" }
    >["input"],
    signal: AbortSignal,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const operation = "probe_learned_model";
    let configuration: ProtolearnProbeConfiguration;
    try {
      configuration = resolveProtolearnProbeConfiguration(
        this.#environment,
        settingTimeout(this.#settings),
      );
    } catch (cause: unknown) {
      if (cause instanceof ProtolearnProbeConfigurationFailure)
        return err(
          providerConfigurationRefusal(PROTOLEARN_PROVIDER_ID, operation, cause),
        );
      return err(
        new AnalysisProtocolError(
          `The probe lane selection failed for ${operation}`,
          { cause },
        ),
      );
    }
    const approval = labEndpointApproval(input.endpoint, configuration.endpoints);
    if (!approval.approved) {
      return err(
        providerConfigurationRefusal(
          PROTOLEARN_PROVIDER_ID,
          operation,
          new ProtolearnConfigurationFailure(
            "endpoint_not_allowlisted",
            approval.reason,
            {
              remediation: `Add ${input.endpoint.host}:${String(input.endpoint.port)} to REA_PROTOLEARN_LAB_ENDPOINTS in the REA launch environment and restart REA.`,
            },
          ),
        ),
      );
    }
    if (!isLoopbackLabHost(approval.endpoint.host))
      return err(
        providerConfigurationRefusal(
          PROTOLEARN_PROVIDER_ID,
          operation,
          new ProtolearnConfigurationFailure(
            "endpoint_not_allowlisted",
            `The deny-default sandbox profile names only localhost, so a probe to ${approval.endpoint.host} cannot be confined`,
            {
              remediation:
                "Probe a loopback lab endpoint, or forward the lab service to a loopback port from a host you control. REA never probes unconfined.",
            },
          ),
        ),
      );
    const timeoutMs = input.timeout_ms ?? configuration.probeTimeoutMs;
    let model: ProtocolModel;
    try {
      model = await readProtocolModelFile({
        operation,
        path: input.model_path,
        signal,
      });
    } catch (cause: unknown) {
      return err(cause as AnalysisError);
    }
    const index = protocolModelIndex(model);
    const probes: ProtocolProbeResult["probes"][number][] = [];
    const confinementLimitations: string[] = [];
    let confinement: "enforced" | "disabled" = "enforced";
    for (const probe of input.probes) {
      if (signal.aborted)
        return err(
          new AnalysisCancelledError(operation, { cause: signal.reason }),
        );
      const steps: (typeof probe.steps)[number][] = probe.steps;
      const repeats: {
        repeat: number;
        observations: {
          responseBytes: Buffer | null;
          timedOut: boolean;
        }[];
      }[] = [];
      for (let repeat = 0; repeat < input.repeats; repeat += 1) {
        if (signal.aborted)
          return err(
            new AnalysisCancelledError(operation, { cause: signal.reason }),
          );
        let connection: Awaited<ReturnType<typeof runProtocolProbeConnection>>;
        try {
          connection = await runProtocolProbeConnection({
            configuration,
            endpoint: approval.endpoint,
            steps: steps.map((step) => ({
              bytes: Buffer.from(step.template_hex, "hex"),
              waitForResponse: step.wait_for_response,
            })),
            timeoutMs,
            environment: this.#environment,
            ...(this.#probeLaunchPlanner === undefined
              ? {}
              : { launchPlanner: this.#probeLaunchPlanner }),
            signal,
          });
        } catch (cause: unknown) {
          if (cause instanceof AnalysisError) return err(cause);
          return err(
            new AnalysisProtocolError(
              `The probe connection failed for ${probe.label}: ${cause instanceof Error ? cause.message : String(cause)}`,
              { cause },
            ),
          );
        }
        if (connection.limitations.length > 0) {
          confinement = "disabled";
          for (const limitation of connection.limitations)
            if (!confinementLimitations.includes(limitation))
              confinementLimitations.push(limitation);
        }
        repeats.push({
          repeat,
          observations: connection.steps.map((step) => ({
            responseBytes:
              step.response_base64 === null
                ? null
                : Buffer.from(step.response_base64, "base64").subarray(
                    0,
                    PROTOLEARN_LIMITS.maxProbeResponseBytes,
                  ),
            timedOut: step.timed_out,
          })),
        });
      }
      const labelSteps: ProtocolProbeResult["probes"][number]["steps"] = [];
      let state = index.initialState;
      for (const [ordinal, step] of steps.entries()) {
        const sentBytes = Buffer.from(step.template_hex, "hex");
        const sentSketch = payloadSketch(sentBytes);
        const observations: ProbeStepObservation[] = repeats.map(
          (repeat) => {
            const observed = repeat.observations[ordinal];
            const bytes = observed?.responseBytes ?? null;
            const sketch =
              bytes === null ? null : payloadSketch(bytes);
            const responseClass =
              sketch === null
                ? null
                : (index.classByKey.get(
                    messageClassKey("response", sketch),
                  )?.class_id ?? null);
            return {
              repeat: repeat.repeat,
              timed_out: observed?.timedOut ?? true,
              response_bytes: bytes?.length ?? 0,
              response_sha256: bytes === null ? null : payloadDigest(bytes),
              response_class: responseClass,
              response_sketch: sketch,
            };
          },
        );
        const diagnosis = diagnoseProbeStep(
          index,
          state,
          sentSketch,
          observations,
        );
        state = diagnosis.next_state;
        labelSteps.push({
          ordinal,
          sent_bytes: sentBytes.length,
          sent_sha256: payloadDigest(sentBytes),
          sent_class: diagnosis.sent_class,
          model:
            diagnosis.model === null
              ? null
              : {
                  from: diagnosis.model.from,
                  to: diagnosis.model.to,
                  expected_response_classes: [
                    ...diagnosis.model.expected_response_classes,
                  ],
                },
          observations: observations.map((observation) => ({
            repeat: observation.repeat,
            timed_out: observation.timed_out,
            response_bytes: observation.response_bytes,
            response_sha256: observation.response_sha256,
            response_class: observation.response_class,
            response_sketch: observation.response_sketch,
          })),
          verdict: diagnosis.verdict,
        });
      }
      probes.push({
        label: probe.label,
        repeats: input.repeats,
        stable: labelSteps.every(({ verdict }) => verdict !== "unstable"),
        steps: labelSteps,
      });
    }
    const counts = {
      consistent: 0,
      divergent: 0,
      unmodeled: 0,
      unstable: 0,
      steps: 0,
    };
    for (const probe of probes)
      for (const step of probe.steps) {
        counts[step.verdict] += 1;
        counts.steps += 1;
      }
    const parsedProbe = protocolProbeResultSchema.safeParse({
      endpoint: {
        host: approval.endpoint.host,
        port: approval.endpoint.port,
        operator_allowlisted: true,
      },
      sandbox: {
        confinement,
        profile: "deny-default" as const,
        limitation:
          confinementLimitations.length === 0
            ? null
            : confinementLimitations.join(" "),
      },
      probes,
      counts,
      limitations: [
        "Requests are the caller's templates; responses are reported as lengths, SHA-256 digests, and type sketches only, so no response payload is echoed",
        "A consistent step shows the model's expected response class appeared; it does not establish the response is correct",
        "A divergent step is a question about the model or the service, not proof that either is wrong",
        ...(confinement === "disabled"
          ? ["The deny-default sandbox was disabled for these launches; see sandbox.limitation"]
          : []),
        ...confinementLimitations,
      ],
    });
    if (!parsedProbe.success)
      return err(
        outputSchemaFailure("probe_learned_model", parsedProbe.error),
      );
    const result = parsedProbe.data;
    return ok(
      createAnalysisExecution(result, PROTOLEARN_PROVIDER_IDENTITY, {
        limitations: result.limitations,
        locations: [],
      }),
    );
  }

  async #export(
    input: Extract<
      ProtolearnRequest,
      { operation: "export_protocol_grammar" }
    >["input"],
    signal: AbortSignal,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    try {
      const model = await readProtocolModelFile({
        operation: "export_protocol_grammar",
        path: input.model_path,
        signal,
      });
      const exported = await exportProtocolGrammar({
        model,
        outputDirectory: input.output_directory,
        signal,
      });
      const parsedExport = protocolGrammarExportSchema.safeParse(exported);
      if (!parsedExport.success)
        return err(
          outputSchemaFailure(
            "export_protocol_grammar",
            parsedExport.error,
          ),
        );
      const result = parsedExport.data;
      return ok(
        createAnalysisExecution(result, PROTOLEARN_PROVIDER_IDENTITY, {
          limitations: [...PROTOCOL_GRAMMAR_LIMITATIONS, ...result.limitations],
          locations: [{ kind: "artifact-path", path: result.seed_directory }],
        }),
      );
    } catch (cause: unknown) {
      if (cause instanceof AnalysisError) return err(cause);
      return err(
        new AnalysisProtocolError(
          "The grammar export failed without a typed reason",
          { cause },
        ),
      );
    }
  }
}

