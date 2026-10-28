import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import {
  assembleBytesResultSchema,
  emulateFunctionResultSchema,
  emuRequestSchema,
  type EmulateFunctionResult,
  type EmuRequest,
  type EmuRequestInput,
} from "../domain/emu/emuEmulation.js";
import { analysisOperationInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { emuBridgeResponseSchema } from "../domain/emu/emuBridgeProtocol.js";
import {
  EMU_BIG_ENDIAN_ARCHITECTURES,
  EMU_LIMITS,
  EMU_PROTOCOL_VERSION,
  EMU_PROVIDER_ID,
  EMU_PROVIDER_NAME,
  type EmuArchitecture,
} from "../domain/emu/emuLimits.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  emuConfigurationAvailability,
  EmuConfigurationFailure,
  resolveEmuConfiguration,
  type EmuConfiguration,
} from "./EmuConfiguration.js";
import {
  addressAt,
  readCodeSlice,
  sha256Hex,
  type CodeBytes,
} from "./CodeSlice.js";
import { bridgeJobFailure } from "./EmuRefusal.js";
import {
  runUnicornBridgeJob,
  UnicornBridgeProtocolFailure,
} from "./UnicornBridgeJob.js";

export const EMU_PROVIDER_IDENTITY = {
  id: EMU_PROVIDER_ID,
  name: EMU_PROVIDER_NAME,
  version: null,
} as const;

export interface EmuProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

const UNEMULATED_SCOPE_NOTE =
  "One bounded, isolated execution of the selected code with stubbed arguments; this is not a program run and no operating system, loader, import, or syscall is modelled";

const BRIDGE_STDOUT_SCHEMA_ERROR =
  "The Unicorn bridge returned a frame that does not match the emulation contract";

const requireEndianness = (
  operation: string,
  arch: EmuArchitecture,
  endianness: "little" | "big",
): AnalysisError | null =>
  endianness === "big" && !EMU_BIG_ENDIAN_ARCHITECTURES.has(arch)
    ? new AnalysisInputError(operation, undefined, [
        {
          path: ["endianness"],
          reason: "invalid_value",
          message: `Unicorn 2.1 has no big-endian ${arch} mode; select little or a big-endian-capable architecture`,
        },
      ])
    : null;

const providerOf = (unicornVersion: string) => ({
  ...EMU_PROVIDER_IDENTITY,
  version: unicornVersion,
});

/** Isolated, bounded Unicorn emulation and Keystone assembly over one sidecar. */
export class EmuProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  #closing = false;

  constructor(options: EmuProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
  }

  /** Report the caller's selection without starting the sidecar. */
  inspectAvailability(): ProviderAvailability {
    try {
      const configuration = resolveEmuConfiguration(this.#environment);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          bridge_script: configuration.bridgeScript,
          interpreter: configuration.python,
          pinned_unicorn_version: "2.1.x",
          probe: "selection_only",
          unicorn_version_unverified: true,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof EmuConfigurationFailure)
        return emuConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "version_unresolved",
        reason:
          cause instanceof Error
            ? cause.message
            : "The Unicorn bridge selection could not be read",
        diagnostics: {},
      };
    }
  }

  /** Stop admission; each job owns its process, so nothing is retained. */
  close(): Promise<void> {
    this.#closing = true;
    return Promise.resolve();
  }

  async execute(
    request: EmuRequestInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    if (this.#closing || signal?.aborted === true)
      return err(
        new AnalysisCancelledError(request.operation, {
          cause: signal?.reason,
        }),
      );
    const parsed = emuRequestSchema.safeParse(request);
    if (!parsed.success)
      return err(
        analysisOperationInputErrorFromIssues(
          request.operation,
          parsed.error.issues,
          request.input,
          parsed.error,
        ),
      );
    const normalized: EmuRequest = parsed.data;
    let configuration: EmuConfiguration;
    try {
      configuration = resolveEmuConfiguration(this.#environment);
    } catch (cause: unknown) {
      if (cause instanceof EmuConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            EMU_PROVIDER_ID,
            request.operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `The Unicorn bridge selection failed for ${request.operation}`,
          { cause },
        ),
      );
    }
    const endiannessProblem = requireEndianness(
      normalized.operation,
      normalized.input.arch,
      normalized.input.endianness,
    );
    if (endiannessProblem !== null) return err(endiannessProblem);
    switch (normalized.operation) {
      case "emulate_function_isolated":
        return await this.#emulate(
          configuration,
          normalized.input,
          normalized.operation,
          signal,
        );
      case "assemble_bytes":
        return await this.#assemble(
          configuration,
          normalized.input,
          normalized.operation,
          signal,
        );
    }
  }

  async #emulate(
    configuration: EmuConfiguration,
    input: Extract<
      EmuRequest,
      { operation: "emulate_function_isolated" }
    >["input"],
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    let code: CodeBytes;
    if (input.source.kind === "file") {
      const read = await readCodeSlice(
        operation,
        input.source.path,
        input.source.offset,
        input.source.length,
        signal,
      );
      if (!read.ok) return read;
      code = read.value;
    } else {
      const bytes = Buffer.from(input.source.hex, "hex");
      code = { bytes, sha256: sha256Hex(bytes), path: null, offset: null };
    }
    const entry = addressAt(
      operation,
      input.code_base,
      input.entry_offset,
      code.bytes.byteLength,
    );
    if (!entry.ok) return entry;
    const frame = await this.#job(configuration, operation, signal, {
      kind: "emulate",
      arch: input.arch,
      endianness: input.endianness,
      code_hex: code.bytes.toString("hex"),
      code_sha256: code.sha256,
      code_base: input.code_base,
      entry: entry.value,
      stack_size: input.stack_size,
      args: input.args,
      max_steps: input.max_steps,
      timeout_ms: input.timeout_ms,
      stop_addresses: input.stop_addresses,
      observe_registers: input.observe_registers,
      observe_memory: input.observe_memory,
      limits: {
        max_edges: EMU_LIMITS.maxEdges,
        max_call_targets: EMU_LIMITS.maxCallTargets,
      },
    });
    if (!frame.ok) return frame;
    const parsed = emulateFunctionResultSchema.safeParse(frame.value);
    if (!parsed.success)
      return err(
        new AnalysisProtocolError(BRIDGE_STDOUT_SCHEMA_ERROR, {
          cause: parsed.error,
          diagnostics: {
            operation,
            issue_count: parsed.error.issues.length,
            bridge_protocol: EMU_PROTOCOL_VERSION,
          },
        }),
      );
    const result = {
      ...parsed.data,
      // REA owns the code facts it selected; the bridge only proved it ran them.
      code: {
        source: input.source.kind,
        path: code.path,
        offset: code.offset,
        length: code.bytes.byteLength,
        sha256: code.sha256,
      },
    };
    if (
      parsed.data.code.sha256 !== code.sha256 ||
      parsed.data.code.length !== code.bytes.byteLength
    )
      return err(
        new AnalysisProtocolError(
          "The Unicorn bridge emulated code other than the bytes REA selected",
          {
            diagnostics: {
              operation,
              selected_sha256: code.sha256,
              observed_sha256: result.code.sha256,
            },
          },
        ),
      );
    return ok(this.#execution(code, result));
  }

  async #assemble(
    configuration: EmuConfiguration,
    input: Extract<EmuRequest, { operation: "assemble_bytes" }>["input"],
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const frame = await this.#job(configuration, operation, signal, {
      kind: "assemble",
      arch: input.arch,
      endianness: input.endianness,
      base_address: input.base_address,
      assembly: input.assembly,
      max_bytes: EMU_LIMITS.maxAssembledBytes,
    });
    if (!frame.ok) return frame;
    const parsed = assembleBytesResultSchema.safeParse(frame.value);
    if (!parsed.success)
      return err(
        new AnalysisProtocolError(BRIDGE_STDOUT_SCHEMA_ERROR, {
          cause: parsed.error,
          diagnostics: {
            operation,
            issue_count: parsed.error.issues.length,
            bridge_protocol: EMU_PROTOCOL_VERSION,
          },
        }),
      );
    const result = parsed.data;
    if (result.size > EMU_LIMITS.maxAssembledBytes)
      return err(
        new AnalysisProtocolError(
          "The Unicorn bridge returned more bytes than the assembly budget admits",
          {
            diagnostics: {
              operation,
              size: result.size,
              max_assembled_bytes: EMU_LIMITS.maxAssembledBytes,
            },
          },
        ),
      );
    return ok(
      createAnalysisExecution(
        result,
        providerOf(result.bridge.unicorn_version),
        {
          limitations: [
            "Keystone encodes the caller's assembly for the selected architecture; a successful encoding is not a claim that the bytes are valid at that address in the original program",
            `At most ${String(EMU_LIMITS.maxAssembledBytes)} bytes are encoded per request`,
          ],
        },
      ),
    );
  }

  async #job(
    configuration: EmuConfiguration,
    operation: string,
    signal: AbortSignal | undefined,
    body: Readonly<Record<string, unknown>>,
  ): Promise<Result<unknown, AnalysisError>> {
    try {
      const frame = await runUnicornBridgeJob({
        configuration,
        operation,
        body,
        timeoutMs:
          typeof body.timeout_ms === "number"
            ? body.timeout_ms
            : EMU_LIMITS.defaultTimeoutMs,
        hostEnvironment: this.#environment,
        ...(signal === undefined ? {} : { signal }),
      });
      const envelope = emuBridgeResponseSchema.safeParse(frame);
      if (!envelope.success)
        return err(
          new AnalysisProtocolError(BRIDGE_STDOUT_SCHEMA_ERROR, {
            cause: envelope.error,
            diagnostics: {
              operation,
              issue_count: envelope.error.issues.length,
              bridge_protocol: EMU_PROTOCOL_VERSION,
            },
          }),
        );
      if (envelope.data.kind !== body.kind)
        return err(
          new AnalysisProtocolError(
            `The Unicorn bridge answered a ${envelope.data.kind} job for a ${String(body.kind)} request`,
            { diagnostics: { operation } },
          ),
        );
      if (!envelope.data.ok) {
        const failure = envelope.data.error ?? {
          code: "bridge_error",
          message: "The Unicorn bridge refused the job without a reason",
        };
        return err(bridgeJobFailure(operation, failure.code, failure.message));
      }
      if (envelope.data.result === undefined)
        return err(
          new AnalysisProtocolError(
            "The Unicorn bridge reported success without a result",
            { diagnostics: { operation } },
          ),
        );
      return ok(envelope.data.result);
    } catch (cause: unknown) {
      if (cause instanceof AnalysisError) return err(cause);
      if (cause instanceof UnicornBridgeProtocolFailure)
        return err(
          new AnalysisProtocolError(`${cause.message} for ${operation}`, {
            cause,
            diagnostics: cause.diagnostics,
          }),
        );
      if (signal?.aborted === true)
        return err(
          new AnalysisCancelledError(operation, { cause: signal.reason }),
        );
      return err(
        new AnalysisCapabilityUnavailableError(
          EMU_PROVIDER_ID,
          operation,
          cause instanceof Error
            ? cause.message
            : "The Unicorn bridge failed without a reason",
          { cause },
        ),
      );
    }
  }

  #execution(
    code: CodeBytes,
    result: EmulateFunctionResult,
  ): AnalysisExecution {
    return createAnalysisExecution(
      result,
      providerOf(result.bridge.unicorn_version),
      {
        limitations: [
          UNEMULATED_SCOPE_NOTE,
          result.exit === "max_steps"
            ? "The job stopped at max_steps, so the observed registers, memory, and edges describe an incomplete execution"
            : result.exit === "timeout"
              ? "The job stopped at its deadline, so the observed registers, memory, and edges describe an incomplete execution"
              : "The job reached a terminal state before either bound, so its observations describe that one execution path only",
          "Call counts come from executed call opcodes at instruction boundaries; they carry no symbol names and no argument values",
          "Executed edges are observed address pairs, not a decoded basic-block or control-flow graph",
          "Observed memory windows are reported as length and SHA-256 only, so no recovered content can be read back from Evidence",
          result.unknown_registers.length === 0
            ? "Every requested register was reported"
            : `The bridge has no value for ${result.unknown_registers.join(", ")} in this architecture mode`,
          ...(result.edges_truncated
            ? [
                `Executed-path coverage retained at most ${String(EMU_LIMITS.maxEdges)} distinct edges`,
              ]
            : []),
          ...(result.call_targets_truncated
            ? [
                `Call targets retained at most ${String(EMU_LIMITS.maxCallTargets)} distinct addresses`,
              ]
            : []),
        ],
        locations: [
          ...(code.path === null
            ? []
            : [
                { kind: "artifact-path" as const, path: code.path },
                ...(code.offset === null
                  ? []
                  : [
                      {
                        kind: "file-offset-range" as const,
                        start: code.offset,
                        end: code.offset + code.bytes.byteLength,
                      },
                    ]),
              ]),
          { kind: "address" as const, address: result.entry },
        ],
      },
    );
  }
}
