import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { artifactFileCancellationCause } from "../../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../../application/AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisError as AnalysisErrorClass } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import {
  decompileV8BytecodeResultSchema,
  type DecompileV8BytecodeResult,
  type V8BytecodeRequest,
} from "../../domain/javascript/v8Bytecode.js";
import { providerConfigurationRefusal } from "../../domain/providerConfigurationRefusal.js";
import { err, ok, type Result } from "../../domain/result.js";
import { RegularFileOperationCancelled } from "../../filesystem/RegularFile.js";
import {
  MAX_V8_HEADER_BYTES,
  readV8BytecodeHeader,
} from "./V8BytecodeHeader.js";
import { runView8Command, view8Arguments } from "./View8Command.js";
import {
  resolveView8Configuration,
  view8ConfigurationAvailability,
  type View8Configuration,
  View8ConfigurationFailure,
} from "./View8Configuration.js";
import {
  VIEW8_LANE_UNVERIFIED_NOTE,
  VIEW8_MAX_INPUT_BYTES,
  VIEW8_OUTPUT_REMEDIATION,
  VIEW8_PROVIDER_ID,
  VIEW8_PROVIDER_NAME,
} from "./View8Release.js";

export const VIEW8_PROVIDER_IDENTITY = {
  id: VIEW8_PROVIDER_ID,
  name: VIEW8_PROVIDER_NAME,
  version: null,
} as const;

export interface View8ProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

/** Serialized V8 disassembly over a caller-supplied View8 build. */
export class View8Provider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: View8ProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
  }

  /** Probe the selected launcher without reading bytecode. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    if (signal?.aborted === true)
      return {
        status: "unavailable",
        code: "not_configured",
        reason: "The availability probe was cancelled",
        diagnostics: {},
      };
    try {
      const configuration = resolveView8Configuration(this.#environment);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          patched_v8_required: true,
          version_probed: false,
        },
      };
    } catch (cause: unknown) {
      if (cause instanceof View8ConfigurationFailure)
        return view8ConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code: "not_configured",
        reason:
          cause instanceof Error
            ? cause.message
            : "The View8 launcher selection failed",
        diagnostics: {},
      };
    }
  }

  /** Stop admission, await active work, and release retained descriptors. */
  close(): Promise<void> {
    this.#closing = true;
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = (async () => {
      await Promise.all(this.#activeOperations);
      await this.#resources.close();
    })().finally(() => {
      if (this.#closePromise === closing) this.#closePromise = undefined;
    });
    this.#closePromise = closing;
    return this.#closePromise;
  }

  async execute(
    request: V8BytecodeRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    if (this.#closing || signal?.aborted === true)
      return err(
        new AnalysisCancelledError(request.operation, {
          cause: signal?.reason,
        }),
      );
    let release!: () => void;
    const active = new Promise<void>((done) => {
      release = done;
    });
    this.#activeOperations.add(active);
    try {
      const configuration = this.#requireConfiguration(request.operation);
      if (!configuration.ok) return configuration;
      return await this.#decompile(
        configuration.value,
        request.input.path,
        signal,
        request.operation,
      );
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  #requireConfiguration(
    operation: string,
  ): Result<View8Configuration, AnalysisError> {
    try {
      return ok(resolveView8Configuration(this.#environment));
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof View8ConfigurationFailure)
        return err(
          providerConfigurationRefusal(VIEW8_PROVIDER_ID, operation, cause),
        );
      return err(
        new AnalysisProtocolError(
          `The View8 launcher selection failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #decompile(
    configuration: View8Configuration,
    path: string,
    signal: AbortSignal | undefined,
    operation: string,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const snapshot = await this.#read(operation, path, signal);
    if (!snapshot.ok) return snapshot;
    const header = readV8BytecodeHeader(
      snapshot.value.bytes.subarray(0, MAX_V8_HEADER_BYTES),
      snapshot.value.bytes.byteLength,
    );
    const ran = await runView8Command(
      operation,
      configuration.command,
      view8Arguments(path),
      { timeoutMs: configuration.operationTimeoutMs },
      signal,
    );
    if (!ran.ok) return ran;
    if (ran.value.stdoutBytes === 0)
      return err(
        new AnalysisProtocolError(
          `The selected View8 launcher returned no disassembly. ${VIEW8_OUTPUT_REMEDIATION}`,
          { diagnostics: { selected_command: configuration.command } },
        ),
      );
    const result: DecompileV8BytecodeResult = {
      client: { command: configuration.command, version: null },
      path,
      sha256: snapshot.value.sha256,
      bytes: snapshot.value.bytes.byteLength,
      container: { ...header, prefix_words: [...header.prefix_words] },
      disassembly: {
        bytes: ran.value.stdoutBytes,
        sha256: ran.value.stdoutSha256,
        lines: ran.value.lines,
        empty: false,
      },
      coverage:
        header.state === "recognized"
          ? ("complete" as const)
          : ("partial" as const),
    };
    const parsed = decompileV8BytecodeResultSchema.safeParse(result);
    if (!parsed.success)
      throw new AnalysisOutputError(
        operation,
        "The View8 lane produced a result outside its schema.",
        { cause: parsed.error },
      );
    return ok(
      createAnalysisExecution(
        parsed.data,
        { ...VIEW8_PROVIDER_IDENTITY, version: null },
        {
          limitations: [
            VIEW8_LANE_UNVERIFIED_NOTE,
            "Disassembly text stays out of Evidence; only its SHA-256, byte count and line count are reported",
            "A cached-data header does not establish that this V8 build produced the payload, that the embedded source is recoverable, or that the selected View8 patched V8 revision matches it",
            ...(header.state === "recognized"
              ? [
                  `Header words follow the pinned ${header.layout ?? "cached-data"} layout; a matching layout does not establish the V8 build, the embedded source, or View8's own V8 revision`,
                ]
              : header.state === "layout_unverifiable"
                ? [
                    "The artifact carries a V8 cached-data marker, but no pinned header layout declares its observed payload size. Prefix words stay uninterpreted: the file may be truncated, appended to, or produced by a V8 line whose layout is not pinned",
                  ]
                : [
                    "The selected artifact does not carry a recognizable V8 cached-data marker; it is reported as unrecognized rather than repaired or reinterpreted",
                  ]),
          ],
          locations: [{ kind: "artifact-path", path }],
        },
      ),
    );
  }

  async #read(
    operation: string,
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<{ bytes: Buffer; sha256: string }, AnalysisError>> {
    try {
      const snapshot = await readStableArtifact(
        path,
        VIEW8_MAX_INPUT_BYTES,
        signal,
        undefined,
        this.#resources,
      );
      return ok({ bytes: snapshot.bytes, sha256: snapshot.sha256 });
    } catch (cause: unknown) {
      if (cause instanceof RegularFileOperationCancelled)
        return err(
          new AnalysisCancelledError(operation, { cause: cause.reason }),
        );
      if (cause instanceof ArtifactReaderFailure) {
        if (cause.reason === "cancelled")
          return err(
            new AnalysisCancelledError(operation, {
              cause: artifactFileCancellationCause(cause),
            }),
          );
        if (cause.reason === "limit")
          return err(
            new AnalysisResourceConstraintError(
              operation,
              "memory",
              `The selected bytecode artifact exceeds the ${String(VIEW8_MAX_INPUT_BYTES)}-byte read allowance`,
              { max_input_bytes: VIEW8_MAX_INPUT_BYTES },
              { cause },
            ),
          );
        return err(
          new AnalysisInputError(operation, {
            cause,
            userMessage: `The selected bytecode artifact could not be read as a regular file: ${path}`,
          }),
        );
      }
      return err(
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The selected bytecode artifact could not be read and digested: ${path}`,
        }),
      );
    }
  }
}
