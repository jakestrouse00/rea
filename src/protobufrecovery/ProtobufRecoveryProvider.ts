import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisError as AnalysisErrorClass } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import type {
  EnumerateGrpcReflectionResult,
  ProtobufRecoveryRequestInput,
  RecoverProtoDefinitionsResult,
} from "../domain/protobufrecovery/protobufRecovery.js";
import {
  enumerateGrpcReflectionResultSchema,
  recoverProtoDefinitionsResultSchema,
} from "../domain/protobufrecovery/protobufRecovery.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import {
  PrivateRuntimeRoot,
  type PrivateRuntimeRootOptions,
} from "../process/PrivateRuntimeRoot.js";
import {
  grpcReflectionArguments,
  recoveryArgumentsFor,
  runProtobufCommand,
} from "./ProtobufRecoveryCommand.js";
import {
  ProtobufConfigurationFailure,
  protobufConfigurationAvailability,
  resolveGrpcReflectionConfiguration,
  resolveProtoRecoveryConfiguration,
  type ProtoRecoveryConfiguration,
} from "./ProtobufRecoveryConfiguration.js";
import {
  PROTOBUF_LANE_UNVERIFIED_NOTE,
  PROTOBUF_OUTPUT_REMEDIATION,
  PROTOBUF_RECOVERY_PROVIDER_ID,
  PROTOBUF_RECOVERY_PROVIDER_NAME,
} from "./ProtobufRecoveryRelease.js";
import { parseProtoFile } from "./ProtoFileParser.js";
import {
  parseGrpcServiceDescription,
  parseGrpcServiceList,
} from "./GrpcReflectionOutput.js";

export const PROTOBUF_RECOVERY_PROVIDER_IDENTITY = {
  id: PROTOBUF_RECOVERY_PROVIDER_ID,
  name: PROTOBUF_RECOVERY_PROVIDER_NAME,
  version: null,
} as const;

export interface ProtobufRecoveryProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly createRuntimeRoot?: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<Pick<PrivateRuntimeRoot, "path" | "close">>;
}

interface FileDigest {
  readonly bytes: number;
  readonly sha256: string;
}

interface CollectedProto {
  readonly relativePath: string;
  readonly contents: Buffer;
}

interface PublishedProto {
  readonly relative_path: string;
  readonly bytes: number;
  readonly sha256: string;
}

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;

const MAX_RECOVERED_PROTO_BYTES = 32 * 1024 * 1024;

/** Protobuf definition recovery and gRPC reflection over caller-supplied tools. */
export class ProtobufRecoveryProvider {
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #createRuntimeRoot: (
    options?: PrivateRuntimeRootOptions,
  ) => Promise<RuntimeRoot>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: ProtobufRecoveryProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      ((rootOptions) => PrivateRuntimeRoot.create(rootOptions));
  }

  /** Probe configured recovery and reflection tools without starting them. */
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
    const recovery = this.#recoveryAvailability();
    const reflection = this.#reflectionAvailability();
    if (recovery.status === "available" || reflection.status === "available")
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          recovery: recovery.status === "available",
          reflection: reflection.status === "available",
        },
      };
    return recovery;
  }

  /** Probe the recovery-tool selection only. */
  inspectRecoveryAvailability(_signal?: AbortSignal): ProviderAvailability {
    return this.#recoveryAvailability();
  }

  /** Probe the grpcurl selection only. */
  inspectReflectionAvailability(_signal?: AbortSignal): ProviderAvailability {
    return this.#reflectionAvailability();
  }

  #recoveryAvailability(): ProviderAvailability {
    try {
      const configuration = resolveProtoRecoveryConfiguration(
        this.#environment,
        "auto",
      );
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_tool: configuration.tool,
          selected_command: configuration.command,
          version_probed: false,
        },
      };
    } catch (cause: unknown) {
      return cause instanceof ProtobufConfigurationFailure
        ? protobufConfigurationAvailability(cause)
        : {
            status: "unavailable",
            code: "not_configured",
            reason:
              cause instanceof Error
                ? cause.message
                : "The protobuf recovery selection failed",
            diagnostics: {},
          };
    }
  }

  #reflectionAvailability(): ProviderAvailability {
    try {
      const configuration = resolveGrpcReflectionConfiguration(
        this.#environment,
      );
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          selected_command: configuration.command,
          version_probed: false,
        },
      };
    } catch (cause: unknown) {
      return cause instanceof ProtobufConfigurationFailure
        ? protobufConfigurationAvailability(cause)
        : {
            status: "unavailable",
            code: "not_configured",
            reason:
              cause instanceof Error
                ? cause.message
                : "The grpcurl selection failed",
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
    request: ProtobufRecoveryRequestInput,
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
      switch (request.operation) {
        case "recover_proto_definitions":
          return await this.#recoverProtos(
            request.operation,
            request.input.path,
            request.input.output_directory,
            request.input.tool ?? "auto",
            request.input.max_files ?? 100,
            signal,
          );
        case "enumerate_grpc_reflection":
          return await this.#enumerateReflection(
            request.operation,
            request.input,
            signal,
          );
      }
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  async #recoverProtos(
    operation: string,
    path: string,
    outputDirectory: string,
    requestedTool: "auto" | "pbtk" | "protodump",
    maxFiles: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const configuration = this.#recoveryConfiguration(operation, requestedTool);
    if (!configuration.ok) return configuration;
    const digest = await this.#digest(operation, path, signal);
    if (!digest.ok) return digest;
    const prepared = await prepareOutputDirectory(operation, outputDirectory);
    if (!prepared.ok) return prepared;
    const root = await this.#createRoot();
    if (!root.ok) return root;
    let outcome: Result<AnalysisExecution, AnalysisError>;
    try {
      outcome = await this.#recoverInto(
        root.value,
        operation,
        configuration.value,
        path,
        digest.value,
        prepared.value,
        maxFiles,
        signal,
      );
    } catch (cause: unknown) {
      outcome =
        cause instanceof AnalysisErrorClass
          ? err(cause)
          : err(
              new AnalysisProtocolError(
                `Protobuf recovery failed for ${operation}`,
                { cause },
              ),
            );
    }
    try {
      await root.value.close();
    } catch (cause: unknown) {
      return err(
        new ProviderCleanupError(
          PROTOBUF_RECOVERY_PROVIDER_ID,
          [root.value.path],
          {
            reason: cause instanceof Error ? cause.message : String(cause),
          },
          { operation, cause },
        ),
      );
    }
    return outcome;
  }

  async #recoverInto(
    root: RuntimeRoot,
    operation: string,
    configuration: ProtoRecoveryConfiguration,
    path: string,
    digest: FileDigest,
    outputDirectory: string,
    maxFiles: number,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const staging = join(root.path, "recovered");
    await mkdir(staging, { mode: 0o700 });
    const ran = await runProtobufCommand(
      operation,
      configuration.command,
      recoveryArgumentsFor(configuration.tool, path, staging),
      { timeoutMs: configuration.operationTimeoutMs },
      signal,
      configuration.tool,
    );
    if (!ran.ok) return ran;
    const collected = await collectProtoFiles(staging, maxFiles);
    if (collected.files.length === 0)
      return err(
        new AnalysisProtocolError(
          `The selected tool recovered no .proto files. ${PROTOBUF_OUTPUT_REMEDIATION}`,
          {
            diagnostics: {
              tool: configuration.tool,
              stdout_excerpt: ran.value.stdout.slice(0, 256),
              stderr_excerpt: ran.value.stderr.slice(0, 256),
            },
          },
        ),
      );
    const destination = join(
      outputDirectory,
      `rea-protos-${sanitize(basename(path))}-${digest.sha256.slice(0, 12)}`,
    );
    const published = await publishProtoFiles(
      operation,
      destination,
      collected.files,
    );
    if (!published.ok) return published;
    const files = collected.files.map((file, index) => {
      const parsed = parseProtoFile(file.contents.toString("utf8"));
      const record = published.value[index]!;
      return {
        relative_path: record.relative_path,
        bytes: record.bytes,
        sha256: record.sha256,
        package: parsed.package,
        messages: parsed.messages.map((message) => ({
          name: message.name,
          fields: message.fields.map((field) => ({ ...field })),
          nested_message_count: message.nestedMessageCount,
        })),
        enums: parsed.enums.map((enumeration) => ({
          name: enumeration.name,
          values: enumeration.values.map((value) => ({ ...value })),
        })),
        service_count: parsed.serviceCount,
        unparsed_lines: parsed.unparsedLines,
      };
    });
    const messageCount = files.reduce(
      (total, file) => total + file.messages.length,
      0,
    );
    const fieldCount = files.reduce(
      (total, file) =>
        total +
        file.messages.reduce(
          (count, message) => count + message.fields.length,
          0,
        ),
      0,
    );
    const enumCount = files.reduce(
      (total, file) => total + file.enums.length,
      0,
    );
    const unparsedLines = files.reduce(
      (total, file) => total + file.unparsed_lines,
      0,
    );
    const truncated = collected.truncated || files.length > maxFiles;
    const result: RecoverProtoDefinitionsResult = {
      client: {
        tool: configuration.tool,
        command: configuration.command,
        version: null,
      },
      path,
      sha256: digest.sha256,
      bytes: digest.bytes,
      output_directory: destination,
      files: files.map((file) => ({
        relative_path: file.relative_path,
        bytes: file.bytes,
        sha256: file.sha256,
        package: file.package,
        messages: file.messages,
        enums: file.enums,
        service_count: file.service_count,
      })),
      file_count: files.length,
      message_count: messageCount,
      field_count: fieldCount,
      enum_count: enumCount,
      truncated,
      unparsed_lines: unparsedLines,
      coverage:
        truncated || unparsedLines > 0
          ? ("partial" as const)
          : ("complete" as const),
    };
    recoverProtoDefinitionsResultSchema.parse(result);
    return ok(
      createAnalysisExecution(
        result,
        {
          ...PROTOBUF_RECOVERY_PROVIDER_IDENTITY,
          version: null,
        },
        {
          limitations: [
            PROTOBUF_LANE_UNVERIFIED_NOTE,
            "Recovered .proto files are published with digests; their structure is reported, never their bytes",
            "Field options and default values are never read, so they cannot reach Evidence",
            ...(truncated
              ? ["max_files capped the published recovered-file list"]
              : []),
            ...(unparsedLines > 0
              ? [
                  "Unrecognized recovered definition lines were counted, not guessed",
                ]
              : []),
          ],
          locations: [{ kind: "artifact-path", path }],
        },
      ),
    );
  }

  async #enumerateReflection(
    operation: string,
    input: {
      readonly endpoint: string;
      readonly plaintext?: boolean | undefined;
      readonly max_services?: number | undefined;
      readonly max_methods?: number | undefined;
      readonly timeout_ms?: number | undefined;
    },
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const configuration = this.#reflectionConfiguration(operation);
    if (!configuration.ok) return configuration;
    const plaintext = input.plaintext ?? true;
    const maxServices = input.max_services ?? 100;
    const maxMethods = input.max_methods ?? 1_000;
    const timeoutMs = input.timeout_ms ?? 15_000;
    const listed = await runProtobufCommand(
      operation,
      configuration.value.command,
      grpcReflectionArguments.list(input.endpoint, plaintext),
      { timeoutMs },
      signal,
      "grpcurl",
    );
    if (!listed.ok) return listed;
    const discovered = parseGrpcServiceList(listed.value.stdout);
    const selected = discovered.slice(0, maxServices);
    let unparsedServices = 0;
    let truncated = discovered.length > maxServices;
    const services: EnumerateGrpcReflectionResult["services"][number][] = [];
    let methodCount = 0;
    for (const service of selected) {
      if (methodCount >= maxMethods) {
        truncated = true;
        break;
      }
      const described = await runProtobufCommand(
        operation,
        configuration.value.command,
        grpcReflectionArguments.describe(input.endpoint, plaintext, service),
        { timeoutMs },
        signal,
        "grpcurl",
      );
      if (!described.ok) {
        if (
          described.error._tag === "AnalysisCancelledError" ||
          described.error._tag === "AnalysisTimeoutError"
        )
          return described;
        unparsedServices += 1;
        continue;
      }
      const parsed = parseGrpcServiceDescription(
        described.value.stdout,
        service,
      );
      if (parsed === null) {
        unparsedServices += 1;
        continue;
      }
      const remaining = maxMethods - methodCount;
      const methods =
        parsed.methods.length > remaining
          ? parsed.methods.slice(0, remaining)
          : parsed.methods;
      if (parsed.methods.length > remaining) truncated = true;
      methodCount += methods.length;
      services.push({
        name: parsed.name,
        methods: methods.map((method) => ({
          name: method.name,
          input_type: method.inputType,
          output_type: method.outputType,
          client_streaming: method.clientStreaming,
          server_streaming: method.serverStreaming,
        })),
      });
    }
    const result: EnumerateGrpcReflectionResult = {
      client: {
        tool: "grpcurl",
        command: configuration.value.command,
        version: null,
      },
      endpoint: input.endpoint,
      plaintext,
      services,
      service_count: services.length,
      method_count: methodCount,
      unparsed_services: unparsedServices,
      truncated,
      coverage:
        truncated || unparsedServices > 0
          ? ("partial" as const)
          : ("complete" as const),
    };
    enumerateGrpcReflectionResultSchema.parse(result);
    return ok(
      createAnalysisExecution(
        result,
        {
          ...PROTOBUF_RECOVERY_PROVIDER_IDENTITY,
          version: null,
        },
        {
          limitations: [
            PROTOBUF_LANE_UNVERIFIED_NOTE,
            "Reflection reports the server's advertised services and method signatures; it does not prove implementation behavior",
            "Only caller-declared lab endpoints are contacted; REA never discovers endpoints",
            ...(unparsedServices > 0
              ? ["Services whose description failed were counted, not guessed"]
              : []),
            ...(truncated
              ? ["max_services or max_methods capped the published reflection"]
              : []),
          ],
        },
      ),
    );
  }

  #recoveryConfiguration(
    operation: string,
    requested: "auto" | "pbtk" | "protodump",
  ): Result<ProtoRecoveryConfiguration, AnalysisError> {
    try {
      return ok(
        resolveProtoRecoveryConfiguration(this.#environment, requested),
      );
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof ProtobufConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            PROTOBUF_RECOVERY_PROVIDER_ID,
            operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `The protobuf recovery selection failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  #reflectionConfiguration(
    operation: string,
  ): Result<{ readonly command: string }, AnalysisError> {
    try {
      const configuration = resolveGrpcReflectionConfiguration(
        this.#environment,
      );
      return ok({ command: configuration.command });
    } catch (cause: unknown) {
      if (cause instanceof AnalysisErrorClass) return err(cause);
      if (cause instanceof ProtobufConfigurationFailure)
        return err(
          providerConfigurationRefusal(
            PROTOBUF_RECOVERY_PROVIDER_ID,
            operation,
            cause,
          ),
        );
      return err(
        new AnalysisProtocolError(
          `The grpcurl selection failed for ${operation}`,
          { cause },
        ),
      );
    }
  }

  async #createRoot(): Promise<Result<RuntimeRoot, AnalysisError>> {
    try {
      return ok(await this.#createRuntimeRoot({ prefix: "rea-protobuf-" }));
    } catch (cause: unknown) {
      return err(
        new AnalysisProtocolError(
          "A private recovery output directory could not be created",
          { cause },
        ),
      );
    }
  }

  async #digest(
    operation: string,
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<FileDigest, AnalysisError>> {
    try {
      const digest = await hashStableFile(path, {
        ...(signal === undefined ? {} : { signal }),
        retainFailedClose: (handle) => {
          this.#resources.retain({
            kind: "lease",
            resource: path,
            lease: new AnalysisCleanupLease(() => handle.close(), [path]),
          });
        },
      });
      return ok({ bytes: digest.bytes, sha256: digest.sha256 });
    } catch (cause: unknown) {
      if (cause instanceof RegularFileOperationCancelled)
        return err(
          new AnalysisCancelledError(operation, { cause: cause.reason }),
        );
      return err(
        new AnalysisInputError(operation, {
          cause,
          userMessage: `The selected artifact could not be read and digested: ${path}`,
        }),
      );
    }
  }
}

const sanitize = (value: string): string =>
  value.replaceAll(/[^\w.-]+/gu, "-").slice(0, 64) || "artifact";

const prepareOutputDirectory = async (
  operation: string,
  directory: string,
): Promise<Result<string, AnalysisError>> => {
  try {
    await mkdir(directory, { recursive: true });
    return ok(directory);
  } catch (cause) {
    return err(
      new AnalysisOutputError(
        operation,
        `The output directory could not be created: ${directory}`,
        { cause },
      ),
    );
  }
};

const collectProtoFiles = async (
  root: string,
  limit: number,
): Promise<{
  readonly files: readonly CollectedProto[];
  readonly truncated: boolean;
}> => {
  const files: CollectedProto[] = [];
  let bytes = 0;
  let truncated = false;
  const walk = async (directory: string): Promise<void> => {
    if (truncated) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries.sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
      if (truncated) return;
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile() && entry.name.endsWith(".proto")) {
        if (files.length >= limit) {
          truncated = true;
          return;
        }
        try {
          const contents = await readFile(absolute);
          bytes += contents.byteLength;
          if (bytes > MAX_RECOVERED_PROTO_BYTES) {
            truncated = true;
            return;
          }
          files.push({
            relativePath: absolute.slice(root.length + 1),
            contents,
          });
        } catch {
          truncated = true;
          return;
        }
      }
    }
  };
  await walk(root);
  return { files, truncated };
};

const publishProtoFiles = async (
  operation: string,
  destination: string,
  files: readonly CollectedProto[],
): Promise<Result<readonly PublishedProto[], AnalysisError>> => {
  try {
    await mkdir(destination, { recursive: false });
  } catch (cause) {
    return err(
      new AnalysisOutputError(
        operation,
        `The recovered-file destination already exists or could not be created: ${destination}`,
        { cause },
      ),
    );
  }
  const published: PublishedProto[] = [];
  for (const file of files) {
    const target = join(destination, file.relativePath);
    try {
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, file.contents, { mode: 0o600, flag: "wx" });
      published.push({
        relative_path: file.relativePath,
        bytes: file.contents.byteLength,
        sha256: createHash("sha256").update(file.contents).digest("hex"),
      });
    } catch (cause) {
      return err(
        new AnalysisOutputError(
          operation,
          `A recovered .proto file could not be published: ${file.relativePath}`,
          { cause },
        ),
      );
    }
  }
  return ok(published);
};
