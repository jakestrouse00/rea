import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Maximum recovered `.proto` files one result may publish. */
export const MAX_PROTO_FILES = 500;

/** Maximum reflected services one result may publish. */
export const MAX_GRPC_SERVICES = 500;

/** Maximum reflected methods one result may publish. */
export const MAX_GRPC_METHODS = 5_000;

const coverageSchema = z.enum(["complete", "partial"]);

export const PROTO_RECOVERY_TOOLS = ["auto", "pbtk", "protodump"] as const;

/**
 * Caller intent for protobuf definition recovery over a caller-supplied pbtk or
 * protodump binary. Recovered `.proto` files are published with digests; their
 * structure is the Evidence.
 */
export const recoverProtoDefinitionsInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a binary, APK, JAR, or web bundle carrying protobuf descriptors",
  ),
  output_directory: absoluteLocalPathStringSchema.describe(
    "Local directory that receives one new subdirectory of recovered .proto files",
  ),
  tool: z
    .enum(PROTO_RECOVERY_TOOLS)
    .default("auto")
    .describe(
      "Recovery tool: auto prefers pbtk, then protodump; an explicit choice fails when that tool is unselected",
    ),
  max_files: z
    .int()
    .min(1)
    .max(MAX_PROTO_FILES)
    .default(100)
    .describe("Upper bound on recovered .proto files published"),
});

export type RecoverProtoDefinitionsInput = z.input<
  typeof recoverProtoDefinitionsInputSchema
>;

/**
 * Caller intent for gRPC server reflection against one caller-declared lab
 * endpoint. REA never discovers endpoints.
 */
export const enumerateGrpcReflectionInputSchema = z.strictObject({
  endpoint: z
    .string()
    .min(1)
    .max(512)
    .regex(
      /^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(?::\d{1,5})?$/u,
      "Endpoint must be host[:port] or [IPv6][:port] with no scheme, path, or whitespace",
    )
    .describe("gRPC endpoint as host[:port], for example 127.0.0.1:50051"),
  plaintext: z
    .boolean()
    .default(true)
    .describe("Send cleartext HTTP/2 rather than TLS"),
  max_services: z
    .int()
    .min(1)
    .max(MAX_GRPC_SERVICES)
    .default(100)
    .describe("Upper bound on reflected services"),
  max_methods: z
    .int()
    .min(1)
    .max(MAX_GRPC_METHODS)
    .default(1_000)
    .describe("Upper bound on reflected methods"),
  timeout_ms: z
    .int()
    .min(1_000)
    .max(120_000)
    .default(15_000)
    .describe("Per-invocation reflection deadline"),
});

export type EnumerateGrpcReflectionInput = z.input<
  typeof enumerateGrpcReflectionInputSchema
>;

export const protobufClientSchema = z.strictObject({
  tool: z.enum(["pbtk", "protodump", "grpcurl"]),
  command: z.string().min(1),
  version: z.string().min(1).nullable(),
});

export const protoFieldSchema = z.strictObject({
  name: z.string().min(1),
  number: z.int().nonnegative().nullable(),
  type: z.string().min(1),
  label: z.enum(["optional", "required", "repeated", "singular", "map"]),
  map: z.boolean(),
  oneof: z.string().min(1).nullable(),
});

export const protoMessageSchema = z.strictObject({
  name: z.string().min(1),
  fields: z.array(protoFieldSchema),
  nested_message_count: z.int().nonnegative(),
});

export const protoEnumValueSchema = z.strictObject({
  name: z.string().min(1),
  number: z.int().nullable(),
});

export const protoEnumSchema = z.strictObject({
  name: z.string().min(1),
  values: z.array(protoEnumValueSchema),
});

const publishedProtoSchema = z.strictObject({
  relative_path: z.string().min(1),
  bytes: z.int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  package: z.string().min(1).nullable(),
  messages: z.array(protoMessageSchema),
  enums: z.array(protoEnumSchema),
  service_count: z.int().nonnegative(),
});

/** Structural protobuf recovery result. */
export const recoverProtoDefinitionsResultSchema = z.strictObject({
  client: protobufClientSchema,
  path: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.int().nonnegative(),
  output_directory: z.string().min(1),
  files: z.array(publishedProtoSchema),
  file_count: z.int().nonnegative(),
  message_count: z.int().nonnegative(),
  field_count: z.int().nonnegative(),
  enum_count: z.int().nonnegative(),
  truncated: z.boolean(),
  unparsed_lines: z.int().nonnegative(),
  coverage: coverageSchema,
});

const grpcMethodSchema = z.strictObject({
  name: z.string().min(1),
  input_type: z.string().min(1),
  output_type: z.string().min(1),
  client_streaming: z.boolean(),
  server_streaming: z.boolean(),
});

const grpcServiceSchema = z.strictObject({
  name: z.string().min(1),
  methods: z.array(grpcMethodSchema),
});

/** Structural gRPC reflection result. */
export const enumerateGrpcReflectionResultSchema = z.strictObject({
  client: protobufClientSchema,
  endpoint: z.string().min(1),
  plaintext: z.boolean(),
  services: z.array(grpcServiceSchema),
  service_count: z.int().nonnegative(),
  method_count: z.int().nonnegative(),
  unparsed_services: z.int().nonnegative(),
  truncated: z.boolean(),
  coverage: coverageSchema,
});

export type RecoverProtoDefinitionsResult = z.infer<
  typeof recoverProtoDefinitionsResultSchema
>;
export type EnumerateGrpcReflectionResult = z.infer<
  typeof enumerateGrpcReflectionResultSchema
>;

/** One validated protobuf recovery request. */
export const protobufRecoveryRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("recover_proto_definitions"),
    input: recoverProtoDefinitionsInputSchema,
  }),
  z.strictObject({
    operation: z.literal("enumerate_grpc_reflection"),
    input: enumerateGrpcReflectionInputSchema,
  }),
]);

export type ProtobufRecoveryRequest = z.output<
  typeof protobufRecoveryRequestSchema
>;
export type ProtobufRecoveryRequestInput = z.input<
  typeof protobufRecoveryRequestSchema
>;
