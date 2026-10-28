import {
  enumerateGrpcReflectionInputSchema,
  enumerateGrpcReflectionResultSchema,
  recoverProtoDefinitionsInputSchema,
  recoverProtoDefinitionsResultSchema,
} from "../../domain/protobufrecovery/protobufRecovery.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * Protobuf definition recovery and gRPC reflection over caller-supplied tools.
 *
 * Recovered `.proto` structure is reported and the files are published with
 * digests; recovered bytes never enter Evidence.
 */
export const PROTOBUF_RECOVERY_TOOL_CONTRACTS = [
  {
    name: "recover_proto_definitions",
    ...toolContractMetadata("recover_proto_definitions"),
    description:
      "Recover protobuf definitions from one explicit local binary, APK, JAR, or web bundle through a caller-supplied pbtk or protodump binary. Recovered .proto files are published into one new output subdirectory with SHA-256 digests, and Evidence reports each file's package, messages, fields, enums, and service count; a field inside a oneof block is reported in its parent message with the group name. Field options and default values are never read. Select the tool with an absolute REA_PBTK_COMMAND or REA_PROTODUMP_COMMAND; auto prefers pbtk. REA never installs a recovery tool and never runs the analyzed artifact.",
    kind: "protobuf-provider",
    inputSchema: recoverProtoDefinitionsInputSchema,
    outputSchema: evidenceResultOf(recoverProtoDefinitionsResultSchema),
    examples: [
      {
        title: "Recover definitions from an APK",
        input: {
          path: "/artifacts/app.apk",
          output_directory: "/tmp/rea-protos",
        },
      },
    ],
  },
  {
    name: "enumerate_grpc_reflection",
    ...toolContractMetadata("enumerate_grpc_reflection"),
    description:
      "Enumerate the services and method signatures one caller-declared gRPC lab endpoint advertises through server reflection, using a caller-supplied grpcurl binary. Returns each service's name and each method's input and output types plus client and server streaming flags; service descriptions that fail are counted, not guessed. Select grpcurl with an absolute REA_GRPCURL_COMMAND. REA never discovers endpoints, never uses TLS unless the request disables plaintext, and never invokes a method.",
    kind: "protobuf-provider",
    inputSchema: enumerateGrpcReflectionInputSchema,
    outputSchema: evidenceResultOf(enumerateGrpcReflectionResultSchema),
    examples: [
      {
        title: "Reflect a local lab endpoint",
        input: { endpoint: "127.0.0.1:50051" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
