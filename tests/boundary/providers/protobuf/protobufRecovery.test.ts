import { expect, test } from "vitest";
import { readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { ProtobufRecoveryProvider } from "../../../../src/protobufrecovery/ProtobufRecoveryProvider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { writeFakeGrpcurl } from "./fakeGrpcurl.js";
import { writeFakeProtoTool } from "./fakeProtoTool.js";

const PROTO_FIXTURE = `syntax = "proto3";
package example.api;

message Request {
  string name = 1;
  repeated int32 ids = 2;
  map<string, string> labels = 3;

  oneof contact {
    string email = 4;
    int64 phone = 5;
  }

  message Nested {
    bool ok = 1;
  }

  enum Kind {
    UNKNOWN = 0;
    ACTIVE = 1;
  }
}

message Response {
  Request request = 1;
}

enum Status {
  STATUS_UNKNOWN = 0;
  STATUS_OK = 1;
}

service Greeter {
  rpc Hello (Request) returns (Response);
}
`;

const DESCRIBE_FIXTURE = `example.api.Greeter is a service:
service Greeter {
  rpc Hello ( .example.api.Request ) returns ( .example.api.Response );
  rpc Stream ( stream .example.api.Request ) returns ( stream .example.api.Response );
}
`;

test("recovers .proto structure, publishes files with digests, and parses fields", async () => {
  const root = await createTestTempDirectory("rea-protobuf-");
  const { launcher, callsPath } = await writeFakeProtoTool(root, "pbtk", {
    files: { "example/api.proto": PROTO_FIXTURE },
  });
  const provider = new ProtobufRecoveryProvider({
    environment: { REA_PBTK_COMMAND: launcher },
  });
  const artifact = join(root, "app.apk");
  await writeFile(artifact, "APK-FIXTURE");
  const result = await provider.execute({
    operation: "recover_proto_definitions",
    input: {
      path: artifact,
      output_directory: join(root, "out"),
    },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.client).toEqual({
    tool: "pbtk",
    command: launcher,
    version: null,
  });
  expect(value.file_count).toBe(1);
  expect(value.message_count).toBe(3);
  expect(value.field_count).toBe(7);
  expect(value.unparsed_lines).toBe(0);
  expect(value.coverage).toBe("complete");
  expect(value.enum_count).toBe(2);
  const files = value.files as Array<Record<string, unknown>>;
  expect(files[0]).toMatchObject({
    relative_path: "example/api.proto",
    package: "example.api",
    service_count: 1,
  });
  expect(files[0]?.sha256).toMatch(/^[a-f0-9]{64}$/u);
  const messages = files[0]?.messages as Array<Record<string, unknown>>;
  expect(messages.map(({ name }) => name)).toEqual([
    "Request",
    "Nested",
    "Response",
  ]);
  const request = messages[0] as {
    fields: Array<Record<string, unknown>>;
    nested_message_count: number;
  };
  expect(request.fields).toEqual([
    {
      name: "name",
      number: 1,
      type: "string",
      label: "singular",
      map: false,
      oneof: null,
    },
    {
      name: "ids",
      number: 2,
      type: "int32",
      label: "repeated",
      map: false,
      oneof: null,
    },
    {
      name: "labels",
      number: 3,
      type: "map<string,string>",
      label: "map",
      map: true,
      oneof: null,
    },
    {
      name: "email",
      number: 4,
      type: "string",
      label: "singular",
      map: false,
      oneof: "contact",
    },
    {
      name: "phone",
      number: 5,
      type: "int64",
      label: "singular",
      map: false,
      oneof: "contact",
    },
  ]);
  expect(request.nested_message_count).toBe(1);
  const published = join(value.output_directory as string, "example/api.proto");
  expect(await readFile(published, "utf8")).toBe(PROTO_FIXTURE);
  expect((await stat(published)).mode & 0o777).toBe(0o600);
  await provider.close();
  expect(await readFile(callsPath, "utf8")).toContain('"recover"');
});

test("auto falls back to protodump when pbtk is unselected", async () => {
  const root = await createTestTempDirectory("rea-protobuf-fallback-");
  const { launcher, callsPath } = await writeFakeProtoTool(root, "protodump", {
    files: { "api.proto": PROTO_FIXTURE },
  });
  const provider = new ProtobufRecoveryProvider({
    environment: { REA_PROTODUMP_COMMAND: launcher },
  });
  const artifact = join(root, "blob.bin");
  await writeFile(artifact, "BIN-FIXTURE");
  const result = await provider.execute({
    operation: "recover_proto_definitions",
    input: { path: artifact, output_directory: join(root, "out") },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect((result.value.result as Record<string, unknown>).client).toMatchObject(
    {
      tool: "protodump",
      command: launcher,
    },
  );
  await provider.close();
  expect(await readFile(callsPath, "utf8")).toContain('"-o"');
});

test("refuses an explicitly selected tool that is not configured", async () => {
  const root = await createTestTempDirectory("rea-protobuf-explicit-");
  const { launcher } = await writeFakeProtoTool(root, "protodump", {
    files: { "api.proto": PROTO_FIXTURE },
  });
  const provider = new ProtobufRecoveryProvider({
    environment: { REA_PROTODUMP_COMMAND: launcher },
  });
  const artifact = join(root, "blob.bin");
  await writeFile(artifact, "BIN-FIXTURE");
  const result = await provider.execute({
    operation: "recover_proto_definitions",
    input: {
      path: artifact,
      output_directory: join(root, "out"),
      tool: "pbtk",
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_PBTK_COMMAND");
  await provider.close();
});

test("rejects a tool that writes no recognizable .proto file", async () => {
  const root = await createTestTempDirectory("rea-protobuf-empty-");
  const { launcher } = await writeFakeProtoTool(root, "pbtk", { files: {} });
  const provider = new ProtobufRecoveryProvider({
    environment: { REA_PBTK_COMMAND: launcher },
  });
  const artifact = join(root, "blob.bin");
  await writeFile(artifact, "BIN-FIXTURE");
  const result = await provider.execute({
    operation: "recover_proto_definitions",
    input: { path: artifact, output_directory: join(root, "out") },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisProtocolError");
  await provider.close();
});

test("reflects service and method signatures and counts undescribed services", async () => {
  const root = await createTestTempDirectory("rea-grpc-");
  const { launcher, callsPath } = await writeFakeGrpcurl(root, {
    services: ["example.api.Greeter", "hidden.Service"],
    descriptions: { "example.api.Greeter": DESCRIBE_FIXTURE },
    failingServices: ["hidden.Service"],
  });
  const provider = new ProtobufRecoveryProvider({
    environment: { REA_GRPCURL_COMMAND: launcher },
  });
  const result = await provider.execute({
    operation: "enumerate_grpc_reflection",
    input: { endpoint: "127.0.0.1:50051" },
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value.result as Record<string, unknown>;
  expect(value.client).toEqual({
    tool: "grpcurl",
    command: launcher,
    version: null,
  });
  expect(value.endpoint).toBe("127.0.0.1:50051");
  expect(value.plaintext).toBe(true);
  expect(value.service_count).toBe(1);
  expect(value.method_count).toBe(2);
  expect(value.unparsed_services).toBe(1);
  expect(value.coverage).toBe("partial");
  expect(value.services).toEqual([
    {
      name: "example.api.Greeter",
      methods: [
        {
          name: "Hello",
          input_type: "example.api.Request",
          output_type: "example.api.Response",
          client_streaming: false,
          server_streaming: false,
        },
        {
          name: "Stream",
          input_type: "example.api.Request",
          output_type: "example.api.Response",
          client_streaming: true,
          server_streaming: true,
        },
      ],
    },
  ]);
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain('"-plaintext","127.0.0.1:50051","list"');
  expect(calls).toContain('"describe","example.api.Greeter"');
});

test("refuses plainly when grpcurl is not selected", async () => {
  const provider = new ProtobufRecoveryProvider({ environment: {} });
  const result = await provider.execute({
    operation: "enumerate_grpc_reflection",
    input: { endpoint: "127.0.0.1:50051" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_GRPCURL_COMMAND");
  await provider.close();
});

test("probes recovery and reflection selections separately", async () => {
  const root = await createTestTempDirectory("rea-protobuf-avail-");
  const { launcher } = await writeFakeProtoTool(root, "pbtk", { files: {} });
  const { launcher: grpcurl } = await writeFakeGrpcurl(root, {});
  const provider = new ProtobufRecoveryProvider({
    environment: { REA_PBTK_COMMAND: launcher },
  });
  expect(provider.inspectRecoveryAvailability()).toMatchObject({
    status: "available",
  });
  expect(provider.inspectReflectionAvailability()).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await provider.close();

  const reflection = new ProtobufRecoveryProvider({
    environment: { REA_GRPCURL_COMMAND: grpcurl },
  });
  expect(reflection.inspectReflectionAvailability()).toMatchObject({
    status: "available",
  });
  await reflection.close();
});

const failingRootFactory = async (path: string) => ({
  path,
  close: async () => {
    throw new Error("root removal denied");
  },
});

test("retains a successful recovery when root cleanup fails", async () => {
  const root = await createTestTempDirectory("rea-protobuf-cleanup-");
  const { launcher } = await writeFakeProtoTool(root, "pbtk", {
    files: { "example/api.proto": PROTO_FIXTURE },
  });
  const runtimeRoot = await createTestTempDirectory("rea-protobuf-root-");
  const provider = new ProtobufRecoveryProvider({
    environment: { REA_PBTK_COMMAND: launcher },
    createRuntimeRoot: async () => failingRootFactory(runtimeRoot),
  });
  const artifact = join(root, "app.apk");
  await writeFile(artifact, "APK-FIXTURE");
  const result = await provider.execute({
    operation: "recover_proto_definitions",
    input: { path: artifact, output_directory: join(root, "out") },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.cleanupIncomplete).toBe(true);
  expect(result.error.partialObservation).toMatchObject({
    kind: "provider-result",
    operation: "recover_proto_definitions",
  });
  const partial = result.error.partialObservation as
    | { kind: "provider-result"; result: unknown }
    | undefined;
  if (partial?.kind !== "provider-result") return;
  expect(partial.result).toMatchObject({ file_count: 1 });
  expect(result.error.cleanupResources).toContain(runtimeRoot);
  expect(result.error.cleanup?.reason).toContain("root removal denied");
  await provider.close();
});

test("preserves the real recovery error when root cleanup also fails", async () => {
  const root = await createTestTempDirectory("rea-protobuf-cleanup-fail-");
  const { launcher } = await writeFakeProtoTool(root, "pbtk", {
    exit: 2,
    stderr: "recovery failed badly",
  });
  const runtimeRoot = await createTestTempDirectory("rea-protobuf-root-fail-");
  const provider = new ProtobufRecoveryProvider({
    environment: { REA_PBTK_COMMAND: launcher },
    createRuntimeRoot: async () => failingRootFactory(runtimeRoot),
  });
  const artifact = join(root, "app.apk");
  await writeFile(artifact, "APK-FIXTURE");
  const result = await provider.execute({
    operation: "recover_proto_definitions",
    input: { path: artifact, output_directory: join(root, "out") },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.cleanupIncomplete).toBe(true);
  expect(result.error.cleanupPrimary?._tag).toBe("ProviderAdapterError");
  expect(JSON.stringify(result.error.diagnostics?.primary_error)).toContain(
    "recovery failed badly",
  );
  expect(JSON.stringify(result.error.diagnostics?.cleanup_error)).toContain(
    "root removal denied",
  );
  await provider.close();
});
