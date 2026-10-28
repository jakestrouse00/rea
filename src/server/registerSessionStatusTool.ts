import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

import type { BinarySessionPort } from "../application/binary/BinarySessionPort.js";
import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { JebAnalysisAvailability } from "../application/jeb/JebAnalysisPort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  buildCapabilityInventory,
  compactToolAvailability,
} from "../application/CapabilityInventory.js";
import { toolContract } from "../contracts/toolContracts.js";
import type {
  ClientFeatureAvailability,
  ToolAvailability,
} from "../contracts/toolOutputSchemaPrimitives.js";
import { jsonObjectSchema, type JsonValue } from "../domain/jsonValue.js";
import { createServerIdentity } from "../serverIdentity.js";
import { mcpClientMetadata } from "./mcpClientMetadata.js";
import type { AvailabilityPolicy } from "../application/CapabilityInventory.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { err } from "../domain/result.js";
import { CURRENT_ENTRYPOINT_PATH } from "../process/CurrentEntrypointPath.js";

/** Provider-owned live probes used by session discovery. */
export interface SessionAvailabilityProbes {
  readonly androidAnalysisAvailability: (
    signal: AbortSignal,
  ) => Promise<ProviderAvailability>;
  readonly adbAnalysisAvailability?: (
    signal: AbortSignal,
  ) => Promise<ProviderAvailability>;
  readonly ipswAnalysisAvailability?: (
    signal: AbortSignal,
  ) => Promise<ProviderAvailability>;
  readonly capaAnalysisAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly yaraAnalysisAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly goresymAnalysisAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly rustfiltAnalysisAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly dumpSymsAnalysisAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly dotnetDecompilerAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly pythonDecompilerAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly jvmDecompilerAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly v8BytecodeAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly protobufRecoveryAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly grpcReflectionAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly bindiffDiffAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly bindiffExportAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly apktoolAnalysisAvailability?: (
    signal: AbortSignal,
  ) => Promise<ProviderAvailability>;
  readonly jebAnalysisAvailability?: (
    signal: AbortSignal,
  ) => Promise<JebAnalysisAvailability>;
  readonly evmLimiterAvailability?: (
    signal: AbortSignal,
  ) => Promise<ProviderAvailability | undefined>;
  readonly labVmAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly benchAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly objectionAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly androguardAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
  readonly ileAppAvailability?: (
    signal: AbortSignal,
  ) => ProviderAvailability | Promise<ProviderAvailability>;
}

/** Inputs required to register the binary session status tool. */
export interface SessionStatusToolOptions extends SessionAvailabilityProbes {
  readonly server: EvidenceMcpServer;
  readonly session: BinarySessionPort;
  readonly contract: ReturnType<typeof toolContract<"binary_session">>;
  readonly startedAt: string;
  readonly availabilityPolicy: () => AvailabilityPolicy;
}

const probeSessionAvailability = (
  probes: SessionAvailabilityProbes,
  signal: AbortSignal,
): Promise<{
  readonly android: ProviderAvailability;
  readonly adb: ProviderAvailability | undefined;
  readonly ipsw: ProviderAvailability | undefined;
  readonly capa: ProviderAvailability | undefined;
  readonly yara: ProviderAvailability | undefined;
  readonly goresym: ProviderAvailability | undefined;
  readonly rustfilt: ProviderAvailability | undefined;
  readonly dumpSyms: ProviderAvailability | undefined;
  readonly dotnetDecompiler: ProviderAvailability | undefined;
  readonly pythonDecompiler: ProviderAvailability | undefined;
  readonly jvmDecompiler: ProviderAvailability | undefined;
  readonly v8Bytecode: ProviderAvailability | undefined;
  readonly protobufRecovery: ProviderAvailability | undefined;
  readonly grpcReflection: ProviderAvailability | undefined;
  readonly bindiffDiff: ProviderAvailability | undefined;
  readonly bindiffExport: ProviderAvailability | undefined;
  readonly apktool: ProviderAvailability | undefined;
  readonly jeb: JebAnalysisAvailability | undefined;
  readonly evmLimiter: ProviderAvailability | undefined;
  readonly labVm: ProviderAvailability | undefined;
  readonly bench: ProviderAvailability | undefined;
  readonly objection: ProviderAvailability | undefined;
  readonly androguard: ProviderAvailability | undefined;
  readonly ileApp: ProviderAvailability | undefined;
}> =>
  Promise.all([
    probes.androidAnalysisAvailability(signal),
    probes.adbAnalysisAvailability?.(signal) ?? undefined,
    probes.ipswAnalysisAvailability?.(signal) ?? undefined,
    probes.capaAnalysisAvailability?.(signal) ?? undefined,
    probes.yaraAnalysisAvailability?.(signal) ?? undefined,
    probes.goresymAnalysisAvailability?.(signal) ?? undefined,
    probes.rustfiltAnalysisAvailability?.(signal) ?? undefined,
    probes.dumpSymsAnalysisAvailability?.(signal) ?? undefined,
    probes.dotnetDecompilerAvailability?.(signal) ?? undefined,
    probes.pythonDecompilerAvailability?.(signal) ?? undefined,
    probes.jvmDecompilerAvailability?.(signal) ?? undefined,
    probes.v8BytecodeAvailability?.(signal) ?? undefined,
    probes.protobufRecoveryAvailability?.(signal) ?? undefined,
    probes.grpcReflectionAvailability?.(signal) ?? undefined,
    probes.bindiffDiffAvailability?.(signal) ?? undefined,
    probes.bindiffExportAvailability?.(signal) ?? undefined,
    probes.apktoolAnalysisAvailability?.(signal) ?? undefined,
    probes.jebAnalysisAvailability?.(signal) ?? undefined,
    probes.evmLimiterAvailability?.(signal) ?? undefined,
    probes.labVmAvailability?.(signal) ?? undefined,
    probes.benchAvailability?.(signal) ?? undefined,
    probes.objectionAvailability?.(signal) ?? undefined,
    probes.androguardAvailability?.(signal) ?? undefined,
    probes.ileAppAvailability?.(signal) ?? undefined,
  ] as const).then(
    ([
      android,
      adb,
      ipsw,
      capa,
      yara,
      goresym,
      rustfilt,
      dumpSyms,
      dotnetDecompiler,
      pythonDecompiler,
      jvmDecompiler,
      v8Bytecode,
      protobufRecovery,
      grpcReflection,
      bindiffDiff,
      bindiffExport,
      apktool,
      jeb,
      evmLimiter,
      labVm,
      bench,
      objection,
      androguard,
      ileApp,
    ]) => ({
      android,
      adb,
      ipsw,
      capa,
      yara,
      goresym,
      rustfilt,
      dumpSyms,
      dotnetDecompiler,
      pythonDecompiler,
      jvmDecompiler,
      v8Bytecode,
      protobufRecovery,
      grpcReflection,
      bindiffDiff,
      bindiffExport,
      apktool,
      jeb,
      evmLimiter,
      labVm,
      bench,
      objection,
      androguard,
      ileApp,
    }),
  );

/** Register the read-only provider and target status operation. */
export const registerSessionStatusTool = (
  options: SessionStatusToolOptions,
): void => {
  const { server, session, contract, startedAt, availabilityPolicy } = options;
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) => {
      const { client, clientFeatures, protocolVersion } = mcpClientMetadata(
        context,
        server.server,
      );
      let availabilityResults: Awaited<
        ReturnType<typeof probeSessionAvailability>
      >;
      let status: JsonValue;
      try {
        availabilityResults = await probeSessionAvailability(
          options,
          context.mcpReq.signal,
        );
        status = await session.status({ signal: context.mcpReq.signal });
      } catch (cause) {
        if (!(cause instanceof AnalysisError)) throw cause;
        return server.delivery.toCallToolResult(err(cause), contract);
      }
      const statusObject = jsonObjectSchema.parse(status);
      const toolAvailability = buildCapabilityInventory(
        status,
        {
          ...availabilityPolicy(),
          androidAnalysisAvailability: availabilityResults.android,
          ...(availabilityResults.adb === undefined
            ? {}
            : { adbAnalysisAvailability: availabilityResults.adb }),
          ...(availabilityResults.ipsw === undefined
            ? {}
            : { ipswAnalysisAvailability: availabilityResults.ipsw }),
          ...(availabilityResults.capa === undefined
            ? {}
            : { capaAnalysisAvailability: availabilityResults.capa }),
          ...(availabilityResults.yara === undefined
            ? {}
            : { yaraAnalysisAvailability: availabilityResults.yara }),
          ...(availabilityResults.goresym === undefined
            ? {}
            : { goresymAnalysisAvailability: availabilityResults.goresym }),
          ...(availabilityResults.rustfilt === undefined
            ? {}
            : { rustfiltAnalysisAvailability: availabilityResults.rustfilt }),
          ...(availabilityResults.dumpSyms === undefined
            ? {}
            : { dumpSymsAnalysisAvailability: availabilityResults.dumpSyms }),
          ...(availabilityResults.dotnetDecompiler === undefined
            ? {}
            : {
                dotnetDecompilerAvailability:
                  availabilityResults.dotnetDecompiler,
              }),
          ...(availabilityResults.pythonDecompiler === undefined
            ? {}
            : {
                pythonDecompilerAvailability:
                  availabilityResults.pythonDecompiler,
              }),
          ...(availabilityResults.jvmDecompiler === undefined
            ? {}
            : { jvmDecompilerAvailability: availabilityResults.jvmDecompiler }),
          ...(availabilityResults.v8Bytecode === undefined
            ? {}
            : { v8BytecodeAvailability: availabilityResults.v8Bytecode }),
          ...(availabilityResults.protobufRecovery === undefined
            ? {}
            : {
                protobufRecoveryAvailability:
                  availabilityResults.protobufRecovery,
              }),
          ...(availabilityResults.grpcReflection === undefined
            ? {}
            : {
                grpcReflectionAvailability: availabilityResults.grpcReflection,
              }),
          ...(availabilityResults.apktool === undefined
            ? {}
            : { apktoolAnalysisAvailability: availabilityResults.apktool }),
          ...(availabilityResults.jeb === undefined
            ? {}
            : { jebAnalysisAvailability: availabilityResults.jeb }),
          ...(availabilityResults.evmLimiter === undefined
            ? {}
            : { evmLimiterAvailability: availabilityResults.evmLimiter }),
          ...(availabilityResults.labVm === undefined
            ? {}
            : { labVmAvailability: availabilityResults.labVm }),
          ...(availabilityResults.bench === undefined
            ? {}
            : { benchAvailability: availabilityResults.bench }),
          ...(availabilityResults.objection === undefined
            ? {}
            : { objectionAvailability: availabilityResults.objection }),
          ...(availabilityResults.androguard === undefined
            ? {}
            : { androguardAvailability: availabilityResults.androguard }),
          ...(availabilityResults.ileApp === undefined
            ? {}
            : { ileAppAvailability: availabilityResults.ileApp }),
        },
        clientFeatures,
      );
      const serverIdentity = createServerIdentity({
        startedAt,
        commandPath: CURRENT_ENTRYPOINT_PATH,
        catalog: server.catalogIdentity,
        expected: {
          ...(input.expected_package_version === undefined
            ? {}
            : { package_version: input.expected_package_version }),
          ...(input.expected_catalog_digest === undefined
            ? {}
            : { catalog_digest: input.expected_catalog_digest }),
          ...(input.expected_server_path === undefined
            ? {}
            : { server_path: input.expected_server_path }),
        },
        ...(client === undefined ? {} : { client }),
        ...(protocolVersion === undefined ? {} : { protocolVersion }),
      });
      return server.delivery.toCallToolResult(
        {
          ok: true,
          value: projectSessionStatus({
            status: statusObject,
            toolAvailability,
            serverIdentity,
            clientFeatures,
          }),
        },
        contract,
      );
    },
  );
};

const projectSessionStatus = (options: {
  readonly status: Readonly<
    Record<string, import("../domain/jsonValue.js").JsonValue>
  >;
  readonly toolAvailability: readonly ToolAvailability[];
  readonly serverIdentity: ReturnType<typeof createServerIdentity>;
  readonly clientFeatures: ClientFeatureAvailability;
}) =>
  jsonObjectSchema.parse({
    ...options.status,
    tool_availability: compactToolAvailability(options.toolAvailability),
    client_features: options.clientFeatures,
    server_identity: options.serverIdentity,
  });
