import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  GRPCURL_COMMAND_ENV,
  GRPCURL_COMMAND_REMEDIATION,
  PBTK_COMMAND_ENV,
  PROTODUMP_COMMAND_ENV,
  PROTOBUF_RECOVERY_REMEDIATION,
  PROTOBUF_TOOL_REMEDIATION,
} from "./ProtobufRecoveryRelease.js";

export type ProtoRecoveryTool = "pbtk" | "protodump";

const TOOL_SETTINGS: Readonly<
  Record<ProtoRecoveryTool, { readonly setting: string }>
> = {
  pbtk: { setting: PBTK_COMMAND_ENV },
  protodump: { setting: PROTODUMP_COMMAND_ENV },
};

/** One bounded recovery invocation. */
const DEFAULT_OPERATION_TIMEOUT_MS = 600_000;
const DEFAULT_REFLECTION_TIMEOUT_MS = 60_000;

/** Caller-selected recovery tool and REA-owned bounds. */
export interface ProtoRecoveryConfiguration {
  readonly tool: ProtoRecoveryTool;
  readonly command: string;
  readonly operationTimeoutMs: number;
}

/** Caller-selected grpcurl binary and REA-owned bounds. */
export interface GrpcReflectionConfiguration {
  readonly command: string;
  readonly operationTimeoutMs: number;
}

export type ProtobufConfigurationFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable"
  | "tool_unavailable";

export class ProtobufConfigurationFailure extends Error {
  constructor(
    readonly code: ProtobufConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

const executabilityFailure = (
  setting: string,
  command: string,
): ProtobufConfigurationFailure | null => {
  try {
    accessSync(command, constants.X_OK);
    if (!statSync(command).isFile())
      return new ProtobufConfigurationFailure(
        "binary_not_executable",
        `The selected path is not a regular file: ${command}`,
        {
          setting,
          selected_binary: command,
          remediation: PROTOBUF_RECOVERY_REMEDIATION,
        },
      );
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    return new ProtobufConfigurationFailure(
      code === "EACCES" || code === "EPERM"
        ? "binary_not_executable"
        : "binary_missing",
      code === "EACCES" || code === "EPERM"
        ? `Execution of the selected binary was denied: ${command}`
        : `The selected binary was not found: ${command}`,
      {
        setting,
        selected_binary: command,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: PROTOBUF_RECOVERY_REMEDIATION,
      },
      { cause },
    );
  }
};

const resolveOneTool = (
  environment: Readonly<Record<string, string | undefined>>,
  tool: ProtoRecoveryTool,
): { readonly tool: ProtoRecoveryTool; readonly command: string } => {
  const setting = TOOL_SETTINGS[tool].setting;
  const configured = environment[setting];
  if (configured === undefined || configured.trim() === "")
    throw new ProtobufConfigurationFailure(
      "tool_unavailable",
      `The ${tool} recovery tool is not selected: ${setting} is unset`,
      {
        setting,
        tool,
        remediation: PROTOBUF_TOOL_REMEDIATION(tool),
      },
    );
  if (!isAbsolute(configured))
    throw new ProtobufConfigurationFailure(
      "not_absolute",
      `${setting} must be an absolute path to the ${tool} binary`,
      {
        setting,
        configured_path: configured,
        remediation: PROTOBUF_TOOL_REMEDIATION(tool),
      },
    );
  const failure = executabilityFailure(setting, configured);
  if (failure !== null) throw failure;
  return { tool, command: configured };
};

/**
 * Resolve the recovery tool. `auto` prefers pbtk and falls back to protodump;
 * the other selections fail closed with the exact setting.
 */
export const resolveProtoRecoveryConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
  requested: "auto" | ProtoRecoveryTool,
): ProtoRecoveryConfiguration => {
  if (requested !== "auto") {
    const selected = resolveOneTool(environment, requested);
    return {
      ...selected,
      operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS,
    };
  }
  const failures: ProtobufConfigurationFailure[] = [];
  for (const tool of ["pbtk", "protodump"] as const) {
    try {
      const selected = resolveOneTool(environment, tool);
      return {
        ...selected,
        operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS,
      };
    } catch (cause: unknown) {
      if (cause instanceof ProtobufConfigurationFailure) failures.push(cause);
      else throw cause;
    }
  }
  throw new ProtobufConfigurationFailure(
    "not_configured",
    `No protobuf recovery tool is selected: ${PBTK_COMMAND_ENV} and ${PROTODUMP_COMMAND_ENV} are unset or unusable`,
    {
      settings: [PBTK_COMMAND_ENV, PROTODUMP_COMMAND_ENV],
      failures: failures.length,
      remediation: PROTOBUF_RECOVERY_REMEDIATION,
    },
  );
};

/** Resolve the caller-supplied grpcurl executable. */
export const resolveGrpcReflectionConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): GrpcReflectionConfiguration => {
  const command = environment[GRPCURL_COMMAND_ENV];
  if (command === undefined || command.trim() === "")
    throw new ProtobufConfigurationFailure(
      "not_configured",
      `No grpcurl binary is selected: ${GRPCURL_COMMAND_ENV} is unset`,
      {
        setting: GRPCURL_COMMAND_ENV,
        remediation: GRPCURL_COMMAND_REMEDIATION,
      },
    );
  if (!isAbsolute(command))
    throw new ProtobufConfigurationFailure(
      "not_absolute",
      `${GRPCURL_COMMAND_ENV} must be an absolute path to the grpcurl binary`,
      {
        setting: GRPCURL_COMMAND_ENV,
        configured_path: command,
        remediation: GRPCURL_COMMAND_REMEDIATION,
      },
    );
  const failure = executabilityFailure(GRPCURL_COMMAND_ENV, command);
  if (failure !== null)
    throw new ProtobufConfigurationFailure(
      failure.code,
      failure.message,
      { ...failure.diagnostics, remediation: GRPCURL_COMMAND_REMEDIATION },
      { cause: failure },
    );
  return {
    command,
    operationTimeoutMs: DEFAULT_REFLECTION_TIMEOUT_MS,
  };
};

const rejectionCodeOf = (
  code: ProtobufConfigurationFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "binary_missing":
      return "executable_missing";
    case "binary_not_executable":
    case "not_configured":
    case "not_absolute":
    case "tool_unavailable":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const protobufConfigurationAvailability = (
  cause: ProtobufConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
