import { constants, accessSync, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  DUMP_SYMS_COMMAND_ENV,
  DUMP_SYMS_COMMAND_REMEDIATION,
  GORESYM_COMMAND_ENV,
  GORESYM_COMMAND_REMEDIATION,
  RUSTFILT_COMMAND_ENV,
  RUSTFILT_COMMAND_REMEDIATION,
} from "./SymbolRecoveryRelease.js";

export type SymbolTool =
  | "recover_go_symbols"
  | "demangle_rust_name"
  | "generate_symbol_table";

interface ToolSelection {
  readonly setting: string;
  readonly name: string;
  readonly pathFallback: boolean;
  readonly remediation: string;
}

/** Exact settings each symbol tool resolves before any process starts. */
export const SYMBOL_TOOL_SELECTION: Readonly<
  Record<SymbolTool, ToolSelection>
> = {
  recover_go_symbols: {
    setting: GORESYM_COMMAND_ENV,
    name: "GoReSym",
    pathFallback: false,
    remediation: GORESYM_COMMAND_REMEDIATION,
  },
  demangle_rust_name: {
    setting: RUSTFILT_COMMAND_ENV,
    name: "rustfilt",
    pathFallback: true,
    remediation: RUSTFILT_COMMAND_REMEDIATION,
  },
  generate_symbol_table: {
    setting: DUMP_SYMS_COMMAND_ENV,
    name: "dump_syms",
    pathFallback: false,
    remediation: DUMP_SYMS_COMMAND_REMEDIATION,
  },
};

/** Caller- or PATH-selected executable for one symbol tool. */
export interface SymbolCommandSelection {
  readonly tool: SymbolTool;
  readonly command: string;
  readonly pathSource: "environment" | "path";
}

export type SymbolConfigurationFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable";

export class SymbolConfigurationFailure extends Error {
  constructor(
    readonly code: SymbolConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

const executabilityFailure = (
  selection: ToolSelection,
  command: string,
  pathSource: "environment" | "path",
  cause: unknown,
): SymbolConfigurationFailure | null => {
  try {
    accessSync(command, constants.X_OK);
    return statSync(command).isFile()
      ? null
      : new SymbolConfigurationFailure(
          "binary_not_executable",
          `The selected ${selection.name} path is not a regular file: ${command}`,
          {
            setting: selection.setting,
            selected_binary: command,
            path_source: pathSource,
            remediation: selection.remediation,
          },
          { cause },
        );
  } catch (error: unknown) {
    const code = (error as NodeJS.ErrnoException).code;
    return new SymbolConfigurationFailure(
      code === "EACCES" || code === "EPERM"
        ? "binary_not_executable"
        : "binary_missing",
      code === "EACCES" || code === "EPERM"
        ? `Execution of the selected ${selection.name} binary was denied: ${command}`
        : `The selected ${selection.name} binary was not found: ${command}`,
      {
        setting: selection.setting,
        selected_binary: command,
        path_source: pathSource,
        ...(code === undefined ? {} : { filesystem_error: code }),
        remediation: selection.remediation,
      },
      { cause: error },
    );
  }
};

const searchPath = (
  name: string,
  environment: Readonly<Record<string, string | undefined>>,
): string | null => {
  const path = environment.PATH ?? process.env.PATH ?? "";
  for (const directory of path.split(delimiter)) {
    if (directory === "") continue;
    const candidate = join(directory, name);
    try {
      accessSync(candidate, constants.X_OK);
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      continue;
    }
  }
  return null;
};

/**
 * Resolve one symbol tool's executable. Absolute `REA_*` selections are
 * asserted to exist; rustfilt may fall back to PATH because upstream ships it
 * that way. Other tools have no PATH fallback.
 */
export const resolveSymbolCommand = (
  environment: Readonly<Record<string, string | undefined>>,
  tool: SymbolTool,
): SymbolCommandSelection => {
  const selection = SYMBOL_TOOL_SELECTION[tool];
  const configured = environment[selection.setting];
  if (configured !== undefined && configured.trim() !== "") {
    if (!isAbsolute(configured))
      throw new SymbolConfigurationFailure(
        "not_absolute",
        `${selection.setting} must be an absolute path to the ${selection.name} binary`,
        {
          setting: selection.setting,
          configured_path: configured,
          remediation: selection.remediation,
        },
      );
    const failure = executabilityFailure(
      selection,
      configured,
      "environment",
      undefined,
    );
    if (failure !== null) throw failure;
    return { tool, command: configured, pathSource: "environment" };
  }
  if (selection.pathFallback) {
    const resolved = searchPath(selection.name, environment);
    if (resolved === null)
      throw new SymbolConfigurationFailure(
        "not_configured",
        `No ${selection.name} binary is selected: ${selection.setting} is unset and PATH carries no ${selection.name}`,
        {
          setting: selection.setting,
          path_source: "path",
          remediation: selection.remediation,
        },
      );
    return { tool, command: resolved, pathSource: "path" };
  }
  throw new SymbolConfigurationFailure(
    "not_configured",
    `No ${selection.name} binary is selected: ${selection.setting} is unset`,
    {
      setting: selection.setting,
      remediation: selection.remediation,
    },
  );
};

const rejectionCodeOf = (
  code: SymbolConfigurationFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "binary_missing":
      return "executable_missing";
    case "binary_not_executable":
      return "not_configured";
    case "not_configured":
    case "not_absolute":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const symbolConfigurationAvailability = (
  cause: SymbolConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
