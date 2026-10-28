import { constants, accessSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import {
  FUZZING_AFLFRIDA_COMMAND_ENV,
  FUZZING_AFLFRIDA_REMEDIATION,
  FUZZING_ENGINES,
  FUZZING_JACKALOPE_DIR_ENV,
  FUZZING_JACKALOPE_FUZZER_FILE,
  FUZZING_JACKALOPE_INSTRUMENTATION_FILE,
  FUZZING_JACKALOPE_REMEDIATION,
  FUZZING_LFZ_COMMAND_ENV,
  FUZZING_LFZ_REMEDIATION,
  type FuzzingEngine,
} from "../domain/fuzzing/fuzzingEngine.js";
import type { JsonValue } from "../domain/jsonValue.js";

/** One resolved engine selection. */
export interface FuzzingEngineConfiguration {
  readonly engine: FuzzingEngine;
  /** Absolute executable the adapter launches. */
  readonly command: string;
  /** Build directory a Jackalope launch also references, else null. */
  readonly supportDirectory: string | null;
}

export type FuzzingEngineConfigurationCode =
  | "engine_not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable"
  | "build_missing"
  | "unsupported_host";

/** An engine selection that cannot be launched as configured. */
export class FuzzingEngineConfigurationFailure extends Error {
  readonly _tag = "FuzzingEngineConfigurationFailure";
  constructor(
    readonly engine: FuzzingEngine,
    readonly code: FuzzingEngineConfigurationCode,
    message: string,
    readonly setting: string,
    readonly remediation: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "FuzzingEngineConfigurationFailure";
  }
}

const remediationFor = (engine: FuzzingEngine): string =>
  engine === "libfuzzer"
    ? FUZZING_LFZ_REMEDIATION
    : engine === "aflpp_frida"
      ? FUZZING_AFLFRIDA_REMEDIATION
      : FUZZING_JACKALOPE_REMEDIATION;

const executableFailure = (
  engine: FuzzingEngine,
  command: string,
  setting: string,
): FuzzingEngineConfigurationFailure | null => {
  const remediation = remediationFor(engine);
  try {
    accessSync(command, constants.X_OK);
    if (!statSync(command).isFile())
      return new FuzzingEngineConfigurationFailure(
        engine,
        "binary_not_executable",
        `The selected engine path is not a regular file: ${command}`,
        setting,
        remediation,
        { selected_binary: command },
      );
    return null;
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    const denied = code === "EACCES" || code === "EPERM";
    return new FuzzingEngineConfigurationFailure(
      engine,
      denied ? "binary_not_executable" : "binary_missing",
      denied
        ? `Execution of the selected engine binary was denied: ${command}`
        : `The selected engine binary was not found: ${command}`,
      setting,
      remediation,
      {
        selected_binary: command,
        ...(code === undefined ? {} : { filesystem_error: code }),
      },
      { cause },
    );
  }
};

const configuredPath = (
  environment: Readonly<Record<string, string | undefined>>,
  engine: FuzzingEngine,
  setting: string,
): string => {
  const command = environment[setting];
  const remediation = remediationFor(engine);
  if (command === undefined || command.trim() === "")
    throw new FuzzingEngineConfigurationFailure(
      engine,
      "engine_not_configured",
      `No ${engine} engine is selected: ${setting} is unset`,
      setting,
      remediation,
    );
  if (!isAbsolute(command))
    throw new FuzzingEngineConfigurationFailure(
      engine,
      "not_absolute",
      `${setting} must be an absolute path`,
      setting,
      remediation,
      { configured_path: command },
    );
  return command;
};

/** Whether this host runs the macOS arm64 FRIDA mode the adapter documents. */
const aflFridaHostSupported = (
  platform: NodeJS.Platform,
  arch: string,
): boolean => platform === "darwin" && arch === "arm64";

const jackalopeBuild = (
  directory: string,
): FuzzingEngineConfiguration | FuzzingEngineConfigurationFailure => {
  const remediation = FUZZING_JACKALOPE_REMEDIATION;
  try {
    if (!statSync(directory).isDirectory())
      return new FuzzingEngineConfigurationFailure(
        "jackalope",
        "build_missing",
        `The selected Jackalope path is not a directory: ${directory}`,
        FUZZING_JACKALOPE_DIR_ENV,
        remediation,
        { selected_directory: directory },
      );
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    return new FuzzingEngineConfigurationFailure(
      "jackalope",
      "build_missing",
      `The selected Jackalope build directory was not found: ${directory}`,
      FUZZING_JACKALOPE_DIR_ENV,
      remediation,
      {
        selected_directory: directory,
        ...(code === undefined ? {} : { filesystem_error: code }),
      },
      { cause },
    );
  }
  const command = join(directory, FUZZING_JACKALOPE_FUZZER_FILE);
  const instrumentation = join(
    directory,
    FUZZING_JACKALOPE_INSTRUMENTATION_FILE,
  );
  const executable = executableFailure(
    "jackalope",
    command,
    FUZZING_JACKALOPE_DIR_ENV,
  );
  if (executable !== null) return executable;
  try {
    if (!statSync(instrumentation).isFile())
      throw Object.assign(new Error("not a file"), { code: "ENOENT" });
  } catch (cause: unknown) {
    return new FuzzingEngineConfigurationFailure(
      "jackalope",
      "build_missing",
      `The selected Jackalope build has no ${FUZZING_JACKALOPE_INSTRUMENTATION_FILE} module: ${instrumentation}`,
      FUZZING_JACKALOPE_DIR_ENV,
      remediation,
      { selected_directory: directory },
      { cause },
    );
  }
  return { engine: "jackalope", command, supportDirectory: directory };
};

/**
 * Resolve one caller-supplied engine, fail-closed.
 *
 * REA never builds, downloads, or installs an engine or a fuzz target. An
 * unconfigured engine leaves every other engine and the campaign bookkeeping
 * usable; only the launch that selected it refuses.
 */
export const resolveFuzzingEngineConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
  engine: FuzzingEngine,
  host: {
    readonly platform?: NodeJS.Platform;
    readonly arch?: string;
    /**
     * Whether this process can observe the selected path. A lab-VM route names
     * a guest path that does not exist on the host, so it resolves without the
     * local probe and reports the guest's own launch failure instead.
     */
    readonly probe?: boolean;
  } = {},
): FuzzingEngineConfiguration => {
  if (engine === "jackalope") {
    const build = jackalopeBuild(
      configuredPath(environment, engine, FUZZING_JACKALOPE_DIR_ENV),
    );
    if (build instanceof FuzzingEngineConfigurationFailure) throw build;
    return build;
  }
  if (
    engine === "aflpp_frida" &&
    !aflFridaHostSupported(
      host.platform ?? process.platform,
      host.arch ?? process.arch,
    )
  )
    throw new FuzzingEngineConfigurationFailure(
      engine,
      "unsupported_host",
      `AFL++ FRIDA mode is selected for host execution on ${host.platform ?? process.platform}-${host.arch ?? process.arch}; the adapter documents macOS arm64. Run the engine in a lab VM for a Linux guest.`,
      FUZZING_AFLFRIDA_COMMAND_ENV,
      FUZZING_AFLFRIDA_REMEDIATION,
      { host_platform: host.platform ?? process.platform },
    );
  const command = configuredPath(
    environment,
    engine,
    engine === "libfuzzer"
      ? FUZZING_LFZ_COMMAND_ENV
      : FUZZING_AFLFRIDA_COMMAND_ENV,
  );
  if (host.probe !== false) {
    const failure = executableFailure(
      engine,
      command,
      engine === "libfuzzer"
        ? FUZZING_LFZ_COMMAND_ENV
        : FUZZING_AFLFRIDA_COMMAND_ENV,
    );
    if (failure !== null) throw failure;
  }
  return { engine, command, supportDirectory: null };
};

/** Per-engine selection state, without starting or probing any engine. */
export const inspectFuzzingEngines = (
  environment: Readonly<Record<string, string | undefined>>,
  host: {
    readonly platform?: NodeJS.Platform;
    readonly arch?: string;
    /**
     * Whether this process can observe the selected path. A lab-VM route names
     * a guest path that does not exist on the host, so it resolves without the
     * local probe and reports the guest's own launch failure instead.
     */
    readonly probe?: boolean;
  } = {},
): readonly {
  readonly engine: FuzzingEngine;
  readonly available: boolean;
  readonly reason: string | null;
}[] =>
  FUZZING_ENGINES.map((engine) => {
    try {
      resolveFuzzingEngineConfiguration(environment, engine, host);
      return { engine, available: true, reason: null };
    } catch (cause: unknown) {
      return {
        engine,
        available: false,
        reason:
          cause instanceof FuzzingEngineConfigurationFailure
            ? cause.message
            : `The ${engine} selection could not be resolved`,
      };
    }
  });

/**
 * Fresh owner observation of the engine selection for discovery.
 *
 * One configured engine makes the campaign lane available; the selected engine
 * is still resolved again at launch, so discovery never claims an engine the
 * launch would refuse.
 */
export const fuzzingEngineAvailability = (
  environment: Readonly<Record<string, string | undefined>>,
  host: {
    readonly platform?: NodeJS.Platform;
    readonly arch?: string;
    /**
     * Whether this process can observe the selected path. A lab-VM route names
     * a guest path that does not exist on the host, so it resolves without the
     * local probe and reports the guest's own launch failure instead.
     */
    readonly probe?: boolean;
  } = {},
): ProviderAvailability => {
  const engines = inspectFuzzingEngines(environment, host);
  const selected = engines.filter((engine) => engine.available);
  if (selected.length > 0)
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: {
        engines: selected.map((engine) => engine.engine),
      },
    };
  return {
    status: "unavailable",
    code: "not_configured",
    reason: engines.map((engine) => engine.reason ?? "").join(" "),
    diagnostics: {
      engines: engines.map((engine) => engine.engine),
      settings: [
        FUZZING_LFZ_COMMAND_ENV,
        FUZZING_AFLFRIDA_COMMAND_ENV,
        FUZZING_JACKALOPE_DIR_ENV,
      ],
    },
  };
};
