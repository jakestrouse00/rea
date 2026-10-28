import { constants, accessSync, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";

import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
import {
  ExecFileOutputCancelledError,
  execFileFailureCapturedOutput,
  execFileOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import {
  VINEFLOWER_JAR_ENV,
  VINEFLOWER_JAR_REMEDIATION,
  VINEFLOWER_JAVA_REMEDIATION,
} from "./JvmDecompilerRelease.js";

const JAVA_VERSION_TIMEOUT_MS = 10_000;
const JAVA_VERSION_MAX_OUTPUT_BYTES = 64 * 1024;

/** One bounded decompilation. */
const DEFAULT_OPERATION_TIMEOUT_MS = 300_000;

/** Minimum Java major version Vineflower supports. */
const MINIMUM_JAVA_MAJOR = 11;

export interface JvmDecompilerConfiguration {
  readonly jar: string;
  readonly java: string;
  readonly javaVersion: string;
  readonly javaMajor: number;
  readonly operationTimeoutMs: number;
}

export type JvmDecompilerFailureCode =
  | "not_configured"
  | "not_absolute"
  | "file_missing"
  | "not_executable"
  | "version_unresolved"
  | "unsupported_version";

export class JvmDecompilerConfigurationFailure extends Error {
  constructor(
    readonly code: JvmDecompilerFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

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

const resolveJava = (
  environment: Readonly<Record<string, string | undefined>>,
): string => {
  const javaHome = environment.JAVA_HOME;
  if (javaHome !== undefined && javaHome.trim() !== "") {
    if (!isAbsolute(javaHome))
      throw new JvmDecompilerConfigurationFailure(
        "not_absolute",
        "JAVA_HOME must be an absolute JDK home path",
        {
          setting: "JAVA_HOME",
          configured_path: javaHome,
          remediation: VINEFLOWER_JAVA_REMEDIATION,
        },
      );
    const candidate = join(
      javaHome,
      "bin",
      process.platform === "win32" ? "java.exe" : "java",
    );
    try {
      accessSync(candidate, constants.X_OK);
      if (!statSync(candidate).isFile()) throw new Error("not a file");
      return candidate;
    } catch (cause) {
      throw new JvmDecompilerConfigurationFailure(
        "file_missing",
        `JAVA_HOME does not contain a runnable java executable: ${candidate}`,
        {
          setting: "JAVA_HOME",
          selected_binary: candidate,
          remediation: VINEFLOWER_JAVA_REMEDIATION,
        },
        { cause },
      );
    }
  }
  const resolved = searchPath("java", environment);
  if (resolved === null)
    throw new JvmDecompilerConfigurationFailure(
      "not_configured",
      "No Java runtime is selected: JAVA_HOME is unset and PATH carries no java",
      {
        setting: "JAVA_HOME",
        path_source: "path",
        remediation: VINEFLOWER_JAVA_REMEDIATION,
      },
    );
  return resolved;
};

const resolveJar = (
  environment: Readonly<Record<string, string | undefined>>,
): string => {
  const jar = environment[VINEFLOWER_JAR_ENV];
  if (jar === undefined || jar.trim() === "")
    throw new JvmDecompilerConfigurationFailure(
      "not_configured",
      `No Vineflower JAR is selected: ${VINEFLOWER_JAR_ENV} is unset`,
      {
        setting: VINEFLOWER_JAR_ENV,
        remediation: VINEFLOWER_JAR_REMEDIATION,
      },
    );
  if (!isAbsolute(jar))
    throw new JvmDecompilerConfigurationFailure(
      "not_absolute",
      `${VINEFLOWER_JAR_ENV} must be an absolute path to the Vineflower JAR`,
      {
        setting: VINEFLOWER_JAR_ENV,
        configured_path: jar,
        remediation: VINEFLOWER_JAR_REMEDIATION,
      },
    );
  try {
    accessSync(jar, constants.R_OK);
    if (!statSync(jar).isFile()) throw new Error("not a file");
  } catch (cause) {
    throw new JvmDecompilerConfigurationFailure(
      "file_missing",
      `The selected Vineflower JAR could not be read: ${jar}`,
      {
        setting: VINEFLOWER_JAR_ENV,
        selected_binary: jar,
        remediation: VINEFLOWER_JAR_REMEDIATION,
      },
      { cause },
    );
  }
  return jar;
};

const JAVA_VERSION_PATTERN = /\bversion\s+"(?:1\.)?(\d+)(?:[._+-]\d+)*"/u;

/** Parse `java -version`, which writes to stderr on every supported JDK. */
export const parseJavaVersionOutput = (
  stdout: string,
  stderr: string,
): { readonly version: string; readonly major: number } | null => {
  const combined = `${stderr}\n${stdout}`;
  const match = JAVA_VERSION_PATTERN.exec(combined);
  if (match === null) return null;
  const versionLine = combined
    .split(/\r?\n/u)
    .find((line) => JAVA_VERSION_PATTERN.test(line));
  return {
    version: versionLine?.trim() ?? `java ${match[1]!}`,
    major: Number.parseInt(match[1]!, 10),
  };
};

/** Resolve the JAR and JDK, then assert a supported Java version. */
export const resolveJvmDecompilerConfiguration = async (
  environment: Readonly<Record<string, string | undefined>>,
  signal?: AbortSignal,
  operation = "decompile_jar_archive",
): Promise<JvmDecompilerConfiguration> => {
  const jar = resolveJar(environment);
  const java = resolveJava(environment);
  const observed = await inspectJavaRuntime(java, signal, operation);
  return {
    jar,
    java,
    javaVersion: observed.version,
    javaMajor: observed.major,
    operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS,
  };
};

const inspectJavaRuntime = async (
  java: string,
  signal: AbortSignal | undefined,
  operation: string,
): Promise<{ readonly version: string; readonly major: number }> => {
  try {
    const { stdout, stderr } = await execFileOutput(java, ["-version"], {
      timeout: JAVA_VERSION_TIMEOUT_MS,
      stopSignal: "SIGTERM",
      maxBuffer: JAVA_VERSION_MAX_OUTPUT_BYTES,
      ...(signal === undefined ? {} : { signal }),
    });
    const observed = parseJavaVersionOutput(stdout, stderr);
    if (observed === null)
      throw new JvmDecompilerConfigurationFailure(
        "version_unresolved",
        "The selected Java runtime did not report a parseable version",
        {
          selected_binary: java,
          version_probe: "unrecognized_output",
          remediation: VINEFLOWER_JAVA_REMEDIATION,
        },
      );
    if (observed.major < MINIMUM_JAVA_MAJOR)
      throw new JvmDecompilerConfigurationFailure(
        "unsupported_version",
        `The selected Java runtime is ${String(observed.major)}; Vineflower needs Java ${String(MINIMUM_JAVA_MAJOR)} or newer`,
        {
          selected_binary: java,
          java_major: observed.major,
          minimum_java_major: MINIMUM_JAVA_MAJOR,
          remediation: VINEFLOWER_JAVA_REMEDIATION,
        },
      );
    return observed;
  } catch (cause) {
    if (cause instanceof JvmDecompilerConfigurationFailure) throw cause;
    const failure = execFileOutputFailure(cause);
    if (cause instanceof ExecFileOutputCancelledError)
      throw new AnalysisCancelledError(operation, {
        cause: cause.cause,
        ...(failure === undefined
          ? {}
          : { capturedOutput: execFileFailureCapturedOutput(failure) }),
      });
    const diagnostics = {
      selected_binary: java,
      ...(failure === undefined ? {} : { exit_code: failure.code }),
    };
    const options = {
      cause,
      diagnostics,
      ...(failure === undefined
        ? {}
        : { capturedOutput: execFileFailureCapturedOutput(failure) }),
    };
    if (failure?.outputTruncated === true)
      throw new AnalysisResourceConstraintError(
        operation,
        "memory",
        `java -version output exceeded the ${String(JAVA_VERSION_MAX_OUTPUT_BYTES)}-byte capture budget`,
        { max_output_bytes: JAVA_VERSION_MAX_OUTPUT_BYTES },
        {
          ...options,
          ...fixedAllowanceOptions(
            `The java -version capture allowance of ${String(JAVA_VERSION_MAX_OUTPUT_BYTES)} bytes (this release has no runtime override)`,
            "capture",
          ),
        },
      );
    if (failure?.code === "ETIMEDOUT")
      throw new AnalysisTimeoutError(operation, JAVA_VERSION_TIMEOUT_MS, {
        ...options,
        userMessage: `The java -version probe reached its ${String(JAVA_VERSION_TIMEOUT_MS)} ms deadline (deadlineExpired). This release has no runtime override.`,
        remediationAction: `This ${String(JAVA_VERSION_TIMEOUT_MS)} ms Java version probe has no runtime override. Allow execution, cleanup and delivery headroom in the outer MCP client deadline. Confirm outstanding work and cleanup before retrying.`,
      });
    if (failure?.code === "ENOENT")
      throw new JvmDecompilerConfigurationFailure(
        "file_missing",
        `The selected Java runtime was not found: ${java}`,
        {
          selected_binary: java,
          remediation: VINEFLOWER_JAVA_REMEDIATION,
        },
        { cause },
      );
    if (failure?.code === "EACCES" || failure?.code === "EPERM")
      throw new JvmDecompilerConfigurationFailure(
        "not_executable",
        `Execution of the selected Java runtime was denied: ${java}`,
        {
          selected_binary: java,
          filesystem_error: failure.code,
          remediation: VINEFLOWER_JAVA_REMEDIATION,
        },
        { cause },
      );
    throw new JvmDecompilerConfigurationFailure(
      "version_unresolved",
      "The selected Java runtime did not report a usable version",
      {
        selected_binary: java,
        ...(failure === undefined
          ? {}
          : {
              exit_code: failure.code,
              stderr_excerpt: failure.stderr.slice(0, 512),
            }),
        remediation: VINEFLOWER_JAVA_REMEDIATION,
      },
      { cause },
    );
  }
};

const rejectionCodeOf = (
  code: JvmDecompilerFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "file_missing":
      return "executable_missing";
    case "version_unresolved":
      return "version_unresolved";
    case "unsupported_version":
      return "unsupported_version";
    case "not_configured":
    case "not_absolute":
    case "not_executable":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const jvmDecompilerConfigurationAvailability = (
  cause: JvmDecompilerConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
