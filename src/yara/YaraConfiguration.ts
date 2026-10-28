import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
import {
  ExecFileOutputCancelledError,
  execFileFailureCapturedOutput,
  execFileOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import {
  YARA_CRYPTO_PACK,
  YARA_CRYPTO_PACK_REMEDIATION,
  YARAX_COMMAND_ENV,
  YARAX_COMMAND_REMEDIATION,
  YARAX_VERSION_PROBE_REMEDIATION,
} from "./YaraRelease.js";

const VERSION_TIMEOUT_MS = 10_000;
const VERSION_MAX_OUTPUT_BYTES = 64 * 1024;

/** One bounded scan over a local artifact. */
const DEFAULT_OPERATION_TIMEOUT_MS = 300_000;

/** Caller-selected YARA-X CLI and REA-owned bounds. */
export interface YaraConfiguration {
  readonly command: string;
  readonly operationTimeoutMs: number;
}

export type YaraConfigurationFailureCode =
  | "not_configured"
  | "not_absolute"
  | "binary_missing"
  | "binary_not_executable"
  | "version_unresolved";

export class YaraConfigurationFailure extends Error {
  constructor(
    readonly code: YaraConfigurationFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

export type YaraRulePackFailureCode =
  | "rule_pack_missing"
  | "rule_pack_invalid"
  | "rule_pack_mismatch";

/** Fail-closed result when REA's own vendored rule pack is unusable. */
export class YaraRulePackFailure extends Error {
  constructor(
    readonly code: YaraRulePackFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/**
 * Resolve the caller-supplied YARA-X binary. This release has no PATH
 * fallback: an unset `REA_YARAX_COMMAND` is a configuration refusal.
 */
export const resolveYaraConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): YaraConfiguration => {
  const command = environment[YARAX_COMMAND_ENV];
  if (command === undefined || command.trim() === "")
    throw new YaraConfigurationFailure(
      "not_configured",
      `No YARA-X CLI is selected: ${YARAX_COMMAND_ENV} is unset`,
      {
        setting: YARAX_COMMAND_ENV,
        remediation: YARAX_COMMAND_REMEDIATION,
      },
    );
  if (!isAbsolute(command))
    throw new YaraConfigurationFailure(
      "not_absolute",
      `${YARAX_COMMAND_ENV} must be an absolute path to the YARA-X \`yr\` binary`,
      {
        setting: YARAX_COMMAND_ENV,
        configured_path: command,
        remediation: YARAX_COMMAND_REMEDIATION,
      },
    );
  return { command, operationTimeoutMs: DEFAULT_OPERATION_TIMEOUT_MS };
};

const YARA_VERSION_PATTERN = /\b(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b/u;

/** Parse `yr --version`, which prints `yr <semver>` or a bare version. */
export const parseYaraVersionOutput = (stdout: string): string | null => {
  const match = YARA_VERSION_PATTERN.exec(stdout);
  return match === null ? null : match[1]!;
};

export interface YaraClientIdentity {
  readonly version: string | null;
}

/** Probe the selected binary without scanning any target. */
export const inspectYaraClient = async (
  configuration: YaraConfiguration,
  signal?: AbortSignal,
  operation = "scan_artifact_with_rules",
): Promise<YaraClientIdentity> => {
  try {
    const { stdout } = await execFileOutput(
      configuration.command,
      ["--version"],
      {
        timeout: VERSION_TIMEOUT_MS,
        stopSignal: "SIGTERM",
        maxBuffer: VERSION_MAX_OUTPUT_BYTES,
        ...(signal === undefined ? {} : { signal }),
      },
    );
    const version = parseYaraVersionOutput(stdout);
    if (version === null)
      throw new YaraConfigurationFailure(
        "version_unresolved",
        "The selected YARA-X binary exited successfully but did not report a recognizable version",
        {
          selected_binary: configuration.command,
          version_probe: "unrecognized_output",
          remediation: YARAX_VERSION_PROBE_REMEDIATION,
        },
      );
    return { version };
  } catch (cause) {
    if (cause instanceof YaraConfigurationFailure) throw cause;
    const failure = execFileOutputFailure(cause);
    if (cause instanceof ExecFileOutputCancelledError)
      throw new AnalysisCancelledError(operation, {
        cause: cause.cause,
        ...(failure === undefined
          ? {}
          : { capturedOutput: execFileFailureCapturedOutput(failure) }),
      });
    const diagnostics = {
      selected_binary: configuration.command,
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
        `YARA-X version output exceeded the ${String(VERSION_MAX_OUTPUT_BYTES)}-byte capture budget`,
        { max_output_bytes: VERSION_MAX_OUTPUT_BYTES },
        {
          ...options,
          ...fixedAllowanceOptions(
            `The YARA-X version-output capture allowance of ${String(VERSION_MAX_OUTPUT_BYTES)} bytes (this release has no runtime override)`,
            "capture",
          ),
        },
      );
    if (failure?.code === "ETIMEDOUT")
      throw new AnalysisTimeoutError(operation, VERSION_TIMEOUT_MS, {
        ...options,
        userMessage: `The YARA-X version probe reached its ${String(VERSION_TIMEOUT_MS)} ms deadline (deadlineExpired). This release has no runtime override.`,
        remediationAction: `This ${String(VERSION_TIMEOUT_MS)} ms YARA-X version probe has no runtime override. Allow execution, cleanup and delivery headroom in the outer MCP client deadline. Confirm outstanding work and cleanup before retrying.`,
      });
    if (failure?.code === "ENOENT")
      throw new YaraConfigurationFailure(
        "binary_missing",
        `The selected YARA-X binary was not found: ${configuration.command}`,
        {
          selected_binary: configuration.command,
          remediation: YARAX_COMMAND_REMEDIATION,
        },
        { cause },
      );
    if (failure?.code === "EACCES" || failure?.code === "EPERM")
      throw new YaraConfigurationFailure(
        "binary_not_executable",
        `Execution of the selected YARA-X binary was denied (${failure.code}): ${configuration.command}`,
        {
          selected_binary: configuration.command,
          filesystem_error: failure.code,
          remediation: YARAX_COMMAND_REMEDIATION,
        },
        { cause },
      );
    throw new YaraConfigurationFailure(
      "version_unresolved",
      "The selected YARA-X binary did not report a usable version",
      {
        selected_binary: configuration.command,
        ...(failure === undefined
          ? {}
          : {
              exit_code: failure.code,
              stderr_excerpt: failure.stderr.slice(0, 512),
            }),
        remediation: YARAX_VERSION_PROBE_REMEDIATION,
      },
      { cause },
    );
  }
};

const rejectionCodeOf = (
  code: YaraConfigurationFailureCode,
): ProviderRejectionCode => {
  switch (code) {
    case "binary_missing":
      return "executable_missing";
    case "version_unresolved":
      return "version_unresolved";
    case "not_configured":
    case "not_absolute":
    case "binary_not_executable":
      return "not_configured";
  }
};

/** Availability in the shape shared by every probe-backed provider. */
export const yaraConfigurationAvailability = (
  cause: YaraConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: rejectionCodeOf(cause.code),
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});

const manifestSchema = z.strictObject({
  pack: z.string().min(1),
  version: z.int().nonnegative(),
  description: z.string().min(1).optional(),
  rules: z
    .array(
      z.strictObject({
        file: z.string().min(1),
        sha256: z.string().regex(/^[a-f0-9]{64}$/u),
      }),
    )
    .min(1),
});

export interface CryptoRulePack {
  readonly rulesPath: string;
  readonly rulesSha256: string;
  readonly pack: string;
  readonly version: number;
}

const cryptoPackDirectory = (): string =>
  fileURLToPath(new URL(YARA_CRYPTO_PACK.directory, import.meta.url));

/**
 * Read and verify the vendored crypto-constant pack against its manifest.
 * A missing, malformed, or hash-mismatched pack is a typed refusal; REA never
 * substitutes a downloaded pack.
 */
export const resolveCryptoRulePack = async (): Promise<CryptoRulePack> => {
  const directory = cryptoPackDirectory();
  const manifestPath = join(directory, YARA_CRYPTO_PACK.manifestFile);
  let manifestText: string;
  try {
    manifestText = await readFile(manifestPath, "utf8");
  } catch (cause) {
    throw new YaraRulePackFailure(
      "rule_pack_missing",
      `The bundled ${YARA_CRYPTO_PACK.id} manifest could not be read`,
      {
        expected_path: manifestPath,
        remediation: YARA_CRYPTO_PACK_REMEDIATION,
      },
      { cause },
    );
  }
  let manifest: z.infer<typeof manifestSchema>;
  try {
    manifest = manifestSchema.parse(JSON.parse(manifestText) as unknown);
  } catch (cause) {
    throw new YaraRulePackFailure(
      "rule_pack_invalid",
      `The bundled ${YARA_CRYPTO_PACK.id} manifest is not a recognized rule index`,
      {
        expected_path: manifestPath,
        remediation: YARA_CRYPTO_PACK_REMEDIATION,
      },
      { cause },
    );
  }
  const entry = manifest.rules.find(
    ({ file }) => file === YARA_CRYPTO_PACK.ruleFile,
  );
  if (entry === undefined)
    throw new YaraRulePackFailure(
      "rule_pack_invalid",
      `The bundled ${YARA_CRYPTO_PACK.id} manifest does not list ${YARA_CRYPTO_PACK.ruleFile}`,
      {
        expected_path: manifestPath,
        remediation: YARA_CRYPTO_PACK_REMEDIATION,
      },
    );
  const rulesPath = join(directory, entry.file);
  let contents: Buffer;
  try {
    contents = await readFile(rulesPath);
  } catch (cause) {
    throw new YaraRulePackFailure(
      "rule_pack_missing",
      `The bundled ${YARA_CRYPTO_PACK.id} rule file could not be read`,
      {
        expected_path: rulesPath,
        remediation: YARA_CRYPTO_PACK_REMEDIATION,
      },
      { cause },
    );
  }
  const sha256 = createHash("sha256").update(contents).digest("hex");
  if (sha256 !== entry.sha256)
    throw new YaraRulePackFailure(
      "rule_pack_mismatch",
      `The bundled ${YARA_CRYPTO_PACK.id} rule file does not match its pinned SHA-256`,
      {
        expected_path: rulesPath,
        expected_sha256: entry.sha256,
        observed_sha256: sha256,
        remediation: YARA_CRYPTO_PACK_REMEDIATION,
      },
    );
  return {
    rulesPath,
    rulesSha256: sha256,
    pack: manifest.pack,
    version: manifest.version,
  };
};
