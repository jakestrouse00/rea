import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import type {
  FridaScriptPresetDeclaration,
  FridaScriptPresetName,
  FridaScriptPresetSource,
} from "../domain/fridaScriptPreset.js";
import { err, ok, type Result } from "../domain/result.js";

const presetDirectory = new URL("../../bridge/frida/presets/", import.meta.url);

/**
 * The presets this release ships. Each is authored for this repository as a
 * minimal reference agent: structure-only hooks over publicly documented
 * checks, never a copy of an upstream project. Upstream projects that
 * inspired the names (including the AGPL-3.0 httptoolkit
 * frida-interception-and-unpinning) are documented, not vendored; see
 * third_party/frida-presets/README.md.
 */
export const FRIDA_SCRIPT_PRESETS: readonly FridaScriptPresetDeclaration[] = [
  {
    name: "ssl-unpinning",
    title: "TLS certificate pinning bypass",
    description:
      "Hooks OkHttp CertificatePinner, conscrypt TrustManagerImpl, X509TrustManagerExtensions, and the NSURLSession challenge delegate so an intercepted TLS session continues past certificate pinning. Reports each hook's installation status and a per-hook interception counter.",
    detectedMethods: [
      "okhttp3.CertificatePinner.check",
      "conscrypt.TrustManagerImpl.checkTrustedRecursive",
      "X509TrustManagerExtensions.checkServerTrusted",
      "NSURLSession.delegate-challenge",
    ],
    fileName: "ssl-unpinning.js",
  },
  {
    name: "jail-root-detect-bypass",
    title: "Jailbreak/root detection bypass",
    description:
      "Hooks Java file/exec/build-tag/package-manager probes and the NSFileManager path probe, answering the documented jailbreak and root markers as absent. File content and property values are never read; each refusal is counted by hook.",
    detectedMethods: [
      "java.io.File.exists",
      "java.lang.Runtime.exec",
      "android.os.Build.TAGS",
      "ApplicationPackageManager.getPackageInfo",
      "NSFileManager.fileExistsAtPath",
    ],
    fileName: "jail-root-detect-bypass.js",
  },
  {
    name: "keystore-dump-structure",
    title: "Android Keystore structure inventory",
    description:
      "Enumerates AndroidKeyStore aliases and reports each entry's structural facts (alias, algorithm, format, entry type). Key material, encoded bytes, and certificates are never read or sent.",
    detectedMethods: [
      "java.security.KeyStore.AndroidKeyStore.aliases",
      "java.security.Key.getAlgorithm",
    ],
    fileName: "keystore-dump-structure.js",
  },
] as const;

export const findFridaScriptPreset = (
  name: FridaScriptPresetName,
): FridaScriptPresetDeclaration | undefined =>
  FRIDA_SCRIPT_PRESETS.find((preset) => preset.name === name);

/**
 * Read one preset's authored bytes. The digest identifies exactly the source
 * this call loaded; the caller's Evidence carries that digest and the
 * preset's declared methods, never the script text.
 */
export const readFridaScriptPreset = async (
  name: FridaScriptPresetName,
  operation: string,
): Promise<Result<FridaScriptPresetSource, AnalysisError>> => {
  const preset = findFridaScriptPreset(name);
  if (preset === undefined)
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["preset"],
          reason: "invalid_value",
          message: `Unknown Frida script preset: ${String(name)}. Use one of ${FRIDA_SCRIPT_PRESETS.map(({ name: presetName }) => presetName).join(", ")}.`,
        },
      ]),
    );
  try {
    const bytes = await readFile(new URL(preset.fileName, presetDirectory));
    return ok({
      ...preset,
      source: bytes.toString("utf8"),
      bytes: bytes.byteLength,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  } catch (cause: unknown) {
    return err(
      new AnalysisInputError(operation, { cause }, [
        {
          path: ["preset"],
          reason: "invalid_value",
          message: `The ${preset.name} preset source is not readable in this installation: ${fileURLToPath(new URL(preset.fileName, presetDirectory))}. Reinstall REA so bridge/frida/presets ships with the package.`,
        },
      ]),
    );
  }
};
