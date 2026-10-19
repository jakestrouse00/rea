/**
 * Frida bindings release shipped with this REA checkout's own dependencies;
 * observed in `node_modules/frida/package.json` on 2026-10-19. Releases other
 * than this one report as unverified.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

export const FRIDA_VERIFIED_VERSION = "17.23.2";

/** Stable provider ID shared by readiness, doctor and Evidence. */
export const FRIDA_PROVIDER_ID = "frida";

/** Remediation when the local frida Node binding cannot be loaded or probed. */
export const FRIDA_RUNTIME_PROBE_REMEDIATION = `The frida provider uses the frida Node module that ships with REA's own dependencies (verified with ${FRIDA_VERIFIED_VERSION}). REA does not download frida-server, gadget, or platform tooling; reinstall REA's dependencies if the binding fails to load.`;

/**
 * Probe the installed frida binding. The binding exports no version constant,
 * so the release comes from its installed package manifest; the load itself is
 * exercised because a failed native load is the readiness failure callers hit.
 * The binding is an optional dependency, so a missing or failed probe resolves
 * to null; doctor and Evidence treat null as an unknown version, never as
 * absence.
 */
export const probeFridaRuntimeVersion = async (
  loader: () => Promise<{ readonly version: string }> = async (): Promise<{
    readonly version: string;
  }> => {
    await import("frida");
    const entry = createRequire(import.meta.url).resolve("frida");
    let manifestDirectory = dirname(entry);
    for (let hop = 0; hop < 8; hop += 1) {
      const text = await readFile(
        join(manifestDirectory, "package.json"),
        "utf8",
      ).catch((): string | undefined => undefined);
      if (text === undefined) {
        manifestDirectory = dirname(manifestDirectory);
        continue;
      }
      const manifest = JSON.parse(text) as {
        readonly name: string;
        readonly version: string;
      };
      if (manifest.name !== "frida") throw new RangeError(manifest.name);
      return manifest;
    }
    throw new Error("frida package manifest not found");
  },
): Promise<string | null> => {
  try {
    const { version } = await loader();
    return typeof version === "string" && version.length > 0 ? version : null;
  } catch {
    return null;
  }
};
