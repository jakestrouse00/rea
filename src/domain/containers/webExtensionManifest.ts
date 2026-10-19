import { z } from "zod";
import {
  ContainerFormatError,
  containerLimitError,
} from "./containerFormatError.js";

/** Bounded, value-free projection of an extension manifest.json. */
export const MAX_WEBEXT_MANIFEST_BYTES = 4 * 1024 * 1024;
export const MAX_WEBEXT_LIST_ITEMS = 1024;

const nonnegative = z.number().int().nonnegative();

export const webExtensionContentScriptSchema = z.strictObject({
  matches: z.array(z.string()),
  js: z.array(z.string()),
  css: z.array(z.string()),
});

export const webExtensionGeckoSettingsSchema = z.strictObject({
  id: z.string().nullable(),
  strict_min_version: z.string().nullable(),
});

export const webExtensionManifestSchema = z.strictObject({
  name: z.string().nullable(),
  version: z.string().nullable(),
  manifest_version: z
    .union([z.literal(1), z.literal(2), z.literal(3)])
    .nullable(),
  permissions: z.array(z.string()),
  host_permissions: z.array(z.string()),
  background_service_worker: z.string().nullable(),
  background_scripts: z.array(z.string()),
  content_scripts: z.array(webExtensionContentScriptSchema),
  browser_specific_settings: webExtensionGeckoSettingsSchema.nullable(),
  unrecognized_member_count: nonnegative,
  limitations: z.array(z.string()),
});
export type WebExtensionContentScript = z.infer<
  typeof webExtensionContentScriptSchema
>;
export type WebExtensionGeckoSettings = z.infer<
  typeof webExtensionGeckoSettingsSchema
>;
export type WebExtensionManifest = z.infer<typeof webExtensionManifestSchema>;

const optionalString = (
  manifest: Record<string, unknown>,
  key: string,
): string | null => {
  const value = manifest[key];
  return typeof value === "string" ? value : null;
};

const optionalStringList = (
  manifest: Record<string, unknown>,
  key: string,
): string[] | undefined => {
  const value = manifest[key];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string"))
    return undefined;
  const list = value as string[];
  return list.length > MAX_WEBEXT_LIST_ITEMS
    ? list.slice(0, MAX_WEBEXT_LIST_ITEMS)
    : list;
};

const projectContentScript = (
  value: unknown,
): WebExtensionContentScript | undefined => {
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as Record<string, unknown>;
  return {
    matches: optionalStringList(record, "matches") ?? [],
    js: optionalStringList(record, "js") ?? [],
    css: optionalStringList(record, "css") ?? [],
  };
};

const projectGeckoSettings = (
  value: unknown,
): WebExtensionGeckoSettings | null | undefined => {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as Record<string, unknown>;
  const gecko = record["gecko"];
  if (typeof gecko !== "object" || gecko === null)
    return { id: null, strict_min_version: null };
  const geckoRecord = gecko as Record<string, unknown>;
  return {
    id: optionalString(geckoRecord, "id"),
    strict_min_version: optionalString(geckoRecord, "strict_min_version"),
  };
};

const truncatedListLimitation = (declared: number): string =>
  `manifest.json declares ${String(declared)} items in a collection; observation is truncated to the first ${String(MAX_WEBEXT_LIST_ITEMS)}.`;

/** Parse bounded manifest.json bytes into the value-free extension metadata surface. */
export const parseWebExtensionManifest = (
  bytes: Uint8Array,
): WebExtensionManifest => {
  if (bytes.length > MAX_WEBEXT_MANIFEST_BYTES)
    throw containerLimitError(
      "extension manifest.json",
      bytes.length,
      MAX_WEBEXT_MANIFEST_BYTES,
    );
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (cause: unknown) {
    throw new ContainerFormatError(
      "format",
      "Extension manifest.json is not valid UTF-8 JSON",
      { cause },
    );
  }
  if (typeof json !== "object" || json === null || Array.isArray(json))
    throw new ContainerFormatError(
      "format",
      "Extension manifest.json must decode to a JSON object",
    );
  const manifest = json as Record<string, unknown>;
  const limitations: string[] = [];
  const contentScriptsRaw = manifest["content_scripts"];
  let contentScripts: WebExtensionManifest["content_scripts"] = [];
  if (Array.isArray(contentScriptsRaw)) {
    contentScripts = contentScriptsRaw
      .map(projectContentScript)
      .filter(
        (
          value,
        ): value is NonNullable<ReturnType<typeof projectContentScript>> =>
          value !== undefined,
      );
    if (contentScripts.length > MAX_WEBEXT_LIST_ITEMS) {
      contentScripts = contentScripts.slice(0, MAX_WEBEXT_LIST_ITEMS);
      limitations.push(truncatedListLimitation(contentScriptsRaw.length));
    }
  }
  const unrecognizedMemberCount = Object.keys(manifest).filter(
    (key) =>
      ![
        "name",
        "version",
        "manifest_version",
        "permissions",
        "host_permissions",
        "background",
        "content_scripts",
        "browser_specific_settings",
      ].includes(key),
  ).length;
  if (unrecognizedMemberCount > 0)
    limitations.push(
      `${String(unrecognizedMemberCount)} unrecognized manifest.json member(s) were counted but not projected; extension metadata surfaces outside the permissions/hosts/background/content-script set are not interpreted.`,
    );
  const background = manifest["background"];
  let backgroundServiceWorker: string | null = null;
  let backgroundScripts: string[] = [];
  if (typeof background === "object" && background !== null) {
    const backgroundRecord = background as Record<string, unknown>;
    backgroundServiceWorker = optionalString(
      backgroundRecord,
      "service_worker",
    );
    // MV1/MV2 background carries script lists (or a page); keep value-free.
    backgroundScripts = optionalStringList(backgroundRecord, "scripts") ?? [];
  }

  return webExtensionManifestSchema.parse({
    name: optionalString(manifest, "name"),
    version: optionalString(manifest, "version"),
    manifest_version:
      typeof manifest["manifest_version"] === "number" &&
      Number.isInteger(manifest["manifest_version"]) &&
      [1, 2, 3].includes(manifest["manifest_version"])
        ? manifest["manifest_version"]
        : null,
    permissions: optionalStringList(manifest, "permissions") ?? [],
    host_permissions: optionalStringList(manifest, "host_permissions") ?? [],
    background_service_worker: backgroundServiceWorker,
    background_scripts: backgroundScripts,
    content_scripts: contentScripts,
    browser_specific_settings:
      projectGeckoSettings(manifest["browser_specific_settings"]) ?? null,
    unrecognized_member_count: unrecognizedMemberCount,
    limitations,
  });
};
