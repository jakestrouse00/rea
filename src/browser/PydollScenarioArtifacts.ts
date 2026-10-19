import { createHash } from "node:crypto";
import { readFile, rm } from "node:fs/promises";

import {
  browserStepArtifactsSchema,
  type BrowserStepArtifacts,
} from "../domain/browserScenarioCaptureValues.js";
import type { BrowserScenario } from "../domain/browserScenario.js";
import type { BrowserScenarioSecrets } from "./BrowserScenarioSecrets.js";
import type {
  PydollCaptureArtifact,
  PydollCaptureResult,
} from "./pydollBridgeProtocol.js";

type SnapshotKind = BrowserScenario["capture"]["after_each_step"][number];

const notRequested = () => ({ state: "not_requested" as const });
const missing = (reason: string) => ({ state: "missing" as const, reason });

const textArtifact = (text: string) => {
  const bytes = Buffer.from(text);
  return {
    state: "captured" as const,
    value: {
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.byteLength,
      text,
    },
  };
};

const normalizeSameSite = (value: string): "Strict" | "Lax" | "None" => {
  const normalized =
    value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
  return normalized === "Strict" ||
    normalized === "Lax" ||
    normalized === "None"
    ? normalized
    : "None";
};

const navigationType = (
  value: string,
): "navigate" | "reload" | "back_forward" | "prerender" | "unknown" => {
  switch (value) {
    case "navigate":
    case "reload":
    case "back_forward":
    case "prerender":
      return value;
    default:
      return "unknown";
  }
};

/** Digest-verified bounded read of one bridge artifact file. */
const readArtifactFile = async (
  artifact: Extract<PydollCaptureArtifact, { path: string }> | undefined,
  maxBytes: number,
): Promise<
  { readonly content: string; readonly truncated: boolean } | undefined
> => {
  if (artifact === undefined || artifact.bytes > maxBytes) return undefined;
  const bytes = await readFile(artifact.path);
  if (
    bytes.byteLength !== artifact.bytes ||
    createHash("sha256").update(bytes).digest("hex") !== artifact.sha256
  )
    return undefined;
  return {
    content: bytes.toString("utf8"),
    truncated: artifact.truncated === true,
  };
};

/** Spilled artifacts embed their JSON payload in the file with the kind key removed. */
const readSpilledArtifact = async (
  artifact: Extract<PydollCaptureArtifact, { path: string }> | undefined,
  maxBytes: number,
): Promise<Record<string, unknown> | undefined> => {
  if (artifact === undefined) return undefined;
  if (artifact.kind !== "history" && artifact.kind !== "storage")
    return undefined;
  const read = await readArtifactFile(artifact, maxBytes);
  if (read === undefined) return undefined;
  try {
    const parsed: unknown = JSON.parse(read.content);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
};

/** Bridge artifact files live only in the caller-created session scratch directory. */
const removeArtifactFiles = async (
  assets: readonly string[],
  sessionDir: string,
): Promise<void> => {
  for (const path of assets)
    if (path.startsWith(sessionDir))
      await rm(path, { force: true, maxRetries: 3 }).catch(() => undefined);
};

/** Map one bridge capture reply into step artifacts; redaction stays Node-owned. */
export const capturePydollStepArtifacts = async (input: {
  readonly result: PydollCaptureResult;
  readonly requested: ReadonlySet<SnapshotKind>;
  readonly secrets: BrowserScenarioSecrets;
  readonly sessionUrl: string;
  readonly sessionDir: string;
  readonly maxArtifactBytes: number;
}): Promise<BrowserStepArtifacts> => {
  const { result, requested, secrets, sessionDir, maxArtifactBytes } = input;
  const byKind = (kind: string): PydollCaptureArtifact | undefined => {
    let match: PydollCaptureArtifact | undefined;
    for (const artifact of result.artifacts)
      if ("kind" in artifact && artifact.kind === kind) match = artifact;
    return match;
  };
  const fileArtifactOf = (
    kind: string,
  ): Extract<PydollCaptureArtifact, { path: string }> | undefined => {
    const artifact = byKind(kind);
    if (artifact !== undefined && artifact.kind === kind && "path" in artifact)
      return artifact;
    return undefined;
  };
  const state = <Value>(
    kind: SnapshotKind,
    capture: () => Promise<Value>,
  ): Promise<
    Value | ReturnType<typeof notRequested> | ReturnType<typeof missing>
  > => (!requested.has(kind) ? Promise.resolve(notRequested()) : capture());
  const rawUrlArtifact = byKind("url");
  const rawUrl =
    rawUrlArtifact !== undefined &&
    rawUrlArtifact.kind === "url" &&
    rawUrlArtifact.raw_url !== null
      ? rawUrlArtifact.raw_url
      : undefined;
  // History tracks the current page even without a "url" artifact; the
  // session's tracked final URL is the fallback source.
  const historyUrl =
    rawUrl ?? (input.sessionUrl === "" ? undefined : input.sessionUrl);
  try {
    return await browserStepArtifactsSchema.parseAsync({
      screenshot: await state("screenshot", async () => {
        try {
          const screenshot = fileArtifactOf("screenshot");
          if (screenshot === undefined)
            return missing("screenshot capture failed");
          const bytes = await readFile(screenshot.path);
          if (
            bytes.byteLength !== screenshot.bytes ||
            createHash("sha256").update(bytes).digest("hex") !==
              screenshot.sha256
          )
            return missing("screenshot capture failed");
          return {
            state: "captured" as const,
            value: {
              sha256: screenshot.sha256,
              bytes: screenshot.bytes,
              media_type: "image/png" as const,
              data_base64: bytes.toString("base64"),
            },
          };
        } catch {
          return missing("screenshot capture failed");
        }
      }),
      dom: await state("dom", async () => {
        try {
          const dom = fileArtifactOf("dom");
          if (dom === undefined) return missing("DOM capture failed");
          const read = await readArtifactFile(dom, maxArtifactBytes);
          if (read === undefined) return missing("DOM capture failed");
          return textArtifact(secrets.redact(read.content));
        } catch {
          return missing("DOM capture failed");
        }
      }),
      accessibility: await state("accessibility", async () => {
        try {
          const accessibility = fileArtifactOf("accessibility");
          if (accessibility === undefined)
            return missing("accessibility capture failed");
          const read = await readArtifactFile(accessibility, maxArtifactBytes);
          if (read === undefined)
            return missing("accessibility capture failed");
          return textArtifact(secrets.redact(read.content));
        } catch {
          return missing("accessibility capture failed");
        }
      }),
      url: await state("url", async () =>
        rawUrl === undefined
          ? missing("URL capture failed")
          : { state: "captured" as const, value: secrets.sanitizeUrl(rawUrl) },
      ),
      history: await state("history", async () => {
        if (historyUrl === undefined) return missing("history capture failed");
        const history = byKind("history");
        if (history === undefined) return missing("history capture failed");
        if (history.kind === "history" && "length" in history) {
          if (history.length === null) return missing("history capture failed");
          return {
            state: "captured" as const,
            value: {
              length: history.length,
              current_url: secrets.sanitizeUrl(historyUrl),
              navigation_entries: history.raw_entries.map((entry) => ({
                type: navigationType(entry.type),
                name: secrets.sanitizeUrl(entry.url),
              })),
            },
          };
        }
        const spilled = await readSpilledArtifact(
          fileArtifactOf("history"),
          maxArtifactBytes,
        );
        const length = spilled?.length;
        const entries = Array.isArray(spilled?.raw_entries)
          ? (spilled.raw_entries as readonly { type: string; url: string }[])
          : [];
        if (typeof length !== "number")
          return missing("history capture failed");
        return {
          state: "captured" as const,
          value: {
            length,
            current_url: secrets.sanitizeUrl(historyUrl),
            navigation_entries: entries.map((entry) => ({
              type: navigationType(entry.type),
              name: secrets.sanitizeUrl(entry.url),
            })),
          },
        };
      }),
      storage: await state("storage", async () => {
        const storage = byKind("storage");
        if (storage === undefined) return missing("storage capture failed");
        let cookies: unknown[];
        let localStorageBuckets: unknown[];
        let sessionStorageBuckets: unknown[];
        if (storage.kind === "storage" && "cookies" in storage) {
          cookies = storage.cookies;
          localStorageBuckets = storage.local_storage;
          sessionStorageBuckets = storage.session_storage;
        } else {
          const spilled = await readSpilledArtifact(
            fileArtifactOf("storage"),
            maxArtifactBytes,
          );
          if (spilled === undefined) return missing("storage capture failed");
          cookies = Array.isArray(spilled.cookies) ? spilled.cookies : [];
          localStorageBuckets = Array.isArray(spilled.local_storage)
            ? spilled.local_storage
            : [];
          sessionStorageBuckets = Array.isArray(spilled.session_storage)
            ? spilled.session_storage
            : [];
        }
        const cookieEntries = cookies.flatMap((cookie) => {
          if (typeof cookie !== "object" || cookie === null) return [];
          const record = cookie as Record<string, unknown>;
          if (
            typeof record.name !== "string" ||
            typeof record.value !== "string" ||
            typeof record.domain !== "string" ||
            typeof record.path !== "string" ||
            typeof record.secure !== "boolean" ||
            typeof record.http_only !== "boolean" ||
            typeof record.same_site !== "string"
          )
            return [];
          return [
            {
              name: secrets.redact(record.name),
              domain: secrets.redact(record.domain),
              path: secrets.redact(record.path),
              secure: record.secure,
              http_only: record.http_only,
              same_site: normalizeSameSite(record.same_site),
              ...secrets.fingerprint(record.value),
            },
          ];
        });
        const storageBucketEntries = (buckets: unknown[]) =>
          buckets.flatMap((bucket) => {
            if (typeof bucket !== "object" || bucket === null) return [];
            const record = bucket as Record<string, unknown>;
            const entries = Array.isArray(record.entries) ? record.entries : [];
            return (entries as unknown[]).flatMap((entry) => {
              if (typeof entry !== "object" || entry === null) return [];
              const item = entry as Record<string, unknown>;
              if (
                typeof item.name !== "string" ||
                typeof item.value !== "string"
              )
                return [];
              return [
                {
                  name: secrets.redact(item.name),
                  ...secrets.fingerprint(item.value),
                },
              ];
            });
          });
        return {
          state: "captured" as const,
          value: {
            cookies: cookieEntries,
            local_storage: storageBucketEntries(localStorageBuckets),
            session_storage: storageBucketEntries(sessionStorageBuckets),
          },
        };
      }),
    });
  } finally {
    await removeArtifactFiles(
      result.artifacts.flatMap((artifact) =>
        "path" in artifact ? [artifact.path] : [],
      ),
      sessionDir,
    );
  }
};
