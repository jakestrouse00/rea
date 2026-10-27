import { once } from "node:events";
import { createWriteStream } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { finished } from "node:stream/promises";

import type { ArtifactEntry } from "../../artifacts/ArtifactReader.js";
import { ZipArtifactReader } from "../../artifacts/ZipArtifactReader.js";
import {
  ArtifactResourceRetryFailure,
  ArtifactResourceScope,
} from "../../artifacts/ArtifactResourceScope.js";
import { AnalysisCleanupLease } from "../../artifacts/AnalysisCleanupLease.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { ContainerFormatError } from "../../domain/containers/containerFormatError.js";
import { CONTAINER_PROVIDER_IDENTITY } from "../../domain/containers/containerIdentity.js";
import {
  crxExtensionReportSchema,
  inspectCrxExtensionInputSchema,
  inspectPyInstallerArchiveInputSchema,
  inspectXpiExtensionInputSchema,
  pyInstallerArchiveReportSchema,
  xpiExtensionReportSchema,
} from "../../domain/containers/containerReports.js";
import {
  CRX3_HEADER_PREFIX_BYTES,
  MAX_CRX3_HEADER_BYTES,
  crx3MagicMatches,
  parseCrx3Header,
  type Crx3Header,
} from "../../domain/containers/crxHeader.js";
import {
  MAX_WEBEXT_MANIFEST_BYTES,
  parseWebExtensionManifest,
  type WebExtensionManifest,
} from "../../domain/containers/webExtensionManifest.js";
import {
  MAX_JAR_MANIFEST_BYTES,
  parseJarDigestFile,
  type JarDigestFile,
} from "../../domain/containers/jarManifestDigests.js";
import {
  CARCHIVE_COOKIE_BYTES_20,
  MAX_CARCHIVE_TOC_BYTES,
  MAX_PYZ_HEADER_BYTES,
  carchiveCookieBytesFor,
  carchiveTocEntrySchema,
  locateCarchiveCookie,
  parseCarchiveCookieBytes,
  parseCarchiveToc,
  parsePyzHeader,
  pyzArchiveInventorySchema,
  type CarchiveCookie,
  type CarchiveTocEntry,
  type PyzArchiveInventory,
} from "../../domain/containers/pyinstallerArchive.js";
import {
  MAX_PYZ_TOC_BYTES,
  parsePyzToc,
  type PyzToc,
} from "../../domain/containers/pyzToc.js";
import { parsePycHeader } from "../../domain/containers/pycHeader.js";
import {
  createEvidence,
  type Evidence,
  type EvidenceLocation,
} from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  RegularFileCleanupFailure,
  withOwnedRegularFile,
} from "../../filesystem/OwnedRegularFile.js";
import {
  assertRegularFileActive,
  openRegularFile,
  RegularFileChangedError,
} from "../../filesystem/RegularFile.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { hashStableFile } from "../../filesystem/StableFileHash.js";
import { readFileHandleChunks } from "../../filesystem/readFileHandleChunks.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import { containerFailure } from "./ContainerFailures.js";

/** Read-only container inspections: no target execution, no network. */
export const CONTAINER_OPERATIONS = [
  "inspect_crx_extension",
  "inspect_xpi_extension",
  "inspect_pyinstaller_archive",
] as const;
export type ContainerOperation = (typeof CONTAINER_OPERATIONS)[number];

export interface ContainerInspectionServiceOptions {
  /** Override runtime-root creation at the service's owned-resource boundary. */
  readonly createRuntimeRoot?: () => Promise<RuntimeRoot>;
}

type RuntimeRoot = Pick<PrivateRuntimeRoot, "path" | "close">;

const OPERATIONS: Readonly<Record<ContainerOperation, ContainerOperation>> =
  Object.freeze({
    inspect_crx_extension: "inspect_crx_extension",
    inspect_xpi_extension: "inspect_xpi_extension",
    inspect_pyinstaller_archive: "inspect_pyinstaller_archive",
  });

const MANIFEST_ENTRY_NAME = "manifest.json";
const MANIFEST_MF_ENTRY_NAME = "META-INF/manifest.mf";
const MOZILLA_SF_ENTRY_NAME = "META-INF/mozilla.sf";
const SIGNATURE_ENTRY_SUFFIX = /\.(?:sf|rsa|ec|sig)$/iu;
/** Bounded temporary footprint for the CRX inner-archive payload copy. */
const MAX_CRX_PAYLOAD_BYTES = 256 * 1024 * 1024;
const MAX_ZIP_ENTRY_FACTS = 262_144;
const MAX_SIGNATURE_FACT_ENTRIES = 256;
const MAX_PYC_HEADER_PROBES = 65_536;
const MAX_PYZ_ARCHIVES_INDEXED = 16;

interface ContainerWorkInput {
  readonly path: string;
}

interface ContainerArtifactIdentity {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

interface PositionalBytes {
  read(position: number, length: number): Promise<Uint8Array>;
}

const parseContainerInput = (
  operation: ContainerOperation,
  rawInput: unknown,
): Result<ContainerWorkInput, AnalysisError> => {
  const schema =
    operation === OPERATIONS.inspect_crx_extension
      ? inspectCrxExtensionInputSchema
      : operation === OPERATIONS.inspect_xpi_extension
        ? inspectXpiExtensionInputSchema
        : inspectPyInstallerArchiveInputSchema;
  const parsed = schema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(operation, parsed.error.issues, rawInput, {
        cause: parsed.error,
      }),
    );
  if (!isAbsolute(parsed.data.path))
    return err(
      new AnalysisInputError(operation, undefined, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: "Expected an absolute filesystem path on this host.",
        },
      ]),
    );
  return ok(parsed.data);
};

const admitArtifact = async (
  path: string,
  operation: ContainerOperation,
  signal: AbortSignal | undefined,
  retainDigestHandle: (owner: OwnedFileHandle) => void,
): Promise<ContainerArtifactIdentity> => {
  try {
    const hashed = await hashStableFile(path, {
      ...(signal === undefined ? {} : { signal }),
      retainFailedClose: retainDigestHandle,
    });
    return { path, sha256: hashed.sha256, bytes: hashed.bytes };
  } catch (cause: unknown) {
    throw containerFailure(cause, path, operation, signal);
  }
};

const containerEvidence = (
  operation: ContainerOperation,
  input: ContainerWorkInput,
  artifact: ContainerArtifactIdentity,
  report: JsonValue,
  limitations: readonly string[],
  locations: readonly EvidenceLocation[],
  signal: AbortSignal | undefined,
): Result<Evidence, AnalysisError> =>
  completeProviderEvidence(
    createEvidence(
      { path: artifact.path, sha256: artifact.sha256, format: "file" },
      CONTAINER_PROVIDER_IDENTITY,
      {
        operation,
        parameters: { path: input.path },
        result: report,
        confidence: "observed",
        limitations,
        locations,
      },
    ),
    signal,
  );

const cleanupIdentifier = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const closeResource = async (close: () => Promise<void>): Promise<unknown> => {
  try {
    await close();
    return undefined;
  } catch (cause: unknown) {
    return cause;
  }
};

/**
 * Compose one unresolved cleanup failure with the settled outcome so the
 * caller sees unreleased resources and any retained observation.
 */
const composeCleanupFailure = (
  operation: ContainerOperation,
  cleanupCauses: readonly {
    readonly resource: string;
    readonly cause: unknown;
  }[],
  settled?: Result<Evidence, AnalysisError>,
): Result<Evidence, AnalysisError> => {
  const first =
    cleanupCauses[0] ??
    ({
      resource: operation,
      cause: new Error("cleanup failed without a resource"),
    } as const);
  const primary =
    settled !== undefined && !settled.ok ? settled.error : undefined;
  return err(
    new ProviderCleanupError(
      CONTAINER_PROVIDER_IDENTITY.id,
      cleanupCauses.map((failure) => failure.resource),
      {
        reason: cleanupIdentifier(first.cause),
        ...(primary === undefined
          ? {}
          : { previous_error: projectAnalysisError(primary) }),
      },
      {
        operation,
        cause: first.cause,
        ...(settled?.ok ? { partialObservation: settled.value } : {}),
      },
    ),
  );
};

/** Read one positional slice through an owned descriptor, checking extent. */
const readSlice = async (
  handle: FileHandle,
  position: number,
  length: number,
  signal: AbortSignal | undefined,
): Promise<Buffer> => {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    assertRegularFileActive(signal);
    const read = await handle.read(
      bytes,
      offset,
      length - offset,
      position + offset,
    );
    if (read.bytesRead === 0)
      throw new RegularFileChangedError("container artifact");
    offset += read.bytesRead;
  }
  return bytes;
};

const handleBytes = (
  handle: FileHandle,
  path: string,
  operation: ContainerOperation,
  signal: AbortSignal | undefined,
): PositionalBytes => ({
  read: async (position: number, length: number) => {
    try {
      return await readSlice(handle, position, length, signal);
    } catch (cause: unknown) {
      throw containerFailure(cause, path, operation, signal);
    }
  },
});

/** Read one ZIP entry's bytes, bounded before unbounded growth. */
const readBoundedEntry = async (
  reader: ZipArtifactReader,
  entry: ArtifactEntry,
  maximumBytes: number,
  signal: AbortSignal | undefined,
): Promise<Buffer> => {
  const stream = await reader.open(entry, signal);
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of stream) {
      const piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += piece.length;
      if (total > maximumBytes)
        throw new ContainerFormatError(
          "limit",
          `ZIP entry ${JSON.stringify(entry.path)} exceeds the ${String(maximumBytes)}-byte read budget`,
        );
      chunks.push(piece);
    }
  } catch (cause: unknown) {
    stream.destroy(cause instanceof Error ? cause : new Error(String(cause)));
    throw cause;
  }
  return Buffer.concat(chunks);
};

interface ZipEntryFacts {
  readonly entryCount: number;
  readonly rootManifest: ArtifactEntry | undefined;
  readonly manifestMf: ArtifactEntry | undefined;
  readonly mozillaSf: ArtifactEntry | undefined;
  readonly otherSignatureEntries: readonly { name: string; bytes: number }[];
}

/** Enumerate outer ZIP entries once; facts are read from entry metadata. */
const scanZipEntries = async (
  reader: ZipArtifactReader,
  signal: AbortSignal | undefined,
): Promise<ZipEntryFacts> => {
  const otherSignatureEntries: { name: string; bytes: number }[] = [];
  let count = 0;
  let rootManifest: ArtifactEntry | undefined;
  let manifestMf: ArtifactEntry | undefined;
  let mozillaSf: ArtifactEntry | undefined;
  for await (const entry of reader.entries(signal)) {
    count += 1;
    if (count > MAX_ZIP_ENTRY_FACTS)
      throw new ContainerFormatError(
        "limit",
        `ZIP declares more than ${String(MAX_ZIP_ENTRY_FACTS)} entries`,
      );
    if (entry.kind !== "file") continue;
    if (entry.path === MANIFEST_ENTRY_NAME) rootManifest = entry;
    else if (entry.path === MANIFEST_MF_ENTRY_NAME) manifestMf = entry;
    else if (entry.path === MOZILLA_SF_ENTRY_NAME) mozillaSf = entry;
    else if (
      entry.path.startsWith("META-INF/") &&
      SIGNATURE_ENTRY_SUFFIX.test(entry.path) &&
      otherSignatureEntries.length < MAX_SIGNATURE_FACT_ENTRIES
    )
      otherSignatureEntries.push({
        name: entry.path,
        bytes: entry.declaredSize ?? 0,
      });
  }
  return {
    entryCount: count,
    rootManifest,
    manifestMf,
    mozillaSf,
    otherSignatureEntries,
  };
};

/* ------------------------------------------------------------------ */
/* CRX3                                                                 */
/* ------------------------------------------------------------------ */

interface CrxWorkFacts {
  readonly header: Crx3Header;
  readonly manifest: WebExtensionManifest | null;
  readonly archiveEntryCount: number;
  readonly limitations: readonly string[];
}

const CRX_TEMP_COPY_LIMITATION =
  "The inner ZIP payload was streamed once into an owned owner-only temporary root so the trusted ZIP reader could parse it; no entry content was retained beyond manifest.json bytes.";

const copyZipPayload = async (
  handle: FileHandle,
  archiveOffset: number,
  destination: string,
  signal: AbortSignal | undefined,
): Promise<number> => {
  const output = createWriteStream(destination, { flags: "wx", mode: 0o600 });
  let written = 0;
  try {
    for await (const chunk of readFileHandleChunks(handle, {
      start: archiveOffset,
      signal,
    })) {
      written += chunk.length;
      if (written > MAX_CRX_PAYLOAD_BYTES)
        throw new ContainerFormatError(
          "limit",
          `CRX archive section exceeds the ${String(MAX_CRX_PAYLOAD_BYTES)}-byte payload copy budget`,
        );
      if (!output.write(chunk)) await once(output, "drain");
    }
  } catch (cause: unknown) {
    output.destroy(cause instanceof Error ? cause : new Error(String(cause)));
    await finished(output).catch(() => undefined);
    throw cause;
  }
  output.end();
  await finished(output);
  return written;
};

const buildCrxEvidence = (
  input: ContainerWorkInput,
  artifact: ContainerArtifactIdentity,
  facts: CrxWorkFacts,
  signal: AbortSignal | undefined,
): Result<Evidence, AnalysisError> => {
  const report = crxExtensionReportSchema.parse({
    artifact,
    header: facts.header,
    archive_offset: facts.header.archive_offset,
    manifest: facts.manifest,
    archive_entry_count: facts.archiveEntryCount,
    limitations: facts.limitations,
  });
  return containerEvidence(
    OPERATIONS.inspect_crx_extension,
    input,
    artifact,
    report as unknown as JsonValue,
    report.limitations,
    [
      { kind: "artifact-path", path: artifact.path },
      { kind: "file-offset", offset: report.archive_offset },
    ],
    signal,
  );
};

/**
 * Probe the header, stream the ZIP payload into the private root, enumerate
 * the inner archive, and own every lifecycle transition through close. A
 * close that cannot be confirmed is adopted into the caller's retained
 * resource scope for later retry.
 */
const inspectCrxExtension = async (
  input: ContainerWorkInput,
  artifact: ContainerArtifactIdentity,
  signal: AbortSignal | undefined,
  resources: ArtifactResourceScope,
  createRuntimeRoot: () => Promise<RuntimeRoot>,
): Promise<Result<Evidence, AnalysisError>> => {
  const operation = OPERATIONS.inspect_crx_extension;
  const { path } = input;
  let root: RuntimeRoot;
  try {
    root = await createRuntimeRoot();
  } catch (cause: unknown) {
    return err(containerFailure(cause, path, operation, signal));
  }
  const payloadPath = join(root.path, "payload.zip");
  let settled: Result<Evidence, AnalysisError>;
  let reader: ZipArtifactReader | undefined;
  let handleOwner: OwnedFileHandle | undefined;
  try {
    const { handle } = await openRegularFile(path, {
      symlinks: "reject",
      signal,
    }).catch((cause: unknown) => {
      throw containerFailure(cause, path, operation, signal);
    });
    handleOwner = new OwnedFileHandle(handle);
    const metadata = await handle.stat();
    const fileBytes = metadata.size;
    if (fileBytes < CRX3_HEADER_PREFIX_BYTES)
      throw new ContainerFormatError(
        "format",
        `CRX3 container requires at least ${String(CRX3_HEADER_PREFIX_BYTES)} bytes; observed ${String(fileBytes)}`,
      );
    const fixed = await readSlice(handle, 0, CRX3_HEADER_PREFIX_BYTES, signal);
    if (!crx3MagicMatches(fixed))
      throw new ContainerFormatError(
        "format",
        `Selected file is not a CRX3 container: magic ${JSON.stringify(fixed.subarray(0, 4).toString("latin1"))}`,
      );
    const declaredHeaderSize = fixed.readUInt32LE(8);
    if (declaredHeaderSize > MAX_CRX3_HEADER_BYTES)
      throw new ContainerFormatError(
        "limit",
        `CRX3 header section requires ${String(declaredHeaderSize)} bytes, exceeding the ${String(MAX_CRX3_HEADER_BYTES)}-byte read budget`,
      );
    const headerBytes = await readSlice(
      handle,
      CRX3_HEADER_PREFIX_BYTES,
      declaredHeaderSize,
      signal,
    );
    const header = parseCrx3Header(
      Buffer.concat([fixed, headerBytes]),
      fileBytes,
    );
    await copyZipPayload(handle, header.archive_offset, payloadPath, signal);
    reader = new ZipArtifactReader(payloadPath, "zip");
    const zipFacts = await scanZipEntries(reader, signal);
    const manifest =
      zipFacts.rootManifest === undefined
        ? null
        : parseWebExtensionManifest(
            await readBoundedEntry(
              reader,
              zipFacts.rootManifest,
              MAX_WEBEXT_MANIFEST_BYTES,
              signal,
            ),
          );
    const facts: CrxWorkFacts = {
      header,
      manifest,
      archiveEntryCount: zipFacts.entryCount,
      limitations: [
        CRX_TEMP_COPY_LIMITATION,
        ...header.limitations,
        ...(manifest === null
          ? [
              `No ${MANIFEST_ENTRY_NAME} entry exists at the archive root; browser-extension metadata stays unknown.`,
            ]
          : manifest.limitations),
      ],
    };
    settled = buildCrxEvidence(input, artifact, facts, signal);
  } catch (cause: unknown) {
    settled =
      cause instanceof AnalysisError
        ? err(cause)
        : err(containerFailure(cause, path, operation, signal));
  }
  const cleanupCauses: { resource: string; cause: unknown }[] = [];
  const readerFailure = await closeResource(async () => {
    if (reader !== undefined) await reader.close();
  });
  if (readerFailure !== undefined) {
    if (reader !== undefined)
      resources.retain({ kind: "reader", resource: payloadPath, reader });
    cleanupCauses.push({ resource: payloadPath, cause: readerFailure });
  }
  if (handleOwner !== undefined) {
    const ownerFailure = await closeResource(() => handleOwner.close());
    if (ownerFailure !== undefined) {
      resources.retain({
        kind: "file-handle",
        resource: path,
        handle: handleOwner,
      });
      cleanupCauses.push({ resource: path, cause: ownerFailure });
    }
  }
  const rootFailure = await closeResource(() => root.close());
  if (rootFailure !== undefined) {
    // The private runtime root retries its own removal after a failed close.
    resources.retain({
      kind: "private-runtime-root",
      resource: root.path,
      root,
    });
    cleanupCauses.push({ resource: root.path, cause: rootFailure });
  }
  if (cleanupCauses.length > 0)
    return composeCleanupFailure(operation, cleanupCauses, settled);
  return settled;
};

/* ------------------------------------------------------------------ */
/* XPI                                                                  */
/* ------------------------------------------------------------------ */

const XPI_DIGEST_LIMITATION =
  "Digest values are observed metadata; entry-digest and JAR signature validity were not verified.";

interface JarDigestOutcome {
  readonly file: JarDigestFile | null;
  readonly limitations: readonly string[];
}

interface XpiWorkFacts {
  readonly manifestMf: JarDigestOutcome;
  readonly mozillaSf: JarDigestOutcome;
  readonly otherSignatureEntries: readonly { name: string; bytes: number }[];
  readonly manifest: WebExtensionManifest | null;
  readonly archiveEntryCount: number;
  readonly limitations: readonly string[];
}

const inspectXpiExtension = async (
  input: ContainerWorkInput,
  artifact: ContainerArtifactIdentity,
  signal: AbortSignal | undefined,
  resources: ArtifactResourceScope,
): Promise<Result<Evidence, AnalysisError>> => {
  const operation = OPERATIONS.inspect_xpi_extension;
  const { path } = input;
  const reader = new ZipArtifactReader(path, "zip");
  let settled: Result<Evidence, AnalysisError>;
  try {
    const zipFacts = await scanZipEntries(reader, signal);
    const readDigestFile = async (
      entry: ArtifactEntry | undefined,
      label: string,
    ): Promise<JarDigestOutcome> => {
      if (entry === undefined)
        return {
          file: null,
          limitations: [
            `No ${label} entry exists; its digest facts stay unknown.`,
          ],
        };
      if ((entry.declaredSize ?? 0) > MAX_JAR_MANIFEST_BYTES)
        return {
          file: null,
          limitations: [
            `${label} declares ${String(entry.declaredSize)} bytes, exceeding the ${String(MAX_JAR_MANIFEST_BYTES)}-byte digest-manifest budget; its digest facts stay unknown.`,
          ],
        };
      const file = parseJarDigestFile(
        await readBoundedEntry(reader, entry, MAX_JAR_MANIFEST_BYTES, signal),
      );
      return { file, limitations: [...file.limitations] };
    };
    const manifestMf = await readDigestFile(
      zipFacts.manifestMf,
      MANIFEST_MF_ENTRY_NAME,
    );
    const mozillaSf = await readDigestFile(
      zipFacts.mozillaSf,
      MOZILLA_SF_ENTRY_NAME,
    );
    const manifestEntry = zipFacts.rootManifest;
    const manifest =
      manifestEntry === undefined || manifestEntry.encrypted
        ? null
        : parseWebExtensionManifest(
            await readBoundedEntry(
              reader,
              manifestEntry,
              MAX_WEBEXT_MANIFEST_BYTES,
              signal,
            ),
          );
    const facts: XpiWorkFacts = {
      manifestMf,
      mozillaSf,
      otherSignatureEntries: zipFacts.otherSignatureEntries,
      manifest,
      archiveEntryCount: zipFacts.entryCount,
      limitations: [
        XPI_DIGEST_LIMITATION,
        ...manifestMf.limitations,
        ...mozillaSf.limitations,
        ...(manifest === null
          ? [
              `No readable ${MANIFEST_ENTRY_NAME} entry exists at the archive root; browser-extension metadata stays unknown.`,
            ]
          : manifest.limitations),
        ...(zipFacts.otherSignatureEntries.length >= MAX_SIGNATURE_FACT_ENTRIES
          ? [
              `Signature-fact entries are truncated at ${String(MAX_SIGNATURE_FACT_ENTRIES)}; remaining META-INF signature artifacts are not listed.`,
            ]
          : []),
      ],
    };
    const report = xpiExtensionReportSchema.parse({
      artifact,
      manifest_mf: facts.manifestMf.file,
      mozilla_sf: facts.mozillaSf.file,
      other_signature_entries: facts.otherSignatureEntries,
      manifest: facts.manifest,
      archive_entry_count: facts.archiveEntryCount,
      limitations: facts.limitations,
    });
    settled = containerEvidence(
      operation,
      input,
      artifact,
      report as unknown as JsonValue,
      report.limitations,
      [{ kind: "artifact-path", path: artifact.path }],
      signal,
    );
  } catch (cause: unknown) {
    settled =
      cause instanceof AnalysisError
        ? err(cause)
        : err(containerFailure(cause, path, operation, signal));
  }
  const readerFailure = await closeResource(() => reader.close());
  if (readerFailure !== undefined) {
    // The reader's descriptor stays owned and retried by the service close.
    resources.retain({ kind: "reader", resource: path, reader });
    return composeCleanupFailure(
      operation,
      [{ resource: path, cause: readerFailure }],
      settled,
    );
  }
  return settled;
};

/* ------------------------------------------------------------------ */
/* PyInstaller CArchive / PYZ / pyc                                     */
/* ------------------------------------------------------------------ */

const PYINSTALLER_ENCRYPTION_LIMITATION =
  "The CArchive TOC carries no per-entry encryption flag; entry contents are never decrypted and an encrypted build's data is not detected here.";

interface PyInstallerWorkFacts {
  readonly cookie: CarchiveCookie;
  readonly tocEntries: readonly CarchiveTocEntry[];
  readonly pyzArchives: readonly PyzArchiveInventory[];
  readonly limitations: readonly string[];
}

const attachPycHeaderFacts = async (
  handle: FileHandle,
  path: string,
  entries: readonly CarchiveTocEntry[],
  limitations: string[],
  signal: AbortSignal | undefined,
): Promise<readonly CarchiveTocEntry[]> => {
  let probes = 0;
  let opaqueCount = 0;
  const updated: CarchiveTocEntry[] = [];
  for (const entry of entries) {
    const isModuleData =
      entry.typecode === "m" ||
      entry.typecode === "M" ||
      entry.typecode === "s";
    if (
      !isModuleData ||
      entry.compressed ||
      entry.compressed_size < 16 ||
      probes >= MAX_PYC_HEADER_PROBES
    ) {
      if (isModuleData) opaqueCount += 1;
      updated.push(entry);
      continue;
    }
    probes += 1;
    let header: ReturnType<typeof parsePycHeader>;
    try {
      header = parsePycHeader(
        await readSlice(handle, entry.position, 16, signal),
      );
    } catch {
      // PyInstaller >= 5.3 strips module pyc headers; other opaque prefixes
      // are equally not headerful pyc data.
      opaqueCount += 1;
      updated.push(entry);
      continue;
    }
    updated.push(
      carchiveTocEntrySchema.parse({
        ...entry,
        pyc_header_state: "parsed",
        pyc_header: header,
      }),
    );
  }
  void path;
  if (opaqueCount > 0)
    limitations.push(
      `${String(opaqueCount)} module entries carry opaque (or stripped, PyInstaller >= 5.3) byte prefixes or exceed the probe budget; their pyc headers were not parsed.`,
    );
  return updated;
};

/** Index one embedded PYZ; contained failures stay limitations, not refusals. */
const indexPyzArchive = async (
  bytes: PositionalBytes,
  entry: CarchiveTocEntry,
  limitations: string[],
): Promise<PyzArchiveInventory> => {
  const displayName = entry.name ?? entry.name_bytes_base64 ?? "unnamed";
  const entryLimitations: string[] = [
    "PYZ entry blobs are individually zlib-compressed and are never decompressed here; their pyc header facts stay unknown.",
  ];
  const containedFailure = (message: string): PyzArchiveInventory => {
    limitations.push(`Embedded pyz ${JSON.stringify(displayName)}: ${message}`);
    return pyzArchiveInventorySchema.parse({
      name: entry.name,
      archive_position: entry.position,
      python_magic_bytes_base64: null,
      toc_position: 0,
      pyz_toc: null,
      limitations: [...entryLimitations, message],
    });
  };
  if (entry.compressed)
    return containedFailure(
      "the pyz blob is stored compressed inside the CArchive; its TOC is only reachable by decompressing entry content, which this operation never does",
    );
  if (entry.compressed_size < MAX_PYZ_HEADER_BYTES)
    return containedFailure(
      `the pyz blob is ${String(entry.compressed_size)} bytes, shorter than a PYZ header`,
    );
  let header: ReturnType<typeof parsePyzHeader>;
  let pyzToc: PyzToc | undefined;
  try {
    header = parsePyzHeader(
      Buffer.from(await bytes.read(entry.position, MAX_PYZ_HEADER_BYTES)),
    );
  } catch (cause: unknown) {
    return containedFailure(
      cause instanceof Error ? cause.message : "the PYZ header is malformed",
    );
  }
  const blobOffset = entry.position + header.toc_position;
  const available = entry.compressed_size - header.toc_position;
  if (available <= 0)
    return containedFailure(
      `PYZ TOC position ${String(header.toc_position)} leaves no readable bytes inside the ${String(entry.compressed_size)}-byte embedded archive`,
    );
  if (available > MAX_PYZ_TOC_BYTES)
    entryLimitations.push(
      `PYZ TOC spans ${String(available)} bytes, exceeding the ${String(MAX_PYZ_TOC_BYTES)}-byte read budget; the TOC read is clamped and may stay incomplete.`,
    );
  try {
    pyzToc = parsePyzToc(
      Buffer.from(
        await bytes.read(blobOffset, Math.min(available, MAX_PYZ_TOC_BYTES)),
      ),
      header.toc_position,
    );
  } catch (cause: unknown) {
    return containedFailure(
      `${cause instanceof Error ? cause.message : "the PYZ TOC is malformed"}; the embedded module inventory stays unknown`,
    );
  }
  return pyzArchiveInventorySchema.parse({
    name: entry.name,
    archive_position: entry.position,
    python_magic_bytes_base64: header.python_magic_bytes_base64,
    toc_position: header.toc_position,
    pyz_toc: pyzToc,
    limitations: [...entryLimitations, ...pyzToc.limitations],
  });
};

const producePyInstallerFacts = async (
  input: ContainerWorkInput,
  signal: AbortSignal | undefined,
): Promise<PyInstallerWorkFacts> => {
  const operation = OPERATIONS.inspect_pyinstaller_archive;
  const { path } = input;
  return await withOwnedRegularFile(
    path,
    { ...(signal === undefined ? {} : { signal }), symlinks: "reject" },
    async ({ handle }) => {
      const metadata = await handle.stat();
      const fileBytes = metadata.size;
      const bytes = handleBytes(handle, path, operation, signal);
      const cookieOffset = await locateCarchiveCookie(bytes, fileBytes, signal);
      // Dual-cookie detection: the 2.1+ cookie appends a 64-byte library name.
      let followsCookie = Buffer.alloc(0);
      if (fileBytes - (cookieOffset + CARCHIVE_COOKIE_BYTES_20) >= 64)
        followsCookie = Buffer.from(
          await bytes.read(cookieOffset + CARCHIVE_COOKIE_BYTES_20, 64),
        );
      const cookieBytesCount = carchiveCookieBytesFor(followsCookie);
      const cookie = parseCarchiveCookieBytes(
        Buffer.from(await bytes.read(cookieOffset, cookieBytesCount)),
        cookieBytesCount,
        cookieOffset,
        fileBytes,
      );
      const limitations: string[] = [
        PYINSTALLER_ENCRYPTION_LIMITATION,
        ...cookie.limitations,
      ];
      const tocPosition = cookie.archive_start + cookie.toc_offset;
      const tocAvailable = Math.max(fileBytes - tocPosition, 0);
      if (cookie.toc_length > tocAvailable)
        limitations.push(
          `CArchive TOC length ${String(cookie.toc_length)} exceeds the ${String(tocAvailable)} bytes available at its offset; the TOC read is clamped.`,
        );
      if (cookie.toc_length > MAX_CARCHIVE_TOC_BYTES)
        limitations.push(
          `CArchive TOC length ${String(cookie.toc_length)} exceeds the ${String(MAX_CARCHIVE_TOC_BYTES)}-byte read budget; the TOC read is clamped.`,
        );
      const tocLength = Math.min(
        cookie.toc_length,
        tocAvailable,
        MAX_CARCHIVE_TOC_BYTES,
      );
      const parsed = parseCarchiveToc(
        Buffer.from(await bytes.read(tocPosition, tocLength)),
        cookie.archive_start,
      );
      limitations.push(...parsed.limitations);
      const entries = await attachPycHeaderFacts(
        handle,
        path,
        parsed.entries,
        limitations,
        signal,
      );
      const pyzEntries = entries.filter(
        (entry) => entry.typecode === "z" || entry.typecode === "Z",
      );
      if (pyzEntries.length > MAX_PYZ_ARCHIVES_INDEXED)
        limitations.push(
          `${String(pyzEntries.length)} embedded pyz entries exist; only the first ${String(MAX_PYZ_ARCHIVES_INDEXED)} are indexed.`,
        );
      const pyzArchives: PyzArchiveInventory[] = [];
      for (const entry of pyzEntries.slice(0, MAX_PYZ_ARCHIVES_INDEXED))
        pyzArchives.push(await indexPyzArchive(bytes, entry, limitations));
      return { cookie, tocEntries: entries, pyzArchives, limitations };
    },
  );
};

const buildPyInstallerEvidence = (
  input: ContainerWorkInput,
  artifact: ContainerArtifactIdentity,
  facts: PyInstallerWorkFacts,
  signal: AbortSignal | undefined,
): Result<Evidence, AnalysisError> => {
  const report = pyInstallerArchiveReportSchema.parse({
    artifact,
    cookie: facts.cookie,
    toc_offset: facts.cookie.archive_start + facts.cookie.toc_offset,
    entries: facts.tocEntries,
    pyz_archives: facts.pyzArchives,
    limitations: facts.limitations,
  });
  return containerEvidence(
    OPERATIONS.inspect_pyinstaller_archive,
    input,
    artifact,
    report as unknown as JsonValue,
    report.limitations,
    [
      { kind: "artifact-path", path: artifact.path },
      { kind: "file-offset", offset: facts.cookie.cookie_offset },
    ],
    signal,
  );
};

const inspectPyInstallerArchive = async (
  input: ContainerWorkInput,
  artifact: ContainerArtifactIdentity,
  signal: AbortSignal | undefined,
  resources: ArtifactResourceScope,
): Promise<Result<Evidence, AnalysisError>> => {
  const operation = OPERATIONS.inspect_pyinstaller_archive;
  const { path } = input;
  try {
    const facts = await producePyInstallerFacts(input, signal);
    return buildPyInstallerEvidence(input, artifact, facts, signal);
  } catch (cause: unknown) {
    if (
      cause instanceof RegularFileCleanupFailure &&
      cause.outcome.kind === "completed"
    ) {
      // The inspection completed; its failed descriptor close stays unresolved.
      // The descriptor owner is adopted for close-time retry, matching the
      // CRX and XPI lanes.
      resources.retain({
        kind: "file-handle",
        resource: cause.path,
        handle: cause.owner,
      });
      const facts = cause.outcome.value as PyInstallerWorkFacts;
      const partial = buildPyInstallerEvidence(input, artifact, facts, signal);
      return partial.ok
        ? err(
            new ProviderCleanupError(
              CONTAINER_PROVIDER_IDENTITY.id,
              [cause.path],
              { reason: cleanupIdentifier(cause.cleanupCause) },
              { operation, cause, partialObservation: partial.value },
            ),
          )
        : partial;
    }
    if (cause instanceof RegularFileCleanupFailure)
      resources.retain({
        kind: "file-handle",
        resource: cause.path,
        handle: cause.owner,
      });
    return err(containerFailure(cause, path, operation, signal));
  }
};

/** Shared exact validation and Evidence-led execution for the container family. */
export class ContainerInspectionService {
  readonly #createRuntimeRoot: () => Promise<RuntimeRoot>;
  readonly #resources = new ArtifactResourceScope();
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;
  #closePromise: Promise<void> | undefined;

  constructor(options: ContainerInspectionServiceOptions = {}) {
    this.#createRuntimeRoot =
      options.createRuntimeRoot ??
      (() => PrivateRuntimeRoot.create({ prefix: "rea-crx-" }));
  }

  /**
   * Await active inspections, then retry every retained cleanup failure
   * (descriptor owners, readers, and private runtime roots adopted after a
   * failed close).
   */
  close(): Promise<void> {
    this.#closing = true;
    if (this.#closePromise !== undefined) return this.#closePromise;
    const closing = (async () => {
      await Promise.all(this.#activeOperations);
      try {
        await this.#resources.close();
      } catch (cause: unknown) {
        const resources =
          cause instanceof ArtifactResourceRetryFailure
            ? [...new Set(cause.failedOwners.map((owner) => owner.resource))]
            : ["container inspection resources"];
        throw new ProviderCleanupError(
          CONTAINER_PROVIDER_IDENTITY.id,
          resources,
          { reason: cause instanceof Error ? cause.message : String(cause) },
          { operation: "close_binary", cause },
        );
      }
    })().finally(() => {
      if (this.#closePromise === closing) this.#closePromise = undefined;
    });
    this.#closePromise = closing;
    return this.#closePromise;
  }

  /** Execute one named container inspection with exact shared validation. */
  async execute(
    operation: ContainerOperation,
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (this.#closing) return err(new AnalysisCancelledError(operation));
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    const signal = options?.signal;
    let release!: () => void;
    const active = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.#activeOperations.add(active);
    try {
      const input = parseContainerInput(operation, rawInput);
      if (!input.ok) return input;
      // A selected Safari .appex is an Apple bundle, not a ZIP: detect and defer.
      if (
        operation === OPERATIONS.inspect_xpi_extension &&
        /\.appex$/iu.test(input.value.path)
      )
        return err(
          new AnalysisUnsupportedTargetError(
            operation,
            input.value.path,
            "Selected Safari app extension is an Apple bundle; use the existing Apple application-bundle analysis (project_apple_application_graph) instead of the XPI reader",
          ),
        );
      let artifact: ContainerArtifactIdentity;
      try {
        artifact = await admitArtifact(
          input.value.path,
          operation,
          signal,
          (handle) => {
            const resource = `${input.value.path} (container digest handle)`;
            const lease = new AnalysisCleanupLease(
              () => handle.close(),
              [input.value.path],
            );
            this.#resources.retain({ kind: "lease", resource, lease });
          },
        );
      } catch (cause: unknown) {
        return err(cause as AnalysisError);
      }
      if (operation === OPERATIONS.inspect_crx_extension)
        return await inspectCrxExtension(
          input.value,
          artifact,
          signal,
          this.#resources,
          this.#createRuntimeRoot,
        );
      if (operation === OPERATIONS.inspect_xpi_extension)
        return await inspectXpiExtension(
          input.value,
          artifact,
          signal,
          this.#resources,
        );
      return await inspectPyInstallerArchive(
        input.value,
        artifact,
        signal,
        this.#resources,
      );
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }
}
