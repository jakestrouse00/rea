import { join, isAbsolute } from "node:path";
import { open, readdir } from "node:fs/promises";
import type { Dirent } from "node:fs";

import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import {
  ArtifactFileCleanupFailure,
  artifactFileCancellationCause,
} from "../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  type AnalysisExecution,
  type ExecutionOptions,
  createAnalysisExecution,
} from "../application/AnalysisProvider.js";
import type { GameDataPort } from "./GameDataPort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { z } from "zod";
import type {
  GamedataOperation,
  GamedataRequest,
} from "../domain/gamedata/gamedataRequests.js";
import {
  CALLER_KEY_NOT_READ,
  PCK_EXTRACTION_MAX_BYTES,
  digestEntryBody,
  godotPckReportSchema,
  parseGodotPck,
  type GodotPckExtraction,
  type GodotPckEntry,
} from "../domain/gamedata/godotPck.js";
import {
  parseVpkArchive,
  vpkReportSchema,
} from "../domain/gamedata/vpkArchive.js";
import {
  parseGamemakerData,
  gamemakerReportSchema,
} from "../domain/gamedata/gamemakerData.js";
import {
  parseRpaArchive,
  rpaReportSchema,
} from "../domain/gamedata/rpaArchive.js";
import {
  RPGMAKER_MAX_CANDIDATE_FILES,
  RPGMAKER_MAX_DIRECTORY_DEPTH,
  RpgmakerDirectoryError,
  classifyRpgmakerHead,
  inspectRpgmakerAssetPrefixesInputSchema,
  rpgmakerReportSchema,
  sliceRpgmakerFiles,
} from "../domain/gamedata/rpgmakerAssets.js";
import { compareUnicodeCodePoints as compare } from "../domain/unicodeCodePointOrder.js";
import { err, ok, type Result } from "../domain/result.js";

/** Bounded structure-only game-container reader; no decryption or decoding. */
export const GAME_DATA_PROVIDER_IDENTITY = {
  id: "game-data-structure",
  name: "REA game-container structure reader",
  version: "1",
} as const;
const INPUT_BYTES = 256 * 1024 * 1024;
const OUTPUT_BYTES = 8 * 1024 * 1024;
const RPGMAKER_HEAD_BYTES = 24;

interface StableSnapshot {
  readonly bytes: Buffer;
  readonly sha256: string;
}
interface ArtifactIdentityValue {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}
type FileSubject = {
  readonly path: string;
  readonly sha256: string;
  readonly format: "file";
};

/**
 * Bounded structure-only game-container reader. Inspects pack indexes, chunk
 * maps and detection headers only; encrypted sections stay typed unknowns and
 * file bodies are never decoded, decrypted or stripped.
 */
export class GameDataProvider implements GameDataPort {
  readonly identity = GAME_DATA_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ArtifactReaderFailure) ||
        cause.cleanup === undefined
      )
        throw cause;
      throw new ProviderCleanupError(
        GAME_DATA_PROVIDER_IDENTITY.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: "gamedata.close" },
      );
    }
  }

  async execute(
    request: GamedataRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    try {
      const value = await this.#resources.run(async () => {
        this.#assertActive(options?.signal);
        switch (request.operation) {
          case "inspect_godot_pck":
            return await this.#inspectGodotPck(request, options);
          case "inspect_vpk_archive":
            return await this.#inspectContainerFile(
              request.operation,
              request.input.path,
              options,
              (bytes) =>
                parseVpkArchive(bytes, {
                  entries_start: request.input.entries_start,
                  entries_limit: request.input.entries_limit,
                }),
              vpkReportSchema,
              (report) => offsetLocation(report.tree_offset as number),
            );
          case "inspect_gamemaker_data":
            return await this.#inspectContainerFile(
              request.operation,
              request.input.path,
              options,
              parseGamemakerData,
              gamemakerReportSchema,
              (report) =>
                report.gen8 === null
                  ? null
                  : offsetLocation(report.gen8.offset as number),
            );
          case "inspect_rpa_archive":
            return await this.#inspectContainerFile(
              request.operation,
              request.input.path,
              options,
              (bytes) =>
                parseRpaArchive(bytes, {
                  entries_start: request.input.entries_start,
                  entries_limit: request.input.entries_limit,
                }),
              rpaReportSchema,
              (report) => offsetLocation(report.index.offset_in_file as number),
            );
          case "inspect_rpgmaker_asset_prefixes":
            return await this.#inspectRpgmakerAssetPrefixes(request, options);
        }
      });
      return ok(value);
    } catch (cause: unknown) {
      return err(
        this.#failureFor(
          cause,
          selectedPath(request),
          request.operation,
          options?.signal,
        ),
      );
    }
  }

  /** One stable snapshot, one parse, one validated atomic execution. */
  async #inspectContainerFile<
    Report extends { readonly limitations: readonly string[] },
  >(
    operation: GamedataOperation,
    path: string,
    options: ExecutionOptions | undefined,
    parse: (bytes: Buffer) => Omit<Report, "artifact">,
    schema: z.ZodType<Report>,
    extraLocation: (
      report: Report,
    ) => { kind: "file-offset"; offset: number } | null,
  ): Promise<AnalysisExecution> {
    this.#assertAbsolute(path, operation);
    const snapshot = await readStableArtifact(
      path,
      INPUT_BYTES,
      options?.signal,
      undefined,
      this.#resources,
    );
    this.#assertActive(options?.signal);
    let parsed: Omit<Report, "artifact">;
    try {
      parsed = parse(snapshot.bytes);
    } catch (cause) {
      throw formatAdmissionError(operation, cause);
    }
    const report = {
      ...parsed,
      artifact: artifactIdentity(path, snapshot),
    } as unknown as Report;
    return this.#toExecution(
      operation,
      schema,
      report,
      { path, sha256: snapshot.sha256, format: "file" },
      extraLocation(report),
    );
  }

  /** Structure-only v1/v2 pack observation with optional bounded extraction. */
  async #inspectGodotPck(
    request: Extract<GamedataRequest, { operation: "inspect_godot_pck" }>,
    options: ExecutionOptions | undefined,
  ): Promise<AnalysisExecution> {
    const path = request.input.path;
    this.#assertAbsolute(path, "inspect_godot_pck");
    if (request.input.extract !== undefined)
      this.#assertAbsolute(
        request.input.extract.output_directory,
        "inspect_godot_pck",
        "extract.output_directory",
      );
    const snapshot = await readStableArtifact(
      path,
      INPUT_BYTES,
      options?.signal,
      undefined,
      this.#resources,
    );
    this.#assertActive(options?.signal);
    let parsed: ReturnType<typeof parseGodotPck>;
    try {
      parsed = parseGodotPck(snapshot.bytes, {
        entries_start: request.input.entries_start,
        entries_limit: request.input.entries_limit,
      });
    } catch (cause) {
      throw formatAdmissionError("inspect_godot_pck", cause);
    }
    let extraction: GodotPckExtraction | null = null;
    const limitations: string[] = [...parsed.report.limitations];
    if (request.input.extract !== undefined) {
      const wrote = await this.#extractGodotEntry(
        snapshot,
        parsed.locateEntry,
        request.input.extract,
      );
      extraction = wrote.extraction;
      limitations.push(...wrote.limitations);
    }
    const report = {
      ...parsed.report,
      limitations,
      extraction,
      artifact: artifactIdentity(path, snapshot),
    };
    return this.#toExecution(
      "inspect_godot_pck",
      godotPckReportSchema,
      report,
      { path, sha256: snapshot.sha256, format: "file" },
      offsetLocation(parsed.report.directory_offset),
    );
  }

  /** Bounded single-entry body fact: digests plus one written copy, no decoding. */
  async #extractGodotEntry(
    snapshot: StableSnapshot,
    locate: (entryPath: string) => GodotPckEntry | undefined,
    extract: { entry_path: string; output_directory: string },
  ): Promise<{
    extraction: GodotPckExtraction;
    limitations: readonly string[];
  }> {
    const entry = locate(extract.entry_path);
    if (entry === undefined)
      throw new AnalysisInputError("inspect_godot_pck", undefined, [
        {
          path: ["extract", "entry_path"],
          reason: "invalid_value",
          message:
            "No directory entry with exactly that path exists in the pack index.",
        },
      ]);
    if (entry.encrypted)
      throw new AnalysisUnsupportedTargetError(
        "inspect_godot_pck",
        entry.path,
        `Entry body is flagged encrypted; ${CALLER_KEY_NOT_READ}`,
      );
    if (entry.size > PCK_EXTRACTION_MAX_BYTES)
      throw new AnalysisResourceConstraintError(
        "inspect_godot_pck",
        "file-size",
        `Entry ${JSON.stringify(entry.path)} of ${String(entry.size)} bytes exceeds the extraction bound`,
        { maximum_entry_bytes: PCK_EXTRACTION_MAX_BYTES },
      );
    const digest = digestEntryBody(snapshot.bytes, entry);
    const leaf = entry.path.split(/[\\/]/u).at(-1) ?? "";
    if (leaf.length === 0 || leaf === "." || leaf === "..")
      throw new AnalysisInputError("inspect_godot_pck", undefined, [
        {
          path: ["extract", "entry_path"],
          reason: "invalid_value",
          message: "Entry path has no usable file name for extraction.",
        },
      ]);
    const outputPath = join(extract.output_directory, leaf);
    let handle;
    try {
      handle = await open(outputPath, "wx");
    } catch (cause) {
      throw writeFailure(cause, outputPath);
    }
    try {
      const body = snapshot.bytes.subarray(
        entry.data_offset,
        entry.data_offset + entry.size,
      );
      await handle.writeFile(body);
    } catch (cause) {
      throw writeFailure(cause, outputPath);
    } finally {
      await handle.close();
    }
    return {
      extraction: {
        path: entry.path,
        output_path: outputPath,
        bytes: entry.size,
        sha256: digest.sha256,
        stored_md5_hex: entry.md5_hex,
        computed_md5_hex: digest.computed_md5_hex,
        md5_matches_stored: digest.computed_md5_hex === entry.md5_hex,
      },
      limitations: [
        `One selected entry body was read verbatim to compute its sha256 and check the index MD5, then written to ${outputPath}; no engine format or asset was decoded.`,
      ],
    };
  }

  /** Detection-only bounded directory scan; one head read per candidate file. */
  async #inspectRpgmakerAssetPrefixes(
    request: Extract<
      GamedataRequest,
      { operation: "inspect_rpgmaker_asset_prefixes" }
    >,
    options: ExecutionOptions | undefined,
  ): Promise<AnalysisExecution> {
    const input = inspectRpgmakerAssetPrefixesInputSchema.parse(request.input);
    this.#assertAbsolute(input.directory, "inspect_rpgmaker_asset_prefixes");
    const walked = await this.#walkRpgmakerCandidates(
      input.directory,
      input.extensions,
      0,
      options?.signal,
    );
    this.#assertActive(options?.signal);
    const denials = [...walked.denials];
    const headed: {
      path: string;
      bytes: number;
      prefix_present: boolean;
      prefix_hex: string | null;
      following_hex: string | null;
      encrypted_kind_guess: "png" | "ogg" | "unknown" | "insufficient_bytes";
      plain_kind: "png" | "ogg" | "unknown";
    }[] = [];
    for (const relative of walked.files) {
      const absolute = `${input.directory.endsWith("/") ? input.directory : `${input.directory}/`}${relative}`;
      const head = await this.#readHead(absolute, denials);
      if (head === null) continue;
      const classified = classifyRpgmakerHead(head.size, head.head);
      headed.push({ path: relative, bytes: head.size, ...classified });
    }
    const ordered = headed.sort((left, right) =>
      compare(left.path, right.path),
    );
    const sliced = sliceRpgmakerFiles(
      ordered,
      input.entries_start,
      input.entries_limit,
    );
    const encryptedCount = ordered.filter((file) => file.prefix_present).length;
    const plainCount = ordered.filter(
      (file) => !file.prefix_present && file.plain_kind !== "unknown",
    ).length;
    const report = {
      directory: input.directory,
      candidate_extensions: [...input.extensions],
      candidate_total: ordered.length,
      encrypted_count: encryptedCount,
      plain_count: plainCount,
      symlink_skipped: walked.symlinkSkipped,
      files: sliced.files,
      slice: sliced.slice,
      unreadable_paths: denials,
      limitations: [
        "Detection-only inventory: one bounded 24-byte head read per candidate file; no asset bytes were decrypted, stripped, extracted or digested.",
        "The 16-byte fake header and the eight bytes after it are reported verbatim in hex; the original header bytes a decrypter would restore are never reconstructed here.",
        "Encrypted kind guesses come from the bytes after the fake header alone (those are the original header bytes: a restored `\x89PNG` magic implies PNG and `OggS` implies Ogg; anything else stays unknown); asset privacy stays unknown.",
        "No file digests were computed; per-file identity is the reported byte size under the selected directory.",
        ...(denials.length === 0
          ? []
          : [
              `${String(denials.length)} paths could not be read head-only; their coverage is unknown and the refusal reasons are preserved in unreadable_paths.`,
            ]),
      ],
    };
    return this.#toExecution(
      "inspect_rpgmaker_asset_prefixes",
      rpgmakerReportSchema,
      report,
      undefined,
      null,
    );
  }

  async #walkRpgmakerCandidates(
    absolute: string,
    extensions: readonly string[],
    depth: number,
    signal: AbortSignal | undefined,
  ): Promise<{
    files: string[];
    symlinkSkipped: number;
    denials: readonly string[];
  }> {
    if (depth > RPGMAKER_MAX_DIRECTORY_DEPTH)
      throw new RpgmakerDirectoryError(
        "nesting",
        `Directory nesting exceeds ${String(RPGMAKER_MAX_DIRECTORY_DEPTH)} levels: ${absolute}`,
      );
    let entries: readonly Dirent[];
    try {
      entries = await readdir(absolute, { withFileTypes: true });
    } catch (cause) {
      if (cause instanceof Error && "code" in cause && cause.code === "EACCES")
        return { files: [], symlinkSkipped: 0, denials: [absolute] };
      throw cause;
    }
    const files: string[] = [];
    let symlinkSkipped = 0;
    const denials: string[] = [];
    const prefix = absolute.endsWith("/") ? absolute : `${absolute}/`;
    for (const entry of entries) {
      this.#assertActive(signal);
      const childAbsolute = `${prefix}${entry.name}`;
      const childRelative = entry.name;
      if (entry.isSymbolicLink()) {
        symlinkSkipped++;
        continue;
      }
      if (entry.isDirectory()) {
        const nested = await this.#walkRpgmakerCandidates(
          childAbsolute,
          extensions,
          depth + 1,
          signal,
        );
        files.push(...nested.files.map((file) => `${childRelative}/${file}`));
        symlinkSkipped += nested.symlinkSkipped;
        denials.push(...nested.denials);
        continue;
      }
      if (!entry.isFile()) {
        symlinkSkipped++;
        continue;
      }
      const extension = entry.name.includes(".")
        ? (entry.name.split(".").at(-1) ?? "").toLowerCase()
        : "";
      if (!(extensions as readonly string[]).includes(extension)) continue;
      if (files.length >= RPGMAKER_MAX_CANDIDATE_FILES)
        throw new RpgmakerDirectoryError(
          "capacity",
          `Candidate file count exceeds ${String(RPGMAKER_MAX_CANDIDATE_FILES)} in the selected directory`,
        );
      files.push(childRelative);
    }
    return { files, symlinkSkipped, denials };
  }

  async #readHead(
    absolute: string,
    denials: string[],
  ): Promise<{ size: number; head: Buffer } | null> {
    let size = 0;
    const head = Buffer.alloc(RPGMAKER_HEAD_BYTES);
    let handle;
    try {
      handle = await open(absolute, "r");
      try {
        size = (await handle.stat()).size;
        const read = await handle.read(head, 0, RPGMAKER_HEAD_BYTES, 0);
        return { size, head: head.subarray(0, read.bytesRead) };
      } finally {
        await handle.close();
      }
    } catch (cause) {
      denials.push(
        `${absolute}: ${cause instanceof Error && "code" in cause ? String(cause.code) : cause instanceof Error ? cause.message : String(cause)}`,
      );
      return null;
    }
  }

  #toExecution<Report>(
    operation: GamedataOperation,
    schema: z.ZodType<Report>,
    report: Report | Record<string, unknown>,
    subject: FileSubject | undefined,
    extraLocation:
      | { kind: "file-offset"; offset: number }
      | { kind: "artifact-path"; path: string }
      | null,
  ): AnalysisExecution {
    const serialized = JSON.stringify(report as Record<string, unknown>);
    if (Buffer.byteLength(serialized, "utf8") > OUTPUT_BYTES)
      throw new AnalysisResourceConstraintError(
        operation,
        "transport",
        "The complete structure report exceeds the inline output budget; no partial success is returned.",
        { maximum_output_bytes: OUTPUT_BYTES },
      );
    const parsed = schema.safeParse(report);
    if (!parsed.success)
      throw new AnalysisOutputError(
        operation,
        "Game-container reader produced invalid structure values.",
        { cause: parsed.error },
      );
    const locations: (
      | { kind: "artifact-path"; path: string }
      | { kind: "file-offset"; offset: number }
    )[] =
      subject === undefined
        ? [{ kind: "artifact-path", path: directoryOf(report) }]
        : [{ kind: "artifact-path", path: subject.path }];
    if (extraLocation !== null) locations.push(extraLocation);
    return createAnalysisExecution(parsed.data, this.identity, {
      ...(subject === undefined ? {} : { subject }),
      limitations: limitationsOfReport(report),
      locations,
    });
  }

  #assertActive(signal?: AbortSignal): void {
    if (signal?.aborted)
      throw new AnalysisCancelledError("gamedata", { cause: signal.reason });
  }

  #assertAbsolute(
    path: string,
    operation: GamedataOperation,
    field = "path",
  ): void {
    if (isAbsolute(path)) return;
    throw new AnalysisInputError(operation, undefined, [
      {
        path: field === "path" ? ["path"] : field.split("."),
        reason: "invalid_format",
        message: "Expected an absolute filesystem path on this host.",
      },
    ]);
  }

  #failureFor(
    cause: unknown,
    path: string,
    operation: GamedataOperation,
    signal?: AbortSignal,
  ): AnalysisError {
    const primary =
      cause instanceof ArtifactFileCleanupFailure &&
      cause.fileCleanupFailure.outcome.kind === "failed"
        ? this.#failureFor(
            cause.fileCleanupFailure.outcome.cause,
            path,
            operation,
            signal,
          )
        : cause instanceof ArtifactFileCleanupFailure && signal?.aborted
          ? new AnalysisCancelledError("gamedata", { cause: signal.reason })
          : this.#primaryFailure(cause, path, operation);
    if (
      !(cause instanceof ArtifactReaderFailure) ||
      cause.cleanup === undefined
    )
      return primary;
    const cleanup = new ProviderCleanupError(
      GAME_DATA_PROVIDER_IDENTITY.id,
      cause.cleanup.resources,
      { reason: cause.cleanup.reason },
      { cause },
    );
    return analysisErrorWithCleanupFailure(primary, cleanup, "gamedata");
  }

  #primaryFailure(
    cause: unknown,
    path: string,
    operation: GamedataOperation,
  ): AnalysisError {
    if (cause instanceof AnalysisError) return cause;
    if (cause instanceof RpgmakerDirectoryError)
      return new AnalysisResourceConstraintError(
        operation,
        "capacity",
        cause.message,
        cause.kind === "nesting"
          ? { maximum_directory_depth: RPGMAKER_MAX_DIRECTORY_DEPTH }
          : { maximum_candidate_files: RPGMAKER_MAX_CANDIDATE_FILES },
      );
    if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
      return new AnalysisArtifactChangedError(operation, path, cause.message, {
        cause,
      });
    if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
      return new AnalysisCancelledError(operation, {
        cause: artifactFileCancellationCause(cause),
      });
    if (cause instanceof ArtifactReaderFailure && cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        operation,
        "file-size",
        cause.message,
        { maximum_input_bytes: INPUT_BYTES },
        {
          cause,
          remediationAction:
            "Select a container within the reported input byte allowance; do not truncate required bytes.",
        },
      );
    if (cause instanceof ArtifactReaderFailure)
      return new AnalysisInputError(operation, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
    if (cause instanceof Error && "code" in cause) {
      if (cause.code === "EACCES" || cause.code === "EPERM")
        return new AnalysisAccessDeniedError(operation, path, cause.code, {
          cause,
        });
      if (
        ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
          String(cause.code),
        )
      )
        return new AnalysisInputError(operation, { cause }, [
          {
            path:
              operation === "inspect_rpgmaker_asset_prefixes"
                ? ["directory"]
                : ["path"],
            reason: "invalid_value",
            message: `Selected path could not be read (${String(cause.code)}): ${path}.`,
          },
        ]);
    }
    return new AnalysisInputError(operation, { cause }, [
      {
        path: ["path"],
        reason: "invalid_value",
        message: cause instanceof Error ? cause.message : String(cause),
      },
    ]);
  }
}

const writeFailure = (cause: unknown, path: string): never => {
  if (cause instanceof Error && "code" in cause && cause.code === "EEXIST")
    throw new AnalysisInputError("inspect_godot_pck", { cause }, [
      {
        path: ["extract", "output_directory"],
        reason: "invalid_value",
        message: `Output file already exists and extraction never overwrites: ${path}.`,
      },
    ]);
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    throw new AnalysisAccessDeniedError("inspect_godot_pck", path, cause.code, {
      cause,
    });
  if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
    throw new AnalysisInputError("inspect_godot_pck", { cause }, [
      {
        path: ["extract", "output_directory"],
        reason: "invalid_value",
        message: `Output directory does not exist: ${path}.`,
      },
    ]);
  throw new AnalysisInputError("inspect_godot_pck", { cause }, [
    {
      path: ["extract", "output_directory"],
      reason: "invalid_value",
      message: cause instanceof Error ? cause.message : String(cause),
    },
  ]);
};

const formatAdmissionError = (
  operation: GamedataOperation,
  cause: unknown,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  return new AnalysisInputError(operation, { cause }, [
    {
      path: ["path"],
      reason: "invalid_format",
      message: cause instanceof Error ? cause.message : String(cause),
    },
  ]);
};

const artifactIdentity = (
  path: string,
  snapshot: StableSnapshot,
): ArtifactIdentityValue => ({
  path,
  sha256: snapshot.sha256,
  bytes: snapshot.bytes.length,
});

const offsetLocation = (
  offset: number,
): { kind: "file-offset"; offset: number } => ({ kind: "file-offset", offset });

const selectedPath = (request: GamedataRequest): string =>
  request.operation === "inspect_rpgmaker_asset_prefixes"
    ? request.input.directory
    : request.input.path;

const limitationsOfReport = (report: unknown): readonly string[] => {
  const limitations = (report as { limitations?: readonly string[] })
    .limitations;
  return [...(limitations ?? [])];
};

const directoryOf = (report: unknown): string =>
  (report as { directory?: string }).directory ?? "unknown";
