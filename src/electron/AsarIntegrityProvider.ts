import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";

import { getRawHeader } from "@electron/asar";
import { AsarArtifactReader } from "../artifacts/AsarArtifactReader.js";
import {
  admitAsarHeader,
  resolveAsarHeaderAdmission,
} from "../artifacts/AsarHeader.js";
import type { AsarHeaderAdmission } from "../config/asarHeaderAdmission.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import type { ArtifactEntry } from "../artifacts/ArtifactReader.js";
import {
  artifactFileCancellationCause,
  assertArtifactReadActive,
  withArtifactFileHandle,
} from "../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import type { AsarIntegrityPort } from "../application/electron/AsarIntegrityPort.js";
import {
  asarIntegrityReportSchema,
  type AsarIntegrityReport,
  type InspectAsarIntegrityRequest,
} from "../domain/electron/asarIntegrity.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import { RegularFileOperationCancelled } from "../filesystem/RegularFile.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import {
  compareCandidatePaths,
  isV8BytecodeCandidatePath,
  V8_BYTECODE_HANDOFF_INSTRUCTION,
} from "./AsarBytecodeHandoff.js";
import {
  summarizeAsarHeader,
  verifyAsarMemberIntegrity,
  type AsarHeaderMember,
  type AsarHeaderSummary,
} from "./AsarPackedIntegrity.js";

/** Bundled ASAR header-integrity reader. It never executes archived content. */
export const ASAR_INTEGRITY_PROVIDER_IDENTITY = {
  id: "asar-integrity",
  name: "REA ASAR packed-integrity reader",
  version: "1",
} as const satisfies ProviderIdentity;

const OPERATION = "inspect_asar_integrity";
const MAXIMUM_LISTED_MISMATCHES = 50;

const ASAR_INTEGRITY_LIMITATIONS = [
  "Header-declared checksums describe the archive builder's own bytes and do not establish that Electron will load this archive, that its fuse policy enforces integrity, or that a signed bundle is unmodified.",
  "Only packed members within the selected verification budget are checked; unpacked companions, members outside the budget, and members without declared checksums are reported as unverified rather than assumed valid.",
  "V8 bytecode candidates are selected by path suffix only. A listed candidate may hold plain text or another container, and REA reads no member bytes to classify it.",
  "Listed paths and digests describe this archive's index. REA does not extract, publish, or execute any member for this operation.",
] as const;

type MemberIntegrityState =
  | "verified"
  | "mismatched"
  | "not_declared"
  | "unverified";

/** Check header-declared ASAR member checksums and list V8 bytecode handoffs. */
export class AsarIntegrityProvider implements AsarIntegrityPort {
  readonly identity = ASAR_INTEGRITY_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();
  readonly #headerAdmission: AsarHeaderAdmission;

  constructor(
    environment: Readonly<Record<string, string | undefined>> = process.env,
  ) {
    this.#headerAdmission = resolveAsarHeaderAdmission(environment);
  }

  async close(): Promise<void> {
    await this.#resources.close();
  }

  async inspect(
    input: InspectAsarIntegrityRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AsarIntegrityReport, AnalysisError>> {
    try {
      return await this.#resources.run(() =>
        this.#inspectArchive(input, options),
      );
    } catch (cause: unknown) {
      return err(translateFailure(cause, input.path));
    }
  }

  async #inspectArchive(
    input: InspectAsarIntegrityRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AsarIntegrityReport, AnalysisError>> {
    const signal = options?.signal;
    const { resolved, digest, header, summary } = await this.#locate(
      input.path,
      signal,
    );
    const declared = summary.members.filter(
      (member) => member.integrity.state === "declared",
    );
    const {
      states,
      mismatchedPaths,
      verified: membersVerified,
      mismatched: membersMismatched,
      bytes: verifiedBytes,
      truncated,
      cleanupFailures,
    } = await this.#verifyMembers(
      resolved,
      declared.filter((member) => !member.unpacked),
      input.max_verify_bytes,
      signal,
    );
    const membersWithoutChecksums = summary.members.length - declared.length;
    const membersUnverified = Math.max(
      0,
      declared.length - membersVerified - membersMismatched,
    );
    const candidates = summary.members
      .filter((member) => isV8BytecodeCandidatePath(member.path))
      .sort((left, right) => compareCandidatePaths(left.path, right.path))
      .slice(0, input.max_candidates)
      .map((member) => ({
        path: member.path,
        bytes: member.bytes,
        sha256: null,
        unpacked: member.unpacked,
        integrity: candidateState(member, states),
      }));
    const report: AsarIntegrityReport = {
      path: input.path,
      resolved_path: resolved,
      sha256: digest.sha256,
      bytes: digest.bytes,
      container: {
        header_bytes: header.headerSize,
        files: summary.files,
        directories: summary.directories,
        symlinks: summary.symlinks,
        unpacked_files: summary.unpackedFiles,
      },
      integrity: {
        algorithm: "SHA256",
        block_size: firstBlockSize(summary.members),
        members_declaring: declared.length,
        members_verified: membersVerified,
        members_mismatched: membersMismatched,
        members_without_checksums: membersWithoutChecksums,
        members_unverified: membersUnverified,
        mismatched_paths: mismatchedPaths,
        verified_bytes: verifiedBytes,
        truncated,
        state:
          membersMismatched > 0
            ? ("mismatched" as const)
            : declared.length === 0
              ? ("not_declared" as const)
              : truncated || membersUnverified > 0
                ? ("partial" as const)
                : ("verified" as const),
      },
      handoff: {
        tool: "decompile_v8_bytecode",
        command_environment: "REA_VIEW8_COMMAND",
        instruction: V8_BYTECODE_HANDOFF_INSTRUCTION,
        candidates,
      },
      coverage:
        truncated || summary.unpackedFiles > 0
          ? ("partial" as const)
          : ("complete" as const),
      limitations: [...ASAR_INTEGRITY_LIMITATIONS, ...cleanupFailures],
    };
    const parsed = asarIntegrityReportSchema.safeParse(report);
    if (!parsed.success)
      throw new AnalysisOutputError(
        OPERATION,
        "ASAR integrity reader produced a report outside its schema.",
        { cause: parsed.error },
      );
    assertArtifactReadActive(signal);
    return ok(parsed.data);
  }

  /** Resolve the selected archive, digest it, and decode its header index once. */
  async #locate(
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<{
    readonly resolved: string;
    readonly digest: { readonly sha256: string; readonly bytes: number };
    readonly header: { readonly header: unknown; readonly headerSize: number };
    readonly summary: AsarHeaderSummary;
  }> {
    assertArtifactReadActive(signal);
    const resolved = await realpath(path).catch((cause: unknown) => {
      throw new AnalysisInputError(OPERATION, {
        cause,
        userMessage: `The selected archive cannot be resolved: ${path}`,
      });
    });
    const digest = await this.#digest(resolved, signal);
    const header = await this.#header(resolved, signal);
    return {
      resolved,
      digest,
      header,
      summary: summarizeAsarHeader(header.header),
    };
  }

  /** Stream each packed member within the aggregate budget and keep its outcome. */
  async #verifyMembers(
    resolved: string,
    verifiable: readonly AsarHeaderMember[],
    maxVerifyBytes: number,
    signal: AbortSignal | undefined,
  ): Promise<{
    readonly states: ReadonlyMap<string, MemberIntegrityState>;
    readonly mismatchedPaths: string[];
    readonly verified: number;
    readonly mismatched: number;
    readonly bytes: number;
    readonly truncated: boolean;
    readonly cleanupFailures: string[];
  }> {
    const states = new Map<string, MemberIntegrityState>();
    const mismatchedPaths: string[] = [];
    const cleanupFailures: string[] = [];
    if (verifiable.length === 0)
      return {
        states,
        mismatchedPaths,
        verified: 0,
        mismatched: 0,
        bytes: 0,
        truncated: false,
        cleanupFailures,
      };
    let verified = 0;
    let mismatched = 0;
    let bytes = 0;
    let truncated = false;
    const reader = new AsarArtifactReader(resolved, {
      headerAdmission: this.#headerAdmission,
    });
    try {
      const entries = new Map<string, ArtifactEntry>();
      for await (const entry of reader.entries(signal))
        if (entry.kind === "file") entries.set(entry.path, entry);
      for (const member of [...verifiable].sort((left, right) =>
        compareCandidatePaths(left.path, right.path),
      )) {
        const entry = entries.get(member.path);
        if (entry === undefined || member.integrity.state !== "declared")
          continue;
        if (bytes + member.bytes > maxVerifyBytes) {
          truncated = true;
          continue;
        }
        assertArtifactReadActive(signal);
        const stream = await reader.open(entry, signal);
        const outcome = await verifyAsarMemberIntegrity(
          member.integrity.value,
          stream,
          signal,
        );
        bytes += outcome.bytes;
        if (outcome.verified) {
          verified += 1;
          states.set(member.path, "verified");
          continue;
        }
        mismatched += 1;
        states.set(member.path, "mismatched");
        if (mismatchedPaths.length < MAXIMUM_LISTED_MISMATCHES)
          mismatchedPaths.push(member.path);
      }
    } finally {
      try {
        await reader.close();
      } catch {
        // Keep ownership so provider close retries the snapshot directory.
        this.#resources.retain({
          kind: "reader",
          resource: `ASAR snapshot reader for ${resolved}`,
          reader,
        });
        cleanupFailures.push(
          "An ASAR snapshot directory could not be removed; provider shutdown retries the retained reader ownership.",
        );
      }
    }
    return {
      states,
      mismatchedPaths,
      verified,
      mismatched,
      bytes,
      truncated,
      cleanupFailures,
    };
  }

  async #digest(
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<{ readonly sha256: string; readonly bytes: number }> {
    try {
      return await hashStableFile(path, {
        ...(signal === undefined ? {} : { signal }),
        retainFailedClose: (handle) => {
          this.#resources.retain({
            kind: "lease",
            resource: path,
            lease: new AnalysisCleanupLease(() => handle.close(), [path]),
          });
        },
      });
    } catch (cause: unknown) {
      if (cause instanceof RegularFileOperationCancelled)
        throw new AnalysisCancelledError(OPERATION, { cause: cause.reason });
      throw cause;
    }
  }

  /** Admit the header extents before the shared decoder allocates them. */
  async #header(
    path: string,
    signal: AbortSignal | undefined,
  ): Promise<{ readonly header: unknown; readonly headerSize: number }> {
    const handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    await withArtifactFileHandle(
      path,
      handle,
      this.#resources,
      signal,
      (owned) => admitAsarHeader(owned, signal, this.#headerAdmission),
    );
    const raw = getRawHeader(path);
    return { header: raw.header, headerSize: raw.headerSize };
  }
}

const firstBlockSize = (
  members: readonly AsarHeaderMember[],
): number | null => {
  for (const member of members)
    if (member.integrity.state === "declared")
      return member.integrity.value.blockSize;
  return null;
};

const candidateState = (
  member: AsarHeaderMember,
  states: ReadonlyMap<string, MemberIntegrityState>,
): MemberIntegrityState =>
  states.get(member.path) ??
  (member.integrity.state === "declared" ? "unverified" : "not_declared");

const translateFailure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "cancelled")
      return new AnalysisCancelledError(OPERATION, {
        cause: artifactFileCancellationCause(cause),
      });
    return new AnalysisInputError(OPERATION, {
      cause,
      userMessage: `The selected archive could not be read as an ASAR container: ${path}: ${cause.message}`,
    });
  }
  return new AnalysisInputError(OPERATION, {
    cause,
    userMessage: `The selected archive could not be inspected: ${path}`,
  });
};
