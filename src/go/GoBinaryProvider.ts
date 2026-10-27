import { isSelectedRegularFileError } from "../filesystem/RegularFile.js";
import {
  readStableArtifact,
  completedStableArtifact,
} from "../artifacts/readStableArtifact.js";
import {
  artifactFilePrimaryFacts,
  type ArtifactFilePrimaryFacts,
  assertArtifactReadActive,
  bindArtifactFileCleanup,
  artifactFileCancellationCause,
} from "../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { GoBinaryPort } from "../application/go/GoBinaryPort.js";
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
import {
  goBinarySchema,
  goProcedureTableSchema,
  type GoBinary,
  type GoProcedureEntry,
  type GoProcedureTable,
  type InspectGoBinaryInput,
  type InspectGoProcedureTableInput,
} from "../domain/go/goBinary.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { fixedAllowanceOptions } from "../domain/fixedAllowanceRemediation.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { readGoBinaryImage, type GoBinaryImage } from "./GoBinaryImage.js";
import { requireSelectedNativeImage } from "../native/metadata/MachoSliceSelection.js";
import {
  readGoPclntabImage,
  readGoPclntabProcedures,
  type GoProcedureRow,
  type GoPclntabTable,
} from "./GoPclntab.js";
import {
  BinaryFormatFailure,
  BinaryResourceFailure,
} from "../native/metadata/BinaryContainer.js";
import { fileSnapshotPartialObservationSchema } from "../domain/fileSnapshotObservation.js";

/** Bundled format reader identity; embedded compiler versions are separate observed facts. */
export const GO_BINARY_PROVIDER_IDENTITY = {
  id: "go-build-info",
  name: "REA Go build-information reader",
  version: "1",
} as const;
const OPERATION = "inspect_go_binary";
const GO_PROCEDURE_OPERATION = "inspect_go_procedure_table";
const INPUT_BYTES = 256 * 1024 * 1024;
const OUTPUT_BYTES = 8 * 1024 * 1024;

const failureForPrimary = (
  facts: ArtifactFilePrimaryFacts,
  path: string,
  operation: string,
): AnalysisError => {
  const { cause, origin } = facts;
  if (origin === "owned-or-classified" && cause instanceof AnalysisError)
    return cause;
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure &&
    cause.reason === "integrity"
  )
    return new AnalysisArtifactChangedError(operation, path, cause.message, {
      cause,
    });
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure &&
    cause.reason === "cancelled"
  )
    return new AnalysisCancelledError(operation, {
      cause: artifactFileCancellationCause(cause),
    });
  if (cause instanceof BinaryResourceFailure)
    return new AnalysisResourceConstraintError(
      operation,
      cause.boundary === "search" ? "cpu" : "memory",
      `Selected artifact ${path}: ${cause.message}`,
      { boundary: cause.boundary, maximum_bytes: cause.maximum_bytes },
      {
        cause,
        ...fixedAllowanceOptions(
          cause.boundary === "search"
            ? "The Go build-info header-search allowance"
            : cause.boundary === "build-info"
              ? "The Go build-info string allowance"
              : "The Go structural decoding allowance",
          cause.boundary === "search" ? "work" : "parser",
        ),
      },
    );
  if (cause instanceof BinaryFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(operation, path, cause.message, {
          cause,
        })
      : new AnalysisInputError(operation, { cause }, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: `Selected artifact ${path}: ${cause.message}`,
          },
        ]);
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure
  ) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        operation,
        "file-size",
        cause.message,
        { maximum_input_bytes: INPUT_BYTES },
        {
          cause,
          remediationAction: `Select a suitable stable artifact within the reported ${String(INPUT_BYTES)}-byte input byte allowance. This release has no runtime override. Do not truncate required bytes; retrying the unchanged oversized input will fail again.`,
        },
      );
    if (cause.reason === "path")
      return new AnalysisInputError(operation, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(operation, path, cause.code, {
        cause,
      });
    if (isSelectedRegularFileError(cause))
      return new AnalysisInputError(operation, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(operation, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(GO_BINARY_PROVIDER_IDENTITY.id, operation, {
    cause,
    diagnostics: {
      path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};

const failureFor = (
  cause: unknown,
  path: string,
  operation: string,
): AnalysisError => {
  const primary = failureForPrimary(
    artifactFilePrimaryFacts(cause),
    path,
    operation,
  );
  const snapshot = completedStableArtifact(cause);
  if (snapshot !== undefined) {
    // This inspect boundary acquires exactly one StableArtifactSnapshot before
    // metadata decoding. Completion describes that read, not a decoded report.
    primary.retainPartialObservation(
      fileSnapshotPartialObservationSchema.parse({
        kind: "file-snapshot-hash",
        path,
        sha256: snapshot.sha256,
        bytes: snapshot.bytes.length,
      }),
    );
  }
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    GO_BINARY_PROVIDER_IDENTITY.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation, cause },
  );
  const error = analysisErrorWithCleanupFailure(primary, cleanup, operation);
  bindArtifactFileCleanup(cause, error);
  return error;
};

const outputLimit = (path: string, operation: string) =>
  new AnalysisResourceConstraintError(
    operation,
    "transport",
    `Complete Go metadata for ${path} exceeds the inline output budget; no partial success is returned.`,
    { maximum_output_bytes: OUTPUT_BYTES },
    fixedAllowanceOptions("The Go complete-report allowance", "report"),
  );

/** Fixed reader boundaries plus unknowns left by the observed metadata. */
const limitationsFor = (
  info: GoBinaryImage["build_info"],
  sectionNamesLimitation: string | undefined,
): string[] => [
  "Embedded build metadata is observed file content, not proof of compiler identity, dependency authenticity or runtime behavior.",
  "Only Go build information is inspected here; embedded procedure names are recovered by the separate inspect_go_procedure_table reader, while source mappings, type metadata and decompiled code are not recovered.",
  "Resource guards bound stable artifact reads and cumulative header searches to 256 MiB each, aggregate embedded strings to 1 MiB, structural table decoding to 16 MiB and complete metadata payloads to 8 MiB; these are not operating-system memory or CPU limits.",
  ...(info !== null && (info.go_version === null || info.module_text === null)
    ? [
        "Some embedded Go strings contain non-UTF8 bytes; undecodable text is null and exact source bytes are preserved as base64.",
      ]
    : []),
  ...(info === null
    ? [
        "No recognized Go build-info record was found in the inspected image; absent metadata does not establish that the binary is not Go.",
      ]
    : []),
  ...(sectionNamesLimitation === undefined ? [] : [sectionNamesLimitation]),
  ...(info !== null && info.module.main === null
    ? [
        "Dependency coverage is unknown because no main-module record was decoded from the embedded module information, as in GOPATH-mode builds. Decoded dependency records remain visible; an empty list does not establish the absence of dependencies.",
      ]
    : []),
  ...(info?.module.complete === false
    ? [
        "Some embedded module-text records could not be parsed completely; their original lines are preserved and additional metadata remains unknown.",
      ]
    : []),
];

/** Locate image-relative build-info ranges in the selected file. */
const inFile = (
  info: GoBinaryImage["build_info"],
  fileOffset: number,
): GoBinaryImage["build_info"] =>
  info === null || fileOffset === 0
    ? info
    : {
        ...info,
        header_offset: info.header_offset + fileOffset,
        version_location: {
          ...info.version_location,
          offset: info.version_location.offset + fileOffset,
        },
        module_location: {
          ...info.module_location,
          offset: info.module_location.offset + fileOffset,
        },
      };

/** Stable in-process metadata inspection without subprocesses, temporary files or Go installation. */
export class GoBinaryProvider implements GoBinaryPort {
  readonly identity = GO_BINARY_PROVIDER_IDENTITY;
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
      const error = new ProviderCleanupError(
        GO_BINARY_PROVIDER_IDENTITY.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: OPERATION },
      );
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  /** Read complete compiler/module metadata while preserving original byte identity and source ranges. */
  async inspect(
    input: Omit<InspectGoBinaryInput, "detail">,
    options?: ExecutionOptions,
  ): Promise<Result<GoBinary, AnalysisError>> {
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          INPUT_BYTES,
          options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(options?.signal);
        const selected = requireSelectedNativeImage(
          OPERATION,
          input.path,
          snapshot.bytes,
          input.architecture,
        );
        const image = readGoBinaryImage(selected.bytes);
        const {
          section_names_limitation: sectionNamesLimitation,
          ...publicImage
        } = image;
        const info = inFile(image.build_info, selected.fileOffset);
        const report = {
          ...publicImage,
          artifact: {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          ...(selected.selection === null
            ? {}
            : { selected_slice: selected.selection }),
          build_info: info,
          limitations: limitationsFor(info, sectionNamesLimitation),
        };
        if (Buffer.byteLength(JSON.stringify(report), "utf8") > OUTPUT_BYTES)
          throw outputLimit(input.path, OPERATION);
        const parsed = goBinarySchema.safeParse(report);
        if (!parsed.success)
          throw new AnalysisOutputError(
            OPERATION,
            "Go reader produced invalid source ranges or report values.",
            { cause: parsed.error },
          );
        assertArtifactReadActive(options?.signal);
        return ok(parsed.data);
      });
    } catch (cause: unknown) {
      return err(failureFor(cause, input.path, OPERATION));
    }
  }

  /** Page the embedded pclntab procedure table with bounded, unknown-preserving decoding. */
  async procedureTable(
    input: InspectGoProcedureTableInput,
    options?: ExecutionOptions,
  ): Promise<Result<GoProcedureTable, AnalysisError>> {
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          INPUT_BYTES,
          options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(options?.signal);
        const selected = requireSelectedNativeImage(
          GO_PROCEDURE_OPERATION,
          input.path,
          snapshot.bytes,
          input.architecture,
        );
        const { container, pclntab } = readGoPclntabImage(selected.bytes);
        const artifactBytes = snapshot.bytes.length;
        const rows =
          pclntab === null
            ? []
            : readGoPclntabProcedures(
                selected.bytes,
                pclntab,
                input.offset,
                input.limit,
              );
        const legacy = pclntab?.era === "go1.2-1.15";
        const total = pclntab === null || legacy ? 0 : (pclntab.nfunc ?? 0);
        const report = {
          artifact: {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: artifactBytes,
          },
          format: container.format,
          architecture: container.architecture,
          bits: container.bits,
          byte_order: container.byte_order,
          pclntab: pclntab === null ? null : pclntabReportOf(pclntab),
          offset: input.offset,
          limit: input.limit,
          total,
          procedures: rows.map(procedureEntryOf),
          next_offset:
            input.offset + rows.length < total
              ? input.offset + rows.length
              : null,
          limitations: procedureLimitationsFor(pclntab),
        };
        if (Buffer.byteLength(JSON.stringify(report), "utf8") > OUTPUT_BYTES)
          throw outputLimit(input.path, GO_PROCEDURE_OPERATION);
        const parsed = goProcedureTableSchema.safeParse(report);
        if (!parsed.success)
          throw new AnalysisOutputError(
            GO_PROCEDURE_OPERATION,
            "Go procedure-table reader produced invalid report values.",
            { cause: parsed.error },
          );
        assertArtifactReadActive(options?.signal);
        return ok(parsed.data);
      });
    } catch (cause: unknown) {
      return err(failureFor(cause, input.path, GO_PROCEDURE_OPERATION));
    }
  }
}

const hex = (value: bigint): string => `0x${value.toString(16)}`;

const tableNumber = (value: bigint): number | null =>
  value > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(value);

const procedureEntryOf = (row: GoProcedureRow): GoProcedureEntry => ({
  index: row.index,
  name: row.name,
  entry_offset:
    row.entry_offset === null ? null : tableNumber(row.entry_offset),
  end_offset: row.end_offset === null ? null : tableNumber(row.end_offset),
  entry_address: row.entry === null ? null : hex(row.entry),
  end_address: row.end === null ? null : hex(row.end),
});

const pclntabReportOf = (table: GoPclntabTable) => ({
  location: {
    source: table.location.source,
    section_name: table.location.section_name,
    file_offset: table.location.file_offset,
    address: hex(table.location.address),
    bytes: table.location.bytes,
  },
  magic: `0x${table.magic.toString(16).padStart(8, "0")}`,
  era: table.era,
  min_lc: table.min_lc,
  ptr_size: table.ptr_size,
  nfunc: table.era === "go1.2-1.15" ? null : table.nfunc,
  nfiles: table.nfiles,
  funcname_bytes: table.funcnametab?.bytes ?? null,
  functab: table.functab,
  text_start: table.text_start === null ? null : hex(table.text_start),
  text_base:
    table.text_base === null
      ? null
      : {
          address: hex(table.text_base.address),
          source: table.text_base.source,
        },
  moduledata: {
    found: table.moduledata.found,
    file_offset: table.moduledata.file_offset,
    nfunc_matches: table.moduledata.nfunc_matches,
    text_address:
      table.moduledata.text === null ? null : hex(table.moduledata.text),
  },
  legacy: table.era === "go1.2-1.15",
});

/** Fixed reader boundaries plus unknowns left by the observed procedure table. */
const procedureLimitationsFor = (table: GoPclntabTable | null): string[] => [
  "Procedure names are compiler-written pclntab funcnametab values, not decompiled source or verified runtime identities; source files and line mappings follow filetab and pcvalue records that this reader does not decode.",
  "End addresses come from the next function-table entry or the table sentinel, not from instruction decoding of function bodies.",
  "Resource guards bound stable artifact reads to 256 MiB, cumulative pclntab discovery searches to 256 MiB, structural table decoding to 16 MiB and complete pages to 500 procedures; these are not operating-system memory or CPU limits.",
  ...(table === null
    ? [
        "No recognizable Go function table was found in the inspected image; absent pclntab bytes do not establish that the binary contains no Go procedures.",
      ]
    : []),
  ...(table?.era === "go1.2-1.15"
    ? [
        "A go1.2-1.15 legacy pclntab was recognized, but its function table was left undecoded; procedure names, offsets and addresses remain unknown.",
      ]
    : []),
  ...((table?.era ?? "") !== "go1.2-1.15" &&
  table !== null &&
  table.text_base === null
    ? [
        "Procedure entry and end addresses are unknown because neither the pclntab textStart nor a matching moduledata established a text base; relative procedure offsets remain reported.",
      ]
    : []),
  ...(table !== null && table.moduledata.budget_limited
    ? [
        "The moduledata scan stopped at the 16 MiB structural decoding budget before covering every candidate span, so a reported moduledata found:false records not-searched rather than confirmed absence.",
      ]
    : []),
];
