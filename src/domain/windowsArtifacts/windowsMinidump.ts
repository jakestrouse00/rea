import { z } from "zod";
import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";
import { CANONICAL_BASE64_PATTERN } from "../stringPatterns.js";
import { u32Schema, u64Schema } from "./u64.js";

/** Absolute filesystem path and stable identity of one selected minidump. */
export const inspectWindowsMinidumpInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the selected Windows minidump",
  ),
});

/** File location of one stream or recorded structure, as the dump declares it. */
export const minidumpLocationSchema = z.strictObject({
  data_size: u32Schema,
  rva: u32Schema,
});

/**
 * One stream-directory entry. `status: "unparsed"` preserves a stream type
 * this reader does not model; its bytes are never fabricated or summarized.
 */
export const minidumpStreamSchema = z.strictObject({
  type: u32Schema,
  status: z.enum(["parsed", "unparsed"]),
  location: minidumpLocationSchema,
});

/** Module name read from a MINIDUMP_STRING at its name RVA. */
export const minidumpModuleNameSchema = z.strictObject({
  /** Losslessly decoded UTF-16LE text; null when the bytes are not valid UTF-16LE. */
  name: z.string().nullable(),
  raw_bytes_base64: z.string().regex(CANONICAL_BASE64_PATTERN),
  name_rva: u32Schema,
});

export const minidumpModuleSchema = z.strictObject({
  name: minidumpModuleNameSchema,
  base: u64Schema,
  size: u32Schema,
  checksum: u32Schema,
  timestamp: u32Schema,
  version_info_signature: u32Schema,
  version_info_struc_version: u32Schema,
  file_version_ms: u32Schema,
  file_version_ls: u32Schema,
  product_version_ms: u32Schema,
  product_version_ls: u32Schema,
  file_flags_mask: u32Schema,
  file_flags: u32Schema,
  os: u32Schema,
  file_type: u32Schema,
  file_subtype: u32Schema,
  file_date_ms: u32Schema,
  file_date_ls: u32Schema,
  codeview_record: minidumpLocationSchema.nullable(),
  misc_record: minidumpLocationSchema.nullable(),
  reserved0: u64Schema,
  reserved1: u64Schema,
});

/** Recorded thread facts as addresses only; CONTEXT register data is not decoded. */
export const minidumpThreadSchema = z.strictObject({
  id: u32Schema,
  suspend_count: u32Schema,
  priority_class: u32Schema,
  priority: u32Schema,
  teb: u64Schema,
  stack: z.strictObject({
    start_of_memory_range: u64Schema,
    memory: minidumpLocationSchema,
  }),
  /** Context-record file location; its architecture-specific contents stay unread. */
  context: minidumpLocationSchema,
});

export const minidumpExceptionSchema = z.strictObject({
  thread_id: u32Schema,
  /** Exception code as written; NTSTATUS interpretation stays with the caller. */
  code: u32Schema,
  flags: u32Schema,
  record: u64Schema,
  address: u64Schema,
  parameter_count: u32Schema,
  parameters: z.array(u64Schema).max(15),
  thread_context: minidumpLocationSchema.nullable(),
});

/** One recorded memory range from a MemoryListStream. */
export const minidumpMemoryRangeSchema = z.strictObject({
  start: u64Schema,
  data_size: u32Schema,
  rva: u32Schema,
});

/** One recorded range from a Memory64ListStream; data follows sequentially. */
export const minidumpMemory64RangeSchema = z.strictObject({
  start: u64Schema,
  data_size: u64Schema,
  data_offset: u64Schema,
});

/** One region fact from a MemoryInfoListStream entry. */
export const minidumpMemoryInfoSchema = z.strictObject({
  base: u64Schema,
  allocation_base: u64Schema,
  allocation_protect: u32Schema,
  region_size: u64Schema,
  state: u32Schema,
  protect: u32Schema,
  type: u32Schema,
});

/** NUMERIC-only system facts; the CSD string location is preserved, not expanded. */
export const minidumpSystemInfoSchema = z.strictObject({
  processor_architecture: u32Schema,
  processor_level: u32Schema,
  processor_revision: u32Schema,
  number_of_processors: u32Schema,
  product_type: u32Schema,
  major_version: u32Schema,
  minor_version: u32Schema,
  build_number: u32Schema,
  platform_id: u32Schema,
  csd_version_rva: u32Schema,
  suite_mask: u32Schema,
});

export const windowsMinidumpSchema = z
  .strictObject({
    artifact: z.strictObject({
      path: localPathStringSchema,
      sha256: digestSchema,
      bytes: z.number().int().nonnegative(),
    }),
    /** Raw header `Version` value; the format does not assign every bit a meaning. */
    format_version: u32Schema,
    timestamp: u32Schema,
    flags: u64Schema,
    streams: z.array(minidumpStreamSchema),
    modules: z.array(minidumpModuleSchema),
    threads: z.array(minidumpThreadSchema),
    exception: minidumpExceptionSchema.nullable(),
    system_info: minidumpSystemInfoSchema.nullable(),
    memory_ranges: z.array(minidumpMemoryRangeSchema),
    memory64_ranges: z.array(minidumpMemory64RangeSchema),
    memory_info: z.strictObject({
      list: z
        .strictObject({
          size_of_header: u32Schema,
          size_of_entry: u32Schema,
          number_of_entries: u64Schema,
        })
        .nullable(),
      entries: z.array(minidumpMemoryInfoSchema),
    }),
    /** Examined-record coverage; completeness derives from these counts. */
    examined: z.strictObject({
      streams: z.number().int().nonnegative(),
      parsed_streams: z.number().int().nonnegative(),
      unparsed_streams: z.number().int().nonnegative(),
      modules: z.number().int().nonnegative(),
      threads: z.number().int().nonnegative(),
      memory_ranges: z.number().int().nonnegative(),
      memory64_ranges: z.number().int().nonnegative(),
      memory_info_entries: z.number().int().nonnegative(),
    }),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    const bytes = report.artifact.bytes;
    const checkLocation = (
      location: { data_size: number; rva: number },
      path: (string | number)[],
    ): void => {
      if (location.rva > bytes || location.data_size > bytes - location.rva)
        context.addIssue({
          code: "custom",
          path,
          message:
            "Recorded structure location is outside the selected artifact.",
        });
    };
    for (const [index, stream] of report.streams.entries())
      checkLocation(stream.location, ["streams", index, "location"]);
    for (const [index, module] of report.modules.entries())
      if (module.name.name_rva > bytes)
        context.addIssue({
          code: "custom",
          path: ["modules", index, "name", "name_rva"],
          message:
            "Recorded structure location is outside the selected artifact.",
        });
    for (const [index, thread] of report.threads.entries()) {
      checkLocation(thread.stack.memory, ["threads", index, "stack", "memory"]);
      checkLocation(thread.context, ["threads", index, "context"]);
    }
    if (report.exception?.thread_context !== null && report.exception !== null)
      checkLocation(report.exception.thread_context, [
        "exception",
        "thread_context",
      ]);
    for (const [index, range] of report.memory_ranges.entries())
      checkLocation({ data_size: range.data_size, rva: range.rva }, [
        "memory_ranges",
        index,
      ]);
    const snapshotBytes = BigInt(bytes);
    for (const [index, range] of report.memory64_ranges.entries()) {
      const offset = BigInt(range.data_offset);
      const size = BigInt(range.data_size);
      if (offset > snapshotBytes || size > snapshotBytes - offset)
        context.addIssue({
          code: "custom",
          path: ["memory64_ranges", index],
          message:
            "Recorded structure location is outside the selected artifact.",
        });
    }
  });

export type MinidumpLocation = z.infer<typeof minidumpLocationSchema>;
export type MinidumpStream = z.infer<typeof minidumpStreamSchema>;
export type MinidumpModuleName = z.infer<typeof minidumpModuleNameSchema>;
export type MinidumpModule = z.infer<typeof minidumpModuleSchema>;
export type MinidumpThread = z.infer<typeof minidumpThreadSchema>;
export type MinidumpException = z.infer<typeof minidumpExceptionSchema>;
export type MinidumpSystemInfo = z.infer<typeof minidumpSystemInfoSchema>;
export type WindowsMinidump = z.infer<typeof windowsMinidumpSchema>;
export type InspectWindowsMinidumpInput = z.infer<
  typeof inspectWindowsMinidumpInputSchema
>;
