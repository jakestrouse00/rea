import type {
  InspectWindowsMinidumpInput,
  MinidumpException,
  MinidumpLocation,
  MinidumpModule,
  MinidumpModuleName,
  MinidumpStream,
  MinidumpSystemInfo,
  MinidumpThread,
  WindowsMinidump,
} from "../domain/windowsArtifacts/windowsMinidump.js";

/**
 * Structural Windows minidump (MDMP) reader, bounded like every REA byte
 * parser. Offsets, sizes and counts come only from the dump itself; a declared
 * range that leaves the selected snapshot is a typed failure, not silence, and
 * unrecognized stream types remain listed unparsed rather than fabricated.
 *
 * `MINIDUMP_MEMORY_INFO` alignment padding fields and the `Reserved2` tail of
 * `MINIDUMP_SYSTEM_INFO` carry no identity and are not reported.
 */
export const MINIDUMP_INPUT_BYTES = 1024 * 1024 * 1024;
/** Real dumps carry on the order of ten streams; 4096 admits extreme ones. */
export const MINIDUMP_MAX_STREAMS = 4096;
/** Stream and table entry counts share one measured admissibility budget. */
export const MINIDUMP_MAX_ENTRIES = 65536;

/** The dump's declared structure contradicts itself or leaves the snapshot. */
export class MinidumpFormatFailure extends Error {
  readonly kind: "unsupported" | "malformed";
  constructor(
    kind: "unsupported" | "malformed",
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "MinidumpFormatFailure";
    this.kind = kind;
  }
}

/** A declared table exceeds a measured, documented structural budget. */
export class MinidumpResourceFailure extends Error {
  readonly maximum_entries: number;
  constructor(
    readonly boundary: "memory",
    maximumEntries: number,
    message: string,
  ) {
    super(message);
    this.name = "MinidumpResourceFailure";
    this.maximum_entries = maximumEntries;
  }
}

const MDMP_SIGNATURE = 0x504d444d;

/** Stream types this reader models; every other declared type stays unparsed. */
export const PARSED_STREAM_TYPES: Readonly<Record<number, string>> = {
  3: "ThreadListStream",
  4: "ModuleListStream",
  5: "MemoryListStream",
  6: "ExceptionStream",
  7: "SystemInfoStream",
  9: "Memory64ListStream",
  16: "MemoryInfoListStream",
};

const decimal = (value: bigint): string => value.toString(10);

/** Bounds-checked absolute-offset reader over one stream's stated range. */
class Reader {
  #cursor: number;
  constructor(
    readonly bytes: Buffer,
    readonly start: number,
    readonly end: number,
    readonly label: string,
  ) {
    if (start < 0 || end > bytes.length || end < start)
      throw new MinidumpFormatFailure(
        "malformed",
        `${label} declares ${String(start)}-${String(end)} bytes outside the snapshot`,
      );
    this.#cursor = start;
  }

  remaining(): number {
    return this.end - this.#cursor;
  }

  need(count: number): void {
    if (this.#cursor + count > this.end)
      throw new MinidumpFormatFailure(
        "malformed",
        `${this.label} needs ${String(count)} more bytes at offset ${String(this.#cursor)} but only ${String(this.remaining())} are declared`,
      );
  }

  u32(): number {
    this.need(4);
    const value = this.bytes.readUInt32LE(this.#cursor);
    this.#cursor += 4;
    return value;
  }

  u16(): number {
    this.need(2);
    const value = this.bytes.readUInt16LE(this.#cursor);
    this.#cursor += 2;
    return value;
  }

  u8(): number {
    this.need(1);
    const value = this.bytes.readUInt8(this.#cursor);
    this.#cursor += 1;
    return value;
  }

  u64(): bigint {
    this.need(8);
    const value = this.bytes.readBigUInt64LE(this.#cursor);
    this.#cursor += 8;
    return value;
  }

  location(): MinidumpLocation {
    const data_size = this.u32();
    const rva = this.u32();
    if (rva > this.bytes.length || data_size > this.bytes.length - rva)
      throw new MinidumpFormatFailure(
        "malformed",
        `${this.label} location (rva ${String(rva)}, size ${String(data_size)}) is outside the snapshot`,
      );
    return { data_size, rva };
  }
}

/** One MINIDUMP_STRING: byte length, then UTF-16LE wchar text. */
const minidumpString = (bytes: Buffer, rva: number): MinidumpModuleName => {
  if (rva < 0 || rva + 4 > bytes.length)
    throw new MinidumpFormatFailure(
      "malformed",
      `MINIDUMP_STRING length at rva ${String(rva)} is outside the snapshot`,
    );
  const byteLength = bytes.readUInt32LE(rva);
  if (byteLength % 2 !== 0)
    throw new MinidumpFormatFailure(
      "malformed",
      `MINIDUMP_STRING at rva ${String(rva)} declares an odd byte length ${String(byteLength)}`,
    );
  if (byteLength > bytes.length - rva - 4)
    throw new MinidumpFormatFailure(
      "malformed",
      `MINIDUMP_STRING at rva ${String(rva)} declares ${String(byteLength)} bytes beyond the snapshot`,
    );
  const raw = bytes.subarray(rva + 4, rva + 4 + byteLength);
  let name: string | null = null;
  try {
    name = new TextDecoder("utf-16le", { fatal: true }).decode(raw);
  } catch {
    name = null;
  }
  return { name, raw_bytes_base64: raw.toString("base64"), name_rva: rva };
};

/** One MINIDUMP_THREAD (48 bytes). */
const parseThreadList = (
  bytes: Buffer,
  stream: MinidumpLocation,
): MinidumpThread[] => {
  const reader = new Reader(
    bytes,
    stream.rva,
    stream.rva + stream.data_size,
    "ThreadListStream",
  );
  const count = reader.u32();
  if (count > MINIDUMP_MAX_ENTRIES)
    throw new MinidumpResourceFailure(
      "memory",
      MINIDUMP_MAX_ENTRIES,
      `ThreadListStream declares ${String(count)} entries above the ${String(MINIDUMP_MAX_ENTRIES)} entry budget`,
    );
  reader.need(count * 48);
  const threads: MinidumpThread[] = [];
  for (let index = 0; index < count; index += 1) {
    const id = reader.u32();
    const suspendCount = reader.u32();
    const priorityClass = reader.u32();
    const priority = reader.u32();
    const teb = reader.u64();
    const stackStart = reader.u64();
    const stackMemory = reader.location();
    const context = reader.location();
    threads.push({
      id,
      suspend_count: suspendCount,
      priority_class: priorityClass,
      priority,
      teb: decimal(teb),
      stack: {
        start_of_memory_range: decimal(stackStart),
        memory: stackMemory,
      },
      context,
    });
  }
  return threads;
};

/** One MINIDUMP_MODULE (108 bytes) plus its name MINIDUMP_STRING. */
const parseModuleList = (
  bytes: Buffer,
  stream: MinidumpLocation,
): MinidumpModule[] => {
  const reader = new Reader(
    bytes,
    stream.rva,
    stream.rva + stream.data_size,
    "ModuleListStream",
  );
  const count = reader.u32();
  if (count > MINIDUMP_MAX_ENTRIES)
    throw new MinidumpResourceFailure(
      "memory",
      MINIDUMP_MAX_ENTRIES,
      `ModuleListStream declares ${String(count)} entries above the ${String(MINIDUMP_MAX_ENTRIES)} entry budget`,
    );
  reader.need(count * 108);
  const modules: MinidumpModule[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = reader.u64();
    const size = reader.u32();
    const checksum = reader.u32();
    const timestamp = reader.u32();
    const moduleNameRva = reader.u32();
    const versionInfoSignature = reader.u32();
    const versionInfoStrucVersion = reader.u32();
    const fileVersionMs = reader.u32();
    const fileVersionLs = reader.u32();
    const productVersionMs = reader.u32();
    const productVersionLs = reader.u32();
    const fileFlagsMask = reader.u32();
    const fileFlags = reader.u32();
    const os = reader.u32();
    const fileType = reader.u32();
    const fileSubtype = reader.u32();
    const fileDateMs = reader.u32();
    const fileDateLs = reader.u32();
    const codeview = reader.location();
    const misc = reader.location();
    const reserved0 = reader.u64();
    const reserved1 = reader.u64();
    modules.push({
      name: minidumpString(bytes, moduleNameRva),
      base: decimal(base),
      size,
      checksum,
      timestamp,
      version_info_signature: versionInfoSignature,
      version_info_struc_version: versionInfoStrucVersion,
      file_version_ms: fileVersionMs,
      file_version_ls: fileVersionLs,
      product_version_ms: productVersionMs,
      product_version_ls: productVersionLs,
      file_flags_mask: fileFlagsMask,
      file_flags: fileFlags,
      os,
      file_type: fileType,
      file_subtype: fileSubtype,
      file_date_ms: fileDateMs,
      file_date_ls: fileDateLs,
      codeview_record: codeview,
      misc_record: misc,
      reserved0: decimal(reserved0),
      reserved1: decimal(reserved1),
    });
  }
  return modules;
};

/** One MINIDUMP_MEMORY_DESCRIPTOR pair (16 bytes). */
const parseMemoryList = (
  bytes: Buffer,
  stream: MinidumpLocation,
): { start: string; data_size: number; rva: number }[] => {
  const reader = new Reader(
    bytes,
    stream.rva,
    stream.rva + stream.data_size,
    "MemoryListStream",
  );
  const count = reader.u32();
  if (count > MINIDUMP_MAX_ENTRIES)
    throw new MinidumpResourceFailure(
      "memory",
      MINIDUMP_MAX_ENTRIES,
      `MemoryListStream declares ${String(count)} entries above the ${String(MINIDUMP_MAX_ENTRIES)} entry budget`,
    );
  reader.need(count * 16);
  const ranges = [];
  for (let index = 0; index < count; index += 1) {
    const rangeStart = reader.u64();
    const memory = reader.location();
    ranges.push({
      start: decimal(rangeStart),
      data_size: memory.data_size,
      rva: memory.rva,
    });
  }
  return ranges;
};

/** MINIDUMP_EXCEPTION_STREAM (168 bytes) with the full parameter vector. */
const parseException = (
  bytes: Buffer,
  stream: MinidumpLocation,
): MinidumpException => {
  const reader = new Reader(
    bytes,
    stream.rva,
    stream.rva + stream.data_size,
    "ExceptionStream",
  );
  const threadId = reader.u32();
  reader.u32(); // __alignment
  const code = reader.u32();
  const flags = reader.u32();
  const record = reader.u64();
  const address = reader.u64();
  const parameterCount = reader.u32();
  reader.u32(); // __unusedAlignment
  if (parameterCount > 15)
    throw new MinidumpFormatFailure(
      "malformed",
      `ExceptionStream declares ${String(parameterCount)} parameters above the format limit of 15`,
    );
  const parameters: string[] = [];
  for (let index = 0; index < 15; index += 1) {
    const value = reader.u64();
    if (index < parameterCount) parameters.push(decimal(value));
  }
  const threadContext = reader.location();
  return {
    thread_id: threadId,
    code,
    flags,
    record: decimal(record),
    address: decimal(address),
    parameter_count: parameterCount,
    parameters,
    thread_context: threadContext,
  };
};

/** MINIDUMP_SYSTEM_INFO (32 bytes); only the identity-bearing numbers are kept. */
const parseSystemInfo = (
  bytes: Buffer,
  stream: MinidumpLocation,
): MinidumpSystemInfo => {
  const reader = new Reader(
    bytes,
    stream.rva,
    stream.rva + stream.data_size,
    "SystemInfoStream",
  );
  const processorArchitecture = reader.u16();
  const processorLevel = reader.u16();
  const processorRevision = reader.u16();
  const numberOfProcessors = reader.u8();
  const productType = reader.u8();
  const majorVersion = reader.u32();
  const minorVersion = reader.u32();
  const buildNumber = reader.u32();
  const platformId = reader.u32();
  const csdVersionRva = reader.u32();
  const suiteMask = reader.u16();
  reader.u16(); // Reserved2
  return {
    processor_architecture: processorArchitecture,
    processor_level: processorLevel,
    processor_revision: processorRevision,
    number_of_processors: numberOfProcessors,
    product_type: productType,
    major_version: majorVersion,
    minor_version: minorVersion,
    build_number: buildNumber,
    platform_id: platformId,
    csd_version_rva: csdVersionRva,
    suite_mask: suiteMask,
  };
};

/** MINIDUMP_MEMORY64_LIST: ranges whose data follows from BASE RVA sequentially. */
const parseMemory64List = (
  bytes: Buffer,
  stream: MinidumpLocation,
): { start: string; data_size: string; data_offset: string }[] => {
  const reader = new Reader(
    bytes,
    stream.rva,
    stream.rva + stream.data_size,
    "Memory64ListStream",
  );
  const count = reader.u64();
  const baseRva = reader.u64();
  if (count > BigInt(MINIDUMP_MAX_ENTRIES))
    throw new MinidumpResourceFailure(
      "memory",
      MINIDUMP_MAX_ENTRIES,
      `Memory64ListStream declares ${count.toString(10)} entries above the ${String(MINIDUMP_MAX_ENTRIES)} entry budget`,
    );
  if (count * 16n > BigInt(reader.remaining()))
    throw new MinidumpFormatFailure(
      "malformed",
      `Memory64ListStream declares ${count.toString(10)} entries beyond its ${String(stream.data_size)} bytes`,
    );
  const ranges = [];
  let offset = baseRva;
  for (let index = 0; index < count; index += 1) {
    const rangeStart = reader.u64();
    const dataSize = reader.u64();
    if (
      offset > BigInt(bytes.length) ||
      dataSize > BigInt(bytes.length) - offset
    )
      throw new MinidumpFormatFailure(
        "malformed",
        `Memory64ListStream range ${index} at data offset ${offset.toString(10)} declares ${dataSize.toString(10)} bytes beyond the snapshot`,
      );
    ranges.push({
      start: decimal(rangeStart),
      data_size: decimal(dataSize),
      data_offset: decimal(offset),
    });
    offset += dataSize;
  }
  return ranges;
};

const u32At = (bytes: Buffer, offset: number): number => {
  if (offset < 0 || offset + 4 > bytes.length)
    throw new MinidumpFormatFailure(
      "malformed",
      `MemoryInfoList entry at offset ${String(offset)} extends past the snapshot`,
    );
  return bytes.readUInt32LE(offset);
};

const u64At = (bytes: Buffer, offset: number): bigint => {
  if (offset < 0 || offset + 8 > bytes.length)
    throw new MinidumpFormatFailure(
      "malformed",
      `MemoryInfoList entry at offset ${String(offset)} extends past the snapshot`,
    );
  return bytes.readBigUInt64LE(offset);
};

/** MINIDUMP_MEMORY_INFO_LIST: header sizes come from the dump itself. */
const parseMemoryInfoList = (
  bytes: Buffer,
  stream: MinidumpLocation,
): {
  list: {
    size_of_header: number;
    size_of_entry: number;
    number_of_entries: string;
  } | null;
  entries: {
    base: string;
    allocation_base: string;
    allocation_protect: number;
    region_size: string;
    state: number;
    protect: number;
    type: number;
  }[];
} => {
  const reader = new Reader(
    bytes,
    stream.rva,
    stream.rva + stream.data_size,
    "MemoryInfoListStream",
  );
  const sizeOfHeader = reader.u32();
  const sizeOfEntry = reader.u32();
  const numberOfEntries = reader.u64();
  const list = {
    size_of_header: sizeOfHeader,
    size_of_entry: sizeOfEntry,
    number_of_entries: numberOfEntries.toString(10),
  };
  if (numberOfEntries === 0n) return { list, entries: [] };
  if (sizeOfEntry < 48 || sizeOfHeader < 16)
    throw new MinidumpFormatFailure(
      "malformed",
      `MemoryInfoListStream declares an impossible entry size ${String(sizeOfEntry)} or header size ${String(sizeOfHeader)}`,
    );
  if (numberOfEntries > BigInt(MINIDUMP_MAX_ENTRIES))
    throw new MinidumpResourceFailure(
      "memory",
      MINIDUMP_MAX_ENTRIES,
      `MemoryInfoListStream declares ${numberOfEntries.toString(10)} entries above the ${String(MINIDUMP_MAX_ENTRIES)} entry budget`,
    );
  if (
    BigInt(sizeOfHeader) + numberOfEntries * BigInt(sizeOfEntry) >
    BigInt(stream.data_size)
  )
    throw new MinidumpFormatFailure(
      "malformed",
      `MemoryInfoListStream declares ${numberOfEntries.toString(10)} entries beyond its ${String(stream.data_size)} bytes`,
    );
  const entries = [];
  for (let index = 0; index < Number(numberOfEntries); index += 1) {
    const at = stream.rva + sizeOfHeader + index * sizeOfEntry;
    entries.push({
      base: decimal(u64At(bytes, at)),
      allocation_base: decimal(u64At(bytes, at + 8)),
      allocation_protect: u32At(bytes, at + 16),
      region_size: decimal(u64At(bytes, at + 24)),
      state: u32At(bytes, at + 32),
      protect: u32At(bytes, at + 36),
      type: u32At(bytes, at + 40),
    });
  }
  return { list, entries };
};

/**
 * Parse one complete bounded minidump snapshot into the structural report.
 * Throws typed `MinidumpFormatFailure` / `MinidumpResourceFailure` values; the
 * snapshot bytes are never executed, followed or resolved as addresses.
 */
export const parseWindowsMinidump = (
  snapshot: { readonly bytes: Buffer; readonly sha256: string },
  input: InspectWindowsMinidumpInput,
): WindowsMinidump => {
  const bytes = snapshot.bytes;
  if (bytes.length < 32)
    throw new MinidumpFormatFailure(
      "malformed",
      `Snapshot is ${String(bytes.length)} bytes; an MDMP header needs at least 32`,
    );
  if (bytes.readUInt32LE(0) !== MDMP_SIGNATURE)
    throw new MinidumpFormatFailure(
      "unsupported",
      "Selected artifact does not start with the `MDMP` signature",
    );
  const formatVersion = bytes.readUInt32LE(4);
  const numberOfStreams = bytes.readUInt32LE(8);
  const directoryRva = bytes.readUInt32LE(12);
  const timestamp = bytes.readUInt32LE(16);
  const flags = bytes.readBigUInt64LE(24);
  if (numberOfStreams > MINIDUMP_MAX_STREAMS)
    throw new MinidumpResourceFailure(
      "memory",
      MINIDUMP_MAX_STREAMS,
      `Header declares ${String(numberOfStreams)} streams above the ${String(MINIDUMP_MAX_STREAMS)} stream budget`,
    );
  const directory = new Reader(
    bytes,
    32,
    Math.min(bytes.length, 32 + numberOfStreams * 12),
    "StreamDirectory",
  );
  const streams: MinidumpStream[] = [];
  for (let index = 0; index < numberOfStreams; index += 1) {
    const type = directory.u32();
    const location = directory.location();
    streams.push({
      type,
      status: PARSED_STREAM_TYPES[type] === undefined ? "unparsed" : "parsed",
      location,
    });
  }

  const rangeOf = (type: number): MinidumpLocation | undefined => {
    const stream = streams.find((candidate) => candidate.type === type);
    return stream === undefined ? undefined : stream.location;
  };

  const threadList = rangeOf(3);
  const threads =
    threadList === undefined ? [] : parseThreadList(bytes, threadList);
  const moduleList = rangeOf(4);
  const modules =
    moduleList === undefined ? [] : parseModuleList(bytes, moduleList);
  const memoryList = rangeOf(5);
  const memoryRanges =
    memoryList === undefined ? [] : parseMemoryList(bytes, memoryList);
  const exceptionStream = rangeOf(6);
  const exception =
    exceptionStream === undefined || exceptionStream.data_size < 168
      ? null
      : parseException(bytes, exceptionStream);
  const systemInfoStream = rangeOf(7);
  const systemInfo =
    systemInfoStream === undefined || systemInfoStream.data_size < 32
      ? null
      : parseSystemInfo(bytes, systemInfoStream);
  const memory64List = rangeOf(9);
  const memory64Ranges =
    memory64List === undefined ? [] : parseMemory64List(bytes, memory64List);
  const memoryInfoStream = rangeOf(16);
  const memoryInfo =
    memoryInfoStream === undefined
      ? { list: null, entries: [] }
      : parseMemoryInfoList(bytes, memoryInfoStream);

  const parsedStreams = streams.filter((stream) => stream.status === "parsed");
  const truncatedStreamLimitations = [
    ...(exceptionStream !== undefined && exceptionStream.data_size < 168
      ? [
          `ExceptionStream declares ${String(exceptionStream.data_size)} bytes; below the 168-byte MINIDUMP_EXCEPTION structure, so exception facts stay unknown.`,
        ]
      : []),
    ...(systemInfoStream !== undefined && systemInfoStream.data_size < 32
      ? [
          `SystemInfoStream declares ${String(systemInfoStream.data_size)} bytes; below the 32-byte MINIDUMP_SYSTEM_INFO structure, so system facts stay unknown.`,
        ]
      : []),
  ];
  const duplicateStreamLimitations = Object.entries(
    PARSED_STREAM_TYPES,
  ).flatMap(([type, label]) => {
    const occurrences = streams.filter(
      (stream) => stream.type === Number(type),
    ).length;
    return occurrences > 1
      ? [
          `${occurrences} ${label} directory entries were declared; only the first informs the report and the others go undecoded.`,
        ]
      : [];
  });
  return {
    artifact: {
      path: input.path,
      sha256: snapshot.sha256,
      bytes: bytes.length,
    },
    format_version: formatVersion,
    timestamp,
    flags: decimal(flags),
    streams,
    modules,
    threads,
    exception,
    system_info: systemInfo,
    memory_ranges: memoryRanges,
    memory64_ranges: memory64Ranges,
    memory_info: memoryInfo,
    examined: {
      streams: streams.length,
      parsed_streams: parsedStreams.length,
      unparsed_streams: streams.length - parsedStreams.length,
      modules: modules.length,
      threads: threads.length,
      memory_ranges: memoryRanges.length,
      memory64_ranges: memory64Ranges.length,
      memory_info_entries: memoryInfo.entries.length,
    },
    limitations: [
      "Table facts only; no recorded address is resolved against the dump's contents and no payload bytes are returned.",
      "Thread CONTEXT records are reported as file locations; register values stay unknown.",
      ...(systemInfo === null
        ? []
        : [
            "SystemInfoStream CSD (service-pack) string is preserved by location and not expanded.",
          ]),
      "Unrecognized stream types remain unparsed directory entries; their contents are not interpreted.",
      ...truncatedStreamLimitations,
      ...duplicateStreamLimitations,
    ],
  };
};
