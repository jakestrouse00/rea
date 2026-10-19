import { createHash } from "node:crypto";

/**
 * Hand-built synthetic MDMP fixtures, laid out byte-for-byte against the
 * documented MINIDUMP format: a 32-byte header, a 12-byte-per-entry stream
 * directory, and stream payloads at declared RVAs. The builders are the
 * committed evidence for the parser's expectations; boundary tests
 * materialize the same bytes as stable files.
 */

export interface MinidumpFixtureThread {
  id: number;
  suspendCount?: number;
  priorityClass?: number;
  priority?: number;
  teb: bigint;
  stackStart: bigint;
  /** Recorded stack bytes stored at the declared stack location. */
  stackBytes?: number;
  contextSize?: number;
}

export interface MinidumpFixtureModuleVersionInfo {
  signature?: number;
  strucVersion?: number;
  fileVersionMs?: number;
  fileVersionLs?: number;
  productVersionMs?: number;
  productVersionLs?: number;
  fileFlagsMask?: number;
  fileFlags?: number;
  os?: number;
  fileType?: number;
  fileSubtype?: number;
  fileDateMs?: number;
  fileDateLs?: number;
}

export interface MinidumpFixtureModule {
  name: string;
  base: bigint;
  size: number;
  checksum?: number;
  timestamp?: number;
  versionInfo?: MinidumpFixtureModuleVersionInfo;
}

export interface MinidumpFixtureMemoryRange {
  start: bigint;
  bytes: number;
}

export interface MinidumpFixtureException {
  threadId: number;
  code: number;
  flags?: number;
  record?: bigint;
  address: bigint;
  parameters?: bigint[];
  /** Omit the thread-context location entirely (zero size, zero RVA). */
  omitContext?: boolean;
}

export interface MinidumpFixtureSystemInfo {
  processorArchitecture?: number;
  processorLevel?: number;
  processorRevision?: number;
  numberOfProcessors?: number;
  productType?: number;
  majorVersion?: number;
  minorVersion?: number;
  buildNumber?: number;
  platformId?: number;
  csdVersionRva?: number;
  suiteMask?: number;
}

export interface MinidumpFixtureMemoryInfoEntry {
  base: bigint;
  allocationBase: bigint;
  allocationProtect: number;
  regionSize: bigint;
  state: number;
  protect: number;
  type: number;
}

export type MinidumpFixtureStream =
  | { kind: "thread-list"; threads: MinidumpFixtureThread[] }
  | { kind: "module-list"; modules: MinidumpFixtureModule[] }
  | { kind: "memory-list"; ranges: MinidumpFixtureMemoryRange[] }
  | { kind: "memory64-list"; ranges: { start: bigint; bytes: number }[] }
  | { kind: "exception"; exception: MinidumpFixtureException }
  | { kind: "system-info"; info: MinidumpFixtureSystemInfo }
  | { kind: "memory-info-list"; entries: MinidumpFixtureMemoryInfoEntry[] }
  | { kind: "unparsed"; type: number; bytes?: readonly number[] };

export interface MinidumpFixtureInput {
  version?: number;
  timestamp?: number;
  flags?: bigint;
  streams: MinidumpFixtureStream[];
}

export interface BuiltMinidump {
  readonly bytes: Buffer;
  readonly sha256: string;
}

const CONTEXT_SIZE = 0x4d0;
const DATA_FILL = 0xcd;

const u32 = (value: number): Buffer => {
  const chunk = Buffer.alloc(4);
  chunk.writeUInt32LE(value >>> 0, 0);
  return chunk;
};

const u64 = (value: bigint): Buffer => {
  const chunk = Buffer.alloc(8);
  chunk.writeBigUInt64LE(value, 0);
  return chunk;
};

const minidumpString = (text: string): Buffer => {
  const body = Buffer.from(text, "utf16le");
  return Buffer.concat([u32(body.length), body, u32(0)]);
};

/**
 * One stream payload under construction. Every recorded-byte area the reader
 * must locate by RVA is appended inline right after its table, so its
 * payload-relative offset is known the moment it is written; reserved RVA
 * fields are bound to those offsets and resolved to absolute RVAs once the
 * assembler knows each stream's file position.
 */
class Body {
  readonly chunks: Buffer[] = [];
  length = 0;
  readonly patches: { at: number; target: number }[] = [];

  u32(value: number): void {
    this.append(u32(value));
  }

  u64(value: bigint): void {
    this.append(u64(value));
  }

  byte(value: number): void {
    this.append(Buffer.from([value & 0xff]));
  }

  u16(value: number): void {
    const chunk = Buffer.alloc(2);
    chunk.writeUInt16LE(value & 0xffff, 0);
    this.append(chunk);
  }

  /** Reserve a u32 RVA field; then bind it with `setTarget`. */
  reserveRva(): number {
    this.chunks.push(u32(0));
    const at = this.length;
    this.length += 4;
    this.patches.push({ at, target: 0 });
    return this.patches.length - 1;
  }

  /** Reserve a u64 RVA field (Memory64 base RVA); bind it with `setTarget`. */
  reserveRva64(): number {
    this.chunks.push(u64(0n));
    const at = this.length;
    this.length += 8;
    this.patches.push({ at, target: 0 });
    return this.patches.length - 1;
  }

  /** Bind a reserved RVA field to a body-relative target offset. */
  setTarget(reservation: number, target: number): void {
    const patch = this.patches[reservation];
    if (patch === undefined)
      throw new RangeError(`Unknown RVA reservation ${String(reservation)}`);
    patch.target = target;
  }

  append(value: Buffer): void {
    this.chunks.push(value);
    this.length += value.length;
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

interface SerializedStream {
  readonly type: number;
  readonly body: Buffer;
  readonly patches: readonly { at: number; target: number }[];
}

const serializeThreadList = (
  threads: MinidumpFixtureThread[],
): SerializedStream => {
  const body = new Body();
  body.u32(threads.length);
  const reservations: { stack: number; context: number }[] = [];
  for (const thread of threads) {
    const stackBytes = thread.stackBytes ?? 0;
    const contextSize = thread.contextSize ?? CONTEXT_SIZE;
    body.u32(thread.id);
    body.u32(thread.suspendCount ?? 0);
    body.u32(thread.priorityClass ?? 2);
    body.u32(thread.priority ?? 0);
    body.u64(thread.teb);
    body.u64(thread.stackStart);
    body.u32(stackBytes);
    const stack = body.reserveRva();
    body.u32(contextSize);
    const context = body.reserveRva();
    reservations.push({ stack, context });
  }
  for (const [index, thread] of threads.entries()) {
    const reservation = reservations[index];
    if (reservation === undefined) continue;
    const stackTarget = body.length;
    body.append(Buffer.alloc(thread.stackBytes ?? 0, DATA_FILL));
    const contextTarget = body.length;
    body.append(Buffer.alloc(thread.contextSize ?? CONTEXT_SIZE, 0));
    body.setTarget(reservation.stack, stackTarget);
    body.setTarget(reservation.context, contextTarget);
  }
  return { type: 3, body: body.toBuffer(), patches: body.patches };
};

const serializeModuleList = (
  modules: MinidumpFixtureModule[],
): SerializedStream => {
  const body = new Body();
  body.u32(modules.length);
  const nameReservations: number[] = [];
  for (const module of modules) {
    const version = module.versionInfo ?? {};
    body.u64(module.base);
    body.u32(module.size);
    body.u32(module.checksum ?? 0);
    body.u32(module.timestamp ?? 0);
    nameReservations.push(body.reserveRva());
    body.u32(version.signature ?? 0xf00fee04);
    body.u32(version.strucVersion ?? 65536);
    body.u32(version.fileVersionMs ?? 10);
    body.u32(version.fileVersionLs ?? 1);
    body.u32(version.productVersionMs ?? 6);
    body.u32(version.productVersionLs ?? 3);
    body.u32(version.fileFlagsMask ?? 0x3f);
    body.u32(version.fileFlags ?? 0);
    body.u32(version.os ?? 0x40004);
    body.u32(version.fileType ?? 2);
    body.u32(version.fileSubtype ?? 0);
    body.u32(version.fileDateMs ?? 0);
    body.u32(version.fileDateLs ?? 0);
    body.u32(0);
    body.u32(0);
    body.u32(0);
    body.u32(0);
    body.u64(0n);
    body.u64(0n);
  }
  let nameCursor = body.length;
  for (const [index, module] of modules.entries()) {
    const reservation = nameReservations[index];
    if (reservation === undefined) continue;
    const name = minidumpString(module.name);
    body.setTarget(reservation, nameCursor);
    nameCursor += name.length;
    body.append(name);
  }
  return { type: 4, body: body.toBuffer(), patches: body.patches };
};

const serializeMemoryList = (
  ranges: MinidumpFixtureMemoryRange[],
): SerializedStream => {
  const body = new Body();
  body.u32(ranges.length);
  const reservations: number[] = [];
  for (const range of ranges) {
    body.u64(range.start);
    body.u32(range.bytes);
    reservations.push(body.reserveRva());
  }
  for (const [index, range] of ranges.entries()) {
    const reservation = reservations[index];
    if (reservation === undefined) continue;
    const target = body.length;
    body.append(Buffer.alloc(range.bytes, DATA_FILL));
    body.setTarget(reservation, target);
  }
  return { type: 5, body: body.toBuffer(), patches: body.patches };
};

const serializeMemory64List = (
  ranges: { start: bigint; bytes: number }[],
): SerializedStream => {
  const body = new Body();
  body.u64(BigInt(ranges.length));
  const base = body.reserveRva64();
  for (const range of ranges) {
    body.u64(range.start);
    body.u64(BigInt(range.bytes));
  }
  const baseTarget = body.length;
  for (const range of ranges) body.append(Buffer.alloc(range.bytes, DATA_FILL));
  body.setTarget(base, baseTarget);
  return { type: 9, body: body.toBuffer(), patches: body.patches };
};

const serializeException = (
  exception: MinidumpFixtureException,
): SerializedStream => {
  const body = new Body();
  const parameters = exception.parameters ?? [];
  body.u32(exception.threadId);
  body.u32(0);
  body.u32(exception.code);
  body.u32(exception.flags ?? 0);
  body.u64(exception.record ?? 0n);
  body.u64(exception.address);
  if (parameters.length > 15)
    throw new RangeError("MINIDUMP_EXCEPTION admits at most 15 parameters");
  body.u32(parameters.length);
  body.u32(0);
  for (let index = 0; index < 15; index += 1) {
    const value = index < parameters.length ? parameters[index] : 0n;
    body.u64(value ?? 0n);
  }
  if (exception.omitContext === true) {
    body.u32(0);
    body.u32(0);
  } else {
    body.u32(0x40);
    const context = body.reserveRva();
    const contextTarget = body.length;
    body.append(Buffer.alloc(0x40, DATA_FILL));
    body.setTarget(context, contextTarget);
  }
  return { type: 6, body: body.toBuffer(), patches: body.patches };
};

const serializeSystemInfo = (
  info: MinidumpFixtureSystemInfo,
): SerializedStream => {
  const body = new Body();
  body.u16(info.processorArchitecture ?? 9);
  body.u16(info.processorLevel ?? 6);
  body.u16(info.processorRevision ?? 0x0302);
  body.byte(info.numberOfProcessors ?? 8);
  body.byte(info.productType ?? 1);
  body.u32(info.majorVersion ?? 10);
  body.u32(info.minorVersion ?? 0);
  body.u32(info.buildNumber ?? 19045);
  body.u32(info.platformId ?? 2);
  body.u32(info.csdVersionRva ?? 0);
  body.u16(info.suiteMask ?? 0x0100);
  body.u16(0);
  return { type: 7, body: body.toBuffer(), patches: body.patches };
};

const serialize = (stream: MinidumpFixtureStream): SerializedStream => {
  switch (stream.kind) {
    case "thread-list":
      return serializeThreadList(stream.threads);
    case "module-list":
      return serializeModuleList(stream.modules);
    case "memory-list":
      return serializeMemoryList(stream.ranges);
    case "memory64-list":
      return serializeMemory64List(stream.ranges);
    case "exception":
      return serializeException(stream.exception);
    case "system-info":
      return serializeSystemInfo(stream.info);
    case "memory-info-list": {
      const body = new Body();
      body.u32(16);
      body.u32(48);
      body.u64(BigInt(stream.entries.length));
      for (const entry of stream.entries) {
        body.u64(entry.base);
        body.u64(entry.allocationBase);
        body.u32(entry.allocationProtect);
        body.u32(0);
        body.u64(entry.regionSize);
        body.u32(entry.state);
        body.u32(entry.protect);
        body.u32(entry.type);
        body.u32(0);
      }
      return { type: 16, body: body.toBuffer(), patches: body.patches };
    }
    case "unparsed":
      return {
        type: stream.type,
        body:
          stream.bytes === undefined
            ? Buffer.alloc(0)
            : Buffer.from([...stream.bytes]),
        patches: [],
      };
  }
};

/**
 * Assemble one synthetic minidump: 32-byte header, 12-byte directory entries,
 * then stream payloads laid out sequentially from RVA 32 + 12 * count.
 */
export const buildMinidumpFixture = (
  input: MinidumpFixtureInput,
): BuiltMinidump => {
  const bodies = input.streams.map((stream) => serialize(stream));
  // Serialization is deterministic and independent of file position, so the
  // payload base is derivable from the sizes it just produced.
  const payloadBase = 32 + bodies.length * 12;
  const total = payloadBase + bodies.reduce((sum, b) => sum + b.body.length, 0);
  const file = Buffer.alloc(total);
  file.write("MDMP", 0, "ascii");
  file.writeUInt32LE(input.version ?? 42899, 4);
  file.writeUInt32LE(bodies.length, 8);
  file.writeUInt32LE(32, 12);
  file.writeUInt32LE(input.timestamp ?? 1729200000, 16);
  file.writeUInt32LE(0, 20);
  file.writeBigUInt64LE(input.flags ?? 0n, 24);
  let cursor = payloadBase;
  for (const [index, stream] of bodies.entries()) {
    file.writeUInt32LE(stream.type, 32 + index * 12);
    file.writeUInt32LE(stream.body.length, 32 + index * 12 + 4);
    file.writeUInt32LE(cursor, 32 + index * 12 + 8);
    stream.body.copy(file, cursor);
    for (const patch of stream.patches)
      file.writeUInt32LE(cursor + patch.target, cursor + patch.at);
    cursor += stream.body.length;
  }
  const sha256 = createHash("sha256").update(file).digest("hex");
  return { bytes: file, sha256 };
};

/** A representative crash dump: threads, modules, memory, exception, system,
 * plus one unrecognized stream type that must stay an unparsed entry. */
export const representativeMinidump = (): BuiltMinidump =>
  buildMinidumpFixture({
    streams: [
      {
        kind: "thread-list",
        threads: [
          {
            id: 4040,
            teb: 0x7ffdf0000000n,
            stackStart: 0x0f1000n,
            stackBytes: 16,
          },
          {
            id: 4041,
            suspendCount: 1,
            teb: 0x7ffdf0001000n,
            stackStart: 0x0f4000n,
            stackBytes: 8,
          },
        ],
      },
      {
        kind: "module-list",
        modules: [
          {
            name: "C:\\Windows\\System32\\example.dll",
            base: 0x7ff600000000n,
            size: 0x1000,
            checksum: 0x1234,
            timestamp: 1729000000,
          },
        ],
      },
      {
        kind: "memory-list",
        ranges: [
          { start: 0x0f1000n, bytes: 16 },
          { start: 0x0f4000n, bytes: 8 },
        ],
      },
      {
        kind: "exception",
        exception: {
          threadId: 4040,
          code: 0xc0000005,
          address: 0x7ff600000123n,
          parameters: [0n, 0x7ff600000123n],
        },
      },
      {
        kind: "system-info",
        info: { processorArchitecture: 9, numberOfProcessors: 8 },
      },
      { kind: "unparsed", type: 19, bytes: [1, 2, 3, 4] },
    ],
  });
