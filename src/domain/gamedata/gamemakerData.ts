import { z } from "zod";

import { gamedataArtifactSchema } from "./gamedataShared.js";
import { localPathStringSchema } from "../localPath.js";

/** data.win / game.unx FORM chunk fourcc; single ASCII characters 0..255. */
export const FORM_MAGIC_BYTES = Buffer.from("FORM");
export const GAMEDATA_MAX_CHUNKS = 4096;
/** Fixed GEN8 prefix observed before any version-dependent fields. */
export const GEN8_EXAMINED_BYTES = 44;

/** One top-level chunk: fourcc, payload offset and byte count. */
export const gamemakerChunkSchema = z.strictObject({
  fourcc: z.string().regex(/^[A-Za-z0-9_]{4}$/u),
  fourcc_raw_hex: z.string().regex(/^[0-9a-f]{8}$/u),
  offset: z.number().int().min(0),
  bytes: z.number().int().min(0),
});
export type GamemakerChunk = z.infer<typeof gamemakerChunkSchema>;

/** One resolved GEN8 string pointer, without moving any source bytes. */
export const gamemakerStringSchema = z.strictObject({
  pointer: z.number().int().nonnegative(),
  text: z.string(),
  bytes: z.number().int().min(0),
});
export const gamemakerUnresolvedStringSchema = z.strictObject({
  pointer: z.number().int().nonnegative(),
  detail: z.string(),
});
const gamemakerNullableStringSchema = z.union([
  z.null(),
  gamemakerStringSchema,
  gamemakerUnresolvedStringSchema,
]);

/** GEN8 fixed-prefix fields; deeper fields remain unknown rather than guessed. */
export const gamemakerGen8Schema = z.strictObject({
  offset: z.number().int().nonnegative(),
  bytes: z.number().int().nonnegative(),
  debugger_disabled: z.union([z.boolean(), z.literal("unknown")]),
  bytecode_version: z.number().int().min(0).max(0xff),
  padding_hex: z.string().regex(/^[0-9a-f]{4}$/u),
  file_identification: gamemakerNullableStringSchema,
  config: gamemakerNullableStringSchema,
  name: gamemakerNullableStringSchema,
  last_obj: z.number().int().nonnegative(),
  last_tile: z.number().int().nonnegative(),
  game_id: z.number().int().nonnegative(),
  direct_play_guid_hex: z.string().regex(/^[0-9a-f]{32}$/u),
  unexamined_bytes: z.number().int().nonnegative(),
});
export type GamemakerGen8 = z.infer<typeof gamemakerGen8Schema>;

/** Structure-only chunk map of the caller-selected data file. */
export const gamemakerReportSchema = z
  .strictObject({
    artifact: gamedataArtifactSchema,
    form_bytes: z.number().int().nonnegative(),
    chunks: z.array(gamemakerChunkSchema),
    chunk_walk_complete: z.boolean(),
    unexplained_bytes: z.number().int().nonnegative(),
    chunk_walk_end_offset: z.number().int().nonnegative(),
    named_chunks: z.strictObject({
      CODE: gamemakerChunkSchema.nullable(),
      STRG: gamemakerChunkSchema.nullable(),
      TXOR: gamemakerChunkSchema.nullable(),
      SOND: gamemakerChunkSchema.nullable(),
    }),
    gen8: gamemakerGen8Schema.nullable(),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    const bound = report.artifact.bytes;
    for (const [index, chunk] of report.chunks.entries())
      if (chunk.offset > bound || chunk.bytes > bound - chunk.offset)
        context.addIssue({
          code: "custom",
          path: ["chunks", String(index)],
          message: "Chunk range is outside the inspected artifact.",
        });
  });
export type GamemakerReport = z.infer<typeof gamemakerReportSchema>;

export const inspectGamemakerDataInputSchema = z.strictObject({
  path: localPathStringSchema,
});

export class GameMakerFormatError extends Error {
  constructor(message: string) {
    super(message);
  }
}

const readU32 = (bytes: Buffer, offset: number): number =>
  bytes.readUInt32LE(offset);

const readByte = (bytes: Buffer, index: number): number => {
  const value = bytes[index];
  if (value === undefined)
    throw new GameMakerFormatError(
      `GEN8 byte at offset ${String(index)} is outside the artifact`,
    );
  return value;
};

const readStringAt = (
  bytes: Buffer,
  pointer: number,
):
  | { kind: "string"; value: { pointer: number; text: string; bytes: number } }
  | { kind: "unresolved"; value: { pointer: number; detail: string } }
  | undefined => {
  if (pointer === 0) return undefined; // null string, genuinely absent
  if (pointer + 4 > bytes.length)
    return {
      kind: "unresolved",
      value: { pointer, detail: "pointer is outside the artifact" },
    };
  const length = readU32(bytes, pointer);
  if (length > 0x100000 || pointer + 4 + length > bytes.length)
    return {
      kind: "unresolved",
      value: {
        pointer,
        detail: `string length ${String(length)} is unusable at the pointed offset`,
      },
    };
  const text = bytes
    .subarray(pointer + 4, pointer + 4 + length)
    .toString("utf8");
  if (Buffer.byteLength(text, "utf8") !== length || text.includes("\u0000"))
    return {
      kind: "unresolved",
      value: { pointer, detail: "string is not valid UTF-8" },
    };
  return { kind: "string", value: { pointer, text, bytes: length } };
};

const asNullableString = (
  resolved:
    | {
        kind: "string";
        value: { pointer: number; text: string; bytes: number };
      }
    | { kind: "unresolved"; value: { pointer: number; detail: string } }
    | undefined,
): z.infer<typeof gamemakerNullableStringSchema> =>
  resolved === undefined ? null : resolved.value;

/** Walk FORM chunks until the form ends or an unexplained region appears. */
export const parseGamemakerChunks = (
  bytes: Buffer,
): {
  chunks: readonly GamemakerChunk[];
  walkComplete: boolean;
  unexplainedBytes: number;
  formBytes: number;
} => {
  if (bytes.length < 8 || !bytes.subarray(0, 4).equals(FORM_MAGIC_BYTES))
    throw new GameMakerFormatError(
      "Artifact does not start with the FORM magic; GameMaker data.win and game.unx files do",
    );
  const formBytes = readU32(bytes, 4);
  if (formBytes > bytes.length - 8)
    throw new GameMakerFormatError(
      `FORM declares ${String(formBytes)} body bytes, more than the artifact holds beyond the header`,
    );
  const formEnd = 8 + formBytes;
  const chunks: GamemakerChunk[] = [];
  let offset = 8;
  while (offset < formEnd) {
    if (offset + 8 > formEnd)
      return {
        chunks,
        walkComplete: false,
        unexplainedBytes: formEnd - offset,
        formBytes,
      };
    const fourccRaw = bytes.readUInt32LE(offset);
    const fourcc = bytes.subarray(offset, offset + 4).toString("latin1");
    const printable = /^[A-Za-z0-9_]{4}$/u.test(fourcc);
    const size = readU32(bytes, offset + 4);
    if (!printable || size > formEnd - offset - 8)
      return {
        chunks,
        walkComplete: false,
        unexplainedBytes: formEnd - offset,
        formBytes,
      };
    chunks.push({
      fourcc,
      fourcc_raw_hex: fourccRaw.toString(16).padStart(8, "0"),
      offset: offset + 8,
      bytes: size,
    });
    if (chunks.length > GAMEDATA_MAX_CHUNKS)
      throw new GameMakerFormatError(
        `Chunk walk exceeds the ${String(GAMEDATA_MAX_CHUNKS)}-chunk bound`,
      );
    offset += 8 + size;
  }
  return {
    chunks,
    walkComplete: true,
    unexplainedBytes: bytes.length - formEnd,
    formBytes,
  };
};

const GEN8_HEX = (fourcc: string): boolean => fourcc === "GEN8";

/** Parse the fixed GEN8 prefix when its chunk exists. */
export const parseGamemakerGen8 = (
  bytes: Buffer,
  chunk: GamemakerChunk,
): GamemakerGen8 => {
  const base = chunk.offset;
  if (!GEN8_HEX(chunk.fourcc))
    throw new GameMakerFormatError("Not the GEN8 chunk");
  const available = chunk.bytes;
  if (available < GEN8_EXAMINED_BYTES)
    throw new GameMakerFormatError(
      `GEN8 chunk of ${String(available)} bytes is shorter than the fixed prefix`,
    );
  const debuggerByte = readByte(bytes, base);
  const bytecodeVersion = readByte(bytes, base + 1);
  const paddingHex = bytes.subarray(base + 2, base + 4).toString("hex");
  const filename = readStringAt(bytes, readU32(bytes, base + 4));
  const config = readStringAt(bytes, readU32(bytes, base + 8));
  const lastObj = readU32(bytes, base + 12);
  const lastTile = readU32(bytes, base + 16);
  const gameId = readU32(bytes, base + 20);
  const guidHex = bytes.subarray(base + 24, base + 40).toString("hex");
  // Name string pointer follows the 16-byte DirectPlay GUID.
  const name = readStringAt(bytes, readU32(bytes, base + 40));
  return {
    offset: base,
    bytes: available,
    debugger_disabled:
      debuggerByte === 0 ? false : debuggerByte === 1 ? true : "unknown",
    bytecode_version: bytecodeVersion,
    padding_hex: paddingHex,
    file_identification: asNullableString(filename),
    config: asNullableString(config),
    name: asNullableString(name),
    last_obj: lastObj,
    last_tile: lastTile,
    game_id: gameId,
    direct_play_guid_hex: guidHex,
    unexamined_bytes: available - GEN8_EXAMINED_BYTES,
  };
};

/** Parse the whole data file: FORM walk, named chunk map, and GEN8 when present. */
export const parseGamemakerData = (
  bytes: Buffer,
): Omit<GamemakerReport, "artifact"> => {
  const walked = parseGamemakerChunks(bytes);
  const named = (fourcc: string): GamemakerChunk | null =>
    walked.chunks.find((chunk) => chunk.fourcc === fourcc) ?? null;
  const gen8Chunk = named("GEN8");
  const gen8 = gen8Chunk === null ? null : parseGamemakerGen8(bytes, gen8Chunk);
  return {
    form_bytes: walked.formBytes,
    chunks: [...walked.chunks],
    chunk_walk_complete: walked.walkComplete,
    unexplained_bytes: walked.unexplainedBytes,
    chunk_walk_end_offset: walked.walkComplete
      ? walkTailOffset(walked.chunks)
      : 0,
    named_chunks: {
      CODE: named("CODE"),
      STRG: named("STRG"),
      TXOR: named("TXOR"),
      SOND: named("SOND"),
    },
    gen8,
    limitations: [
      "Structure-only inspection: chunk fourccs, offsets and sizes plus the fixed GEN8 prefix are observations; chunk contents were not decoded.",
      "Chunk presence is not identity: TXOR appears in YoYo-obfuscated data files and does not by itself identify a game or its origin.",
      ...(gen8 === null
        ? []
        : [
            `The GEN8 fixed ${String(GEN8_EXAMINED_BYTES)}-byte prefix was examined; ${String(gen8.unexamined_bytes)} further bytes remain unknown.`,
          ]),
      ...(walked.walkComplete
        ? []
        : [
            "The chunk walk stopped before the declared FORM end; trailing bytes are unexplained rather than chunks.",
          ]),
    ],
  };
};

const walkTailOffset = (chunks: readonly GamemakerChunk[]): number => {
  const last = chunks.at(-1);
  return last === undefined ? 0 : last.offset + last.bytes;
};
