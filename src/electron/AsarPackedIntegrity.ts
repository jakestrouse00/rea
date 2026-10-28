import { createHash } from "node:crypto";
import type { Readable } from "node:stream";

/** Integrity declaration one ASAR member carries in the archive header. */
export interface AsarDeclaredIntegrity {
  readonly algorithm: "SHA256";
  readonly hash: string;
  readonly blockSize: number;
  readonly blocks: readonly string[];
}

export type AsarIntegrityDeclaration =
  | { readonly state: "declared"; readonly value: AsarDeclaredIntegrity }
  | { readonly state: "absent" }
  | { readonly state: "unsupported"; readonly reason: string };

/** One packed member as the archive header describes it. */
export interface AsarHeaderMember {
  readonly path: string;
  readonly bytes: number;
  readonly offset: string;
  readonly unpacked: boolean;
  readonly executable: boolean;
  readonly integrity: AsarIntegrityDeclaration;
}

export interface AsarHeaderSummary {
  readonly members: readonly AsarHeaderMember[];
  readonly files: number;
  readonly directories: number;
  readonly symlinks: number;
  readonly unpackedFiles: number;
}

const SHA256_HEX = /^[a-f0-9]{64}$/u;
const MAXIMUM_BLOCK_SIZE = 64 * 1024 * 1024;

/** Interpret one header integrity object without repairing it. */
export const asarIntegrityDeclaration = (
  value: unknown,
): AsarIntegrityDeclaration => {
  if (value === undefined || value === null) return { state: "absent" };
  if (typeof value !== "object")
    return { state: "unsupported", reason: "integrity is not an object" };
  const record = value as Record<string, unknown>;
  if (record.algorithm !== "SHA256")
    return {
      state: "unsupported",
      reason: "integrity algorithm is not SHA256",
    };
  if (typeof record.hash !== "string" || !SHA256_HEX.test(record.hash))
    return {
      state: "unsupported",
      reason: "integrity hash is not SHA-256 hex",
    };
  const blockSize = record.blockSize;
  if (
    typeof blockSize !== "number" ||
    !Number.isSafeInteger(blockSize) ||
    blockSize <= 0 ||
    blockSize > MAXIMUM_BLOCK_SIZE
  )
    return { state: "unsupported", reason: "integrity blockSize is invalid" };
  const blocks = record.blocks;
  if (
    !Array.isArray(blocks) ||
    blocks.length === 0 ||
    !blocks.every(
      (block) => typeof block === "string" && SHA256_HEX.test(block),
    )
  )
    return {
      state: "unsupported",
      reason: "integrity blocks are not SHA-256 hex",
    };
  return {
    state: "declared",
    value: {
      algorithm: "SHA256",
      hash: record.hash,
      blockSize,
      blocks: blocks as readonly string[],
    },
  };
};

type HeaderNode = Record<string, unknown>;

const isRecord = (value: unknown): value is HeaderNode =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Walk the decoded ASAR header once, keeping member extents, unpacked markers
 * and integrity declarations. A malformed node is skipped rather than repaired.
 */
export const summarizeAsarHeader = (header: unknown): AsarHeaderSummary => {
  const members: AsarHeaderMember[] = [];
  let files = 0;
  let directories = 0;
  let symlinks = 0;
  let unpackedFiles = 0;
  const stack: { readonly prefix: string; readonly node: HeaderNode }[] = [];
  if (isRecord(header)) stack.push({ prefix: "", node: header });
  while (stack.length > 0) {
    const frame = stack.pop();
    if (frame === undefined) break;
    const children = frame.node.files;
    if (!isRecord(children)) continue;
    for (const [name, child] of Object.entries(children)) {
      if (!isRecord(child)) continue;
      const path = frame.prefix === "" ? name : `${frame.prefix}/${name}`;
      if (isRecord(child.files)) {
        directories += 1;
        stack.push({ prefix: path, node: child });
        continue;
      }
      if (typeof child.link === "string") {
        symlinks += 1;
        continue;
      }
      const size = child.size;
      if (
        typeof size !== "number" ||
        !Number.isSafeInteger(size) ||
        size < 0 ||
        typeof child.offset !== "string"
      )
        continue;
      const unpacked = child.unpacked === true;
      files += 1;
      if (unpacked) unpackedFiles += 1;
      members.push({
        path,
        bytes: size,
        offset: child.offset,
        unpacked,
        executable: child.executable === true,
        integrity: asarIntegrityDeclaration(child.integrity),
      });
    }
  }
  return { members, files, directories, symlinks, unpackedFiles };
};

export interface AsarMemberVerification {
  readonly verified: boolean;
  readonly computedHash: string;
  readonly declaredBlocks: number;
  readonly computedBlocks: number;
  readonly mismatchedBlocks: number;
  readonly bytes: number;
}

/**
 * Check one member's declared whole-file and per-block checksums while
 * streaming its content. Block boundaries restart at each member, matching the
 * archive writer that produced the declaration.
 */
export const verifyAsarMemberIntegrity = async (
  declared: AsarDeclaredIntegrity,
  stream: Readable,
  signal?: AbortSignal,
): Promise<AsarMemberVerification> => {
  const whole = createHash("SHA256");
  const computed: string[] = [];
  let block = createHash("SHA256");
  let filled = 0;
  let bytes = 0;
  for await (const chunk of stream) {
    if (signal?.aborted === true) throw signal.reason;
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    bytes += data.byteLength;
    whole.update(data);
    let offset = 0;
    while (offset < data.byteLength) {
      const take = Math.min(
        declared.blockSize - filled,
        data.byteLength - offset,
      );
      block.update(data.subarray(offset, offset + take));
      filled += take;
      if (filled === declared.blockSize) {
        computed.push(block.digest("hex"));
        block = createHash("SHA256");
        filled = 0;
      }
      offset += take;
    }
  }
  if (filled > 0 || computed.length === 0) computed.push(block.digest("hex"));
  const computedHash = whole.digest("hex");
  const compared = Math.min(computed.length, declared.blocks.length);
  let mismatchedBlocks = 0;
  for (let index = 0; index < compared; index += 1)
    if (declared.blocks[index] !== computed[index]) mismatchedBlocks += 1;
  const extra = Math.abs(computed.length - declared.blocks.length);
  return {
    verified:
      computedHash === declared.hash &&
      computed.length === declared.blocks.length &&
      mismatchedBlocks === 0,
    computedHash,
    declaredBlocks: declared.blocks.length,
    computedBlocks: computed.length,
    mismatchedBlocks: mismatchedBlocks + extra,
    bytes,
  };
};
