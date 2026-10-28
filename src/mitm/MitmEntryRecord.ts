import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";

import { z } from "zod";
import {
  absoluteLocalPathStringSchema,
  isPathWithinRoot,
} from "../domain/localPath.js";
import {
  MITM_ENTRY_RECORD_VERSION,
  MITM_LIMITS,
} from "../domain/mitm/mitmLimits.js";
import { REPLAY_LIMITS } from "../domain/replay/replayLimits.js";
import type {
  ReplayBody,
  ReplayRequest,
} from "../domain/replay/replayRequest.js";

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);

const heldBodySchema = z.strictObject({
  path: absoluteLocalPathStringSchema.nullable(),
  bytes: z.int().min(0),
  sha256: sha256Schema.nullable(),
});

/** One owner-only record the addon wrote so its request can be re-sent. */
export const mitmEntryRecordSchema = z.strictObject({
  version: z.literal(MITM_ENTRY_RECORD_VERSION),
  sequence: z.int().min(1),
  method: z.string().min(1).max(32),
  url: z.string().min(1).max(8_192),
  headers: z
    .array(z.tuple([z.string().min(1).max(256), z.string()]))
    .max(REPLAY_LIMITS.maxHeaderCount),
  body: heldBodySchema,
  response: z
    .strictObject({
      status: z.int().min(100).max(999),
      body: heldBodySchema,
    })
    .nullable(),
});
export type MitmEntryRecord = z.infer<typeof mitmEntryRecordSchema>;

export type MitmEntryFailure =
  | "record-missing"
  | "record-outside-capture"
  | "record-too-large"
  | "record-invalid"
  | "record-sequence-mismatch"
  | "body-outside-capture"
  | "body-missing"
  | "body-too-large"
  | "body-digest-mismatch";

export type MitmEntryRead =
  | { readonly ok: true; readonly request: ReplayRequest }
  | {
      readonly ok: false;
      readonly reason: MitmEntryFailure;
      readonly detail: string;
    };

const failure = <Read extends MitmEntryRead | HeldBodyRead>(
  reason: MitmEntryFailure,
  detail: string,
): Read => ({ ok: false, reason, detail }) as Read;

/** Read the request facts and body bytes of one captured entry. */
export const readMitmEntry = async (
  captureDirectory: string,
  recordPath: string,
  sequence: number,
): Promise<MitmEntryRead> => {
  if (!isPathWithinRoot(captureDirectory, recordPath))
    return failure(
      "record-outside-capture",
      "The entry record is outside the session's capture directory",
    );
  let size: number;
  try {
    const stats = await stat(recordPath);
    if (!stats.isFile())
      return failure(
        "record-missing",
        "The entry record is not a regular file",
      );
    size = stats.size;
  } catch {
    return failure("record-missing", "The entry record no longer exists");
  }
  if (size > MITM_LIMITS.maxEntryRecordBytes)
    return failure(
      "record-too-large",
      `The entry record exceeds ${String(MITM_LIMITS.maxEntryRecordBytes)} bytes`,
    );
  let decoded: unknown;
  try {
    decoded = JSON.parse(await readFile(recordPath, "utf8"));
  } catch {
    return failure("record-invalid", "The entry record is not valid JSON");
  }
  const parsed = mitmEntryRecordSchema.safeParse(decoded);
  if (!parsed.success)
    return failure(
      "record-invalid",
      "The entry record does not match the replayable-entry contract",
    );
  const record = parsed.data;
  if (record.sequence !== sequence)
    return failure(
      "record-sequence-mismatch",
      `The record holds sequence ${String(record.sequence)}, not ${String(sequence)}`,
    );
  const body = await readHeldBody(captureDirectory, record.body);
  if (!body.ok) return body;
  return {
    ok: true,
    request: {
      method: record.method,
      url: record.url,
      headers: record.headers.map(([name, value]) => ({ name, value })),
      body: body.value,
    },
  };
};

type HeldBodyRead =
  | { readonly ok: true; readonly value: ReplayBody }
  | {
      readonly ok: false;
      readonly reason: MitmEntryFailure;
      readonly detail: string;
    };

const readHeldBody = async (
  captureDirectory: string,
  held: z.infer<typeof heldBodySchema>,
): Promise<HeldBodyRead> => {
  if (held.path === null)
    return held.bytes === 0
      ? { ok: true, value: { kind: "none" } }
      : failure(
          "body-missing",
          "The record declares body bytes but names no retained file",
        );
  if (!isPathWithinRoot(captureDirectory, held.path))
    return failure(
      "body-outside-capture",
      "The retained body is outside the session's capture directory",
    );
  if (held.bytes > REPLAY_LIMITS.maxRequestBodyBytes)
    return failure(
      "body-too-large",
      `The retained body exceeds the ${String(REPLAY_LIMITS.maxRequestBodyBytes)}-byte replay budget`,
    );
  let bytes: Buffer;
  try {
    bytes = await readFile(held.path);
  } catch {
    return failure("body-missing", "The retained body file no longer exists");
  }
  if (bytes.byteLength !== held.bytes)
    return failure(
      "body-digest-mismatch",
      "The retained body length differs from its record",
    );
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (held.sha256 !== null && digest !== held.sha256)
    return failure(
      "body-digest-mismatch",
      "The retained body digest differs from its record",
    );
  return {
    ok: true,
    value: { kind: "base64", base64: bytes.toString("base64") },
  };
};
