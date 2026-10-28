import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { z } from "zod";

import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import type {
  ProtocolMessageClass,
  ProtocolModel,
} from "../domain/protolearn/protocolModel.js";
import { protocolModelSchema } from "../domain/protolearn/protocolModel.js";
import { payloadDigest } from "../domain/protolearn/protocolMessage.js";
import { PROTOLEARN_LIMITS } from "../domain/protolearn/protolearnLimits.js";

export const PROTOCOL_MODEL_STORE_CONTRACT = "rea.protolearn.model-store/v1";
export const PROTOCOL_MODEL_STORE_MANIFEST = "manifest.json";
export const PROTOCOL_MODEL_STORE_MODEL_FILE = "model.json";

/** Bounds the model file this lane reads back, before it parses any of it. */
export const PROTOCOL_MODEL_FILE_MAX_BYTES = 4 * 1024 * 1024;

const manifestSchema = z.strictObject({
  contract: z.literal(PROTOCOL_MODEL_STORE_CONTRACT),
  model_file: z.string().regex(/^[a-z0-9._\x2d]{1,64}$/u),
  class_count: z.int().nonnegative(),
  files: z.array(
    z.strictObject({
      class_id: z.string().regex(/^c[0-9]{1,3}$/u),
      file: z.string().regex(/^[a-z0-9._\x2d]{1,64}$/u),
      bytes: z.int().positive().max(PROTOLEARN_LIMITS.maxTemplateBytes),
      sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    }),
  ),
});

const templateEntries = (classes: readonly ProtocolMessageClass[]) =>
  classes.flatMap((messageClass) =>
    messageClass.template === null
      ? []
      : [{ classId: messageClass.class_id, template: messageClass.template }],
  );

const assertActive = (operation: string, signal?: AbortSignal): void => {
  if (signal?.aborted)
    throw new AnalysisCancelledError(operation, { cause: signal.reason });
};

const writePrivate = async (
  path: string,
  value: string | Buffer,
): Promise<void> => {
  await writeFile(path, value, { mode: 0o600 });
  await chmod(path, 0o600);
};

/**
 * Write one model store: the model file, one exemplar payload per class that
 * has one, and a manifest of every class digest.
 *
 * Files are created 0600, so a later probe or export reads exactly the model
 * the caller learned rather than a copy that drifted.
 */
export const writeProtocolModelStore = async (options: {
  readonly operation: string;
  readonly directory: string;
  readonly model: ProtocolModel;
  readonly templates: ReadonlyMap<string, Buffer>;
  readonly signal?: AbortSignal;
}): Promise<void> => {
  const { operation, directory, model, templates, signal } = options;
  assertActive(operation, signal);
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const files: {
      class_id: string;
      file: string;
      bytes: number;
      sha256: string;
    }[] = [];
    for (const { classId, template } of templateEntries(model.classes)) {
      assertActive(operation, signal);
      const bytes = templates.get(classId);
      if (bytes === undefined) continue;
      if (bytes.length > PROTOLEARN_LIMITS.maxTemplateBytes)
        throw new AnalysisOutputError(
          operation,
          `Class ${classId} template exceeds the store's byte bound`,
        );
      await writePrivate(join(directory, template.file), bytes);
      files.push({
        class_id: classId,
        file: template.file,
        bytes: bytes.length,
        sha256: payloadDigest(bytes),
      });
    }
    await writePrivate(
      join(directory, PROTOCOL_MODEL_STORE_MODEL_FILE),
      `${JSON.stringify(model, null, 2)}\n`,
    );
    await writePrivate(
      join(directory, PROTOCOL_MODEL_STORE_MANIFEST),
      `${JSON.stringify(
        {
          contract: PROTOCOL_MODEL_STORE_CONTRACT,
          model_file: PROTOCOL_MODEL_STORE_MODEL_FILE,
          class_count: files.length,
          files,
        },
        null,
        2,
      )}\n`,
    );
  } catch (cause: unknown) {
    if (
      cause instanceof AnalysisOutputError ||
      cause instanceof AnalysisCancelledError
    )
      throw cause;
    throw new AnalysisOutputError(
      operation,
      `The protocol model store ${directory} could not be written: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
};

/**
 * Read one model back from its store. The file must be the store's own model
 * file and must satisfy the model contract this release writes.
 */
export const readProtocolModelFile = async (options: {
  readonly operation: string;
  readonly path: string;
  readonly signal?: AbortSignal;
}): Promise<ProtocolModel> => {
  const { operation, path, signal } = options;
  const refuse = (message: string, cause?: unknown): never => {
    throw new AnalysisInputError(
      operation,
      cause === undefined ? {} : { cause },
      [{ path: ["model_path"], reason: "invalid_value", message }],
    );
  };
  assertActive(operation, signal);
  let bytes: Buffer;
  try {
    bytes = await readFile(path, { signal });
  } catch (cause: unknown) {
    return refuse(
      `The model file ${path} could not be read: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }
  if (bytes.length > PROTOCOL_MODEL_FILE_MAX_BYTES)
    throw new AnalysisResourceConstraintError(
      operation,
      "memory",
      `The model file ${path} exceeds ${String(PROTOCOL_MODEL_FILE_MAX_BYTES)} bytes`,
      { max_bytes: PROTOCOL_MODEL_FILE_MAX_BYTES, bytes: bytes.length },
    );
  let raw: unknown;
  try {
    raw = JSON.parse(bytes.toString("utf8"));
  } catch (cause: unknown) {
    return refuse(
      `The model file ${path} is not JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }
  const parsed = protocolModelSchema.safeParse(raw);
  if (!parsed.success)
    return refuse(
      `The model file ${path} is not a protocol model this release reads`,
      parsed.error,
    );
  if (
    parsed.data.model_store === null ||
    parsed.data.model_store.model_file !== basename(path)
  )
    return refuse(
      `The model file ${path} is not the model file of its own store`,
    );
  return parsed.data;
};

/**
 * Read one store's exemplars for a model, verifying the manifest contract,
 * every class digest, and every byte count before any seed is built.
 */
export const readProtocolModelTemplates = async (options: {
  readonly operation: string;
  readonly model: ProtocolModel;
  readonly signal?: AbortSignal;
}): Promise<ReadonlyMap<string, Buffer>> => {
  const { operation, model, signal } = options;
  const refuse = (message: string, cause?: unknown): never => {
    throw new AnalysisInputError(
      operation,
      cause === undefined ? {} : { cause },
      [{ path: ["model_path"], reason: "invalid_value", message }],
    );
  };
  assertActive(operation, signal);
  if (model.model_store === null)
    return refuse(
      "The model carries no store, so it has no exemplars to build seeds from; learn it again with model_directory set",
    );
  const directory = model.model_store.directory;
  let text: string;
  try {
    text = await readFile(
      join(directory, PROTOCOL_MODEL_STORE_MANIFEST),
      "utf8",
    );
  } catch (cause: unknown) {
    return refuse(
      `The model store ${directory} has no readable ${PROTOCOL_MODEL_STORE_MANIFEST}`,
      cause,
    );
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (cause: unknown) {
    return refuse(
      `The model store manifest is not JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
      cause,
    );
  }
  const manifest = manifestSchema.safeParse(raw);
  if (!manifest.success)
    return refuse(
      "The model store manifest is not a protocol model store this release reads",
      manifest.error,
    );
  const templates = new Map<string, Buffer>();
  for (const { classId, template } of templateEntries(model.classes)) {
    assertActive(operation, signal);
    const entry = manifest.data.files.find(
      ({ class_id }) => class_id === classId,
    );
    if (
      entry === undefined ||
      entry.file !== template.file ||
      entry.bytes !== template.bytes ||
      entry.sha256 !== template.sha256
    )
      return refuse(
        `The model store does not hold the class ${classId} exemplar this model names`,
      );
    let bytes: Buffer;
    try {
      bytes = await readFile(join(directory, entry.file));
    } catch (cause: unknown) {
      return refuse(
        `Class ${classId} exemplar ${entry.file} could not be read`,
        cause,
      );
    }
    if (bytes.length !== entry.bytes || payloadDigest(bytes) !== entry.sha256)
      return refuse(
        `Class ${classId} exemplar ${entry.file} does not match the digest this model names`,
      );
    templates.set(classId, bytes);
  }
  return templates;
};
