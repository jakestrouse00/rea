import { executableFormatHintSchema } from "../domain/dosCom.js";
import {
  absoluteLocalPathStringSchema,
  nulFreeStringSchema,
} from "../domain/localPath.js";
import {
  binaryArchitectureSchema,
  rawBinaryEntryPointSchema,
  rawBinarySelectionError,
} from "../domain/rawBinary.js";
import { labVmCommandTimeoutField } from "../domain/vmlab/labVm.js";
import { z } from "zod";
import { analysisProviderSelectorSchema } from "./providerSelection.js";

/** Caller-supplied analysis snapshot path; must name its destination absolutely. */
const snapshotPathSchema = absoluteLocalPathStringSchema.describe(
  "Absolute local filesystem path for the analysis snapshot; relative paths are rejected.",
);

/** Caller-supplied analysis target path; must name the target absolutely. */
const binaryTargetPathSchema = absoluteLocalPathStringSchema.describe(
  "Absolute local filesystem path for the analysis target; relative paths are rejected.",
);

/** Input contract for opening a target with an optional staged snapshot. */
export const openBinaryInputSchema = z
  .strictObject({
    path: binaryTargetPathSchema,
    format: executableFormatHintSchema
      .optional()
      .describe(
        "Explicit interpretation: dos-com or raw-binary (headerless), or gamecube-dol (GameCube/Wii DOL, never auto-detected). Omission preserves header-based detection.",
      ),
    architecture: binaryArchitectureSchema
      .optional()
      .describe(
        "Caller-supplied CPU family. Required with format=raw-binary; rejected otherwise. format=gamecube-dol takes powerpc from the header, so it must be omitted.",
      ),
    entry_point: rawBinaryEntryPointSchema
      .optional()
      .describe(
        "Caller-supplied load and entry address (0xhex). File offset 0 is mapped here. Required with format=raw-binary; rejected otherwise. Optional with format=gamecube-dol; must equal the DOL header entry.",
      ),
    provider_id: analysisProviderSelectorSchema.optional(),
    snapshot_path: snapshotPathSchema.optional(),
  })
  .superRefine((value, context) => {
    const pairing = rawBinarySelectionError({
      ...(value.format === undefined ? {} : { format: value.format }),
      ...(value.architecture === undefined
        ? {}
        : { architecture: value.architecture }),
      ...(value.entry_point === undefined
        ? {}
        : { entryPoint: value.entry_point }),
    });
    if (pairing === undefined) return;
    context.addIssue({
      code: "custom",
      path:
        value.format === "raw-binary"
          ? value.architecture === undefined
            ? ["architecture"]
            : ["entry_point"]
          : value.architecture === undefined
            ? ["entry_point"]
            : ["architecture"],
      message: pairing,
    });
  });

/** Open only app resources when no declared executable is available. */
export const openBundleResourcesInputSchema = z.strictObject({
  path: binaryTargetPathSchema,
});

/** Input contract for closing a target after an optional atomic snapshot. */
export const closeBinaryInputSchema = z.strictObject({
  snapshot_path: snapshotPathSchema.optional(),
  overwrite: z.boolean().default(false),
});

/** Session identity issued by `start_lab_vm`; not a binary target identity. */
export const labVmSessionIdSchema = z.string().uuid();

/** Start one lab VM on the caller's workspace mount. */
export const startLabVmInputSchema = z.strictObject({
  workspace_path: absoluteLocalPathStringSchema.describe(
    "Existing absolute host directory mounted read-write at /workspace in the guest; artifacts the guest writes there are visible to the caller after the VM stops.",
  ),
});

/** Run one shell command line through the guest exec channel. */
export const runLabVmCommandInputSchema = z.strictObject({
  session_id: labVmSessionIdSchema,
  command: nulFreeStringSchema
    .min(1)
    .describe(
      "Command line passed to /bin/sh -lc inside the guest, with the workspace as the working directory.",
    ),
  command_timeout_ms: labVmCommandTimeoutField,
});

/** Stop and remove one lab VM by its issued session identity. */
export const stopLabVmInputSchema = z.strictObject({
  session_id: labVmSessionIdSchema,
});
