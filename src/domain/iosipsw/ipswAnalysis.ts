import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";

/** Maximum images one extraction request may publish. */
export const MAX_IPSW_DSC_IMAGES = 256;

/** Maximum classes one class-metadata request may report. */
export const MAX_IPSW_CLASSES = 5_000;

/**
 * Shared-cache image selectors as the cache manifest reports them
 * (`/System/Library/Frameworks/UIKit.framework/UIKit` or `UIKit`). The pattern
 * keeps arguments free of whitespace and quotes; argv is positional in the
 * provider, so this is admission hygiene rather than injection defense.
 */
const dscImageSelectorSchema = z
  .string()
  .min(1)
  .max(512)
  .regex(
    /^[^\x00\s"']+$/u,
    "Image selectors cannot contain whitespace, quotes, or NUL",
  );

const ipswClientSchema = z.strictObject({
  command: z.string().min(1),
  version: z.string().nullable(),
});

const coverageSchema = z.enum(["complete", "partial"]);

/**
 * Caller intent for iOS static-image inspection through a caller-supplied
 * blacktop/ipsw CLI.
 *
 * REA never downloads firmware, shared caches, or the ipsw binary; every
 * operation reads archives and images the caller already holds.
 */
export const ipswInputSchemas = {
  inspect_ipsw: z.strictObject({
    path: absoluteLocalPathStringSchema.describe(
      "Absolute path to a local IPSW, OTA, or .ipsw.zip archive",
    ),
  }),
  extract_dyld_shared_cache_images: z.strictObject({
    cache: absoluteLocalPathStringSchema
      .optional()
      .describe(
        "Absolute path to a dyld shared cache file or its containing directory; defaults to REA_IPSW_DSC_PATH, then to the macOS cryptex directory read-only",
      ),
    output_directory: absoluteLocalPathStringSchema.describe(
      "Local directory that receives one new subdirectory of extracted images",
    ),
    images: z
      .array(dscImageSelectorSchema)
      .min(1)
      .max(MAX_IPSW_DSC_IMAGES)
      .optional()
      .describe(
        "Image names or paths to extract; every manifest image is selected up to max_images when omitted",
      ),
    max_images: z
      .int()
      .min(1)
      .max(MAX_IPSW_DSC_IMAGES)
      .default(32)
      .describe("Upper bound on images extracted and published"),
  }),
  dump_ios_class_metadata: z.strictObject({
    path: absoluteLocalPathStringSchema.describe(
      "Absolute path to a Mach-O image or shared-cache member",
    ),
    family: z
      .enum(["objc", "swift"])
      .default("objc")
      .describe(
        "Metadata family to dump: Objective-C class tables or Swift types",
      ),
    max_classes: z
      .int()
      .min(1)
      .max(MAX_IPSW_CLASSES)
      .default(500)
      .describe("Upper bound on reported classes or types"),
  }),
  symbolicate_ios_crash: z.strictObject({
    crash: absoluteLocalPathStringSchema.describe(
      "Absolute path to a crash report already collected from the device",
    ),
    cache: absoluteLocalPathStringSchema
      .optional()
      .describe(
        "Absolute path to the matching dyld shared cache; defaults to REA_IPSW_DSC_PATH",
      ),
  }),
  inspect_macho_entitlements: z.strictObject({
    path: absoluteLocalPathStringSchema.describe(
      "Absolute path to a Mach-O image whose entitlements and load commands are read",
    ),
  }),
} as const;

/** Supported ipsw-backed operations. */
export type IpswOperation = keyof typeof ipswInputSchemas;

/** Validated ipsw requests carry their selected operation. */
export type IpswRequest = {
  [Name in IpswOperation]: {
    operation: Name;
    input: z.infer<(typeof ipswInputSchemas)[Name]>;
  };
}[IpswOperation];

/** Validate operation and input together so their types remain correlated. */
export const ipswRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("inspect_ipsw"),
    input: ipswInputSchemas.inspect_ipsw,
  }),
  z.strictObject({
    operation: z.literal("extract_dyld_shared_cache_images"),
    input: ipswInputSchemas.extract_dyld_shared_cache_images,
  }),
  z.strictObject({
    operation: z.literal("dump_ios_class_metadata"),
    input: ipswInputSchemas.dump_ios_class_metadata,
  }),
  z.strictObject({
    operation: z.literal("symbolicate_ios_crash"),
    input: ipswInputSchemas.symbolicate_ios_crash,
  }),
  z.strictObject({
    operation: z.literal("inspect_macho_entitlements"),
    input: ipswInputSchemas.inspect_macho_entitlements,
  }),
]);

const ipswPartitionSchema = z.strictObject({
  name: z.string().min(1),
  bytes: z.int().nonnegative().nullable(),
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable(),
});

const dscImageSchema = z.strictObject({
  name: z.string().min(1),
  path: z.string().min(1).nullable(),
  address: z.string().min(1).nullable(),
  bytes: z.int().nonnegative().nullable(),
});

const publishedImageSchema = z.strictObject({
  relative_path: z.string().min(1),
  bytes: z.int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
});

const classMethodSchema = z.strictObject({
  name: z.string().min(1),
  kind: z.enum(["instance", "class", "unknown"]),
  return_type: z.string().nullable(),
  parameter_types: z.array(z.string()),
});

const classIvarSchema = z.strictObject({
  name: z.string().min(1),
  type: z.string().nullable(),
  offset: z.int().nonnegative().nullable(),
});

const classEntrySchema = z.strictObject({
  name: z.string().min(1),
  superclass: z.string().nullable(),
  protocols: z.array(z.string()),
  methods: z.array(classMethodSchema),
  ivars: z.array(classIvarSchema),
});

const crashFrameSchema = z.strictObject({
  index: z.int().nonnegative(),
  image: z.string().nullable(),
  symbol: z.string().nullable(),
  address: z.string().nullable(),
  offset: z.string().nullable(),
  source_file: z.string().nullable(),
  source_line: z.int().nonnegative().nullable(),
});

const crashThreadSchema = z.strictObject({
  id: z.int().nullable(),
  name: z.string().nullable(),
  crashed: z.boolean(),
  frames: z.array(crashFrameSchema),
});

const entitlementSchema = z.strictObject({
  key: z.string().min(1),
  value_kind: z.enum([
    "string",
    "integer",
    "boolean",
    "array",
    "dictionary",
    "data",
    "unknown",
  ]),
});

const loadCommandSchema = z.strictObject({
  command: z.string().min(1),
  size: z.int().nonnegative().nullable(),
  offset: z.int().nonnegative().nullable(),
});

/** Provider-returned results, strict enough to reject adapter drift. */
export const ipswResultSchemas = {
  inspect_ipsw: z.strictObject({
    client: ipswClientSchema,
    path: z.string().min(1),
    bytes: z.int().nonnegative(),
    product: z.string().nullable(),
    version: z.string().nullable(),
    build: z.string().nullable(),
    build_train: z.string().nullable(),
    device_identifiers: z.array(z.string().min(1)),
    partitions: z.array(ipswPartitionSchema),
    partition_count: z.int().nonnegative(),
    coverage: coverageSchema,
  }),
  extract_dyld_shared_cache_images: z.strictObject({
    client: ipswClientSchema,
    cache_path: z.string().min(1),
    cache_bytes: z.int().nonnegative(),
    architecture: z.string().nullable(),
    image_count: z.int().nonnegative(),
    manifest: z.array(dscImageSchema),
    manifest_truncated: z.boolean(),
    requested: z.array(z.string().min(1)),
    missing: z.array(z.string().min(1)),
    output_directory: z.string().min(1),
    published: z.array(publishedImageSchema),
    published_truncated: z.boolean(),
    coverage: coverageSchema,
  }),
  dump_ios_class_metadata: z.strictObject({
    client: ipswClientSchema,
    path: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    bytes: z.int().nonnegative(),
    family: z.enum(["objc", "swift"]),
    classes: z.array(classEntrySchema),
    class_count: z.int().nonnegative(),
    method_count: z.int().nonnegative(),
    ivar_count: z.int().nonnegative(),
    truncated: z.boolean(),
    unparsed_entries: z.int().nonnegative(),
    coverage: coverageSchema,
  }),
  symbolicate_ios_crash: z.strictObject({
    client: ipswClientSchema,
    crash_path: z.string().min(1),
    crash_bytes: z.int().nonnegative(),
    crash_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    cache_path: z.string().min(1).nullable(),
    threads: z.array(crashThreadSchema),
    frame_count: z.int().nonnegative(),
    unparsed_entries: z.int().nonnegative(),
    coverage: coverageSchema,
  }),
  inspect_macho_entitlements: z.strictObject({
    client: ipswClientSchema,
    path: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    bytes: z.int().nonnegative(),
    architecture: z.string().nullable(),
    file_type: z.string().nullable(),
    entitlements: z.array(entitlementSchema),
    entitlement_count: z.int().nonnegative(),
    load_commands: z.array(loadCommandSchema),
    load_command_count: z.int().nonnegative(),
    unparsed_entries: z.int().nonnegative(),
    coverage: coverageSchema,
  }),
} as const;
