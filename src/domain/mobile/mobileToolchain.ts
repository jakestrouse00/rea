import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";
import { digestSchema } from "../digests.js";

/** Whitelisted objection recipes: name, argv, and the rows they may expose. */
export const objectionRecipeIds = [
  "app-environment-names",
  "list-loaded-classes",
  "list-activities",
  "keystore-aliases",
] as const;

export type ObjectionRecipeId = (typeof objectionRecipeIds)[number];

export const objectionRecipeIdSchema = z.enum(objectionRecipeIds);

/**
 * One objection recipe's bounded structure. Text the tool printed is reduced
 * to row names and per-recipe counters at the REA boundary; environment
 * values, payloads, and free text never reach Evidence.
 */
const objectionRecipeResult = z.strictObject({
  client: z.strictObject({
    command: z.string().min(1),
    version: z.string().min(1).nullable(),
  }),
  target: z.strictObject({
    kind: z.enum(["bundle", "process"]),
    value: z.string().min(1),
    serial: z.string().min(1).nullable(),
  }),
  recipe: objectionRecipeIdSchema,
  recipe_argv: z.array(z.string().min(1)),
  rows: z.array(z.string().min(1)),
  row_count: z.number().int().nonnegative(),
  rows_truncated: z.boolean(),
  dropped_line_count: z.number().int().nonnegative(),
  unparsed_line_count: z.number().int().nonnegative(),
  elapsed_ms: z.number().int().nonnegative(),
  exit_code: z.number().int().nullable(),
  coverage: z.enum(["complete", "partial"]),
});

/** Android APK structure as androguard v5 reported it. */
const apkComponent = z.strictObject({
  kind: z.enum(["activity", "service", "receiver", "provider"]),
  name: z.string().min(1),
  exported: z.boolean().nullable(),
});

const apkCrossReference = z.strictObject({
  from: z.string().min(1),
  to: z.string().min(1),
  count: z.number().int().positive(),
});

const apkStructureResult = z.strictObject({
  client: z.strictObject({
    python: z.string().min(1),
    androguard_version: z.string().min(1).nullable(),
  }),
  apk: z.strictObject({
    path: absoluteLocalPathStringSchema,
    sha256: digestSchema,
    bytes: z.number().int().positive(),
  }),
  package: z.string().min(1).nullable(),
  app_name: z.string().min(1).nullable(),
  version_name: z.string().min(1).nullable(),
  version_code: z.string().min(1).nullable(),
  min_sdk: z.number().int().nonnegative().nullable(),
  target_sdk: z.number().int().nonnegative().nullable(),
  permissions: z.array(z.string().min(1)),
  components: z.array(apkComponent),
  component_count: z.number().int().nonnegative(),
  components_truncated: z.boolean(),
  cross_references: z.array(apkCrossReference),
  cross_reference_count: z.number().int().nonnegative(),
  cross_references_truncated: z.boolean(),
  native_libraries: z.array(z.string().min(1)),
  unparsed_facts: z.number().int().nonnegative(),
  warnings: z.array(z.string().min(1)),
  elapsed_ms: z.number().int().nonnegative(),
  coverage: z.enum(["complete", "partial"]),
});

/** One structure finding: a stable id and where it was observed. */
const apkVulnerabilityFinding = z.strictObject({
  id: z.string().min(1),
  severity: z.enum(["info", "warning", "high"]),
  location: z.string().min(1),
});

const apkVulnerabilityResult = z.strictObject({
  client: z.strictObject({
    python: z.string().min(1),
    androguard_version: z.string().min(1).nullable(),
  }),
  apk: z.strictObject({
    path: absoluteLocalPathStringSchema,
    sha256: digestSchema,
    bytes: z.number().int().positive(),
  }),
  findings: z.array(apkVulnerabilityFinding),
  finding_count: z.number().int().nonnegative(),
  findings_truncated: z.boolean(),
  elapsed_ms: z.number().int().nonnegative(),
  coverage: z.enum(["complete", "partial"]),
});

/** One parsed iLEAPP/ALEAPP TSV table. */
const forensicTable = z.strictObject({
  name: z.string().min(1),
  sha256: digestSchema,
  bytes: z.number().int().nonnegative(),
  columns: z.array(z.string().min(1)),
  rows: z.array(z.array(z.string())),
  row_count: z.number().int().nonnegative(),
  retained_rows: z.number().int().nonnegative(),
  truncated: z.boolean(),
});

const mobileForensicsResult = z.strictObject({
  client: z.strictObject({
    command: z.string().min(1),
    platform: z.enum(["ios", "android"]),
  }),
  input: z.strictObject({
    path: absoluteLocalPathStringSchema,
    kind: z.enum(["file", "directory"]),
  }),
  output_directory: absoluteLocalPathStringSchema,
  tables: z.array(forensicTable),
  table_count: z.number().int().nonnegative(),
  total_rows: z.number().int().nonnegative(),
  unparsed_files: z.array(z.string().min(1)),
  tables_truncated: z.boolean(),
  exit_code: z.number().int().nullable(),
  elapsed_ms: z.number().int().nonnegative(),
  coverage: z.enum(["complete", "partial"]),
});

/** Caller-visible inputs for the mobile toolchain tools. */
export const mobileToolchainInputSchemas = {
  run_objection_recipe: z.strictObject({
    recipe: objectionRecipeIdSchema.describe(
      "One whitelisted recipe; free-form objection commands are not accepted",
    ),
    target_kind: z
      .enum(["bundle", "process"])
      .default("bundle")
      .describe(
        "Whether the target value is a bundle identifier or a process name",
      ),
    target: z
      .string()
      .min(1)
      .max(256)
      .describe(
        "Bundle identifier, application name, or process name objection attaches to",
      ),
    serial: z
      .string()
      .min(1)
      .max(128)
      .optional()
      .describe(
        "Optional adb device serial when more than one device is attached",
      ),
    max_rows: z
      .number()
      .int()
      .min(1)
      .max(500)
      .default(200)
      .describe("Maximum structural rows retained from the recipe's output"),
    timeout_ms: z
      .number()
      .int()
      .min(5_000)
      .max(120_000)
      .default(60_000)
      .describe("Deadline for one objection invocation"),
  }),
  analyze_apk_structure: z.strictObject({
    apk_path: absoluteLocalPathStringSchema.describe(
      "Absolute path of the APK to inspect; REA reads and digests it without unpacking",
    ),
    max_components: z
      .number()
      .int()
      .min(1)
      .max(2_000)
      .default(500)
      .describe("Maximum declared components retained"),
    max_cross_references: z
      .number()
      .int()
      .min(1)
      .max(2_000)
      .default(500)
      .describe("Maximum class cross-reference rows retained"),
  }),
  scan_apk_vulnerabilities: z.strictObject({
    apk_path: absoluteLocalPathStringSchema.describe(
      "Absolute path of the APK to inspect; REA reads and digests it without unpacking",
    ),
    max_findings: z
      .number()
      .int()
      .min(1)
      .max(1_000)
      .default(200)
      .describe("Maximum findings retained"),
  }),
  run_mobile_forensics_report: z.strictObject({
    input_path: absoluteLocalPathStringSchema.describe(
      "Absolute path of the evidence iLEAPP/ALEAPP reads: an iOS backup, a full file-system extraction, or an Android image directory",
    ),
    platform: z
      .enum(["ios", "android"])
      .default("ios")
      .describe("Which artifact family the selected tool run targets"),
    output_directory: absoluteLocalPathStringSchema.describe(
      "Caller-selected existing directory where the tool writes its TSV tables; REA never creates, replaces, or deletes it",
    ),
    max_tables: z
      .number()
      .int()
      .min(1)
      .max(128)
      .default(48)
      .describe("Maximum TSV tables retained"),
    max_rows_per_table: z
      .number()
      .int()
      .min(1)
      .max(2_000)
      .default(200)
      .describe("Maximum rows retained per table"),
    timeout_ms: z
      .number()
      .int()
      .min(30_000)
      .max(900_000)
      .default(300_000)
      .describe("Deadline for one report run"),
  }),
} as const;

export type MobileToolchainOperation = keyof typeof mobileToolchainInputSchemas;

export const mobileToolchainRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("run_objection_recipe"),
    input: mobileToolchainInputSchemas.run_objection_recipe,
  }),
  z.strictObject({
    operation: z.literal("analyze_apk_structure"),
    input: mobileToolchainInputSchemas.analyze_apk_structure,
  }),
  z.strictObject({
    operation: z.literal("scan_apk_vulnerabilities"),
    input: mobileToolchainInputSchemas.scan_apk_vulnerabilities,
  }),
  z.strictObject({
    operation: z.literal("run_mobile_forensics_report"),
    input: mobileToolchainInputSchemas.run_mobile_forensics_report,
  }),
]);

export type MobileToolchainRequest = z.infer<
  typeof mobileToolchainRequestSchema
>;

export const mobileToolchainResultSchemas = {
  run_objection_recipe: objectionRecipeResult,
  analyze_apk_structure: apkStructureResult,
  scan_apk_vulnerabilities: apkVulnerabilityResult,
  run_mobile_forensics_report: mobileForensicsResult,
} as const;
