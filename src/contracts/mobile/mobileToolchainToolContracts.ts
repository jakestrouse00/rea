import {
  mobileToolchainInputSchemas,
  mobileToolchainResultSchemas,
} from "../../domain/mobile/mobileToolchain.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/**
 * Caller-supplied mobile lanes: objection recipes over an attached app,
 * androguard structure and structure-rule scanning over an APK, and the
 * iLEAPP/ALEAPP TSV report lane. Every operation is a subprocess over a
 * caller-selected launcher; none is installed, linked, or upgraded by REA.
 */
export const MOBILE_TOOLCHAIN_TOOL_CONTRACTS = [
  {
    name: "run_objection_recipe",
    ...toolContractMetadata("run_objection_recipe"),
    kind: "mobile-toolchain-provider",
    description:
      "Run one whitelisted objection recipe against a caller-named attached application and return its structure only. Recipes are read-only inventories (environment key names, loaded classes, activities, keystore aliases); free-form commands are never assembled, and the tool's printed values, payloads, and free text are dropped at this boundary. objection is GPL-3.0 upstream and runs as a subprocess REA never links or installs; the recipe attaches to the app, which can change its debugger and instrumentation state.",
    inputSchema: mobileToolchainInputSchemas.run_objection_recipe,
    outputSchema: evidenceResultOf(
      mobileToolchainResultSchemas.run_objection_recipe,
    ),
    examples: [
      {
        title: "List loaded classes in an attached app",
        input: { recipe: "list-loaded-classes", target: "com.example.app" },
      },
    ],
  },
  {
    name: "analyze_apk_structure",
    ...toolContractMetadata("analyze_apk_structure"),
    kind: "mobile-toolchain-provider",
    description:
      "Read one APK's declared structure through caller-supplied androguard 5.x: package identity, SDK bounds, declared permissions, declared components with their exported flag, native libraries, and a bounded class cross-reference sample. Parsing is static and the application is never executed. REA reads and digests the APK and never installs Python packages.",
    inputSchema: mobileToolchainInputSchemas.analyze_apk_structure,
    outputSchema: evidenceResultOf(
      mobileToolchainResultSchemas.analyze_apk_structure,
    ),
    examples: [
      {
        title: "Inspect an APK's components and permissions",
        input: { apk_path: "/evidence/app.apk" },
      },
    ],
  },
  {
    name: "scan_apk_vulnerabilities",
    ...toolContractMetadata("scan_apk_vulnerabilities"),
    kind: "mobile-toolchain-provider",
    description:
      "Evaluate this release's fixed structure rules over one APK's declared manifest facts and report each finding as a stable rule id, a severity, and the location it was observed at. Output stays value-free: no matched value, exploit path, or rule text. This is a structure review over static facts, not a penetration test, and an unlisted rule is not proof a weakness is absent.",
    inputSchema: mobileToolchainInputSchemas.scan_apk_vulnerabilities,
    outputSchema: evidenceResultOf(
      mobileToolchainResultSchemas.scan_apk_vulnerabilities,
    ),
    examples: [
      {
        title: "Scan one APK's declared structure",
        input: { apk_path: "/evidence/app.apk" },
      },
    ],
  },
  {
    name: "run_mobile_forensics_report",
    ...toolContractMetadata("run_mobile_forensics_report"),
    kind: "mobile-toolchain-provider",
    description:
      "Run a caller-supplied iLEAPP (iOS) or ALEAPP (Android) launcher over a caller-selected extraction and parse the TSV tables it writes into the caller-owned output directory. Tables are reported with their columns, bounded rows, digest and byte count; cells are kept as written within a per-cell bound. The tool decides what it recognizes, so an absent table is not evidence of an absent artifact.",
    inputSchema: mobileToolchainInputSchemas.run_mobile_forensics_report,
    outputSchema: evidenceResultOf(
      mobileToolchainResultSchemas.run_mobile_forensics_report,
    ),
    examples: [
      {
        title: "Parse an iOS extraction into tables",
        input: {
          input_path: "/evidence/ios-extraction",
          platform: "ios",
          output_directory: "/evidence/ileapp-out",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
