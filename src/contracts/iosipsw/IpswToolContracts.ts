import {
  ipswInputSchemas,
  ipswResultSchemas,
} from "../../domain/iosipsw/ipswAnalysis.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/**
 * iOS static-image inspection over a caller-supplied blacktop/ipsw CLI.
 *
 * Every operation reads an archive, shared cache, or Mach-O image already on
 * the caller's host. REA does not fetch firmware or shared caches.
 */
export const IPSW_TOOL_CONTRACTS = [
  {
    name: "inspect_ipsw",
    ...toolContractMetadata("inspect_ipsw"),
    description:
      "Inventory a local IPSW or OTA archive: product identity, iOS version, build train, device identifiers, and partition rows with sizes and any reported SHA-256. Unrecognized entries are counted rather than guessed. Select the CLI with REA_IPSW_COMMAND; REA neither fetches firmware images nor reads a target.",
    kind: "ipsw-provider",
    inputSchema: ipswInputSchemas.inspect_ipsw,
    outputSchema: evidenceResultOf(ipswResultSchemas.inspect_ipsw),
    examples: [
      {
        title: "Inventory an IPSW",
        input: { path: "/Users/analyst/IPSW/iPhone15,2_18.3.1_22D72.ipsw" },
      },
    ],
  },
  {
    name: "extract_dyld_shared_cache_images",
    ...toolContractMetadata("extract_dyld_shared_cache_images"),
    description:
      "List a dyld shared cache's images with load addresses and sizes, then extract the selected images into one new subdirectory of the caller's output directory. Every published file carries its SHA-256; selectors the manifest does not contain are reported as missing rather than substituted. Select the CLI with REA_IPSW_COMMAND and a cache with REA_IPSW_DSC_PATH or the request.",
    kind: "ipsw-provider",
    inputSchema: ipswInputSchemas.extract_dyld_shared_cache_images,
    outputSchema: evidenceResultOf(
      ipswResultSchemas.extract_dyld_shared_cache_images,
    ),
    examples: [
      {
        title: "Extract two cache images",
        input: {
          output_directory: "/tmp/rea-dsc",
          images: ["UIKit", "Foundation"],
        },
      },
    ],
  },
  {
    name: "dump_ios_class_metadata",
    ...toolContractMetadata("dump_ios_class_metadata"),
    description:
      "Report Objective-C or Swift type tables from one Mach-O image: class names, superclasses, protocols, method signatures, and ivar types. Values are structural, so field contents and default values are absent. Bounded by max_classes; the image is digested before and after the read.",
    kind: "ipsw-provider",
    inputSchema: ipswInputSchemas.dump_ios_class_metadata,
    outputSchema: evidenceResultOf(ipswResultSchemas.dump_ios_class_metadata),
    examples: [
      {
        title: "Dump Objective-C classes",
        input: { path: "/tmp/rea-dsc/images/UIKit", family: "objc" },
      },
    ],
  },
  {
    name: "symbolicate_ios_crash",
    ...toolContractMetadata("symbolicate_ios_crash"),
    description:
      "Symbolicate a crash report already collected from the device against a dyld shared cache, reporting each thread's frames with image, symbol, address, offset, and source location when the report carries one. Frames the symbolizer leaves unresolved stay null. Select the cache with REA_IPSW_DSC_PATH or the request.",
    kind: "ipsw-provider",
    inputSchema: ipswInputSchemas.symbolicate_ios_crash,
    outputSchema: evidenceResultOf(ipswResultSchemas.symbolicate_ios_crash),
    examples: [
      {
        title: "Symbolicate a crash report",
        input: { crash: "/tmp/rea-captures/App-2026-10-19-121500.ips" },
      },
    ],
  },
  {
    name: "inspect_macho_entitlements",
    ...toolContractMetadata("inspect_macho_entitlements"),
    description:
      "Read a Mach-O image's code-signing entitlements and load commands: entitlement keys with their value kinds, and each load command with its size and file offset. Entitlement values, including team identifiers, stay out of Evidence. Bounded to the image's own tables.",
    kind: "ipsw-provider",
    inputSchema: ipswInputSchemas.inspect_macho_entitlements,
    outputSchema: evidenceResultOf(
      ipswResultSchemas.inspect_macho_entitlements,
    ),
    examples: [
      {
        title: "Read entitlements and load commands",
        input: { path: "/tmp/rea-dsc/images/UIKit" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
