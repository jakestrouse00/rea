import type { LiefFormat } from "../domain/lief/liefArtifact.js";

/**
 * Facts this lane deliberately leaves to the tool that already owns them.
 *
 * The deep report returns counts and cross-format declaration facts only, so a
 * reader is told where each omitted detail lives instead of finding a second,
 * drifting copy of it here. Every counted field in the report has a row below.
 */
export const liefDelegatedFacts = (
  format: LiefFormat,
): readonly { readonly fact: string; readonly tool: string }[] => {
  const common = [
    { fact: "section and segment file layout", tool: "inspect_binary_layout" },
    {
      fact: "exported symbols and their addresses",
      tool: "inspect_native_exports",
    },
    { fact: "imported symbol names", tool: "inspect_native_exports" },
  ];
  switch (format) {
    case "elf":
      return [
        ...common,
        { fact: "ELF notes and build-id", tool: "inspect_elf_notes" },
        {
          fact: "relocations, RELR and static mitigations",
          tool: "inspect_binary_layout",
        },
        {
          fact: "program interpreter and DT_NEEDED library names",
          tool: "inspect_binary_layout",
        },
      ];
    case "pe":
      return [
        ...common,
        { fact: "PE imports and import addresses", tool: "inspect_pe_imports" },
        {
          fact: "PE TLS callbacks and load configuration",
          tool: "inspect_pe_load_config",
        },
        {
          fact: "authenticode certificate table",
          tool: "inspect_pe_certificates",
        },
      ];
    case "macho":
    case "macho-fat":
      return [
        ...common,
        {
          fact: "Mach-O header, sections and symbol table",
          tool: "inspect_macho",
        },
        { fact: "Mach-O UUID", tool: "inspect_macho" },
        {
          fact: "linked dylib names and version pairs",
          tool: "inspect_macho",
        },
        { fact: "load-command inventory", tool: "inspect_macho" },
        {
          fact: "code signatures and entitlements",
          tool: "inspect_signature",
        },
      ];
    case "pdb":
    case "unknown":
      return common;
  }
};
