/** Deep-analysis providers whose readiness can be selected explicitly by doctor. */
export const DOCTOR_PROVIDER_IDS = [
  "hopper",
  "ghidra",
  "ida",
  "jadx",
  "kuna",
  "idevice",
  "discovery",
  "llvm-pdbutil",
  "windows-artifacts",
  "frida",
] as const;
