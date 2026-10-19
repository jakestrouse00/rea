import type { DoctorProviderInspection } from "../application/Doctor.js";
import { MINIDUMP_INPUT_BYTES } from "./WindowsMinidump.js";

/**
 * One bundled offline-parser doctor identity: the minidump and WER readers
 * need no host tooling, so the only check reports the bundled lane itself.
 */
export const WINDOWS_ARTIFACTS_PROVIDER_ID = "windows-artifacts";

/** Project the bundled offline Windows-artifact lanes into the doctor contract. */
export const inspectWindowsArtifacts =
  async (): Promise<DoctorProviderInspection> => ({
    id: WINDOWS_ARTIFACTS_PROVIDER_ID,
    configured: true,
    available: true,
    providerVersion: "1",
    registrationEnvironment: {},
    checks: [
      {
        name: "offline-parser",
        ok: true,
        code: null,
        detail:
          "Bundled Windows minidump (.dmp) and WER (.wer) structural readers are available offline on every supported host; no target execution and no toolchain installation are required. PDB symbol inspection is a separate llvm-pdbutil lane with its own doctor entry.",
        remediation: null,
        classification: "unknown",
        details: {
          minidump:
            "bundled structural reader (MDMP streams 3, 4, 5, 6, 7, 9, 16)",
          wer: "bundled UTF-16LE key=value reader",
          minidump_input_budget_bytes: MINIDUMP_INPUT_BYTES,
        },
      },
    ],
  });
