import type { CrashTriagePort } from "../application/crashTriage/CrashTriagePort.js";
import { CrashTriageService } from "../crashTriage/CrashTriageService.js";

/** Compose campaign bookkeeping without import-time I/O or engine discovery. */
export const createCrashTriageService = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): CrashTriagePort => new CrashTriageService({ environment });
