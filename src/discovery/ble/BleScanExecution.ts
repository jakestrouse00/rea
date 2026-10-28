import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  runDiscoveryObservation,
  type DiscoveryProcessLauncher,
} from "../DiscoveryCommand.js";
import { DISCOVERY_PROVIDER_ID } from "../DiscoveryRelease.js";
import {
  parseBleScanLines,
  type ParsedBleAdvertisement,
} from "./BleScanAnalysis.js";

/** The operation name the integrator must wire into the provider switch. */
export const BLE_SCAN_OPERATION = "scan_ble_advertisements";

/** Grace on top of the helper's own --seconds window, mirroring the inquiry path. */
export const BLE_SCAN_GRACE_MS = 5_000;

/**
 * Normalized payload for one bounded BLE advertisement window. The
 * integrator passes this to createAnalysisExecution verbatim.
 */
export interface BleScanNormalizedResult {
  readonly scan_seconds: number;
  readonly address_filter: string | null;
  readonly advertisements: ParsedBleAdvertisement[];
  readonly window_exhausted: boolean;
  readonly elapsed_ms: number;
  readonly exit_code: number | null;
  readonly unparsed_lines: string[];
  readonly coverage: "complete" | "partial";
}

/** True when the helper reported the TCC Bluetooth authorization denial. */
export const isAuthorizationDenied = (stderr: string): boolean =>
  /"event"\s*:\s*"authorization_denied"/u.test(stderr);

const capturedOutput = (run: {
  readonly stdout: string;
  readonly stderr: string;
  readonly exit_code: number | null;
  readonly timed_out: boolean;
}) => ({
  stdout: run.stdout,
  stderr: run.stderr,
  truncated: false,
  exit_code: run.exit_code,
  ...(run.timed_out ? { signal: "SIGTERM" } : {}),
});

/**
 * Run one bounded BLE advertisement scan with the caller-supplied scanner and
 * normalize its JSON line stream. Denial of macOS Bluetooth authorization is a
 * structural refusal, not observed data: the caller must grant access before
 * this lane can observe anything.
 */
export const executeBleScan = async (
  scannerPath: string,
  input: {
    readonly scan_seconds: number;
    readonly address_filter: string | null;
  },
  signal?: AbortSignal,
  launcher?: DiscoveryProcessLauncher,
): Promise<Result<BleScanNormalizedResult, AnalysisError>> => {
  const started = Date.now();
  const args = [
    "--seconds",
    String(input.scan_seconds),
    ...(input.address_filter === null
      ? []
      : ["--address", input.address_filter]),
  ];
  const ran = await runDiscoveryObservation(
    BLE_SCAN_OPERATION,
    scannerPath,
    args,
    { timeoutMs: input.scan_seconds * 1000 + BLE_SCAN_GRACE_MS },
    signal,
    launcher,
  );
  if (!ran.ok) return ran;

  if (isAuthorizationDenied(ran.value.stderr))
    return err(
      new ProviderAdapterError(DISCOVERY_PROVIDER_ID, BLE_SCAN_OPERATION, {
        capturedOutput: capturedOutput(ran.value),
        userMessage:
          "macOS Bluetooth authorization was denied for the BLE scanner, so the scan observed nothing. Grant Bluetooth access to the terminal or app that launches REA in System Settings, Privacy & Security, Bluetooth; then retry once.",
        remediationAction: "grant_bluetooth_authorization",
      }),
    );

  const parsed = parseBleScanLines(ran.value.stdout);
  if (
    parsed.items.length === 0 &&
    parsed.unparsedLines.length === 0 &&
    ran.value.timed_out === false &&
    typeof ran.value.exit_code === "number" &&
    ran.value.exit_code !== 0
  ) {
    const diagnostic = ran.value.stderr.trim().split("\n").at(-1) || "";
    return err(
      new ProviderAdapterError(DISCOVERY_PROVIDER_ID, BLE_SCAN_OPERATION, {
        capturedOutput: capturedOutput(ran.value),
        userMessage: `The BLE scanner exited with code ${String(ran.value.exit_code)} and reported no advertisements${
          diagnostic.length > 0 ? `: ${diagnostic}` : ""
        }`,
      }),
    );
  }

  return ok({
    scan_seconds: input.scan_seconds,
    address_filter: input.address_filter,
    advertisements: parsed.items,
    window_exhausted: ran.value.timed_out,
    elapsed_ms: Date.now() - started,
    exit_code: ran.value.exit_code,
    unparsed_lines: parsed.unparsedLines,
    coverage:
      parsed.unparsedLines.length > 0 || ran.value.timed_out
        ? ("partial" as const)
        : ("complete" as const),
  });
};
