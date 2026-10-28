import type { ProviderAvailability } from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import {
  type BenchProfile,
  BENCH_LIMA_PROFILE_ENV,
  BENCH_LIMA_PROFILE_REMEDIATION,
  BENCH_PROFILES,
  benchProfileSchema,
} from "../domain/bench/benchLimits.js";
import type { JsonValue } from "../domain/jsonValue.js";

/** One resolved benchmark-profile selection. */
export interface BenchConfiguration {
  readonly profile: BenchProfile;
}

export type BenchFailureCode = "not_configured" | "unsupported_profile";

export class BenchConfigurationFailure extends Error {
  readonly _tag = "BenchConfigurationFailure";
  constructor(
    readonly code: BenchFailureCode,
    message: string,
    readonly diagnostics: Readonly<Record<string, JsonValue>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "BenchConfigurationFailure";
  }
}

/** Resolve the benchmark profile this process may run, fail-closed. */
export const resolveBenchConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): BenchConfiguration => {
  const configured = environment[BENCH_LIMA_PROFILE_ENV];
  if (configured === undefined || configured.trim() === "")
    throw new BenchConfigurationFailure(
      "not_configured",
      `No benchmark profile is selected: ${BENCH_LIMA_PROFILE_ENV} is unset or blank`,
      {
        setting: BENCH_LIMA_PROFILE_ENV,
        supported_profiles: [...BENCH_PROFILES],
        remediation: BENCH_LIMA_PROFILE_REMEDIATION,
      },
    );
  const parsed = benchProfileSchema.safeParse(configured.trim());
  if (!parsed.success)
    throw new BenchConfigurationFailure(
      "unsupported_profile",
      `${BENCH_LIMA_PROFILE_ENV} names an unsupported benchmark profile: ${configured}`,
      {
        setting: BENCH_LIMA_PROFILE_ENV,
        configured_profile: configured,
        supported_profiles: [...BENCH_PROFILES],
        remediation: BENCH_LIMA_PROFILE_REMEDIATION,
      },
    );
  return { profile: parsed.data };
};

/** No profile refusal maps to a different availability code. */
const BENCH_REJECTION_CODE: ProviderRejectionCode = "not_configured";

/** Availability in the shape shared by every probe-backed provider. */
export const benchConfigurationAvailability = (
  cause: BenchConfigurationFailure,
): ProviderAvailability => ({
  status: "unavailable",
  code: BENCH_REJECTION_CODE,
  reason: cause.message,
  diagnostics: { ...cause.diagnostics },
});
