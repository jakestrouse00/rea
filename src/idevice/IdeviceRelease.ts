/**
 * Scope decision: approved by fork maintainer, 2026-10-19; boundaries as
 * documented in docs/idevice-provider.md. The real pymobiledevice3 lane was
 * not exercised on the implementing host: no `pymobiledevice3` command was
 * installed and no iOS device was paired there, so a verified release cannot
 * be pinned and every release reports unverified until a maintainer lane
 * records one.
 */
export const IDEVICE_VERIFIED_VERSION: string | null = null;

/** Stable provider ID shared by readiness, doctor and Evidence. */
export const IDEVICE_PROVIDER_ID = "idevice";

/** Remediation when `REA_IPHONE_PMD3_COMMAND` is missing or not absolute. */
export const IDEVICE_COMMAND_REMEDIATION = `Set REA_IPHONE_PMD3_COMMAND to the absolute path of a caller-supplied pymobiledevice3 launcher script. REA never installs pymobiledevice3, its Python dependencies, or iOS developers-and-disk-images.`;

/** Remediation when the host cannot run the iOS device plane. */
export const IDEVICE_UNSUPPORTED_HOST_REMEDIATION =
  "Use macOS (or another host with working usbmuxd tooling) for the iOS device plane. Only the macOS lane was in scope; other platforms report the provider as unavailable.";

/** Remediation when `pymobiledevice3 --version` cannot establish the release. */
export const IDEVICE_VERSION_PROBE_REMEDIATION =
  "Run the selected launcher with `--version`: it must exit promptly and print a pymobiledevice3 release string.";

/**
 * Honesty note surfaced by readiness and Evidence while no verified release
 * exists: simulated fixtures do not establish real-device behavior.
 */
export const IDEVICE_LANE_UNVERIFIED_NOTE =
  "REA has not verified a pymobiledevice3 release against real paired hardware yet; observed device behavior comes from the caller's installation and remains unverified.";
