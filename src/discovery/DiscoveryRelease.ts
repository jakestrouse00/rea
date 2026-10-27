/**
 * Scope decision: approved by fork maintainer, 2026-10-27. The lane covers
 * four passive sources (neighbor tables, mDNS browse, USB tree, Bluetooth
 * inventory) plus one explicitly authorized active subnet sweep, as
 * documented in docs/discovery-analysis.md. Passive sources read this
 * host's own observation state; only `probe_subnet_reachability` emits
 * packets that other hosts can observe, and it requires an explicit
 * `authorize_probe: true` input plus a /22.._/32 CIDR bound.
 *
 * Real-host verification: the macOS commands were executed on the
 * implementing host against its own LAN at lane-addition time (observed,
 * not simulated).
 */
export const DISCOVERY_PROVIDER_ID = "discovery";

/** Remediation when a required host tool cannot be resolved. */
export const DISCOVERY_TOOL_REMEDIATION = `The discovery lane resolves macOS host tools at their standard absolute paths (arp, ndp, dns-sd, system_profiler, ping); override individually with REA_ARP_PATH, REA_NDP_PATH, REA_DNS_SD_PATH, REA_SYSTEM_PROFILER_PATH or REA_PING_PATH. REA never installs these tools or blueutil.`;

/** Remediation when the host cannot run the discovery lane. */
export const DISCOVERY_UNSUPPORTED_HOST_REMEDIATION =
  "Use a macOS host for the discovery lane; the command locations and flags REA drives are Apple-shipped tool paths verified on macOS only, and other platforms report the provider as unavailable rather than pretending parity.";

/** Remediation when blueutil is required by an inquiry but not configured. */
export const DISCOVERY_BLUEUTIL_REMEDIATION =
  "Set REA_BLUEUTIL_PATH to the absolute path of a caller-installed blueutil binary. REA never installs blueutil; without it the inquiry source stays skipped and only the paired inventory is reported.";

/**
 * Honesty note surfaced by readiness and Evidence: the paired/neighbor
 * sources are snapshots of host state that can be stale, and the inquiry
 * is classic Bluetooth, not BLE advertisement monitoring.
 */
export const DISCOVERY_LANE_NOTE =
  "Neighbor and Bluetooth inventories are kernels' cached observation state and can be stale; the blueutil inquiry is classic Bluetooth discovery, not BLE advertisement monitoring, and macOS may prompt for Bluetooth permission the first time.";
