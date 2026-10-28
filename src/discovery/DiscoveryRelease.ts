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
 *
 * GATT extension: approved by fork maintainer, 2026-10-28. Adds one
 * caller-authorized, caller-supplied-helper BLE GATT session lane over
 * connect_ble_gatt (authorize_gatt), read_gatt_characteristic,
 * write_gatt_characteristic (authorize_write, the only data-mutating op),
 * observe_gatt_notifications (CCCD control write within the session) and
 * close_ble_gatt, as documented in docs/discovery-analysis.md. The helper
 * process is REA-owned supervision of a caller-built binary; REA never
 * pairs and never retries a GATT write.
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

/** Remediation when a BLE scan is requested but the scanner is not usable. */
export const DISCOVERY_BLE_REMEDIATION =
  "Set REA_BLE_SCANNER_PATH to the absolute path of a caller-installed BLE advertisement scanner that prints one JSON object per line (a reference CoreBluetooth helper source ships at third_party/rea-helpers/ble-scan.swift; compile it locally with swiftc). REA never installs the scanner; without it scan_ble_advertisements stays skipped.";

/** Remediation when GATT work is requested but the GATT helper is not usable. */
export const DISCOVERY_BLE_GATT_REMEDIATION = `Set REA_BLE_GATT_PATH to the absolute path of a caller-compiled CoreBluetooth GATT helper (build with: swiftc -framework CoreBluetooth -o ~/.local/share/rea/bin/gatt <rea checkout>/third_party/rea-helpers/gatt.swift; the helper owns one connection and speaks a JSON-line protocol on stdio, reporting macOS Bluetooth authorization denial with a {"event":"authorization_denied"} stderr row and exit 2). REA never installs or builds the helper and never pairs; without it the GATT session tools stay skipped.`;

/** Remediation when a capture is requested but the capture program is not configured. */
export const DISCOVERY_CAPTURE_REMEDIATION = `Set REA_PACKET_CAPTURE_COMMAND to the absolute path of a caller-provided capture program (for example a tcpdump wrapper script preconfigured with its own interface and flags) that writes its output to the single argument REA appends, the output path. A packet capture originates packets and RxFrames from this host and needs caller-provided privileges: REA never installs a capture binary and never elevates privileges itself.`;

/** Remediation when the Wi-Fi RF lane has no caller-built scan helper. */
export const DISCOVERY_WIFI_REMEDIATION = `Set REA_WIFI_SCANNER_PATH to the absolute path of a caller-compiled CoreWLAN scan helper (build with: swiftc -framework CoreWLAN -framework CoreLocation -o ~/.local/share/rea/bin/wifi-scan <rea checkout>/third_party/rea-helpers/wifi-scan.swift; the helper prints one JSON object per observed network and reports macOS location-authorization denial with a {"event":"authorization_required"} stderr row and exit 2). REA never installs or builds the helper; without it the RF lane stays skipped and only the system_profiler fallback is reported.`;

/**
 * Honesty note surfaced by readiness and Evidence: the paired/neighbor
 * sources are snapshots of host state that can be stale, and the inquiry
 * is classic Bluetooth, not BLE advertisement monitoring.
 */
export const DISCOVERY_LANE_NOTE =
  "Neighbor and Bluetooth inventories are kernels' cached observation state and can be stale; the blueutil inquiry is classic Bluetooth discovery, not BLE advertisement monitoring, and macOS may prompt for Bluetooth permission the first time.";
