# Discovery analysis

Local network and device discovery reads are often the first step of a
reverse-engineering engagement: which devices are attached, what services
advertise themselves on the LAN, and which hosts answer. This lane answers
that question over macOS host-provided tools, without installing anything
and without pretending to know what it did not observe.

## Maintainer scope decision (fork, 2026-10-27)

Approved by the fork maintainer, with these boundaries:

- **Sources (passive):** the host's own neighbor tables (`arp`, `ndp`),
  the USB/Thunderbolt device tree (`system_profiler SPUSBDataType`), the
  paired Bluetooth inventory (`system_profiler SPBluetoothDataType`), and
  a bounded mDNS/Bonjour browse (`dns-sd`). These read or observe this
  host's own neighborhood.
- **One active operation:** `probe_subnet_reachability` sends exactly one
  ICMP echo request per candidate host of a caller-selected IPv4 CIDR
  bounded to /22.._/32 (at most 1022 candidates) at bounded concurrency,
  plus optional TCP connect probes to at most eight caller-selected ports
  against responsive hosts. It requires an explicit
  `authorize_probe: true` input. No other packet originates from REA,
  there is no exploitation or credential guessing, and nothing is retried
  or re-swept beyond what the caller selects per invocation.
- **Side effects:** neighbor/USB/Bluetooth reads launch one-shot host
  tools and touch no network; the mDNS browse emits multicast queries
  visible on the LAN; the Bluetooth inquiry (only with a caller-supplied
  `blueutil`) emits short-range classic-Bluetooth discovery queries; the
  sweep emits one ICMP datagram per candidate and TCP connects to the
  selected ports. All of this is declared in each tool's effects audit.
- **Never installed:** REA never installs arp, ndp, dns-sd,
  system_profiler, ping, or blueutil. These are bring-your-own host
  tools; the lane refuses them missing rather than provisioning.
- **Verified scope:** only macOS. Other hosts report the provider as
  unavailable instead of pretending parity.

## Maintainer scope decision (extension, 2026-10-28)

Approved by the fork maintainer, the lane extends beyond the neighbor
inventories above with these boundaries:

- **`scan_ble_advertisements`** observes BLE advertising packets for a
  bounded window through a caller-supplied CoreBluetooth helper
  (`REA_BLE_SCANNER_PATH`; reference helper source ships under
  `third_party/rea-helpers/`). It is receive-only — no connection
  requests to peers — and macOS reports peripherals by CoreBluetooth
  UUID, never by MAC address.
- **BLE GATT sessions (approved by the fork maintainer, 2026-10-28):**
  `connect_ble_gatt` opens ONE connection to a caller-named peripheral
  identifier through the caller-supplied GATT helper
  (`REA_BLE_GATT_PATH`; reference source `third_party/rea-helpers/gatt.swift`),
  and requires `authorize_gatt: true` because the connection sends ATT
  protocol requests and changes the peer's connection state. The session
  is held by the REA process (`session_id`), one command in flight at a
  time, never auto-reconnected. `read_gatt_characteristic` and
  `observe_gatt_notifications` receive ATT payloads within that session;
  values are reported value-free by default (SHA-256 + length) with
  payload hex only on a per-call `include_payload_hex` opt-in, because
  these payloads carry user data on real devices.
  `enumerate_gatt_services` asks the live helper for the peripheral's
  current service tree instead of replaying the handshake's answer (a
  bonded peer can publish services later), bounded by `max_services` and
  `max_characteristics_per_service`; omitted characteristics are counted.
  `subscribe_characteristic` collects one notifiable characteristic's
  notifications into a bounded buffer: the window ends at
  `observe_seconds` or when `max_notifications` rows were retained, and a
  full buffer reports `buffer_full` with the count of rows that arrived
  after it, so a full buffer is never mistaken for a quiet characteristic.
  Notification rows carry a SHA-256 digest and length; their `raw` framing
  keeps the helper's event shape with the payload bytes removed, so a
  digest-only caller never receives the bytes back through that field.
  `write_gatt_characteristic` is the only data-mutating operation of the
  lane: audited `mutatesDevice`, destructive, requires
  `authorize_write: true` per call, sends the bytes exactly once, never
  retries, and never echoes the payload into Evidence (byte count and
  target only). `close_ble_gatt` disconnects and reports cleanup
  uncertainty from the stop-escalation path (SIGTERM/SIGKILL). The
  observe window's subscription sends the peer's CCCD control write on
  the session's own connection. The helper is never installed, paired,
  or rebuilt by REA.
- **Bundled bleak bridge (`REA_BLEAK_PYTHON`):** `bridge/ble/bleak_bridge.py`
  is an REA-authored helper that speaks the same JSON-line protocol over
  bleak's macOS CoreBluetooth backend. Selecting an absolute interpreter
  through `REA_BLEAK_PYTHON` uses it when `REA_BLE_GATT_PATH` is unset; a
  caller-built CoreBluetooth helper always wins, and neither selected is a
  typed refusal rather than a guessed interpreter. REA never installs Python
  packages or bleak. The lane is availability-gated to macOS CoreBluetooth:
  on another host the BLE GATT tools report `unsupported_host`, and the
  availability policy carries that gate as the `bleGatt` host restriction plus
  a `bleGattEnabled` feature. Evidence names the transport that ran
  (`tools.ble_gatt` or `tools.bleak_python`).
  Real-device verification (a live peripheral
  connect/enumerate/subscribe/read/write/close cycle) has not been run yet: it
  is an explicit unknown, and the lane's Evidence records no claims about it.
- **`scan_wifi_networks`** observes 802.11 beacon frames through a
  caller-compiled CoreWLAN helper (`REA_WIFI_SCANNER_PATH`), falling
  back to the host's `system_profiler` airport scan cache. macOS gates
  neighbor scans behind Location Services: a TCC denial is a structured
  failure (never retried), and a withheld BSSID/SSID is preserved as
  null. SSID inclusion is a caller choice dropped at the parse boundary.
- **`resolve_mdns_records`** and **`inspect_network_interfaces`** read
  more of what `browse_lan_services` and `list_network_neighbors` found:
  bounded `dns-sd -L/-Z/-G` resolution of one instance and the interface
  table with an ifIndex mapping, with AWDL peers read from the kernel
  neighbor rows on `awdl0`/`llw0`.
- **`capture_radio_packets`** runs a caller-provided capture program
  (`REA_PACKET_CAPTURE_COMMAND`, e.g. a tcpdump wrapper script; REA never
  installs one and never elevates privileges) for one bounded window,
  validates the retained file's pcap/pcapng magic and digest, and never
  deletes the output — even on failure. Requires `authorize_capture:
  true`. Feed the retained path to `inspect_pcap_capture` afterwards.
- **`list_serial_ports` / `observe_serial_port`** inventory serial
  device nodes and read one node's receive side for a bounded window;
  the write path does not exist in the lane. Opening a port asserts
  modem-control lines (some devices reset), and the operation is audited
  `mutatesDevice` for that reason.
- **`correlate_device_evidence`** queries only the session's retained
  Evidence ledger: 2..16 caller-selected records are walked for
  address-like endpoints with all original spellings preserved, matching
  across records is reported (observed), OUI vendors come from a curated
  non-exhaustive table derived from the IEEE registry, and same-device
  claims are never made.
- **Never installed (extension):** the BLE and Wi-Fi helpers are
  bring-your-own binaries compiled by the caller; their source ships as
  reference material only.

## What each tool reports and what it cannot

- **`list_network_neighbors`** reads the kernel-cached neighbor tables.
  Rows can be stale or expired; absence from the table is not absence on
  the network. Incomplete rows are preserved with `mac: null`.
- **`browse_lan_services`** browses only for as long as its windows run;
  instance lists reflect the window, not steady state. Discovered types
  beyond the `max_types` bound are counted and reported, not silently
  dropped.
- **`list_usb_devices`** makes devices visible even when adb or
  pymobiledevice3 tooling is not installed; it does not diagnose those
  lanes (see [adb-device-analysis.md](adb-device-analysis.md) and
  [idevice-provider.md](idevice-provider.md)).
- **`list_bluetooth_devices`** reports the paired inventory from the
  host; the `inquiry` source is classic Bluetooth discovery through a
  caller-supplied blueutil — not BLE advertisement monitoring — and
  reports rows verbatim with their raw line preserved.
- **`probe_subnet_reachability`** reports one ICMP exchange per host and
  optional TCP connect results. A non-response is silence on the wire
  (firewalling, drop rules, offline), never proof of absence.

## Configuration

Tools resolve at Apple's standard absolute paths; each has an explicit
override:

| Tool                       | Standard path               | Override                     |
| -------------------------- | --------------------------- | ---------------------------- |
| arp                        | `/usr/sbin/arp`             | `REA_ARP_PATH`               |
| ndp                        | `/usr/sbin/ndp`             | `REA_NDP_PATH`               |
| dns-sd                     | `/usr/bin/dns-sd`           | `REA_DNS_SD_PATH`            |
| system_profiler            | `/usr/sbin/system_profiler` | `REA_SYSTEM_PROFILER_PATH`   |
| ping                       | `/sbin/ping`                | `REA_PING_PATH`              |
| ifconfig                   | `/sbin/ifconfig`            | `REA_IFCONFIG_PATH`          |
| blueutil (optional)        | caller-installed            | `REA_BLUEUTIL_PATH`          |
| BLE scanner (optional)     | caller-compiled             | `REA_BLE_SCANNER_PATH`       |
| GATT helper (optional)     | caller-compiled             | `REA_BLE_GATT_PATH`          |
| bleak bridge interpreter   | caller-installed Python 3   | `REA_BLEAK_PYTHON`           |
| Wi-Fi helper (optional)    | caller-compiled             | `REA_WIFI_SCANNER_PATH`      |
| stty (optional)            | `/bin/stty`                 | `REA_STTY_PATH`              |
| capture program (optional) | caller-provided             | `REA_PACKET_CAPTURE_COMMAND` |

Relative paths are refused fail-closed. `blueutil` is required only by
the inquiry source; without it that source is skipped and reported as
skipped, never silently absent. Every GATT operation requires a selected
helper: a caller-built CoreBluetooth helper, or an interpreter for the bundled
bleak bridge. Without either, those operations are refused with the
remediation string rather than returning empty results. Its reference
source is `third_party/rea-helpers/gatt.swift`; it is caller-compiled,
and REA never installs, pairs, or retries a GATT write.

## Real-provider verification

The macOS commands were executed on the implementing host against its
own LAN and USB tree at lane-addition time (observed, not simulated).
Boundary tests script the toolset so every operation is exercised end to
end without touching the real network or devices.
