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

| Tool                | Standard path               | Override                   |
| ------------------- | --------------------------- | -------------------------- |
| arp                 | `/usr/sbin/arp`             | `REA_ARP_PATH`             |
| ndp                 | `/usr/sbin/ndp`             | `REA_NDP_PATH`             |
| dns-sd              | `/usr/bin/dns-sd`           | `REA_DNS_SD_PATH`          |
| system_profiler     | `/usr/sbin/system_profiler` | `REA_SYSTEM_PROFILER_PATH` |
| ping                | `/sbin/ping`                | `REA_PING_PATH`            |
| blueutil (optional) | caller-installed            | `REA_BLUEUTIL_PATH`        |

Relative paths are refused fail-closed. `blueutil` is required only by
the inquiry source; without it that source is skipped and reported as
skipped, never silently absent.

## Real-provider verification

The macOS commands were executed on the implementing host against its
own LAN and USB tree at lane-addition time (observed, not simulated).
Boundary tests script the toolset so every operation is exercised end to
end without touching the real network or devices.
