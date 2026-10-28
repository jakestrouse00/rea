// wifi-scan — one bounded CoreWLAN RF scan, one JSON object per line.
//
// Compile locally (never shipped as a binary):
//   swiftc -framework CoreWLAN -framework CoreLocation \
//     -o ~/.local/share/rea/bin/wifi-scan wifi-scan.swift
// Usage: wifi-scan [--seconds N]
//   --seconds is a best-effort self-bound (default 10, 1..120): CoreWLAN has
//   no scan duration parameter and returns when the scan completes, so the
//   watchdog below is the soft bound and the observing parent's deadline is
//   the hard one.
//
// Line shape (verbatim CoreWLAN facts; null where the row gives none):
//   {"ts":<epoch ms>,"bssid":"...","ssid":null|"...","rssi":<n>|null,
//    "noise":<n>|null,"channel":<n>|null,"band":null|"2.4"|"5"|"6",
//    "channel_width_mhz":<n>|null,"phy_mode":null,"security":null}
//
// phy_mode and security are always null: this SDK's public CWNetwork
// scan results expose no per-network PHY mode or security property
// (supportsPHYMode/supportsSecurity are capability probes, not facts).
//
// Authorization (macOS TCC location) failure:
//   stderr {"event":"authorization_required","reason":"..."}, exit 2.
// Other scan failures:
//   stderr {"event":"scan_error","reason":"..."}, exit 1.

import CoreLocation
import CoreWLAN
import Foundation

let EXIT_OK: Int32 = 0
let EXIT_FAIL: Int32 = 1
let EXIT_AUTH_REQUIRED: Int32 = 2

let DEFAULT_SECONDS = 10
let MAX_SECONDS = 120

let OUTPUT = FileHandle.standardOutput
let ERROR = FileHandle.standardError

func emit(_ object: [String: Any], to stream: FileHandle) {
    guard JSONSerialization.isValidJSONObject(object) else { return }
    guard let data = try? JSONSerialization.data(withJSONObject: object) else {
        return
    }
    stream.write(data)
    stream.write(Data("\n".utf8))
}

func failAuthorization(_ reason: String) -> Never {
    emit(["event": "authorization_required", "reason": reason], to: ERROR)
    exit(EXIT_AUTH_REQUIRED)
}

func failScan(_ reason: String) -> Never {
    emit(["event": "scan_error", "reason": reason], to: ERROR)
    exit(EXIT_FAIL)
}

func fatalUsage(_ reason: String) -> Never {
    emit(["event": "usage_error", "reason": reason], to: ERROR)
    exit(EXIT_FAIL)
}

func parseSeconds() -> Int {
    let arguments = Array(CommandLine.arguments.dropFirst())
    var value: String?
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        if argument == "--seconds", index + 1 < arguments.count {
            value = arguments[index + 1]
            break
        }
        if argument.hasPrefix("--seconds=") {
            value = String(argument.dropFirst("--seconds=".count))
            break
        }
        index += 1
    }
    guard let raw = value else { return DEFAULT_SECONDS }
    guard let parsed = Int(raw), parsed >= 1, parsed <= MAX_SECONDS else {
        fatalUsage("--seconds must be an integer 1..\(MAX_SECONDS)")
    }
    return parsed
}

func isAuthorizationFailure(_ description: String) -> Bool {
    let lowered = description.lowercased()
    return lowered.contains("not permitted")
        || lowered.contains("denied")
        || lowered.contains("unauthorized")
        || lowered.contains("permission")
}

func bandName(_ band: CWChannelBand?) -> String? {
    guard let band = band else { return nil }
    switch band.rawValue {
    case 1: return "2.4"
    case 2: return "5"
    case 3: return "6"
    default: return nil
    }
}

func channelWidthMhz(_ width: CWChannelWidth?) -> Int? {
    guard let width = width else { return nil }
    switch width.rawValue {
    case 1: return 20
    case 2: return 40
    case 3: return 80
    case 4: return 160
    default: return nil
    }
}

let scanSeconds = parseSeconds()

// Location authorization is the macOS TCC gate that denies neighbor scans.
let locationStatus = CLLocationManager().authorizationStatus
switch locationStatus {
case .denied, .restricted:
    failAuthorization(
        "Location Services authorization is denied for this process (status: \(locationStatus.rawValue))"
    )
default:
    break
}

func numberOr(_ value: Int?) -> Any {
    value == nil ? NSNull() : NSNumber(value: value!)
}

func anyString(_ value: String?) -> Any {
    value ?? NSNull()
}

let client = CWWiFiClient.shared()
guard let interface = client.interface() else {
    failScan("no CoreWLAN Wi-Fi interface is available")
}

// Best-effort self-bound: if the scan has not returned after --seconds,
// stop and report the rows captured so far (CoreWLAN returns earlier on
// completion; the observing parent enforces the hard deadline).
let watchdog = Thread {
    Thread.sleep(forTimeInterval: Double(scanSeconds))
    exit(EXIT_OK)
}
watchdog.start()

do {
    let networks = try interface.scanForNetworks(
        withSSID: nil,
        includeHidden: false
    )
    let timestampMs = Int64(Date().timeIntervalSince1970 * 1000)
    for network in networks {
        let wlanChannel = network.wlanChannel
        let row: [String: Any] = [
            "ts": timestampMs,
            "bssid": anyString(network.bssid),
            "ssid": anyString(network.ssid),
            "rssi": NSNumber(value: network.rssiValue),
            "noise": NSNumber(value: network.noiseMeasurement),
            "channel": numberOr(wlanChannel?.channelNumber),
            "band": bandName(wlanChannel?.channelBand) ?? NSNull(),
            "channel_width_mhz":
                channelWidthMhz(wlanChannel?.channelWidth) ?? NSNull(),
            "phy_mode": NSNull(),
            "security": NSNull(),
        ]
        emit(row, to: OUTPUT)
    }
    exit(EXIT_OK)
} catch {
    let description = (error as NSError?)?.description
        ?? String(describing: error)
    if isAuthorizationFailure(description) {
        failAuthorization("CoreWLAN scan denied: \(description)")
    }
    failScan("CoreWLAN scan failed: \(description)")
}