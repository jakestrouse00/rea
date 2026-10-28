// ble-scan — passive CoreBluetooth BLE advertisement observer for REA.
//
// Producer format: one JSON object per line on stdout, one line per
// discovered/updated peripheral advertisement:
//   {"event":"discovered","ts":"2026-10-27T12:00:00.000Z","address_or_uuid":"<CBUUID>",
//    "name":null,"rssi":-62,"connectable":null,"manufacturer_hex":"4c000215...",
//    "service_uuids":["180F"],"flags_description":null}
// Unknown fields stay null; the parser on the REA side preserves rows it
// cannot recognize.
//
// Authorization handling: when macOS TCC denies Bluetooth access the helper
// prints {"event":"authorization_denied"} to stderr and exits nonzero (code 2).
// The caller treats denial as terminal for that attempt and must not retry.
//
// This helper is passive receive-only: CBCentralManager scanning listens for
// advertisement packets; it sends no connection requests to peers.

import CoreBluetooth
import Foundation

let USAGE = "usage: ble-scan [--seconds N] [--address UUID]\n"

var scanSeconds = 10
var addressFilter: String? = nil

var arguments = Array(CommandLine.arguments.dropFirst())
var index = 0
while index < arguments.count {
    switch arguments[index] {
    case "--seconds":
        index += 1
        guard index < arguments.count, let value = Int(arguments[index]),
              value >= 1, value <= 120
        else {
            FileHandle.standardError.write(Data(USAGE.utf8))
            exit(4)
        }
        scanSeconds = value
    case "--address":
        index += 1
        guard index < arguments.count, !arguments[index].isEmpty
        else {
            FileHandle.standardError.write(Data(USAGE.utf8))
            exit(4)
        }
        addressFilter = arguments[index]
    default:
        FileHandle.standardError.write(Data(USAGE.utf8))
        exit(4)
    }
    index += 1
}

let timestampFormatter = ISO8601DateFormatter()
timestampFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

final class AdvertisementObserver: NSObject, CBCentralManagerDelegate {
    // kCBAdvDataIsConnectable: macOS CoreBluetooth does not surface a Swift
    // constant for this advertisement key; the raw value is stable across SDKs.
    static let connectableKey = "kCBAdvDataIsConnectable"
    let seconds: Int
    let filter: String?
    var central: CBCentralManager?
    var seen = Set<String>()
    var deadline = Date.distantPast

    init(seconds: Int, filter: String?) {
        self.seconds = seconds
        self.filter = filter
    }

    func run() {
        deadline = Date().addingTimeInterval(TimeInterval(seconds))
        central = CBCentralManager(delegate: self, queue: .main)
        let runLoop = RunLoop.main
        while runLoop.run(mode: .default, before: Date().addingTimeInterval(0.5)) {
            if Date() >= deadline { break }
        }
        if let central, central.state == .poweredOn { central.stopScan() }
        exit(0)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            central.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        case .unauthorized:
            // TCC authorization denied (or not yet granted): terminal for this
            // attempt, the caller reports it instead of retrying.
            emitControlLine("authorization_denied")
            exit(2)
        case .poweredOff:
            emitControlLine("bluetooth_powered_off")
            exit(3)
        case .unsupported:
            emitControlLine("bluetooth_unsupported")
            exit(3)
        default:
            break
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let identifier = peripheral.identifier.uuidString
        if let filter, identifier.caseInsensitiveCompare(filter) != .orderedSame {
            return
        }
        let event = seen.contains(identifier) ? "updated" : "discovered"
        seen.insert(identifier)

        var record: [String: Any] = [
            "event": event,
            "ts": timestampFormatter.string(from: Date()),
            "address_or_uuid": identifier,
            "rssi": RSSI.intValue,
            "service_uuids": (advertisementData[CBAdvertisementDataServiceUUIDsKey]
                as? [CBUUID])?.map(\.uuidString) ?? [],
            "flags_description": NSNull(),
        ]
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String)
            ?? peripheral.name
        record["name"] = name.map { $0 as Any } ?? NSNull()
        if let connectable = advertisementData[
            Self.connectableKey
        ] as? Bool {
            record["connectable"] = connectable
        } else {
            record["connectable"] = NSNull()
        }
        if let manufacturerData = advertisementData[
            CBAdvertisementDataManufacturerDataKey
        ] as? Data {
            record["manufacturer_hex"] = manufacturerData.map {
                String(format: "%02x", $0)
            }.joined()
        } else {
            record["manufacturer_hex"] = NSNull()
        }

        guard let line = try? JSONSerialization.data(withJSONObject: record) else {
            return
        }
        FileHandle.standardOutput.write(line)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}

func emitControlLine(_ event: String) {
    let payload: [String: Any] = ["event": event]
    guard let line = try? JSONSerialization.data(withJSONObject: payload) else {
        return
    }
    FileHandle.standardError.write(line)
    FileHandle.standardError.write(Data("\n".utf8))
}

let observer = AdvertisementObserver(seconds: scanSeconds, filter: addressFilter)
observer.run()