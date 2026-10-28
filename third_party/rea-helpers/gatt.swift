import CoreBluetooth
import Foundation

// Reference CoreBluetooth GATT helper for REA's discovery lane.
//
// Spawned as:  gatt --peripheral-id UUID --timeout-ms N --max-output-bytes N
// On success it prints exactly one connected line:
//   {"event":"connected","name":...,"services":[{"uuid":...,
//    "characteristics":[{"uuid":...,"properties":[...]}]}]}
// then consumes one JSON command per stdin line and answers per command
// (value/written/notification+window_end/error/disconnected), echoing the id.
// macOS Bluetooth authorization denial is {"event":"authorization_denied"} on
// stderr with exit 2; it is never retried. REA digests payloads itself; this
// helper publishes payload bytes as lowercase hex.

let USAGE = "usage: gatt --peripheral-id UUID --timeout-ms N --max-output-bytes N"
let AUTH_DENIED_EXIT: Int32 = 2
let CONNECT_FAILED_EXIT: Int32 = 3
let ARG_ERROR_EXIT: Int32 = 4

final class HandshakeState {
  var done = false
  let gate = DispatchSemaphore(value: 0)

  func fail(code: String, message: String) -> Never {
    guard !done else { dispatchMain() }
    done = true
    let escaped = message.replacingOccurrences(of: "\"", with: "\\\"")
    print("{\"event\":\"connection_failed\",\"code\":\"\(code)\",\"message\":\"\(escaped)\"}")
    fflush(stdout)
    exit(CONNECT_FAILED_EXIT)
  }

  func succeed() {
    guard !done else { return }
    done = true
    gate.signal()
  }
}

func hexToData(_ hex: String) -> Data {
  var data = Data()
  var characters = ArraySlice(hex)
  while characters.count >= 2 {
    let pair = String(characters.prefix(2))
    if let byte = UInt8(pair, radix: 16) { data.append(byte) }
    characters = characters.dropFirst(2)
  }
  return data
}

func dataToHex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}

func escape(_ text: String) -> String {
  text.replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(
    of: "\n", with: "\\n")
}

func shortUuid(_ uuid: CBUUID) -> String {
  let text = uuid.uuidString.uppercased()
  if text.hasSuffix("-0000-1000-8000-00805F9B34FB") && text.hasPrefix("0000") {
    return String(text.dropFirst(4).prefix(4))
  }
  return text.uppercased()
}

/// Case- and hyphen-insensitive keying for GATT UUID lookups.
func normalizeGatt(_ text: String) -> String {
  text.uppercased().replacingOccurrences(of: "-", with: "")
}

final class Session: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
  static var handshake = HandshakeState()
  static var maxOutputBytes = 2 * 1024 * 1024
  static var emittedBytes = 0

  let central: CBCentralManager
  let ioQueue = DispatchQueue(label: "rea-gatt-io", qos: .utility)
  let peripheralIdentifier: UUID
  var peripheral: CBPeripheral?
  var serviceIndex: [String: CBService] = [:]
  var pendingServiceDiscovery = 0
  var observeId: String? = nil
  var observeEnding = false
  var observerCharacteristic: CBCharacteristic? = nil

  init(peripheralIdentifier: UUID, timeoutMs: Int) {
    self.central = CBCentralManager(delegate: nil, queue: ioQueue)
    self.peripheralIdentifier = peripheralIdentifier
    super.init()
    central.delegate = self
    // Cover the theoretical race where the power-state callback enqueued
    // before the delegate landed: re-dispatch the current state once.
    if central.state != .unknown {
      ioQueue.async { [weak self] in
        if let self = self, !Session.handshake.done {
          self.centralManagerDidUpdateState(self.central)
        }
      }
    }

    // The power-state callback drives everything after the radio reports;
    // the deadline is armed before the request so a silent peer is
    // reported on time.
    ioQueue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) {
      if !Session.handshake.done {
        Session.handshake.fail(
          code: "timeout", message: "the peer did not connect in time")
      }
    }
  }

  func centralManagerDidUpdateState(_ central: CBCentralManager) {
    guard !Session.handshake.done else { return }
    switch central.state {
    case .unauthorized:
      FileHandle.standardError.write(
        Data("{\"event\":\"authorization_denied\"}\n".utf8))
      exit(AUTH_DENIED_EXIT)
    case .poweredOn:
      let found = central.retrievePeripherals(withIdentifiers: [peripheralIdentifier])
      guard let target = found.first else {
        Session.handshake.fail(
          code: "refused",
          message: "peripheral identifier not known to this host")
      }
      target.delegate = self
      peripheral = target
      central.connect(target, options: nil)
    case .poweredOff:
      Session.handshake.fail(code: "refused", message: "Bluetooth radio is powered off")
    default:
      Session.handshake.fail(
        code: "refused",
        message: "Bluetooth is not available (state \(central.state.rawValue))")
    }
  }

  func emit(_ line: String) {
    Session.emittedBytes += line.utf8.count + 1
    if Session.emittedBytes > Session.maxOutputBytes {
      FileHandle.standardError.write(Data(
        "{\"event\":\"error\",\"message\":\"output budget exhausted\"}\n".utf8))
      exit(1)
    }
    print(line)
    fflush(stdout)
  }

  func characteristic(named json: [String: Any], id: String) -> CBCharacteristic? {
    let serviceText = normalizeGatt(json["service"] as? String ?? "")
    let characteristicText = normalizeGatt(json["characteristic"] as? String ?? "")
    guard let service = serviceIndex[serviceText] ?? serviceIndex.values.first(
      where: { normalizeGatt($0.uuid.uuidString) == serviceText })
    else {
      emit("{\"event\":\"error\",\"id\":\"\(id)\",\"message\":\"service \(escape(json["service"] as? String ?? "")) is not in this session's discovery\"}")
      return nil
    }
    guard let characteristic = (service.characteristics ?? []).first(
      where: { normalizeGatt($0.uuid.uuidString) == characteristicText })
    else {
      emit("{\"event\":\"error\",\"id\":\"\(id)\",\"message\":\"characteristic \(escape(json["characteristic"] as? String ?? "")) is not in this session's discovery\"}")
      return nil
    }
    return characteristic
  }

  static func properties(_ characteristic: CBCharacteristic) -> [String] {
    let map: [(CBCharacteristicProperties, String)] = [
      (.broadcast, "broadcast"),
      (.read, "read"),
      (.writeWithoutResponse, "write_without_response"),
      (.write, "write"),
      (.notify, "notify"),
      (.indicate, "indicate"),
      (.authenticatedSignedWrites, "authenticated_signed_writes"),
      (.extendedProperties, "extended_properties"),
    ]
    return map.filter { characteristic.properties.contains($0.0) }.map { $0.1 }
  }

  // CBCentralManagerDelegate

  func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
    peripheral.delegate = self
    pendingServiceDiscovery = 0
    peripheral.discoverServices(nil)
  }

  func centralManager(_ central: CBCentralManager,
                      didFailToConnect peripheral: CBPeripheral, error: Error?) {
    Session.handshake.fail(
      code: "refused",
      message: error?.localizedDescription ?? "the peer refused the connection")
  }

  func centralManager(_ central: CBCentralManager,
                      didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
    if observerCharacteristic !== nil {
      emit("{\"event\":\"error\",\"id\":\"\(observeId ?? "")\",\"message\":\"peer disconnected\"}")
      finishObserve()
    }
  }

  // CBPeripheralDelegate

  func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
    if let error = error {
      Session.handshake.fail(
        code: "refused", message: "service discovery failed: \(error.localizedDescription)")
    }
    let services = peripheral.services ?? []
    pendingServiceDiscovery = services.count
    for service in services {
      peripheral.discoverCharacteristics(nil, for: service)
    }
    if services.isEmpty { completeConnection() }
  }

  func peripheral(_ peripheral: CBPeripheral,
                  didDiscoverCharacteristicsFor service: CBService, error: Error?) {
    serviceIndex[normalizeGatt(service.uuid.uuidString)] = service
    if let error = error {
      emit("{\"event\":\"error\",\"message\":\"\(escape(error.localizedDescription))\"}")
    }
    pendingServiceDiscovery -= 1
    if pendingServiceDiscovery <= 0 { completeConnection() }
  }

  func completeConnection() {
    var serviceRows: [String] = []
    for service in peripheral?.services ?? [] {
      var characteristicRows: [String] = []
      for characteristic in service.characteristics ?? [] {
        characteristicRows.append(
          "{\"uuid\":\"\(shortUuid(characteristic.uuid))\",\"properties\":[\(Self.properties(characteristic).map({ "\"\($0)\"" }).joined(separator: ","))]}")
      }
      serviceRows.append(
        "{\"uuid\":\"\(shortUuid(service.uuid))\",\"characteristics\":[\(characteristicRows.joined(separator: ","))]}")
    }
    let name = peripheral?.name
    let nameJson = name.map({ "\"\(escape($0))\"" }) ?? "null"
    emit("{\"event\":\"connected\",\"name\":\(nameJson),\"services\":[\(serviceRows.joined(separator: ","))]}")
    Session.handshake.succeed()
  }

  func peripheral(_ peripheral: CBPeripheral,
                  didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
    guard let id = observeId, observerCharacteristic === characteristic else { return }
    if error != nil {
      emit("{\"event\":\"error\",\"id\":\"\(id)\",\"message\":\"\(escape(error?.localizedDescription ?? "read failed"))\"}")
      return
    }
    emit("{\"event\":\"notification\",\"id\":\"\(id)\",\"ts\":\"\(Self.isoNow())\",\"payload_hex\":\"\(dataToHex(characteristic.value ?? Data()))\"}")
  }

  static func isoNow() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
  }

  func finishObserve() {
    observerCharacteristic = nil
    observeId = nil
  }

  func endObserve(_ id: String, characteristic: CBCharacteristic) {
    peripheral?.setNotifyValue(false, for: characteristic)
    emit("{\"event\":\"window_end\",\"id\":\"\(id)\"}")
    finishObserve()
  }

  // Command handling, one command at a time on the IO queue.

  func handle(_ json: [String: Any]) {
    guard let id = json["id"] as? String ?? nil else {
      emit("{\"event\":\"error\",\"message\":\"the command carried no id\"}")
      return
    }
    switch json["op"] as? String {
    case "read":
      guard let characteristic = characteristic(named: json, id: id) else { return }
      if let cached = characteristic.value {
        emit("{\"event\":\"value\",\"id\":\"\(id)\",\"payload_hex\":\"\(dataToHex(cached))\"}")
        peripheral?.readValue(for: characteristic)
        return
      }
      readContinuations[id] = id
      peripheral?.readValue(for: characteristic)
      emit("{\"event\":\"value\",\"id\":\"\(id)\",\"payload_hex\":\"\(dataToHex(characteristic.value ?? Data()))\"}")
    case "write":
      guard let characteristic = characteristic(named: json, id: id) else { return }
      let payload = hexToData(json["payload_hex"] as? String ?? "")
      let withoutResponse = json["without_response"] as? Bool ?? false
      if withoutResponse {
        guard characteristic.properties.contains(.writeWithoutResponse) else {
          emit("{\"event\":\"error\",\"id\":\"\(id)\",\"message\":\"characteristic cannot write without response\"}")
          return
        }
        peripheral?.writeValue(payload, for: characteristic, type: .withoutResponse)
        emit("{\"event\":\"written\",\"id\":\"\(id)\"}")
        return
      }
      guard characteristic.properties.contains(.write) else {
        emit("{\"event\":\"error\",\"id\":\"\(id)\",\"message\":\"characteristic cannot write with response\"}")
        return
      }
      writeContinuations[id] = id
      peripheral?.writeValue(payload, for: characteristic, type: .withResponse)
    case "observe":
      guard let characteristic = characteristic(named: json, id: id) else { return }
      let seconds = json["seconds"] as? Int ?? 0
      guard characteristic.properties.contains(.notify) || characteristic.properties.contains(.indicate) else {
        emit("{\"event\":\"error\",\"id\":\"\(id)\",\"message\":\"characteristic is not notifiable\"}")
        return
      }
      observeId = id
      observerCharacteristic = characteristic
      peripheral?.setNotifyValue(true, for: characteristic)
      ioQueue.asyncAfter(deadline: .now() + .milliseconds(seconds * 1000)) {
        [weak self] in
        guard let self = self, self.observerCharacteristic === characteristic else { return }
        self.endObserve(id, characteristic: characteristic)
      }
    case "disconnect":
      if let peripheral = peripheral {
        central.cancelPeripheralConnection(peripheral)
      }
      emit("{\"event\":\"disconnected\",\"id\":\"\(id)\"}")
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { exit(0) }
    default:
      emit("{\"event\":\"error\",\"id\":\"\(id)\",\"message\":\"unsupported op\"}")
    }
  }

  var readContinuations: [String: String] = [:]
  var writeContinuations: [String: String] = [:]
}

// Argument parsing; the main thread only waits on the handshake gate, all
// CoreBluetooth work lives on the helper's private IO queue.
var args = Array(CommandLine.arguments.dropFirst())
var peripheralText: String? = nil
var timeoutMs = 10_000
var maxOutputBytes = 2 * 1024 * 1024
var index = 0
while index + 1 < args.count {
  switch args[index] {
  case "--peripheral-id": peripheralText = args[index + 1]
  case "--timeout-ms":
    if let value = Int(args[index + 1]) { timeoutMs = max(1000, min(120_000, value)) }
  case "--max-output-bytes":
    if let value = Int(args[index + 1]) { maxOutputBytes = value }
  default:
    FileHandle.standardError.write(Data("\(USAGE)\n".utf8))
    exit(ARG_ERROR_EXIT)
  }
  index += 2
}
guard let peripheralString = peripheralText,
      let peripheralIdentifier = UUID(uuidString: peripheralString)
else {
  FileHandle.standardError.write(Data("\(USAGE)\n".utf8))
  exit(ARG_ERROR_EXIT)
}
Session.maxOutputBytes = maxOutputBytes

let session = Session(peripheralIdentifier: peripheralIdentifier, timeoutMs: timeoutMs)

let commandThread = Thread {
  while let line = readLine() {
    let trimmed = line.trimmingCharacters(in: .whitespaces)
    if trimmed.isEmpty { continue }
    guard let data = trimmed.data(using: .utf8),
          let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    else {
      session.ioQueue.async {
        session.emit("{\"event\":\"error\",\"message\":\"the command line was not a JSON object\"}")
      }
      continue
    }
    session.ioQueue.async { session.handle(json) }
  }
}

// Commands start only after the handshake, so requests over stdin can never
// race the service tree.
Session.handshake.gate.wait()
commandThread.name = "gatt-commands"
commandThread.start()
dispatchMain()