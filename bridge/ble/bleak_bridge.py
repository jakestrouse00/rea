#!/usr/bin/env python3
"""REA bundled bleak GATT bridge (MIT, authored for this repository).

Speaks the same JSON-line protocol as the reference CoreBluetooth helper in
third_party/rea-helpers/gatt.swift, but over bleak's macOS CoreBluetooth
backend. REA spawns it with a caller-supplied interpreter
(REA_BLEAK_PYTHON); when REA_BLE_GATT_PATH is set, the CoreBluetooth helper
wins and this bridge is not used.

Spawn:  bleak_bridge.py --peripheral-id UUID --timeout-ms N --max-output-bytes N

Handshake (one line): {"event":"connected","name":...,"services":[...]}
Authorization denial: {"event":"authorization_denied"} on stderr, exit 2.
Connection failure: {"event":"connection_failed","code":...,"message":...},
exit 3. Unsupported command: {"event":"error","id":...,"message":...}.

Commands, one JSON object per stdin line, echoing the caller's id:
  {"op":"read","service":UUID,"characteristic":UUID}
      -> {"event":"value","id":...,"payload_hex":...}
  {"op":"write","service":...,"characteristic":...,"payload_hex":...,
   "without_response":bool}
      -> {"event":"written","id":...}
  {"op":"enumerate"}
      -> {"event":"services","id":...,"services":[...]}
  {"op":"observe","service":...,"characteristic":...,"seconds":N}
  {"op":"subscribe","service":...,"characteristic":...,"seconds":N,
   "max_notifications":N}
      -> notification rows, then {"event":"window_end","id":...,
         "stop_reason":"deadline"|"buffer_full"}
  {"op":"disconnect"} -> {"event":"disconnected","id":...}, exit 0

Only structure and payload bytes the peer sent are emitted; the bridge never
prints device names beyond the peripheral's own, file content, or keys.
"""

import asyncio
import json
import sys
from datetime import datetime, timezone

MAX_OUTPUT_BYTES_ARG_ERROR = 4
AUTH_DENIED_EXIT = 2
CONNECT_FAILED_EXIT = 3

PROPERTY_NAMES = {
    "broadcast": "broadcast",
    "read": "read",
    "write-without-response": "write_without_response",
    "write": "write",
    "notify": "notify",
    "indicate": "indicate",
    "authenticated-signed-writes": "authenticated_signed_writes",
    "extended-properties": "extended_properties",
}


class Output:
    """Serializes one JSON line at a time and enforces the byte budget."""

    def __init__(self, limit):
        self.limit = limit
        self.written = 0

    def emit(self, document):
        line = json.dumps(document) + "\n"
        encoded = line.encode("utf-8")
        if self.written + len(encoded) > self.limit:
            document = {
                "event": "error",
                "id": document.get("id"),
                "message": "the bridge reached its output budget",
            }
            line = json.dumps(document) + "\n"
            encoded = line.encode("utf-8")
            if self.written + len(encoded) > self.limit:
                return
        self.written += len(encoded)
        sys.stdout.write(line)
        sys.stdout.flush()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def short_uuid(uuid):
    text = str(uuid).lower()
    if text.startswith("0000") and text.endswith("-0000-1000-8000-00805f9b34fb"):
        return text[4:8]
    return text


def service_rows(services):
    rows = []
    for service in services:
        characteristics = []
        for characteristic in service.characteristics:
            properties = []
            for prop in characteristic.properties:
                name = PROPERTY_NAMES.get(prop)
                if name is not None and name not in properties:
                    properties.append(name)
            characteristics.append(
                {"uuid": short_uuid(characteristic.uuid), "properties": properties}
            )
        rows.append({"uuid": short_uuid(service.uuid), "characteristics": characteristics})
    return rows


def find_characteristic(client, service_uuid, characteristic_uuid):
    wanted_service = str(service_uuid).lower()
    wanted_characteristic = str(characteristic_uuid).lower()
    for service in client.services:
        if short_uuid(service.uuid) != wanted_service and str(service.uuid).lower() != wanted_service:
            continue
        for characteristic in service.characteristics:
            if (
                short_uuid(characteristic.uuid) == wanted_characteristic
                or str(characteristic.uuid).lower() == wanted_characteristic
            ):
                return characteristic
    return None


async def run(argv):
    peripheral_id = None
    timeout_ms = 10000
    max_output_bytes = 2 * 1024 * 1024
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag == "--peripheral-id":
            peripheral_id = argv[index + 1]
            index += 2
        elif flag == "--timeout-ms":
            timeout_ms = int(argv[index + 1])
            index += 2
        elif flag == "--max-output-bytes":
            max_output_bytes = int(argv[index + 1])
            index += 2
        else:
            sys.stderr.write("usage: bleak_bridge.py --peripheral-id UUID --timeout-ms N --max-output-bytes N\n")
            return MAX_OUTPUT_BYTES_ARG_ERROR
    if peripheral_id is None:
        sys.stderr.write("usage: bleak_bridge.py --peripheral-id UUID --timeout-ms N --max-output-bytes N\n")
        return MAX_OUTPUT_BYTES_ARG_ERROR

    output = Output(max_output_bytes)
    try:
        from bleak import BleakClient
    except Exception as error:
        sys.stderr.write(json.dumps({"event": "connection_failed", "code": "bridge_unavailable", "message": "bleak is not importable: %s" % type(error).__name__}) + "\n")
        return CONNECT_FAILED_EXIT

    client = BleakClient(peripheral_id, timeout=timeout_ms / 1000.0)
    try:
        await client.connect()
    except Exception as error:
        message = str(error)
        if "denied" in message.lower() or "unauthorized" in message.lower():
            sys.stderr.write(json.dumps({"event": "authorization_denied"}) + "\n")
            return AUTH_DENIED_EXIT
        sys.stderr.write(json.dumps({"event": "connection_failed", "code": "connect_failed", "message": message[:200]}) + "\n")
        return CONNECT_FAILED_EXIT

    try:
        await client.get_services()
    except Exception:
        pass
    output.emit(
        {
            "event": "connected",
            "name": None,
            "services": service_rows(client.services),
        }
    )

    loop = asyncio.get_running_loop()
    stopping = asyncio.Event()

    async def handle(command):
        identifier = command.get("id")
        operation = command.get("op")
        if operation == "read":
            characteristic = find_characteristic(client, command.get("service"), command.get("characteristic"))
            if characteristic is None:
                output.emit({"event": "error", "id": identifier, "message": "characteristic not found"})
                return
            try:
                payload = await client.read_gatt_char(characteristic)
            except Exception as error:
                output.emit({"event": "error", "id": identifier, "message": str(error)[:200]})
                return
            output.emit({"event": "value", "id": identifier, "payload_hex": bytes(payload).hex()})
            return
        if operation == "write":
            characteristic = find_characteristic(client, command.get("service"), command.get("characteristic"))
            if characteristic is None:
                output.emit({"event": "error", "id": identifier, "message": "characteristic not found"})
                return
            payload = bytes.fromhex(command.get("payload_hex") or "")
            try:
                await client.write_gatt_char(characteristic, payload, response=not command.get("without_response", False))
            except Exception as error:
                output.emit({"event": "error", "id": identifier, "message": str(error)[:200]})
                return
            output.emit({"event": "written", "id": identifier})
            return
        if operation == "enumerate":
            try:
                await client.get_services()
            except Exception:
                pass
            output.emit({"event": "services", "id": identifier, "services": service_rows(client.services)})
            return
        if operation in ("observe", "subscribe"):
            characteristic = find_characteristic(client, command.get("service"), command.get("characteristic"))
            if characteristic is None:
                output.emit({"event": "error", "id": identifier, "message": "characteristic not found"})
                return
            maximum = int(command.get("max_notifications") or 0)
            received = 0
            finished = asyncio.Event()
            stop_reason = {"value": "deadline"}

            def on_notification(_characteristic, data):
                nonlocal received
                received += 1
                output.emit(
                    {
                        "event": "notification",
                        "id": identifier,
                        "ts": now(),
                        "payload_hex": bytes(data).hex(),
                    }
                )
                if maximum > 0 and received >= maximum:
                    stop_reason["value"] = "buffer_full"
                    loop.call_soon_threadsafe(finished.set)

            try:
                await client.start_notify(characteristic, on_notification)
            except Exception as error:
                output.emit({"event": "error", "id": identifier, "message": str(error)[:200]})
                return
            seconds = float(command.get("seconds") or 0)
            try:
                await asyncio.wait_for(finished.wait(), timeout=seconds)
            except asyncio.TimeoutError:
                pass
            try:
                await client.stop_notify(characteristic)
            except Exception:
                pass
            output.emit({"event": "window_end", "id": identifier, "stop_reason": stop_reason["value"]})
            return
        if operation == "disconnect":
            output.emit({"event": "disconnected", "id": identifier})
            stopping.set()
            return
        output.emit({"event": "error", "id": identifier, "message": "unsupported op"})

    async def read_commands():
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        while not stopping.is_set():
            line = await reader.readline()
            if not line:
                break
            text = line.decode("utf-8").strip()
            if text == "":
                continue
            try:
                command = json.loads(text)
            except Exception:
                output.emit({"event": "error", "message": "the command was not JSON"})
                continue
            if not isinstance(command, dict):
                output.emit({"event": "error", "message": "the command was not a JSON object"})
                continue
            await handle(command)

    try:
        await read_commands()
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
    return 0


def main():
    try:
        return asyncio.run(run(sys.argv[1:]))
    except Exception as error:  # pragma: no cover - defensive
        sys.stderr.write(
            json.dumps({"event": "error", "message": "bridge failure: %s" % type(error).__name__}) + "\n"
        )
        return 3


if __name__ == "__main__":
    sys.exit(main())
