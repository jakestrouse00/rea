#!/usr/bin/env python3
"""REA protocol probe runner.

One connection per process. A single JSON request line arrives on stdin and
exactly one JSON answer line leaves on stdout; diagnostics go to stderr. The
runner owns the socket so the deny-default sandbox profile REA wraps around it
is what bounds the network side effect.

The answer carries lengths and response bytes only. REA hashes and sketches
those bytes in its own process and drops them; the runner never interprets,
parses, or echoes a reply as text.

Standard library only, so no caller-managed site packages are needed:

    "$REA_PROTOLEARN_PYTHON" -I -B "$REA_PROTOLEARN_BRIDGE_DIR/probe_runner.py"
"""

from __future__ import annotations

import base64
import json
import socket
import sys

PROTOCOL = 1
MAX_FRAME_BYTES = 1 << 20
MAX_STEPS = 32
MAX_SEND_BYTES = 4096
MAX_RESPONSE_BYTES = 16384
MAX_TOTAL_RESPONSE_BYTES = 262144
MAX_TIMEOUT_MS = 120000
RECV_CHUNK = 65536


class ProbeRefusal(Exception):
    """A job REA must not retry unchanged."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def answer(job_id, result=None, refusal=None) -> dict:
    frame = {"protocol": PROTOCOL, "job_id": job_id, "ok": refusal is None}
    if refusal is None:
        frame["result"] = result
    else:
        frame["error"] = {"code": refusal.code, "message": refusal.message}
    return frame


def emit(frame: dict) -> None:
    payload = json.dumps(frame, separators=(",", ":"))
    if len(payload.encode("utf-8")) > MAX_FRAME_BYTES:
        payload = json.dumps(
            {
                "protocol": PROTOCOL,
                "job_id": frame.get("job_id"),
                "ok": False,
                "error": {
                    "code": "job_failed",
                    "message": "the answer exceeded the transport frame budget",
                },
            },
            separators=(",", ":"),
        )
    sys.stdout.write(payload + "\n")
    sys.stdout.flush()


def bounded_int(request: dict, name: str, default: int, maximum: int) -> int:
    value = request.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ProbeRefusal("invalid_request", f"{name} must be a positive integer")
    if value > maximum:
        raise ProbeRefusal("invalid_request", f"{name} exceeds the runner's bound")
    return value


def endpoint_of(request: dict) -> tuple[str, int]:
    endpoint = request.get("endpoint")
    if not isinstance(endpoint, dict):
        raise ProbeRefusal("invalid_request", "endpoint must be an object")
    host = endpoint.get("host")
    port = endpoint.get("port")
    if not isinstance(host, str) or host == "":
        raise ProbeRefusal("invalid_request", "endpoint.host must be a nonempty string")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ProbeRefusal("invalid_request", "endpoint.port must be an integer from 1 to 65535")
    return host, port


def steps_of(request: dict) -> list[dict]:
    steps = request.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ProbeRefusal("invalid_request", "steps must be a nonempty array")
    if len(steps) > MAX_STEPS:
        raise ProbeRefusal("invalid_request", "steps exceed the runner's bound")
    prepared = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ProbeRefusal("invalid_request", f"steps[{index}] must be an object")
        template = step.get("bytes_hex")
        if not isinstance(template, str) or template == "":
            raise ProbeRefusal("invalid_request", f"steps[{index}].bytes_hex must be a nonempty string")
        try:
            payload = bytes.fromhex(template)
        except ValueError as cause:
            raise ProbeRefusal(
                "invalid_request", f"steps[{index}].bytes_hex is not hexadecimal"
            ) from cause
        if len(payload) > MAX_SEND_BYTES:
            raise ProbeRefusal(
                "invalid_request", f"steps[{index}] exceeds the runner's send bound"
            )
        wait = step.get("wait_for_response", True)
        if not isinstance(wait, bool):
            raise ProbeRefusal(
                "invalid_request", f"steps[{index}].wait_for_response must be a boolean"
            )
        prepared.append({"ordinal": index, "payload": payload, "wait": wait})
    return prepared


def read_reply(connection: socket.socket, read_timeout_s: float, budget: int):
    """Read up to budget bytes; report truncation and an idle timeout separately."""
    received = bytearray()
    timed_out = False
    truncated = False
    connection.settimeout(read_timeout_s)
    while True:
        remaining = budget - len(received)
        if remaining <= 0:
            truncated = True
            break
        try:
            chunk = connection.recv(min(remaining, RECV_CHUNK))
        except socket.timeout:
            timed_out = len(received) == 0
            break
        except (ConnectionResetError, BrokenPipeError):
            break
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received), truncated, timed_out


def handle(request) -> dict:
    if not isinstance(request, dict):
        raise ProbeRefusal("invalid_request", "the request must be one JSON object")
    if request.get("protocol") != PROTOCOL:
        raise ProbeRefusal("invalid_request", "the request does not carry protocol 1")
    host, port = endpoint_of(request)
    steps = steps_of(request)
    connect_timeout_s = bounded_int(request, "connect_timeout_ms", 10000, MAX_TIMEOUT_MS) / 1000.0
    read_timeout_s = bounded_int(request, "read_timeout_ms", 10000, MAX_TIMEOUT_MS) / 1000.0
    per_step_budget = bounded_int(
        request, "max_response_bytes", MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES
    )
    total_budget = bounded_int(
        request, "max_total_response_bytes", MAX_TOTAL_RESPONSE_BYTES, MAX_TOTAL_RESPONSE_BYTES
    )
    try:
        connection = socket.create_connection((host, port), timeout=connect_timeout_s)
    except OSError as cause:
        raise ProbeRefusal(
            "connect_failed", f"the lab endpoint refused a connection: {type(cause).__name__}"
        ) from cause
    results = []
    total_received = 0
    try:
        for step in steps:
            response = b""
            truncated = False
            timed_out = False
            error_code = None
            if step["wait"]:
                budget = min(per_step_budget, max(0, total_budget - total_received))
                try:
                    connection.sendall(step["payload"])
                except OSError:
                    error_code = "send_failed"
                else:
                    try:
                        response, truncated, timed_out = read_reply(
                            connection, read_timeout_s, budget
                        )
                    except OSError:
                        error_code = "read_failed"
                total_received += len(response)
            else:
                try:
                    connection.sendall(step["payload"])
                except OSError:
                    error_code = "send_failed"
            results.append(
                {
                    "ordinal": step["ordinal"],
                    "sent_bytes": len(step["payload"]),
                    "response_bytes": len(response),
                    "response_base64": base64.b64encode(response).decode("ascii")
                    if response
                    else None,
                    "truncated": truncated,
                    "timed_out": timed_out,
                    "error_code": error_code,
                }
            )
            if error_code is not None:
                break
    finally:
        connection.close()
    return {
        "connected": True,
        "steps": results,
        "total_response_bytes": total_received,
    }


def main() -> int:
    line = sys.stdin.readline(MAX_FRAME_BYTES + 2)
    if not line:
        sys.stderr.write("rea-protolearn-runner: no request on stdin\n")
        return 2
    job_id = None
    try:
        request = json.loads(line)
    except ValueError:
        emit(answer(job_id, refusal=ProbeRefusal("invalid_request", "the request was not one JSON frame")))
        return 0
    if isinstance(request, dict):
        job_id = request.get("job_id")
    try:
        result = handle(request)
    except ProbeRefusal as refusal:
        emit(answer(job_id, refusal=refusal))
        return 0
    except Exception as cause:  # noqa: BLE001 - one job must always answer
        emit(
            answer(
                job_id,
                refusal=ProbeRefusal("job_failed", f"{type(cause).__name__}: {cause}"),
            )
        )
        return 0
    emit(answer(job_id, result=result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
