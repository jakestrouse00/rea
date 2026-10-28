"""Offline tests for the REA protocol probe runner.

A loopback socket server in this process stands in for a lab service, so the
runner's framing, bounds, truncation, timeout, and refusal rules are exercised
without any external service. A passing run says nothing about any real lab
service; it establishes only the runner's own contract.
"""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import socket
import threading
import unittest
from pathlib import Path
from unittest import mock

BRIDGE_PATH = Path(__file__).with_name("probe_runner.py")


def load_bridge():
    spec = importlib.util.spec_from_file_location("rea_probe_runner", BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


bridge = load_bridge()


class FakeLab:
    """One loopback listener that answers each newline-framed request."""

    def __init__(self, respond):
        self.respond = respond
        self.received = []
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        self._listener.close()
        self._thread.join(timeout=2.0)
        return False

    def _serve(self):
        try:
            connection, _ = self._listener.accept()
        except OSError:
            return
        buffer = b""
        with connection:
            connection.settimeout(2.0)
            while True:
                try:
                    chunk = connection.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    message = f"{line.decode('ascii')}\n".encode("ascii")
                    self.received.append(message)
                    reply = self.respond(message)
                    if reply is None:
                        continue
                    try:
                        connection.sendall(reply)
                    except OSError:
                        return


def request(port, steps, **limits):
    body = {
        "protocol": 1,
        "job_id": "00000000-0000-4000-8000-000000000000",
        "endpoint": {"host": "127.0.0.1", "port": port},
        "steps": steps,
        "connect_timeout_ms": 2000,
        "read_timeout_ms": 250,
        "max_response_bytes": 16384,
        "max_total_response_bytes": 262144,
    }
    body.update(limits)
    return body


def step(template="01\n", wait=True):
    return {"bytes_hex": template.encode("ascii").hex(), "wait_for_response": wait}


class ProbeRunnerTests(unittest.TestCase):
    def test_reports_lengths_and_exact_reply_bytes_per_step(self):
        replies = {b"HELLO\n": b"OK\n", b"NEXT\n": b"READY\n"}
        with FakeLab(lambda message: replies.get(message)) as lab:
            result = bridge.handle(
                request(lab.port, [step("HELLO\n"), step("NEXT\n")])
            )
        self.assertTrue(result["connected"])
        self.assertEqual([s["sent_bytes"] for s in result["steps"]], [6, 5])
        self.assertEqual([s["response_bytes"] for s in result["steps"]], [3, 6])
        self.assertEqual(
            base64.b64decode(result["steps"][1]["response_base64"]), b"READY\n"
        )
        self.assertEqual(result["total_response_bytes"], 9)
        self.assertFalse(any(s["truncated"] for s in result["steps"]))
        self.assertFalse(any(s["timed_out"] for s in result["steps"]))

    def test_marks_a_reply_that_exceeds_the_per_step_bound_as_truncated(self):
        with FakeLab(lambda _message: b"A" * 4000) as lab:
            result = bridge.handle(
                request(lab.port, [step()], max_response_bytes=64)
            )
        outcome = result["steps"][0]
        self.assertEqual(outcome["response_bytes"], 64)
        self.assertTrue(outcome["truncated"])

    def test_reports_an_idle_service_as_a_timeout_with_no_bytes(self):
        with FakeLab(lambda _message: None) as lab:
            result = bridge.handle(request(lab.port, [step()]))
        outcome = result["steps"][0]
        self.assertEqual(outcome["response_bytes"], 0)
        self.assertTrue(outcome["timed_out"])
        self.assertIsNone(outcome["response_base64"])

    def test_stops_reading_a_reply_without_waiting_for_a_close(self):
        with FakeLab(lambda _message: b"PONG") as lab:
            result = bridge.handle(request(lab.port, [step()]))
        self.assertFalse(result["steps"][0]["timed_out"])
        self.assertEqual(result["steps"][0]["response_bytes"], 4)

    def test_a_step_that_waits_for_no_reply_sends_only(self):
        replies = {b"PING\n": None, b"NEXT\n": b"AFTER\n"}
        with FakeLab(lambda message: replies.get(message)) as lab:
            result = bridge.handle(
                request(lab.port, [step("PING\n", wait=False), step("NEXT\n")])
            )
        self.assertEqual(result["steps"][0]["response_bytes"], 0)
        self.assertIsNone(result["steps"][0]["response_base64"])
        self.assertEqual(result["steps"][1]["response_bytes"], 6)

    def test_total_budget_bounds_a_later_step(self):
        with FakeLab(lambda message: b"B" * 40 if message == b"02\n" else b"A" * 40) as lab:
            result = bridge.handle(
                request(
                    lab.port,
                    [step("01\n"), step("02\n")],
                    max_response_bytes=64,
                    max_total_response_bytes=48,
                )
            )
        self.assertEqual(result["steps"][0]["response_bytes"], 40)
        self.assertEqual(result["steps"][1]["response_bytes"], 8)
        self.assertTrue(result["steps"][1]["truncated"])

    def test_refuses_a_closed_endpoint_without_naming_it(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        with self.assertRaises(bridge.ProbeRefusal) as caught:
            bridge.handle(request(port, [step()]))
        self.assertEqual(caught.exception.code, "connect_failed")
        self.assertNotIn("127.0.0.1", str(caught.exception))

    def test_refuses_malformed_steps_before_opening_a_socket(self):
        cases = [
            {"steps": []},
            {"steps": [{"bytes_hex": "zz"}]},
            {"steps": [step()] * (bridge.MAX_STEPS + 1)},
            {"steps": [{"bytes_hex": "01" * (bridge.MAX_SEND_BYTES + 1)}]},
            {"steps": [{"bytes_hex": "01", "wait_for_response": "yes"}]},
            {"endpoint": {"host": "", "port": 1}, "steps": [step()]},
            {"endpoint": {"host": "127.0.0.1", "port": 0}, "steps": [step()]},
            {"max_response_bytes": bridge.MAX_RESPONSE_BYTES + 1, "steps": [step()]},
        ]
        for override in cases:
            body = request(1, [step()])
            for key, value in override.items():
                body[key] = value
            with self.subTest(override=override):
                with self.assertRaises(bridge.ProbeRefusal) as caught:
                    bridge.handle(body)
                self.assertEqual(caught.exception.code, "invalid_request")


class ProbeRunnerMainTests(unittest.TestCase):
    def run_main(self, payload):
        stdout = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(payload)), mock.patch(
            "sys.stdout", stdout
        ):
            code = bridge.main()
        return code, stdout.getvalue()

    def test_answers_one_frame_for_a_connection_refusal(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        code, text = self.run_main(json.dumps(request(port, [step()])) + "\n")
        self.assertEqual(code, 0)
        frame = json.loads(text)
        self.assertEqual(frame["protocol"], 1)
        self.assertFalse(frame["ok"])
        self.assertEqual(frame["error"]["code"], "connect_failed")

    def test_answers_a_malformed_request_instead_of_crashing(self):
        code, text = self.run_main("{not json\n")
        self.assertEqual(code, 0)
        frame = json.loads(text)
        self.assertFalse(frame["ok"])
        self.assertEqual(frame["error"]["code"], "invalid_request")

    def test_answers_a_request_that_is_not_an_object(self):
        code, text = self.run_main("[]\n")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["error"]["code"], "invalid_request")

    def test_refuses_a_request_without_the_protocol_version(self):
        body = request(1, [step()])
        body.pop("protocol")
        code, text = self.run_main(json.dumps(body) + "\n")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["error"]["code"], "invalid_request")

    def test_reports_a_missing_request_on_stderr_only(self):
        code, text = self.run_main("")
        self.assertEqual(code, 2)
        self.assertEqual(text, "")


if __name__ == "__main__":
    unittest.main()
