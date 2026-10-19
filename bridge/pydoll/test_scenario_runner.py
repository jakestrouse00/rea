"""Source-owned tests for the pydoll scenario bridge's pure protocol helpers."""

import asyncio
import enum
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock


def stand_in(name, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


class FakeKey(tuple, enum.Enum):
    ENTER = ("Enter", 13)
    ESCAPE = ("Escape", 27)
    SPACE = ("Space", 32)
    ARROWLEFT = ("ArrowLeft", 37)


class FakePageLoadState(str, enum.Enum):
    COMPLETE = "complete"
    INTERACTIVE = "interactive"


def load_scenario_runner():
    fake_exceptions = stand_in(
        "pydoll.exceptions",
        BrowserNotRunning=type("BrowserNotRunning", (Exception,), {}),
        CommandExecutionTimeout=type("CommandExecutionTimeout", (Exception,), {}),
        CommandFailed=type("CommandFailed", (Exception,), {}),
        ElementNotInteractable=type("ElementNotInteractable", (Exception,), {}),
        ElementNotVisible=type("ElementNotVisible", (Exception,), {}),
        NavigationError=type("NavigationError", (Exception,), {}),
        NetworkError=type("NetworkError", (Exception,), {}),
        PageLoadTimeout=type("PageLoadTimeout", (Exception,), {}),
        WebSocketConnectionClosed=type("WebSocketConnectionClosed", (Exception,), {}),
    )
    commands = stand_in(
        "pydoll.commands",
        AccessibilityCommands=object,
        EmulationCommands=object,
        InputCommands=object,
        NetworkCommands=object,
        PageCommands=object,
    )
    constants = stand_in(
        "pydoll.constants",
        CHAR_TO_KEY_INFO={"a": ("a", "KeyA", 65), " ": (" ", "Space", 32)},
        PageLoadState=FakePageLoadState,
    )
    network_events = stand_in(
        "pydoll.protocol.network.events",
        NetworkEvent=enum.Enum(
            "NetworkEvent",
            {name: name for name in [
                "REQUEST_WILL_BE_SENT", "RESPONSE_RECEIVED", "LOADING_FINISHED",
                "LOADING_FAILED", "WEBSOCKET_CREATED", "WEBSOCKET_FRAME_RECEIVED",
                "WEBSOCKET_FRAME_SENT", "WEBSOCKET_CLOSED"]},
        ),
    )
    page_events = stand_in(
        "pydoll.protocol.page.events",
        PageEvent=enum.Enum("PageEvent", {name: name for name in [
            "FRAME_NAVIGATED", "LOAD_EVENT_FIRED", "DOM_CONTENT_EVENT_FIRED"]}),
    )
    runtime_events = stand_in(
        "pydoll.protocol.runtime.events",
        RuntimeEvent=enum.Enum("RuntimeEvent", {name: name for name in [
            "CONSOLE_API_CALLED", "EXCEPTION_THROWN"]}),
    )
    browser = stand_in("pydoll.browser", __path__=[])
    chromium = stand_in("pydoll.browser.chromium", __path__=[])
    chrome = stand_in("pydoll.browser.chromium.chrome", Chrome=object)
    input_types = stand_in(
        "pydoll.protocol.input.types",
        KeyEventType=enum.Enum("KeyEventType", {name: name for name in ["KEY_DOWN", "KEY_UP"]}),
    )
    page_types = stand_in("pydoll.protocol.page.types", ScreenshotFormat=object)
    runtime_types = stand_in(
        "pydoll.protocol.runtime.types",
        CallArgument=lambda value=None: {"value": value},
    )
    protocol = stand_in("pydoll.protocol", __path__=[])
    inputs = stand_in("pydoll.protocol.input", __path__=[])
    network = stand_in("pydoll.protocol.network", __path__=[])
    page = stand_in("pydoll.protocol.page", __path__=[])
    runtime = stand_in("pydoll.protocol.runtime", __path__=[])
    fake_pydoll = stand_in("pydoll", ChromiumOptions=object, Key=FakeKey)
    stand_ins = {
        "pydoll": fake_pydoll,
        "pydoll.browser": browser,
        "pydoll.browser.chromium": chromium,
        "pydoll.browser.chromium.chrome": chrome,
        "pydoll.commands": commands,
        "pydoll.constants": constants,
        "pydoll.exceptions": fake_exceptions,
        "pydoll.protocol": protocol,
        "pydoll.protocol.input": inputs,
        "pydoll.protocol.input.types": input_types,
        "pydoll.protocol.network": network,
        "pydoll.protocol.network.events": network_events,
        "pydoll.protocol.page": page,
        "pydoll.protocol.page.events": page_events,
        "pydoll.protocol.page.types": page_types,
        "pydoll.protocol.runtime": runtime,
        "pydoll.protocol.runtime.events": runtime_events,
        "pydoll.protocol.runtime.types": runtime_types,
    }
    spec = importlib.util.spec_from_file_location(
        "rea_pydoll_scenario_runner",
        os.path.join(os.path.dirname(__file__), "scenario_runner.py"),
    )
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, stand_ins):
        spec.loader.exec_module(module)
    return module


scenario_runner = load_scenario_runner()


def capture_stdout(callable, *args, **kwargs):
    original = sys.stdout
    sys.stdout = io.StringIO()
    try:
        outcome = callable(*args, **kwargs)
    finally:
        text = sys.stdout.getvalue()
        sys.stdout = original
    return outcome, text


def event_lines(text):
    return [json.loads(line) for line in text.splitlines() if line]


class TruncationTests(unittest.TestCase):
    def test_ascii_under_limit_passes_through(self):
        text, truncated = scenario_runner.truncate_utf8("short", 10)
        self.assertEqual((text, truncated), ("short", False))

    def test_ascii_over_limit_cuts(self):
        text, truncated = scenario_runner.truncate_utf8("x" * 10, 4)
        self.assertEqual((text, truncated), ("xxxx", True))

    def test_utf8_cut_keeps_character_boundaries(self):
        text, truncated = scenario_runner.truncate_utf8("ä" * 3, 5)
        self.assertEqual(text, "ä" * 2)
        self.assertTrue(truncated)


class PngDimensionTests(unittest.TestCase):
    IHDR_TAIL = b"\x00\x00\x00\x0dIHDR"

    def test_parses_ihdr(self):
        width, height = scenario_runner.png_dimensions(
            b"\x89PNG\r\n\x1a\n" + self.IHDR_TAIL + (16).to_bytes(4, "big") + (9).to_bytes(4, "big") + b"xx")
        self.assertEqual((width, height), (16, 9))

    def test_short_payload_answers_null(self):
        self.assertEqual(scenario_runner.png_dimensions(b"PN"), (None, None))

    def test_wrong_signature_answers_null(self):
        payload = b"\x89PNG\r\n\x1b\n" + self.IHDR_TAIL + (16).to_bytes(4, "big") + (9).to_bytes(4, "big")
        self.assertEqual(scenario_runner.png_dimensions(payload), (None, None))


class CookieTests(unittest.TestCase):
    def test_same_site_passes_through_verbatim(self):
        record = scenario_runner.cookie_record(
            {"name": "c", "value": "v", "domain": ".x.com", "path": "/",
             "secure": True, "httpOnly": False, "sameSite": "Lax"})
        self.assertEqual(record["same_site"], "Lax")
        self.assertEqual(record["same_site_raw"], "Lax")

    def test_missing_same_site_maps_to_none_with_null_raw(self):
        record = scenario_runner.cookie_record({"name": "c", "value": "v"})
        self.assertEqual(record["same_site"], "None")
        self.assertIsNone(record["same_site_raw"])

    def test_seed_param_maps_representable_same_site(self):
        param, same_site = scenario_runner.cookie_to_param(
            {"name": "n", "value": "v", "domain": "x.com", "same_site": "Strict"})
        self.assertEqual(param["sameSite"], "Strict")
        self.assertEqual(same_site, "Strict")

    def test_seed_param_omits_unusable_same_site_but_admits_it(self):
        param, same_site = scenario_runner.cookie_to_param(
            {"name": "n", "value": "v", "same_site": "weird"})
        self.assertNotIn("sameSite", param)
        self.assertEqual(same_site, "weird")

    def test_seed_param_requires_strings(self):
        with self.assertRaises(scenario_runner.ProtocolError) as raised:
            scenario_runner.cookie_to_param({"name": "n"})
        self.assertEqual(raised.exception.reason, "bad_params")


class StorageEntryTests(unittest.TestCase):
    def test_pairs_become_records_past_the_limit_are_flagged(self):
        entries, truncated = scenario_runner.storage_entry_records([["a", "1"], ["b", "2"]], limit=1)
        self.assertEqual(entries, [{"name": "a", "value": "1"}])
        self.assertTrue(truncated)

    def test_malformed_pairs_dropped(self):
        entries, truncated = scenario_runner.storage_entry_records([["a", "1"], "bad"])
        self.assertEqual([entry["name"] for entry in entries], ["a"])
        self.assertFalse(truncated)


class RequestUrlTests(unittest.TestCase):
    def test_string_query_appends_mark(self):
        self.assertEqual(
            scenario_runner.build_request_url({"url": "https://x.test/p", "query": "b=2"}),
            "https://x.test/p?b=2")
        self.assertEqual(
            scenario_runner.build_request_url({"url": "https://x.test/p?c=1", "query": "b=2"}),
            "https://x.test/p?c=1&b=2")

    def test_object_query_urlencodes_pairs(self):
        self.assertEqual(
            scenario_runner.build_request_url({"url": "https://x.test/p", "query": {"a": "1 2"}}),
            "https://x.test/p?a=1+2")

    def test_missing_url_is_bad_params(self):
        with self.assertRaises(scenario_runner.ProtocolError) as raised:
            scenario_runner.build_request_url({})
        self.assertEqual(raised.exception.reason, "bad_params")


class KeyTranslationTests(unittest.TestCase):
    def test_named_keys_use_the_enum_spelling(self):
        for name in ("Enter", "Escape", "ArrowLeft", "Space"):
            translation = scenario_runner.key_translation(name)
            self.assertEqual(translation["kind"], "enum")
            self.assertEqual(translation["name"], name)
            self.assertEqual(translation["vkey"], FakeKey[name.upper()].value[1])

    def test_printable_single_characters_carry_text(self):
        translation = scenario_runner.key_translation("a")
        self.assertEqual(translation["kind"], "char")
        self.assertEqual(translation["code"], "KeyA")

    def test_unknown_multi_character_names_are_unsupported(self):
        with self.assertRaises(scenario_runner.ProtocolError) as raised:
            scenario_runner.key_translation("VolumeUp")
        self.assertEqual(raised.exception.reason, "key_input_unsupported")


class EndpointTests(unittest.TestCase):
    def test_loopback_http_endpoint_parses(self):
        self.assertEqual(scenario_runner.parse_cdp_endpoint("http://127.0.0.1:9222"), ("127.0.0.1", 9222))

    def test_non_loopback_host_is_rejected(self):
        with self.assertRaises(scenario_runner.ProtocolError) as raised:
            scenario_runner.parse_cdp_endpoint("http://example.com:9222")
        self.assertEqual(raised.exception.reason, "bad_params")

    def test_missing_port_is_rejected(self):
        with self.assertRaises(scenario_runner.ProtocolError):
            scenario_runner.parse_cdp_endpoint("http://127.0.0.1")


class LocatorTests(unittest.TestCase):
    def test_test_id_is_quoted_css(self):
        selector = scenario_runner.locator_selector({"kind": "test_id", "value": 'has"quote'})
        self.assertEqual(selector, '[data-testid="' + 'has\\"quote' + '"]')

    def test_css_passes_through(self):
        self.assertEqual(
            scenario_runner.locator_selector({"kind": "css", "selector": "main .a"}), "main .a")

    def test_unsupported_shape_is_bad_params(self):
        with self.assertRaises(scenario_runner.ProtocolError) as raised:
            scenario_runner.locator_selector({"kind": "xpath", "selector": "//div"})
        self.assertEqual(raised.exception.reason, "bad_params")

    def test_role_selector_maps_small_role_tags(self):
        self.assertEqual(scenario_runner.role_selector({"role": "button"}), "button,[role=button]")
        with self.assertRaises(scenario_runner.ProtocolError):
            scenario_runner.role_selector({"role": "window"})


class VersionFieldTests(unittest.TestCase):
    def test_browser_field_wins(self):
        self.assertEqual(
            scenario_runner.connect_version_field({"Browser": "Chrome/141.0.7390.55"}),
            "Chrome/141.0.7390.55")

    def test_user_agent_fallback(self):
        self.assertEqual(
            scenario_runner.connect_version_field(
                {"User-Agent": "Mozilla/5.0 (x) Chrome/140.0.0.0 Safari/537"}), "Chrome/140.0.0.0")

    def test_unknown(self):
        self.assertEqual(scenario_runner.connect_version_field({}), "unknown")


class OriginEnumerationTests(unittest.TestCase):
    def test_cookie_origins_are_derived_with_both_schemes(self):
        origins = scenario_runner.origins_from_cookies([{"domain": ".Example.com"}], "https://app.test/home")
        self.assertEqual(origins[0], "https://app.test")
        self.assertIn("https://example.com", origins)
        self.assertIn("http://example.com", origins)

    def test_current_origin_is_deduplicated_and_first(self):
        origins = scenario_runner.origins_from_cookies([{"domain": "app.test"}], "https://app.test/x")
        self.assertEqual(origins[0], "https://app.test")

    def test_attempts_are_capped(self):
        many = [{"domain": "host" + str(index) + ".test"} for index in range(100)]
        self.assertEqual(len(scenario_runner.origins_from_cookies(many, None)), 32)


class ActionTimeoutTests(unittest.TestCase):
    def test_default_and_cap_and_floor(self):
        bridge = scenario_runner.Bridge()
        self.assertEqual(bridge.action_timeout({}, {}), 120.0)
        self.assertEqual(bridge.action_timeout({"timeout_ms": 500}, {}), 0.5)
        self.assertEqual(bridge.action_timeout({"timeout_ms": 10**8}, {}), 600.0)
        self.assertGreaterEqual(bridge.action_timeout({"timeout_ms": 1}, {}), 0.05)


class WriteLineTests(unittest.TestCase):
    def test_writes_one_flushed_json_line(self):
        _, text = capture_stdout(scenario_runner.write_line, {"id": 3, "ok": True, "result": {"a": 1}})
        self.assertEqual(event_lines(text), [{"id": 3, "ok": True, "result": {"a": 1}}])

    def test_unserializable_reply_falls_back_to_internal_error(self):
        _, text = capture_stdout(scenario_runner.write_line, {"id": 5, "result": {object}})
        lines = event_lines(text)
        self.assertEqual(lines[0]["id"], 5)
        self.assertFalse(lines[0]["ok"])
        self.assertEqual(lines[0]["error"]["reason"], "internal")

    def test_oversized_reply_answers_output_limit(self):
        original = scenario_runner.MESSAGE_LIMIT
        try:
            scenario_runner.MESSAGE_LIMIT = 64
            _, text = capture_stdout(
                scenario_runner.write_line, {"id": 7, "ok": True, "result": "z" * 200})
            lines = event_lines(text)
            self.assertEqual(lines[0]["error"]["reason"], "output_limit")
        finally:
            scenario_runner.MESSAGE_LIMIT = original


class FlushEventTests(unittest.TestCase):
    def test_events_are_line_json_with_family_and_data(self):
        bridge = scenario_runner.Bridge()
        bridge.enqueue("frames", {"kind": "frame_navigated", "url": "https://x.test/", "is_main": True})
        _, text = capture_stdout(bridge.flush_events)
        self.assertEqual(event_lines(text), [{"event": "scenario", "params": {
            "family": "frames",
            "data": {"kind": "frame_navigated", "url": "https://x.test/", "is_main": True}}}])
        self.assertEqual(len(bridge._events), 0)

    def test_oversized_event_becomes_a_marker(self):
        original = scenario_runner.MESSAGE_LIMIT
        try:
            scenario_runner.MESSAGE_LIMIT = 96
            bridge = scenario_runner.Bridge()
            bridge.enqueue("network", {"kind": "response", "url": "y" * 200})
            _, text = capture_stdout(bridge.flush_events)
            lines = event_lines(text)
            self.assertEqual(lines[0]["params"]["family"], "network")
            self.assertEqual(lines[0]["params"]["data"]["kind"], "event_oversized")
        finally:
            scenario_runner.MESSAGE_LIMIT = original


class EventQueueOverflowTests(unittest.TestCase):
    def test_overflow_drops_are_reported_with_a_count(self):
        original = scenario_runner.EVENT_QUEUE_LIMIT
        try:
            scenario_runner.EVENT_QUEUE_LIMIT = 4
            bridge = scenario_runner.Bridge()
            for index in range(5):
                bridge.enqueue(
                    "network",
                    {"kind": "request", "request_id": str(index),
                     "url": "https://x.test/" + str(index), "method": "GET",
                     "resource_type": "Document"},
                )
            self.assertEqual(len(bridge._events), 4)
            _, text = capture_stdout(bridge.flush_events)
            lines = event_lines(text)
            self.assertEqual(len(lines), 5)
            self.assertEqual(
                lines[-1],
                {"event": "scenario", "params": {
                    "family": "omissions",
                    "data": {"kind": "event_queue_overflow", "count": 1}}})
            marker_after = [line for line in lines[:-1]
                            if line["params"]["data"].get("kind") == "event_queue_overflow"]
            self.assertEqual(marker_after, [])
        finally:
            scenario_runner.EVENT_QUEUE_LIMIT = original

    def test_drops_accumulate_across_flushes_and_the_marker_resets_the_count(self):
        original = scenario_runner.EVENT_QUEUE_LIMIT
        try:
            scenario_runner.EVENT_QUEUE_LIMIT = 2
            bridge = scenario_runner.Bridge()
            for index in range(4):
                bridge.enqueue("frames", {"kind": "frame_navigated",
                                          "url": "https://x.test/" + str(index), "is_main": True})
            bridge.enqueue("frames", {"kind": "frame_navigated",
                                      "url": "https://x.test/late", "is_main": True})
            _, text = capture_stdout(bridge.flush_events)
            lines = event_lines(text)
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[-1]["params"]["data"], {"kind": "event_queue_overflow", "count": 3})
            self.assertEqual(len(bridge._events), 0)
        finally:
            scenario_runner.EVENT_QUEUE_LIMIT = original

    def test_response_event_without_body_capture_emits_headers_only(self):
        bridge = scenario_runner.Bridge()
        bridge.on_response_received({"params": {"requestId": "r1", "response": {
            "url": "https://x.test/", "status": 200, "statusText": "OK",
            "mimeType": "text/html", "protocol": "h2", "headers": {"x": "1"}}}})
        self.assertEqual(bridge._events[0]["family"], "network")
        data = bridge._events[0]["data"]
        self.assertEqual(data["kind"], "response")
        self.assertEqual(data["status"], 200)
        self.assertNotIn("body", data)

    def test_response_body_capture_defers_to_loading_finished(self):
        bridge = scenario_runner.Bridge()
        bridge._capture_response_bodies = True
        bridge.on_response_received({"params": {"requestId": "r1", "response": {
            "url": "https://x.test/", "status": 200, "statusText": "OK",
            "mimeType": "text/html", "protocol": "h2", "headers": {}}}})
        self.assertEqual(len(bridge._events), 0)
        self.assertEqual(bridge._response_pending["r1"]["url"], "https://x.test/")

    def test_loading_failed_reports_url_from_pending_response(self):
        bridge = scenario_runner.Bridge()
        bridge._capture_response_bodies = True
        bridge._response_pending["r9"] = {"url": "https://x.test/missing"}
        bridge.on_loading_failed({"params": {"requestId": "r9", "errorText": "net::ERR_..."}})
        data = bridge._events[0]["data"]
        self.assertEqual(data["kind"], "request_failed")
        self.assertEqual(data["url"], "https://x.test/missing")

    def test_console_event_joins_argument_values(self):
        bridge = scenario_runner.Bridge()
        bridge.on_console({"params": {"type": "warning", "args": [
            {"type": "string", "value": "boom"}, {"type": "number", "value": 7}]}})
        data = bridge._events[0]["data"]
        self.assertEqual(data, {"kind": "console", "level": "warning", "text": "boom 7", "url": ""})

    def test_page_error_event_maps_message_stack_and_url(self):
        bridge = scenario_runner.Bridge()
        bridge.on_exception({"params": {"exceptionDetails": {
            "text": "Uncaught", "exception": {"description": "TypeError: q"},
            "stackTrace": {"callFrames": [{"url": "https://x.test/s.js", "lineNumber": 9,
                                           "columnNumber": 3, "functionName": "go"}]}}}})
        data = bridge._events[0]["data"]
        self.assertEqual(data["kind"], "page_error")
        self.assertEqual(data["message"], "TypeError: q")
        self.assertEqual(data["url"], "https://x.test/s.js")
        self.assertIn("s.js:9:3 go", data["stack"])

    def test_frame_navigated_reports_main_frame(self):
        bridge = scenario_runner.Bridge()
        bridge.on_frame_navigated({"params": {"frame": {"id": "f1", "url": "https://x.test/a"}}})
        data = bridge._events[0]["data"]
        self.assertEqual(data, {"kind": "frame_navigated", "frame_id": "f1",
                                "url": "https://x.test/a", "is_main": True})

    def test_history_observer_marks_reload_and_navigate(self):
        bridge = scenario_runner.Bridge()
        bridge.on_history_navigation({"params": {"frame": {"id": "f", "url": "https://x.test/a"}}})
        bridge.on_history_navigation({"params": {"frame": {"id": "f", "url": "https://x.test/a"}}})
        bridge.on_history_navigation({"params": {"frame": {"id": "f", "url": "https://x.test/b"}}})
        self.assertEqual([entry["type"] for entry in bridge._history_entries],
                         ["navigate", "reload", "navigate"])
        bridge.on_history_navigation({"params": {"frame": {"id": "child", "parentId": "f",
                                                           "url": "https://x.test/c"}}})
        self.assertEqual(len(bridge._history_entries), 3)


class ReplySpillTests(unittest.TestCase):
    def test_small_reply_stays_inline(self):
        bridge = scenario_runner.Bridge()
        with tempfile.TemporaryDirectory() as session_dir:
            bridge.session_dir = session_dir
            _, text = capture_stdout(bridge.send_reply, 1, {
                "artifacts": [{"kind": "url", "raw_url": "https://x.test/"}], "notes": []})
            lines = event_lines(text)
            self.assertEqual(lines[0]["result"]["artifacts"][0]["raw_url"], "https://x.test/")
            self.assertEqual(os.listdir(session_dir), [])

    def test_oversized_storage_artifact_spills_to_session_dir(self):
        original = scenario_runner.REPLY_LIMIT
        bridge = scenario_runner.Bridge()
        try:
            scenario_runner.REPLY_LIMIT = 512
            cookies = [{"name": "c" * 60, "value": "v" * 60} for _ in range(20)]
            with tempfile.TemporaryDirectory() as session_dir:
                bridge.session_dir = session_dir
                result = {
                    "artifacts": [{"kind": "storage", "cookies": cookies,
                                   "local_storage": [], "session_storage": []}],
                    "notes": [],
                }
                _, text = capture_stdout(bridge.send_reply, 9, result)
                lines = event_lines(text)
                self.assertTrue(lines[0]["ok"])
                artifact = lines[0]["result"]["artifacts"][0]
                self.assertEqual(artifact["kind"], "storage")
                self.assertTrue(os.path.exists(artifact["path"]))
                self.assertTrue(artifact["path"].startswith(session_dir))
                self.assertIn("storage artifact was written to a file",
                              " ".join(lines[0]["result"]["notes"]))
                with open(artifact["path"], "rb") as handle:
                    blob = handle.read()
                self.assertEqual(artifact["sha256"], scenario_runner.sha256_hex(blob))
                self.assertEqual(artifact["bytes"], len(blob))
                os.unlink(artifact["path"])
        finally:
            scenario_runner.REPLY_LIMIT = original


class HandleLineTests(unittest.TestCase):
    def run_async(self, coroutine):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coroutine)
        finally:
            loop.close()

    def test_dispatch_result_is_written_as_ok_true(self):
        bridge = scenario_runner.Bridge()

        async def fake_dispatch(method, params):
            return {"notes": ["done"]}

        bridge.dispatch = fake_dispatch
        _, text = capture_stdout(
            self.run_async, bridge.handle_line(json.dumps({"id": 12, "method": "capture", "params": {}})))
        lines = event_lines(text)
        self.assertEqual(lines[0], {"id": 12, "ok": True, "result": {"notes": ["done"]}})

    def test_protocol_error_becomes_ok_false_with_reason(self):
        bridge = scenario_runner.Bridge()

        async def fake_dispatch(method, params):
            raise scenario_runner.ProtocolError("locator_not_found", "no element matched")

        bridge.dispatch = fake_dispatch
        _, text = capture_stdout(
            self.run_async, bridge.handle_line(json.dumps({"id": 13, "method": "perform", "params": {}})))
        lines = event_lines(text)
        self.assertEqual(lines[0]["error"]["reason"], "locator_not_found")
        self.assertEqual(lines[0]["id"], 13)

    def test_uncaught_failure_maps_to_internal(self):
        bridge = scenario_runner.Bridge()

        async def fake_dispatch(method, params):
            raise ZeroDivisionError()

        bridge.dispatch = fake_dispatch
        _, text = capture_stdout(
            self.run_async, bridge.handle_line(json.dumps({"id": 14, "method": "capture", "params": {}})))
        self.assertEqual(event_lines(text)[0]["error"]["reason"], "internal")

    def test_non_json_lines_are_dropped_without_output(self):
        bridge = scenario_runner.Bridge()
        _, text = capture_stdout(self.run_async, bridge.handle_line("not json"))
        self.assertEqual(text, "")

    def test_missing_id_is_dropped(self):
        bridge = scenario_runner.Bridge()
        _, text = capture_stdout(
            self.run_async, bridge.handle_line(json.dumps({"method": "capture", "params": {}})))
        self.assertEqual(text, "")

    def test_bad_shape_answers_bad_params(self):
        bridge = scenario_runner.Bridge()
        _, text = capture_stdout(
            self.run_async, bridge.handle_line(json.dumps({"id": 15, "method": 7, "params": {}})))
        self.assertEqual(event_lines(text)[0]["error"]["reason"], "bad_params")

    def test_browser_gone_stops_the_loop_for_the_next_check(self):
        bridge = scenario_runner.Bridge()

        async def fake_dispatch(method, params):
            raise scenario_runner.ProtocolError("browser_gone", "the page WebSocket closed")

        bridge.dispatch = fake_dispatch
        _, text = capture_stdout(
            self.run_async, bridge.handle_line(json.dumps({"id": 16, "method": "capture", "params": {}})))
        lines = event_lines(text)
        self.assertEqual(lines[0]["error"]["reason"], "browser_gone")
        self.assertTrue(bridge.stopping)
        self.assertEqual(bridge.exit_code, 1)

    def test_failed_open_session_releases_state(self):
        bridge = scenario_runner.Bridge()
        bridge.mode = "launch"
        bridge.tab = object()
        bridge.browser = object()

        async def fake_dispatch(method, params):
            raise scenario_runner.ProtocolError("launch_failed", "browser launch failed")

        bridge.dispatch = fake_dispatch
        _, text = capture_stdout(
            self.run_async, bridge.handle_line(json.dumps({"id": 17, "method": "open_session", "params": {}})))
        self.assertEqual(event_lines(text)[0]["error"]["reason"], "launch_failed")
        self.assertIsNone(bridge.mode)


class OnStdinClosedTests(unittest.TestCase):
    def test_eof_without_close_is_cancellation(self):
        bridge = scenario_runner.Bridge()
        bridge.on_stdin_closed()
        self.assertEqual(bridge.exit_code, 1)
        self.assertTrue(bridge.stopping)

    def test_eof_after_close_is_success(self):
        bridge = scenario_runner.Bridge()
        bridge.stopping = True
        bridge.on_stdin_closed()
        self.assertEqual(bridge.exit_code, 0)


class AdvertisingShapeTests(unittest.TestCase):
    def test_advertising_payload_shape(self):
        _, text = capture_stdout(lambda: scenario_runner.write_line(
            {"advertising": {"protocol": scenario_runner.PROTOCOL_VERSION,
                              "pydoll_version": scenario_runner.pydoll_version(),
                              "capabilities": scenario_runner.CAPABILITIES}}))
        payload = event_lines(text)[0]["advertising"]
        self.assertEqual(payload["protocol"], 1)
        self.assertEqual(sorted(payload["capabilities"]), [
            "downloads", "emulation", "keyboard", "popups", "select_option", "workers"])
        self.assertFalse(payload["capabilities"]["downloads"])
        self.assertFalse(payload["capabilities"]["popups"])
        self.assertFalse(payload["capabilities"]["workers"])


if __name__ == "__main__":
    unittest.main(verbosity=2)