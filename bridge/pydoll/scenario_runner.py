"""REA pydoll browser-scenario bridge child process (protocol version 1).

Spawned by the Node parent, which implements the other half of this contract
line-for-line. The child drives Chrome via pydoll: CDP-only, no WebDriver, no
webdriver-affecting launch flags, and ``Runtime.enable`` is sent only when the
caller requests the ``console`` or ``page-errors`` event families.

Framing
    Line-delimited UTF-8 JSON over stdio, flushed per line, both directions.
    One JSON message per line; escaped messages stay under 1 MiB
    (1048576 bytes). Nothing else is ever written to stdout. Diagnostics go
    to stderr; pydoll's own logging is pinned to WARNING there (DEBUG with
    REA_PYDOLL_BRIDGE_LOG=DEBUG).

Startup
    One advertising line immediately:
        {"advertising":{"protocol":1,"pydoll_version":"<installed>",
         "capabilities":{"emulation":true,"keyboard":true,"select_option":true,
                          "downloads":false,"popups":false,"workers":false}}}
    pydoll_version resolves the ``pydoll-python`` distribution, then
    ``pydoll``, else "unknown". Capabilities claim only implemented paths;
    downloads/popups/workers have no method here, so they are false.

Requests
    {"id":<int>,"method":"open_session|perform|capture|seed_storage|close_session",
     "params":{...}}
Replies
    {"id":<int>,"ok":true,"result":{...}} or
    {"id":<int>,"ok":false,"error":{"reason":"<snake_case_token>",
     "message":"<human text; never quotes fill/secret values>"}}
Unsolicited events
    {"event":"scenario","params":{"family":"console|network|websockets|frames|
     page-errors","data":{...}}}
    Flushed by a 250ms background pump and always before the next reply.
    The queue is bounded at 2000; when the parent stays idle across very
    heavy traffic, the oldest events are dropped and the drop is reported
    by an {"kind":"event_queue_overflow","count":N} marker (family
    "omissions") written at the next flush boundary. An event that does
    not fit in one line is replaced by a marker {"kind":"event_oversized"}
    in its own family.

open_session params
    mode "launch"|"connect"; session_dir must be an existing absolute
    directory owned by the caller (all artifact files are written there and
    nowhere else).
    launch {executable_path, headless, user_data_dir, window_size:{w,h}}:
        ChromiumOptions gets --user-data-dir and --window-size; pydoll picks
        the CDP port itself (find_free_port) and adds
        --remote-debugging-port itself. Start budget 60s wall clock.
    connect {cdp_endpoint "http://127.0.0.1:<port>", target_id}:
        /json/version and /json/list are fetched over loopback HTTP with a
        10s timeout; the matching page target is attached by a direct
        page-level WebSocket (pydoll ConnectionHandler port+target path, so
        no browser-level Runtime surface is used). The external browser is
        never stopped, killed or owned.
    environment {timezone, locale, color_scheme, reduced_motion,
                 viewport:{width,height,device_scale_factor}}:
        timezone -> Emulation.setTimezoneOverride; locale ->
        Emulation.setLocaleOverride; viewport ->
        Emulation.setDeviceMetricsOverride; color_scheme and reduced_motion
        merge into ONE Emulation.setEmulatedMedia call because each call
        replaces the previously emulated features. Applied to the attached
        page only; failures land in skipped_environment, successes in
        applied_environment.
    capture {events:[console|page-errors|network|websockets|frames],
             network:{request_body,response_body,header_values}}:
        only the domains each family needs are enabled: Network for
        network/websockets (plus body fetches), Page for frames, Runtime
        only when console or page-errors was requested.
    result
        {"product","version","target_id","initial_url","owned_browser_pid",
         "applied_environment","skipped_environment","event_domains_enabled"}
        product is always "Chromium"; version is the Browser.getVersion
        product (launch) or /json/version Browser string (connect).
        owned_browser_pid is null in connect mode. event_domains_enabled is
        the honest record of domains enabled so far; wait_until and seed
        paths may add Network/Page later, which the capture/seed notes admit
        (Accessibility is enabled transiently during its capture and never
        listed).

Event data shapes
    network
        {"kind":"request","request_id","url","method","resource_type"[,
         "headers"][,"body":str,"body_truncated":true]}
        request bodies come from the event's postData or
        Network.getRequestPostData when request_body capture is on;
        {"kind":"response","request_id","url","status","status_text",
         "mime_type","protocol"[,"headers"][,"body","body_encoding":
         "text|base64","body_truncated":true]}
        when response_body capture is off, response events are emitted at
        Network.responseReceived; when it is on they are emitted at
        Network.loadingFinished after the body fetch (a finish without a
        preceding responseReceived emits request_id only, with null url and
        status). {"kind":"request_failed","request_id","error_text"[,"url"]}
        Bodies and payloads are capped at 256 KiB with _truncated true; text
        bodies travel as text, base64 bodies stay base64 (CDP's encoding).
    websockets
        {"kind":"websocket_created","request_id","url"},
        {"kind":"websocket_frame","request_id","direction":"received|sent",
         "payload","payload_encoding":"text"[,"payload_truncated":true]}
        payload is the CDP string as received (binary frames arrive base64
        from CDP and are passed through), {"kind":"websocket_closed",...}.
    frames
        {"kind":"frame_navigated","frame_id","url","is_main"}
    console
        {"kind":"console","level","text"[,"text_truncated"],"url"}
        text joins argument values/descriptions; url is the first stack
        frame's url when CDP provided one.
    page-errors
        {"kind":"page_error","message"[,"message_truncated"],"url",
         "stack"[,"stack_truncated"]}

perform params {action, timeout_ms} (timeout_ms per request or per action;
    default 120s, hard cap 600s; expiry answers
    {"ok":false,"error":{"reason":"action_timeout"}})
    goto {destination:{url,query}, wait_until:"load"|"domcontentloaded"|"commit"}:
        load waits Page.loadEventFired via tab.go_to; domcontentloaded uses
        pydoll's PageLoadState.INTERACTIVE path (Page.domContentEventFired);
        commit sends Page.navigate via raw CDP and releases on the first
        Network.requestWillBeSent for the destination or the load event,
        recording which in notes. Query may be a raw query string or an
        object of key/value pairs; none of it is echoed in replies.
    click {locator, button, click_count}: element.click(humanize=True);
        humanize is a request only - elements found via tab.query() carry no
        Mouse instance in pydoll 3.0.0, so the raw CDP Input mouse path runs;
        noted. pydoll's click is left-button only: middle/right degrade with
        a note; click_count 2 uses double_click (two press/release pairs,
        clickCount 1 then 2); other counts degrade to a single left click.
    fill {locator, value}: element.clear() then element.insert_text(value);
        pydoll dispatches synthetic input and change events (no per-key
        events) - noted. The value travels only inside the CDP command.
    press {locator, key}: when a locator resolves it is focused first
        (DOM.focus); events go through Input.dispatchKeyEvent: named keys map
        to pydoll's Key enum ("Enter", "Escape", "ArrowLeft", "Backspace",
        "PageUp", ...); single printable characters carry text; modifier
        forms "Control+A"/"Shift+Enter"/"Meta+K" are supported (Control,
        Ctrl, Alt, Meta, Cmd, Shift); anything else answers
        key_input_unsupported.
    select_option {locator, value}: matches the option whose value attribute
        equals value on a resolved <select> (or clicks a resolved <option>),
        dispatching input+change events; missing option answers
        option_not_found. A value-text match is not implemented.
    check|uncheck {locator}: read checked first - already satisfied: no
        click, note; else click, re-read, mismatch answers ok:false
        reason check_failed with the observed boolean in the message.
    wait_for {locator, state:"attached"|"detached"|"visible"|"hidden"}:
        100ms polls until the state holds or the deadline; hidden matches
        absent-or-invisible; visibility is getBoundingClientRect + computed
        visibility/display; role locators re-run the role matcher each poll.
    wait_for_timeout {duration_ms}: cancellable sleep (hard cap 600s).
    locator shapes
        {kind:"test_id", value} -> CSS [data-testid="<value>"]
        {kind:"css", selector} -> as-is
        {kind:"role", role, name} -> no native role locator exists in pydoll
            3.0.0: a JS first-match pass over [role=<role>] plus a small
            role->tag map, with accessible-name approximation (aria-label,
            then value for inputs, then innerText, then title), builds a
            unique :nth-child CSS path that pydoll then resolves. This is
            an approximation of accessible-name computation and is noted on
            every role-locator action. Main-frame documents only; no locator
            kind traverses iframes.
    result {"final_url":<string|null after the action>,"notes":[...]};
        unresolvable locators answer reason locator_not_found.

capture params {requested:[screenshot|dom|accessibility|url|history|storage]}
    screenshot: Page.captureScreenshot (png) -> <session_dir>/screenshot-<n>.png
        (0600); width/height parsed from the PNG IHDR when possible.
    dom: DOMSnapshot.captureSnapshot (plain CDP command, empty computedStyles,
        no Runtime); when the browser rejects it, a JS outerHTML fallback
        runs. Result -> dom-<n>.json (representation "dom-snapshot-json") or
        dom-<n>.html (representation "html").
    accessibility: Accessibility.enable (no Runtime) +
        Accessibility.getFullAXTree; the whole result tree serialized to
        compact JSON -> accessibility-<n>.json.
    url: inline {"kind":"url","raw_url":<current url>}.
    history: inline {"kind":"history","length":<window.history.length|null>,
        "raw_entries":[{"type":"navigate|reload|unknown","url"}]} - maintained
        from main-frame Page.frameNavigated events observed since session
        open (consecutive identical urls marked "reload"). With no Page
        tracking at all, entries are empty, length null, and a note says so.
        Entries cap 1000.
    storage: inline {"kind":"storage","cookies":[{name,value,domain,path,
        secure,http_only,same_site,same_site_raw}],"local_storage":
        [{"origin","entries":[{name,value}]}],"session_storage":[...]} -
        cookies from Network.getCookies; same_site passes the CDP string
        through verbatim ("None" appears only when CDP omitted sameSite)
        with same_site_raw duplicating it or null; Node owns normalization.
        localStorage/sessionStorage are read per origin via
        DOMStorage.getDOMStorageItems attempts (origins derived from cookie
        domains and the current location, https and http variants, capped at
        32 attempts); when no origin answers, a current-origin-only JS read
        is the fallback (capped at 512 entries per store) and the capture
        notes record which origins answered.
    Every artifact file is 0600, capped at 16 MiB (truncated:true marks the
        digest of exactly the truncated bytes). Oversized inline storage or
        history artifacts spill to storage-<n>.json / history-<n>.json files
        when the reply would exceed the 1 MiB bound; the note records the
        spill.
    result {"artifacts":[...],"notes":[...]}; a requested kind that fails on
        every path is noted and skipped; when nothing at all could be
        captured the whole request answers artifact_failed.

seed_storage (invoked before the first navigation of a scenario)
    params {cookies:[{name,value,domain,path,secure,http_only,same_site}],
            local_storage:[{origin,entries}],
            session_storage:[{origin,entries}]}   (entries: {name:value})
    cookies -> Network.setCookies immediately (sameSite onto Strict/Lax/None;
        other spellings are seeded without it and noted).
    local/session -> Page.addScriptToEvaluateOnNewDocument installs a seed
        function that applies each origin's entries when a document of that
        origin loads, so the effect is limited to the FIRST navigation; the
        script is removed via Page.removeScriptToEvaluateOnNewDocument on
        the first main-frame Page.frameNavigated afterwards. Page domain is
        enabled for that removal listener and admitted in the seed notes.
        Origins never navigated to do not materialize their seeds; this gap
        is noted.
    result {"applied":[cookies local_storage session_storage...],"notes":[...]}

close_session params {stop_loading}
    launch: owned Chrome stopped (pydoll Browser.stop: Browser.close then
        SIGTERM with 15s grace and SIGKILL; a sync SIGTERM/SIGKILL fallback
        covers external-exit races) -> reply {"outcome":
        "terminated-owned-process","profile_removed":false}; Node removes
        the profile directory itself.
    connect: only WebSockets are closed, the external browser is never
        touched; {"outcome":"disconnected-external"}. stop_loading attempts
        Page.stopLoading at the page level and notes "page navigation stop
        applied" when it ran.
    The child exits 0 promptly after replying.

Signals / cancellation / teardown
    EOF on stdin before close_session, or SIGTERM, cancels current work: an
    owned Chrome is killed promptly (SIGTERM, 3s, SIGKILL), WebSockets close,
    no further protocol lines are written, exit code 1 (130 on
    KeyboardInterrupt). A browser killed by an external actor answers one
    {"ok":false,"error":{"reason":"browser_gone"}} then exits. Every CDP
    command carries its own deadline (60s default), every bounded write is
    capped, and wait loops are deadline-bounded. A failed open_session
    releases whatever it partially launched (owned processes are killed;
    external connections are merely detached).

Error reason tokens
    bad_params, method_unknown, session_not_open, session_already_open,
    target_not_found, launch_failed, browser_gone, cdp_command_failed,
    cdp_timeout, deadline_exceeded, action_timeout, locator_not_found,
    option_not_found, check_failed, key_input_unsupported,
    element_not_interactable, navigation_failed, script_failed,
    artifact_failed, output_limit, internal
    (locator_not_found, check_failed, action_timeout and browser_gone are
    canonical; the rest spell out honest failures this bridge can produce).
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import signal
import struct
import sys
import threading
import urllib.request
from collections import deque
from importlib import metadata as importlib_metadata
from urllib.parse import urlencode, urlsplit

try:
    from pydoll import ChromiumOptions, Key
    from pydoll.browser.chromium.chrome import Chrome
    from pydoll.commands import (
        AccessibilityCommands,
        EmulationCommands,
        InputCommands,
        NetworkCommands,
        PageCommands,
    )
    from pydoll.constants import CHAR_TO_KEY_INFO, PageLoadState
    from pydoll.exceptions import (
        BrowserNotRunning,
        CommandExecutionTimeout,
        CommandFailed,
        ElementNotInteractable,
        ElementNotVisible,
        NavigationError,
        NetworkError,
        PageLoadTimeout,
        WebSocketConnectionClosed,
    )
    from pydoll.protocol.input.types import KeyEventType
    from pydoll.protocol.network.events import NetworkEvent
    from pydoll.protocol.page.events import PageEvent
    from pydoll.protocol.page.types import ScreenshotFormat
    from pydoll.protocol.runtime.events import RuntimeEvent
    from pydoll.protocol.runtime.types import CallArgument

    PYDOLL_AVAILABLE = True
except ImportError:
    ChromiumOptions = None
    Key = None
    Chrome = None
    CHAR_TO_KEY_INFO = {}
    PageLoadState = None
    PYDOLL_AVAILABLE = False

PROTOCOL_VERSION = 1
MESSAGE_LIMIT = 1024 * 1024
REPLY_LIMIT = 900 * 1024
ARTIFACT_LIMIT = 16 * 1024 * 1024
INLINE_TEXT_LIMIT = 256 * 1024
EVENT_QUEUE_LIMIT = 2000
READ_LIMIT = 2 * MESSAGE_LIMIT
POLL_INTERVAL_SECONDS = 0.1
PUMP_INTERVAL_SECONDS = 0.25
CDP_TIMEOUT_SECONDS = 60.0
OPEN_SESSION_BUDGET_SECONDS = 120.0
CLOSE_SESSION_BUDGET_SECONDS = 75.0
CAPTURE_BUDGET_SECONDS = 120.0
SEED_BUDGET_SECONDS = 60.0
DEFAULT_ACTION_TIMEOUT_SECONDS = 120.0
HARD_ACTION_CAP_SECONDS = 600.0
HTTP_TIMEOUT_SECONDS = 10.0
HISTORY_ENTRIES_LIMIT = 1000
STORAGE_ORIGINS_LIMIT = 32
RESOLUTION_BUDGET_SECONDS = 30.0

CAPABILITIES = {
    "emulation": True,
    "keyboard": True,
    "select_option": True,
    "downloads": False,
    "popups": False,
    "workers": False,
}

ROLE_TAGS = {
    "button": "button,[role=button]",
    "link": "a,[role=link]",
    "textbox": "textarea,input,[contenteditable],[role=textbox]",
    "checkbox": "input[type=checkbox],[role=checkbox]",
    "radio": "input[type=radio],[role=radio]",
    "switch": "input[type=checkbox],[role=switch]",
    "combobox": "select,input,[role=combobox]",
    "listbox": "select,[role=listbox]",
    "tab": "[role=tab]",
    "dialog": "[role=dialog]",
    "menuitem": "[role=menuitem]",
    "option": "option,[role=option]",
    "slider": "input[type=range],[role=slider]",
    "spinbutton": "input[type=number],[role=spinbutton]",
}

MODIFIER_KEYS = {"control": 2, "ctrl": 2, "alt": 1, "meta": 4, "cmd": 4, "shift": 8}

_ROLE_FINDER_BODY = r"""(() => {
  const cfg = __CFG__;
  const cssPath = (el) => {
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && node !== document.documentElement) {
      let seg = node.tagName.toLowerCase();
      const parent = node.parentElement;
      if (parent && parent.children.length > 1) {
        const kids = parent.children;
        let index = 1;
        for (let i = 0; i < kids.length; i++) { if (kids[i] === node) { index = i + 1; break; } }
        seg += ':nth-child(' + index + ')';
      }
      parts.unshift(seg);
      node = node.parentElement;
    }
    if (parts.length === 0 && el === document.documentElement) return 'html';
    return parts.join(' > ');
  };
  const nodes = document.querySelectorAll(cfg.selector);
  for (let i = 0; i < nodes.length; i++) {
    const el = nodes[i];
    let name = '';
    const label = el.getAttribute('aria-label');
    if (label && label.trim()) name = label.trim();
    if (!name) {
      const lower = el.tagName.toLowerCase();
      if (lower === 'input' || lower === 'textarea') {
        const v = (el.value || '').trim();
        if (v) name = v.slice(0, 200);
      }
    }
    if (!name) {
      const raw = (el.innerText !== undefined && el.innerText !== null) ? el.innerText : (el.textContent || '');
      const text = String(raw).trim().slice(0, 200);
      if (text) name = text;
      else {
        const title = el.getAttribute('title') || '';
        if (title.trim()) name = title.trim();
      }
    }
    if (cfg.name === '' || name === cfg.name) {
      const rect = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      const visible = rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
      if (cfg.requireVisible && !visible) continue;
      return JSON.stringify({ path: cssPath(el), visible: !!visible });
    }
  }
  return 'null';
})()"""

_SELECTOR_STATE_BODY = r"""(() => {
  const el = document.querySelector(__SELECTOR__);
  if (!el) { return JSON.stringify({ found: false, visible: false }); }
  const rect = el.getBoundingClientRect();
  const style = getComputedStyle(el);
  const visible = rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
  return JSON.stringify({ found: true, visible: !!visible });
})()"""

_CURRENT_STORAGE_BODY = r"""(() => {
  const dump = (store, cap) => {
    const out = [];
    const n = store.length;
    for (let i = 0; i < n && i < cap; i++) {
      const k = store.key(i);
      out.push([String(k), String(store.getItem(k))]);
    }
    return { entries: out, truncated: n > cap };
  };
  const local = dump(window.localStorage, 512);
  const session = dump(window.sessionStorage, 512);
  return JSON.stringify({ origin: location.origin, truncation: local.truncated || session.truncated,
                          local: local.entries, session: session.entries });
})()"""

_SELECT_OPTION_FUNCTION = r"""function(value) {
  const el = this;
  if (!el || !el.tagName || el.tagName.toLowerCase() !== 'select') return null;
  let matched = null;
  for (let i = 0; i < el.options.length; i++) {
    el.options[i].selected = false;
    if (el.options[i].value === value && matched === null) matched = el.options[i];
  }
  if (matched === null) return false;
  matched.selected = true;
  el.value = matched.value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}"""

_SEED_STORAGE_BODY = r"""(() => {
  const seeds = __SEEDS__;
  for (let i = 0; i < seeds.length; i++) {
    const seed = seeds[i];
    if (String(seed.origin).replace(/\/+$/, '') !== location.origin) { continue; }
    const store = seed.session ? window.sessionStorage : window.localStorage;
    for (const key in seed.entries) {
      try {
        if (Object.prototype.hasOwnProperty.call(seed.entries, key)) {
          store.setItem(key, String(seed.entries[key]));
        }
      } catch (error) {}
    }
  }
})()"""


class ProtocolError(Exception):
    """Request-level failure carrying its snake_case reason token."""

    def __init__(self, reason, message=""):
        self.reason = reason
        self.message = message
        super().__init__(message)


def emit(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def write_line(payload):
    try:
        line = json.dumps(payload, allow_nan=False, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        line = None
    if line is not None:
        if len(line) + 1 <= MESSAGE_LIMIT:
            emit(line)
            return
        id_value = payload.get("id") if isinstance(payload, dict) else None
        if isinstance(id_value, int) and not isinstance(id_value, bool):
            emit('{"id":' + str(id_value) + ',"ok":false,"error":'
                 '{"reason":"output_limit","message":"protocol line exceeded the 1 MiB bound"}}')
            return
        if isinstance(payload, dict) and "event" in payload and _emit_marker():
            return
        log("a protocol payload could not fit its line; it was reduced")
        return
    id_value = payload.get("id") if isinstance(payload, dict) else None
    if isinstance(id_value, int) and not isinstance(id_value, bool) and _emit_internal_error(id_value):
        return
    if isinstance(payload, dict) and "event" in payload and _emit_marker():
        return
    log("a protocol payload could not be serialized")


def _emit_internal_error(id_value):
    line = ('{"id":' + str(id_value) + ',"ok":false,"error":'
            '{"reason":"internal","message":"reply serialization failed"}}')
    if len(line) + 1 > MESSAGE_LIMIT:
        return False
    emit(line)
    return True


def _emit_marker():
    line = '{"event":"scenario","params":{"data":{"kind":"event_oversized"}}}'
    if len(line) + 1 > MESSAGE_LIMIT:
        return False
    emit(line)
    return True


def log(text):
    sys.stderr.write("[rea-pydoll-bridge] " + str(text) + "\n")
    sys.stderr.flush()


def write_error(id_value, reason, message):
    write_line({"id": id_value, "ok": False, "error": {"reason": reason, "message": message}})


def truncate_utf8(text, limit=INLINE_TEXT_LIMIT):
    if len(text.encode("utf-8", errors="replace")) <= limit:
        return text, False
    return text.encode("utf-8", errors="replace")[:limit].decode("utf-8", errors="ignore"), True


def png_dimensions(data):
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        width, height = struct.unpack(">II", data[16:24])
        return int(width), int(height)
    return None, None


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def pydoll_version():
    try:
        return importlib_metadata.version("pydoll-python")
    except importlib_metadata.PackageNotFoundError:
        pass
    try:
        return importlib_metadata.version("pydoll")
    except importlib_metadata.PackageNotFoundError:
        return "unknown"


def probe_pydoll():
    """Return a failure message when the pydoll import is missing, else None."""
    if PYDOLL_AVAILABLE:
        return None
    return (
        "pydoll-python is not importable in this interpreter; install it "
        "into the interpreter named by REA_PYDOLL_COMMAND"
    )


def connect_version_field(version_payload):
    if not isinstance(version_payload, dict):
        return "unknown"
    browser = version_payload.get("Browser")
    if isinstance(browser, str) and browser:
        return browser
    agent = version_payload.get("User-Agent")
    if isinstance(agent, str) and "Chrome/" in agent:
        return "Chrome/" + agent.split("Chrome/", 1)[1].split(" ", 1)[0]
    return "unknown"


def build_request_url(destination):
    url = destination.get("url")
    if not isinstance(url, str) or not url:
        raise ProtocolError("bad_params", "goto destination requires a url string")
    query = destination.get("query")
    if isinstance(query, str) and query:
        url += ("&" if "?" in url else "?") + query.lstrip("?")
    elif isinstance(query, dict) and query:
        url += ("&" if "?" in url else "?") + urlencode(query, doseq=True)
    return url


def cookie_to_param(seed):
    if not isinstance(seed, dict) or not isinstance(seed.get("name"), str) or not isinstance(seed.get("value"), str):
        raise ProtocolError("bad_params", "each seed cookie needs string name and value")
    param = {"name": seed["name"], "value": seed["value"]}
    if isinstance(seed.get("domain"), str) and seed["domain"]:
        param["domain"] = seed["domain"]
    if isinstance(seed.get("path"), str) and seed["path"]:
        param["path"] = seed["path"]
    if seed.get("secure") is True:
        param["secure"] = True
    if seed.get("http_only") is True:
        param["httpOnly"] = True
    same_site = seed.get("same_site")
    if same_site in {"Strict", "Lax", "None"}:
        param["sameSite"] = same_site
    return param, same_site


def cookie_record(cookie):
    if not isinstance(cookie, dict):
        cookie = {}
    raw = cookie.get("sameSite")
    return {
        "name": cookie.get("name", ""),
        "value": cookie.get("value", ""),
        "domain": cookie.get("domain", ""),
        "path": cookie.get("path", ""),
        "secure": bool(cookie.get("secure", False)),
        "http_only": bool(cookie.get("httpOnly", False)),
        "same_site": raw if isinstance(raw, str) else "None",
        "same_site_raw": raw if isinstance(raw, str) else None,
    }


def storage_entry_records(pairs, limit=512):
    if not isinstance(pairs, list):
        return [], False
    entries = []
    for pair in pairs[:limit]:
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            entries.append({"name": str(pair[0]), "value": str(pair[1])})
    return entries, len(pairs) > limit


def parse_cdp_endpoint(endpoint):
    parts = urlsplit(endpoint if isinstance(endpoint, str) else "")
    host = parts.hostname or ""
    if parts.scheme != "http" or parts.path not in {"", "/"} or host not in {"127.0.0.1", "localhost", "::1", None}:
        raise ProtocolError("bad_params", "cdp_endpoint must be http://127.0.0.1:<port>")
    if not parts.port or parts.port < 1 or parts.port > 65535:
        raise ProtocolError("bad_params", "cdp_endpoint requires a port between 1 and 65535")
    return host, parts.port


def locator_selector(locator):
    kind = locator.get("kind")
    if kind == "test_id" and isinstance(locator.get("value"), str):
        return "[data-testid=" + json.dumps(locator["value"]) + "]"
    if kind == "css" and isinstance(locator.get("selector"), str):
        return locator["selector"]
    raise ProtocolError("bad_params", "test_id and css locators must carry their values")


def role_selector(locator):
    tags = ROLE_TAGS.get(locator.get("role"))
    if tags is None:
        raise ProtocolError("bad_params", "unsupported role locator role")
    return tags


def key_translation(name):
    for member in Key:
        if member.value[0] == name:
            return {"kind": "enum", "name": member.value[0], "vkey": member.value[1], "code": ""}
    if len(name) == 1 and name in CHAR_TO_KEY_INFO:
        mapped_key, mapped_code, mapped_vkey = CHAR_TO_KEY_INFO[name]
        return {"kind": "char", "name": mapped_key, "vkey": mapped_vkey, "code": mapped_code}
    normalized = name.upper().replace("_", "").replace(" ", "")
    if normalized.isidentifier():
        try:
            member = Key[normalized]
            return {"kind": "enum", "name": member.value[0], "vkey": member.value[1], "code": ""}
        except KeyError:
            pass
    raise ProtocolError("key_input_unsupported", "no Input.dispatchKeyEvent path for this key")


def origins_from_cookies(cookies, current_url):
    origins = []
    for cookie in cookies:
        domain = (cookie.get("domain") or "").strip().lower()
        while domain.startswith("."):
            domain = domain[1:]
        if not domain:
            continue
        for scheme in ("https", "http"):
            origin = scheme + "://" + domain
            if origin not in origins and len(origins) < STORAGE_ORIGINS_LIMIT:
                origins.append(origin)
    current = urlsplit(current_url or "")
    if current.scheme and current.netloc:
        origin = current.scheme + "://" + current.netloc
        if origin in origins:
            origins.remove(origin)
        origins.insert(0, origin)
    return origins[:STORAGE_ORIGINS_LIMIT]


def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "rea-pydoll-bridge/1"})
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read(4 * 1024 * 1024).decode("utf-8"))


def read_lines_forever(loop, lines):
    """One daemon thread owns stdin; complete lines are enqueued thread-safely."""
    buffer = b""
    draining = False
    while True:
        try:
            chunk = os.read(0, 65536)
        except OSError:
            chunk = b""
        if not chunk:
            loop.call_soon_threadsafe(lines.put_nowait, None)
            return
        buffer += chunk
        while True:
            if draining:
                if b"\n" not in buffer:
                    break
                buffer = buffer.split(b"\n", 1)[1]
                draining = False
                continue
            if b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if len(line) > READ_LIMIT:
                    loop.call_soon_threadsafe(lines.put_nowait, "oversize")
                    draining = True
                    continue
                if line:
                    loop.call_soon_threadsafe(lines.put_nowait, line.decode("utf-8", errors="replace"))
                continue
            if len(buffer) > READ_LIMIT:
                loop.call_soon_threadsafe(lines.put_nowait, "oversize")
                draining = True
                buffer = b""
                break
            break


def terminate_process(process):
    try:
        process.terminate()
        try:
            process.wait(timeout=3)
            return
        except Exception:
            process.kill()
            try:
                process.wait(timeout=1)
            except Exception:
                pass
    except Exception:
        pass


class Bridge:
    def __init__(self):
        self.mode = None
        self.browser = None
        self.tab = None
        self.session_dir = None
        self.stopping = False
        self.gone = False
        self.exit_code = 0
        self.own_stopped = False
        self._artifact_seq = 0
        self._events = deque(maxlen=EVENT_QUEUE_LIMIT)
        self._dropped_events = 0
        self._enabled_domains = []
        self._history_entries = []
        self._history_urls = []
        self._history_observer_registered = False
        self._seed_script_id = None
        self._seed_callback_id = None
        self._capture_request_bodies = False
        self._capture_response_bodies = False
        self._capture_header_values = False
        self._response_pending = {}
        self._connect_version = "unknown"

    # transport ------------------------------------------------------------

    async def serve(self):
        if not PYDOLL_AVAILABLE:
            sys.stderr.write(
                "[rea-pydoll-bridge] pydoll-python is not importable; the bridge cannot serve\n"
            )
            self.exit_code = 1
            return
        write_line({"advertising": {"protocol": PROTOCOL_VERSION,
                                    "pydoll_version": pydoll_version(),
                                    "capabilities": CAPABILITIES}})
        loop = asyncio.get_running_loop()
        lines = asyncio.Queue()
        reader = threading.Thread(target=read_lines_forever, args=(loop, lines), daemon=True)
        reader.start()
        get_task = None
        while True:
            if self.stopping:
                return
            pulse = asyncio.ensure_future(asyncio.sleep(PUMP_INTERVAL_SECONDS))
            if get_task is None:
                get_task = asyncio.ensure_future(lines.get())
            done, _ = await asyncio.wait({get_task, pulse}, return_when=asyncio.FIRST_COMPLETED)
            if pulse in done:
                self.flush_events()
            else:
                pulse.cancel()
            if get_task in done:
                item = get_task.result()
                get_task = None
                self.flush_events()
                if item is None:
                    self.on_stdin_closed()
                    return
                if item == "oversize":
                    log("an incoming line exceeded the 2 MiB read bound and was skipped")
                    continue
                await self.handle_line(item)
                self.flush_events()

    def on_stdin_closed(self):
        if self.stopping:
            self.exit_code = 0
            return
        self.exit_code = 1
        self.log_exit()
        self.stopping = True

    def log_exit(self):
        log("stdin closed before close_session; treating as cancellation")

    async def handle_line(self, item):
        try:
            request = json.loads(item)
        except ValueError:
            log("dropping a line that is not JSON")
            return
        if not isinstance(request, dict):
            log("dropping a request that is not a JSON object")
            return
        id_value = request.get("id")
        if not isinstance(id_value, int) or isinstance(id_value, bool):
            log("dropping a request without an integer id")
            return
        method = request.get("method")
        params = request.get("params")
        if not isinstance(method, str) or not isinstance(params, dict):
            write_error(id_value, "bad_params", "a method name and a params object are required")
            return
        try:
            result = await self.dispatch(method, params)
        except ProtocolError as error:
            self.flush_events()
            write_error(id_value, error.reason, error.message or "request failed: " + error.reason)
            if error.reason == "browser_gone":
                self.exit_code = 1
                self.stopping = True
                return
            if method == "open_session":
                await self.release_failed_open()
            return
        except Exception as error:
            self.flush_events()
            write_error(id_value, "internal", "bridge failure: " + type(error).__name__)
            return
        self.flush_events()
        self.send_reply(id_value, result)

    async def release_failed_open(self):
        if self.mode == "launch" and self.browser is not None:
            process = self.owned_process()
            if process is not None and process.poll() is None:
                await asyncio.get_running_loop().run_in_executor(None, terminate_process, process)
            self.own_stopped = True
        if self.mode == "connect" and self.tab is not None:
            try:
                await asyncio.wait_for(self.tab._connection_handler.close(), timeout=5)
            except Exception:
                pass
        self.mode = None
        self.tab = None
        self.browser = None

    # request dispatch -----------------------------------------------------

    async def dispatch(self, method, params):
        if method == "open_session":
            return await self.budgeted(self.open_session, params, OPEN_SESSION_BUDGET_SECONDS)
        if method not in {"perform", "capture", "seed_storage", "close_session"}:
            raise ProtocolError("method_unknown", "no such method")
        if self.mode is None:
            raise ProtocolError("session_not_open", "open_session first")
        if method == "perform":
            return await self.perform(params)
        if method == "capture":
            return await self.budgeted(self.capture, params, CAPTURE_BUDGET_SECONDS)
        if method == "seed_storage":
            return await self.budgeted(self.seed_storage, params, SEED_BUDGET_SECONDS)
        if method == "close_session":
            return await self.budgeted(self.close_session, params, CLOSE_SESSION_BUDGET_SECONDS)
        raise ProtocolError("method_unknown", "no such method")

    @staticmethod
    async def budgeted(method, params, budget):
        try:
            return await asyncio.wait_for(method(params), timeout=budget)
        except asyncio.TimeoutError:
            raise ProtocolError("deadline_exceeded", "the method exceeded its budget") from None

    def send_reply(self, id_value, result):
        payload = {"id": id_value, "ok": True, "result": result}
        line = json.dumps(payload, allow_nan=False, separators=(",", ":"), ensure_ascii=True)
        if len(line) + 1 < REPLY_LIMIT:
            write_line(payload)
            return
        self.spill_artifacts(result)
        payload = {"id": id_value, "ok": True, "result": result}
        line = json.dumps(payload, allow_nan=False, separators=(",", ":"), ensure_ascii=True)
        if len(line) + 1 < REPLY_LIMIT:
            write_line(payload)
            return
        write_error(id_value, "output_limit",
                    "the reply stayed over the 1 MiB bound even after spilling artifacts to files")

    def spill_artifacts(self, result):
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, list):
            return
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict) or artifact.get("kind") not in {"storage", "history"}:
                continue
            if "path" in artifact:
                continue
            content = dict(artifact)
            kind = content.pop("kind", "data")
            self._artifact_seq += 1
            path = os.path.join(self.session_dir, kind + "-" + str(self._artifact_seq) + ".json")
            blob = json.dumps(content, allow_nan=False, separators=(",", ":")).encode("utf-8")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(blob)
            os.chmod(path, 0o600)
            artifacts[index] = {"kind": kind, "path": path, "sha256": sha256_hex(blob), "bytes": len(blob)}
            notes = result.get("notes")
            result["notes"] = list(notes) + [kind + " artifact was written to a file to keep the reply small"]

    # cdp helpers ----------------------------------------------------------

    async def cdp(self, command, timeout=CDP_TIMEOUT_SECONDS):
        if self.tab is None:
            raise ProtocolError("session_not_open", "open_session first")
        handler = self.tab._connection_handler
        try:
            return await handler.execute_command(command, timeout=timeout)
        except WebSocketConnectionClosed:
            self.gone = True
            raise ProtocolError("browser_gone", "the page WebSocket closed") from None
        except (NetworkError, OSError) as error:
            self.gone = True
            raise ProtocolError("browser_gone", "the browser stopped answering: " + type(error).__name__) from None
        except CommandExecutionTimeout:
            if not await handler.ping():
                self.gone = True
                raise ProtocolError("browser_gone", "the browser stopped answering") from None
            raise ProtocolError("cdp_timeout", "a CDP command exceeded its deadline") from None
        except CommandFailed as error:
            raise ProtocolError("cdp_command_failed", "CDP command rejected: " + str(error)) from None

    async def script_value(self, expression, timeout=CDP_TIMEOUT_SECONDS):
        response = await self.cdp(
            {"method": "Runtime.evaluate",
             "params": {"expression": expression, "returnByValue": True, "silent": True, "awaitPromise": False}},
            timeout=timeout,
        )
        evaluated = response.get("result", {})
        if evaluated.get("exceptionDetails") is not None:
            raise ProtocolError("script_failed", "the page script failed")
        return evaluated.get("result", {}).get("value")

    async def script_json(self, body, embedded):
        raw = await self.script_value(body
                                      .replace("__CFG__", embedded)
                                      .replace("__SELECTOR__", embedded)
                                      .replace("__SEEDS__", embedded))
        if not isinstance(raw, str):
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    # open_session ---------------------------------------------------------

    async def open_session(self, params):
        if self.mode is not None:
            raise ProtocolError("session_already_open", "close_session before opening again")
        mode = params.get("mode")
        session_dir = params.get("session_dir")
        if mode not in {"launch", "connect"}:
            raise ProtocolError("bad_params", "mode must be launch or connect")
        if not isinstance(session_dir, str) or not os.path.isabs(session_dir) or not os.path.isdir(session_dir):
            raise ProtocolError("bad_params", "session_dir must be an existing absolute directory")
        self.session_dir = session_dir

        capture = params.get("capture") if isinstance(params.get("capture"), dict) else {}
        requested = capture.get("events") if isinstance(capture.get("events"), list) else []
        network_capture = capture.get("network") if isinstance(capture.get("network"), dict) else {}
        self._capture_request_bodies = bool(network_capture.get("request_body"))
        self._capture_response_bodies = bool(network_capture.get("response_body"))
        self._capture_header_values = bool(network_capture.get("header_values"))

        if mode == "launch":
            await self.open_launch(params.get("launch") if isinstance(params.get("launch"), dict) else {})
        else:
            await self.open_connect(params.get("connect") if isinstance(params.get("connect"), dict) else {})

        applied, skipped = await self.apply_environment(
            params.get("environment") if isinstance(params.get("environment"), dict) else {})

        if "network" in requested or "websockets" in requested:
            await self.enable_domain("Network", self.tab.enable_network_events())
        if "frames" in requested:
            await self.ensure_page_enabled()
        if "console" in requested or "page-errors" in requested:
            await self.enable_domain("Runtime", self.tab.enable_runtime_events())
        await self.register_capture_events(requested)

        version = self._connect_version
        if self.mode == "launch":
            try:
                version = (await self.browser.get_version()).get("product") or "unknown"
            except Exception:
                pass
        try:
            initial_url = str(await asyncio.wait_for(self.tab.current_url(), timeout=10))
        except Exception:
            initial_url = None

        return {
            "product": "Chromium",
            "version": str(version),
            "target_id": self.tab.target_id,
            "initial_url": initial_url,
            "owned_browser_pid": self.owned_pid(),
            "applied_environment": applied,
            "skipped_environment": skipped,
            "event_domains_enabled": list(self._enabled_domains),
        }

    async def open_launch(self, launch):
        options = ChromiumOptions()
        executable = launch.get("executable_path")
        if isinstance(executable, str) and executable:
            options.binary_location = executable
        user_data_dir = launch.get("user_data_dir")
        if not isinstance(user_data_dir, str) or not user_data_dir:
            raise ProtocolError("bad_params", "launch mode requires a user_data_dir path string")
        window = launch.get("window_size") if isinstance(launch.get("window_size"), dict) else {}
        try:
            width, height = int(window.get("width", 1280)), int(window.get("height", 720))
        except (TypeError, ValueError):
            raise ProtocolError("bad_params", "window_size needs integer width and height") from None
        options.headless = bool(launch.get("headless", False))
        options.add_argument("--user-data-dir=" + user_data_dir)
        options.add_argument(f"--window-size={width},{height}")
        options.start_timeout = 30
        self.mode = "launch"
        self.browser = Chrome(options=options)
        try:
            self.tab = await asyncio.wait_for(self.browser.start(), timeout=60)
        except asyncio.TimeoutError:
            self.sync_kill_owned()
            raise ProtocolError("deadline_exceeded", "browser launch exceeded the 60s wall clock") from None
        except (BrowserNotRunning, CommandFailed, OSError) as error:
            self.sync_kill_owned()
            raise ProtocolError("launch_failed", "browser launch failed: " + type(error).__name__) from None

    async def open_connect(self, connect):
        loop = asyncio.get_running_loop()
        host, port = parse_cdp_endpoint(connect.get("cdp_endpoint"))
        target_id = connect.get("target_id")
        if not isinstance(target_id, str) or not target_id:
            raise ProtocolError("bad_params", "connect requires target_id")
        try:
            version_payload = await asyncio.wait_for(
                loop.run_in_executor(None, fetch_json, f"http://{host}:{port}/json/version"),
                timeout=HTTP_TIMEOUT_SECONDS + 5)
            targets = await asyncio.wait_for(
                loop.run_in_executor(None, fetch_json, f"http://{host}:{port}/json/list"),
                timeout=HTTP_TIMEOUT_SECONDS + 5)
        except asyncio.TimeoutError:
            raise ProtocolError("deadline_exceeded",
                                "the CDP endpoint did not answer within 10s") from None
        except (OSError, ValueError) as error:
            raise ProtocolError("target_not_found",
                                "the CDP endpoint could not be reached: " + type(error).__name__) from None
        self._connect_version = connect_version_field(version_payload)
        match = None
        for target in targets if isinstance(targets, list) else []:
            if (isinstance(target, dict) and target.get("id") == target_id
                    and target.get("type") == "page"
                    and isinstance(target.get("webSocketDebuggerUrl"), str)):
                match = target
                break
        if match is None:
            raise ProtocolError("target_not_found", "no page target carries the requested target_id")
        self.mode = "connect"
        self.browser = Chrome(options=ChromiumOptions(), connection_port=port)
        self.tab = await self.browser.get_tab_by_target({"targetId": target_id, "type": "page"})

    def owned_pid(self):
        process = self.owned_process()
        try:
            if process is not None and process.poll() is None:
                return int(process.pid)
        except (AttributeError, ValueError):
            return None
        return None

    def owned_process(self):
        if self.mode != "launch" or self.browser is None:
            return None
        manager = getattr(self.browser, "_browser_process_manager", None)
        if manager is None:
            return None
        return getattr(manager, "_process", None)

    async def apply_environment(self, environment):
        applied, skipped = [], []
        if isinstance(environment.get("timezone"), str) and environment["timezone"]:
            if await self.apply_env_command(EmulationCommands.set_timezone_override(environment["timezone"])):
                applied.append("timezone")
            else:
                skipped.append("timezone")
        if isinstance(environment.get("locale"), str) and environment["locale"]:
            if await self.apply_env_command(EmulationCommands.set_locale_override(environment["locale"])):
                applied.append("locale")
            else:
                skipped.append("locale")
        viewport = environment.get("viewport")
        if isinstance(viewport, dict) and viewport.get("width") is not None and viewport.get("height") is not None:
            try:
                command = EmulationCommands.set_device_metrics_override(
                    int(viewport["width"]), int(viewport["height"]),
                    float(viewport.get("device_scale_factor", 1)), False)
            except (TypeError, ValueError):
                raise ProtocolError("bad_params", "viewport needs numeric sizes") from None
            if await self.apply_env_command(command):
                applied.append("viewport")
            else:
                skipped.append("viewport")
        wanted = []
        media_features = []
        if environment.get("color_scheme") in {"light", "dark"}:
            media_features.append({"name": "prefers-color-scheme", "value": environment["color_scheme"]})
            wanted.append("color_scheme")
        if environment.get("reduced_motion"):
            media_features.append({"name": "prefers-reduced-motion", "value": "reduce"})
            wanted.append("reduced_motion")
        if media_features:
            if await self.apply_env_command(
                    EmulationCommands.set_emulated_media(media="screen", features=media_features)):
                applied.extend(wanted)
            else:
                skipped.extend(wanted)
        return applied, skipped

    async def apply_env_command(self, command):
        try:
            await self.cdp(command, timeout=CDP_TIMEOUT_SECONDS)
            return True
        except ProtocolError:
            return False

    async def enable_domain(self, domain, coroutine):
        try:
            await asyncio.wait_for(coroutine, timeout=CDP_TIMEOUT_SECONDS)
        except ProtocolError:
            raise
        except Exception as error:
            raise ProtocolError("cdp_command_failed",
                                domain + " domain enable failed: " + type(error).__name__) from None
        if domain not in self._enabled_domains:
            self._enabled_domains.append(domain)

    # capture event registration ------------------------------------------

    async def register_capture_events(self, requested):
        if self.tab is None:
            return
        if "network" in requested:
            for event_name, callback in [
                (NetworkEvent.REQUEST_WILL_BE_SENT, self.on_request_will_be_sent),
                (NetworkEvent.RESPONSE_RECEIVED, self.on_response_received),
                (NetworkEvent.LOADING_FINISHED, self.on_loading_finished),
                (NetworkEvent.LOADING_FAILED, self.on_loading_failed),
            ]:
                await self.tab.on(event_name, callback)
        if "websockets" in requested:
            for event_name, callback in [
                (NetworkEvent.WEBSOCKET_CREATED, self.on_websocket_created),
                (NetworkEvent.WEBSOCKET_FRAME_RECEIVED, self.on_websocket_frame_received),
                (NetworkEvent.WEBSOCKET_FRAME_SENT, self.on_websocket_frame_sent),
                (NetworkEvent.WEBSOCKET_CLOSED, self.on_websocket_closed),
            ]:
                await self.tab.on(event_name, callback)
        if "frames" in requested:
            await self.tab.on(PageEvent.FRAME_NAVIGATED, self.on_frame_navigated)
        if "console" in requested:
            await self.tab.on(RuntimeEvent.CONSOLE_API_CALLED, self.on_console)
        if "page-errors" in requested:
            await self.tab.on(RuntimeEvent.EXCEPTION_THROWN, self.on_exception)

    async def ensure_page_enabled(self):
        if "Page" not in self._enabled_domains:
            await self.enable_domain("Page", self.tab.enable_page_events())
        if not self._history_observer_registered:
            self._history_observer_registered = True
            await self.tab.on(PageEvent.FRAME_NAVIGATED, self.on_history_navigation)

    def enqueue(self, family, data):
        if len(self._events) >= EVENT_QUEUE_LIMIT:
            self._dropped_events += 1
        self._events.append({"family": family, "data": data})

    def flush_events(self):
        while True:
            if self._events:
                params = self._events[0]
                payload = {"event": "scenario", "params": params}
                line = json.dumps(payload, allow_nan=False, separators=(",", ":"), ensure_ascii=True)
                self._events.popleft()
                if len(line) + 1 > MESSAGE_LIMIT:
                    write_line({"event": "scenario", "params": {"family": params["family"],
                                                                "data": {"kind": "event_oversized"}}})
                    continue
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
                continue
            if self._dropped_events <= 0:
                return
            # Report the bounded queue's evictions; the marker is written only
            # after the queue drains, so it follows every event it accounts for.
            self._events.append({"family": "omissions",
                                 "data": {"kind": "event_queue_overflow",
                                          "count": self._dropped_events}})
            self._dropped_events = 0

    # network/websocket/console/frame callbacks ---------------------------

    def header_values_for(self, headers):
        if not self._capture_header_values or not isinstance(headers, dict):
            return None
        trimmed = {}
        for key, value in list(headers.items())[:64]:
            name = str(key)[:256]
            trimmed[name] = value if isinstance(value, str) else str(value)[:256]
        return trimmed

    async def on_request_will_be_sent(self, event):
        params = event.get("params", {})
        request = params.get("request", {})
        data = {
            "kind": "request",
            "request_id": str(params.get("requestId", "")),
            "url": str(request.get("url", "")),
            "method": str(request.get("method", "GET")),
            "resource_type": str(params.get("type", "")),
        }
        headers = self.header_values_for(request.get("headers", {}))
        if headers is not None:
            data["headers"] = headers
        if self._capture_request_bodies:
            post = request.get("postData")
            if post is None:
                post = await self.try_post_data(str(params.get("requestId", "")))
            if post is not None:
                body, truncated = truncate_utf8(str(post))
                data["body"] = body
                if truncated:
                    data["body_truncated"] = True
        self.enqueue("network", data)

    async def try_post_data(self, request_id):
        if self.tab is None or not request_id:
            return None
        try:
            response = await self.tab._connection_handler.execute_command(
                NetworkCommands.get_request_post_data(request_id), timeout=10)
            return response.get("result", {}).get("postData")
        except Exception:
            return None

    def on_response_received(self, event):
        params = event.get("params", {})
        request_id = str(params.get("requestId", ""))
        response = params.get("response", {})
        if self._capture_response_bodies:
            self._response_pending[request_id] = {
                "url": str(response.get("url", "")),
                "status": response.get("status", 0),
                "status_text": str(response.get("statusText", "")),
                "mime_type": str(response.get("mimeType", "")),
                "protocol": str(response.get("protocol", "")),
                "headers": self.header_values_for(response.get("headers", {})),
            }
            return
        data = {"kind": "response", "request_id": request_id,
                "url": str(response.get("url", "")),
                "status": response.get("status", 0),
                "status_text": str(response.get("statusText", "")),
                "mime_type": str(response.get("mimeType", "")),
                "protocol": str(response.get("protocol", ""))}
        headers = self.header_values_for(response.get("headers", {}))
        if headers is not None:
            data["headers"] = headers
        self.enqueue("network", data)

    async def on_loading_finished(self, event):
        params = event.get("params", {})
        request_id = str(params.get("requestId", ""))
        if not self._capture_response_bodies:
            return
        pending = self._response_pending.pop(request_id, None)
        if pending is None:
            self.enqueue("network", {"kind": "response", "request_id": request_id, "url": None,
                                     "status": None, "status_text": "", "mime_type": "", "protocol": ""})
            return
        body, encoding, truncated = await self.try_response_body(request_id)
        if body is not None:
            pending["body"] = body
            pending["body_encoding"] = encoding
            if truncated:
                pending["body_truncated"] = True
        self.enqueue("network", pending)

    async def try_response_body(self, request_id):
        if self.tab is None or not request_id:
            return None, None, False
        for attempt in range(2):
            try:
                response = await self.tab._connection_handler.execute_command(
                    NetworkCommands.get_response_body(request_id), timeout=10)
                result = response.get("result", {})
                body = result.get("body")
                if body is None:
                    return None, None, False
                if result.get("base64Encoded"):
                    try:
                        decoded = base64.b64decode(body)
                    except (ValueError, TypeError):
                        return None, None, False
                    if len(decoded) <= INLINE_TEXT_LIMIT:
                        return base64.b64encode(decoded).decode("ascii"), "base64", False
                    return base64.b64encode(decoded[:INLINE_TEXT_LIMIT]).decode("ascii"), "base64", True
                text, truncated = truncate_utf8(str(body))
                return text, "text", truncated
            except Exception:
                if attempt == 1:
                    return None, None, False
                await asyncio.sleep(0.1)
        return None, None, False

    def on_loading_failed(self, event):
        params = event.get("params", {})
        request_id = str(params.get("requestId", ""))
        pending = self._response_pending.pop(request_id, None)
        data = {"kind": "request_failed", "request_id": request_id,
                "error_text": str(params.get("errorText", ""))}
        if pending is not None:
            data["url"] = str(pending.get("url") if pending.get("url") is not None else "")
        self.enqueue("network", data)

    def on_websocket_created(self, event):
        params = event.get("params", {})
        self.enqueue("websockets", {"kind": "websocket_created",
                                    "request_id": str(params.get("requestId", "")),
                                    "url": str(params.get("url", ""))})

    def on_websocket_frame_received(self, event):
        self.on_websocket_frame(event, "received")

    def on_websocket_frame_sent(self, event):
        self.on_websocket_frame(event, "sent")

    def on_websocket_frame(self, event, direction):
        params = event.get("params", {})
        frame = params.get("response") if isinstance(params.get("response"), dict) else params.get("request", {})
        data = {"kind": "websocket_frame", "request_id": str(params.get("requestId", "")),
                "direction": direction}
        payload = frame.get("payload")
        if isinstance(payload, str):
            text, truncated = truncate_utf8(payload)
            data["payload"] = text
            data["payload_encoding"] = "text"
            if truncated:
                data["payload_truncated"] = True
        self.enqueue("websockets", data)

    def on_websocket_closed(self, event):
        params = event.get("params", {})
        self.enqueue("websockets", {"kind": "websocket_closed",
                                    "request_id": str(params.get("requestId", ""))})

    def on_frame_navigated(self, event):
        frame = event.get("params", {}).get("frame", {})
        self.enqueue("frames", {"kind": "frame_navigated", "frame_id": str(frame.get("id", "")),
                                "url": str(frame.get("url", "")),
                                "is_main": not bool(frame.get("parentId"))})

    def on_history_navigation(self, event):
        frame = event.get("params", {}).get("frame", {})
        if frame.get("parentId"):
            return
        url = str(frame.get("url", ""))
        kind = "reload" if self._history_urls and url == self._history_urls[-1] else "navigate"
        self._history_urls.append(url)
        if len(self._history_entries) < HISTORY_ENTRIES_LIMIT:
            self._history_entries.append({"type": kind, "url": url})

    def on_console(self, event):
        params = event.get("params", {})
        pieces = []
        for argument in params.get("args", []):
            if "value" in argument:
                pieces.append(str(argument["value"]))
            elif "description" in argument:
                pieces.append(str(argument["description"]))
            else:
                pieces.append(str(argument.get("type", "?")))
        text, truncated = truncate_utf8(" ".join(pieces))
        frames = (params.get("stackTrace") or {}).get("callFrames") or []
        data = {"kind": "console", "level": str(params.get("type", "")), "text": text,
                "url": str(frames[0].get("url", "")) if frames else ""}
        if truncated:
            data["text_truncated"] = True
        self.enqueue("console", data)

    def on_exception(self, event):
        params = event.get("params", {})
        details = params.get("exceptionDetails", {})
        exception = details.get("exception") or {}
        message, message_truncated = truncate_utf8(str(exception.get("description") or details.get("text") or ""))
        frames = (details.get("stackTrace") or {}).get("callFrames") or []
        stack, stack_truncated = truncate_utf8("\n".join(
            "{0}:{1}:{2} {3}".format(str(frame.get("url", "")), frame.get("lineNumber", 0),
                                     frame.get("columnNumber", 0), str(frame.get("functionName", "")))
            for frame in frames[:50]))
        data = {"kind": "page_error", "message": message,
                "url": str(frames[0].get("url", "")) if frames else "", "stack": stack}
        if message_truncated:
            data["message_truncated"] = True
        if stack_truncated:
            data["stack_truncated"] = True
        self.enqueue("page-errors", data)

    # perform --------------------------------------------------------------

    @staticmethod
    def action_timeout(params, action):
        raw = params.get("timeout_ms", action.get("timeout_ms"))
        try:
            timeout = float(raw) / 1000 if raw is not None else DEFAULT_ACTION_TIMEOUT_SECONDS
        except (TypeError, ValueError):
            timeout = DEFAULT_ACTION_TIMEOUT_SECONDS
        return max(0.05, min(timeout, HARD_ACTION_CAP_SECONDS))

    async def perform(self, params):
        action = params.get("action")
        if not isinstance(action, dict):
            raise ProtocolError("bad_params", "perform requires an action object")
        handlers = {
            "goto": self.perform_goto,
            "click": self.perform_click,
            "fill": self.perform_fill,
            "press": self.perform_press,
            "select_option": self.perform_select,
            "check": self.perform_checked,
            "uncheck": self.perform_checked,
            "wait_for": self.perform_wait_for,
            "wait_for_timeout": self.perform_wait_timeout,
        }
        kind = action.get("action") or action.get("kind") or action.get("type")
        handler = handlers.get(kind)
        if handler is None:
            raise ProtocolError("bad_params", "unsupported action kind")
        seconds = self.action_timeout(params, action)
        try:
            result = await asyncio.wait_for(handler(action, seconds), timeout=seconds + 2)
        except asyncio.TimeoutError:
            raise ProtocolError("action_timeout", "the action exceeded its deadline; it may have half-run") from None
        try:
            final_url = str(await asyncio.wait_for(self.tab.current_url(), timeout=5))
        except Exception:
            final_url = None
        return {"final_url": final_url, "notes": result.get("notes", [])}

    async def perform_goto(self, action, seconds):
        destination = action.get("destination")
        if not isinstance(destination, dict):
            raise ProtocolError("bad_params", "goto requires a destination object")
        url = build_request_url(destination)
        wait_until = action.get("wait_until", "load")
        budget = min(seconds + 10.0, HARD_ACTION_CAP_SECONDS)
        notes = []
        if wait_until == "commit":
            notes.append(await self.goto_commit(url, budget))
        elif wait_until == "domcontentloaded":
            await self.goto_wait(url, budget, PageLoadState.INTERACTIVE)
            notes.append("waited for Page.domContentEventFired via pydoll's INTERACTIVE load state")
        else:
            await self.goto_wait(url, budget, PageLoadState.COMPLETE)
            notes.append("waited for Page.loadEventFired")
        return {"notes": notes}

    async def goto_wait(self, url, seconds, load_state):
        await self.ensure_page_enabled()
        options = self.browser.options if self.browser is not None else None
        previous = options.page_load_state if options is not None else None
        if options is not None:
            options.page_load_state = load_state
        try:
            await asyncio.wait_for(self.tab.go_to(url, timeout=int(seconds)), timeout=seconds + 5)
        except asyncio.TimeoutError:
            raise ProtocolError("deadline_exceeded", "the navigation exceeded its wall clock") from None
        except PageLoadTimeout:
            raise ProtocolError("navigation_failed",
                                "the page did not reach the requested wait state in time") from None
        except NavigationError as error:
            detail = str(error.args[-1]) if error.args else type(error).__name__
            raise ProtocolError("navigation_failed", "navigation failed: " + detail) from None
        finally:
            if options is not None and previous is not None:
                options.page_load_state = previous

    async def goto_commit(self, url, seconds):
        await self.ensure_page_enabled()
        if "Network" not in self._enabled_domains:
            await self.enable_domain("Network", self.tab.enable_network_events())
        released = asyncio.Event()
        release_kind = {"event": None}
        needle = url.split("#", 1)[0]

        def on_request(event):
            request_url = event.get("params", {}).get("request", {}).get("url", "")
            if release_kind["event"] is None and request_url.startswith(needle):
                release_kind["event"] = "request-will-be-sent"
                released.set()

        def on_loaded(_event):
            if release_kind["event"] is None:
                release_kind["event"] = "load-event"
                released.set()

        callbacks = [await self.tab.on(NetworkEvent.REQUEST_WILL_BE_SENT, on_request),
                     await self.tab.on(PageEvent.LOAD_EVENT_FIRED, on_loaded)]
        try:
            response = await asyncio.wait_for(
                self.tab._connection_handler.execute_command(PageCommands.navigate(url), timeout=int(seconds)),
                timeout=seconds)
            error_text = response.get("result", {}).get("errorText")
            if error_text:
                raise ProtocolError("navigation_failed", "navigation failed: " + str(error_text))
            try:
                await asyncio.wait_for(released.wait(), timeout=max(seconds, 1.0))
            except asyncio.TimeoutError:
                raise ProtocolError("navigation_failed",
                                    "no commit evidence arrived within the deadline") from None
        finally:
            for callback_id in callbacks:
                try:
                    await self.tab.remove_callback(callback_id)
                except Exception:
                    pass
        return "commit released by " + release_kind["event"]

    async def resolve_locator(self, locator, seconds=None):
        if not isinstance(locator, dict):
            raise ProtocolError("bad_params", "an action with a target requires a locator object")
        notes = []
        if locator.get("kind") == "role":
            cfg = {"selector": role_selector(locator), "name": str(locator.get("name", "")),
                   "requireVisible": False}
            matched = await self.script_json(_ROLE_FINDER_BODY, json.dumps(cfg, ensure_ascii=True))
            path = matched.get("path") if isinstance(matched, dict) else None
            if path is None:
                raise ProtocolError("locator_not_found", "no element matched the role locator")
            notes.append("role locator matched by accessible-name approximation "
                         "(aria-label, value for inputs, innerText, title); not a full aria computation")
            element = await self.query_once(path)
            if element is None:
                raise ProtocolError("locator_not_found", "the role match could not be resolved in pydoll")
            return element, notes
        selector = locator_selector(locator)
        budget = min(RESOLUTION_BUDGET_SECONDS, seconds if seconds is not None else RESOLUTION_BUDGET_SECONDS)
        try:
            element = await asyncio.wait_for(
                self.tab.query(selector, timeout=int(budget), raise_exc=False), timeout=budget + 5)
        except asyncio.TimeoutError:
            raise ProtocolError("locator_not_found", "the locator did not resolve in time") from None
        if element is None:
            raise ProtocolError("locator_not_found", "no element matched the locator")
        return element, notes

    async def query_once(self, selector):
        try:
            return await self.tab.query(selector, timeout=0, raise_exc=False)
        except WebSocketConnectionClosed:
            self.gone = True
            raise ProtocolError("browser_gone", "the page WebSocket closed") from None
        except Exception:
            return None

    async def perform_click(self, action, seconds):
        element, notes = await self.resolve_locator(action.get("locator"), seconds)
        button = action.get("button")
        if button not in {None, "", "left"}:
            notes.append("pydoll 3.0.0 clicks are left-button only; a left click was sent instead of " + str(button))
        try:
            count = int(action.get("click_count", 1))
        except (TypeError, ValueError):
            count = 1
        try:
            if count == 2:
                await element.double_click()
                notes.append("double click sent via pydoll double_click (clickCount 1 then 2)")
            elif count > 2:
                await element.click(humanize=True)
                notes.append("click_count " + str(count) + " is unsupported in pydoll; a single left click was sent")
            else:
                await element.click(humanize=True)
                notes.append("click via pydoll element.click; humanize applies only when a Mouse "
                             "instance is present, otherwise raw Input mouse events ran")
        except (ElementNotVisible, ElementNotInteractable) as error:
            raise ProtocolError("element_not_interactable", type(error).__name__) from None
        return {"notes": notes}

    async def perform_fill(self, action, seconds):
        element, notes = await self.resolve_locator(action.get("locator"), seconds)
        value = action.get("value")
        if not isinstance(value, str):
            raise ProtocolError("bad_params", "fill requires a string value")
        try:
            await element.clear()
            await element.insert_text(value)
        except ElementNotInteractable:
            raise ProtocolError("element_not_interactable", "the element does not accept text input") from None
        notes.append("cleared then re-entered via pydoll insert_text; synthetic input and change "
                     "events fired, no per-key events")
        return {"notes": notes}

    async def perform_press(self, action, seconds):
        notes = []
        locator = action.get("locator")
        if locator is not None:
            element, _ = await self.resolve_locator(locator, seconds)
            try:
                await element.focus()
            except (ElementNotInteractable, ElementNotVisible):
                notes.append("the locator could not be focused; the key went to the focused element")
            else:
                notes.append("the locator was focused before the key")
        key = action.get("key")
        if not isinstance(key, str) or not key:
            raise ProtocolError("bad_params", "press requires a key string")
        names = key.split("+")
        base = names[-1]
        modifiers = None
        if len(names) > 1:
            modifiers = 0
            for name in names[:-1]:
                bit = MODIFIER_KEYS.get(name.strip().lower())
                if bit is None:
                    raise ProtocolError("key_input_unsupported", "no such modifier in the key")
                modifiers |= bit
            modifiers = modifiers or None
        await self.send_key(key_translation(base), modifiers)
        notes.append("key events sent via Input.dispatchKeyEvent")
        return {"notes": notes}

    async def send_key(self, translation, modifiers):
        if translation["kind"] == "char":
            down_text = translation["name"]
            if modifiers is not None and modifiers & 8 and down_text.isalpha():
                down_text = down_text.upper()
            down = InputCommands.dispatch_key_event(
                type=KeyEventType.KEY_DOWN, key=translation["name"], code=translation["code"],
                text=down_text, unmodified_text=translation["name"],
                windows_virtual_key_code=translation["vkey"], native_virtual_key_code=translation["vkey"],
                modifiers=modifiers)
        else:
            down = InputCommands.dispatch_key_event(
                type=KeyEventType.KEY_DOWN, key=translation["name"],
                windows_virtual_key_code=translation["vkey"], native_virtual_key_code=translation["vkey"],
                modifiers=modifiers)
        up = InputCommands.dispatch_key_event(
            type=KeyEventType.KEY_UP, key=translation["name"],
            windows_virtual_key_code=translation["vkey"], native_virtual_key_code=translation["vkey"],
            modifiers=modifiers)
        await self.cdp(down, timeout=10)
        await self.cdp(up, timeout=10)

    async def perform_select(self, action, seconds):
        element, notes = await self.resolve_locator(action.get("locator"), seconds)
        value = action.get("value")
        if not isinstance(value, str):
            raise ProtocolError("bad_params", "select_option requires a string value")
        try:
            tag_response = await element.execute_script("return this.tagName", return_by_value=True)
            tag = str(tag_response.get("result", {}).get("result", {}).get("value") or "").lower()
        except Exception:
            tag = ""
        if tag == "option":
            try:
                await element.click()
            except (ElementNotVisible, ElementNotInteractable) as error:
                raise ProtocolError("element_not_interactable", type(error).__name__) from None
            notes.append("the resolved element is an <option>; pydoll's option click path selected it")
            return {"notes": notes}
        if tag == "select":
            try:
                response = await element.execute_script(
                    _SELECT_OPTION_FUNCTION, arguments=[CallArgument(value=value)], return_by_value=True)
            except (ElementNotVisible, ElementNotInteractable) as error:
                raise ProtocolError("element_not_interactable", type(error).__name__) from None
            outcome = response.get("result", {}).get("result", {}).get("value")
            if outcome is None:
                raise ProtocolError("option_not_found", "the resolved element is not a select")
            if outcome is False:
                raise ProtocolError("option_not_found", "no option matched the requested value")
            notes.append("the option was selected by value via a function on the element; "
                         "synthetic input and change events fired")
            return {"notes": notes}
        raise ProtocolError("option_not_found", "the resolved element is neither a select nor an option")

    async def perform_checked(self, action, seconds):
        element, notes = await self.resolve_locator(action.get("locator"), seconds)
        want = (action.get("kind") or action.get("type")) == "check"
        observed = await self.read_checked(element)
        if observed is None:
            raise ProtocolError("check_failed", "the resolved element has no checked state")
        if bool(observed) == want:
            notes.append("already in the requested state; no click was sent")
            return {"notes": notes}
        try:
            await element.click(humanize=True)
        except (ElementNotVisible, ElementNotInteractable) as error:
            raise ProtocolError("element_not_interactable", type(error).__name__) from None
        observed = await self.read_checked(element)
        if observed is None or bool(observed) != want:
            state = "true" if bool(observed) else "false"
            raise ProtocolError("check_failed", "the element reported checked=" + state + " after the click")
        notes.append("clicked and the checked state was verified through a function on the element")
        return {"notes": notes}

    async def read_checked(self, element):
        try:
            response = await element.execute_script("return this.checked", return_by_value=True)
            value = response.get("result", {}).get("result", {}).get("value")
            return bool(value) if isinstance(value, bool) else None
        except Exception:
            return None

    async def perform_wait_for(self, action, seconds):
        state = action.get("state", "visible")
        if state not in {"attached", "detached", "visible", "hidden"}:
            raise ProtocolError("bad_params", "unsupported wait_for state")
        locator = action.get("locator")
        if not isinstance(locator, dict):
            raise ProtocolError("bad_params", "wait_for requires a locator")
        budget = min(seconds + 10.0, HARD_ACTION_CAP_SECONDS)
        loop = asyncio.get_running_loop()
        start = loop.time()
        notes = []
        if locator.get("kind") == "role":
            notes.append("the role locator state was polled via the accessible-name approximation")
        while True:
            if await self.locator_holds(locator, state):
                elapsed = round(loop.time() - start, 3)
                notes.append("waited " + state + " for " + str(elapsed) + "s")
                break
            if loop.time() - start >= budget:
                raise ProtocolError("locator_not_found", "the waited state did not hold in time")
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
        return {"notes": notes}

    async def locator_holds(self, locator, state):
        if locator.get("kind") == "role":
            cfg = {"selector": role_selector(locator), "name": str(locator.get("name", "")),
                   "requireVisible": state == "visible"}
            matched = await self.script_json(_ROLE_FINDER_BODY, json.dumps(cfg, ensure_ascii=True))
            found = isinstance(matched, dict) and isinstance(matched.get("path"), str)
            visible = bool(matched.get("visible")) if found else False
        else:
            selector = locator_selector(locator)
            snapshot = await self.script_json(_SELECTOR_STATE_BODY, json.dumps(selector, ensure_ascii=True))
            found = isinstance(snapshot, dict) and bool(snapshot.get("found"))
            visible = bool(snapshot.get("visible")) if isinstance(snapshot, dict) else False
        if state == "attached":
            return found
        if state == "detached":
            return not found
        if state == "visible":
            return found and visible
        return (not found) or (found and not visible)

    async def perform_wait_timeout(self, action, seconds):
        try:
            duration = min(float(action.get("duration_ms", 0)) / 1000, HARD_ACTION_CAP_SECONDS)
        except (TypeError, ValueError):
            raise ProtocolError("bad_params", "wait_for_timeout needs a numeric duration_ms") from None
        await asyncio.sleep(max(duration, 0))
        return {"notes": ["slept for " + str(round(duration, 3)) + "s"]}

    # capture --------------------------------------------------------------

    async def capture(self, params):
        requested = params.get("requested")
        if not isinstance(requested, list) or not requested:
            raise ProtocolError("bad_params", "capture requires a requested list")
        artifacts, notes = [], []
        handlers = {
            "screenshot": self.capture_screenshot,
            "dom": self.capture_dom,
            "accessibility": self.capture_accessibility,
            "url": self.capture_url,
            "history": self.capture_history,
            "storage": self.capture_storage,
        }
        failed = 0
        for kind in requested:
            handler = handlers.get(kind)
            if handler is None:
                notes.append("unsupported capture kind requested: " + str(kind))
                failed += 1
                continue
            try:
                artifacts.append(await handler(notes))
            except ProtocolError as error:
                notes.append("kind " + str(kind) + " failed: " + error.reason)
                failed += 1
        if failed == len(requested) and not artifacts:
            raise ProtocolError("artifact_failed", "every requested capture kind failed")
        return {"artifacts": artifacts, "notes": notes}

    def artifact_file(self, kind, payload, suffix, representation=None):
        self._artifact_seq += 1
        path = os.path.join(self.session_dir, kind + "-" + str(self._artifact_seq) + suffix)
        truncated = len(payload) > ARTIFACT_LIMIT
        if truncated:
            payload = payload[:ARTIFACT_LIMIT]
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.chmod(path, 0o600)
        artifact = {"kind": kind, "path": path, "sha256": sha256_hex(payload), "bytes": len(payload)}
        if truncated:
            artifact["truncated"] = True
        if representation:
            artifact.update(representation)
        return artifact

    async def capture_screenshot(self, notes):
        response = await self.cdp(PageCommands.capture_screenshot(format=ScreenshotFormat.PNG), timeout=30)
        data = response.get("result", {}).get("data")
        if not isinstance(data, str) or not data:
            raise ProtocolError("artifact_failed", "no screenshot data was returned")
        try:
            png = base64.b64decode(data)
        except (ValueError, TypeError):
            raise ProtocolError("artifact_failed", "the screenshot data was not valid base64") from None
        width, height = png_dimensions(png)
        return self.artifact_file("screenshot", png, ".png", {"width": width, "height": height})

    async def capture_dom(self, notes):
        try:
            response = await self.cdp(
                {"method": "DOMSnapshot.captureSnapshot", "params": {"computedStyles": []}}, timeout=60)
            if response.get("result", {}).get("documents") is not None:
                content = json.dumps(response["result"], allow_nan=False,
                                     separators=(",", ":")).encode("utf-8")
                return self.artifact_file("dom", content, ".json",
                                          {"representation": "dom-snapshot-json"})
        except ProtocolError as error:
            if error.reason != "cdp_command_failed":
                raise
        notes.append("DOMSnapshot.captureSnapshot was rejected; a documentElement.outerHTML read ran instead")
        html = await self.script_value(
            "(() => { return JSON.stringify(document.documentElement.outerHTML); })()")
        if not isinstance(html, str) or html == '""':
            raise ProtocolError("artifact_failed", "no DOM could be read")
        try:
            text = json.loads(html)
        except ValueError:
            text = html
        return self.artifact_file("dom", str(text).encode("utf-8"), ".html", {"representation": "html"})

    async def capture_accessibility(self, notes):
        try:
            await self.cdp(AccessibilityCommands.enable(), timeout=10)
        except ProtocolError as error:
            if error.reason == "browser_gone":
                raise
            notes.append("accessibility enable failed; the tree fetch was attempted anyway")
        response = await self.cdp(AccessibilityCommands.get_full_ax_tree(), timeout=60)
        result = response.get("result", {})
        if result.get("nodes") is None:
            raise ProtocolError("artifact_failed", "the accessibility tree was empty")
        content = json.dumps(result, allow_nan=False, separators=(",", ":")).encode("utf-8")
        return self.artifact_file("accessibility", content, ".json")

    async def capture_url(self, notes):
        try:
            raw_url = str(await asyncio.wait_for(self.tab.current_url(), timeout=10))
        except Exception:
            raw_url = None
        return {"kind": "url", "raw_url": raw_url}

    async def capture_history(self, notes):
        tracked = "Page" in self._enabled_domains or self._history_observer_registered
        try:
            length = await self.script_value("window.history.length")
        except ProtocolError:
            length = None
        if not tracked and not self._history_entries:
            notes.append("no main-frame navigations were observed since session open; "
                         "history reconstruction is unavailable")
            return {"kind": "history", "length": None, "raw_entries": []}
        return {"kind": "history",
                "length": int(length) if isinstance(length, int) else None,
                "raw_entries": list(self._history_entries)}

    async def capture_storage(self, notes):
        cookies = await self.download_cookies(notes)
        current_url = await self.current_url_or_none()
        origins = origins_from_cookies(cookies, current_url)
        local_storage, session_storage = await self.download_storages(origins, notes)
        return {"kind": "storage", "cookies": cookies,
                "local_storage": local_storage, "session_storage": session_storage}

    async def download_cookies(self, notes):
        try:
            response = await self.cdp(NetworkCommands.get_cookies(), timeout=30)
        except ProtocolError as error:
            notes.append("the cookie read failed: " + error.reason)
            return []
        all_cookies = response.get("result", {}).get("cookies") or []
        if len(all_cookies) > 1000:
            notes.append("the cookie list was capped at 1000 entries")
        return [cookie_record(cookie) for cookie in all_cookies[:1000]]

    async def current_url_or_none(self):
        try:
            return str(await asyncio.wait_for(self.tab.current_url(), timeout=10))
        except Exception:
            return None

    async def download_storages(self, origins, notes):
        local_storage, session_storage, answered = [], [], set()
        for origin in origins:
            for is_local in (True, False):
                pairs = await self.dom_storage_items(origin, is_local)
                if pairs is None:
                    continue
                entries, truncated = storage_entry_records(pairs)
                if truncated:
                    notes.append("storage entries were capped at 512 for " + origin)
                bucket = {"origin": origin, "entries": entries}
                if is_local:
                    local_storage.append(bucket)
                    answered.add((origin, "local"))
                else:
                    session_storage.append(bucket)
                    answered.add((origin, "session"))
        if answered:
            notes.append("DOMStorage answered for " + str(len(answered)) + " origin/store reads")
            return local_storage, session_storage
        notes.append("DOMStorage answered for no origin; a current-origin-only read ran instead")
        fallback = await self.current_storage_fallback(notes)
        if fallback is None:
            return [], []
        origin = str(fallback.get("origin", ""))
        local_entries, _ = storage_entry_records(fallback.get("local") or [])
        session_entries, _ = storage_entry_records(fallback.get("session") or [])
        return [{"origin": origin, "entries": local_entries}], \
            [{"origin": origin, "entries": session_entries}]

    async def dom_storage_items(self, origin, is_local):
        try:
            response = await self.cdp(
                {"method": "DOMStorage.getDOMStorageItems",
                 "params": {"storageId": {"securityOrigin": origin, "isLocalStorage": is_local}}},
                timeout=15)
            return response.get("result", {}).get("entries") or []
        except ProtocolError:
            return None

    async def current_storage_fallback(self, notes):
        try:
            payload = await self.script_json(_CURRENT_STORAGE_BODY, "")
        except ProtocolError as error:
            notes.append("the storage fallback failed: " + error.reason)
            return None
        if not isinstance(payload, dict):
            return None
        if payload.get("truncation"):
            notes.append("the current-origin fallback was capped at 512 entries per store")
        return payload

    # seed_storage ---------------------------------------------------------

    async def seed_storage(self, params):
        applied, notes = [], []
        cookies = params.get("cookies") if isinstance(params.get("cookies"), list) else []
        local = params.get("local_storage") if isinstance(params.get("local_storage"), list) else []
        session = params.get("session_storage") if isinstance(params.get("session_storage"), list) else []
        if cookies:
            cookie_params, mismatched = [], 0
            for seed in cookies:
                param, same_site = cookie_to_param(seed)
                cookie_params.append(param)
                if same_site is not None and "sameSite" not in param:
                    mismatched += 1
            await self.cdp(NetworkCommands.set_cookies(cookie_params), timeout=30)
            applied.append("cookies")
            if mismatched:
                notes.append(str(mismatched) + " cookies carried an unusable same_site spelling "
                             "and were seeded without it")
        seeds = []
        for bucket, is_session in ((local, False), (session, True)):
            for origin_bucket in bucket:
                if not isinstance(origin_bucket, dict) or not isinstance(origin_bucket.get("origin"), str):
                    raise ProtocolError("bad_params", "each storage bucket needs an origin string")
                entries = origin_bucket.get("entries") if isinstance(origin_bucket.get("entries"), dict) else {}
                seeds.append({"session": is_session, "origin": origin_bucket["origin"],
                              "entries": {str(name): value for name, value in list(entries.items())[:512]}})
        if seeds:
            await self.ensure_page_enabled()
            notes.append("the Page domain was enabled for the one-shot seed removal listener")
            script = _SEED_STORAGE_BODY.replace("__SEEDS__", json.dumps(seeds, ensure_ascii=True))
            response = await self.cdp(PageCommands.add_script_to_evaluate_on_new_document(script), timeout=30)
            identifier = response.get("result", {}).get("identifier")
            if not isinstance(identifier, str) or not identifier:
                raise ProtocolError("artifact_failed", "the seed script did not register")
            self._seed_script_id = identifier
            if self._seed_callback_id is not None:
                try:
                    await self.tab.remove_callback(self._seed_callback_id)
                except Exception:
                    pass
            self._seed_callback_id = await self.tab.on(PageEvent.FRAME_NAVIGATED, self.on_seed_navigation)
            notes.append("storage seeds apply when each seeded origin's next document loads; "
                         "origins not navigated to keep whatever they had")
            if any(not seed["session"] for seed in seeds):
                applied.append("local_storage")
            if any(seed["session"] for seed in seeds):
                applied.append("session_storage")
        if not applied:
            notes.append("nothing to seed")
        return {"applied": applied, "notes": notes}

    async def on_seed_navigation(self, event):
        frame = event.get("params", {}).get("frame", {})
        if frame.get("parentId") or self._seed_script_id is None:
            return
        identifier, self._seed_script_id = self._seed_script_id, None
        callback_id, self._seed_callback_id = self._seed_callback_id, None
        try:
            await self.tab._connection_handler.execute_command(
                PageCommands.remove_script_to_evaluate_on_new_document(identifier), timeout=10)
        except Exception:
            pass
        if callback_id is not None:
            try:
                await self.tab.remove_callback(callback_id)
            except Exception:
                pass

    # close_session --------------------------------------------------------

    async def close_session(self, params):
        stop_loading = bool(params.get("stop_loading", False))
        notes = []
        outcome = "terminated-owned-process"
        if self.mode == "connect":
            outcome = "disconnected-external"
            if stop_loading:
                try:
                    await self.cdp(PageCommands.stop_loading(), timeout=10)
                    notes.append("page navigation stop applied")
                except ProtocolError as error:
                    notes.append("stop_loading failed: " + error.reason)
            try:
                await asyncio.wait_for(self.tab._connection_handler.close(), timeout=5)
            except Exception:
                pass
        else:
            await self.stop_owned_browser()
        self.own_stopped = True
        self.stopping = True
        result = {"outcome": outcome, "profile_removed": False}
        if notes:
            result["notes"] = notes
        return result

    async def stop_owned_browser(self):
        if self.own_stopped or self.browser is None:
            return
        try:
            await asyncio.wait_for(self.browser.stop(), timeout=45)
            self.own_stopped = True
            return
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        process = self.owned_process()
        if process is not None and process.poll() is None:
            await asyncio.get_running_loop().run_in_executor(None, terminate_process, process)
        else:
            log("the owned browser process had already exited")
        self.own_stopped = True

    def sync_kill_owned(self):
        process = self.owned_process()
        if process is None or self.own_stopped:
            return
        terminate_process(process)
        self.own_stopped = True

    async def teardown(self):
        if self.mode == "launch" and self.browser is not None and not self.own_stopped:
            process = self.owned_process()
            if process is not None and process.poll() is None:
                try:
                    await asyncio.wait_for(
                        asyncio.get_running_loop().run_in_executor(None, terminate_process, process),
                        timeout=6)
                except Exception:
                    pass
            self.own_stopped = True
        if self.tab is not None:
            try:
                await asyncio.wait_for(self.tab._connection_handler.close(), timeout=5)
            except Exception:
                pass
        if self.mode == "launch" and self.browser is not None:
            try:
                await asyncio.wait_for(self.browser.close(), timeout=5)
            except Exception:
                pass


async def start_bridge(holder):
    bridge = Bridge()
    holder.append(bridge)
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()

    def on_sigterm():
        bridge.exit_code = 1
        bridge.stopping = True
        task.cancel()

    loop.add_signal_handler(signal.SIGTERM, on_sigterm)
    try:
        await bridge.serve()
    except asyncio.CancelledError:
        pass
    finally:
        await bridge.teardown()


def main():
    logging.basicConfig(format="%(levelname)s %(name)s: %(message)s",
                        level=os.environ.get("REA_PYDOLL_BRIDGE_LOG", "WARNING"))
    if "--check" in sys.argv:
        # The probe must not enter the serve loop: it advertises and exits
        # deterministically without depending on stdin or the event loop.
        write_line({"advertising": {"protocol": PROTOCOL_VERSION,
                                    "pydoll_version": pydoll_version(),
                                    "capabilities": CAPABILITIES}})
        missing = probe_pydoll()
        if missing is not None:
            sys.stderr.write("[rea-pydoll-bridge] " + missing + "\n")
            os._exit(3)
        sys.stdout.flush()
        os._exit(0)
    holder = []
    code = 0
    try:
        asyncio.run(start_bridge(holder))
        code = holder[0].exit_code if holder else 0
    except KeyboardInterrupt:
        code = 130
    finally:
        bridge = holder[0] if holder else None
        if bridge is not None and not bridge.own_stopped:
            bridge.sync_kill_owned()
        os._exit(code)


if __name__ == "__main__":
    main()