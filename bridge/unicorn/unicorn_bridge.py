#!/usr/bin/env python3
"""REA Unicorn/Keystone sidecar.

One job per process. A single JSON request line arrives on stdin and exactly one
JSON answer line leaves on stdout; diagnostics go to stderr. The answer carries
typed values, digests, and executed address pairs only: code bytes, stub
arguments, and emulated memory content are never echoed back.

Pinned against Unicorn 2.1.x with Keystone for assembly. Run it with the
interpreter of the caller-managed environment that carries both, for example:

    "$REA_UNICORN_PYTHON" -I -B "$REA_UNICORN_BRIDGE_DIR/unicorn_bridge.py"
"""

from __future__ import annotations

import hashlib
import json
import sys
import time

PROTOCOL = 1
PINNED_UNICORN_MINOR = "2.1"
MAX_FRAME_BYTES = 1 << 20
MAX_CODE_BYTES = 1 << 18
PAGE = 0x1000

ARGUMENT_REGISTERS = {
    "x86_64": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "x86_32": (),
    "x86_16": (),
    "arm": ("r0", "r1", "r2", "r3"),
    "thumb": ("r0", "r1", "r2", "r3"),
    "arm64": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
    "mips32": ("a0", "a1", "a2", "a3"),
    "mips64": ("a0", "a1", "a2", "a3"),
    "ppc32": ("r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"),
}

STACK_REGISTERS = {
    "x86_64": "rsp",
    "x86_32": "esp",
    "x86_16": "sp",
    "arm": "sp",
    "thumb": "sp",
    "arm64": "sp",
    "mips32": "sp",
    "mips64": "sp",
    "ppc32": "r1",
}

PROGRAM_COUNTER_REGISTERS = {
    "x86_64": "rip",
    "x86_32": "eip",
    "x86_16": "ip",
    "arm": "pc",
    "thumb": "pc",
    "arm64": "pc",
    "mips32": "pc",
    "mips64": "pc",
    "ppc32": "pc",
}

# Register that holds the return address on architectures without a call stack.
LINK_REGISTERS = {
    "arm": "lr",
    "thumb": "lr",
    "arm64": "x30",
    "mips32": "ra",
    "mips64": "ra",
    "ppc32": "lr",
}

ARCH_CONSTANT_NAMES = {
    "x86_16": "x86",
    "x86_32": "x86",
    "x86_64": "x86",
    "arm": "arm",
    "thumb": "arm",
    "arm64": "arm64",
    "mips32": "mips",
    "mips64": "mips",
    "ppc32": "ppc",
}

POINTER_BYTES = {
    "x86_16": 2,
    "x86_32": 4,
    "x86_64": 8,
    "arm": 4,
    "thumb": 4,
    "arm64": 8,
    "mips32": 4,
    "mips64": 8,
    "ppc32": 4,
}

BIG_ENDIAN_ARCHITECTURES = frozenset(("arm", "mips32", "mips64", "ppc32"))


class BridgeRefusal(Exception):
    """A job REA must not retry unchanged."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def align_up(value: int, alignment: int = PAGE) -> int:
    remainder = value % alignment
    return value if remainder == 0 else value + alignment - remainder


def align_down(value: int, alignment: int = PAGE) -> int:
    return value - (value % alignment)


def digest_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def parse_address(value: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise BridgeRefusal("invalid_request", "an address must be a 0x-prefixed string")
    try:
        parsed = int(value, 16)
    except ValueError as cause:
        raise BridgeRefusal("invalid_request", "an address is not hexadecimal") from cause
    if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise BridgeRefusal("invalid_request", "an address is outside the 64-bit space")
    return parsed


def require_int(request: dict, name: str, minimum: int, maximum: int) -> int:
    value = request.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise BridgeRefusal("invalid_request", f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise BridgeRefusal("invalid_request", f"{name} is outside its admitted range")
    return value


def unicorn_version() -> str:
    import unicorn

    version = getattr(unicorn, "__version__", None)
    if isinstance(version, str) and version:
        return version
    major, minor = unicorn.uc_version()
    return f"{major}.{minor}.0"


def keystone_version():
    try:
        import keystone
    except ImportError:
        return None
    version = getattr(keystone, "__version__", None)
    return version if isinstance(version, str) and version else "unknown"


def require_unicorn():
    try:
        import unicorn
    except ImportError as cause:
        raise BridgeRefusal(
            "missing_dependency",
            "the selected interpreter cannot import unicorn",
        ) from cause
    version = unicorn_version()
    if not version.startswith(f"{PINNED_UNICORN_MINOR}."):
        raise BridgeRefusal(
            "version_unsupported",
            f"unicorn {version} is not the pinned {PINNED_UNICORN_MINOR}.x release",
        )
    return unicorn


def unicorn_mode(unicorn, arch: str, big_endian: bool) -> tuple:
    constants = unicorn
    modes = {
        "x86_16": (constants.UC_ARCH_X86, constants.UC_MODE_16),
        "x86_32": (constants.UC_ARCH_X86, constants.UC_MODE_32),
        "x86_64": (constants.UC_ARCH_X86, constants.UC_MODE_64),
        "arm": (constants.UC_ARCH_ARM, constants.UC_MODE_ARM),
        "thumb": (constants.UC_ARCH_ARM, constants.UC_MODE_THUMB),
        "arm64": (constants.UC_ARCH_ARM64, constants.UC_MODE_ARM),
        "mips32": (constants.UC_ARCH_MIPS, constants.UC_MODE_MIPS32),
        "mips64": (constants.UC_ARCH_MIPS, constants.UC_MODE_MIPS64),
        "ppc32": (constants.UC_ARCH_PPC, constants.UC_MODE_PPC32),
    }
    if arch not in modes:
        raise BridgeRefusal("unsupported_mode", f"unicorn has no mode for {arch}")
    uc_arch, mode = modes[arch]
    if big_endian:
        mode |= constants.UC_MODE_BIG_ENDIAN
    return uc_arch, mode


def register_table(unicorn, arch: str) -> dict:
    modules = {
        "x86_16": "x86_const",
        "x86_32": "x86_const",
        "x86_64": "x86_const",
        "arm": "arm_const",
        "thumb": "arm_const",
        "arm64": "arm64_const",
        "mips32": "mips_const",
        "mips64": "mips_const",
        "ppc32": "ppc_const",
    }
    module_name = modules.get(arch)
    if module_name is None:
        raise BridgeRefusal("unsupported_mode", f"unicorn has no register table for {arch}")
    module = getattr(unicorn, module_name, None)
    if module is None:
        raise BridgeRefusal("missing_dependency", f"unicorn cannot expose {module_name}")
    constant_arch = ARCH_CONSTANT_NAMES.get(arch)
    if constant_arch is None:
        raise BridgeRefusal("unsupported_mode", f"unicorn has no register table for {arch}")
    prefix = f"UC_{constant_arch.upper()}_REG_"
    table = {}
    for name in dir(module):
        if not name.startswith(prefix):
            continue
        short = name[len(prefix):].lower()
        if not short.replace("_", "").isalnum() or short == "ending":
            continue
        table[short] = getattr(module, name)
    return table


def peek(memory_read, address: int, width: int) -> bytes:
    for size in (width, 2, 1):
        if size <= 0 or size > width:
            continue
        try:
            return memory_read(address, size)
        except Exception:
            continue
    return b""


def is_call_instruction(arch: str, opcode: bytes) -> bool:
    if not opcode:
        return False
    if arch in ("x86_16", "x86_32", "x86_64"):
        if opcode[0] == 0xE8:
            return True
        if opcode[0] == 0xFF and len(opcode) > 1:
            return (opcode[1] >> 3) & 0x7 in (2, 3)
        return False
    if arch == "thumb":
        word = int.from_bytes(opcode[:2].ljust(2, b"\x00"), "little")
        return (word & 0xF800) == 0xF000
    if arch in ("arm", "arm64", "mips32", "mips64", "ppc32"):
        word = int.from_bytes(opcode[:4].ljust(4, b"\x00"), "little")
        if arch == "arm":
            return (word & 0x0F000000) == 0x0B000000
        if arch == "arm64":
            return (word & 0xFC000000) == 0x94000000 or (
                word & 0xFFFFFC1F
            ) == 0xD63F0000
        if arch in ("mips32", "mips64"):
            return (word >> 26) == 0x03
        return (word >> 26) == 0x12
    return False


def errno_name(unicorn, errno: int) -> str:
    constants = getattr(unicorn, "unicorn_const", unicorn)
    for name in dir(constants):
        if not name.startswith("UC_ERR_"):
            continue
        if getattr(constants, name) == errno:
            return name[len("UC_ERR_"):].lower()
    return f"err_{errno}"


def push_word(uc, table, register_name, pointer_bytes, big_endian, value) -> int:
    if register_name not in table:
        raise BridgeRefusal("unsupported_mode", f"{register_name} is unavailable in this mode")
    stack_pointer = uc.reg_read(table[register_name]) - pointer_bytes
    endianness = "big" if big_endian else "little"
    uc.mem_write(stack_pointer, value.to_bytes(pointer_bytes, endianness))
    uc.reg_write(table[register_name], stack_pointer)
    return stack_pointer


def setup_arguments(uc, table, arch, pointer_bytes, big_endian, args, sentinel) -> None:
    names = ARGUMENT_REGISTERS.get(arch, ())
    stack_spilled = []
    for index, value in enumerate(args):
        if index < len(names) and names[index] in table:
            uc.reg_write(table[names[index]], value)
        else:
            stack_spilled.append(value)
    stack_register = STACK_REGISTERS.get(arch)
    if stack_register is None or stack_register not in table:
        if stack_spilled:
            raise BridgeRefusal("unsupported_mode", "this mode has no modelled stack")
        return
    for value in reversed(stack_spilled):
        push_word(uc, table, stack_register, pointer_bytes, big_endian, value)
    if arch in ("x86_16", "x86_32"):
        push_word(uc, table, stack_register, pointer_bytes, big_endian, sentinel)
    link = LINK_REGISTERS.get(arch)
    if link is not None:
        if link not in table:
            raise BridgeRefusal("unsupported_mode", f"{link} is unavailable in this mode")
        uc.reg_write(table[link], sentinel)


def observe_registers(uc, table, requested) -> tuple:
    values = []
    unknown = []
    for name in requested:
        register_id = table.get(name)
        if register_id is None:
            unknown.append(name)
            continue
        try:
            value = uc.reg_read(register_id)
        except Exception:
            unknown.append(name)
            continue
        values.append({"name": name, "value": f"0x{value:x}"})
    return values, unknown


def observe_memory(uc, requested) -> tuple:
    observed = []
    omitted = 0
    for window in requested:
        address = parse_address(window.get("address", ""))
        length = window.get("length")
        if not isinstance(length, int) or isinstance(length, bool) or length < 1:
            raise BridgeRefusal("invalid_request", "a memory window needs a positive length")
        try:
            payload = uc.mem_read(address, length)
        except Exception:
            omitted += 1
            continue
        observed.append(
            {
                "address": f"0x{address:x}",
                "length": len(payload),
                "sha256": digest_hex(bytes(payload)),
            }
        )
    return observed, omitted


def emulate(unicorn, request: dict, bridge: dict) -> dict:
    arch = request.get("arch")
    if not isinstance(arch, str):
        raise BridgeRefusal("invalid_request", "arch must be a string")
    big_endian = request.get("endianness", "little") == "big"
    if big_endian and arch not in BIG_ENDIAN_ARCHITECTURES:
        raise BridgeRefusal("unsupported_mode", f"unicorn has no big-endian {arch} mode")
    code_hex = request.get("code_hex")
    if not isinstance(code_hex, str) or not code_hex:
        raise BridgeRefusal("invalid_request", "code_hex must be a non-empty hex string")
    try:
        code = bytes.fromhex(code_hex)
    except ValueError as cause:
        raise BridgeRefusal("invalid_request", "code_hex is not hexadecimal") from cause
    if not code or len(code) > MAX_CODE_BYTES:
        raise BridgeRefusal("invalid_request", "code_hex is outside its admitted size")
    if digest_hex(code) != request.get("code_sha256"):
        raise BridgeRefusal("invalid_request", "code_sha256 does not match code_hex")
    pointer_bytes = POINTER_BYTES.get(arch)
    if pointer_bytes is None:
        raise BridgeRefusal("unsupported_mode", f"unicorn has no pointer width for {arch}")

    code_base = parse_address(request.get("code_base", "0x0"))
    entry = parse_address(request.get("entry", "0x0"))
    stack_size = require_int(request, "stack_size", PAGE, 1 << 20)
    max_steps = require_int(request, "max_steps", 1, 5_000_000)
    timeout_ms = require_int(request, "timeout_ms", 1, 30_000)
    limits = request.get("limits") or {}
    max_edges = int(limits.get("max_edges", 4096))
    max_call_targets = int(limits.get("max_call_targets", 32))
    raw_args = request.get("args") or []
    requested_registers = [str(name) for name in (request.get("observe_registers") or [])]
    requested_memory = request.get("observe_memory") or []
    stop_addresses = {
        parse_address(value) for value in (request.get("stop_addresses") or [])
    }

    address_limit = 1 << (pointer_bytes * 8)
    code_start = align_down(code_base)
    code_end = code_base + len(code)
    stack_base = align_up(code_end)
    stack_end = stack_base + stack_size
    sentinel = align_up(stack_end)
    if sentinel + PAGE > address_limit:
        raise BridgeRefusal(
            "invalid_request",
            "the selected layout does not fit this mode's address space",
        )
    if not code_base <= entry < code_end:
        raise BridgeRefusal("invalid_request", "entry lies outside the admitted code")

    uc_arch, uc_mode = unicorn_mode(unicorn, arch, big_endian)
    uc = unicorn.Uc(uc_arch, uc_mode)
    uc.mem_map(code_start, align_up((code_base - code_start) + len(code)), unicorn.UC_PROT_ALL)
    uc.mem_write(code_base, code)
    uc.mem_map(stack_base, align_up(stack_size), unicorn.UC_PROT_ALL)
    uc.mem_map(sentinel, PAGE, unicorn.UC_PROT_ALL)
    table = register_table(unicorn, arch)
    if not table:
        raise BridgeRefusal("missing_dependency", "the register table is empty")

    stack_register = STACK_REGISTERS[arch]
    if stack_register not in table:
        raise BridgeRefusal("unsupported_mode", f"{stack_register} is unavailable")
    uc.reg_write(table[stack_register], stack_end)
    args = [parse_address(value) for value in raw_args]
    setup_arguments(uc, table, arch, pointer_bytes, big_endian, args, sentinel)
    pc_register = PROGRAM_COUNTER_REGISTERS[arch]
    if pc_register not in table:
        raise BridgeRefusal("unsupported_mode", f"{pc_register} is unavailable")
    uc.reg_write(table[pc_register], entry)

    state = {
        "steps": 0,
        "edges": [],
        "seen_edges": set(),
        "call_count": 0,
        "call_targets": {},
        "call_targets_truncated": False,
        "pending_call": None,
        "stop": None,
    }

    def on_code(uc_handle, address, size, user_data=None) -> None:
        if state["pending_call"] is not None:
            target = state["call_targets"].get(address)
            if target is None:
                if len(state["call_targets"]) >= max_call_targets:
                    state["call_targets_truncated"] = True
                else:
                    state["call_targets"][address] = 1
            else:
                state["call_targets"][address] = target + 1
            state["pending_call"] = None
        if state["previous"] is not None:
            edge = f"0x{state['previous']:x}->0x{address:x}"
            if edge not in state["seen_edges"]:
                if len(state["edges"]) >= max_edges:
                    state["edges_truncated"] = True
                else:
                    state["seen_edges"].add(edge)
                    state["edges"].append(edge)
        state["previous"] = address
        state["steps"] += 1
        opcode = peek(uc_handle.mem_read, address, min(size or 4, 4))
        if is_call_instruction(arch, opcode):
            state["call_count"] += 1
            state["pending_call"] = address
        if address in stop_addresses:
            state["stop"] = ("stop_address", {"code": "caller_stop_address", "address": address})
            uc_handle.emu_stop()
            return
        if state["steps"] >= max_steps:
            state["stop"] = ("max_steps", {"code": "max_steps", "address": address})
            uc_handle.emu_stop()

    state["previous"] = None
    state["edges_truncated"] = False
    uc.hook_add(unicorn.UC_HOOK_CODE, on_code)

    timeout_us = timeout_ms * 1000
    started = time.monotonic()
    failure = None
    try:
        uc.emu_start(entry, sentinel, timeout_us, max_steps)
    except unicorn.UcError as cause:
        failure = cause
    elapsed_ms = (time.monotonic() - started) * 1000.0

    if failure is not None:
        errno = getattr(failure, "errno", 0) or 0
        detail_code = errno_name(unicorn, errno)
        if detail_code in ("read_unmapped", "write_unmapped", "fetch_unmapped"):
            exit_reason = "invalid_memory_access"
        elif detail_code in ("insn_invalid", "invalid_instruction"):
            exit_reason = "unsupported_instruction"
        else:
            exit_reason = "bridge_error"
        exit_detail = {"code": detail_code, "address": None}
    elif state["stop"] is not None:
        exit_reason, exit_detail = state["stop"]
    else:
        try:
            pc = uc.reg_read(table[pc_register])
        except Exception:
            pc = None
        if pc == sentinel:
            exit_reason = "returned"
            exit_detail = {"code": "sentinel_return", "address": f"0x{sentinel:x}"}
        elif state["steps"] >= max_steps:
            exit_reason = "max_steps"
            exit_detail = {"code": "step_bound", "address": None}
        elif elapsed_ms >= timeout_ms:
            exit_reason = "timeout"
            exit_detail = {"code": "deadline", "address": None}
        else:
            exit_reason = "bridge_error"
            exit_detail = {"code": "unexpected_stop", "address": None}

    registers, unknown_registers = observe_registers(uc, table, requested_registers)
    memory, memory_omitted = observe_memory(uc, requested_memory)
    call_targets = [
        {"address": f"0x{address:x}", "count": count}
        for address, count in sorted(state["call_targets"].items())
    ]
    return {
        "bridge": bridge,
        "arch": arch,
        "endianness": "big" if big_endian else "little",
        "code": {
            "source": "hex",
            "path": None,
            "offset": None,
            "length": len(code),
            "sha256": digest_hex(code),
        },
        "code_base": f"0x{code_base:x}",
        "entry": f"0x{entry:x}",
        "exit": exit_reason,
        "exit_detail": exit_detail,
        "executed_steps": state["steps"],
        "call_count": state["call_count"],
        "call_targets": call_targets,
        "call_targets_truncated": state["call_targets_truncated"],
        "edges": state["edges"],
        "edge_count": len(state["edges"]),
        "edges_truncated": state["edges_truncated"],
        "registers": registers,
        "unknown_registers": unknown_registers,
        "memory": memory,
        "memory_omitted": memory_omitted,
        "coverage": "partial"
        if state["edges_truncated"] or state["call_targets_truncated"] or exit_reason in ("max_steps", "timeout")
        else "complete",
    }


def keystone_mode(keystone, arch: str, big_endian: bool) -> tuple:
    modes = {
        "x86_16": (keystone.KS_ARCH_X86, keystone.KS_MODE_16),
        "x86_32": (keystone.KS_ARCH_X86, keystone.KS_MODE_32),
        "x86_64": (keystone.KS_ARCH_X86, keystone.KS_MODE_64),
        "arm": (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM),
        "thumb": (keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB),
        "arm64": (keystone.KS_ARCH_ARM64, 0),
        "mips32": (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32),
        "mips64": (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64),
        "ppc32": (keystone.KS_ARCH_PPC, keystone.KS_MODE_PPC32),
    }
    if arch not in modes:
        raise BridgeRefusal("unsupported_mode", f"keystone has no mode for {arch}")
    ks_arch, mode = modes[arch]
    mode |= keystone.KS_MODE_BIG_ENDIAN if big_endian else keystone.KS_MODE_LITTLE_ENDIAN
    return ks_arch, mode


def assemble(request: dict, bridge: dict) -> dict:
    try:
        import keystone
    except ImportError as cause:
        raise BridgeRefusal(
            "missing_dependency", "the selected interpreter cannot import keystone"
        ) from cause
    arch = request.get("arch")
    if not isinstance(arch, str):
        raise BridgeRefusal("invalid_request", "arch must be a string")
    big_endian = request.get("endianness", "little") == "big"
    if big_endian and arch not in BIG_ENDIAN_ARCHITECTURES:
        raise BridgeRefusal("unsupported_mode", f"keystone has no big-endian {arch} mode")
    assembly = request.get("assembly")
    if not isinstance(assembly, str) or not assembly:
        raise BridgeRefusal("invalid_request", "assembly must be a non-empty string")
    base_address = parse_address(request.get("base_address", "0x0"))
    max_bytes = require_int(request, "max_bytes", 1, MAX_CODE_BYTES)
    ks_arch, ks_mode = keystone_mode(keystone, arch, big_endian)
    engine = keystone.Ks(ks_arch, ks_mode)
    try:
        encoding, count = engine.asm(assembly, base_address)
    except keystone.KsError as cause:
        raise BridgeRefusal("invalid_request", str(cause)) from cause
    encoded = bytes(encoding)
    if not encoded:
        raise BridgeRefusal("invalid_request", "the assembly encoded no bytes")
    if len(encoded) > max_bytes:
        raise BridgeRefusal(
            "invalid_request", "the assembly exceeds the admitted byte budget"
        )
    return {
        "bridge": bridge,
        "arch": arch,
        "endianness": "big" if big_endian else "little",
        "base_address": f"0x{base_address:x}",
        "assembly": assembly,
        "bytes_hex": encoded.hex(),
        "size": len(encoded),
        "sha256": digest_hex(encoded),
        "instruction_count": int(count) or None,
    }


def handle(request: dict) -> dict:
    if not isinstance(request, dict):
        raise BridgeRefusal("invalid_request", "a request must be a JSON object")
    kind = request.get("kind")
    if kind not in ("emulate", "assemble"):
        raise BridgeRefusal("invalid_request", "kind must be emulate or assemble")
    if request.get("protocol") != PROTOCOL:
        raise BridgeRefusal(
            "protocol_mismatch", f"this bridge speaks protocol {PROTOCOL}"
        )
    if kind == "emulate":
        unicorn = require_unicorn()
        bridge = {
            "protocol": PROTOCOL,
            "unicorn_version": unicorn_version(),
            "keystone_version": keystone_version(),
        }
        return emulate(unicorn, request, bridge)
    return assemble(
        request,
        {
            "protocol": PROTOCOL,
            "unicorn_version": unicorn_version(),
            "keystone_version": keystone_version(),
        },
    )


def answer(kind, job_id, result=None, refusal=None) -> dict:
    frame = {"protocol": PROTOCOL, "job_id": job_id, "kind": kind}
    if refusal is None:
        frame["ok"] = True
        frame["result"] = result
    else:
        frame["ok"] = False
        frame["error"] = {"code": refusal.code, "message": refusal.message[:4096]}
    return frame


def emit(frame: dict) -> None:
    payload = json.dumps(frame, separators=(",", ":"))
    if len(payload.encode("utf-8")) > MAX_FRAME_BYTES:
        payload = json.dumps(
            {
                "protocol": PROTOCOL,
                "job_id": frame.get("job_id"),
                "kind": frame.get("kind"),
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


def main() -> int:
    line = sys.stdin.readline(MAX_FRAME_BYTES + 2)
    if not line:
        sys.stderr.write("rea-unicorn-bridge: no request on stdin\n")
        return 2
    job_id = None
    kind = None
    try:
        request = json.loads(line)
    except ValueError:
        emit(
            answer(
                kind,
                job_id,
                refusal=BridgeRefusal("invalid_request", "the request was not one JSON frame"),
            )
        )
        return 0
    if isinstance(request, dict):
        job_id = request.get("job_id")
        kind = request.get("kind")
    try:
        result = handle(request)
    except BridgeRefusal as refusal:
        emit(answer(kind, job_id, refusal=refusal))
        return 0
    except Exception as cause:  # noqa: BLE001 - one job must always answer
        emit(
            answer(
                kind,
                job_id,
                refusal=BridgeRefusal("job_failed", f"{type(cause).__name__}: {cause}"),
            )
        )
        return 0
    emit(answer(kind, job_id, result=result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
