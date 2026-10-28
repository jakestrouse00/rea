"""Offline tests for the REA Unicorn/Keystone sidecar.

The real engine is not installed here, so these tests install stand-in
``unicorn`` and ``keystone`` modules that model only the API surface the bridge
uses. They establish the bridge's own protocol, layout, refusal, and
value-free output rules; they make no claim about Unicorn or Keystone behavior.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path

BRIDGE_PATH = Path(__file__).with_name("unicorn_bridge.py")


def load_bridge():
    spec = importlib.util.spec_from_file_location("rea_unicorn_bridge", BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeUcError(Exception):
    def __init__(self, errno: int) -> None:
        super().__init__(f"uc error {errno}")
        self.errno = errno


# The stand-in decodes (uc_arch, uc_mode) back to a name and then applies its
# own return model, so the bridge cannot make a return "true" by assertion: a
# missing return address shows up as a program counter that never reaches the
# stop address.
ARCH_MODES = {
    (4, 2): "x86_16",
    (4, 4): "x86_32",
    (4, 8): "x86_64",
    (1, 0): "arm",
    (1, 16): "thumb",
    (2, 0): "arm64",
    (3, 4): "mips32",
    (3, 8): "mips64",
    (5, 4): "ppc32",
}

CONST_MODULES = {
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

# How each architecture class returns: a popped stack word or a link register.
RETURN_MODELS = {
    "x86_16": {"kind": "stack", "stack": "sp", "pc": "ip", "word": 2},
    "x86_32": {"kind": "stack", "stack": "esp", "pc": "eip", "word": 4},
    "x86_64": {"kind": "stack", "stack": "rsp", "pc": "rip", "word": 8},
    "arm": {"kind": "link", "link": "lr", "pc": "pc", "word": 4},
    "thumb": {"kind": "link", "link": "lr", "pc": "pc", "word": 4},
    "arm64": {"kind": "link", "link": "x30", "pc": "pc", "word": 8},
    "mips32": {"kind": "link", "link": "ra", "pc": "pc", "word": 4},
    "mips64": {"kind": "link", "link": "ra", "pc": "pc", "word": 8},
    "ppc32": {"kind": "link", "link": "lr", "pc": "pc", "word": 4},
}


def register_ids(constants, arch: str) -> dict:
    """Map register names to the stand-in's identifiers for one architecture."""
    prefix = {
        "x86_16": "X86",
        "x86_32": "X86",
        "x86_64": "X86",
        "arm": "ARM",
        "thumb": "ARM",
        "arm64": "ARM64",
        "mips32": "MIPS",
        "mips64": "MIPS",
        "ppc32": "PPC",
    }[arch]
    module = getattr(constants, CONST_MODULES[arch])
    marker = f"UC_{prefix}_REG_"
    return {
        name[len(marker) :].lower(): getattr(module, name)
        for name in dir(module)
        if name.startswith(marker) and name[len(marker) :].lower() != "ending"
    }


class FakeUc:
    constants = None

    def __init__(self, arch, mode) -> None:
        self.arch = ARCH_MODES[(arch, mode & ~(1 << 30))]
        self.mode = mode
        self.ids = register_ids(self.constants, self.arch)
        self.registers = {}
        self.memory = {}
        self.mapped = []
        self.hooked = []
        self.on_start = None

    def mem_map(self, address, size, prot) -> None:
        self.mapped.append((address, size))

    def mem_write(self, address, payload) -> None:
        self.memory[address] = bytes(payload)

    def mem_read(self, address, size):
        for start, payload in self.memory.items():
            if start <= address and address + size <= start + len(payload):
                offset = address - start
                return payload[offset : offset + size]
        raise FakeUcError(6)

    def reg_write(self, register, value) -> None:
        self.registers[register] = value

    def reg_read(self, register):
        return self.registers.get(register, 0)

    def hook_add(self, kind, callback) -> None:
        self.hooked.append(callback)

    def word_at(self, address, size):
        try:
            payload = self.mem_read(address, size)
        except FakeUcError:
            return None
        return int.from_bytes(payload, "big" if self.mode & (1 << 30) else "little")

    def emu_start(self, begin, until, timeout, count) -> None:
        if self.on_start is not None:
            self.on_start(self)
            return
        for callback in self.hooked:
            callback(self, begin, 1, None)
        model = RETURN_MODELS[self.arch]
        program_counter = self.ids[model["pc"]]
        if model["kind"] == "stack":
            stack_pointer = self.ids[model["stack"]]
            pointer = self.reg_read(stack_pointer)
            popped = self.word_at(pointer, model["word"])
            self.reg_write(stack_pointer, pointer + model["word"])
            self.registers[program_counter] = 0 if popped is None else popped
            return
        self.registers[program_counter] = self.reg_read(self.ids[model["link"]])

    def emu_stop(self) -> None:
        return None


def unicorn_stub(version: str = "2.1.4"):
    module = types.ModuleType("unicorn")
    module.__version__ = version
    module.uc_version = lambda: (2, 1)
    module.Uc = FakeUc
    module.UcError = FakeUcError
    module.UC_ARCH_X86 = 4
    module.UC_ARCH_ARM = 1
    module.UC_ARCH_ARM64 = 2
    module.UC_ARCH_MIPS = 3
    module.UC_ARCH_PPC = 5
    module.UC_MODE_16 = 2
    module.UC_MODE_32 = 4
    module.UC_MODE_64 = 8
    module.UC_MODE_ARM = 0
    module.UC_MODE_THUMB = 16
    module.UC_MODE_MIPS32 = 4
    module.UC_MODE_MIPS64 = 8
    module.UC_MODE_PPC32 = 4
    module.UC_MODE_BIG_ENDIAN = 1 << 30
    module.UC_PROT_ALL = 7
    module.UC_HOOK_CODE = 4
    module.UC_ERR_READ_UNMAPPED = 6
    module.UC_ERR_WRITE_UNMAPPED = 7
    module.UC_ERR_FETCH_UNMAPPED = 8
    module.UC_ERR_INSN_INVALID = 17
    module.unicorn_const = types.SimpleNamespace(
        UC_ERR_READ_UNMAPPED=6,
        UC_ERR_WRITE_UNMAPPED=7,
        UC_ERR_FETCH_UNMAPPED=8,
        UC_ERR_INSN_INVALID=17,
    )

    def const_module(prefix: str, names):
        constants = types.ModuleType(prefix.lower())
        for index, name in enumerate(names, start=1):
            setattr(constants, f"UC_{prefix}_REG_{name.upper()}", index)
        setattr(constants, f"UC_{prefix}_REG_ENDING", 0)
        return constants

    module.x86_const = const_module(
        "X86",
        [
            "rax",
            "rcx",
            "rdx",
            "rdi",
            "rsi",
            "r8",
            "r9",
            "rsp",
            "rip",
            "esp",
            "eip",
            "sp",
            "ip",
        ],
    )
    module.arm_const = const_module("ARM", ["r0", "r1", "r2", "r3", "sp", "pc", "lr"])
    module.arm64_const = const_module("ARM64", ["x0", "x1", "sp", "pc", "x30"])
    module.mips_const = const_module("MIPS", ["a0", "sp", "pc", "ra"])
    module.ppc_const = const_module("PPC", ["r1", "r3", "pc", "lr"])
    FakeUc.constants = module
    return module


class FakeKsError(Exception):
    pass


class FakeKs:
    encoded = b"\x90"
    statements = 1
    last_request = None

    def __init__(self, arch, mode) -> None:
        self.arch = arch
        self.mode = mode

    def asm(self, source, address):
        FakeKs.last_request = (self.arch, self.mode, source, address)
        return self.encoded, self.statements


def keystone_stub(version: str = "0.9.2"):
    module = types.ModuleType("keystone")
    module.__version__ = version
    module.Ks = FakeKs
    module.KsError = FakeKsError
    module.KS_ARCH_X86 = 1
    module.KS_ARCH_ARM = 2
    module.KS_ARCH_ARM64 = 3
    module.KS_ARCH_MIPS = 4
    module.KS_ARCH_PPC = 5
    module.KS_MODE_16 = 2
    module.KS_MODE_32 = 4
    module.KS_MODE_64 = 8
    module.KS_MODE_ARM = 0
    module.KS_MODE_THUMB = 16
    module.KS_MODE_MIPS32 = 4
    module.KS_MODE_MIPS64 = 8
    module.KS_MODE_PPC32 = 4
    module.KS_MODE_LITTLE_ENDIAN = 0
    module.KS_MODE_BIG_ENDIAN = 1 << 30
    return module


class BridgeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = load_bridge()
        sys.modules.pop("unicorn", None)
        sys.modules.pop("keystone", None)

    def tearDown(self) -> None:
        sys.modules.pop("unicorn", None)
        sys.modules.pop("keystone", None)

    def request(self, **overrides):
        request = {
            "protocol": 1,
            "job_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
            "kind": "emulate",
            "arch": "x86_64",
            "endianness": "little",
            "code_hex": "90c3",
            "code_sha256": self.bridge.digest_hex(bytes.fromhex("90c3")),
            "code_base": "0x401000",
            "entry": "0x401000",
            "stack_size": 4096,
            "max_steps": 64,
            "timeout_ms": 1000,
            "args": [],
            "stop_addresses": [],
            "observe_registers": [],
            "observe_memory": [],
            "limits": {"max_edges": 8, "max_call_targets": 4},
        }
        request.update(overrides)
        return request

    def refuse(self, request):
        with self.assertRaises(self.bridge.BridgeRefusal) as raised:
            self.bridge.handle(request)
        return raised.exception


class ProtocolTests(BridgeTestCase):
    def test_refuses_an_unknown_job_kind(self):
        self.assertEqual(
            self.refuse({"protocol": 1, "kind": "disassemble"}).code,
            "invalid_request",
        )

    def test_refuses_a_different_protocol(self):
        refusal = self.refuse(self.request(protocol=2))
        self.assertEqual(refusal.code, "protocol_mismatch")

    def test_refuses_a_missing_engine(self):
        self.assertEqual(self.refuse(self.request()).code, "missing_dependency")

    def test_refuses_an_unpinned_engine_release(self):
        sys.modules["unicorn"] = unicorn_stub("2.0.1")
        self.assertEqual(self.refuse(self.request()).code, "version_unsupported")

    def test_refuses_code_the_request_does_not_hash(self):
        sys.modules["unicorn"] = unicorn_stub()
        refusal = self.refuse(self.request(code_sha256="0" * 64))
        self.assertEqual(refusal.code, "invalid_request")

    def test_refuses_a_big_endian_mode_without_one(self):
        sys.modules["unicorn"] = unicorn_stub()
        refusal = self.refuse(self.request(endianness="big"))
        self.assertEqual(refusal.code, "unsupported_mode")

    def test_refuses_a_layout_larger_than_the_mode_address_space(self):
        sys.modules["unicorn"] = unicorn_stub()
        refusal = self.refuse(self.request(arch="x86_16"))
        self.assertEqual(refusal.code, "invalid_request")
        self.assertIn("address space", refusal.message)

    def test_refuses_an_entry_outside_the_code(self):
        sys.modules["unicorn"] = unicorn_stub()
        refusal = self.refuse(self.request(entry="0x500000"))
        self.assertEqual(refusal.code, "invalid_request")


class EmulationTests(BridgeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.unicorn = unicorn_stub()
        sys.modules["unicorn"] = self.unicorn

    def test_reports_a_return_without_echoing_code_or_arguments(self):
        result = self.bridge.handle(
            self.request(
                args=["0xdeadbeef"],
                observe_registers=["rax", "rdx", "nope"],
                observe_memory=[{"address": "0x401000", "length": 2}],
            )
        )
        self.assertEqual(result["exit"], "returned")
        self.assertEqual(result["exit_detail"]["code"], "sentinel_return")
        self.assertEqual(result["code"]["length"], 2)
        self.assertEqual(
            result["code"]["sha256"], self.bridge.digest_hex(bytes.fromhex("90c3"))
        )
        self.assertEqual(result["unknown_registers"], ["nope"])
        self.assertEqual(
            [value["name"] for value in result["registers"]], ["rax", "rdx"]
        )
        self.assertEqual(result["memory"][0]["length"], 2)
        self.assertRegex(result["memory"][0]["sha256"], r"^[0-9a-f]{64}$")
        serialized = json.dumps(result)
        self.assertNotIn("90c3", serialized)
        self.assertNotIn("deadbeef", serialized)
        self.assertNotIn("0xdeadbeef", serialized)
        self.assertEqual(result["coverage"], "complete")

    def test_maps_code_stack_and_sentinel_pages(self):
        captured = {}

        def capture(uc):
            captured["uc"] = uc

        original = self.unicorn.Uc

        def factory(arch, mode):
            instance = original(arch, mode)
            instance.on_start = capture
            return instance

        self.unicorn.Uc = factory
        self.bridge.handle(self.request())
        mapped = captured["uc"].mapped
        self.assertEqual(len(mapped), 3)
        self.assertEqual(mapped[0], (0x401000, 0x1000))
        self.assertEqual(mapped[1], (0x402000, 0x1000))
        self.assertEqual(mapped[2], (0x403000, 0x1000))

    def test_pushes_the_return_address_below_the_spilled_arguments(self):
        captured = {}

        def capture(uc):
            captured["uc"] = uc

        original = self.unicorn.Uc

        def factory(arch, mode):
            instance = original(arch, mode)
            instance.on_start = capture
            return instance

        self.unicorn.Uc = factory
        self.bridge.handle(
            self.request(
                args=[
                    "0x1",
                    "0x2",
                    "0x3",
                    "0x4",
                    "0x5",
                    "0x6",
                    "0x7a7a",
                    "0x8b8b",
                ]
            )
        )
        uc = captured["uc"]
        sentinel = uc.mapped[2][0]
        stack_pointer = uc.reg_read(uc.ids["rsp"])
        self.assertEqual(uc.word_at(stack_pointer, 8), sentinel)
        self.assertEqual(uc.word_at(stack_pointer + 8, 8), 0x7A7A)
        self.assertEqual(uc.word_at(stack_pointer + 16, 8), 0x8B8B)
        self.assertEqual(uc.reg_read(uc.ids["rdi"]), 0x1)
        self.assertEqual(uc.reg_read(uc.ids["r9"]), 0x6)

    def test_reports_a_return_on_a_32_bit_stack_architecture(self):
        captured = {}

        def capture(uc):
            captured["uc"] = uc

        original = self.unicorn.Uc

        def factory(arch, mode):
            instance = original(arch, mode)
            instance.on_start = capture
            return instance

        self.unicorn.Uc = factory
        self.bridge.handle(
            self.request(
                arch="x86_32",
                args=["0x11"],
            )
        )
        uc = captured["uc"]
        sentinel = uc.mapped[2][0]
        stack_pointer = uc.reg_read(uc.ids["esp"])
        self.assertEqual(uc.word_at(stack_pointer, 4), sentinel)
        self.assertEqual(uc.word_at(stack_pointer + 4, 4), 0x11)

    def test_reports_a_return_on_a_link_register_architecture(self):
        result = self.bridge.handle(
            self.request(
                arch="arm64",
                code_hex="c0035fd6",
                code_sha256=self.bridge.digest_hex(bytes.fromhex("c0035fd6")),
            )
        )
        self.assertEqual(result["exit"], "returned")
        self.assertEqual(result["exit_detail"]["code"], "sentinel_return")

    def test_reports_invalid_memory_access_as_a_terminal_reason(self):
        original = self.unicorn.Uc

        def factory(arch, mode):
            instance = original(arch, mode)

            def fail(_uc):
                raise FakeUcError(6)

            instance.on_start = fail
            return instance

        self.unicorn.Uc = factory
        result = self.bridge.handle(self.request())
        self.assertEqual(result["exit"], "invalid_memory_access")
        self.assertEqual(result["exit_detail"]["code"], "read_unmapped")
        self.assertEqual(result["exit_detail"]["address"], None)

    def test_stops_at_a_caller_address(self):
        result = self.bridge.handle(
            self.request(stop_addresses=["0x401000"], max_steps=8)
        )
        self.assertEqual(result["exit"], "stop_address")
        self.assertEqual(result["executed_steps"], 1)
        self.assertEqual(result["registers"], [])

    def test_marks_coverage_partial_at_the_step_bound(self):
        result = self.bridge.handle(
            self.request(stop_addresses=[], max_steps=1, observe_registers=["rax"])
        )
        self.assertEqual(result["exit"], "max_steps")
        self.assertEqual(result["executed_steps"], 1)
        self.assertEqual(result["coverage"], "partial")


class StandInModelTests(BridgeTestCase):
    def test_stand_in_does_not_claim_a_return_without_a_return_address(self):
        self.unicorn = unicorn_stub()
        sys.modules["unicorn"] = self.unicorn
        uc = self.unicorn.Uc(self.unicorn.UC_ARCH_X86, self.unicorn.UC_MODE_64)
        uc.emu_start(0x401000, 0x403000, 1000, 8)
        # Nothing was pushed, so the popped program counter is 0, not the stop
        # address: the stand-in models the pop, it does not assert the outcome.
        self.assertEqual(uc.reg_read(uc.ids["rip"]), 0)
        self.assertEqual(uc.reg_read(uc.ids["rsp"]), 8)


class CallDetectionTests(BridgeTestCase):
    def test_recognizes_call_opcodes_per_architecture(self):
        is_call = self.bridge.is_call_instruction
        self.assertTrue(is_call("x86_64", b"\xe8\x00\x00\x00\x00"))
        self.assertTrue(is_call("x86_32", b"\xff\xd0"))
        self.assertFalse(is_call("x86_64", b"\xe9\x00\x00\x00\x00"))
        self.assertTrue(is_call("arm64", (0x94000000).to_bytes(4, "little")))
        self.assertFalse(is_call("arm64", (0x14000000).to_bytes(4, "little")))
        self.assertTrue(is_call("arm", (0xEB000000).to_bytes(4, "little")))
        self.assertTrue(is_call("thumb", b"\x00\xf0"))
        self.assertTrue(is_call("mips32", (0x0C000000).to_bytes(4, "little")))
        self.assertTrue(is_call("ppc32", (0x48000001).to_bytes(4, "little")))


class AssemblyTests(BridgeTestCase):
    def setUp(self) -> None:
        super().setUp()
        sys.modules["unicorn"] = unicorn_stub()
        sys.modules["keystone"] = keystone_stub()

    def test_encodes_source_and_reports_its_digest(self):
        result = self.bridge.handle(
            {
                "protocol": 1,
                "job_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "kind": "assemble",
                "arch": "x86_64",
                "endianness": "little",
                "base_address": "0x401000",
                "assembly": "nop",
                "max_bytes": 16,
            }
        )
        self.assertEqual(result["bytes_hex"], "90")
        self.assertEqual(result["size"], 1)
        self.assertEqual(result["sha256"], self.bridge.digest_hex(b"\x90"))
        self.assertEqual(result["assembly"], "nop")
        self.assertEqual(result["base_address"], "0x401000")
        self.assertEqual(FakeKs.last_request[3], 0x401000)

    def test_assembles_without_unicorn_and_reports_no_unicorn_version(self):
        del sys.modules["unicorn"]
        result = self.bridge.handle(
            {
                "protocol": 1,
                "job_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "kind": "assemble",
                "arch": "x86_64",
                "endianness": "little",
                "base_address": "0x401000",
                "assembly": "nop",
                "max_bytes": 16,
            }
        )
        self.assertIsNone(result["bridge"]["unicorn_version"])
        self.assertEqual(result["bridge"]["keystone_version"], "0.9.2")
        self.assertEqual(result["bytes_hex"], "90")

    def test_refuses_without_keystone(self):
        del sys.modules["keystone"]
        with self.assertRaises(self.bridge.BridgeRefusal) as raised:
            self.bridge.handle(
                {
                    "protocol": 1,
                    "kind": "assemble",
                    "arch": "x86_64",
                    "assembly": "nop",
                    "max_bytes": 16,
                }
            )
        self.assertEqual(raised.exception.code, "missing_dependency")

    def test_refuses_an_encoding_over_the_byte_budget(self):
        FakeKs.encoded = b"\x90" * 32
        try:
            with self.assertRaises(self.bridge.BridgeRefusal) as raised:
                self.bridge.handle(
                    {
                        "protocol": 1,
                        "kind": "assemble",
                        "arch": "x86_64",
                        "assembly": "nop",
                        "max_bytes": 4,
                    }
                )
            self.assertEqual(raised.exception.code, "invalid_request")
        finally:
            FakeKs.encoded = b"\x90"


class AnswerTests(BridgeTestCase):
    def test_wraps_a_refusal_without_partial_result(self):
        frame = self.bridge.answer("emulate", "job", refusal=self.bridge.BridgeRefusal("invalid_request", "no"))
        self.assertEqual(frame["ok"], False)
        self.assertNotIn("result", frame)
        self.assertEqual(frame["error"]["code"], "invalid_request")

    def test_wraps_a_result(self):
        frame = self.bridge.answer("assemble", "job", result={"bytes_hex": "90"})
        self.assertEqual(frame["ok"], True)
        self.assertEqual(frame["result"], {"bytes_hex": "90"})


if __name__ == "__main__":
    unittest.main()
