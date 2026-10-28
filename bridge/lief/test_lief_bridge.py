"""Offline tests for the REA LIEF deep-parse bridge.

`lief` is not installed on the development host, so every test supplies a local
fake: in-process objects for the structure and lookup semantics, and a one-line
`lief` module on `PYTHONPATH` for the real stdin/stdout frame boundary. No
binary is downloaded, no LIEF release is executed, and nothing reaches a
network.
"""

import enum
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

BRIDGE_PATH = Path(__file__).resolve().parent / "lief_bridge.py"
FIXED_SHA256 = "0" * 64


def load_bridge():
    spec = importlib.util.spec_from_file_location("rea_lief_bridge", BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Machine(enum.Enum):
    X86_64 = 62


class IdentityClass(enum.Enum):
    CLASS64 = 2


class IdentityData(enum.Enum):
    LSB = 1


class Subsystem(enum.Enum):
    WINDOWS_CUI = 3


class Characteristic(enum.Enum):
    EXECUTABLE_IMAGE = 2


class DebugType(enum.Enum):
    CODEVIEW = 2


class CommandKind(enum.Enum):
    LOAD_DYLIB = 12
    SEGMENT_64 = 25


class DynamicTag(enum.Enum):
    NEEDED = 1
    RPATH = 15
    RUNPATH = 29
    FLAGS_1 = 0x6FFFFFFB


def header(**values):
    defaults = {
        "identity_class": IdentityClass.CLASS64,
        "identity_data": IdentityData.LSB,
        "machine": Machine.X86_64,
        "cpu_type": None,
        "cpu_subtype": None,
        "characteristics_list": [Characteristic.EXECUTABLE_IMAGE],
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def elf_binary():
    return SimpleNamespace(
        header=header(),
        entrypoint=0x401000,
        imagebase=0x400000,
        has_interpreter=True,
        interpreter="/lib64/ld-linux-x86-64.so.2",
        soname="libexample.so.1",
        libraries=["libc.so.6"],
        has_dynamic_entries=True,
        dynamic_entries=[
            SimpleNamespace(tag=DynamicTag.NEEDED, value="/libc.so.6"),
            SimpleNamespace(tag=DynamicTag.RPATH, value="/opt/lib"),
            SimpleNamespace(tag=DynamicTag.RUNPATH, value="/opt/run"),
            SimpleNamespace(tag=DynamicTag.FLAGS_1, value=0x8000001),
        ],
        sections=[
            SimpleNamespace(name=".text", size=64),
            SimpleNamespace(name=".debug_info", size=256),
        ],
        segments=[SimpleNamespace()],
    )


def pe_binary():
    return SimpleNamespace(
        header=header(identity_class=None, identity_data=None),
        optional_header=SimpleNamespace(subsystem=Subsystem.WINDOWS_CUI),
        data_directories=[
            SimpleNamespace(type="IMPORT_TABLE", rva=0x1000, size=0x40),
        ],
        has_debug=True,
        debug=[
            SimpleNamespace(
                type=DebugType.CODEVIEW,
                code_view=SimpleNamespace(
                    cv_signature="RSDS",
                    pdb_info=SimpleNamespace(
                        filename="C:\\src\\app.pdb",
                        guid="1F2E3D4C",
                        age=7,
                    ),
                ),
            )
        ],
        sections=[SimpleNamespace(name=".rdata", size=16)],
        segments=[SimpleNamespace()],
        libraries=[],
        entrypoint=0x1000,
        imagebase=0x140000000,
    )


def macho_binary(fat=False):
    return SimpleNamespace(
        header=header(
            identity_class=None,
            identity_data=None,
            machine=None,
            cpu_type=Machine.X86_64,
        ),
        uuid="8E1B2C3D-0000-1111-2222-333344445555",
        has_uuid=True,
        entrypoint=0x100000F00,
        imagebase=0x100000000,
        commands=[
            SimpleNamespace(
                command=CommandKind.LOAD_DYLIB,
                size=56,
                name="/usr/lib/libSystem.B.dylib",
                current_version="1.0.0",
                compatibility_version="1.0.0",
            ),
            SimpleNamespace(command=CommandKind.SEGMENT_64, size=72, name="__TEXT"),
        ],
        libraries=["/usr/lib/libSystem.B.dylib"],
        sections=[SimpleNamespace(name="__debug_info", size=128)],
        segments=[SimpleNamespace(), SimpleNamespace()],
        size=4096 if fat else None,
        offset=0 if fat else None,
    )


def fake_lief(binary, dwarf=None, pdb=None, version="0.16.0"):
    surfaces = {}
    if dwarf is not None:
        surfaces["DWARF"] = SimpleNamespace(from_binary=lambda _: dwarf)
    if pdb is not None:
        surfaces["PDB"] = SimpleNamespace(from_file=lambda _: pdb)
    return SimpleNamespace(
        __version__=version,
        parse=lambda _path: binary,
        **surfaces,
    )


def dwarf_reader():
    def function(name, address, size):
        return SimpleNamespace(name=name, address=address, size=size)

    unit = SimpleNamespace(
        name="main.c",
        functions=[
            function("main", 0x401000, 0x40),
            function("parse", 0x401100, 0x20),
        ],
    )
    return SimpleNamespace(compilation_units=[unit])


class BridgeRefusalTests(unittest.TestCase):
    def setUp(self):
        self.bridge = load_bridge()

    def test_read_request_rejects_an_empty_stdin(self):
        original = sys.stdin
        sys.stdin = SimpleNamespace(buffer=io.BytesIO(b""))
        try:
            with self.assertRaises(self.bridge.BridgeRefusal) as caught:
                self.bridge.read_request()
        finally:
            sys.stdin = original
        self.assertEqual(caught.exception.code, "empty_request")

    def test_read_request_rejects_an_oversized_line(self):
        oversized = b"{" + b" " * self.bridge.MAX_REQUEST_BYTES + b"}\n"
        original = sys.stdin
        sys.stdin = SimpleNamespace(buffer=io.BytesIO(oversized))
        try:
            with self.assertRaises(self.bridge.BridgeRefusal) as caught:
                self.bridge.read_request()
        finally:
            sys.stdin = original
        self.assertEqual(caught.exception.code, "oversized_request")

    def test_classify_refuses_an_unreadable_artifact(self):
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.classify("/nonexistent/artifact")
        self.assertEqual(caught.exception.code, "artifact_unreadable")


class DeepStructureTests(unittest.TestCase):
    def setUp(self):
        self.bridge = load_bridge()
        self.root = tempfile.mkdtemp()

    def materialize(self, name, magic):
        path = os.path.join(self.root, name)
        with open(path, "wb") as handle:
            handle.write(magic + b"\x00" * 60)
        return path

    def report(self, lief, magic=b"\x7fELF", name="example.elf"):
        return self.bridge.inspect_binary_deep(
            lief, self.materialize(name, magic)
        )

    def test_elf_reports_dynamic_facts_and_leaves_layout_to_other_tools(self):
        report = self.report(fake_lief(elf_binary()))
        self.assertEqual(report["format"], "elf")
        self.assertEqual(report["architectures"][0]["bits"], 64)
        self.assertIs(report["architectures"][0]["little_endian"], True)
        self.assertEqual(report["dynamic"]["interpreter"], "/lib64/ld-linux-x86-64.so.2")
        self.assertEqual(report["dynamic"]["needed"], ["libc.so.6"])
        self.assertEqual(report["dynamic"]["rpath"], ["/opt/lib"])
        self.assertEqual(report["dynamic"]["runpath"], ["/opt/run"])
        self.assertEqual(
            report["dynamic"]["entries"],
            [{"tag": "flags_1", "value": 0x8000001}],
        )
        self.assertTrue(report["debug_sources"]["dwarf"]["present"])
        self.assertEqual(
            report["debug_sources"]["dwarf"]["sections"],
            [{"name": ".debug_info", "size": 256}],
        )
        self.assertEqual(
            report["structure_summary"],
            {"section_count": 2, "segment_count": 1, "linked_library_count": 1},
        )

    def test_pe_reports_data_directories_and_the_codeview_reference(self):
        report = self.report(
            fake_lief(pe_binary()), magic=b"MZ", name="example.exe"
        )
        self.assertEqual(report["format"], "pe")
        self.assertEqual(
            report["pe"]["machine"], "x86_64"
        )
        self.assertEqual(
            report["pe"]["data_directories"],
            [{"name": "import_table", "rva": 0x1000, "size": 0x40}],
        )
        self.assertEqual(
            report["debug_sources"]["pdb_reference"],
            {
                "path": "C:\\src\\app.pdb",
                "guid": "1F2E3D4C",
                "age": 7,
                "signature_kind": "rsds",
            },
        )
        self.assertEqual(report["pe"]["debug_entries"][0]["kind"], "codeview")

    def test_macho_reports_uuid_dylibs_and_load_commands(self):
        report = self.report(
            fake_lief(macho_binary()),
            magic=b"\xcf\xfa\xed\xfe",
            name="example.macho",
        )
        self.assertEqual(report["format"], "macho")
        self.assertEqual(
            report["macho"]["uuid"], "8E1B2C3D-0000-1111-2222-333344445555"
        )
        self.assertEqual(
            report["macho"]["libraries"],
            [
                {
                    "name": "/usr/lib/libSystem.B.dylib",
                    "current_version": "1.0.0",
                    "compatibility_version": "1.0.0",
                }
            ],
        )
        self.assertEqual(
            [row["kind"] for row in report["macho"]["load_commands"]],
            ["load_dylib", "segment_64"],
        )

    def test_pdb_is_refused_by_the_binary_structure_operation(self):
        pdb_path = os.path.join(self.root, "example.pdb")
        with open(pdb_path, "wb") as handle:
            handle.write(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.inspect_binary_deep(fake_lief(None), pdb_path)
        self.assertEqual(caught.exception.code, "unsupported_format")

    def test_unknown_magic_is_refused_rather_than_guessed(self):
        text_path = os.path.join(self.root, "notes.txt")
        with open(text_path, "wb") as handle:
            handle.write(b"plain text, not a container")
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.inspect_binary_deep(fake_lief(None), text_path)
        self.assertEqual(caught.exception.code, "unsupported_format")


class DebugInfoTests(unittest.TestCase):
    def setUp(self):
        self.bridge = load_bridge()
        self.root = tempfile.mkdtemp()
        self.elf_path = os.path.join(self.root, "example.elf")
        with open(self.elf_path, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)

    def test_dwarf_symbol_and_address_lookups(self):
        lief = fake_lief(elf_binary(), dwarf=dwarf_reader())
        report = self.bridge.extract_pdb_dwarf_info(
            lief,
            self.elf_path,
            [
                {"kind": "symbol", "name": "main"},
                {"kind": "address", "address": 0x401010},
                {"kind": "symbol", "name": "absent"},
            ],
        )
        self.assertEqual(report["artifact_kind"], "elf")
        self.assertTrue(report["debug_sources"]["dwarf"]["present"])
        self.assertEqual(
            report["debug_sources"]["dwarf"]["compilation_unit_count"], 1
        )
        self.assertEqual(report["debug_sources"]["dwarf"]["function_count"], 2)
        found, inside, missing = report["queries"]
        self.assertEqual(found["outcome"], "found")
        self.assertEqual(
            found["matches"],
            [
                {
                    "kind": "dwarf_function",
                    "name": "main",
                    "address": 0x401000,
                    "size": 0x40,
                    "rva": None,
                    "compilation_unit": "main.c",
                }
            ],
        )
        self.assertEqual(inside["outcome"], "found")
        self.assertEqual(inside["matches"][0]["name"], "main")
        self.assertEqual(missing["outcome"], "not_found")
        self.assertEqual(missing["matches"], [])

    def test_missing_dwarf_reader_reports_unsupported_rather_than_absent(self):
        lief = fake_lief(elf_binary())
        report = self.bridge.extract_pdb_dwarf_info(
            lief, self.elf_path, [{"kind": "symbol", "name": "main"}]
        )
        self.assertTrue(report["debug_sources"]["dwarf"]["present"])
        self.assertEqual(report["queries"][0]["outcome"], "unsupported")
        self.assertIn("DWARF", report["queries"][0]["reason"])

    def test_pdb_public_symbol_lookup_by_name_and_rva(self):
        pdb_path = os.path.join(self.root, "example.pdb")
        with open(pdb_path, "wb") as handle:
            handle.write(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")
        pdb = SimpleNamespace(
            public_symbols=[
                SimpleNamespace(name="main", RVA=0x1000),
                SimpleNamespace(name="helper", RVA=0x2000),
            ],
            compilation_units=[],
        )
        lief = fake_lief(None, pdb=pdb)
        report = self.bridge.extract_pdb_dwarf_info(
            lief,
            pdb_path,
            [
                {"kind": "symbol", "name": "helper"},
                {"kind": "address", "address": 0x1000},
            ],
        )
        self.assertEqual(report["artifact_kind"], "pdb")
        self.assertTrue(report["debug_sources"]["pdb"]["available"])
        self.assertEqual(report["debug_sources"]["pdb"]["public_symbol_count"], 2)
        self.assertEqual(report["queries"][0]["matches"][0]["rva"], 0x2000)
        self.assertEqual(report["queries"][1]["matches"][0]["name"], "main")

    def test_pdb_without_a_reader_reports_unsupported(self):
        pdb_path = os.path.join(self.root, "example.pdb")
        with open(pdb_path, "wb") as handle:
            handle.write(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")
        report = self.bridge.extract_pdb_dwarf_info(
            fake_lief(None),
            pdb_path,
            [{"kind": "symbol", "name": "main"}],
        )
        self.assertFalse(report["debug_sources"]["pdb"]["available"])
        self.assertEqual(report["queries"][0]["outcome"], "unsupported")
        self.assertEqual(report["queries"][0]["matches"], [])


class StdioFrameTests(unittest.TestCase):
    """Exercise the real process boundary with a one-line fake LIEF module."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.fake_root = os.path.join(self.root, "site")
        os.makedirs(self.fake_root, exist_ok=True)
        self.artifact = os.path.join(self.root, "example.elf")
        with open(self.artifact, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        self.bridge = load_bridge()
        self.sha256, self.size = self.bridge.digest(self.artifact)

    def run_bridge(self, request, with_lief=True):
        if with_lief:
            with open(os.path.join(self.fake_root, "lief.py"), "w") as handle:
                handle.write('__version__ = "0.16.0"\n')
        environment = dict(os.environ)
        environment["PYTHONPATH"] = self.fake_root
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        payload = (
            request
            if isinstance(request, bytes)
            else json.dumps(request).encode("utf-8") + b"\n"
        )
        completed = subprocess.run(
            [sys.executable, "-B", str(BRIDGE_PATH)],
            input=payload,
            capture_output=True,
            env=environment,
            timeout=60,
        )
        return completed

    def request(self, operation="inspect_binary_deep", **overrides):
        payload = {
            "protocol": 1,
            "operation": operation,
            "path": self.artifact,
            "artifact": {"sha256": self.sha256, "bytes": self.size},
        }
        payload.update(overrides)
        return payload

    def frame_of(self, completed):
        stdout = completed.stdout.decode("utf-8")
        lines = stdout.splitlines()
        self.assertEqual(len(lines), 1, stdout)
        return json.loads(lines[0])

    def test_missing_lief_is_a_typed_refusal_frame(self):
        completed = self.run_bridge(self.request(), with_lief=False)
        self.assertEqual(completed.returncode, 0)
        frame = self.frame_of(completed)
        self.assertEqual(frame["kind"], "lief_error")
        self.assertEqual(frame["code"], "lief_missing")

    def test_artifact_mismatch_is_refused_before_any_parse(self):
        frame = self.frame_of(
            self.run_bridge(
                self.request(artifact={"sha256": FIXED_SHA256, "bytes": self.size})
            )
        )
        self.assertEqual(frame["kind"], "lief_error")
        self.assertEqual(frame["code"], "artifact_mismatch")

    def test_unknown_operation_and_protocol_are_refused(self):
        unknown = self.frame_of(self.run_bridge(self.request(operation="analyze")))
        self.assertEqual(unknown["code"], "unsupported_operation")
        wrong_protocol = self.frame_of(self.run_bridge(self.request(protocol=9)))
        self.assertEqual(wrong_protocol["code"], "unsupported_protocol")

    def test_oversized_request_line_is_refused(self):
        completed = self.run_bridge(b"{" + b" " * (1024 * 1024 + 8) + b"}\n")
        self.assertEqual(self.frame_of(completed)["code"], "oversized_request")

    def test_no_frame_reaches_stdout_twice_or_with_a_traceback(self):
        completed = self.run_bridge(self.request())
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        frame = self.frame_of(completed)
        self.assertIn(frame["kind"], ("lief_report", "lief_error"))
        self.assertEqual(frame["protocol"], 1)


if __name__ == "__main__":
    unittest.main()
