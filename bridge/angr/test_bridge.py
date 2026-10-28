"""Offline tests for the REA angr symbolic-execution sidecar.

The real engine is not installed here, so these tests install a stand-in
``angr`` and ``claripy`` module that models only the API surface the bridge
uses. They establish the bridge's own protocol, refusal, bound, and
value-free output rules; they make no claim about angr's semantics. A passing
run says nothing about what a real angr would return for these bytes.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

BRIDGE_PATH = Path(__file__).with_name("angr_bridge.py")
SECRET = 0x5A
FINDS = True
STDIN_AT_CONSTRUCTION = True


def load_bridge():
    spec = importlib.util.spec_from_file_location("rea_angr_bridge", BRIDGE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def digest_of(value: int, bits: int) -> str:
    width = max(1, (bits + 7) // 8)
    return hashlib.sha256(value.to_bytes(width, "big")).hexdigest()


class FakeAst:
    """The operator-overloading surface claripy exposes, and nothing more."""

    def __init__(self, op, args=(), length=32, symbolic=False):
        self.op = op
        self.args = tuple(args)
        self.length = length
        self.symbolic = symbolic

    def __eq__(self, other):
        return FakeAst("__eq__", (self, other), 1)

    def __ne__(self, other):
        return FakeAst("__ne__", (self, other), 1)

    def ULT(self, other):
        return FakeAst("ult", (self, other), 1)

    def ULE(self, other):
        return FakeAst("ule", (self, other), 1)

    def UGT(self, other):
        return FakeAst("ugt", (self, other), 1)

    def UGE(self, other):
        return FakeAst("uge", (self, other), 1)

    def __getitem__(self, key):
        high, low = key.start, key.stop
        return FakeAst("extract", (self, high, low), high - low + 1)


class FakeSolver:
    def __init__(self, constraints=()):
        self.constraints = list(constraints)

    def add(self, ast):
        self.constraints.append(ast)

    def satisfiable(self):
        return True

    def eval(self, ast):
        return PLANTED_VALUES.get(ast.args[0], 0)


PLANTED_VALUES = {"rea_stdin": SECRET, "rea_reg_rdi": SECRET}


class FakeRegs:
    def __init__(self, initial):
        self.__dict__.update(initial)


class FakeSimFile:
    """The file handle angr accepts as ``stdin`` when the state is created."""

    def __init__(self, name, content=None, size=None):
        self.name = name
        self.content = content
        self.size = size


class FakePosix:
    """Models the one POSIX-plugin rule this lane depends on: fd 0 is bound at
    creation, so a stream installed on a live state never becomes what reads
    consume."""

    def __init__(self, stdin=None):
        self.__stream = stdin
        self.reads = 0

    @property
    def stdin(self):
        return self.__stream

    @stdin.setter
    def stdin(self, value):
        raise AssertionError(
            "angr binds fd 0 when the state is constructed; stdin cannot be replaced afterwards"
        )


class FakeHistory:
    bbl_addrs = [0x401000, 0x401010]
    descriptions = [b"entry", b"block"]


class FakeState:
    def __init__(self, addr, solver=None, stdin=None):
        self.addr = addr
        self.solver = solver or FakeSolver()
        self.regs = FakeRegs({"rdi": 0, "rsi": 0, "rax": 0})
        self.posix = FakePosix(stdin)
        self.history = FakeHistory()

    def with_constraint(self, constraint):
        clone = FakeState(self.addr, FakeSolver(self.solver.constraints))
        clone.regs.__dict__.update(self.regs.__dict__)
        clone.solver.add(constraint)
        return clone


class FakeSimgr:
    """The stand-in's own return model: one step, then a planted stash move."""

    def __init__(self, state):
        self.active = [state]
        self.found = []
        self.avoid = []
        self.deadended = []
        self.errored = []
        self.source = state

    def explore(self, find, avoid, num_find, find_stash, step_func):
        if not step_func(self):
            return
        stream = self.source.posix.stdin
        self.active = []
        if stream is not None:
            # A read consumes the stream the state was constructed with, so the
            # constraint names that stream's content and nothing else.
            self.source.posix.reads += 1
            constraint = FakeAst(
                "__eq__", (FakeAst("extract", (stream.content, 7, 0), 8), SECRET), 1
            )
        else:
            constraint = None
        if find and FINDS:
            found = self.source.with_constraint(constraint) if constraint is not None else self.source
            found.addr = find[0]
            self.found = [found][:num_find]
        elif avoid:
            self.avoid = [self.source]
        else:
            self.deadended = [self.source]


class FakeFactory:
    def __init__(self, project):
        self.project = project

    def entry_state(self, addr, stdin=None):
        if stdin is not None and not STDIN_AT_CONSTRUCTION:
            raise TypeError("entry_state() got an unexpected keyword argument 'stdin'")
        return FakeState(addr, stdin=stdin)

    def full_init_state(self, addr, stdin=None):
        raise TypeError("full_init_state() got an unexpected keyword argument 'stdin'")

    def simgr(self, state):
        return FakeSimgr(state)


class FakeModel:
    def __init__(self, nodes):
        self._nodes = nodes

    def nodes(self):
        return list(self._nodes)


class FakeNode:
    def __init__(self, addr, size, successors):
        self.addr = addr
        self.size = size
        self.successors = successors


class FakeFunction:
    def __init__(self, addr, blocks):
        self.addr = addr
        self.blocks = {block: None for block in blocks}


class FakeCFG:
    def __init__(self, nodes, functions):
        self.model = FakeModel(nodes)
        self.kb = types.SimpleNamespace(functions=functions)


class FakeLoader:
    def __init__(self, mapped):
        self.main_object = types.SimpleNamespace(
            contains_addr=lambda address: address in mapped
        )


class FakeProject:
    def __init__(self, path, auto_load_libs, mapped=(0x401000, 0x4010A0, 0x401140)):
        self.path = path
        self.factory = FakeFactory(self)
        self.arch = types.SimpleNamespace(bits=64)
        self.loader = FakeLoader(set(mapped))
        self.analyses = self
        self.project = self

    def CFGFast(self, **kwargs):
        nodes = [
            FakeNode(0x401000, 4, [FakeNode(0x401004, 0, [])]),
            FakeNode(0x401004, 4, []),
        ]
        functions = {0x401000: FakeFunction(0x401000, [0x401000, 0x401004])}
        return FakeCFG(nodes, functions)


def install_stand_in(
    version="9.2.1",
    mapped=(0x401000, 0x4010A0, 0x401140),
    sim_file=True,
    stdin_at_construction=True,
    finds=True,
):
    global FINDS, STDIN_AT_CONSTRUCTION
    FINDS = finds
    STDIN_AT_CONSTRUCTION = stdin_at_construction
    claripy = types.ModuleType("claripy")
    claripy.BVS = lambda name, bits: FakeAst("BVS", (name,), bits, symbolic=True)
    claripy.BVV = lambda value, bits: FakeAst("BVV", (value,), bits, symbolic=False)
    angr = types.ModuleType("angr")
    angr.__version__ = version
    angr.claripy = claripy
    if sim_file:
        angr.SimFile = FakeSimFile
    angr.Project = lambda path, auto_load_libs=True: FakeProject(
        path, auto_load_libs, mapped
    )
    sys.modules["claripy"] = claripy
    sys.modules["angr"] = angr
    return angr


def remove_stand_in():
    for name in ("angr", "claripy"):
        sys.modules.pop(name, None)


class BridgeTestCase(unittest.TestCase):
    def setUp(self):
        self.bridge = load_bridge()
        self.directory = tempfile.mkdtemp()
        self.path = os.path.join(self.directory, "firmware.bin")
        with open(self.path, "wb") as handle:
            handle.write(b"\x90" * 32)
        self.sha256 = hashlib.sha256(b"\x90" * 32).hexdigest()

    def tearDown(self):
        remove_stand_in()

    def request(self, kind="find_paths", **overrides):
        base = {
            "protocol": 1,
            "job_id": "11111111-1111-4111-8111-111111111111",
            "kind": kind,
            "path": self.path,
            "binary_sha256": self.sha256,
            "entry": "0x401000",
            "stdin_bytes": 8,
            "symbolic_registers": ["rdi"],
            "find_addresses": ["0x4010a0"],
            "avoid_addresses": [],
            "assertions": [],
            "max_paths": 1,
            "max_states": 8,
            "max_steps": 64,
            "timeout_ms": 1000,
            "limits": {
                "max_conditions": 4,
                "max_condition_nodes": 32,
                "max_model_values": 4,
                "max_visited_blocks": 8,
                "max_paths": 4,
                "max_successors": 4,
            },
        }
        base.update(overrides)
        return base

    def job(self, kind="find_paths", **overrides):
        request = self.request(kind, **overrides)
        return self.bridge.answer(
            request["kind"], request["job_id"], result=self.bridge.handle(request)
        )


class ProtocolTests(BridgeTestCase):
    def test_refuses_a_missing_angr_import(self):
        remove_stand_in()
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(self.request())
        self.assertEqual(caught.exception.code, "missing_dependency")

    def test_refuses_an_unpinned_angr_release(self):
        install_stand_in(version="9.3.0")
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(self.request())
        self.assertEqual(caught.exception.code, "version_unsupported")

    def test_refuses_a_foreign_protocol(self):
        install_stand_in()
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(self.request(protocol=2))
        self.assertEqual(caught.exception.code, "protocol_mismatch")

    def test_refuses_an_artifact_that_changed_since_rea_read_it(self):
        install_stand_in()
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(self.request(binary_sha256="0" * 64))
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_refuses_an_entry_outside_the_loader_object(self):
        install_stand_in()
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(self.request(entry="0x500000"))
        self.assertEqual(caught.exception.code, "entry_not_mapped")

    def test_refuses_a_missing_artifact(self):
        install_stand_in()
        missing = os.path.join(self.directory, "absent.bin")
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(self.request(path=missing))
        self.assertEqual(caught.exception.code, "binary_unreadable")

    def test_downgrades_an_answer_above_the_frame_budget(self):
        frame = {
            "protocol": 1,
            "job_id": "11111111-1111-4111-8111-111111111111",
            "kind": "find_paths",
            "ok": True,
            "result": {"padding": "x" * (1 << 20)},
        }
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.bridge.emit(frame)
        answer = json.loads(buffer.getvalue())
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["error"]["code"], "job_failed")


class FindPathsTests(BridgeTestCase):
    def test_reports_path_structure_without_values(self):
        install_stand_in()
        frame = self.job(
            assertions=[
                {
                    "operand": {"kind": "stdin", "offset": 0, "width_bytes": 1},
                    "relation": "eq",
                    "value": "0x5a",
                }
            ]
        )
        result = frame["result"]
        self.assertTrue(frame["ok"])
        self.assertTrue(result["values_redacted"])
        self.assertTrue(result["reachable"])
        self.assertEqual(result["termination"], "find_hit")
        self.assertEqual(result["target"]["sha256"], self.sha256)
        self.assertEqual(result["assertion_count"], 1)
        path = result["paths"][0]
        self.assertEqual(path["address"], "0x4010a0")
        kinds = {node["kind"] for node in path["conditions"]}
        self.assertIn("symbol", kinds)
        self.assertIn("constant", kinds)
        # The constant of the satisfying condition is a digest, never the value.
        constants = [
            node["constant_sha256"]
            for node in path["conditions"]
            if node["constant_sha256"] is not None
        ]
        self.assertIn(digest_of(SECRET, 8), constants)
        stdin_model = next(
            value for value in path["model"] if value["name"] == "rea_stdin"
        )
        self.assertEqual(stdin_model["value_sha256"], digest_of(SECRET, 64))
        self.assertEqual(stdin_model["bits"], 64)
        # The symbolic register is reported too, and its planted value only as a digest.
        register_model = next(
            value for value in path["model"] if value["name"] == "rea_reg_rdi"
        )
        self.assertEqual(register_model["bits"], 64)
        text = json.dumps(frame)
        self.assertNotIn("0x5a", text)
        for node in path["conditions"] + path["model"]:
            self.assertNotIn("value", node)

    def test_binds_the_stdin_window_at_state_construction(self):
        install_stand_in()
        frame = self.job(
            assertions=[
                {
                    "operand": {"kind": "stdin", "offset": 0, "width_bytes": 1},
                    "relation": "eq",
                    "value": "0x5a",
                }
            ]
        )
        path = frame["result"]["paths"][0]
        symbols = [
            node["operand"]
            for node in path["conditions"]
            if node["kind"] == "symbol"
        ]
        # The condition constrains the stream the state was built with, so the
        # symbolic window is what fd 0 reads rather than a detached bit vector.
        self.assertIn("rea_stdin", symbols)

    def test_refuses_a_stdin_window_when_the_release_has_no_file_api(self):
        install_stand_in(sim_file=False)
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(self.request())
        self.assertEqual(caught.exception.code, "unsupported_mode")

    def test_refuses_a_stdin_window_when_state_creation_cannot_bind_it(self):
        install_stand_in(stdin_at_construction=False)
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(self.request())
        self.assertEqual(caught.exception.code, "unsupported_mode")

    def test_refuses_an_assertion_over_a_register_that_is_not_symbolic(self):
        install_stand_in()
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(
                self.request(
                    symbolic_registers=[],
                    assertions=[
                        {
                            "operand": {"kind": "register", "name": "rdi"},
                            "relation": "eq",
                            "value": "0x1",
                        }
                    ],
                )
            )
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_refuses_a_stdin_assertion_past_the_symbolic_window(self):
        install_stand_in()
        with self.assertRaises(self.bridge.BridgeRefusal) as caught:
            self.bridge.handle(
                self.request(
                    stdin_bytes=4,
                    assertions=[
                        {
                            "operand": {"kind": "stdin", "offset": 8, "width_bytes": 1},
                            "relation": "eq",
                            "value": "0x1",
                        }
                    ],
                )
            )
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_bounds_path_conditions(self):
        install_stand_in()
        frame = self.job(
            limits={
                "max_conditions": 1,
                "max_condition_nodes": 1,
                "max_model_values": 1,
                "max_visited_blocks": 1,
                "max_paths": 4,
                "max_successors": 4,
            }
        )
        path = frame["result"]["paths"][0]
        self.assertLessEqual(len(path["conditions"]), 1)
        self.assertTrue(path["conditions_truncated"])


class ExplorationTests(BridgeTestCase):
    def test_reports_counts_and_addresses_only(self):
        install_stand_in()
        frame = self.job(kind="explore_function")
        result = frame["result"]
        self.assertTrue(result["values_redacted"])
        self.assertEqual(result["termination"], "find_hit")
        self.assertEqual(result["found_states"], 1)
        self.assertEqual(result["visited_blocks"], ["0x401000", "0x401010"])
        self.assertFalse(result["visited_blocks_truncated"])
        for node in result["found"][0]["model"]:
            self.assertNotIn("value", node)
        self.assertIn(digest_of(SECRET, 64), json.dumps(result))

    def test_reports_visited_blocks_when_nothing_was_found(self):
        install_stand_in(finds=False)
        frame = self.job(
            kind="explore_function", find_addresses=["0x4010a0"]
        )
        result = frame["result"]
        self.assertEqual(result["termination"], "deadended")
        self.assertEqual(result["found_states"], 0)
        self.assertEqual(result["found"], [])
        self.assertTrue(result["deadended_states"] >= 1)
        # Blocks ran even though no satisfying path exists.
        self.assertEqual(result["visited_blocks"], ["0x401000", "0x401010"])
        self.assertFalse(result["visited_blocks_truncated"])
        self.assertEqual(result["coverage"], "complete")

    def test_marks_visited_blocks_truncated(self):
        install_stand_in()
        frame = self.job(
            kind="explore_function",
            limits={
                "max_conditions": 4,
                "max_condition_nodes": 32,
                "max_model_values": 4,
                "max_visited_blocks": 1,
                "max_paths": 4,
                "max_successors": 4,
            },
        )
        result = frame["result"]
        self.assertEqual(len(result["visited_blocks"]), 1)
        self.assertTrue(result["visited_blocks_truncated"])


class StandInContractTests(BridgeTestCase):
    def test_rejects_a_stdin_stream_assigned_after_construction(self):
        install_stand_in()
        project = sys.modules["angr"].Project(self.path, auto_load_libs=False)
        state = project.factory.entry_state(addr=0x401000)
        with self.assertRaises(AssertionError):
            state.posix.stdin = FakeSimFile("/dev/stdin", content=None, size=0)

    def test_rejects_replacing_a_bound_stream(self):
        install_stand_in()
        project = sys.modules["angr"].Project(self.path, auto_load_libs=False)
        stream = FakeSimFile("/dev/stdin", content=FakeAst("BVS", ("rea_stdin",), 64, True), size=8)
        state = project.factory.entry_state(addr=0x401000, stdin=stream)
        self.assertIs(state.posix.stdin, stream)
        with self.assertRaises(AssertionError):
            state.posix.stdin = stream


class ControlFlowTests(BridgeTestCase):
    def test_reports_blocks_and_successors_as_addresses(self):
        install_stand_in()
        frame = self.job(kind="recover_cfg", max_functions=8, max_blocks=8)
        result = frame["result"]
        self.assertEqual(result["function_count"], 1)
        self.assertEqual(result["functions"], [{"address": "0x401000", "block_count": 2}])
        self.assertEqual(
            result["blocks"][0],
            {"address": "0x401000", "size": 4, "successors": ["0x401004"]},
        )
        self.assertEqual(result["edge_count"], 1)
        self.assertEqual(result["coverage"], "complete")
        self.assertIsNone(result["target"]["entry"])
        self.assertNotIn("name", json.dumps(result))

    def test_bounds_blocks_and_marks_partial(self):
        install_stand_in()
        frame = self.job(kind="recover_cfg", max_functions=8, max_blocks=1)
        result = frame["result"]
        self.assertEqual(len(result["blocks"]), 1)
        self.assertTrue(result["blocks_truncated"])
        self.assertEqual(result["coverage"], "partial")


if __name__ == "__main__":
    unittest.main()
