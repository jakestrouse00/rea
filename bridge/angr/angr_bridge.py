#!/usr/bin/env python3
"""REA angr symbolic-execution sidecar.

One job per process. A single JSON request line arrives on stdin and exactly one
JSON answer line leaves on stdout; diagnostics go to stderr. The answer carries
structure only: path conditions are reported as an operator tree with constant
digests, model values as digests, and control flow as addresses. No symbolic
solution, concrete register value, or target symbol name is ever echoed back.

Written against angr 9.2.x. Run it with the interpreter of the caller-managed
environment that carries angr, for example:

    "$REA_ANGR_PYTHON" -I -B "$REA_ANGR_BRIDGE_DIR/angr_bridge.py"
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

PROTOCOL = 1
PINNED_ANGR_MINOR = "9.2"
MAX_FRAME_BYTES = 1 << 20
MAX_CONDITION_DEPTH = 32

KIND_FIND_PATHS = "find_paths"
KIND_EXPLORE = "explore_function"
KIND_RECOVER_CFG = "recover_cfg"
KINDS = (KIND_FIND_PATHS, KIND_EXPLORE, KIND_RECOVER_CFG)

RELATIONS = {
    "eq": lambda left, right: left == right,
    "ne": lambda left, right: left != right,
    "lt": lambda left, right: left.ULT(right),
    "le": lambda left, right: left.ULE(right),
    "gt": lambda left, right: left.UGT(right),
    "ge": lambda left, right: left.UGE(right),
}

OPERAND_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_.")


class BridgeRefusal(Exception):
    """A job REA must not retry unchanged."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def digest_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def value_digest(value, bits: int) -> str:
    """Digest one concrete value without returning it.

    The digest is over the value's big-endian fixed-width bytes, which keeps two
    equal values equal across runs without exposing the value itself.
    """
    width = max(1, (bits + 7) // 8)
    return digest_hex(int(value).to_bytes(width, "big", signed=False))


def file_digest(path: str) -> str:
    try:
        handle = open(path, "rb")
    except OSError as cause:
        raise BridgeRefusal("binary_unreadable", f"cannot read the selected artifact: {cause}") from cause
    digest = hashlib.sha256()
    with handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_address(value, name: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise BridgeRefusal("invalid_request", f"{name} must be a 0x-prefixed string")
    try:
        parsed = int(value, 16)
    except ValueError as cause:
        raise BridgeRefusal("invalid_request", f"{name} is not hexadecimal") from cause
    if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise BridgeRefusal("invalid_request", f"{name} is outside the 64-bit space")
    return parsed


def address_list(request: dict, name: str, maximum: int) -> list:
    values = request.get(name) or []
    if not isinstance(values, list) or len(values) > maximum:
        raise BridgeRefusal("invalid_request", f"{name} is outside its admitted count")
    return [parse_address(value, name) for value in values]


def require_int(request: dict, name: str, minimum: int, maximum: int) -> int:
    value = request.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise BridgeRefusal("invalid_request", f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise BridgeRefusal("invalid_request", f"{name} is outside its admitted range")
    return value


def limits_of(request: dict) -> dict:
    raw = request.get("limits") or {}
    if not isinstance(raw, dict):
        raise BridgeRefusal("invalid_request", "limits must be an object")
    return {
        "max_conditions": require_int(raw, "max_conditions", 1, 4096)
        if "max_conditions" in raw
        else 64,
        "max_condition_nodes": require_int(raw, "max_condition_nodes", 1, 65_536)
        if "max_condition_nodes" in raw
        else 512,
        "max_model_values": require_int(raw, "max_model_values", 1, 1024)
        if "max_model_values" in raw
        else 32,
        "max_visited_blocks": require_int(raw, "max_visited_blocks", 1, 1_048_576)
        if "max_visited_blocks" in raw
        else 2048,
        "max_successors": require_int(raw, "max_successors", 1, 1024)
        if "max_successors" in raw
        else 16,
        "max_paths": require_int(raw, "max_paths", 1, 8)
        if "max_paths" in raw
        else 8,
    }


def operand_name(raw) -> str:
    """Reduce a symbolic name to REA's operand vocabulary.

    Only bridge-assigned names are expected here; anything else is normalized
    so a name that happens to carry target text cannot cross the boundary as is.
    """
    text = str(raw).lower()
    cleaned = "".join(char if char in OPERAND_NAME_CHARS else "_" for char in text)
    cleaned = cleaned.lstrip("._") or "symbolic"
    return cleaned[:64]


def node_of(ast, depth: int) -> dict:
    op = str(getattr(ast, "op", "unknown"))
    op = "".join(char if char.isalnum() or char == "_" else "_" for char in op.lower())[:32]
    try:
        bits = int(ast.length)
    except Exception:
        bits = 0
    kind = "operation"
    operand = None
    constant = None
    op_name = op
    if getattr(ast, "symbolic", True) is False:
        kind = "constant"
        op_name = "bvv"
        try:
            constant = value_digest(ast.args[0], bits)
        except Exception:
            constant = None
    elif op in ("BVS", "bvs"):
        kind = "symbol"
        operand = operand_name(ast.args[0] if ast.args else "symbolic")
        op_name = "bvs"
    elif op in ("BVV", "bvv"):
        kind = "constant"
        op_name = "bvv"
        try:
            constant = value_digest(ast.args[0], bits)
        except Exception:
            constant = None
    return {
        "index": 0,
        "depth": depth,
        "kind": kind,
        "op": op_name or "unknown",
        "bits": max(0, min(bits, 4096)),
        "operand": operand,
        "constant_sha256": constant,
    }


def condition_nodes(ast, max_nodes: int) -> tuple:
    """Flatten one constraint into a bounded, value-free operator tree."""
    nodes = []
    truncated = False
    frontier = [(ast, 0)]
    while frontier:
        current, depth = frontier.pop(0)
        if len(nodes) >= max_nodes:
            truncated = True
            break
        entry = node_of(current, depth)
        entry["index"] = len(nodes)
        nodes.append(entry)
        args = getattr(current, "args", ()) or ()
        if depth + 1 > MAX_CONDITION_DEPTH:
            if args:
                truncated = True
            continue
        for argument in args:
            if hasattr(argument, "op"):
                frontier.append((argument, depth + 1))
    return nodes, truncated


def path_record(state, path_id: int, found: bool, limits: dict, inputs: list) -> dict:
    conditions = []
    conditions_truncated = False
    try:
        constraints = list(state.solver.constraints)
    except Exception:
        constraints = []
    for constraint in constraints[: limits["max_conditions"]]:
        nodes, truncated = condition_nodes(constraint, limits["max_condition_nodes"])
        conditions.extend(nodes)
        conditions_truncated = conditions_truncated or truncated
        if len(conditions) >= limits["max_condition_nodes"]:
            conditions_truncated = True
            break
    if len(constraints) > limits["max_conditions"]:
        conditions_truncated = True
    model, model_truncated = model_values(state, inputs, limits)
    try:
        block_count = len(getattr(state.history, "bbl_addrs", ()) or ())
    except Exception:
        block_count = 0
    try:
        steps = len(getattr(state.history, "descriptions", ()) or ())
    except Exception:
        steps = 0
    try:
        address = f"0x{int(state.addr):x}"
    except Exception:
        address = None
    return {
        "path_id": path_id,
        "found": found,
        "steps": max(0, steps),
        "block_count": max(0, block_count),
        "address": address,
        "conditions": conditions,
        "conditions_truncated": conditions_truncated,
        "model": model,
        "model_truncated": model_truncated,
    }


def model_values(state, inputs, limits: dict) -> tuple:
    """Report each symbolic input's solution as a digest, never as a value."""
    values = []
    truncated = False
    for symbol in inputs:
        if len(values) >= limits["max_model_values"]:
            truncated = True
            break
        try:
            resolved = state.solver.eval(symbol.ast)
        except Exception:
            continue
        values.append(
            {
                "name": symbol.name,
                "bits": symbol.bits,
                "value_sha256": value_digest(resolved, symbol.bits),
            }
        )
    return values, truncated


class SymbolicInput:
    def __init__(self, name: str, bits: int, ast) -> None:
        self.name = name
        self.bits = bits
        self.ast = ast


def register_ast(angr, state, name: str):
    register = getattr(state.regs, name, None)
    if register is None:
        raise BridgeRefusal("unsupported_mode", f"this architecture has no register {name}")
    return register


def attach_symbolic_inputs(angr, project, state, request: dict) -> list:
    """Install the caller's symbolic registers and symbolic stdin window."""
    inputs = []
    bits = int(project.arch.bits)
    for name in request.get("symbolic_registers") or []:
        if not isinstance(name, str):
            raise BridgeRefusal("invalid_request", "symbolic_registers must be strings")
        register_ast(angr, state, name)
        symbol = angr.claripy.BVS(f"rea_reg_{name}", bits)
        setattr(state.regs, name, symbol)
        inputs.append(SymbolicInput(f"rea_reg_{operand_name(name)}", bits, symbol))
    stdin_bytes = require_int(request, "stdin_bytes", 0, 4096)
    if stdin_bytes > 0:
        content = angr.claripy.BVS("rea_stdin", stdin_bytes * 8)
        inputs.append(SymbolicInput("rea_stdin", stdin_bytes * 8, content))
        try:
            simfile = angr.SimFile("/dev/stdin", content=content, size=stdin_bytes)
            state.posix.stdin = angr.SimFileStream(simfile, state=state)
        except (AttributeError, TypeError) as cause:
            raise BridgeRefusal(
                "unsupported_mode",
                "this angr release cannot model a symbolic stdin stream",
            ) from cause
    return inputs


def assertion_clause(angr, state, inputs: list, assertion: dict):
    if not isinstance(assertion, dict):
        raise BridgeRefusal("invalid_request", "an assertion must be an object")
    operand = assertion.get("operand")
    if not isinstance(operand, dict):
        raise BridgeRefusal("invalid_request", "an assertion needs an operand")
    relation = assertion.get("relation")
    if relation not in RELATIONS:
        raise BridgeRefusal("invalid_request", "an assertion relation is not supported")
    value = parse_address(assertion.get("value"), "value")
    kind = operand.get("kind")
    if kind == "register":
        name = operand.get("name")
        if not isinstance(name, str):
            raise BridgeRefusal("invalid_request", "a register operand needs a name")
        ast = register_ast(angr, state, name)
        if getattr(ast, "symbolic", False) is not True:
            raise BridgeRefusal(
                "invalid_request",
                f"register {name} is not one of this request's symbolic inputs",
            )
    elif kind == "stdin":
        offset = require_int(operand, "offset", 0, 4095)
        width = require_int(operand, "width_bytes", 1, 16)
        stdin = next((item for item in inputs if item.name == "rea_stdin"), None)
        if stdin is None:
            raise BridgeRefusal(
                "invalid_request",
                "a stdin assertion needs stdin_bytes above zero",
            )
        high = 8 * (offset + width) - 1
        if high >= stdin.bits:
            raise BridgeRefusal(
                "invalid_request",
                "a stdin assertion reaches past the symbolic stdin window",
            )
        ast = stdin.ast[high : 8 * offset]
    else:
        raise BridgeRefusal("invalid_request", "an assertion operand kind is not supported")
    if value >= 1 << max(1, int(ast.length)):
        raise BridgeRefusal("invalid_request", "an assertion value does not fit the operand")
    return RELATIONS[relation](ast, angr.claripy.BVV(value, int(ast.length)))


def require_angr():
    try:
        import angr
    except ImportError as cause:
        raise BridgeRefusal(
            "missing_dependency", "the selected interpreter cannot import angr"
        ) from cause
    try:
        import claripy
    except ImportError as cause:
        raise BridgeRefusal(
            "missing_dependency", "the selected interpreter cannot import claripy"
        ) from cause
    version = getattr(angr, "__version__", None)
    if not isinstance(version, str) or not version:
        raise BridgeRefusal("version_unsupported", "angr reports no version")
    if not version.startswith(f"{PINNED_ANGR_MINOR}."):
        raise BridgeRefusal(
            "version_unsupported",
            f"angr {version} is not the pinned {PINNED_ANGR_MINOR}.x release",
        )
    angr.claripy = claripy
    return angr


def load_project(angr, request: dict) -> tuple:
    path = request.get("path")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise BridgeRefusal("invalid_request", "path must be an absolute path")
    if not os.path.isfile(path):
        raise BridgeRefusal("binary_unreadable", "the selected artifact is not a regular file")
    observed = file_digest(path)
    expected = request.get("binary_sha256")
    if expected != observed:
        raise BridgeRefusal(
            "invalid_request", "the artifact changed since REA read it"
        )
    try:
        project = angr.Project(path, auto_load_libs=False)
    except BridgeRefusal:
        raise
    except Exception as cause:
        raise BridgeRefusal("loader_error", f"angr could not load the artifact: {cause}") from cause
    return project, observed


def target_record(request: dict, observed: str, entry) -> dict:
    return {"path": request.get("path"), "entry": entry, "sha256": observed}


def entry_state(angr, project, entry: int):
    try:
        return project.factory.entry_state(addr=entry)
    except TypeError:
        return project.factory.full_init_state(addr=entry)


def bound_checked(project, entry: int) -> None:
    try:
        mapped = project.loader.main_object.contains_addr(entry)
    except Exception:
        mapped = False
    if not mapped:
        raise BridgeRefusal(
            "entry_not_mapped",
            "the entry address is outside the loader's main object",
        )


def explore(angr, project, state, inputs: list, request: dict, limits: dict, num_find: int) -> dict:
    find = address_list(request, "find_addresses", 4)
    avoid = address_list(request, "avoid_addresses", 8)
    max_states = require_int(request, "max_states", 1, 256)
    max_steps = require_int(request, "max_steps", 1, 2_000_000)
    timeout_ms = require_int(request, "timeout_ms", 1, 600_000)
    for assertion in request.get("assertions") or []:
        state.solver.add(assertion_clause(angr, state, inputs, assertion))
    if state.solver.satisfiable() is False:
        return {
            "termination": "no_viable_state",
            "explored_states": 0,
            "active_states": 0,
            "deadended_states": 0,
            "found_states": 0,
            "avoided_states": 0,
            "errored_states": 0,
            "found": [],
            "found_total": 0,
            "avoided_total": 0,
            "visited_blocks": [],
            "visited_blocks_truncated": False,
        }
    simgr = project.factory.simgr(state)
    deadline = time.monotonic() + timeout_ms / 1000.0
    steps = 0
    bounds = {"steps": False, "states": False, "deadline": False}

    def step_func(manager) -> bool:
        nonlocal steps
        steps += 1
        if steps >= max_steps:
            bounds["steps"] = True
            return False
        if time.monotonic() >= deadline:
            bounds["deadline"] = True
            return False
        if len(manager.active) > max_states:
            bounds["states"] = True
            return False
        return True

    simgr.explore(
        find=find,
        avoid=avoid,
        num_find=num_find,
        find_stash="found",
        step_func=step_func,
    )
    found_states = list(simgr.found)[:num_find]
    found = [
        path_record(state_item, index, True, limits, inputs)
        for index, state_item in enumerate(found_states)
    ]
    if found:
        termination = "find_hit"
    elif bounds["deadline"]:
        termination = "deadline"
    elif bounds["steps"]:
        termination = "step_bound"
    elif bounds["states"]:
        termination = "state_bound"
    elif len(simgr.avoid) > 0 and len(simgr.active) == 0:
        termination = "avoid_hit"
    elif len(simgr.deadended) > 0 and len(simgr.active) == 0:
        termination = "deadended"
    else:
        termination = "no_viable_state"
    visited = []
    seen = set()
    truncated = False
    for state_item in found_states:
        for block in getattr(state_item.history, "bbl_addrs", ()) or ():
            if block in seen:
                continue
            if len(visited) >= limits["max_visited_blocks"]:
                truncated = True
                break
            seen.add(block)
            visited.append(f"0x{int(block):x}")
    return {
        "termination": termination,
        "explored_states": max(0, steps),
        "active_states": len(simgr.active),
        "deadended_states": len(simgr.deadended),
        "found_states": len(simgr.found),
        "avoided_states": len(simgr.avoid),
        "errored_states": len(simgr.errored),
        "found": found,
        "found_total": len(simgr.found),
        "avoided_total": len(simgr.avoid),
        "visited_blocks": visited,
        "visited_blocks_truncated": truncated,
    }


def find_paths(angr, request: dict) -> dict:
    project, observed = load_project(angr, request)
    entry = parse_address(request.get("entry"), "entry")
    bound_checked(project, entry)
    limits = limits_of(request)
    max_paths = require_int(request, "max_paths", 1, 8)
    state = entry_state(angr, project, entry)
    inputs = attach_symbolic_inputs(angr, project, state, request)
    explored = explore(angr, project, state, inputs, request, limits, max_paths)
    found = explored["found"]
    termination = explored["termination"]
    truncated = explored["found_total"] > max_paths
    return {
        "bridge": {
            "protocol": PROTOCOL,
            "angr_version": getattr(angr, "__version__", None),
        },
        "target": target_record(request, observed, f"0x{entry:x}"),
        "reachable": len(found) > 0,
        "termination": termination,
        "assertion_count": len(request.get("assertions") or []),
        "find_address_count": len(request.get("find_addresses") or []),
        "avoid_address_count": len(request.get("avoid_addresses") or []),
        "paths": found,
        "paths_truncated": truncated,
        "explored_states": explored["explored_states"],
        "coverage": "partial"
        if termination in ("step_bound", "state_bound", "deadline") or truncated
        else "complete",
        "values_redacted": True,
    }


def explore_function(angr, request: dict) -> dict:
    project, observed = load_project(angr, request)
    entry = parse_address(request.get("entry"), "entry")
    bound_checked(project, entry)
    limits = limits_of(request)
    state = entry_state(angr, project, entry)
    inputs = attach_symbolic_inputs(angr, project, state, request)
    explored = explore(angr, project, state, inputs, request, limits, limits["max_paths"])
    termination = explored["termination"]
    truncated = explored["found_total"] > limits["max_paths"]
    return {
        "bridge": {
            "protocol": PROTOCOL,
            "angr_version": getattr(angr, "__version__", None),
        },
        "target": target_record(request, observed, f"0x{entry:x}"),
        "termination": termination,
        "explored_states": explored["explored_states"],
        "active_states": explored["active_states"],
        "deadended_states": explored["deadended_states"],
        "found_states": explored["found_total"],
        "avoided_states": explored["avoided_total"],
        "errored_states": explored["errored_states"],
        "find_address_count": len(request.get("find_addresses") or []),
        "avoid_address_count": len(request.get("avoid_addresses") or []),
        "visited_blocks": explored["visited_blocks"],
        "visited_blocks_truncated": explored["visited_blocks_truncated"],
        "found": explored["found"],
        "coverage": "partial"
        if termination in ("step_bound", "state_bound", "deadline") or truncated
        else "complete",
        "values_redacted": True,
    }


def recover_cfg(angr, request: dict) -> dict:
    project, observed = load_project(angr, request)
    limits = limits_of(request)
    max_functions = require_int(request, "max_functions", 1, 4096)
    max_blocks = require_int(request, "max_blocks", 1, 16_384)
    try:
        cfg = project.analyses.CFGFast(
            normalize=True,
            data_references=False,
            resolve_indirect_jumps=True,
        )
    except Exception as cause:
        raise BridgeRefusal("loader_error", f"angr could not recover a CFG: {cause}") from cause
    blocks = []
    functions = []
    edge_count = 0
    blocks_truncated = False
    functions_truncated = False
    for node in cfg.model.nodes():
        if len(blocks) >= max_blocks:
            blocks_truncated = True
            break
        successors = [f"0x{int(successor.addr):x}" for successor in node.successors]
        if len(successors) > limits["max_successors"]:
            successors = successors[: limits["max_successors"]]
        edge_count += len(successors)
        try:
            size = int(node.size) or 1
        except Exception:
            size = 1
        blocks.append(
            {
                "address": f"0x{int(node.addr):x}",
                "size": max(1, size),
                "successors": successors,
            }
        )
    for function in cfg.kb.functions.values():
        if len(functions) >= max_functions:
            functions_truncated = True
            break
        try:
            count = len(function.blocks)
        except Exception:
            count = 0
        functions.append({"address": f"0x{int(function.addr):x}", "block_count": count})
    return {
        "bridge": {
            "protocol": PROTOCOL,
            "angr_version": getattr(angr, "__version__", None),
        },
        "target": target_record(request, observed, None),
        "function_count": len(cfg.kb.functions),
        "functions": functions,
        "functions_truncated": functions_truncated or len(cfg.kb.functions) > max_functions,
        "block_count": len(blocks),
        "blocks": blocks,
        "blocks_truncated": blocks_truncated,
        "edge_count": edge_count,
        "coverage": "partial" if blocks_truncated or functions_truncated else "complete",
    }


def handle(request: dict) -> dict:
    if not isinstance(request, dict):
        raise BridgeRefusal("invalid_request", "a request must be a JSON object")
    kind = request.get("kind")
    if kind not in KINDS:
        raise BridgeRefusal("invalid_request", "kind is not a symbolic job")
    if request.get("protocol") != PROTOCOL:
        raise BridgeRefusal(
            "protocol_mismatch", f"this bridge speaks protocol {PROTOCOL}"
        )
    angr = require_angr()
    if kind == KIND_FIND_PATHS:
        return find_paths(angr, request)
    if kind == KIND_EXPLORE:
        return explore_function(angr, request)
    return recover_cfg(angr, request)


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
        sys.stderr.write("rea-angr-bridge: no request on stdin\n")
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
