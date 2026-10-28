#!/usr/bin/env python3
"""REA LIEF deep-parse bridge.

Reads exactly one bounded JSON request line from stdin and writes exactly one
JSON response frame to stdout. Diagnostics never reach stdout. The script
imports the caller-supplied LIEF release, verifies the artifact digest the
request declares, and reports structure only: no bytes, strings blocks, or
target content are inlined beyond the names LIEF already exposes as structure.
"""

from __future__ import annotations

import hashlib
import json
import sys

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 1024 * 1024
MAX_ARCHITECTURES = 32
MAX_DYNAMIC_ENTRIES = 256
MAX_LIBRARIES = 256
MAX_LOAD_COMMANDS = 512
MAX_DATA_DIRECTORIES = 32
MAX_DEBUG_ENTRIES = 16
MAX_DEBUG_SECTIONS = 64
MAX_QUERIES = 64
MAX_MATCHES_PER_QUERY = 16
MAX_LIMITATIONS = 32
MAX_DWARF_FUNCTIONS_SCANNED = 200000
HASH_CHUNK_BYTES = 1024 * 1024

FORMATS = ("elf", "pe", "macho", "macho-fat", "pdb", "unknown")

MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)


class BridgeRefusal(Exception):
    """A typed refusal this bridge reports as a `lief_error` frame."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def attribute(obj, name, default=None):
    """Read one attribute without letting a vendor property raise."""

    if obj is None:
        return default
    try:
        return getattr(obj, name)
    except Exception:  # noqa: BLE001 - vendor surfaces raise on unparsed objects
        return default


def enum_name(value, default=None):
    """Lowercase enum member name; LIEF enums expose `.name`."""

    if value is None:
        return default
    name = attribute(value, "name")
    if isinstance(name, str) and name:
        return name.lower()
    text = str(value)
    if not text or text in ("None", "0"):
        return default
    return text.rsplit(".", 1)[-1].lower()


def integer(value):
    """Non-negative integer from a LIEF numeric surface, else None."""

    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def text(value):
    """Nonempty string from a LIEF text surface, else None."""

    if value is None:
        return None
    result = str(value)
    return result if result else None


def sequence(value):
    """Iterate a LIEF collection without letting an unparsed one raise."""

    if value is None:
        return []
    try:
        return list(value)
    except Exception:  # noqa: BLE001 - vendor iterators raise on unparsed objects
        return []


def bounded(values, limit):
    """Retain at most `limit` items and report whether anything was dropped."""

    items = list(values)
    return items[:limit], len(items) > limit


def resolve_path(root, dotted):
    """Resolve a dotted attribute path, treating any failure as absent."""

    current = root
    for part in dotted.split("."):
        current = attribute(current, part)
        if current is None:
            return None
    return current


def load_lief():
    """Import the caller's LIEF release, or refuse with `lief_missing`."""

    try:
        import lief  # noqa: PLC0415 - the import is the configurable boundary
    except Exception as error:  # noqa: BLE001 - any import failure is typed
        raise BridgeRefusal(
            "lief_missing",
            f"the selected interpreter cannot import LIEF ({type(error).__name__}: {error})",
        )
    version = attribute(lief, "__version__")
    if not isinstance(version, str) or not version:
        raise BridgeRefusal(
            "lief_missing", "the imported LIEF module reports no __version__"
        )
    return lief


def capabilities(lief):
    """Which LIEF surfaces this release actually exposes."""

    return {
        "dwarf": any(
            resolve_path(lief, path) is not None
            for path in ("DWARF.from_binary", "DWARF.parse", "dwarf.load")
        ),
        "pdb": any(
            resolve_path(lief, path) is not None
            for path in ("PDB.from_file", "PDB.parse", "pdb.load")
        ),
        "fat": resolve_path(lief, "MachO.FatBinary") is not None,
    }


def advertisement(lief):
    """The bridge's own runtime facts, reported with every frame."""

    return {
        "lief_version": attribute(lief, "__version__"),
        "python_version": "{}.{}.{}".format(*sys.version_info[:3]),
        "capabilities": capabilities(lief),
    }


def classify(path):
    """Container kind from the artifact's own magic bytes."""

    try:
        with open(path, "rb") as handle:
            head = handle.read(16)
    except OSError as error:
        raise BridgeRefusal(
            "artifact_unreadable", f"the selected artifact cannot be read: {error}"
        )
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:16].startswith(b"Microsoft C/C++"):
        return "pdb"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in MACHO_MAGICS:
        return "macho"
    return "unknown"


def digest(path):
    """SHA-256 and byte count of the selected artifact."""

    hasher = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                hasher.update(chunk)
                total += len(chunk)
    except OSError as error:
        raise BridgeRefusal(
            "artifact_unreadable", f"the selected artifact cannot be read: {error}"
        )
    return hasher.hexdigest(), total


def is_fat(lief, binary):
    """Whether a parsed Mach-O is a universal container."""

    fat = resolve_path(lief, "MachO.FatBinary")
    return fat is not None and isinstance(binary, fat)


def architecture(lief, binary, index, size=None, offset=None):
    """One architecture row from a thin binary or a fat slice."""

    header = attribute(binary, "header")
    bits = None
    identity_class = enum_name(attribute(header, "identity_class"))
    if identity_class is not None:
        digits = "".join(character for character in identity_class if character.isdigit())
        bits = int(digits) if digits else None
    identity_data = enum_name(attribute(header, "identity_data"))
    little_endian = None if identity_data is None else identity_data in ("lsb", "2lsb", "little")
    cpu = enum_name(attribute(header, "cpu_type") or attribute(header, "machine_type"))
    if cpu is None:
        cpu = enum_name(attribute(header, "machine"))
    return {
        "index": index,
        "cpu": cpu or "unknown",
        "bits": bits,
        "little_endian": little_endian,
        "entrypoint": integer(attribute(binary, "entrypoint")),
        "image_base": integer(attribute(binary, "imagebase")),
        "size": size,
        "offset": offset,
    }


def dwarf_sections(binary):
    """Debug sections the artifact declares, bounded and ordered."""

    rows = []
    for section in sequence(attribute(binary, "sections")):
        name = text(attribute(section, "name"))
        if name is None or not name.lower().startswith((".debug", "__debug")):
            continue
        rows.append(
            {
                "name": name,
                "size": integer(attribute(section, "size")) or 0,
            }
        )
    retained, truncated = bounded(rows, MAX_DEBUG_SECTIONS)
    return {"present": len(rows) > 0, "sections": retained}, truncated


def pdb_reference_of(binary):
    """CodeView PDB identity recorded by a PE debug directory, if any."""

    if attribute(binary, "has_debug") is not True:
        return None
    entries, _ = bounded(sequence(attribute(binary, "debug")), MAX_DEBUG_ENTRIES)
    for entry in entries:
        reference = pdb_reference_of_entry(entry)
        if reference is not None:
            return reference
    return None


def pe_structure(binary):
    """PE header, data-directory and debug facts."""

    header = attribute(binary, "header")
    optional = attribute(binary, "optional_header")
    directories = sequence(attribute(binary, "data_directories"))
    if not directories:
        directories = sequence(attribute(optional, "data_directories"))
    directory_rows, directories_truncated = bounded(
        (
            {
                "name": enum_name(attribute(directory, "type"), "unknown") or "unknown",
                "rva": integer(attribute(directory, "rva")) or 0,
                "size": integer(attribute(directory, "size")) or 0,
            }
            for directory in directories
        ),
        MAX_DATA_DIRECTORIES,
    )
    characteristics = [
        name
        for name in (
            enum_name(value) for value in sequence(attribute(header, "characteristics_list"))
        )
        if name is not None
    ]
    debug_rows = []
    debug_truncated = False
    if attribute(binary, "has_debug") is True:
        entries, debug_truncated = bounded(
            sequence(attribute(binary, "debug")), MAX_DEBUG_ENTRIES
        )
        for entry in entries:
            debug_rows.append(
                {
                    "kind": enum_name(attribute(entry, "type"), "unknown") or "unknown",
                    "pdb_reference": pdb_reference_of_entry(entry),
                }
            )
    return (
        {
            "machine": enum_name(attribute(header, "machine")),
            "subsystem": enum_name(attribute(optional, "subsystem")),
            "characteristics": characteristics,
            "data_directories": directory_rows,
            "debug_entries": debug_rows,
        },
        directories_truncated,
        debug_truncated,
    )


def pdb_reference_of_entry(entry):
    """CodeView identity on one PE debug entry, if the entry carries one."""

    if enum_name(attribute(entry, "type"), "") not in ("codeview", "0"):
        return None
    code_view = attribute(entry, "code_view")
    if code_view is None:
        return None
    info = attribute(code_view, "pdb_info")
    if info is None:
        return None
    return {
        "path": text(attribute(info, "filename")),
        "guid": text(attribute(info, "guid")),
        "age": integer(attribute(info, "age")),
        "signature_kind": enum_name(attribute(code_view, "cv_signature")) or "codeview",
    }


def elf_dynamic(binary):
    """ELF interpreter, soname, dependency and dynamic-tag facts."""

    needed = [name for name in (text(value) for value in sequence(attribute(binary, "libraries"))) if name]
    rpath = []
    runpath = []
    entries = []
    truncated = False
    if attribute(binary, "has_dynamic_entries") is True or sequence(
        attribute(binary, "dynamic_entries")
    ):
        raw = sequence(attribute(binary, "dynamic_entries"))
        retained, truncated = bounded(raw, MAX_DYNAMIC_ENTRIES)
        for entry in retained:
            tag = enum_name(attribute(entry, "tag"), "unknown") or "unknown"
            value = attribute(entry, "value")
            if tag in ("rpath", "runpath", "dt_rpath", "dt_runpath"):
                recorded = text(value)
                if recorded is not None:
                    target = runpath if "runpath" in tag else rpath
                    target.append(recorded)
                continue
            recorded = integer(value)
            if recorded is None:
                continue
            entries.append({"tag": tag, "value": recorded})
    return (
        {
            "interpreter": text(attribute(binary, "interpreter"))
            if attribute(binary, "has_interpreter") is True
            else None,
            "soname": text(attribute(binary, "soname")),
            "needed": needed,
            "rpath": rpath,
            "runpath": runpath,
            "entries": entries,
        },
        truncated,
    )


def macho_structure(lief, binary):
    """Mach-O UUID, linked dylibs and load-command inventory."""

    libraries = []
    library_truncated = False
    for command in sequence(attribute(binary, "commands")):
        if "dylib" not in (enum_name(attribute(command, "command"), "") or ""):
            continue
        name = text(attribute(command, "name"))
        if name is None:
            continue
        libraries.append(
            {
                "name": name,
                "current_version": text(attribute(command, "current_version")),
                "compatibility_version": text(
                    attribute(command, "compatibility_version")
                ),
            }
        )
    libraries, library_truncated = bounded(libraries, MAX_LIBRARIES)
    rows = []
    commands, commands_truncated = bounded(
        sequence(attribute(binary, "commands")), MAX_LOAD_COMMANDS
    )
    for command in commands:
        rows.append(
            {
                "kind": enum_name(attribute(command, "command"), "unknown") or "unknown",
                "size": integer(attribute(command, "size")) or 0,
                "segment_name": text(attribute(command, "name")),
            }
        )
    uuid = text(attribute(binary, "uuid")) if attribute(binary, "has_uuid") is True else None
    return (
        {
            "uuid": uuid,
            "fat": is_fat(lief, binary),
            "libraries": libraries,
            "load_commands": rows,
        },
        library_truncated,
        commands_truncated,
    )


def inspect_binary_deep(lief, path):
    """Cross-format structure facts that the owning layout tools do not report."""

    kind = classify(path)
    if kind == "pdb":
        raise BridgeRefusal(
            "unsupported_format",
            "the artifact is a PDB; extract_pdb_dwarf_info owns its symbol surface",
        )
    if kind not in ("elf", "pe", "macho"):
        raise BridgeRefusal(
            "unsupported_format",
            "the artifact's magic bytes are not ELF, PE or Mach-O",
        )
    try:
        binary = lief.parse(path)
    except Exception as error:  # noqa: BLE001 - vendor parse failures are typed
        raise BridgeRefusal(
            "parse_failed", f"LIEF could not parse the artifact ({type(error).__name__}: {error})"
        )
    if binary is None:
        raise BridgeRefusal("parse_failed", "LIEF returned no parsed object")

    fat = is_fat(lief, binary)
    slices = sequence(binary) if fat else [binary]
    if fat and not slices:
        raise BridgeRefusal("parse_failed", "the universal container carries no slices")
    if len(slices) > MAX_ARCHITECTURES:
        raise BridgeRefusal(
            "parse_failed",
            f"the universal container declares {len(slices)} slices and exceeds the {MAX_ARCHITECTURES}-slice budget",
        )
    architectures = [
        architecture(
            lief,
            item,
            index,
            integer(attribute(item, "size")) if fat else None,
            integer(attribute(item, "offset")) if fat else None,
        )
        for index, item in enumerate(slices)
    ]
    primary = slices[0]
    sections, sections_truncated = dwarf_sections(primary)
    dynamic = None
    macho = None
    pe = None
    dynamic_truncated = False
    libraries_truncated = False
    load_commands_truncated = False
    data_directories_truncated = False
    debug_entries_truncated = False
    if kind == "elf":
        dynamic, dynamic_truncated = elf_dynamic(primary)
    elif kind == "macho":
        macho, libraries_truncated, load_commands_truncated = macho_structure(
            lief, primary
        )
        macho["fat"] = fat
    else:
        pe, data_directories_truncated, debug_entries_truncated = pe_structure(primary)

    limitations = []
    if fat:
        limitations.append(
            "counts and debug sections describe the first architecture of a universal binary; select a thin slice to inspect another"
        )
    if sections_truncated:
        limitations.append(
            f"at most {MAX_DEBUG_SECTIONS} debug sections are listed"
        )
    return {
        "format": "macho-fat" if fat else kind,
        "architectures": architectures,
        "structure_summary": {
            "section_count": len(sequence(attribute(primary, "sections"))),
            "segment_count": len(sequence(attribute(primary, "segments"))),
            "linked_library_count": len(sequence(attribute(primary, "libraries"))),
        },
        "dynamic": dynamic,
        "macho": macho,
        "pe": pe,
        "debug_sources": {
            "dwarf": sections,
            "pdb_reference": pdb_reference_of(primary) if kind == "pe" else None,
        },
        "truncated": {
            "architectures": False,
            "dynamic_entries": dynamic_truncated,
            "libraries": libraries_truncated,
            "load_commands": load_commands_truncated,
            "data_directories": data_directories_truncated,
            "debug_entries": debug_entries_truncated,
            "debug_sections": sections_truncated,
        },
        "limitations": limitations[:MAX_LIMITATIONS],
    }


def load_pdb(lief, path):
    """Load a PDB through whichever entry point this LIEF release exposes."""

    for label, action in (
        ("PDB.from_file", lambda: resolve_path(lief, "PDB.from_file")(path)),
        ("PDB.parse", lambda: resolve_path(lief, "PDB.parse")(path)),
        ("pdb.load", lambda: resolve_path(lief, "pdb.load")(path)),
    ):
        entry = resolve_path(lief, label)
        if entry is None:
            continue
        try:
            parsed = action()
        except Exception:  # noqa: BLE001 - a failing entry point falls through
            continue
        if parsed is not None:
            return parsed, label
    return None, None


def pdb_public_symbols(pdb):
    """Bounded public-symbol facts from a parsed PDB."""

    rows = []
    for symbol in sequence(attribute(pdb, "public_symbols")):
        rows.append(
            {
                "name": text(attribute(symbol, "name")),
                "rva": integer(attribute(symbol, "RVA") or attribute(symbol, "rva")),
            }
        )
        if len(rows) > MAX_DWARF_FUNCTIONS_SCANNED:
            break
    return rows


def load_dwarf(lief, binary, path):
    """Load DWARF through whichever entry point this LIEF release exposes."""

    for label, action in (
        ("DWARF.from_binary", lambda: resolve_path(lief, "DWARF.from_binary")(binary)),
        ("dwarf.load", lambda: resolve_path(lief, "dwarf.load")(binary)),
        ("dwarf.load(path)", lambda: resolve_path(lief, "dwarf.load")(path)),
        ("DWARF.parse", lambda: resolve_path(lief, "DWARF.parse")(binary)),
    ):
        entry = resolve_path(lief, label)
        if entry is None:
            continue
        try:
            parsed = action()
        except Exception:  # noqa: BLE001 - a failing entry point falls through
            continue
        if parsed is not None:
            return parsed, label
    return None, None


def dwarf_functions(dwarf):
    """Flatten compilation-unit functions into bounded (unit, function) rows."""

    rows = []
    units = sequence(attribute(dwarf, "compilation_units"))
    for unit in units:
        unit_name = text(attribute(unit, "name")) or text(
            attribute(unit, "compilation_dir")
        )
        for function in sequence(attribute(unit, "functions")):
            rows.append((unit_name, function))
            if len(rows) >= MAX_DWARF_FUNCTIONS_SCANNED:
                return rows, True
    return rows, False


def function_facts(function):
    """Name, linked range and size of one DWARF function entry."""

    name = text(attribute(function, "name")) or text(
        attribute(function, "linkage_name")
    )
    size = integer(attribute(function, "size"))
    address = integer(attribute(function, "address"))
    if address is None:
        ranges = sequence(attribute(function, "ranges"))
        if ranges:
            address = integer(attribute(ranges[0], "low"))
            if size is None:
                high = integer(attribute(ranges[0], "high"))
                if high is not None and address is not None:
                    size = high - address if high >= address else None
    return {"name": name, "address": address, "size": size}


def evaluate_query(query, source):
    """Answer one bounded lookup against the loaded debug sources."""

    kind = query.get("kind")
    matches = []
    truncated = False
    if kind == "symbol":
        wanted = query.get("name")
        for unit_name, facts in source["functions"]:
            if facts["name"] == wanted:
                matches.append(
                    {
                        "kind": "dwarf_function",
                        "name": facts["name"],
                        "address": facts["address"],
                        "size": facts["size"],
                        "rva": facts["rva"],
                        "compilation_unit": unit_name,
                    }
                )
    elif kind == "address":
        wanted = query.get("address")
        for unit_name, facts in source["functions"]:
            address = facts["address"]
            size = facts["size"] or 0
            if address is None:
                continue
            if address == wanted or (size > 0 and address <= wanted < address + size):
                matches.append(
                    {
                        "kind": "dwarf_function",
                        "name": facts["name"],
                        "address": address,
                        "size": facts["size"],
                        "rva": facts["rva"],
                        "compilation_unit": unit_name,
                    }
                )
    else:
        return {
            "query": query,
            "outcome": "unsupported",
            "matches": [],
            "reason": "the request carries an unknown lookup kind",
        }, truncated
    if len(matches) > MAX_MATCHES_PER_QUERY:
        matches = matches[:MAX_MATCHES_PER_QUERY]
        truncated = True
    return {
        "query": query,
        "outcome": "found" if matches else "not_found",
        "matches": matches,
        "reason": None,
    }, truncated


def pdb_source(lief, path, queries):
    """PDB inventory and public-symbol lookups."""

    pdb, entry = load_pdb(lief, path)
    if pdb is None:
        reason = (
            "this LIEF release exposes no PDB reader"
            if resolve_path(lief, "PDB") is None and resolve_path(lief, "pdb") is None
            else "LIEF could not open the PDB symbol table"
        )
        return {
            "pdb": {
                "reference": None,
                "available": False,
                "public_symbol_count": None,
                "compilation_unit_count": None,
            },
            "queries": [
                {
                    "query": query,
                    "outcome": "unsupported",
                    "matches": [],
                    "reason": reason,
                }
                for query in queries
            ],
            "truncated_matches": False,
            "truncated_functions": False,
            "limitations": [reason],
        }
    symbols = pdb_public_symbols(pdb)
    rows = [
        (
            None,
            {
                "name": symbol["name"],
                "address": None,
                "size": None,
                "rva": symbol["rva"],
            },
        )
        for symbol in symbols
        if symbol["name"] is not None
    ]
    results = []
    truncated = False
    for query in queries:
        result, dropped = evaluate_symbol_query(query, rows)
        truncated = truncated or dropped
        results.append(result)
    units = sequence(attribute(pdb, "compilation_units"))
    return {
        "pdb": {
            "reference": None,
            "available": True,
            "public_symbol_count": len(symbols),
            "compilation_unit_count": len(units) if units else None,
        },
        "queries": results,
        "truncated_matches": truncated,
        "truncated_functions": False,
        "limitations": [
            f"PDB lookups answered by {entry} match public symbol names exactly; private and local symbols stay unlisted"
        ],
    }


def evaluate_symbol_query(query, rows):
    """Exact-match lookup over the flattened symbol rows."""

    if query.get("kind") == "symbol":
        wanted = query.get("name")
        matches = [
            {
                "kind": "pdb_public_symbol",
                "name": facts["name"],
                "address": None,
                "size": None,
                "rva": facts["rva"],
                "compilation_unit": unit,
            }
            for unit, facts in rows
            if facts["name"] == wanted
        ]
    elif query.get("kind") == "address":
        wanted = query.get("address")
        matches = [
            {
                "kind": "pdb_public_symbol",
                "name": facts["name"],
                "address": None,
                "size": None,
                "rva": facts["rva"],
                "compilation_unit": unit,
            }
            for unit, facts in rows
            if facts["rva"] == wanted
        ]
    else:
        return (
            {
                "query": query,
                "outcome": "unsupported",
                "matches": [],
                "reason": "the request carries an unknown lookup kind",
            },
            False,
        )
    dropped = len(matches) > MAX_MATCHES_PER_QUERY
    return (
        {
            "query": query,
            "outcome": "found" if matches else "not_found",
            "matches": matches[:MAX_MATCHES_PER_QUERY],
            "reason": None,
        },
        dropped,
    )


def binary_source(lief, path, kind, binary, queries):
    """DWARF inventory and derived-function lookups for a parsed binary."""

    sections, sections_truncated = dwarf_sections(binary)
    reference = pdb_reference_of(binary) if kind == "pe" else None
    limitations = []
    if sections_truncated:
        limitations.append(f"at most {MAX_DEBUG_SECTIONS} debug sections are listed")
    if not sections["present"]:
        reason = "the artifact declares no DWARF sections"
        return {
            "dwarf": {
                "present": False,
                "sections": [],
                "compilation_unit_count": None,
                "function_count": None,
            },
            "pdb": {
                "reference": reference,
                "available": capabilities(lief)["pdb"],
                "public_symbol_count": None,
                "compilation_unit_count": None,
            },
            "queries": [
                {
                    "query": query,
                    "outcome": "unsupported",
                    "matches": [],
                    "reason": reason,
                }
                for query in queries
            ],
            "truncated_matches": False,
            "truncated_functions": False,
            "limitations": limitations + [reason],
        }
    dwarf, entry = load_dwarf(lief, binary, path)
    if dwarf is None:
        reason = "this LIEF release exposes no DWARF reader for the artifact"
        return {
            "dwarf": {
                "present": True,
                "sections": sections["sections"],
                "compilation_unit_count": None,
                "function_count": None,
            },
            "pdb": {
                "reference": reference,
                "available": capabilities(lief)["pdb"],
                "public_symbol_count": None,
                "compilation_unit_count": None,
            },
            "queries": [
                {
                    "query": query,
                    "outcome": "unsupported",
                    "matches": [],
                    "reason": reason,
                }
                for query in queries
            ],
            "truncated_matches": False,
            "truncated_functions": False,
            "limitations": limitations + [reason],
        }
    rows, scanned_truncated = dwarf_functions(dwarf)
    source = {
        "functions": [
            (
                unit_name,
                {
                    **function_facts(function),
                    "rva": None,
                },
            )
            for unit_name, function in rows
        ],
    }
    results = []
    matches_truncated = False
    for query in queries:
        result, dropped = evaluate_query(query, source)
        matches_truncated = matches_truncated or dropped
        results.append(result)
    units = sequence(attribute(dwarf, "compilation_units"))
    limitations.append(f"DWARF lookups answered by {entry}")
    if scanned_truncated:
        limitations.append(
            f"at most {MAX_DWARF_FUNCTIONS_SCANNED} DWARF functions are scanned"
        )
    return {
        "dwarf": {
            "present": True,
            "sections": sections["sections"],
            "compilation_unit_count": len(units) if units else None,
            "function_count": len(rows),
        },
        "pdb": {
            "reference": reference,
            "available": capabilities(lief)["pdb"],
            "public_symbol_count": None,
            "compilation_unit_count": None,
        },
        "queries": results,
        "truncated_matches": matches_truncated,
        "truncated_functions": scanned_truncated,
        "limitations": limitations,
    }


def extract_pdb_dwarf_info(lief, path, queries):
    """Debug-source inventory plus bounded lookups for one artifact."""

    kind = classify(path)
    queries_truncated = len(queries) > MAX_QUERIES
    queries = queries[:MAX_QUERIES]
    if kind == "pdb":
        source = pdb_source(lief, path, queries)
        artifact_kind = "pdb"
        dwarf = {
            "present": False,
            "sections": [],
            "compilation_unit_count": None,
            "function_count": None,
        }
    else:
        if kind not in ("elf", "pe", "macho"):
            raise BridgeRefusal(
                "unsupported_format",
                "the artifact's magic bytes are not ELF, PE, Mach-O or PDB",
            )
        try:
            binary = lief.parse(path)
        except Exception as error:  # noqa: BLE001 - vendor parse failures are typed
            raise BridgeRefusal(
                "parse_failed",
                f"LIEF could not parse the artifact ({type(error).__name__}: {error})",
            )
        if binary is None:
            raise BridgeRefusal("parse_failed", "LIEF returned no parsed object")
        fat = is_fat(lief, binary)
        slices = sequence(binary) if fat else [binary]
        if not slices:
            raise BridgeRefusal("parse_failed", "the universal container carries no slices")
        artifact_kind = "macho-fat" if fat else kind
        source = binary_source(lief, path, "macho" if fat else kind, slices[0], queries)
        dwarf = source["dwarf"]
    return {
        "artifact_kind": artifact_kind,
        "debug_sources": {"dwarf": dwarf, "pdb": source["pdb"]},
        "queries": source["queries"],
        "truncated": {
            "queries": queries_truncated,
            "matches": source["truncated_matches"],
            "dwarf_functions": source["truncated_functions"],
        },
        "limitations": source["limitations"][:MAX_LIMITATIONS],
    }


def read_request():
    """Read exactly one bounded request line from stdin."""

    line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
    if not line:
        raise BridgeRefusal("empty_request", "stdin carried no request line")
    if len(line) > MAX_REQUEST_BYTES:
        raise BridgeRefusal(
            "oversized_request",
            f"the request line exceeds {MAX_REQUEST_BYTES} bytes",
        )
    try:
        request = json.loads(line.decode("utf-8"))
    except Exception as error:  # noqa: BLE001 - any decode failure is typed
        raise BridgeRefusal(
            "malformed_request", f"the request line is not JSON ({error})"
        )
    if not isinstance(request, dict):
        raise BridgeRefusal("malformed_request", "the request is not a JSON object")
    if request.get("protocol") != PROTOCOL_VERSION:
        raise BridgeRefusal(
            "unsupported_protocol",
            f"the request speaks protocol {request.get('protocol')!r}; this bridge speaks {PROTOCOL_VERSION}",
        )
    return request


def verify_artifact(request):
    """Bind the request to the artifact bytes before any parsing."""

    path = request.get("path")
    declared = request.get("artifact")
    if not isinstance(path, str) or not path:
        raise BridgeRefusal("malformed_request", "the request carries no artifact path")
    if not isinstance(declared, dict):
        raise BridgeRefusal(
            "malformed_request", "the request carries no declared artifact identity"
        )
    sha256, size = digest(path)
    if declared.get("sha256") != sha256 or declared.get("bytes") != size:
        raise BridgeRefusal(
            "artifact_mismatch",
            "the artifact bytes no longer match the digest the caller declared",
        )
    return path


def queries_of(request):
    """Validated lookup list, preserving the caller's order and values."""

    queries = request.get("queries", [])
    if not isinstance(queries, list):
        raise BridgeRefusal("malformed_request", "`queries` must be a list")
    admitted = []
    for query in queries[:MAX_QUERIES]:
        if not isinstance(query, dict):
            raise BridgeRefusal("malformed_request", "each query must be an object")
        kind = query.get("kind")
        if kind == "symbol":
            name = query.get("name")
            if not isinstance(name, str) or not name:
                raise BridgeRefusal(
                    "malformed_request", "a symbol query needs a nonempty name"
                )
            admitted.append({"kind": "symbol", "name": name})
        elif kind == "address":
            address = query.get("address")
            if not isinstance(address, int) or isinstance(address, bool) or address < 0:
                raise BridgeRefusal(
                    "malformed_request", "an address query needs a nonnegative integer"
                )
            admitted.append({"kind": "address", "address": address})
        else:
            raise BridgeRefusal(
                "malformed_request", f"unknown query kind {kind!r}"
            )
    return admitted


def complete_of(truncated):
    """Completeness is the exact negation of any recorded truncation."""

    return not any(truncated.values())


def main():
    """Answer one request with exactly one frame on stdout."""

    lief = None
    try:
        request = read_request()
        lief = load_lief()
        operation = request.get("operation")
        if operation not in ("inspect_binary_deep", "extract_pdb_dwarf_info"):
            raise BridgeRefusal(
                "unsupported_operation",
                f"unknown operation {operation!r}",
            )
        path = verify_artifact(request)
        if operation == "inspect_binary_deep":
            report = inspect_binary_deep(lief, path)
        else:
            report = extract_pdb_dwarf_info(lief, path, queries_of(request))
        report["complete"] = complete_of(report.get("truncated", {}))
        report.setdefault("limitations", [])
        frame = {
            "kind": "lief_report",
            "protocol": PROTOCOL_VERSION,
            "operation": operation,
            "bridge": advertisement(lief),
            "report": report,
        }
    except BridgeRefusal as refusal:
        frame = {
            "kind": "lief_error",
            "protocol": PROTOCOL_VERSION,
            "code": refusal.code,
            "message": refusal.message,
        }
    except Exception as error:  # noqa: BLE001 - one frame, never a traceback
        print(
            f"lief_bridge: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        frame = {
            "kind": "lief_error",
            "protocol": PROTOCOL_VERSION,
            "code": "internal_error",
            "message": f"{type(error).__name__}: {error}",
        }
    sys.stdout.write(json.dumps(frame, separators=(",", ":"), sort_keys=True))
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
