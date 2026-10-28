#!/usr/bin/env python3
"""REA androguard bridge (MIT, authored for this repository).

Runs one bounded androguard 5.x observation over an Android APK and prints a
single JSON object on stdout. REA spawns this script with a caller-supplied
Python interpreter (REA_ANDROGUARD_PYTHON) and never installs packages.

Usage:
  androguard_bridge.py --apk PATH --operation structure|vulnerabilities
                       [--max-components N] [--max-cross-references N]
                       [--max-classes N]

Output shapes (one line each, no pretty printing):
  {"schema":"rea.androguard.v1","operation":"structure",...}
  {"schema":"rea.androguard.v1","operation":"vulnerabilities","findings":[...]}

Exit codes: 0 observed, 2 unreadable/unsupported artifact, 3 bridge failure.
Nothing but structure is emitted: no class bytecode, no string values, no
file paths beyond the digests REA already holds.
"""

import argparse
import json
import sys
import traceback

SCHEMA = "rea.androguard.v1"

DANGEROUS_EXPORTED_KINDS = ("activity", "service", "receiver", "provider")


def emit(document):
    sys.stdout.write(json.dumps(document, sort_keys=True) + "\n")
    sys.stdout.flush()


def android_attribute(element, name):
    for key, value in element.attrib.items():
        if key.rsplit("}", 1)[-1] == name:
            return value
    return None


def as_bool(value):
    if value is None:
        return None
    return str(value).lower() == "true"


def manifest_components(manifest, warnings):
    """Return declared components with their exported flag, or [] when absent.

    The exported flag is the explicit android:exported attribute when present;
    otherwise it is inferred the way the platform does it before API 31: an
    intent-filter makes a component externally reachable. A component whose
    declaration cannot be read keeps exported=None rather than a guess.
    """
    if manifest is None:
        warnings.append("the AndroidManifest.xml could not be decoded")
        return [], {}
    application = None
    for child in list(manifest):
        if child.tag.rsplit("}", 1)[-1] == "application":
            application = child
            break
    facts = {
        "debuggable": None,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
    }
    if application is None:
        warnings.append("the manifest declares no <application> element")
        return [], facts
    facts["debuggable"] = as_bool(android_attribute(application, "debuggable"))
    facts["allow_backup"] = as_bool(android_attribute(application, "allowBackup"))
    facts["uses_cleartext_traffic"] = as_bool(
        android_attribute(application, "usesCleartextTraffic")
    )
    components = []
    for child in list(application):
        kind = child.tag.rsplit("}", 1)[-1]
        if kind not in DANGEROUS_EXPORTED_KINDS:
            continue
        name = android_attribute(child, "name")
        if name is None:
            continue
        explicit = as_bool(android_attribute(child, "exported"))
        has_filter = any(
            grandchild.tag.rsplit("}", 1)[-1] == "intent-filter"
            for grandchild in list(child)
        )
        exported = explicit if explicit is not None else has_filter
        permission = android_attribute(child, "permission")
        components.append(
            {
                "kind": kind,
                "name": name,
                "exported": exported,
                "permission": permission,
            }
        )
    return components, facts


def cross_references(dx, max_classes, max_rows):
    """Aggregate class-to-class xrefs over a bounded class sample."""
    rows = {}
    examined = 0
    for klass in dx.get_classes():
        if examined >= max_classes:
            break
        examined += 1
        name = klass.name
        try:
            sources = klass.get_xref_from()
        except Exception:
            continue
        for source, _method in sources:
            source_name = getattr(source, "name", None)
            if source_name is None:
                continue
            key = (source_name, name)
            rows[key] = rows.get(key, 0) + 1
    ordered = sorted(rows.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    truncated = len(ordered) > max_rows
    return (
        [
            {"from": source, "to": target, "count": count}
            for (source, target), count in ordered[:max_rows]
        ],
        len(ordered),
        truncated,
        examined,
    )


def analyse_structure(a, d, dx, args):
    warnings = []
    try:
        manifest = a.get_android_manifest_xml()
    except Exception as error:  # pragma: no cover - depends on upstream release
        warnings.append("manifest decode failed: %s" % type(error).__name__)
        manifest = None
    components, manifest_facts = manifest_components(manifest, warnings)
    retained = components[: args.max_components]
    xrefs, xref_count, xref_truncated, examined = cross_references(
        dx, args.max_classes, args.max_cross_references
    )
    if examined >= args.max_classes:
        warnings.append(
            "cross references sampled over %d classes; the app has more"
            % args.max_classes
        )
    try:
        permissions = sorted(set(a.get_permissions() or []))
    except Exception:
        permissions = []
        warnings.append("declared permissions could not be enumerated")
    try:
        libraries = sorted(set(a.get_libraries() or []))
    except Exception:
        libraries = []
    return {
        "schema": SCHEMA,
        "operation": "structure",
        "package": a.get_package(),
        "app_name": a.get_app_name(),
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": _as_int(a.get_min_sdk_version()),
        "target_sdk": _as_int(a.get_target_sdk_version()),
        "permissions": permissions,
        "components": [
            {
                "kind": row["kind"],
                "name": row["name"],
                "exported": row["exported"],
            }
            for row in retained
        ],
        "component_count": len(components),
        "components_truncated": len(components) > len(retained),
        "cross_references": xrefs,
        "cross_reference_count": xref_count,
        "cross_references_truncated": xref_truncated,
        "native_libraries": libraries,
        "manifest_facts": manifest_facts,
        "unparsed_facts": 0,
        "warnings": warnings,
    }


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def analyse_vulnerabilities(structure, components, args):
    """Evaluate the fixed structure rules; only ids and locations are emitted."""
    findings = []

    def add(identifier, severity, location):
        findings.append(
            {"id": identifier, "severity": severity, "location": location}
        )

    for row in components:
        if row.get("exported") is True and row.get("permission") is None:
            add(
                "exported-component-without-permission",
                "warning",
                "%s:%s" % (row["kind"], row["name"]),
            )
    facts = structure.get("manifest_facts") or {}
    if facts.get("debuggable") is True:
        add("debuggable-application", "high", "manifest:application@debuggable")
    if facts.get("allow_backup") is True:
        add("allow-backup-enabled", "warning", "manifest:application@allowBackup")
    if facts.get("uses_cleartext_traffic") is True:
        add(
            "cleartext-traffic-permitted",
            "warning",
            "manifest:application@usesCleartextTraffic",
        )
    target_sdk = structure.get("target_sdk")
    if isinstance(target_sdk, int) and target_sdk < 30:
        add("outdated-target-sdk", "info", "manifest:uses-sdk@targetSdkVersion")
    if target_sdk is None:
        add("unknown-target-sdk", "info", "manifest:uses-sdk@targetSdkVersion")
    if not structure.get("permissions"):
        add("no-declared-permissions", "info", "manifest:uses-permission")
    truncated = len(findings) > args.max_findings
    return {
        "schema": SCHEMA,
        "operation": "vulnerabilities",
        "findings": findings[: args.max_findings],
        "finding_count": len(findings),
        "findings_truncated": truncated,
    }


def parse_arguments(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--operation", required=True, choices=("structure", "vulnerabilities"))
    parser.add_argument("--max-components", type=int, default=500)
    parser.add_argument("--max-cross-references", type=int, default=500)
    parser.add_argument("--max-classes", type=int, default=400)
    parser.add_argument("--max-findings", type=int, default=200)
    return parser.parse_args(argv)


def main(argv):
    args = parse_arguments(argv)
    import androguard

    version = getattr(androguard, "__version__", None)
    try:
        from androguard.misc import AnalyzeAPK
    except Exception as error:
        emit(
            {
                "schema": SCHEMA,
                "operation": args.operation,
                "androguard_version": version,
                "error": "androguard 5.x AnalyzeAPK is not importable: %s"
                % type(error).__name__,
            }
        )
        return 3
    try:
        a, d, dx = AnalyzeAPK(args.apk)
    except Exception as error:
        emit(
            {
                "schema": SCHEMA,
                "operation": args.operation,
                "androguard_version": version,
                "error": "the APK could not be parsed: %s" % type(error).__name__,
            }
        )
        return 2
    if args.operation == "structure":
        document = analyse_structure(a, d, dx, args)
        document["androguard_version"] = version
        emit(document)
        return 0
    structure = analyse_structure(a, d, dx, args)
    components, _facts = manifest_components(
        _manifest_or_none(a), structure["warnings"]
    )
    document = analyse_vulnerabilities(structure, components, args)
    document["androguard_version"] = version
    emit(document)
    return 0


def _manifest_or_none(a):
    try:
        return a.get_android_manifest_xml()
    except Exception:
        return None


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc(file=sys.stderr)
        emit({"schema": SCHEMA, "operation": "unknown", "error": "bridge failure"})
        sys.exit(3)
