"""Validate a STIX 2.1 bundle produced by NovrSOC with the OASIS STIX validator and parser.

Usage:  python validate_stix.py <bundle.json> [<bundle.json> ...]
Needs:  pip install stix2-validator==3.2.0 stix2==3.0.1   (test tooling only, not the backend)

Exits non-zero when the OASIS validator reports an error, the stix2 library cannot parse the
bundle, or a NovrSOC-specific rule fails (identifier determinism, references resolve, markings
are the predefined TLP definitions). Warnings are printed and listed but do not fail the run.
"""
import json
import sys
import uuid

from stix2validator import validate_instance, ValidationOptions, print_results
import stix2

NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
TLP_IDS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def pattern_value(pattern):
    # "[ipv4-addr:value = '198.51.100.10']" -> ("ip", "198.51.100.10") for the id check
    obj = pattern[1:pattern.index(":")]
    value = pattern[pattern.index("'") + 1:pattern.rindex("'")].replace("\\'", "'").replace("\\\\", "\\")
    kind = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url"}.get(obj)
    if obj == "file":
        algo = pattern.split("hashes.")[1].split(" ")[0].strip("'").upper().replace("-", "")
        kind = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256"}.get(algo)
    return kind, value


def check(path):
    with open(path, encoding="utf-8") as fh:
        bundle = json.load(fh)
    problems = []
    opts = ValidationOptions(version="2.1", strict=False)
    result = validate_instance(bundle, opts)
    print_results(result)
    if not result.is_valid:
        problems.append("OASIS validator reported errors")
    warnings = [str(w) for w in (getattr(result, "warnings", None) or [])]
    try:
        stix2.parse(bundle, allow_custom=True)
    except Exception as exc:  # noqa: BLE001 - report any parser failure
        problems.append(f"stix2.parse failed: {exc}")
    ids = {o["id"] for o in bundle["objects"]}
    for o in bundle["objects"]:
        for ref_key in ("created_by_ref", "source_ref", "target_ref"):
            if ref_key in o and o[ref_key] not in ids:
                problems.append(f"{o['id']}: {ref_key} {o[ref_key]} is not in the bundle")
        for m in o.get("object_marking_refs", []):
            if m not in TLP_IDS:
                problems.append(f"{o['id']}: marking {m} is not a predefined TLP marking definition")
        if o["type"] == "indicator":
            kind, value = pattern_value(o["pattern"])
            want = f"indicator--{uuid.uuid5(NS, f'{kind}:{value}')}"
            if o["id"] != want:
                problems.append(f"{o['id']}: not the UUIDv5 of {kind}:{value} ({want})")
        if o["type"] == "vulnerability":
            want = f"vulnerability--{uuid.uuid5(NS, 'cve:' + o['name'])}"
            if o["id"] != want:
                problems.append(f"{o['id']}: not the UUIDv5 of cve:{o['name']}")
    counts = {}
    for o in bundle["objects"]:
        counts[o["type"]] = counts.get(o["type"], 0) + 1
    print(f"{path}: {len(bundle['objects'])} objects {counts}; {len(warnings)} warning(s)")
    for w in sorted(set(warnings)):
        print(f"  warning: {w}")
    for p in problems:
        print(f"  ERROR: {p}")
    return not problems


if __name__ == "__main__":
    ok = all(check(p) for p in sys.argv[1:])
    print("STIX VALIDATION:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
