"""Interoperability check: drive NovrSOC's TAXII 2.1 server with the OASIS taxii2-client library.

Usage:  python taxii_client_check.py '<harness JSON line>'
        (the line printed by `npx tsx src/routes/__tests__/tiTaxiiHarness.ts`)
Needs:  pip install taxii2-client==2.3.0 stix2-validator==3.2.0 stix2==3.0.1   (test tooling only)

Checks, through the library's own request and response handling (media types, envelopes,
paging): discovery and API root, the collection list, reading every page of each collection,
the manifest, fetching one object and its versions, wrong credentials refused, writes refused,
the RED fixture never served, and every received object valid per the OASIS STIX validator.
"""
import json
import sys

import requests
from taxii2client.v21 import Server, ApiRoot, Collection, as_pages
from taxii2client.exceptions import TAXIIServiceException
from stix2validator import validate_instance, ValidationOptions

cfg = json.loads(sys.argv[1])
USER, PASS = cfg["username"], cfg["password"]
failures = []


def expect(cond, msg):
    print(("  ok    " if cond else "  FAIL  ") + msg)
    if not cond:
        failures.append(msg)


server = Server(cfg["url"], user=USER, password=PASS)
expect(server.title == "NovrSOC TAXII 2.1", f"discovery title: {server.title!r}")
expect(len(server.api_roots) == 1, f"one API root: {[r.url for r in server.api_roots]}")
root: ApiRoot = server.default
expect(root.versions == ["application/taxii+json;version=2.1"], f"API root versions {root.versions}")
cols = {c.id: c for c in root.collections}
expect(set(cols) == {c["id"] for c in cfg["collections"]}, f"collections {sorted(cols)}")

opts = ValidationOptions(version="2.1", strict=False)
for c in cfg["collections"]:
    col: Collection = cols[c["id"]]
    expect(col.can_read and not col.can_write, f"{c['alias']}: readable, not writable")
    objects = []
    pages = 0
    for envelope in as_pages(col.get_objects, per_request=10):
        pages += 1
        objects.extend(envelope.get("objects", []))
    ids = [o["id"] for o in objects]
    want = cfg["expected"]["indicators" if c["alias"] == "indicators" else "vulnerabilities"]
    expect(len(ids) == want and len(set(ids)) == len(ids), f"{c['alias']}: {len(ids)} objects over {pages} page(s), expected {want}, no duplicates")
    expect(cfg["expected"]["never"] not in ids, f"{c['alias']}: the RED fixture is not served")
    bad = [o["id"] for o in objects if not validate_instance(o, opts).is_valid]
    expect(not bad, f"{c['alias']}: every object passes the OASIS validator ({len(objects) - len(bad)}/{len(objects)})")
    manifest = col.get_manifest()
    expect(all({"id", "date_added", "version", "media_type"} <= set(m) for m in manifest.get("objects", [])), f"{c['alias']}: manifest entries complete")
    if objects:
        one = col.get_object(objects[0]["id"])
        expect([o["id"] for o in one["objects"]] == [objects[0]["id"]], f"{c['alias']}: get_object returns that object")
        versions = col.object_versions(objects[0]["id"])
        expect(versions.get("versions") == [objects[0]["modified"]], f"{c['alias']}: object versions = its modified time")
        added = col.get_objects(added_after=manifest["objects"][-1]["date_added"])
        expect(not added.get("objects"), f"{c['alias']}: added_after the newest date returns nothing")

try:
    Server(cfg["url"], user=USER, password="wrong-password").refresh()
    expect(False, "wrong password refused")
except (TAXIIServiceException, requests.exceptions.HTTPError) as exc:
    expect("401" in str(exc), f"wrong password refused ({str(exc)[:60]})")

first = cols[cfg["collections"][0]["id"]]
try:
    first.add_objects({"type": "bundle", "id": "bundle--6b2e1f5c-0f5a-4a3e-9a62-4c7f0f9d8a11", "objects": []})
    expect(False, "the client refuses to write to a collection with can_write false")
except (TAXIIServiceException, requests.exceptions.HTTPError) as exc:
    expect("allow writing" in str(exc) or "403" in str(exc), f"the client refuses to write ({str(exc)[-40:]})")
# And the server itself, asked directly, refuses with 403 and a TAXII error body.
raw = requests.post(first.url + "objects/", auth=(USER, PASS), headers={"Accept": "application/taxii+json;version=2.1", "Content-Type": "application/taxii+json;version=2.1"}, data=json.dumps({"objects": []}), timeout=10)
expect(raw.status_code == 403 and raw.headers.get("Content-Type") == "application/taxii+json;version=2.1" and "title" in raw.json(), f"server refuses writes: HTTP {raw.status_code}, {raw.headers.get('Content-Type')}")

print("TAXII CLIENT CHECK:", "PASS" if not failures else f"FAIL ({len(failures)})")
sys.exit(1 if failures else 0)
