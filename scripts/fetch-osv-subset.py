#!/usr/bin/env python3
"""Fetch the pinned OSV subset used by tests, the demo and the agreement eval.

For every package that appears in fixtures/sbom/**.json this script:
  1. asks api.osv.dev for *all* advisories of the package (any version), so the
     offline database holds both matching and non-matching records;
  2. downloads each advisory to fixtures/osv/db/<ID>.json;
  3. asks api.osv.dev which advisories affect the exact version in the SBOM and
     stores that as the ground truth in fixtures/osv/expected-matches.json.

A MANIFEST.json with the fetch time and a sha256 per record pins the snapshot.
Stdlib only. Needs network. Not part of `make check`.
"""
import glob
import hashlib
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = "https://api.osv.dev/v1"
SKIP_TYPES = {"generic"}


def _open(req, attempts=5):
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except OSError as exc:  # timeouts, resets, 5xx surfaced as URLError
            if attempt == attempts - 1:
                raise
            print(f"retry {attempt + 1} after {exc}", file=sys.stderr, flush=True)
            time.sleep(2 * (attempt + 1))


def post(path, body):
    req = urllib.request.Request(
        f"{API}/{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    return _open(req)


def get(path):
    return _open(f"{API}/{path}")


def walk_cdx(components, out):
    for c in components or []:
        if c.get("purl"):
            out.add(c["purl"])
        walk_cdx(c.get("components"), out)


def collect_purls():
    purls = set()
    for path in glob.glob(os.path.join(ROOT, "fixtures/sbom/**/*.json"), recursive=True):
        with open(path) as f:
            doc = json.load(f)
        if doc.get("bomFormat") == "CycloneDX":
            walk_cdx(doc.get("components"), purls)
        elif "spdxVersion" in doc:
            for p in doc.get("packages", []):
                for ref in p.get("externalRefs", []):
                    if ref.get("referenceType") == "purl":
                        purls.add(ref["referenceLocator"])
    keep = set()
    for p in purls:
        ptype = p[4:].split("/", 1)[0].lower()
        if ptype in SKIP_TYPES or "@" not in p:
            continue
        keep.add(p)
    return sorted(keep)


def strip_version(purl):
    base = purl.split("?", 1)[0].split("#", 1)[0]
    return base.rsplit("@", 1)[0]


def main():
    purls = collect_purls()
    # Root/project components that are not published packages return nothing; fine.
    packages = sorted({strip_version(p) for p in purls})
    ids = set()
    for pkg in packages:
        token = None
        while True:
            body = {"package": {"purl": pkg}}
            if token:
                body["page_token"] = token
            res = post("query", body)
            ids.update(v["id"] for v in res.get("vulns", []))
            token = res.get("next_page_token")
            if not token:
                break
        print(f"{pkg}: {len(ids)} ids so far", file=sys.stderr, flush=True)

    expected = {}
    for i in range(0, len(purls), 100):
        chunk = purls[i : i + 100]
        res = post("querybatch", {"queries": [{"package": {"purl": p}} for p in chunk]})
        for purl, r in zip(chunk, res["results"]):
            found = sorted(v["id"] for v in r.get("vulns", []))
            if found:
                expected[purl] = found
            ids.update(found)

    db = os.path.join(ROOT, "fixtures/osv/db")
    os.makedirs(db, exist_ok=True)
    manifest = {}
    for vid in sorted(ids):
        rec = get(f"vulns/{vid}")
        data = (json.dumps(rec, indent=1, sort_keys=True) + "\n").encode()
        with open(os.path.join(db, f"{vid}.json"), "wb") as f:
            f.write(data)
        manifest[vid] = hashlib.sha256(data).hexdigest()
    with open(os.path.join(ROOT, "fixtures/osv/expected-matches.json"), "w") as f:
        json.dump(expected, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(os.path.join(ROOT, "fixtures/osv/MANIFEST.json"), "w") as f:
        json.dump(
            {
                "source": API,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "license_note": "See DATA.md: OSV.dev records are CC-BY-4.0 unless the source states otherwise",
                "records": manifest,
            },
            f,
            indent=1,
            sort_keys=True,
        )
        f.write("\n")
    print(f"{len(ids)} records, {len(expected)} affected purls", file=sys.stderr)


if __name__ == "__main__":
    main()
