#!/usr/bin/env python3
"""Verify fixtures/osv/db against the sha256 pins in fixtures/osv/MANIFEST.json."""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "fixtures", "osv", "db")


def main():
    with open(os.path.join(ROOT, "fixtures", "osv", "MANIFEST.json")) as f:
        manifest = json.load(f)["records"]
    on_disk = {n[:-5] for n in os.listdir(DB) if n.endswith(".json")}
    problems = []
    for vid in sorted(on_disk - manifest.keys()):
        problems.append(f"unpinned record: {vid}")
    for vid in sorted(manifest.keys() - on_disk):
        problems.append(f"missing record: {vid}")
    for vid in sorted(on_disk & manifest.keys()):
        with open(os.path.join(DB, vid + ".json"), "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        if digest != manifest[vid]:
            problems.append(f"checksum mismatch: {vid}")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"verify-data: {len(manifest)} OSV records match MANIFEST.json")


if __name__ == "__main__":
    main()
