#!/usr/bin/env bash
# Offline end-to-end demo over the bundled fixtures. No network needed.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release --locked --quiet
BIN="${CARGO_TARGET_DIR:-target}/release/sbomlens"
OUT=out
mkdir -p "$OUT"

step() { printf '\n==> %s\n$ %s\n' "$1" "$2"; }

step "1. Normalize a real SPDX 2.3 SBOM (npm sbom over express@4.17.1)" \
  "sbomlens inspect fixtures/sbom/real/express-4.17.1.spdx.json --tree 2"
"$BIN" inspect fixtures/sbom/real/express-4.17.1.spdx.json --tree 2 | head -24

step "2. Per-ecosystem version ordering" "sbomlens compare <ecosystem> <a> <b>"
"$BIN" compare PyPI 1.0.dev1 1.0a1
"$BIN" compare PyPI 1.0.post1 1.0+local.7
"$BIN" compare Maven 1.0-SNAPSHOT 1.0
"$BIN" compare Maven 30.1-jre 32.0.0-android
"$BIN" compare Go v0.0.0-20210226172049-e18ecbb05110 0.0.0-20220906165146-f3363e06e74c
"$BIN" compare npm 1.0.0-beta.11 1.0.0-beta.2

step "3. Decode a Go pseudo-version purl" \
  "sbomlens purl pkg:golang/golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110"
"$BIN" purl pkg:golang/golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110

step "4. Diff two real SBOMs across formats (CycloneDX 1.5 -> SPDX 2.3)" \
  "sbomlens diff express-4.17.1.cdx.json express-4.21.2.spdx.json"
"$BIN" diff fixtures/sbom/real/express-4.17.1.cdx.json fixtures/sbom/real/express-4.21.2.spdx.json \
  -o "$OUT/express-diff.md"
sed -n '1,12p' "$OUT/express-diff.md"
echo "... (full report: $OUT/express-diff.md)"

step "5. Scan express@4.17.1 against the pinned OSV subset with OpenVEX triage" \
  "sbomlens scan express-4.17.1.spdx.json --osv fixtures/osv/db --vex express-4.17.1.openvex.json"
"$BIN" scan fixtures/sbom/real/express-4.17.1.spdx.json --osv fixtures/osv/db \
  --vex fixtures/vex/express-4.17.1.openvex.json -o "$OUT/express-scan.md"
cat "$OUT/express-scan.md"

step "6. SARIF for the polyglot CycloneDX 1.6 fixture (cargo, Go, Maven, PyPI, npm)" \
  "sbomlens scan polyglot-gateway.cdx.json --osv fixtures/osv/db --format sarif --fail-on critical"
set +e
"$BIN" scan fixtures/sbom/synthetic/polyglot-gateway.cdx.json --osv fixtures/osv/db \
  --format sarif -o "$OUT/polyglot.sarif" --fail-on critical
status=$?
set -e
python3 - "$OUT/polyglot.sarif" <<'PY'
import collections, json, sys
log = json.load(open(sys.argv[1]))
run = log["runs"][0]
levels = collections.Counter(r["level"] for r in run["results"])
print(f"SARIF {log['version']}: {len(run['tool']['driver']['rules'])} rules, {len(run['results'])} results, levels {dict(levels)}")
for r in run["results"][:5]:
    print("  -", r["level"], r["ruleId"], "|", r["message"]["text"][:110])
PY
echo "exit status with --fail-on critical: $status (1 = policy failed, as expected for Log4Shell)"

step "7. Scan the Flask closure (PEP 440 matching), summary only" \
  "sbomlens scan flask-2.2.2.cdx.json --osv fixtures/osv/db --format json"
"$BIN" scan fixtures/sbom/real/flask-2.2.2.cdx.json --osv fixtures/osv/db --format json -o "$OUT/flask.json"
python3 - "$OUT/flask.json" <<'PY'
import collections, json, sys
r = json.load(open(sys.argv[1]))
by_pkg = collections.Counter(f["package"] + "@" + f["version"] for f in r["scan"]["findings"])
print(f"{len(r['scan']['findings'])} findings over {r['scan']['stats']['checked']} components:")
for pkg, n in by_pkg.most_common():
    print(f"  {pkg:<24} {n}")
PY
echo
echo "demo outputs written to $OUT/"
