#!/usr/bin/env bash
# Regenerate the "real" SBOM fixtures in fixtures/sbom/real/ from the dependency
# closures of real open-source projects, using first-party generators only:
#   * npm  >= 10  : `npm sbom` (CycloneDX 1.5 + SPDX 2.3) over a lockfile resolved
#                   with --package-lock-only --ignore-scripts (no package code runs)
#   * uv   >= 0.8 : `uv export --format cyclonedx1.5` over a uv.lock
# Resolution is pinned in time with npm --before / uv --exclude-newer so the
# dependency sets are reproducible. Needs network. Not part of `make check`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/fixtures/sbom/real"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

npm_closure() { # <fixture-name> <package> <version> <before-date>
  local name="$1" pkg="$2" ver="$3" before="$4" dir="$WORK/$1"
  mkdir -p "$dir"
  cat >"$dir/package.json" <<JSON
{ "name": "$name", "version": "1.0.0", "private": true, "license": "MIT",
  "dependencies": { "$pkg": "$ver" } }
JSON
  (cd "$dir" &&
    npm install --package-lock-only --ignore-scripts --before "$before" \
      --no-audit --no-fund >/dev/null &&
    npm sbom --package-lock-only --sbom-format cyclonedx >"$OUT/$name.cdx.json" &&
    npm sbom --package-lock-only --sbom-format spdx >"$OUT/$name.spdx.json")
  echo "wrote $name (.cdx.json, .spdx.json)"
}

uv_closure() { # <fixture-name> <exclude-newer> <requirement>...
  local name="$1" newer="$2" dir="$WORK/$1"
  shift 2
  mkdir -p "$dir"
  {
    echo '[project]'
    echo "name = \"$name\""
    echo 'version = "1.0.0"'
    echo 'requires-python = ">=3.12"'
    printf 'dependencies = ['
    local first=1
    for req in "$@"; do
      [ $first -eq 1 ] || printf ', '
      printf '"%s"' "$req"
      first=0
    done
    echo ']'
  } >"$dir/pyproject.toml"
  (cd "$dir" &&
    uv lock --quiet --exclude-newer "$newer" &&
    uv export --quiet --format cyclonedx1.5 --preview-features sbom-export -o "$OUT/$name.cdx.json")
  echo "wrote $name (.cdx.json)"
}

# Old and new express closures: the pair drives the diff demo.
npm_closure express-4.17.1 express 4.17.1 2021-06-01
npm_closure express-4.21.2 express 4.21.2 2025-01-01
# A Flask web-app closure resolved as of early 2023 (PEP 440 matching).
uv_closure flask-2.2.2 2023-01-15T00:00:00Z "flask==2.2.2" "requests==2.28.1"
