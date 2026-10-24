# Data

All data used by tests, the demo, the evals and the benchmark is committed (about 2.6 MB in
total) or generated deterministically. Nothing is downloaded at test time.

## Real SBOMs (`fixtures/sbom/real/`)

| File | Generator | Subject | Pinned with |
|---|---|---|---|
| `express-4.17.1.cdx.json` | `npm sbom --sbom-format cyclonedx` (npm 11.12.1), CycloneDX 1.5 | dependency closure of `express@4.17.1` | `npm install --package-lock-only --ignore-scripts --before 2021-06-01` |
| `express-4.17.1.spdx.json` | `npm sbom --sbom-format spdx` (npm 11.12.1), SPDX 2.3 | same | same |
| `express-4.21.2.cdx.json` | `npm sbom` CycloneDX 1.5 | closure of `express@4.21.2` | `--before 2025-01-01` |
| `express-4.21.2.spdx.json` | `npm sbom` SPDX 2.3 | same | same |
| `flask-2.2.2.cdx.json` | `uv export --format cyclonedx1.5` (uv 0.11.28) | closure of `flask==2.2.2` + `requests==2.28.1` | `uv lock --exclude-newer 2023-01-15T00:00:00Z` |

- **How:** `scripts/gen-real-sboms.sh`. It needs network access, npm ≥ 10 and uv ≥ 0.8. It
  writes a small wrapper `package.json`/`pyproject.toml` in a temporary directory and resolves
  a lockfile without running any package code (`--package-lock-only --ignore-scripts`). It then
  runs the first-party SBOM generator. The wrapper project is the SBOM's root component, which
  is why each SBOM's root is named after the fixture.
- **License:** the SBOM files describe packages and their declared licenses. They contain no
  third-party code. Package metadata comes from the npm registry and PyPI.
- **Regenerating** changes timestamps and serial numbers. With the same pins, the dependency
  sets should not change.
- sha256 at commit time:
  - `express-4.17.1.cdx.json` bfda879a…63daed
  - `express-4.17.1.spdx.json` 9fed8e1b…ce8d
  - `express-4.21.2.cdx.json` d1b48409…0ded
  - `express-4.21.2.spdx.json` f9e85eaa…aa17
  - `flask-2.2.2.cdx.json` 74ceb85c…638e

## Hand-written fixtures

- `fixtures/sbom/synthetic/polyglot-gateway.cdx.json` is a **synthetic** CycloneDX 1.6
  document for a fictional service. It nests cargo, Go (including a real pseudo-version),
  Maven, PyPI and npm components. The package names and versions are real and were chosen to
  hit known advisories: Log4Shell, Spring4Shell, RUSTSEC-2021-0003, golang.org/x/net, and
  others. Original work, MIT.
- `fixtures/vex/express-4.17.1.openvex.json` is **synthetic** demo triage. The statements are
  invented to exercise VEX behaviour: suppression, annotation, timestamp precedence, an unused
  statement, and an invalid statement. They are not claims by any real project. Original work,
  MIT.
- `tests/golden/*` are outputs rendered by sbomlens itself.

## OSV subset (`fixtures/osv/`)

- **Source:** the OSV.dev API (`https://api.osv.dev/v1`), fetched 2026-10-24T16:58:58Z by
  `scripts/fetch-osv-subset.py` (Python stdlib only).
- **Selection:** for every purl in `fixtures/sbom/**`, the script fetches *all* advisories of
  that package, at any version, so the database holds both matching and non-matching records.
  It also records which advisories OSV.dev reports for the exact version in
  `expected-matches.json`, which is the ground truth for the agreement eval. Result: 382
  records, 2.4 MB, covering npm, PyPI, Maven, Go and crates.io. A few records also carry
  RubyGems/SwiftURL entries.
- **Integrity:** `MANIFEST.json` pins the sha256 of every record. `make verify-data` (part of
  `make check`) fails on any missing, extra or modified record.
- **License:** OSV.dev aggregates sources under their own terms. GitHub Security Advisories,
  PyPA advisories and the Go vulnerability database are CC-BY-4.0. RustSec advisories are
  CC0-1.0. Attribution: OSV.dev and the respective upstream databases. Records are stored
  unmodified, apart from key-sorted re-serialization.

## Specification test vectors (`tests/`)

- `tests/data/purl-spec-test-suite-data.json` is the official purl-spec `test-suite-data.json`
  at commit `3bcba88a651ee9a681620391b869d26d0a6d6dc2` (2025-03-10). sha256
  `9cd3ada5ab0c9b7a2bab245693728cbbd223b2dd115fe671b9eac9336f4c3d77`. MIT license.
- `tests/version_ordering.rs` transcribes ordering examples from:
  - SemVer 2.0.0 §11 (CC-BY-3.0);
  - PEP 440 (public domain);
  - Apache Maven `maven-3.9.9` `ComparableVersionTest.java` (Apache-2.0; test vectors only, no
    code copied);
  - the Go Modules Reference (CC-BY-4.0).

## Synthetic benchmark data

`benches/matching.rs` generates 20,000 advisories and a 5,001-component SBOM in memory from a
fixed xorshift seed (`0x5EED_1234`). No files are written.
