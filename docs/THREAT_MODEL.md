# Threat model

sbomlens is a defensive, offline analysis tool. It reads documents that other tools or other
parties produced: SBOMs, OSV advisories and OpenVEX statements. It produces reports that
humans and CI pipelines act on. It never executes package code, never contacts a network
service at runtime, and never modifies its inputs.

## Assets

1. **Correctness of findings.** A missed vulnerability (false negative) or an invented one
   (false positive) misleads whoever acts on the report.
2. **Integrity of triage.** VEX suppressions must not hide findings they were not written for.
3. **The CI pipeline running sbomlens.** Hostile input must not crash it in a way that slips
   past the gate, exhaust its resources, or inject content into rendered reports.

## Trust boundaries and adversaries

| Input | Who controls it | Trust |
|---|---|---|
| SBOM | the build that produced it; possibly a third-party vendor | untrusted |
| OSV database directory | whoever fetched or mirrored it | trusted for content, untrusted for shape |
| OpenVEX documents | product security team, or a vendor | untrusted for shape; content is policy |
| CLI arguments | the operator | trusted |

The adversaries considered are:

- **A vendor shipping a misleading SBOM**, for example with omitted components, wrong
  versions, or purls crafted to evade matching.
- **A tampered OSV mirror.**
- **A VEX author** who suppresses more than they should, by mistake or on purpose.
- **Malformed input** written to crash the tool or corrupt its output.

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | SBOM omits or misstates components | Out of scope. sbomlens reports what the SBOM says. The `inspect` and report counters show components without a purl, without a version, or in an unsupported ecosystem | A dishonest SBOM produces a clean report |
| T2 | Purl spelled to dodge matching (case, `_` vs `-`, percent-encoding) | purl-spec normalization, PEP 503 names, canonical keys for lookup | Ecosystems whose names are case-sensitive keep that sensitivity (npm, Maven) |
| T3 | Version string crafted to sort wrongly | Strict per-scheme parsers. A version that fails to parse is listed as "not fully checked" and never silently treated as safe | A typo that still parses is taken at face value |
| T4 | Tampered OSV data (edited ranges or removed advisories) | The bundled subset is pinned by sha256 (`make verify-data`). For user-supplied databases, integrity is the operator's responsibility; the report states the record count | No signature verification of OSV exports |
| T5 | Over-broad VEX suppression | Statements need a matching vulnerability id or alias *and* a product match on the component or its dependency path. `not_affected` needs a valid justification or impact statement, and invalid statements are ignored with a warning. Suppressed findings stay in every output (as SARIF suppressions) | A valid but dishonest statement is applied; VEX documents are not signature-checked |
| T6 | Stale VEX hiding a new advisory | Statements match vulnerability ids, not packages alone, and unused statements are reported | A statement written against a CVE also matches every advisory that aliases that CVE. This is intended, but worth knowing |
| T7 | Report injection: Markdown table breaking or link spoofing through summaries or package names | Table cells escape `\|` and newlines. SARIF is produced with a JSON serializer, never by string concatenation | Markdown viewers still render advisory summaries as Markdown inside cells |
| T8 | Resource exhaustion from huge or deeply nested JSON | serde_json's default recursion limit (128) bounds nesting. Graph algorithms are linear (BFS), and the Maven parser is linear in input length | Very large inputs are read fully into memory; there is no streaming |
| T9 | Crash on malformed input | No `unsafe` (`#![forbid(unsafe_code)]`). Every parser returns a typed error, and the CLI exits with code 2 and a message. Property tests run arbitrary purl and version inputs | Panics in dependencies are not fuzzed |
| T10 | CI gate bypass through exit codes | Exit 1 only for `--fail-on` and exit 2 for any error, so a crashing scan never looks like a pass | Unscored (`unknown`) severities never trip `--fail-on` on their own (documented) |

## Out of scope

- Generating SBOMs, and checking that an SBOM matches the artifact it describes.
- Reachability analysis: whether vulnerable code is actually called.
- Signature and provenance verification (Sigstore, in-toto) of SBOM, VEX or OSV inputs.
- Any network access. sbomlens never fetches advisories itself. The fetch scripts in
  `scripts/` are maintainer tools and are not part of the binary.
