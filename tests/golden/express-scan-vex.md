# sbomlens scan: express-4.17.1@1.0.0

- **SBOM:** `fixtures/sbom/real/express-4.17.1.spdx.json` (SPDX 2.3), 51 components, 85 edges, max depth 4
- **Checked:** 51 of 51 components (0 without purl, 0 unsupported ecosystem, 0 without version)
- **OSV database:** 382 advisories from 382 files (0 withdrawn, 684 affected entries indexed)
- **Findings:** 13 active (13 distinct vulnerabilities after alias merge), 3 suppressed by VEX

| Severity | Findings |
|---|---:|
| critical | 1 |
| high | 4 |
| medium | 5 |
| low | 3 |

## Findings

| Severity | Package | Version | Advisory | Aliases | Fixed in | Introduced via |
|---|---|---|---|---|---|---|
| critical (9.1) | proxy-addr | 2.0.6 | [GHSA-jqcg-44mw-7w3h](https://nvd.nist.gov/vuln/detail/CVE-2026-90711) | CVE-2026-90711 | 2.0.8 | express-4.17.1 > express > proxy-addr |
| high (7.5) | body-parser | 1.19.0 | [GHSA-27r3-jxmh-p828](https://nvd.nist.gov/vuln/detail/CVE-2026-111181) | CVE-2026-111181 | 1.20.9 | express-4.17.1 > express > body-parser |
| high (7.5) | body-parser | 1.19.0 | [GHSA-qwcr-r2fm-qrc7](https://nvd.nist.gov/vuln/detail/CVE-2024-45590) | CVE-2024-45590 | 1.20.3 | express-4.17.1 > express > body-parser |
| high (7.5) | path-to-regexp | 0.1.7 | [GHSA-rhx6-c78j-4q9w](https://nvd.nist.gov/vuln/detail/CVE-2024-52798) | CVE-2024-52798 | 0.1.12 | express-4.17.1 > express > path-to-regexp |
| high (7.5) | qs | 6.7.0 | [GHSA-hrpp-h998-j3pp](https://nvd.nist.gov/vuln/detail/CVE-2022-24999) | CVE-2022-24999 | 6.7.3 | express-4.17.1 > express > qs |
| medium (5.0) | express | 4.17.1 | [GHSA-qw6h-vgh9-j6wx](https://nvd.nist.gov/vuln/detail/CVE-2024-43796) | CVE-2024-43796 | 4.20.0 | direct |
| medium (6.1) | express | 4.17.1 | [GHSA-rv95-896h-c2vc](https://nvd.nist.gov/vuln/detail/CVE-2024-29041) | CVE-2024-29041 | 4.19.2 | direct |
| medium (5.3) | qs | 6.7.0 | [GHSA-4mjr-xmp4-gh2g](https://nvd.nist.gov/vuln/detail/CVE-2026-82417) | CVE-2026-82417 | 6.16.0 | express-4.17.1 > express > qs |
| medium (5.0) | send | 0.17.1 | [GHSA-m6fv-jmcg-4jfg](https://nvd.nist.gov/vuln/detail/CVE-2024-43799) | CVE-2024-43799 | 0.19.0 | express-4.17.1 > express > send |
| medium (5.0) | serve-static | 1.14.1 | [GHSA-cm22-4g7w-348p](https://nvd.nist.gov/vuln/detail/CVE-2024-43800) | CVE-2024-43800 | 1.16.0 | express-4.17.1 > express > serve-static |
| low (3.7) | body-parser | 1.19.0 | [GHSA-v422-hmwv-36x6](https://nvd.nist.gov/vuln/detail/CVE-2026-12590) | CVE-2026-12590 | 1.20.6 | express-4.17.1 > express > body-parser |
| low (3.7) | qs | 6.7.0 | [GHSA-6rw7-vpxm-498p](https://nvd.nist.gov/vuln/detail/CVE-2025-15284) | CVE-2025-15284 | 6.14.1 | express-4.17.1 > express > qs |
| low (3.7) | qs | 6.7.0 | [GHSA-w7fw-mjwx-w883](https://nvd.nist.gov/vuln/detail/CVE-2026-2391) | CVE-2026-2391 | 6.14.2 | express-4.17.1 > express > qs |

## Suppressed by VEX

| Package | Version | Advisory | Status | Justification / impact | Statement |
|---|---|---|---|---|---|
| path-to-regexp | 0.1.7 | GHSA-37ch-88jc-xwx2 | not_affected | vulnerable_code_cannot_be_controlled_by_adversary | `https://example.invalid/vex/express-4.17.1-closure#0` |
| path-to-regexp | 0.1.7 | GHSA-9wv6-86v2-598j | not_affected | vulnerable_code_cannot_be_controlled_by_adversary | `https://example.invalid/vex/express-4.17.1-closure#0` |
| cookie | 0.4.0 | GHSA-pxg6-pf52-xh8x | not_affected | vulnerable_code_not_in_execute_path | `https://example.invalid/vex/express-4.17.1-closure#3` |

## VEX annotations on active findings

| Package | Advisory | Status | Action |
|---|---|---|---|
| qs | GHSA-hrpp-h998-j3pp | affected | Upgrade express to 4.21.2, which pulls qs 6.13.0. |

## Warnings

- https://example.invalid/vex/express-4.17.1-closure#5: ignored: not_affected requires a justification or impact_statement
- VEX statement https://example.invalid/vex/express-4.17.1-closure#4 matched no finding
