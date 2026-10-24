# sbomlens scan: flask-2-2-2

- **SBOM:** `fixtures/sbom/real/flask-2.2.2.cdx.json` (CycloneDX 1.5), 13 components, 13 edges, max depth 3
- **Checked:** 12 of 13 components (1 without purl, 0 unsupported ecosystem, 0 without version)
- **OSV database:** 382 advisories from 382 files (0 withdrawn, 684 affected entries indexed)
- **Findings:** 72 active (36 distinct vulnerabilities after alias merge), 0 suppressed by VEX

| Severity | Findings |
|---|---:|
| critical | 1 |
| high | 21 |
| medium | 33 |
| low | 3 |
| unknown | 14 |

## Findings

| Severity | Package | Version | Advisory | Aliases | Fixed in | Introduced via |
|---|---|---|---|---|---|---|
| critical | certifi | 2022.12.7 | [GHSA-6q48-6c7w-9gw2](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2) |  | 2026.10.19 | flask-2-2-2 > requests > certifi |
| high (7.5) | certifi | 2022.12.7 | [GHSA-xqr8-7jwr-rhp7](https://nvd.nist.gov/vuln/detail/CVE-2023-37920) | CVE-2023-37920 | 2023.7.22 | flask-2-2-2 > requests > certifi |
| high (7.5) | certifi | 2022.12.7 | [PYSEC-2024-230](https://github.com/certifi/python-certifi/security/advisories/GHSA-248v-346w-9cwc) | CVE-2024-39689 | 2024.7.4 | flask-2-2-2 > requests > certifi |
| high (7.5) | flask | 2.2.2 | [GHSA-m2qf-hxjv-5gpq](https://nvd.nist.gov/vuln/detail/CVE-2023-30861) | CVE-2023-30861 | 2.2.5 | direct |
| high (7.5) | idna | 3.4 | [PYSEC-2024-60](https://github.com/advisories/GHSA-jjg7-2v4v-x38h) | CVE-2024-3651 | 3.7 | flask-2-2-2 > requests > idna |
| high (8.8) | jinja2 | 3.1.2 | [GHSA-gmj6-6f8f-6699](https://nvd.nist.gov/vuln/detail/CVE-2024-56201) | CVE-2024-56201 | 3.1.5 | flask-2-2-2 > flask > jinja2 |
| high (7.8) | jinja2 | 3.1.2 | [GHSA-q2x7-8rv6-6q7h](https://nvd.nist.gov/vuln/detail/CVE-2024-56326) | CVE-2024-56326 | 3.1.5 | flask-2-2-2 > flask > jinja2 |
| high (8.8) | jinja2 | 3.1.2 | [PYSEC-2026-1472](https://nvd.nist.gov/vuln/detail/CVE-2024-56201) | CVE-2024-56201 | 3.1.5 | flask-2-2-2 > flask > jinja2 |
| high (7.8) | jinja2 | 3.1.2 | [PYSEC-2026-1475](https://nvd.nist.gov/vuln/detail/CVE-2024-56326) | CVE-2024-56326 | 3.1.5 | flask-2-2-2 > flask > jinja2 |
| high | urllib3 | 1.26.14 | [GHSA-2xpw-w6gg-jr37](https://nvd.nist.gov/vuln/detail/CVE-2025-66471) | CVE-2025-66471 | 2.6.0 | flask-2-2-2 > requests > urllib3 |
| high (7.5) | urllib3 | 1.26.14 | [GHSA-38jv-5279-wg99](https://nvd.nist.gov/vuln/detail/CVE-2026-21441) | CVE-2026-21441 | 2.6.3 | flask-2-2-2 > requests > urllib3 |
| high | urllib3 | 1.26.14 | [GHSA-8988-9cw3-xx77](https://nvd.nist.gov/vuln/detail/CVE-2026-97687) | CVE-2026-97687 | 2.8.0 | flask-2-2-2 > requests > urllib3 |
| high | urllib3 | 1.26.14 | [GHSA-gm62-xv2j-4w53](https://nvd.nist.gov/vuln/detail/CVE-2025-66418) | CVE-2025-66418 | 2.6.0 | flask-2-2-2 > requests > urllib3 |
| high | urllib3 | 1.26.14 | [GHSA-vxq7-64xx-v4gw](https://nvd.nist.gov/vuln/detail/CVE-2026-97689) | CVE-2026-97689 | 2.8.0 | flask-2-2-2 > requests > urllib3 |
| high (8.1) | urllib3 | 1.26.14 | [PYSEC-2023-192](https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f) | CVE-2023-43804 | 1.26.17 | flask-2-2-2 > requests > urllib3 |
| high (7.5) | urllib3 | 1.26.14 | [PYSEC-2026-1996](https://nvd.nist.gov/vuln/detail/CVE-2026-21441) | CVE-2026-21441 | 2.6.3 | flask-2-2-2 > requests > urllib3 |
| high (7.5) | werkzeug | 2.2.2 | [GHSA-2g68-c3qc-8985](https://nvd.nist.gov/vuln/detail/CVE-2024-34069) | CVE-2024-34069 | 3.0.3 | flask-2-2-2 > flask > werkzeug |
| high (7.5) | werkzeug | 2.2.2 | [GHSA-q34m-jh98-gwm2](https://nvd.nist.gov/vuln/detail/CVE-2024-49767) | CVE-2024-49767 | 3.0.6 | flask-2-2-2 > flask > werkzeug |
| high (7.5) | werkzeug | 2.2.2 | [GHSA-xg9f-g7g7-2323](https://nvd.nist.gov/vuln/detail/CVE-2023-25577) | CVE-2023-25577 | 2.2.3 | flask-2-2-2 > flask > werkzeug |
| high (7.5) | werkzeug | 2.2.2 | [PYSEC-2023-221](https://github.com/pallets/werkzeug/security/advisories/GHSA-hrfv-mqp8-q5rw) | CVE-2023-46136 | 2.3.8 | flask-2-2-2 > flask > werkzeug |
| high (7.5) | werkzeug | 2.2.2 | [PYSEC-2026-2043](https://nvd.nist.gov/vuln/detail/CVE-2024-34069) | CVE-2024-34069 | 3.0.3 | flask-2-2-2 > flask > werkzeug |
| high (7.5) | werkzeug | 2.2.2 | [PYSEC-2026-3417](https://nvd.nist.gov/vuln/detail/CVE-2024-49767) | CVE-2024-49767 | 3.0.6 | flask-2-2-2 > flask > werkzeug |
| medium (4.3) | flask | 2.2.2 | [PYSEC-2026-2151](https://github.com/pallets/flask/releases/tag/3.1.3) | CVE-2026-27205 | 3.1.3 | direct |
| medium (5.3) | idna | 3.4 | [GHSA-65pc-fj4g-8rjx](https://nvd.nist.gov/vuln/detail/CVE-2026-45409) | CVE-2026-45409 | 3.15 | flask-2-2-2 > requests > idna |
| medium (6.2) | idna | 3.4 | [GHSA-jjg7-2v4v-x38h](https://nvd.nist.gov/vuln/detail/CVE-2024-3651) | CVE-2024-3651 | 3.7 | flask-2-2-2 > requests > idna |
| medium (5.3) | idna | 3.4 | [PYSEC-2026-215](https://github.com/kjd/idna/security/advisories/GHSA-65pc-fj4g-8rjx) | CVE-2026-45409 | 3.15 | flask-2-2-2 > requests > idna |
| medium | jinja2 | 3.1.2 | [GHSA-cpwx-vrp4-4pq7](https://nvd.nist.gov/vuln/detail/CVE-2025-27516) | CVE-2025-27516 | 3.1.6 | flask-2-2-2 > flask > jinja2 |
| medium (5.4) | jinja2 | 3.1.2 | [GHSA-h5c8-rqwp-cp95](https://nvd.nist.gov/vuln/detail/CVE-2024-22195) | CVE-2024-22195 | 3.1.3 | flask-2-2-2 > flask > jinja2 |
| medium (5.4) | jinja2 | 3.1.2 | [GHSA-h75v-3vvj-5mfj](https://nvd.nist.gov/vuln/detail/CVE-2024-34064) | CVE-2024-34064 | 3.1.4 | flask-2-2-2 > flask > jinja2 |
| medium (5.4) | jinja2 | 3.1.2 | [PYSEC-2026-1473](https://nvd.nist.gov/vuln/detail/CVE-2024-22195) | CVE-2024-22195 | 3.1.3 | flask-2-2-2 > flask > jinja2 |
| medium (5.4) | jinja2 | 3.1.2 | [PYSEC-2026-1474](https://nvd.nist.gov/vuln/detail/CVE-2024-34064) | CVE-2024-34064 | 3.1.4 | flask-2-2-2 > flask > jinja2 |
| medium (5.3) | requests | 2.28.1 | [GHSA-9hjg-9r4m-mvj7](https://nvd.nist.gov/vuln/detail/CVE-2024-47081) | CVE-2024-47081 | 2.32.4 | direct |
| medium (5.6) | requests | 2.28.1 | [GHSA-9wx4-h78v-vm56](https://nvd.nist.gov/vuln/detail/CVE-2024-35195) | CVE-2024-35195 | 2.32.0 | direct |
| medium (4.4) | requests | 2.28.1 | [GHSA-gc5v-m9x4-r6x2](https://nvd.nist.gov/vuln/detail/CVE-2026-25645) | CVE-2026-25645 | 2.33.0 | direct |
| medium (6.1) | requests | 2.28.1 | [GHSA-j8r2-6x86-q33q](https://nvd.nist.gov/vuln/detail/CVE-2023-32681) | CVE-2023-32681 | 2.31.0 | direct |
| medium (5.3) | requests | 2.28.1 | [PYSEC-2026-1872](https://nvd.nist.gov/vuln/detail/CVE-2024-47081) | CVE-2024-47081 | 2.32.4 | direct |
| medium (5.6) | requests | 2.28.1 | [PYSEC-2026-1873](https://nvd.nist.gov/vuln/detail/CVE-2024-35195) | CVE-2024-35195 | 2.32.0 | direct |
| medium (5.5) | requests | 2.28.1 | [PYSEC-2026-2275](https://github.com/psf/requests/releases/tag/v2.33.0) | CVE-2026-25645 | 2.33.0 | direct |
| medium (4.4) | urllib3 | 1.26.14 | [GHSA-34jh-p97f-mpxf](https://nvd.nist.gov/vuln/detail/CVE-2024-37891) | CVE-2024-37891 | 1.26.19 | flask-2-2-2 > requests > urllib3 |
| medium (4.2) | urllib3 | 1.26.14 | [GHSA-g4mx-q9vg-27p4](https://nvd.nist.gov/vuln/detail/CVE-2023-45803) | CVE-2023-45803 | 1.26.18 | flask-2-2-2 > requests > urllib3 |
| medium (5.3) | urllib3 | 1.26.14 | [GHSA-pq67-6m6q-mj2v](https://nvd.nist.gov/vuln/detail/CVE-2025-50181) | CVE-2025-50181 | 2.5.0 | flask-2-2-2 > requests > urllib3 |
| medium (5.3) | urllib3 | 1.26.14 | [GHSA-qccp-gfcp-xxvc](https://nvd.nist.gov/vuln/detail/CVE-2026-44431) | CVE-2026-44431 | 2.7.0 | flask-2-2-2 > requests > urllib3 |
| medium (5.9) | urllib3 | 1.26.14 | [GHSA-v845-jxx5-vc9f](https://nvd.nist.gov/vuln/detail/CVE-2023-43804) | CVE-2023-43804 | 1.26.17 | flask-2-2-2 > requests > urllib3 |
| medium (4.2) | urllib3 | 1.26.14 | [PYSEC-2023-212](https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4) | CVE-2023-45803 | 1.26.18 | flask-2-2-2 > requests > urllib3 |
| medium (5.3) | urllib3 | 1.26.14 | [PYSEC-2026-141](https://github.com/urllib3/urllib3/security/advisories/GHSA-qccp-gfcp-xxvc) | CVE-2026-44431 | 2.7.0 | flask-2-2-2 > requests > urllib3 |
| medium (4.4) | urllib3 | 1.26.14 | [PYSEC-2026-1995](https://nvd.nist.gov/vuln/detail/CVE-2024-37891) | CVE-2024-37891 | 1.26.19 | flask-2-2-2 > requests > urllib3 |
| medium (5.3) | urllib3 | 1.26.14 | [PYSEC-2026-1999](https://nvd.nist.gov/vuln/detail/CVE-2025-50181) | CVE-2025-50181 | 2.5.0 | flask-2-2-2 > requests > urllib3 |
| medium | werkzeug | 2.2.2 | [GHSA-29vq-49wr-vm6x](https://nvd.nist.gov/vuln/detail/CVE-2026-27199) | CVE-2026-27199 | 3.1.6 | flask-2-2-2 > flask > werkzeug |
| medium (5.3) | werkzeug | 2.2.2 | [GHSA-87hc-h4r5-73f7](https://nvd.nist.gov/vuln/detail/CVE-2026-21860) | CVE-2026-21860 | 3.1.5 | flask-2-2-2 > flask > werkzeug |
| medium | werkzeug | 2.2.2 | [GHSA-f9vj-2wh5-fj8j](https://nvd.nist.gov/vuln/detail/CVE-2024-49766) | CVE-2024-49766 | 3.0.6 | flask-2-2-2 > flask > werkzeug |
| medium | werkzeug | 2.2.2 | [GHSA-g6x2-hccm-hh4m](https://nvd.nist.gov/vuln/detail/CVE-2026-102598) | CVE-2026-102598 | 3.1.9 | flask-2-2-2 > flask > werkzeug |
| medium | werkzeug | 2.2.2 | [GHSA-hgf8-39gv-g3f2](https://nvd.nist.gov/vuln/detail/CVE-2025-66221) | CVE-2025-66221 | 3.1.4 | flask-2-2-2 > flask > werkzeug |
| medium (5.7) | werkzeug | 2.2.2 | [GHSA-hrfv-mqp8-q5rw](https://nvd.nist.gov/vuln/detail/CVE-2023-46136) | CVE-2023-46136 | 2.3.8 | flask-2-2-2 > flask > werkzeug |
| medium (5.3) | werkzeug | 2.2.2 | [PYSEC-2026-2044](https://nvd.nist.gov/vuln/detail/CVE-2026-21860) | CVE-2026-21860 | 3.1.5 | flask-2-2-2 > flask > werkzeug |
| medium (5.3) | werkzeug | 2.2.2 | [PYSEC-2026-2320](https://github.com/pallets/werkzeug/releases/tag/3.1.6) | CVE-2026-27199 | 3.1.6 | flask-2-2-2 > flask > werkzeug |
| low | certifi | 2022.12.7 | [GHSA-248v-346w-9cwc](https://nvd.nist.gov/vuln/detail/CVE-2024-39689) | CVE-2024-39689 | 2024.7.4 | flask-2-2-2 > requests > certifi |
| low | flask | 2.2.2 | [GHSA-68rp-wp8r-4726](https://nvd.nist.gov/vuln/detail/CVE-2026-27205) | CVE-2026-27205 | 3.1.3 | direct |
| low (2.6) | werkzeug | 2.2.2 | [GHSA-px8h-6qxv-m22q](https://nvd.nist.gov/vuln/detail/CVE-2023-23934) | CVE-2023-23934 | 2.2.3 | flask-2-2-2 > flask > werkzeug |
| unknown | certifi | 2022.12.7 | [PYSEC-2023-135](https://nvd.nist.gov/vuln/detail/CVE-2023-37920) | CVE-2023-37920 | 2023.7.22 | flask-2-2-2 > requests > certifi |
| unknown | certifi | 2022.12.7 | [PYSEC-2026-4320](https://github.com/advisories/GHSA-6q48-6c7w-9gw2) |  | 2026.10.19 | flask-2-2-2 > requests > certifi |
| unknown | flask | 2.2.2 | [PYSEC-2023-62](https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq) | CVE-2023-30861 | 2.2.5 | direct |
| unknown | jinja2 | 3.1.2 | [PYSEC-2026-1471](https://nvd.nist.gov/vuln/detail/CVE-2025-27516) | CVE-2025-27516 | 3.1.6 | flask-2-2-2 > flask > jinja2 |
| unknown | requests | 2.28.1 | [PYSEC-2023-74](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q) | CVE-2023-32681 | 2.31.0 | direct |
| unknown | urllib3 | 1.26.14 | [PYSEC-2026-1994](https://nvd.nist.gov/vuln/detail/CVE-2025-66471) | CVE-2025-66471 | 2.6.0 | flask-2-2-2 > requests > urllib3 |
| unknown | urllib3 | 1.26.14 | [PYSEC-2026-1998](https://nvd.nist.gov/vuln/detail/CVE-2025-66418) | CVE-2025-66418 | 2.6.0 | flask-2-2-2 > requests > urllib3 |
| unknown | urllib3 | 1.26.14 | [PYSEC-2026-4175](https://nvd.nist.gov/vuln/detail/CVE-2026-97687) | CVE-2026-97687 | 2.8.0 | flask-2-2-2 > requests > urllib3 |
| unknown | urllib3 | 1.26.14 | [PYSEC-2026-4177](https://nvd.nist.gov/vuln/detail/CVE-2026-97689) | CVE-2026-97689 | 2.8.0 | flask-2-2-2 > requests > urllib3 |
| unknown | werkzeug | 2.2.2 | [PYSEC-2023-57](https://github.com/pallets/werkzeug/security/advisories/GHSA-px8h-6qxv-m22q) | CVE-2023-23934 | 2.2.3 | flask-2-2-2 > flask > werkzeug |
| unknown | werkzeug | 2.2.2 | [PYSEC-2023-58](https://github.com/pallets/werkzeug/security/advisories/GHSA-xg9f-g7g7-2323) | CVE-2023-25577 | 2.2.3 | flask-2-2-2 > flask > werkzeug |
| unknown | werkzeug | 2.2.2 | [PYSEC-2026-2045](https://nvd.nist.gov/vuln/detail/CVE-2024-49766) | CVE-2024-49766 | 3.0.6 | flask-2-2-2 > flask > werkzeug |
| unknown | werkzeug | 2.2.2 | [PYSEC-2026-2046](https://nvd.nist.gov/vuln/detail/CVE-2025-66221) | CVE-2025-66221 | 3.1.4 | flask-2-2-2 > flask > werkzeug |
| unknown | werkzeug | 2.2.2 | [PYSEC-2026-4312](https://nvd.nist.gov/vuln/detail/CVE-2026-102598) | CVE-2026-102598 | 3.1.9 | flask-2-2-2 > flask > werkzeug |
