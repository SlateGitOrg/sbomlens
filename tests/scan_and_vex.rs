//! End-to-end matching and VEX behaviour on the bundled fixtures.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use sbomlens::cvss::Severity;
use sbomlens::osv::{scan, MatchReason, OsvDatabase};
use sbomlens::report::{self, ScanReport};
use sbomlens::vex::{self, VexDocument, VexStatus};

/// Regression gate for the agreement eval: every (purl, advisory) pair that
/// api.osv.dev reported at fetch time is found, and nothing else.
#[test]
fn matches_agree_with_osv_dev_on_every_fixture() {
    let db = osv();
    let expected: BTreeMap<String, BTreeSet<String>> =
        serde_json::from_str(&std::fs::read_to_string(path("fixtures/osv/expected-matches.json")).unwrap()).unwrap();
    for f in [EXPRESS_OLD_CDX, EXPRESS_OLD_SPDX, EXPRESS_NEW_CDX, EXPRESS_NEW_SPDX, FLASK_CDX, POLYGLOT_CDX] {
        let g = sbom(f);
        let r = scan(&g, &db);
        let ours: BTreeSet<(String, String)> = r.findings.iter().map(|x| (x.purl.clone(), x.id.clone())).collect();
        let truth: BTreeSet<(String, String)> = g
            .components
            .iter()
            .filter_map(|c| c.purl.as_ref())
            .flat_map(|p| {
                expected
                    .get(&p.to_string())
                    .into_iter()
                    .flatten()
                    .map(move |id| (p.to_string(), id.clone()))
            })
            .collect();
        assert_eq!(ours, truth, "{f}");
    }
}

#[test]
fn express_findings_explain_themselves() {
    let r = scan(&sbom(EXPRESS_OLD_CDX), &osv());
    let qs = r.findings.iter().find(|f| f.id == "GHSA-hrpp-h998-j3pp").unwrap();
    assert_eq!(qs.package, "qs");
    assert_eq!(qs.fixed_in.as_deref(), Some("6.7.3"));
    assert!(!qs.direct);
    assert_eq!(qs.path.last().map(String::as_str), Some("qs"));
    assert!(matches!(&qs.reason, MatchReason::Range { range_type, .. } if range_type == "SEMVER"));
    let ex = r.findings.iter().find(|f| f.id == "GHSA-rv95-896h-c2vc").unwrap();
    assert!(ex.direct);
    // Findings are sorted most severe first.
    let levels: Vec<Severity> = r.findings.iter().map(|f| f.severity.level).collect();
    assert!(levels.windows(2).all(|w| w[0] >= w[1]));
    assert_eq!(r.stats.checked, 51);
    assert!(r.skipped.is_empty());
}

#[test]
fn go_pseudo_version_and_maven_matching() {
    let r = scan(&sbom(POLYGLOT_CDX), &osv());
    let net: Vec<_> = r.findings.iter().filter(|f| f.package == "golang.org/x/net").collect();
    assert_eq!(net.len(), 39);
    let log4shell = r.findings.iter().find(|f| f.id == "GHSA-jfh8-c2jp-5v3q").unwrap();
    assert_eq!(log4shell.severity.level, Severity::Critical);
    assert_eq!(log4shell.severity.score, Some(10.0));
    assert_eq!(log4shell.fixed_in.as_deref(), Some("2.15.0"));
    assert_eq!(log4shell.path, ["polyglot-gateway", "com.example.gateway:billing-api", "org.apache.logging.log4j:log4j-core"]);
    // commons-text 1.10.0 is the fixed version of Text4Shell: no finding.
    assert!(!r.findings.iter().any(|f| f.package == "org.apache.commons:commons-text"));
    assert!(r.distinct_vulnerabilities() < r.findings.len());
}

#[test]
fn vex_suppresses_annotates_and_reports_hygiene() {
    let g = sbom(EXPRESS_OLD_SPDX);
    let mut r = scan(&g, &osv());
    let before = r.findings.len();
    let doc = VexDocument::load(&path(EXPRESS_VEX)).unwrap();
    assert_eq!(doc.statements.len(), 5);
    let rep = vex::apply(&mut r, &g, &[doc]);
    assert_eq!(r.findings.len(), before, "VEX never drops findings");
    let status = |id: &str| r.findings.iter().find(|f| f.id == id).and_then(|f| f.vex.as_ref()).map(|v| v.status);
    // CVE-2024-45296 is an alias of both path-to-regexp advisories.
    assert_eq!(status("GHSA-9wv6-86v2-598j"), Some(VexStatus::NotAffected));
    assert_eq!(status("GHSA-37ch-88jc-xwx2"), Some(VexStatus::NotAffected));
    // Subcomponent scoping: the third path-to-regexp advisory has a different CVE.
    assert_eq!(status("GHSA-rhx6-c78j-4q9w"), None);
    // Versionless product purl matches qs@6.7.0.
    assert_eq!(status("GHSA-hrpp-h998-j3pp"), Some(VexStatus::Affected));
    // Later statement (not_affected, 10-23) beats the earlier under_investigation (10-20).
    assert_eq!(status("GHSA-pxg6-pf52-xh8x"), Some(VexStatus::NotAffected));
    // The send statement is invalid (no justification) and was ignored.
    assert_eq!(status("GHSA-m6fv-jmcg-4jfg"), None);
    assert_eq!(rep.applied.get("not_affected"), Some(&3));
    assert_eq!(rep.applied.get("affected"), Some(&1));
    // Only the log4j statement matched nothing; the superseded under_investigation
    // statement did match (and lost on timestamp).
    assert_eq!(rep.unused, ["https://example.invalid/vex/express-4.17.1-closure#4"]);
    assert_eq!(rep.warnings.len(), 1);
    assert_eq!(r.active().count(), before - 3);
}

#[test]
fn vex_later_document_wins_ties() {
    let g = sbom(EXPRESS_OLD_CDX);
    let mut r = scan(&g, &osv());
    let mk = |status: &str, extra: &str| {
        VexDocument::parse(
            &format!(
                r#"{{"@context": "https://openvex.dev/ns/v0.2.0", "timestamp": "2026-01-01T00:00:00Z",
                    "statements": [{{"vulnerability": {{"name": "CVE-2024-43799"}},
                    "products": [{{"@id": "pkg:npm/send@0.17.1"}}], "status": "{status}"{extra}}}]}}"#
            ),
            status,
        )
        .unwrap()
    };
    let docs = [mk("fixed", ""), mk("affected", r#", "action_statement": "upgrade""#)];
    vex::apply(&mut r, &g, &docs);
    let send = r.findings.iter().find(|f| f.package == "send").unwrap();
    assert_eq!(send.vex.as_ref().unwrap().status, VexStatus::Affected);
    assert!(!send.is_suppressed());
}

#[test]
fn sarif_log_structure() {
    let g = sbom(EXPRESS_OLD_SPDX);
    let db = osv();
    let mut r = scan(&g, &db);
    let rep = vex::apply(&mut r, &g, &[VexDocument::load(&path(EXPRESS_VEX)).unwrap()]);
    let report = ScanReport::new("sbom.spdx.json", &g, db.stats.clone(), r, Some(rep));
    let log: serde_json::Value = serde_json::from_str(&report::sarif::scan(&report)).unwrap();
    assert_eq!(log["version"], "2.1.0");
    let run = &log["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 16);
    let ids: BTreeSet<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), rules.len(), "one rule per advisory");
    for res in results {
        let idx = usize::try_from(res["ruleIndex"].as_u64().unwrap()).unwrap();
        assert_eq!(rules[idx]["id"], res["ruleId"]);
        assert_eq!(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "sbom.spdx.json");
        assert!(res["partialFingerprints"]["sbomlensFinding/v1"].as_str().unwrap().len() == 16);
        assert!(["error", "warning", "note"].contains(&res["level"].as_str().unwrap()));
    }
    let suppressed = results.iter().filter(|r| r.get("suppressions").is_some()).count();
    assert_eq!(suppressed, 3);
    assert!(rules.iter().all(|r| r["properties"]["security-severity"].is_string()));
}

#[test]
fn markdown_and_json_reports() {
    let g = sbom(POLYGLOT_CDX);
    let db = osv();
    let r = scan(&g, &db);
    let report = ScanReport::new("poly.json", &g, db.stats.clone(), r, None);
    let md = report::markdown::scan(&report);
    assert!(md.contains("| critical (10.0) | org.apache.logging.log4j:log4j-core | 2.14.1 |"));
    assert!(md.contains("polyglot-gateway > com.example.gateway:billing-api > org.apache.logging.log4j:log4j-core"));
    let json: serde_json::Value = serde_json::from_str(&report::to_json(&report)).unwrap();
    assert_eq!(json["scan"]["findings"].as_array().unwrap().len(), 90);
    assert_eq!(report.max_active_severity(), Some(Severity::Critical));
    assert_eq!(report.severity_counts().iter().map(|(_, n)| n).sum::<usize>(), 90);
}

#[test]
fn unsupported_inputs_are_counted_not_guessed() {
    let doc = r#"{"bomFormat": "CycloneDX", "specVersion": "1.6",
      "components": [
        {"bom-ref": "a", "name": "nopurl", "version": "1.0"},
        {"bom-ref": "b", "name": "curl", "purl": "pkg:deb/debian/curl@7.50.3-1"},
        {"bom-ref": "c", "name": "noversion", "purl": "pkg:npm/qs"},
        {"bom-ref": "d", "name": "badversion", "purl": "pkg:npm/qs@not-a-version"}
      ]}"#;
    let g = sbomlens::sbom::parse_str(doc, "inline").unwrap();
    let r = scan(&g, &osv());
    assert!(r.findings.is_empty());
    assert_eq!(r.stats.without_purl, 1);
    assert_eq!(r.stats.unsupported_ecosystem, 1);
    assert_eq!(r.stats.without_version, 1);
    assert_eq!(r.stats.version_errors, 1);
    assert_eq!(r.stats.checked, 1);
    assert_eq!(r.skipped.len(), 2);
    let empty = OsvDatabase::from_vulns(Vec::new());
    assert!(scan(&g, &empty).findings.is_empty());
}
