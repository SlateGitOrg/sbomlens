//! Runs the official purl-spec test suite (`test-suite-data.json`, pinned to
//! purl-spec commit 3bcba88a651ee9a681620391b869d26d0a6d6dc2, MIT license)
//! against the parser and canonical formatter.

use std::collections::BTreeMap;

use sbomlens::purl::Purl;
use serde_json::Value;

const SUITE: &str = include_str!("data/purl-spec-test-suite-data.json");

fn opt(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

#[test]
fn purl_spec_test_suite() {
    let cases: Vec<Value> = serde_json::from_str(SUITE).unwrap();
    assert_eq!(cases.len(), 59);
    let mut failures = Vec::new();
    for case in &cases {
        let desc = case["description"].as_str().unwrap();
        let input = case["purl"].as_str().unwrap();
        let invalid = case["is_invalid"].as_bool().unwrap();
        match (Purl::parse(input), invalid) {
            (Err(_), true) => {}
            (Ok(p), true) => failures.push(format!("{desc}: accepted invalid {input} as {p}")),
            (Err(e), false) => failures.push(format!("{desc}: rejected {input}: {e}")),
            (Ok(p), false) => {
                let canonical = case["canonical_purl"].as_str().unwrap();
                if p.to_string() != canonical {
                    failures.push(format!("{desc}: canonical {p} != {canonical}"));
                }
                // The canonical form must itself parse back to the same value.
                if Purl::parse(canonical).as_ref() != Ok(&p) {
                    failures.push(format!("{desc}: canonical form does not round-trip"));
                }
                // Field checks. The suite's two "subpath cannot contain '.'/'..'"
                // cases record the *pre-normalization* subpath in their fields
                // while their canonical form drops the segment; we normalize at
                // parse time, so only the canonical form is checked for them.
                if desc.contains("subpath cannot contain") {
                    continue;
                }
                let expect_q: BTreeMap<String, String> = case["qualifiers"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let checks = [
                    ("type", Some(p.ty.clone()), opt(&case["type"])),
                    ("namespace", p.namespace.clone(), opt(&case["namespace"])),
                    ("name", Some(p.name.clone()), opt(&case["name"])),
                    ("version", p.version.clone(), opt(&case["version"])),
                    ("subpath", p.subpath.clone(), opt(&case["subpath"])),
                ];
                for (field, got, want) in checks {
                    if got != want {
                        failures.push(format!("{desc}: {field} {got:?} != {want:?}"));
                    }
                }
                if p.qualifiers != expect_q {
                    failures.push(format!(
                        "{desc}: qualifiers {:?} != {expect_q:?}",
                        p.qualifiers
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
