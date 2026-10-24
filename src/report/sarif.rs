//! SARIF 2.1.0 output.
//!
//! One rule per advisory, one result per (component, advisory). Results
//! point at the SBOM file (physical location, line 1, since SBOM JSON has no
//! meaningful line for a component) and name the component purl as a
//! logical location. Rules carry `security-severity` (the CVSS score, or a
//! representative score for a qualitative label) so code-scanning UIs rank
//! them. VEX `not_affected`/`fixed` findings are emitted with an external,
//! accepted suppression rather than dropped, keeping the audit trail.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{json, Value};

use super::ScanReport;
use crate::cvss::Severity;
use crate::osv::Finding;

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::None | Severity::Unknown => "note",
    }
}

/// Representative numeric score for a qualitative label (GitHub's buckets).
fn security_severity(f: &Finding) -> Option<String> {
    if let Some(s) = f.severity.score {
        return Some(format!("{s:.1}"));
    }
    match f.severity.level {
        Severity::Critical => Some("9.5".into()),
        Severity::High => Some("8.0".into()),
        Severity::Medium => Some("5.5".into()),
        Severity::Low => Some("2.0".into()),
        Severity::None | Severity::Unknown => None,
    }
}

/// 64-bit FNV-1a, used for stable result fingerprints.
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn rule(f: &Finding) -> Value {
    let summary = f
        .summary
        .clone()
        .unwrap_or_else(|| format!("Vulnerability {}", f.id));
    let mut help = format!(
        "{summary}\n\nAliases: {}",
        if f.aliases.is_empty() {
            "-".to_string()
        } else {
            f.aliases.join(", ")
        }
    );
    if let Some(u) = &f.url {
        let _ = write!(help, "\nAdvisory: {u}");
    }
    let mut props = json!({
        "tags": ["security", "vulnerability", "dependency"],
        "severity": f.severity.level.to_string(),
    });
    if let Some(s) = security_severity(f) {
        props["security-severity"] = Value::String(s);
    }
    if let Some(v) = &f.severity.vector {
        props["cvssVector"] = Value::String(v.clone());
    }
    let mut r = json!({
        "id": f.id,
        "name": f.id.replace('-', ""),
        "shortDescription": {"text": summary},
        "fullDescription": {"text": summary},
        "help": {"text": help.clone(), "markdown": help},
        "defaultConfiguration": {"level": level(f.severity.level)},
        "properties": props,
    });
    if let Some(u) = &f.url {
        r["helpUri"] = Value::String(u.clone());
    }
    r
}

fn result(f: &Finding, rule_index: usize, artifact: &str) -> Value {
    let mut msg = format!("{}@{} is affected by {}", f.package, f.version, f.id);
    if let Some(s) = &f.summary {
        let _ = write!(msg, ": {s}");
    }
    match &f.fixed_in {
        Some(v) => {
            let _ = write!(msg, ". Fixed in {v}");
        }
        None => msg.push_str(". No fixed version is recorded"),
    }
    if !f.direct && f.path.len() > 1 {
        let _ = write!(msg, ". Introduced via {}", f.path.join(" > "));
    }
    msg.push('.');
    let mut props = json!({
        "purl": f.purl,
        "package": f.package,
        "version": f.version,
        "direct": f.direct,
        "dependencyPath": f.path,
    });
    if let Some(v) = &f.fixed_in {
        props["fixedIn"] = Value::String(v.clone());
    }
    let mut res = json!({
        "ruleId": f.id,
        "ruleIndex": rule_index,
        "level": level(f.severity.level),
        "message": {"text": msg},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": artifact},
                "region": {"startLine": 1}
            },
            "logicalLocations": [{"fullyQualifiedName": f.purl, "kind": "package"}]
        }],
        "partialFingerprints": {"sbomlensFinding/v1": format!("{:016x}", fnv1a(&format!("{}|{}", f.purl, f.id)))},
        "properties": props,
    });
    if let Some(v) = &f.vex {
        res["properties"]["vexStatus"] = Value::String(v.status.as_str().into());
        if v.suppresses() {
            let why = v
                .justification
                .clone()
                .or_else(|| v.impact_statement.clone())
                .unwrap_or_else(|| v.status.as_str().to_string());
            res["suppressions"] = json!([{
                "kind": "external",
                "status": "accepted",
                "justification": format!("OpenVEX {}: {why} ({})", v.status.as_str(), v.statement),
            }]);
        }
    }
    res
}

/// Renders a scan report as a SARIF 2.1.0 log.
pub fn scan(r: &ScanReport) -> String {
    let artifact = r.sbom.replace('\\', "/");
    let mut rule_index: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rules = Vec::new();
    for f in &r.scan.findings {
        if !rule_index.contains_key(f.id.as_str()) {
            rule_index.insert(&f.id, rules.len());
            rules.push(rule(f));
        }
    }
    let results: Vec<Value> = r
        .scan
        .findings
        .iter()
        .map(|f| result(f, rule_index[f.id.as_str()], &artifact))
        .collect();
    let log = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "sbomlens",
                "version": r.tool_version,
                "semanticVersion": r.tool_version,
                "rules": rules,
            }},
            "artifacts": [{"location": {"uri": artifact}, "description": {"text": format!("{} SBOM", r.sbom_format)}}],
            "results": results,
            "properties": {
                "componentsChecked": r.scan.stats.checked,
                "components": r.scan.stats.components,
                "osvRecords": r.database.records,
            },
        }],
    });
    let mut s = serde_json::to_string_pretty(&log).expect("SARIF values serialize infallibly");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_is_stable() {
        assert_eq!(fnv1a(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a("a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn levels() {
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Unknown), "note");
    }
}
