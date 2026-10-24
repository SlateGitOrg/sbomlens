//! OpenVEX: parsing documents and applying their statements to findings.
//!
//! Supports OpenVEX v0.2.0 (object-shaped `vulnerability` / `products` /
//! `subcomponents`) and the string-shaped v0.0.1 forms.
//!
//! A statement applies to a finding when
//! 1. its vulnerability name, `@id` or aliases intersect the finding's
//!    advisory id and aliases (case-insensitive), and
//! 2. a product identifier matches the vulnerable component itself, or a
//!    product matches a component on the dependency path to it (typically the
//!    SBOM root) and either no subcomponents are listed or one of them matches
//!    the vulnerable component.
//!
//! Identifiers that are purls match by package identity; a product purl
//! without a version matches every version, and qualifiers on the statement
//! must be present on the component. Other identifiers match the component's
//! source reference (`bom-ref` / `SPDXID`) exactly. When several statements
//! apply, the one with the latest timestamp wins (statement timestamp, else
//! the document's); ties go to the statement given last.
//!
//! Invalid statements (unknown status, `not_affected` without a
//! justification or impact statement, unknown justification) are ignored and
//! reported as warnings rather than silently suppressing findings.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::graph::SbomGraph;
use crate::osv::ScanResult;
use crate::purl::Purl;
use crate::version::Version;

/// VEX status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    /// The product is not affected.
    NotAffected,
    /// The product is affected.
    Affected,
    /// The product contains a fix.
    Fixed,
    /// Not yet known.
    UnderInvestigation,
}

impl VexStatus {
    fn parse(s: &str) -> Option<VexStatus> {
        match s {
            "not_affected" => Some(VexStatus::NotAffected),
            "affected" => Some(VexStatus::Affected),
            "fixed" => Some(VexStatus::Fixed),
            "under_investigation" => Some(VexStatus::UnderInvestigation),
            _ => None,
        }
    }

    /// The OpenVEX spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            VexStatus::NotAffected => "not_affected",
            VexStatus::Affected => "affected",
            VexStatus::Fixed => "fixed",
            VexStatus::UnderInvestigation => "under_investigation",
        }
    }
}

const JUSTIFICATIONS: [&str; 5] = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
];

/// One validated statement.
#[derive(Debug, Clone)]
pub struct Statement {
    /// Vulnerability identifiers (name, `@id`, aliases), lower-cased.
    pub vuln_ids: Vec<String>,
    /// Product identifiers, each with its subcomponent identifiers.
    pub products: Vec<(String, Vec<String>)>,
    /// Status.
    pub status: VexStatus,
    /// Justification (for `not_affected`).
    pub justification: Option<String>,
    /// Impact statement.
    pub impact_statement: Option<String>,
    /// Action statement (for `affected`).
    pub action_statement: Option<String>,
    /// Effective timestamp (UTC nanoseconds since the epoch), if known.
    pub timestamp: Option<i128>,
    /// `<document id>#<statement index>`.
    pub reference: String,
}

/// A parsed OpenVEX document.
#[derive(Debug, Clone)]
pub struct VexDocument {
    /// Document `@id`, or the source name.
    pub id: String,
    /// Valid statements.
    pub statements: Vec<Statement>,
    /// Problems found while validating.
    pub warnings: Vec<String>,
}

/// The decision attached to a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VexOutcome {
    /// Status.
    pub status: VexStatus,
    /// Justification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// Impact statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_statement: Option<String>,
    /// Action statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_statement: Option<String>,
    /// Which statement decided.
    pub statement: String,
}

impl VexOutcome {
    /// `not_affected` and `fixed` remove the finding from the active set.
    pub fn suppresses(&self) -> bool {
        matches!(self.status, VexStatus::NotAffected | VexStatus::Fixed)
    }
}

/// Summary of applying VEX documents to a scan.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VexReport {
    /// Findings decided, per status.
    pub applied: BTreeMap<String, usize>,
    /// Statements that matched no finding.
    pub unused: Vec<String>,
    /// Validation warnings from all documents.
    pub warnings: Vec<String>,
}

fn str_field(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Identifiers of a product/subcomponent: a bare string, or an object with
/// `@id` and/or `identifiers.purl`.
fn identifiers(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Object(_) => {
            let mut out = Vec::new();
            if let Some(id) = str_field(v, "@id") {
                out.push(id);
            }
            if let Some(ids) = v.get("identifiers") {
                for k in ["purl", "cpe23", "cpe22"] {
                    if let Some(p) = str_field(ids, k) {
                        out.push(p);
                    }
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

impl VexDocument {
    /// Parses and validates an OpenVEX JSON document.
    pub fn parse(text: &str, what: &str) -> Result<VexDocument> {
        let v: Value = serde_json::from_str(text).map_err(|e| Error::json(what, e))?;
        let context = str_field(&v, "@context").unwrap_or_default();
        if !context.starts_with("https://openvex.dev/ns") {
            return Err(Error::invalid(
                what,
                "not an OpenVEX document (missing openvex @context)",
            ));
        }
        let id = str_field(&v, "@id").unwrap_or_else(|| what.to_string());
        let doc_ts = str_field(&v, "timestamp").and_then(|t| parse_rfc3339(&t));
        let statements = v
            .get("statements")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::invalid(what, "OpenVEX document has no statements array"))?;
        let mut doc = VexDocument {
            id: id.clone(),
            statements: Vec::new(),
            warnings: Vec::new(),
        };
        for (i, s) in statements.iter().enumerate() {
            let reference = format!("{id}#{i}");
            match parse_statement(s, reference.clone(), doc_ts) {
                Ok((st, warn)) => {
                    if let Some(w) = warn {
                        doc.warnings.push(format!("{reference}: {w}"));
                    }
                    doc.statements.push(st);
                }
                Err(w) => doc.warnings.push(format!("{reference}: ignored: {w}")),
            }
        }
        Ok(doc)
    }

    /// Reads and parses a file.
    pub fn load(path: &std::path::Path) -> Result<VexDocument> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        VexDocument::parse(&text, &path.display().to_string())
    }
}

fn parse_statement(
    s: &Value,
    reference: String,
    doc_ts: Option<i128>,
) -> std::result::Result<(Statement, Option<String>), String> {
    let mut vuln_ids = Vec::new();
    match s.get("vulnerability") {
        Some(Value::String(name)) => vuln_ids.push(name.to_ascii_lowercase()),
        Some(v @ Value::Object(_)) => {
            vuln_ids.extend(str_field(v, "name"));
            vuln_ids.extend(str_field(v, "@id"));
            if let Some(a) = v.get("aliases").and_then(Value::as_array) {
                vuln_ids.extend(a.iter().filter_map(Value::as_str).map(str::to_string));
            }
            for x in &mut vuln_ids {
                *x = x.to_ascii_lowercase();
            }
        }
        _ => return Err("missing vulnerability".into()),
    }
    if vuln_ids.is_empty() {
        return Err("vulnerability has no name".into());
    }
    let mut products = Vec::new();
    for p in s
        .get("products")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let subs: Vec<String> = p
            .get("subcomponents")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(identifiers)
            .collect();
        for pid in identifiers(p) {
            products.push((pid, subs.clone()));
        }
    }
    if products.is_empty() {
        return Err("no products".into());
    }
    let status_raw = str_field(s, "status").ok_or("missing status")?;
    let status =
        VexStatus::parse(&status_raw).ok_or_else(|| format!("unknown status {status_raw:?}"))?;
    let justification = str_field(s, "justification");
    let impact_statement = str_field(s, "impact_statement");
    let action_statement = str_field(s, "action_statement");
    let mut warning = None;
    if let Some(j) = &justification {
        if !JUSTIFICATIONS.contains(&j.as_str()) {
            return Err(format!("unknown justification {j:?}"));
        }
    }
    match status {
        VexStatus::NotAffected if justification.is_none() && impact_statement.is_none() => {
            return Err("not_affected requires a justification or impact_statement".into());
        }
        VexStatus::Affected if action_statement.is_none() => {
            warning = Some("affected statement has no action_statement".to_string());
        }
        _ => {}
    }
    let timestamp = str_field(s, "timestamp")
        .and_then(|t| parse_rfc3339(&t))
        .or(doc_ts);
    Ok((
        Statement {
            vuln_ids,
            products,
            status,
            justification,
            impact_statement,
            action_statement,
            timestamp,
            reference,
        },
        warning,
    ))
}

/// Parses an RFC 3339 timestamp to UTC nanoseconds since the Unix epoch.
pub fn parse_rfc3339(s: &str) -> Option<i128> {
    let b = s.trim().as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut nanos: i128 = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let frac = std::str::from_utf8(&b[start..i]).ok()?;
        if frac.is_empty() {
            return None;
        }
        let mut digits: String = frac.chars().take(9).collect();
        while digits.len() < 9 {
            digits.push('0');
        }
        nanos = digits.parse().ok()?;
    }
    let offset_secs: i64 = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let off = num(i + 1..i + 3)? * 3600 + num(i + 4..i + 6)? * 60;
            if *sign == b'+' {
                off
            } else {
                -off
            }
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant's algorithm).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset_secs;
    Some(i128::from(secs) * 1_000_000_000 + nanos)
}

fn ids_match(statement_id: &str, purl: Option<&Purl>, source_ref: &str) -> bool {
    if statement_id == source_ref {
        return true;
    }
    let (Some(component), Ok(p)) = (purl, Purl::parse(statement_id)) else {
        return false;
    };
    if p.package_key() != component.package_key() {
        return false;
    }
    if !p
        .qualifiers
        .iter()
        .all(|(k, v)| component.qualifiers.get(k) == Some(v))
    {
        return false;
    }
    match (&p.version, &component.version) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => {
            if a == b {
                return true;
            }
            // Same version spelled differently (1.0 vs 1.0.0 in PyPI, v-prefix in Go).
            let scheme = crate::ecosystem::Ecosystem::from_purl_type(&p.ty).scheme();
            scheme.is_some_and(|s| match (Version::parse(s, a), Version::parse(s, b)) {
                (Ok(x), Ok(y)) => x.key() == y.key(),
                _ => false,
            })
        }
    }
}

/// Applies VEX documents to a scan result in place.
pub fn apply(result: &mut ScanResult, graph: &SbomGraph, docs: &[VexDocument]) -> VexReport {
    let mut report = VexReport::default();
    for d in docs {
        report.warnings.extend(d.warnings.iter().cloned());
    }
    let statements: Vec<&Statement> = docs.iter().flat_map(|d| d.statements.iter()).collect();
    let mut used = vec![false; statements.len()];
    let (parent, depth) = graph.bfs_from_roots();
    for f in &mut result.findings {
        let ids: Vec<String> = f.all_ids().map(str::to_ascii_lowercase).collect();
        let comp = &graph.components[f.component];
        let chain: Vec<usize> = graph
            .path_to(f.component, &parent, &depth)
            .unwrap_or_default();
        let mut best: Option<(usize, &Statement)> = None;
        for (si, st) in statements.iter().enumerate() {
            if !st.vuln_ids.iter().any(|v| ids.contains(v)) {
                continue;
            }
            let applies = st.products.iter().any(|(pid, subs)| {
                if subs.is_empty() && ids_match(pid, comp.purl.as_ref(), &comp.source_ref) {
                    return true;
                }
                let product_on_path = chain.iter().any(|&a| {
                    let ac = &graph.components[a];
                    ids_match(pid, ac.purl.as_ref(), &ac.source_ref)
                });
                product_on_path
                    && (subs.is_empty()
                        || subs
                            .iter()
                            .any(|s| ids_match(s, comp.purl.as_ref(), &comp.source_ref)))
            });
            if !applies {
                continue;
            }
            used[si] = true;
            let newer = best.is_none_or(|(_, b)| {
                st.timestamp.unwrap_or(i128::MIN) >= b.timestamp.unwrap_or(i128::MIN)
            });
            if newer {
                best = Some((si, st));
            }
        }
        if let Some((_, st)) = best {
            *report
                .applied
                .entry(st.status.as_str().to_string())
                .or_insert(0) += 1;
            f.vex = Some(VexOutcome {
                status: st.status,
                justification: st.justification.clone(),
                impact_statement: st.impact_statement.clone(),
                action_statement: st.action_statement.clone(),
                statement: st.reference.clone(),
            });
        }
    }
    report.unused = statements
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|(s, _)| s.reference.clone())
        .collect();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parsing() {
        let z = parse_rfc3339("2023-01-08T18:02:03Z").unwrap();
        let off = parse_rfc3339("2023-01-08T12:02:03-06:00").unwrap();
        assert_eq!(z, off);
        let frac = parse_rfc3339("2023-01-08T12:02:03.647787998-06:00").unwrap();
        assert_eq!(frac - off, 647_787_998);
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339("2000-03-01T00:00:00+00:00"),
            Some(951_868_800_000_000_000)
        );
        for bad in [
            "",
            "2023-01-08",
            "2023-13-01T00:00:00Z",
            "2023-01-08T25:00:00Z",
            "2023-01-08T00:00:00",
            "2023-01-08T00:00:00.Z",
            "2023-01-08T00:00:00+0100",
            "abcd-01-08T00:00:00Z",
        ] {
            assert!(parse_rfc3339(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn purl_identity_matching() {
        let c = Purl::parse("pkg:pypi/jinja2@3.1.2?arch=x").unwrap();
        assert!(ids_match("pkg:pypi/Jinja2", Some(&c), "r"));
        assert!(ids_match("pkg:pypi/jinja2@3.1.2.0", Some(&c), "r"));
        assert!(ids_match("pkg:pypi/jinja2@3.1.2?arch=x", Some(&c), "r"));
        assert!(!ids_match("pkg:pypi/jinja2@3.1.2?arch=y", Some(&c), "r"));
        assert!(!ids_match("pkg:pypi/jinja2@3.1.3", Some(&c), "r"));
        assert!(!ids_match("pkg:pypi/markupsafe", Some(&c), "r"));
        assert!(ids_match("my-ref", None, "my-ref"));
        assert!(!ids_match("pkg:pypi/jinja2", None, "r"));
        let nov = Purl::parse("pkg:npm/x").unwrap();
        assert!(!ids_match("pkg:npm/x@1.0.0", Some(&nov), "r"));
        let g = Purl::parse("pkg:generic/x@1").unwrap();
        assert!(!ids_match("pkg:generic/x@1.0", Some(&g), "r"));
    }

    #[test]
    fn validation_rules() {
        let doc = |statements: &str| {
            VexDocument::parse(
                &format!(r#"{{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "d", "statements": {statements}}}"#),
                "t",
            )
            .unwrap()
        };
        let d = doc(r#"[
            {"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:npm/a"}], "status": "not_affected"},
            {"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:npm/a"}], "status": "bogus"},
            {"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:npm/a"}], "status": "not_affected", "justification": "because"},
            {"vulnerability": {"name": "CVE-1"}, "products": [], "status": "fixed"},
            {"products": [{"@id": "pkg:npm/a"}], "status": "fixed"},
            {"vulnerability": {}, "products": [{"@id": "pkg:npm/a"}], "status": "fixed"},
            {"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:npm/a"}]},
            {"vulnerability": "CVE-2", "products": ["pkg:npm/a"], "status": "affected"},
            {"vulnerability": {"name": "CVE-3", "aliases": ["GHSA-X"]}, "products": [{"identifiers": {"purl": "pkg:npm/a"}, "subcomponents": ["pkg:npm/b"]}],
             "status": "not_affected", "impact_statement": "not reachable", "timestamp": "2024-01-01T00:00:00Z"}
        ]"#);
        assert_eq!(d.statements.len(), 2);
        assert_eq!(d.warnings.len(), 8, "{:#?}", d.warnings);
        assert_eq!(d.statements[1].vuln_ids, ["cve-3", "ghsa-x"]);
        assert_eq!(d.statements[1].products[0].1, ["pkg:npm/b"]);
        assert!(d.statements[1].timestamp.is_some());

        assert!(VexDocument::parse(r#"{"statements": []}"#, "t").is_err());
        assert!(
            VexDocument::parse(r#"{"@context": "https://openvex.dev/ns/v0.2.0"}"#, "t").is_err()
        );
        assert!(VexDocument::parse("nope", "t").is_err());
        assert!(VexDocument::load(std::path::Path::new("/nonexistent.vex.json")).is_err());
    }
}
