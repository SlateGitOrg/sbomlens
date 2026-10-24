//! Offline OSV (Open Source Vulnerability) data: schema, range evaluation,
//! an indexed database and the component matcher.
//!
//! Only the parts of the [OSV schema](https://ossf.github.io/osv-schema/)
//! that affect matching and reporting are modelled; unknown fields are
//! ignored.

pub mod db;
pub mod matcher;
pub mod range;

use serde::Deserialize;
use serde_json::Value;

use crate::cvss::{base_score_v3, Severity};

pub use db::{LoadStats, OsvDatabase};
pub use matcher::{scan, Finding, MatchReason, ScanResult, Skipped};

/// One OSV advisory.
#[derive(Debug, Clone, Deserialize)]
pub struct Vulnerability {
    /// Advisory identifier (`GHSA-…`, `GO-…`, `PYSEC-…`, `RUSTSEC-…`).
    pub id: String,
    /// One-line summary.
    #[serde(default)]
    pub summary: Option<String>,
    /// Long description (Markdown).
    #[serde(default)]
    pub details: Option<String>,
    /// Other identifiers for the same vulnerability (CVE, GHSA, …).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Last modification time (RFC 3339).
    #[serde(default)]
    pub modified: Option<String>,
    /// Withdrawal time; withdrawn advisories never match.
    #[serde(default)]
    pub withdrawn: Option<String>,
    /// Affected packages.
    #[serde(default)]
    pub affected: Vec<Affected>,
    /// Record-level severity vectors.
    #[serde(default)]
    pub severity: Vec<SeverityEntry>,
    /// Source-specific data (GitHub puts a qualitative `severity` here).
    #[serde(default)]
    pub database_specific: Option<Value>,
    /// Reference links.
    #[serde(default)]
    pub references: Vec<Reference>,
}

/// One `affected[]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Affected {
    /// The affected package.
    #[serde(default)]
    pub package: Option<Package>,
    /// Version ranges.
    #[serde(default)]
    pub ranges: Vec<Range>,
    /// Explicitly enumerated affected versions.
    #[serde(default)]
    pub versions: Vec<String>,
    /// Package-level severity vectors.
    #[serde(default)]
    pub severity: Vec<SeverityEntry>,
}

/// Package coordinates of an affected entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Package {
    /// OSV ecosystem name (`npm`, `PyPI`, `Maven`, `Go`, `crates.io`, …).
    pub ecosystem: String,
    /// Package name in the ecosystem's own spelling.
    pub name: String,
    /// Optional purl of the package.
    #[serde(default)]
    pub purl: Option<String>,
}

/// One `ranges[]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Range {
    /// `SEMVER`, `ECOSYSTEM` or `GIT`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Ordered events.
    #[serde(default)]
    pub events: Vec<Event>,
}

/// A range event: exactly one of the four fields is set.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// Version where the vulnerability was introduced (`"0"` = all earlier).
    #[serde(default)]
    pub introduced: Option<String>,
    /// First fixed version.
    #[serde(default)]
    pub fixed: Option<String>,
    /// Last affected version (inclusive upper bound).
    #[serde(default)]
    pub last_affected: Option<String>,
    /// Upper limit of the range (exclusive), `"*"` for unbounded.
    #[serde(default)]
    pub limit: Option<String>,
}

/// A severity entry (`CVSS_V3`, `CVSS_V4`, …).
#[derive(Debug, Clone, Deserialize)]
pub struct SeverityEntry {
    /// The scoring system.
    #[serde(rename = "type")]
    pub kind: String,
    /// The vector or score.
    pub score: String,
}

/// A reference link.
#[derive(Debug, Clone, Deserialize)]
pub struct Reference {
    /// Reference type (`ADVISORY`, `FIX`, `WEB`, …).
    #[serde(rename = "type", default)]
    pub kind: String,
    /// The URL.
    pub url: String,
}

/// Severity resolved for reporting, with its provenance.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ResolvedSeverity {
    /// Qualitative level.
    pub level: Severity,
    /// CVSS v3 base score when a v3 vector was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// The vector the score came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
}

impl Vulnerability {
    /// Resolves severity: a CVSS v3 vector (record-level, then the given
    /// affected entry) is scored; otherwise the advisory's qualitative
    /// `database_specific.severity` label is used; otherwise `Unknown`.
    /// CVSS v4 vectors are reported but not scored.
    pub fn resolve_severity(&self, affected: Option<&Affected>) -> ResolvedSeverity {
        let entries = self
            .severity
            .iter()
            .chain(affected.into_iter().flat_map(|a| a.severity.iter()));
        let mut v4 = None;
        for e in entries {
            if e.kind == "CVSS_V3" {
                if let Ok(score) = base_score_v3(&e.score) {
                    return ResolvedSeverity {
                        level: Severity::from_score(score),
                        score: Some(score),
                        vector: Some(e.score.clone()),
                    };
                }
            } else if e.kind == "CVSS_V4" && v4.is_none() {
                v4 = Some(e.score.clone());
            }
        }
        let label = self
            .database_specific
            .as_ref()
            .and_then(|d| d.get("severity"))
            .and_then(Value::as_str)
            .and_then(Severity::from_label);
        ResolvedSeverity {
            level: label.unwrap_or(Severity::Unknown),
            score: None,
            vector: v4,
        }
    }

    /// The first `ADVISORY` reference, else the first reference.
    pub fn primary_url(&self) -> Option<&str> {
        self.references
            .iter()
            .find(|r| r.kind == "ADVISORY")
            .or_else(|| self.references.first())
            .map(|r| r.url.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vuln(v: Value) -> Vulnerability {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn severity_resolution_order() {
        let v = vuln(json!({"id": "X", "severity": [
            {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]}));
        let s = v.resolve_severity(None);
        assert_eq!(s.level, Severity::Critical);
        assert_eq!(s.score, Some(9.8));

        let v = vuln(
            json!({"id": "X", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}],
                            "database_specific": {"severity": "MODERATE"}}),
        );
        let s = v.resolve_severity(None);
        assert_eq!(s.level, Severity::Medium);
        assert_eq!(s.vector.as_deref(), Some("CVSS:4.0/AV:N"));

        let v = vuln(json!({"id": "X", "affected": [{"severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"}]}]}));
        assert_eq!(v.resolve_severity(v.affected.first()).level, Severity::Low);
        assert_eq!(v.resolve_severity(None).level, Severity::Unknown);
    }

    #[test]
    fn primary_url_prefers_advisory() {
        let v = vuln(json!({"id": "X", "references": [
            {"type": "WEB", "url": "https://a"}, {"type": "ADVISORY", "url": "https://b"}]}));
        assert_eq!(v.primary_url(), Some("https://b"));
        let v = vuln(json!({"id": "X", "references": [{"type": "WEB", "url": "https://a"}]}));
        assert_eq!(v.primary_url(), Some("https://a"));
        assert_eq!(vuln(json!({"id": "X"})).primary_url(), None);
    }
}
