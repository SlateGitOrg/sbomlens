//! CVSS v3.0/v3.1 base-score calculation and qualitative severity.
//!
//! OSV records carry CVSS vectors, not scores. The base score is computed
//! with the equations of the CVSS v3.1 specification (section 7.1) and its
//! `Roundup` definition (Appendix A); v3.0 vectors use the v3.0 `Roundup`
//! (`ceil(x * 10) / 10`). CVSS v4 vectors are recognized but not scored
//! (the v4 score needs the full MacroVector lookup table); callers fall back
//! to the advisory's own qualitative label for those.

use std::fmt;

use serde::Serialize;

/// Qualitative severity, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No severity information available.
    Unknown,
    /// CVSS 0.0.
    None,
    /// CVSS 0.1–3.9.
    Low,
    /// CVSS 4.0–6.9.
    Medium,
    /// CVSS 7.0–8.9.
    High,
    /// CVSS 9.0–10.0.
    Critical,
}

impl Severity {
    /// Maps a CVSS base score to the v3.1 qualitative rating scale.
    pub fn from_score(score: f64) -> Severity {
        if score <= 0.0 {
            Severity::None
        } else if score < 4.0 {
            Severity::Low
        } else if score < 7.0 {
            Severity::Medium
        } else if score < 9.0 {
            Severity::High
        } else {
            Severity::Critical
        }
    }

    /// Parses a label such as GitHub's `MODERATE` or `HIGH` (case-insensitive).
    pub fn from_label(label: &str) -> Option<Severity> {
        match label.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "moderate" | "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "none" => Some(Severity::None),
            _ => None,
        }
    }

    /// Parses a user-supplied threshold (`low`, `medium`, `high`, `critical`).
    pub fn parse_threshold(s: &str) -> Option<Severity> {
        Severity::from_label(s).filter(|s| *s != Severity::None)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Unknown => "unknown",
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}

/// Error for malformed CVSS vectors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid CVSS vector {vector:?}: {reason}")]
pub struct CvssError {
    /// The rejected vector.
    pub vector: String,
    /// Why it was rejected.
    pub reason: String,
}

/// Computes the base score of a CVSS v3.0 or v3.1 vector string
/// (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
pub fn base_score_v3(vector: &str) -> Result<f64, CvssError> {
    let err = |reason: String| CvssError {
        vector: vector.to_string(),
        reason,
    };
    let mut parts = vector.trim().split('/');
    let v31 = match parts.next() {
        Some("CVSS:3.1") => true,
        Some("CVSS:3.0") => false,
        other => return Err(err(format!("unsupported prefix {other:?}"))),
    };
    let mut metrics = std::collections::HashMap::new();
    for p in parts {
        let (k, v) = p
            .split_once(':')
            .ok_or_else(|| err(format!("malformed metric {p:?}")))?;
        if metrics.insert(k, v).is_some() {
            return Err(err(format!("duplicate metric {k}")));
        }
    }
    let get = |k: &str| {
        metrics
            .get(k)
            .copied()
            .ok_or_else(|| err(format!("missing base metric {k}")))
    };
    let bad = |k: &str, v: &str| err(format!("invalid value {v:?} for {k}"));
    let scope_changed = match get("S")? {
        "U" => false,
        "C" => true,
        v => return Err(bad("S", v)),
    };
    let av = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        v => return Err(bad("AV", v)),
    };
    let ac = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        v => return Err(bad("AC", v)),
    };
    let pr = match (get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        (v, _) => return Err(bad("PR", v)),
    };
    let ui = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        v => return Err(bad("UI", v)),
    };
    let cia = |k: &str| -> Result<f64, CvssError> {
        match get(k)? {
            "H" => Ok(0.56),
            "L" => Ok(0.22),
            "N" => Ok(0.0),
            v => Err(bad(k, v)),
        }
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Ok(0.0);
    }
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Ok(if v31 {
        roundup_v31(raw)
    } else {
        (raw * 10.0).ceil() / 10.0
    })
}

/// CVSS v3.1 `Roundup`: smallest one-decimal number >= input, computed on
/// integers to avoid floating-point artifacts.
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn roundup_v31(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_nvd_scores() {
        for (v, want) in [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0), // CVE-2021-44228
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
            ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ] {
            let got = base_score_v3(v).unwrap();
            assert!((got - want).abs() < 1e-9, "{v}: {got} != {want}");
        }
    }

    #[test]
    fn rejects_malformed_vectors() {
        for v in [
            "CVSS:4.0/AV:N",
            "AV:N/AC:L",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AVN",
            "CVSS:3.1/AV:N/AC:Q/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:Q/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:Q/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:Q/I:H/A:H",
        ] {
            assert!(base_score_v3(v).is_err(), "{v}");
        }
    }

    #[test]
    fn severity_scale_and_labels() {
        assert_eq!(Severity::from_score(0.0), Severity::None);
        assert_eq!(Severity::from_score(3.9), Severity::Low);
        assert_eq!(Severity::from_score(4.0), Severity::Medium);
        assert_eq!(Severity::from_score(7.0), Severity::High);
        assert_eq!(Severity::from_score(9.0), Severity::Critical);
        assert_eq!(Severity::from_label("MODERATE"), Some(Severity::Medium));
        assert_eq!(Severity::from_label("bogus"), None);
        assert_eq!(Severity::parse_threshold("none"), None);
        assert_eq!(Severity::parse_threshold("High"), Some(Severity::High));
        assert!(Severity::Critical > Severity::Unknown);
        assert_eq!(Severity::Medium.to_string(), "medium");
    }
}
