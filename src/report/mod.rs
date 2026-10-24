//! Rendering scan and diff results: Markdown, SARIF 2.1.0 and JSON.

pub mod markdown;
pub mod sarif;

use serde::Serialize;

use crate::cvss::Severity;
use crate::diff::SbomDiff;
use crate::graph::{GraphStats, SbomGraph};
use crate::osv::{LoadStats, ScanResult};
use crate::vex::VexReport;

/// Everything a scan report needs, independent of the output format.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Tool version.
    pub tool_version: String,
    /// The SBOM as given on the command line (used as the SARIF artifact URI).
    pub sbom: String,
    /// SBOM format description (`CycloneDX 1.5`).
    pub sbom_format: String,
    /// Document / primary component name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom_name: Option<String>,
    /// Graph statistics.
    pub graph: GraphStats,
    /// SBOM loading warnings.
    pub sbom_warnings: Vec<String>,
    /// OSV database load statistics.
    pub database: LoadStats,
    /// The scan result (findings carry VEX outcomes when VEX was applied).
    pub scan: ScanResult,
    /// VEX summary, when VEX documents were given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vex: Option<VexReport>,
}

impl ScanReport {
    /// Assembles a report.
    pub fn new(
        sbom: &str,
        graph: &SbomGraph,
        database: LoadStats,
        scan: ScanResult,
        vex: Option<VexReport>,
    ) -> ScanReport {
        ScanReport {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            sbom: sbom.to_string(),
            sbom_format: graph.format.to_string(),
            sbom_name: graph.name.clone(),
            graph: graph.stats(),
            sbom_warnings: graph.warnings.clone(),
            database,
            scan,
            vex,
        }
    }

    /// Highest severity among active (non-suppressed) findings.
    pub fn max_active_severity(&self) -> Option<Severity> {
        self.scan.active().map(|f| f.severity.level).max()
    }

    /// Active finding counts by severity, most severe first.
    pub fn severity_counts(&self) -> Vec<(Severity, usize)> {
        let order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::None,
            Severity::Unknown,
        ];
        order
            .iter()
            .map(|s| {
                (
                    *s,
                    self.scan
                        .active()
                        .filter(|f| f.severity.level == *s)
                        .count(),
                )
            })
            .filter(|(_, n)| *n > 0)
            .collect()
    }
}

/// A diff report.
#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    /// Tool version.
    pub tool_version: String,
    /// Old SBOM path.
    pub old: String,
    /// New SBOM path.
    pub new: String,
    /// The diff.
    pub diff: SbomDiff,
}

impl DiffReport {
    /// Assembles a report.
    pub fn new(old: &str, new: &str, diff: SbomDiff) -> DiffReport {
        DiffReport {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            old: old.to_string(),
            new: new.to_string(),
            diff,
        }
    }
}

/// Serializes any report as pretty JSON.
pub fn to_json<T: Serialize>(value: &T) -> String {
    let mut s = serde_json::to_string_pretty(value).expect("report types serialize infallibly");
    s.push('\n');
    s
}
