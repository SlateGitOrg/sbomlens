//! Matching SBOM components against the OSV database.

use std::collections::{BTreeMap, HashSet};

use serde::Serialize;

use super::range::RangeHit;
use super::{OsvDatabase, ResolvedSeverity};
use crate::graph::SbomGraph;
use crate::version::{Scheme, Version, VersionError};
use crate::vex::VexOutcome;

/// Why a component matched an advisory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MatchReason {
    /// The version falls inside a `SEMVER`/`ECOSYSTEM` range.
    Range {
        /// The OSV range type.
        range_type: String,
        /// The interval that matched.
        #[serde(flatten)]
        hit: RangeHit,
    },
    /// The version is listed in the advisory's `versions` array.
    ListedVersion,
}

/// One vulnerable component.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Component index in the scanned graph.
    pub component: usize,
    /// Component purl (canonical).
    pub purl: String,
    /// Component display name.
    pub package: String,
    /// Component version.
    pub version: String,
    /// Advisory id.
    pub id: String,
    /// Advisory aliases.
    pub aliases: Vec<String>,
    /// Advisory summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Resolved severity.
    pub severity: ResolvedSeverity,
    /// Why it matched.
    pub reason: MatchReason,
    /// Lowest fixed version above the component's version, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    /// Display names from a root to the component (shortest path).
    pub path: Vec<String>,
    /// True when a root depends on the component directly.
    pub direct: bool,
    /// Advisory URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// VEX decision, when statements were applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vex: Option<VexOutcome>,
}

impl Finding {
    /// True when VEX says the finding does not apply (not_affected / fixed).
    pub fn is_suppressed(&self) -> bool {
        self.vex.as_ref().is_some_and(VexOutcome::suppresses)
    }

    /// The advisory id and its aliases.
    pub fn all_ids(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.id.as_str()).chain(self.aliases.iter().map(String::as_str))
    }
}

/// A component that could not be checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    /// Component display name.
    pub package: String,
    /// Component purl or source reference.
    pub reference: String,
    /// Why it was skipped.
    pub reason: String,
}

/// Coverage counters for one scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanStats {
    /// Components in the SBOM.
    pub components: usize,
    /// Components checked against the database.
    pub checked: usize,
    /// Components without a purl (cannot be matched).
    pub without_purl: usize,
    /// Components whose ecosystem sbomlens cannot order versions for.
    pub unsupported_ecosystem: usize,
    /// Components without a version (cannot be matched).
    pub without_version: usize,
    /// Checked components whose version did not parse under some advisory's scheme.
    pub version_errors: usize,
    /// Advisory entries examined.
    pub entries_examined: usize,
    /// Advisory entries that could only be partially evaluated (e.g. GIT ranges).
    pub entries_partial: usize,
}

/// The result of scanning one SBOM.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// Findings sorted by severity (highest first), package, then id.
    pub findings: Vec<Finding>,
    /// Components that could not be checked, with reasons.
    pub skipped: Vec<Skipped>,
    /// Coverage counters.
    pub stats: ScanStats,
}

impl ScanResult {
    /// Findings not suppressed by VEX.
    pub fn active(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.is_suppressed())
    }

    /// Number of distinct vulnerabilities among active findings after
    /// merging advisories that alias each other (GHSA/PYSEC/GO/CVE ids).
    pub fn distinct_vulnerabilities(&self) -> usize {
        let active: Vec<&Finding> = self.active().collect();
        let mut parent: Vec<usize> = (0..active.len()).collect();
        fn find(p: &mut [usize], mut x: usize) -> usize {
            while p[x] != x {
                p[x] = p[p[x]];
                x = p[x];
            }
            x
        }
        let mut owner: BTreeMap<(usize, &str), usize> = BTreeMap::new();
        for (i, f) in active.iter().enumerate() {
            for id in f.all_ids() {
                if let Some(&j) = owner.get(&(f.component, id)) {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    parent[a] = b;
                } else {
                    owner.insert((f.component, id), i);
                }
            }
        }
        (0..active.len()).filter(|&i| find(&mut parent, i) == i).count()
    }
}

/// Lazily parsed component version, one slot per scheme.
struct VersionCache<'a> {
    raw: &'a str,
    slots: Vec<(Scheme, Result<Version, VersionError>)>,
}

impl<'a> VersionCache<'a> {
    fn new(raw: &'a str) -> Self {
        VersionCache {
            raw,
            slots: Vec::new(),
        }
    }

    fn get(&mut self, scheme: Scheme) -> &Result<Version, VersionError> {
        if let Some(i) = self.slots.iter().position(|(s, _)| *s == scheme) {
            return &self.slots[i].1;
        }
        self.slots.push((scheme, Version::parse(scheme, self.raw)));
        &self.slots[self.slots.len() - 1].1
    }
}

/// Scans every component of `graph` against `db`.
pub fn scan(graph: &SbomGraph, db: &OsvDatabase) -> ScanResult {
    let (parent, depth) = graph.bfs_from_roots();
    let mut stats = ScanStats {
        components: graph.components.len(),
        ..ScanStats::default()
    };
    let mut findings = Vec::new();
    let mut skipped = Vec::new();
    for (ci, c) in graph.components.iter().enumerate() {
        let (Some(purl), Some(eco)) = (&c.purl, &c.ecosystem) else {
            stats.without_purl += 1;
            continue;
        };
        let Some(eco_scheme) = eco.scheme() else {
            stats.unsupported_ecosystem += 1;
            continue;
        };
        let Some(raw_version) = c.effective_version() else {
            stats.without_version += 1;
            skipped.push(Skipped {
                package: c.display_name(),
                reference: purl.to_string(),
                reason: "no version".into(),
            });
            continue;
        };
        stats.checked += 1;
        let mut cache = VersionCache::new(raw_version);
        let mut parse_error: Option<String> = None;
        let mut seen = HashSet::new();
        for entry in db.lookup(eco, &eco.package_name(purl)) {
            stats.entries_examined += 1;
            if entry.partially_evaluable {
                stats.entries_partial += 1;
            }
            let vuln = &db.vulns[entry.vuln];
            if seen.contains(&entry.vuln) {
                continue;
            }
            let mut reason = None;
            for r in &entry.ranges {
                match cache.get(r.scheme) {
                    Ok(v) => {
                        if let Some(hit) = r.evaluate(v) {
                            reason = Some(MatchReason::Range {
                                range_type: r.kind.clone(),
                                hit,
                            });
                            break;
                        }
                    }
                    Err(e) => parse_error = Some(e.to_string()),
                }
            }
            if reason.is_none() {
                let listed = entry.versions_raw.contains(raw_version)
                    || matches!(cache.get(eco_scheme), Ok(v) if entry.versions_keys.contains(&v.key()));
                if listed {
                    reason = Some(MatchReason::ListedVersion);
                }
            }
            let Some(reason) = reason else { continue };
            seen.insert(entry.vuln);
            let affected = vuln.affected.get(entry.affected);
            let fixed_in = match &reason {
                MatchReason::Range { hit, .. } => hit.fixed.clone(),
                MatchReason::ListedVersion => None,
            };
            let path: Vec<String> = graph
                .path_to(ci, &parent, &depth)
                .unwrap_or_else(|| vec![ci])
                .into_iter()
                .map(|i| graph.components[i].display_name())
                .collect();
            findings.push(Finding {
                component: ci,
                purl: purl.to_string(),
                package: c.display_name(),
                version: raw_version.to_string(),
                id: vuln.id.clone(),
                aliases: vuln.aliases.clone(),
                summary: vuln.summary.clone(),
                severity: vuln.resolve_severity(affected),
                reason,
                fixed_in,
                direct: depth[ci] == 1,
                path,
                url: vuln.primary_url().map(str::to_string),
                vex: None,
            });
        }
        if let Some(reason) = parse_error {
            stats.version_errors += 1;
            skipped.push(Skipped {
                package: c.display_name(),
                reference: purl.to_string(),
                reason,
            });
        }
    }
    findings.sort_by(|a, b| {
        b.severity
            .level
            .cmp(&a.severity.level)
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.id.cmp(&b.id))
    });
    tracing::debug!(findings = findings.len(), checked = stats.checked, "scan complete");
    ScanResult {
        findings,
        skipped,
        stats,
    }
}
