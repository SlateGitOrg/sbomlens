//! Comparing two SBOMs.
//!
//! Components are paired by version-independent identity (purl package key,
//! or name for purl-less components). Within one identity, versions present
//! on both sides are "unchanged"; the remaining old and new versions are
//! each sorted with the ecosystem's ordering and paired in order, so a
//! package that exists in several versions (common in npm trees) produces
//! sensible upgrade pairs. Each pair is classified as an upgrade or a
//! downgrade by that ordering; when the ecosystem has no known ordering or a
//! version does not parse, the generic ordering is used and the entry is
//! flagged `best_effort`. License changes are reported for every paired
//! component whose canonical license expression differs.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde::Serialize;

use crate::graph::{Component, GraphStats, SbomGraph};
use crate::version::{sort_by_tolerant, Scheme, Version};

/// Classification of a version change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Only in the new SBOM.
    Added,
    /// Only in the old SBOM.
    Removed,
    /// New version sorts higher.
    Upgraded,
    /// New version sorts lower.
    Downgraded,
    /// Versions differ but cannot be ordered (or compare equal while spelled differently).
    Changed,
}

/// One component-level change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// The change kind.
    pub kind: ChangeKind,
    /// Package display name.
    pub package: String,
    /// Ecosystem name, or `unknown`.
    pub ecosystem: String,
    /// Old version (absent for additions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// New version (absent for removals).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// True when the direction came from the generic fallback ordering.
    pub best_effort: bool,
}

/// A license change on a component present in both SBOMs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LicenseChange {
    /// Package display name.
    pub package: String,
    /// Version in the new SBOM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Old license expression (`None` = no license information).
    pub from: Option<String>,
    /// New license expression.
    pub to: Option<String>,
}

/// The full diff.
#[derive(Debug, Clone, Serialize)]
pub struct SbomDiff {
    /// Component changes sorted by kind, then package.
    pub changes: Vec<Change>,
    /// License changes sorted by package.
    pub license_changes: Vec<LicenseChange>,
    /// Components present with the same version on both sides.
    pub unchanged: usize,
    /// Statistics of the old SBOM.
    pub old: GraphStats,
    /// Statistics of the new SBOM.
    pub new: GraphStats,
}

impl SbomDiff {
    /// Number of changes of one kind.
    pub fn count(&self, kind: ChangeKind) -> usize {
        self.changes.iter().filter(|c| c.kind == kind).count()
    }

    /// True when nothing changed.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.license_changes.is_empty()
    }
}

struct Side<'a> {
    comp: &'a Component,
    version: Option<&'a str>,
    parsed: Option<Version>,
    generic: Option<Version>,
}

fn side(comp: &Component) -> Side<'_> {
    let version = comp.effective_version();
    let scheme = comp
        .ecosystem
        .as_ref()
        .and_then(crate::ecosystem::Ecosystem::scheme);
    let parsed = match (scheme, version) {
        (Some(s), Some(v)) => Version::parse(s, v).ok(),
        _ => None,
    };
    let generic = version.and_then(|v| Version::parse(Scheme::Generic, v).ok());
    Side {
        comp,
        version,
        parsed,
        generic,
    }
}

/// Equality key for pairing identical versions.
fn version_key(s: &Side<'_>) -> String {
    match (&s.parsed, s.version) {
        (Some(p), _) => p.key(),
        (None, Some(v)) => v.to_string(),
        (None, None) => String::new(),
    }
}

/// Orders two sides: `(ordering, best_effort)`.
fn order(a: &Side<'_>, b: &Side<'_>) -> (Option<Ordering>, bool) {
    if let (Some(x), Some(y)) = (&a.parsed, &b.parsed) {
        return (x.try_cmp(y), false);
    }
    match (&a.generic, &b.generic) {
        (Some(x), Some(y)) => (x.try_cmp(y), true),
        _ => (None, true),
    }
}

/// Order used to sort leftover versions before pairing them.
///
/// `order` mixes schemes (ecosystem scheme when both sides parse, generic
/// otherwise), so it is not transitive and must not drive a sort. This key
/// is: tier first (ecosystem-parsed, then generic-only, then unparseable),
/// then the version kind, then that kind's own order, then the raw string as
/// a tie-breaker. For SemVer, PEP 440 and generic versions every step is a
/// total order, so the composition is one. Maven's ordering has cycles for
/// some spellings (reproduced from Maven itself), so the caller sorts with
/// [`sort_by_tolerant`] after a raw-string pre-sort.
fn sort_cmp(a: &Side<'_>, b: &Side<'_>) -> Ordering {
    fn tier<'v>(s: &'v Side<'_>) -> (u8, Option<&'v Version>) {
        match (&s.parsed, &s.generic) {
            (Some(p), _) => (0, Some(p)),
            (None, Some(g)) => (1, Some(g)),
            (None, None) => (2, None),
        }
    }
    fn kind(v: Option<&Version>) -> u8 {
        match v {
            Some(Version::SemVer(_)) => 0,
            Some(Version::Pep440(_)) => 1,
            Some(Version::Maven(_)) => 2,
            Some(Version::Generic(_)) => 3,
            None => 4,
        }
    }
    let ((ta, va), (tb, vb)) = (tier(a), tier(b));
    ta.cmp(&tb)
        .then_with(|| kind(va).cmp(&kind(vb)))
        .then_with(|| match (va, vb) {
            (Some(x), Some(y)) => x.try_cmp(y).unwrap_or(Ordering::Equal),
            _ => Ordering::Equal,
        })
        .then_with(|| a.version.cmp(&b.version))
}

fn license_str(c: &Component) -> Option<String> {
    c.license.as_ref().map(ToString::to_string)
}

fn eco_name(c: &Component) -> String {
    c.ecosystem
        .as_ref()
        .map_or_else(|| "unknown".to_string(), ToString::to_string)
}

/// Diffs `old` against `new`.
pub fn diff(old: &SbomGraph, new: &SbomGraph) -> SbomDiff {
    let old_ids = old.by_identity();
    let new_ids = new.by_identity();
    let mut keys: Vec<&String> = old_ids.keys().chain(new_ids.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut changes = Vec::new();
    let mut license_changes = Vec::new();
    let mut unchanged = 0;
    let empty = Vec::new();
    for key in keys {
        let mut olds: Vec<Side> = old_ids
            .get(key)
            .unwrap_or(&empty)
            .iter()
            .map(|&i| side(&old.components[i]))
            .collect();
        let mut news: Vec<Side> = new_ids
            .get(key)
            .unwrap_or(&empty)
            .iter()
            .map(|&i| side(&new.components[i]))
            .collect();
        // Remove duplicates within a side (same version listed twice).
        dedup_sides(&mut olds);
        dedup_sides(&mut news);
        let mut pairs: Vec<(Side, Side)> = Vec::new();
        // 1. identical versions.
        let mut rest_old = Vec::new();
        for o in olds {
            let k = version_key(&o);
            if let Some(pos) = news.iter().position(|n| version_key(n) == k) {
                let n = news.remove(pos);
                unchanged += 1;
                pairs.push((o, n));
            } else {
                rest_old.push(o);
            }
        }
        // 2. remaining versions paired in ascending order (see `sort_cmp`).
        //    The raw-string pre-sort makes the pairing independent of SBOM
        //    order even when the ecosystem ordering is not transitive.
        for v in [&mut rest_old, &mut news] {
            v.sort_by(|a, b| a.version.cmp(&b.version));
            sort_by_tolerant(v, sort_cmp);
        }
        let mut news_iter = news.into_iter();
        for o in rest_old {
            if let Some(n) = news_iter.next() {
                let (ord, best_effort) = order(&o, &n);
                let kind = match ord {
                    Some(Ordering::Less) => ChangeKind::Upgraded,
                    Some(Ordering::Greater) => ChangeKind::Downgraded,
                    _ => ChangeKind::Changed,
                };
                changes.push(Change {
                    kind,
                    package: n.comp.display_name(),
                    ecosystem: eco_name(n.comp),
                    from: o.version.map(str::to_string),
                    to: n.version.map(str::to_string),
                    best_effort,
                });
                pairs.push((o, n));
            } else {
                changes.push(Change {
                    kind: ChangeKind::Removed,
                    package: o.comp.display_name(),
                    ecosystem: eco_name(o.comp),
                    from: o.version.map(str::to_string),
                    to: None,
                    best_effort: false,
                });
            }
        }
        for n in news_iter {
            changes.push(Change {
                kind: ChangeKind::Added,
                package: n.comp.display_name(),
                ecosystem: eco_name(n.comp),
                from: None,
                to: n.version.map(str::to_string),
                best_effort: false,
            });
        }
        for (o, n) in pairs {
            let (a, b) = (o.comp.license.as_ref(), n.comp.license.as_ref());
            if a.map(crate::license::License::key) != b.map(crate::license::License::key) {
                license_changes.push(LicenseChange {
                    package: n.comp.display_name(),
                    version: n.version.map(str::to_string),
                    from: license_str(o.comp),
                    to: license_str(n.comp),
                });
            }
        }
    }
    changes.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.from.cmp(&b.from))
            .then_with(|| a.to.cmp(&b.to))
    });
    license_changes.sort_by(|a, b| {
        a.package
            .cmp(&b.package)
            .then_with(|| a.version.cmp(&b.version))
    });
    SbomDiff {
        changes,
        license_changes,
        unchanged,
        old: old.stats(),
        new: new.stats(),
    }
}

fn dedup_sides(v: &mut Vec<Side<'_>>) {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    v.retain(|s| seen.insert(version_key(s)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphBuilder, SbomFormat};
    use crate::license::License;
    use crate::purl::Purl;

    fn graph(items: &[(&str, Option<&str>)]) -> SbomGraph {
        let mut b = GraphBuilder::new(SbomFormat::CycloneDx("1.6".into()), None);
        for (i, (p, lic)) in items.iter().enumerate() {
            let mut c = if p.starts_with("pkg:") {
                Component::new(format!("r{i}"), "x").with_purl(Purl::parse(p).unwrap())
            } else {
                let (name, ver) = p.split_once('@').unwrap();
                let mut c = Component::new(format!("r{i}"), name);
                c.version = Some(ver.to_string());
                c
            };
            c.license = lic.and_then(License::from_sbom);
            b.add(c);
        }
        b.finish()
    }

    #[test]
    fn classifies_changes_with_ecosystem_ordering() {
        let old = graph(&[
            ("pkg:npm/qs@6.7.0", Some("BSD-3-Clause")),
            ("pkg:npm/debug@2.6.9", Some("MIT")),
            ("pkg:npm/debug@4.3.4", Some("MIT")),
            ("pkg:pypi/urllib3@1.26.14", Some("MIT")),
            ("pkg:maven/g/a@2.0", None),
            ("pkg:npm/gone@1.0.0", None),
            ("pkg:golang/x/y@v1.2.4-0.20191109021931-daa7c04131f5", None),
            ("pkg:deb/debian/curl@7.50.3-1", None),
            ("thing@r10", None),
            ("weird@1.0", None),
        ]);
        let new = graph(&[
            ("pkg:npm/qs@6.13.0", Some("BSD-3-Clause")),
            ("pkg:npm/debug@2.6.9", Some("MIT OR ISC")),
            ("pkg:npm/debug@4.4.0", Some("MIT")),
            ("pkg:pypi/urllib3@1.26.14.0", Some("mit")),
            ("pkg:maven/g/a@2.0-SNAPSHOT", None),
            ("pkg:npm/fresh@0.5.2", None),
            ("pkg:golang/x/y@v1.2.4", None),
            ("pkg:deb/debian/curl@7.50.3-2", None),
            ("thing@r9", None),
            ("weird@+++", None),
        ]);
        let d = diff(&old, &new);
        let find = |p: &str| d.changes.iter().find(|c| c.package == p).unwrap();
        assert_eq!(find("qs").kind, ChangeKind::Upgraded);
        assert_eq!(find("debug").kind, ChangeKind::Upgraded);
        assert_eq!(find("debug").to.as_deref(), Some("4.4.0"));
        assert_eq!(find("g:a").kind, ChangeKind::Downgraded);
        assert_eq!(find("gone").kind, ChangeKind::Removed);
        assert_eq!(find("fresh").kind, ChangeKind::Added);
        assert_eq!(find("x/y").kind, ChangeKind::Upgraded);
        let curl = find("debian/curl");
        assert_eq!((curl.kind, curl.best_effort), (ChangeKind::Upgraded, true));
        let thing = find("thing");
        assert_eq!(
            (thing.kind, thing.best_effort),
            (ChangeKind::Downgraded, true)
        );
        assert_eq!(find("weird").kind, ChangeKind::Changed);
        assert_eq!(
            d.unchanged, 2,
            "debug 2.6.9 and urllib3 1.26.14 == 1.26.14.0"
        );
        assert_eq!(d.license_changes.len(), 1);
        assert_eq!(d.license_changes[0].to.as_deref(), Some("ISC OR MIT"));
        assert_eq!(d.count(ChangeKind::Upgraded), 4);
        assert!(!d.is_empty());
        assert!(diff(&old, &old).is_empty());
    }

    #[test]
    fn license_appearing_is_reported() {
        let d = diff(
            &graph(&[("pkg:cargo/a@1.0.0", None)]),
            &graph(&[("pkg:cargo/a@1.0.0", Some("MIT"))]),
        );
        assert_eq!(d.license_changes[0].from, None);
        assert_eq!(d.unchanged, 1);
        let d = diff(
            &graph(&[("pkg:cargo/a@1.0.0", None)]),
            &graph(&[("pkg:cargo/a@1.0.0", None), ("pkg:cargo/a@1.0.0#x", None)]),
        );
        assert!(d.is_empty());
    }
    /// Regression: many versions of one package, mixing ones that parse under
    /// the ecosystem scheme with ones that only parse as generic, once made
    /// the sort comparator intransitive and `sort_by` panicked (exit 101).
    #[test]
    fn mixed_parseable_versions_sort_without_panicking() {
        let mut items: Vec<String> = (0..70)
            .flat_map(|n| {
                [
                    format!("pkg:npm/p@1.0.{n}-rc.1"),
                    format!("pkg:npm/p@1.0.{n}"),
                    format!("pkg:npm/p@1.0.{n}.a"),
                ]
            })
            .collect();
        // Deterministic shuffles (LCG) so the input order varies.
        for seed in 0u64..8 {
            let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            for i in (1..items.len()).rev() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let j = usize::try_from(state >> 33).unwrap() % (i + 1);
                items.swap(i, j);
            }
            let old: Vec<(&str, Option<&str>)> = items.iter().map(|s| (s.as_str(), None)).collect();
            let d = diff(&graph(&old), &graph(&[("pkg:npm/p@2.0.0", None)]));
            assert_eq!(d.changes.len(), 210);
            assert_eq!(
                d.changes
                    .iter()
                    .filter(|c| c.kind == ChangeKind::Removed)
                    .count(),
                209
            );
            // The newest strictly-parsed version is never paired before the
            // generic-only ones are; the one pairing is the lowest parsed one.
            let up: Vec<_> = d
                .changes
                .iter()
                .filter(|c| c.kind != ChangeKind::Removed)
                .collect();
            assert_eq!(up.len(), 1);
            assert_eq!(up[0].from.as_deref(), Some("1.0.0-rc.1"));
            assert_eq!(up[0].kind, ChangeKind::Upgraded);
        }
    }

    /// Regression: Maven's own ordering has cycles (`1-a < 1-ga-alpha < 1 <
    /// 1-a`, `1 < 1-sp < 1.0.alpha.1 < 1`, both confirmed against Maven
    /// 3.9.9). Many such versions of one artifact made `sort_by` panic with
    /// "comparison function does not correctly implement a total order". The
    /// diff must not panic, and its result must not depend on SBOM order.
    #[test]
    fn maven_versions_with_cyclic_order_diff_without_panicking() {
        let mut items: Vec<String> = (1..60)
            .flat_map(|n| {
                [
                    format!("pkg:maven/g/a@{n}-a"),
                    format!("pkg:maven/g/a@{n}-ga-alpha"),
                    format!("pkg:maven/g/a@{n}"),
                    format!("pkg:maven/g/a@{n}.0.alpha.1"),
                    format!("pkg:maven/g/a@{n}-sp"),
                ]
            })
            .collect();
        let new = graph(&[("pkg:maven/g/a@99", None), ("pkg:maven/g/a@7-a", None)]);
        let mut first: Option<Vec<Change>> = None;
        for seed in 0u64..8 {
            let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            for i in (1..items.len()).rev() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let j = usize::try_from(state >> 33).unwrap() % (i + 1);
                items.swap(i, j);
            }
            let old: Vec<(&str, Option<&str>)> = items.iter().map(|s| (s.as_str(), None)).collect();
            let d = diff(&graph(&old), &new);
            assert_eq!(d.unchanged, 1);
            assert_eq!(d.count(ChangeKind::Removed), 293);
            match &first {
                None => first = Some(d.changes),
                Some(f) => assert_eq!(&d.changes, f, "diff depends on SBOM order"),
            }
        }
    }
}
