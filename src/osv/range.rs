//! OSV range evaluation.
//!
//! Implements the evaluation algorithm from the OSV schema ("Evaluation"
//! section): events are sorted by version (`introduced: "0"` first), then
//! walked in order — `introduced` at or below the version opens the range,
//! `fixed` at or below closes it, `last_affected` strictly below closes it.
//! `limit` events bound the whole range from above (exclusive; `"*"` means
//! unbounded). Versions are compared with the scheme the range type and the
//! ecosystem dictate, so `1.10.0` correctly sorts after `1.9.0` and
//! `1.0rc1` before `1.0`.

use std::cmp::Ordering;

use serde::Serialize;

use super::Range;
use crate::ecosystem::Ecosystem;
use crate::version::{Scheme, Version, VersionError};

/// The kind of a range event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Opens the range.
    Introduced,
    /// Closes the range (exclusive).
    Fixed,
    /// Closes the range (inclusive).
    LastAffected,
    /// Bounds the whole range from above.
    Limit,
}

#[derive(Debug, Clone)]
enum Bound {
    /// `introduced: "0"`: below every version.
    Zero,
    /// A concrete version.
    At(Version),
    /// `limit: "*"`: above every version.
    Infinite,
}

impl Bound {
    fn cmp_version(&self, v: &Version) -> Ordering {
        match self {
            Bound::Zero => Ordering::Less,
            Bound::Infinite => Ordering::Greater,
            Bound::At(b) => b.try_cmp(v).unwrap_or(Ordering::Equal),
        }
    }

    fn cmp_bound(&self, other: &Bound) -> Ordering {
        match (self, other) {
            (Bound::Zero, Bound::Zero) | (Bound::Infinite, Bound::Infinite) => Ordering::Equal,
            (Bound::Zero, _) | (_, Bound::Infinite) => Ordering::Less,
            (_, Bound::Zero) | (Bound::Infinite, _) => Ordering::Greater,
            (Bound::At(a), Bound::At(b)) => a.try_cmp(b).unwrap_or(Ordering::Equal),
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledEvent {
    kind: EventKind,
    raw: String,
    bound: Bound,
}

/// Why a range could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RangeError {
    /// `GIT` ranges need commit graphs, which an SBOM does not carry.
    #[error("GIT ranges cannot be evaluated against package versions")]
    Git,
    /// An `ECOSYSTEM` range for an ecosystem without a known ordering.
    #[error("no version ordering known for ecosystem {0}")]
    UnknownEcosystem(String),
    /// A range type not defined by the OSV schema.
    #[error("unknown range type {0:?}")]
    UnknownType(String),
    /// An event has no recognised field.
    #[error("event without introduced/fixed/last_affected/limit")]
    EmptyEvent,
    /// An event version does not parse under the range's scheme.
    #[error(transparent)]
    BadVersion(#[from] VersionError),
}

/// Explanation of a positive range match, for reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RangeHit {
    /// The `introduced` event that opened the matching interval.
    pub introduced: String,
    /// The `fixed` event closing it, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    /// The `last_affected` event closing it, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
}

/// A range compiled for repeated evaluation.
#[derive(Debug, Clone)]
pub struct CompiledRange {
    /// The scheme versions must be parsed with.
    pub scheme: Scheme,
    /// The OSV range type (`SEMVER` or `ECOSYSTEM`).
    pub kind: String,
    events: Vec<CompiledEvent>,
    limits: Vec<Bound>,
}

/// The scheme used to evaluate a range of `kind` for `ecosystem`.
///
/// `SEMVER` ranges use SemVer precedence everywhere; the npm and Go
/// front-ends are used for those ecosystems so their spellings (`v1.2.3`)
/// parse. `ECOSYSTEM` ranges use the ecosystem's own ordering.
pub fn scheme_for(kind: &str, ecosystem: &Ecosystem) -> Result<Scheme, RangeError> {
    match kind {
        "SEMVER" => Ok(match ecosystem {
            Ecosystem::Go => Scheme::Go,
            Ecosystem::Npm => Scheme::Npm,
            _ => Scheme::SemVer,
        }),
        "ECOSYSTEM" => ecosystem
            .scheme()
            .ok_or_else(|| RangeError::UnknownEcosystem(ecosystem.to_string())),
        "GIT" => Err(RangeError::Git),
        other => Err(RangeError::UnknownType(other.to_string())),
    }
}

impl CompiledRange {
    /// Compiles a range: parses and sorts its events.
    pub fn compile(range: &Range, ecosystem: &Ecosystem) -> Result<CompiledRange, RangeError> {
        let scheme = scheme_for(&range.kind, ecosystem)?;
        let mut events = Vec::with_capacity(range.events.len());
        let mut limits = Vec::new();
        for e in &range.events {
            let (kind, raw) = if let Some(v) = &e.introduced {
                (EventKind::Introduced, v)
            } else if let Some(v) = &e.fixed {
                (EventKind::Fixed, v)
            } else if let Some(v) = &e.last_affected {
                (EventKind::LastAffected, v)
            } else if let Some(v) = &e.limit {
                (EventKind::Limit, v)
            } else {
                return Err(RangeError::EmptyEvent);
            };
            let bound = match (kind, raw.as_str()) {
                (EventKind::Introduced, "0") => Bound::Zero,
                (EventKind::Limit, "*") => Bound::Infinite,
                _ => Bound::At(Version::parse(scheme, raw)?),
            };
            if kind == EventKind::Limit {
                limits.push(bound);
            } else {
                events.push(CompiledEvent {
                    kind,
                    raw: raw.clone(),
                    bound,
                });
            }
        }
        // Stable sort keeps document order for equal versions.
        events.sort_by(|a, b| a.bound.cmp_bound(&b.bound));
        Ok(CompiledRange {
            scheme,
            kind: range.kind.clone(),
            events,
            limits,
        })
    }

    /// Evaluates the range for `v` (which must be parsed with `self.scheme`).
    /// Returns the matching interval, or `None` when `v` is not affected.
    pub fn evaluate(&self, v: &Version) -> Option<RangeHit> {
        if !self.limits.is_empty() && !self.limits.iter().any(|l| l.cmp_version(v) == Ordering::Greater) {
            return None;
        }
        let mut open: Option<&CompiledEvent> = None;
        for e in &self.events {
            let c = e.bound.cmp_version(v); // bound vs version
            match e.kind {
                EventKind::Introduced if c != Ordering::Greater => open = Some(e),
                EventKind::Fixed if c != Ordering::Greater => open = None,
                EventKind::LastAffected if c == Ordering::Less => open = None,
                _ => {}
            }
        }
        let intro = open?;
        // The closing event: first fixed > v or last_affected >= v after the opener.
        let close = self.events.iter().find(|e| match e.kind {
            EventKind::Fixed => e.bound.cmp_version(v) == Ordering::Greater,
            EventKind::LastAffected => e.bound.cmp_version(v) != Ordering::Less,
            _ => false,
        });
        Some(RangeHit {
            introduced: intro.raw.clone(),
            fixed: close
                .filter(|e| e.kind == EventKind::Fixed)
                .map(|e| e.raw.clone()),
            last_affected: close
                .filter(|e| e.kind == EventKind::LastAffected)
                .map(|e| e.raw.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::Event;

    fn ev(kind: &str, v: &str) -> Event {
        let mut e = Event::default();
        let s = Some(v.to_string());
        match kind {
            "i" => e.introduced = s,
            "f" => e.fixed = s,
            "l" => e.last_affected = s,
            _ => e.limit = s,
        }
        e
    }

    fn range(kind: &str, events: Vec<Event>) -> Range {
        Range {
            kind: kind.into(),
            events,
        }
    }

    fn hit(r: &CompiledRange, v: &str) -> Option<RangeHit> {
        r.evaluate(&Version::parse(r.scheme, v).unwrap())
    }

    #[test]
    fn semver_multiple_intervals() {
        // Two vulnerable windows: [0, 1.2.3) and [2.0.0, 2.1.0). Events deliberately unsorted.
        let r = CompiledRange::compile(
            &range("SEMVER", vec![ev("i", "2.0.0"), ev("f", "2.1.0"), ev("i", "0"), ev("f", "1.2.3")]),
            &Ecosystem::Crates,
        )
        .unwrap();
        assert!(hit(&r, "0.1.0").is_some());
        assert_eq!(hit(&r, "1.2.2").unwrap().fixed.as_deref(), Some("1.2.3"));
        assert!(hit(&r, "1.2.3").is_none());
        assert!(hit(&r, "1.9.9").is_none());
        let h = hit(&r, "2.0.0").unwrap();
        assert_eq!((h.introduced.as_str(), h.fixed.as_deref()), ("2.0.0", Some("2.1.0")));
        assert!(hit(&r, "2.1.0").is_none());
        assert!(hit(&r, "2.1.0-rc.1").is_some(), "pre-release of the fix is still affected");
    }

    #[test]
    fn last_affected_is_inclusive() {
        let r = CompiledRange::compile(
            &range("ECOSYSTEM", vec![ev("i", "1.0"), ev("l", "1.4")]),
            &Ecosystem::PyPI,
        )
        .unwrap();
        assert!(hit(&r, "0.9").is_none());
        assert_eq!(hit(&r, "1.4").unwrap().last_affected.as_deref(), Some("1.4"));
        assert!(hit(&r, "1.4.0").is_some(), "PEP 440: 1.4.0 == 1.4");
        assert!(hit(&r, "1.4.post1").is_none());
        assert!(hit(&r, "1.4rc1").is_some());
    }

    #[test]
    fn limits_bound_the_range() {
        let r = CompiledRange::compile(
            &range("SEMVER", vec![ev("i", "0"), ev("lim", "1.5.0")]),
            &Ecosystem::Npm,
        )
        .unwrap();
        assert!(hit(&r, "1.4.9").is_some());
        assert!(hit(&r, "1.5.0").is_none());
        let r = CompiledRange::compile(
            &range("SEMVER", vec![ev("i", "1.0.0"), ev("lim", "*")]),
            &Ecosystem::Npm,
        )
        .unwrap();
        assert!(hit(&r, "99.0.0").is_some());
    }

    #[test]
    fn go_ranges_use_unprefixed_versions() {
        let r = CompiledRange::compile(
            &range("SEMVER", vec![ev("i", "0"), ev("f", "0.0.0-20220906165146-f3363e06e74c")]),
            &Ecosystem::Go,
        )
        .unwrap();
        assert!(hit(&r, "v0.0.0-20210226172049-e18ecbb05110").is_some());
        assert!(hit(&r, "v0.0.0-20221004154528-8021a29435af").is_none());
        assert!(hit(&r, "v0.1.0").is_none());
    }

    #[test]
    fn maven_ecosystem_ordering() {
        let r = CompiledRange::compile(
            &range("ECOSYSTEM", vec![ev("i", "2.0-beta9"), ev("f", "2.15.0")]),
            &Ecosystem::Maven,
        )
        .unwrap();
        assert!(hit(&r, "2.14.1").is_some());
        assert!(hit(&r, "2.0-beta8").is_none());
        assert!(hit(&r, "2.0").is_some());
        assert!(hit(&r, "2.15.0").is_none());
    }

    #[test]
    fn compile_errors() {
        let e = |r: Range, eco: Ecosystem| CompiledRange::compile(&r, &eco).unwrap_err();
        assert_eq!(e(range("GIT", vec![]), Ecosystem::Npm), RangeError::Git);
        assert!(matches!(
            e(range("ECOSYSTEM", vec![]), Ecosystem::from_osv("Debian:11")),
            RangeError::UnknownEcosystem(_)
        ));
        assert!(matches!(e(range("WAT", vec![]), Ecosystem::Npm), RangeError::UnknownType(_)));
        assert_eq!(e(range("SEMVER", vec![Event::default()]), Ecosystem::Npm), RangeError::EmptyEvent);
        assert!(matches!(
            e(range("SEMVER", vec![ev("f", "1.0")]), Ecosystem::Crates),
            RangeError::BadVersion(_)
        ));
    }
}
