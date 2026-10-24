//! Per-ecosystem version parsing and ordering.
//!
//! Each [`Scheme`] parses into a [`Version`]; versions parsed with the same
//! scheme are totally ordered. Comparing versions from different schemes is
//! a programming error and is reported by [`Version::try_cmp`] as `None`.

pub mod generic;
pub mod golang;
pub mod maven;
pub mod pep440;
pub mod semver;

use std::cmp::Ordering;
use std::fmt;

use serde::Serialize;

pub use generic::GenericVersion;
pub use maven::MavenVersion;
pub use pep440::Pep440;
pub use semver::SemVer;

/// A version-ordering scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Scheme {
    /// Strict SemVer 2.0.0 (crates.io, and OSV `SEMVER` ranges).
    SemVer,
    /// SemVer with npm's lenient front-end (`v1.2.3`, `=1.2.3`).
    Npm,
    /// Go module versions (`v` prefix optional, shorthands, pseudo-versions).
    Go,
    /// PEP 440 (PyPI).
    Pep440,
    /// Maven `ComparableVersion` ordering.
    Maven,
    /// Best-effort dotted/alphanumeric ordering for unknown ecosystems
    /// (used only to label SBOM diffs, never for vulnerability matching).
    Generic,
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Scheme::SemVer => "semver",
            Scheme::Npm => "npm",
            Scheme::Go => "go",
            Scheme::Pep440 => "pep440",
            Scheme::Maven => "maven",
            Scheme::Generic => "generic",
        })
    }
}

/// A version string that failed to parse under a scheme.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {scheme} version {input:?}: {reason}")]
pub struct VersionError {
    /// The scheme that rejected the input.
    pub scheme: Scheme,
    /// The rejected input.
    pub input: String,
    /// Why it was rejected.
    pub reason: String,
}

/// A parsed version under some [`Scheme`].
#[derive(Debug, Clone)]
pub enum Version {
    /// SemVer-shaped (SemVer, npm and Go schemes).
    SemVer(SemVer),
    /// PEP 440.
    Pep440(Pep440),
    /// Maven.
    Maven(MavenVersion),
    /// Generic fallback.
    Generic(GenericVersion),
}

impl Version {
    /// Parses `input` under `scheme`.
    pub fn parse(scheme: Scheme, input: &str) -> Result<Version, VersionError> {
        let r = match scheme {
            Scheme::SemVer => SemVer::parse(input.trim()).map(Version::SemVer),
            Scheme::Npm => SemVer::parse_npm(input).map(Version::SemVer),
            Scheme::Go => golang::parse(input).map(Version::SemVer),
            Scheme::Pep440 => Pep440::parse(input).map(Version::Pep440),
            Scheme::Maven => MavenVersion::parse(input).map(Version::Maven),
            Scheme::Generic => GenericVersion::parse(input).map(Version::Generic),
        };
        r.map_err(|reason| VersionError {
            scheme,
            input: input.to_string(),
            reason,
        })
    }

    /// Compares two versions of the same kind; `None` across kinds.
    pub fn try_cmp(&self, other: &Version) -> Option<Ordering> {
        match (self, other) {
            (Version::SemVer(a), Version::SemVer(b)) => Some(a.cmp(b)),
            (Version::Pep440(a), Version::Pep440(b)) => Some(a.cmp(b)),
            (Version::Maven(a), Version::Maven(b)) => Some(a.cmp(b)),
            (Version::Generic(a), Version::Generic(b)) => Some(a.cmp(b)),
            _ => None,
        }
    }

    /// A string key such that two versions of one kind have equal keys
    /// exactly when they compare equal (used for set membership of OSV
    /// `versions` lists).
    pub fn key(&self) -> String {
        match self {
            Version::SemVer(v) => {
                let mut v = v.clone();
                v.build.clear();
                v.to_string()
            }
            Version::Pep440(v) => v.key(),
            Version::Maven(v) => v.canonical(),
            Version::Generic(v) => v.key(),
        }
    }

    /// True for pre-releases in the scheme's own sense.
    pub fn is_prerelease(&self) -> bool {
        match self {
            Version::SemVer(v) => v.is_prerelease(),
            Version::Pep440(v) => v.is_prerelease(),
            Version::Maven(v) => v.is_prerelease(),
            Version::Generic(_) => false,
        }
    }
}

/// Parses both strings under `scheme` and compares them.
pub fn compare(scheme: Scheme, a: &str, b: &str) -> Result<Ordering, VersionError> {
    let va = Version::parse(scheme, a)?;
    let vb = Version::parse(scheme, b)?;
    Ok(va
        .try_cmp(&vb)
        .expect("one scheme always yields one version kind"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_dispatches_by_scheme() {
        assert_eq!(
            compare(Scheme::Pep440, "1.0", "1.0.0").unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            compare(Scheme::SemVer, "1.0.0", "1.0.1").unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare(Scheme::Go, "v1.2.3", "1.2.3").unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            compare(Scheme::Npm, "v2.0.0", "1.9.9").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare(Scheme::Maven, "1-SNAPSHOT", "1").unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare(Scheme::Generic, "1.10", "1.9").unwrap(),
            Ordering::Greater
        );
        let err = compare(Scheme::SemVer, "1.0", "1.0.0").unwrap_err();
        assert_eq!(err.scheme, Scheme::SemVer);
        assert!(err.to_string().contains("invalid semver version"));
    }

    #[test]
    fn cross_kind_compare_is_none() {
        let a = Version::parse(Scheme::SemVer, "1.0.0").unwrap();
        let b = Version::parse(Scheme::Pep440, "1.0.0").unwrap();
        assert!(a.try_cmp(&b).is_none());
        assert!(!a.is_prerelease());
        assert!(Version::parse(Scheme::Maven, "1-rc1")
            .unwrap()
            .is_prerelease());
        assert!(!Version::parse(Scheme::Generic, "1-rc1")
            .unwrap()
            .is_prerelease());
        assert!(Version::parse(Scheme::Pep440, "1rc1")
            .unwrap()
            .is_prerelease());
    }

    #[test]
    fn scheme_display() {
        let names: Vec<String> = [
            Scheme::SemVer,
            Scheme::Npm,
            Scheme::Go,
            Scheme::Pep440,
            Scheme::Maven,
            Scheme::Generic,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(names, ["semver", "npm", "go", "pep440", "maven", "generic"]);
    }
}
