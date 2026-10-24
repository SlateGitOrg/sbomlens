//! Package ecosystems: the bridge between purl types, OSV ecosystem names,
//! per-ecosystem package-name normalization and version-ordering schemes.

use std::fmt;

use serde::Serialize;

use crate::purl::Purl;
use crate::version::Scheme;

/// A package ecosystem sbomlens understands.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(into = "String")]
pub enum Ecosystem {
    /// npm registry (`pkg:npm`, OSV `npm`).
    Npm,
    /// crates.io (`pkg:cargo`, OSV `crates.io`).
    Crates,
    /// Python Package Index (`pkg:pypi`, OSV `PyPI`).
    PyPI,
    /// Maven Central and compatible repositories (`pkg:maven`, OSV `Maven`).
    Maven,
    /// Go modules (`pkg:golang`, OSV `Go`).
    Go,
    /// Anything else, carrying the OSV-style name (or purl type) verbatim.
    Other(String),
}

impl Ecosystem {
    /// Maps a purl type to an ecosystem.
    pub fn from_purl_type(ty: &str) -> Ecosystem {
        match ty {
            "npm" => Ecosystem::Npm,
            "cargo" => Ecosystem::Crates,
            "pypi" => Ecosystem::PyPI,
            "maven" => Ecosystem::Maven,
            "golang" => Ecosystem::Go,
            other => Ecosystem::Other(other.to_string()),
        }
    }

    /// Maps an OSV `affected[].package.ecosystem` value. Suffixes such as
    /// `Debian:11` keep their full text inside [`Ecosystem::Other`].
    pub fn from_osv(name: &str) -> Ecosystem {
        match name {
            "npm" => Ecosystem::Npm,
            "crates.io" => Ecosystem::Crates,
            "PyPI" => Ecosystem::PyPI,
            "Maven" => Ecosystem::Maven,
            "Go" => Ecosystem::Go,
            other => Ecosystem::Other(other.to_string()),
        }
    }

    /// The OSV ecosystem name.
    pub fn osv_name(&self) -> &str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Crates => "crates.io",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Maven => "Maven",
            Ecosystem::Go => "Go",
            Ecosystem::Other(s) => s,
        }
    }

    /// The version-ordering scheme used for `ECOSYSTEM` ranges and for diffing.
    /// `None` means sbomlens does not know how this ecosystem orders versions.
    pub fn scheme(&self) -> Option<Scheme> {
        match self {
            Ecosystem::Npm => Some(Scheme::Npm),
            Ecosystem::Crates => Some(Scheme::SemVer),
            Ecosystem::PyPI => Some(Scheme::Pep440),
            Ecosystem::Maven => Some(Scheme::Maven),
            Ecosystem::Go => Some(Scheme::Go),
            Ecosystem::Other(_) => None,
        }
    }

    /// The package name as OSV spells it for this ecosystem, derived from a purl:
    /// npm `@scope/name`, Maven `group:artifact`, Go module path, PyPI
    /// PEP 503-normalized name, crates.io crate name.
    pub fn package_name(&self, purl: &Purl) -> String {
        let raw = match (self, &purl.namespace) {
            (Ecosystem::Maven, Some(ns)) => format!("{ns}:{}", purl.name),
            (_, Some(ns)) => format!("{ns}/{}", purl.name),
            (_, None) => purl.name.clone(),
        };
        self.normalize_name(&raw)
    }

    /// Normalizes a package name for index lookups. PyPI names follow PEP 503
    /// (lower-case, runs of `-_.` collapse to `-`); other ecosystems are
    /// case-sensitive and returned unchanged.
    pub fn normalize_name(&self, name: &str) -> String {
        match self {
            Ecosystem::PyPI => pep503(name),
            _ => name.to_string(),
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.osv_name())
    }
}

impl From<Ecosystem> for String {
    fn from(e: Ecosystem) -> String {
        e.osv_name().to_string()
    }
}

/// PEP 503 name normalization.
pub fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_sep {
                out.push('-');
            }
            in_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            in_sep = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osv_and_purl_mapping_roundtrip() {
        for (ty, osv) in [
            ("npm", "npm"),
            ("cargo", "crates.io"),
            ("pypi", "PyPI"),
            ("maven", "Maven"),
            ("golang", "Go"),
        ] {
            let e = Ecosystem::from_purl_type(ty);
            assert_eq!(e.osv_name(), osv);
            assert_eq!(Ecosystem::from_osv(osv), e);
            assert!(e.scheme().is_some());
        }
        let deb = Ecosystem::from_osv("Debian:11");
        assert_eq!(deb.to_string(), "Debian:11");
        assert!(deb.scheme().is_none());
        assert_eq!(String::from(Ecosystem::Go), "Go");
    }

    #[test]
    fn package_names_follow_osv_conventions() {
        let p = Purl::parse("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1").unwrap();
        assert_eq!(
            Ecosystem::Maven.package_name(&p),
            "org.apache.logging.log4j:log4j-core"
        );
        let p = Purl::parse("pkg:golang/golang.org/x/net@v0.1.0").unwrap();
        assert_eq!(Ecosystem::Go.package_name(&p), "golang.org/x/net");
        let p = Purl::parse("pkg:npm/%40babel/core@7.0.0").unwrap();
        assert_eq!(Ecosystem::Npm.package_name(&p), "@babel/core");
        let p = Purl::parse("pkg:pypi/Zope.Interface@5").unwrap();
        assert_eq!(Ecosystem::PyPI.package_name(&p), "zope-interface");
    }

    #[test]
    fn pep503_collapses_runs() {
        assert_eq!(pep503("Foo__Bar.-baz"), "foo-bar-baz");
        assert_eq!(pep503("requests"), "requests");
    }
}
