//! Semantic Versioning 2.0.0 parsing and precedence.
//!
//! Used directly for crates.io, with a lenient front-end for npm
//! (leading `v`/`=` and surrounding whitespace) and as the backing model for
//! Go module versions (see [`super::golang`]).

use std::cmp::Ordering;
use std::fmt;

/// One dot-separated pre-release identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identifier {
    /// Purely numeric identifier, compared numerically.
    Numeric(u64),
    /// Identifier containing a letter or hyphen, compared in ASCII order.
    Alpha(String),
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Identifier::Numeric(a), Identifier::Numeric(b)) => a.cmp(b),
            // Numeric identifiers always have lower precedence than alphanumeric ones.
            (Identifier::Numeric(_), Identifier::Alpha(_)) => Ordering::Less,
            (Identifier::Alpha(_), Identifier::Numeric(_)) => Ordering::Greater,
            (Identifier::Alpha(a), Identifier::Alpha(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Identifier::Numeric(n) => write!(f, "{n}"),
            Identifier::Alpha(s) => f.write_str(s),
        }
    }
}

/// A SemVer 2.0.0 version. Equality and ordering ignore build metadata, as
/// the specification requires for precedence.
#[derive(Debug, Clone)]
pub struct SemVer {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
    /// Pre-release identifiers (empty for a release).
    pub pre: Vec<Identifier>,
    /// Build metadata identifiers (ignored for precedence).
    pub build: Vec<String>,
}

impl SemVer {
    /// Strict SemVer 2.0.0 parse: exactly `MAJOR.MINOR.PATCH[-PRE][+BUILD]`,
    /// no leading zeros in numeric parts, no prefixes.
    pub fn parse(s: &str) -> Result<SemVer, String> {
        let (rest, build) = match s.split_once('+') {
            Some((r, b)) => (r, parse_build(b)?),
            None => (s, Vec::new()),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((c, p)) => (c, parse_pre(p)?),
            None => (rest, Vec::new()),
        };
        let mut parts = core.split('.');
        let major = numeric_part(parts.next(), "major")?;
        let minor = numeric_part(parts.next(), "minor")?;
        let patch = numeric_part(parts.next(), "patch")?;
        if parts.next().is_some() {
            return Err("more than three numeric components".into());
        }
        Ok(SemVer {
            major,
            minor,
            patch,
            pre,
            build,
        })
    }

    /// npm-style lenient parse: trims whitespace and a leading `=` or `v`
    /// (as node-semver's `clean` does), then parses strictly.
    pub fn parse_npm(s: &str) -> Result<SemVer, String> {
        let t = s.trim();
        let t = t.strip_prefix('=').unwrap_or(t).trim_start();
        let t = t
            .strip_prefix('v')
            .or_else(|| t.strip_prefix('V'))
            .unwrap_or(t);
        SemVer::parse(t)
    }

    /// True when the version has pre-release identifiers.
    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

fn numeric_part(p: Option<&str>, what: &str) -> Result<u64, String> {
    let p = p.ok_or_else(|| format!("missing {what} component"))?;
    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{what} component {p:?} is not numeric"));
    }
    if p.len() > 1 && p.starts_with('0') {
        return Err(format!("{what} component {p:?} has a leading zero"));
    }
    p.parse()
        .map_err(|_| format!("{what} component {p:?} overflows"))
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn parse_pre(p: &str) -> Result<Vec<Identifier>, String> {
    p.split('.')
        .map(|id| {
            if !valid_ident(id) {
                return Err(format!("invalid pre-release identifier {id:?}"));
            }
            if id.bytes().all(|b| b.is_ascii_digit()) {
                if id.len() > 1 && id.starts_with('0') {
                    return Err(format!(
                        "numeric pre-release identifier {id:?} has a leading zero"
                    ));
                }
                id.parse()
                    .map(Identifier::Numeric)
                    .map_err(|_| format!("pre-release identifier {id:?} overflows"))
            } else {
                Ok(Identifier::Alpha(id.to_string()))
            }
        })
        .collect()
}

fn parse_build(b: &str) -> Result<Vec<String>, String> {
    b.split('.')
        .map(|id| {
            if valid_ident(id) {
                Ok(id.to_string())
            } else {
                Err(format!("invalid build identifier {id:?}"))
            }
        })
        .collect()
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A pre-release version has lower precedence than the release.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SemVer {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for SemVer {}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            let pre: Vec<String> = self.pre.iter().map(ToString::to_string).collect();
            write!(f, "-{}", pre.join("."))?;
        }
        if !self.build.is_empty() {
            write!(f, "+{}", self.build.join("."))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid() {
        for bad in [
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3-a..b",
            "1.2.3+",
            "1.2.3+a_b",
            "a.b.c",
            "v1.2.3",
            "",
            "1.2.99999999999999999999",
        ] {
            assert!(SemVer::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn npm_front_end_is_lenient() {
        assert_eq!(SemVer::parse_npm(" =v1.2.3 ").unwrap().to_string(), "1.2.3");
        assert_eq!(
            SemVer::parse_npm("V2.0.0-rc.1").unwrap().to_string(),
            "2.0.0-rc.1"
        );
    }

    #[test]
    fn display_roundtrips() {
        let v = SemVer::parse("1.0.0-alpha.1+build.5").unwrap();
        assert_eq!(v.to_string(), "1.0.0-alpha.1+build.5");
        assert!(v.is_prerelease());
    }
}
