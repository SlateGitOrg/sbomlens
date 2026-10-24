//! Go module versions.
//!
//! Go module versions are SemVer with a mandatory `v` prefix, with two
//! extras: the `vMAJOR` / `vMAJOR.MINOR` shorthands accepted by
//! `golang.org/x/mod/semver`, and the `+incompatible` build suffix, which
//! (like all build metadata) does not take part in ordering.
//!
//! Pseudo-versions (`v0.0.0-20210226172049-e18ecbb05110` and friends) are
//! valid SemVer pre-releases, so ordering them needs no special case: SemVer
//! precedence already places `vX.Y.(Z+1)-0.TIMESTAMP-REV` after `vX.Y.Z` and
//! before `vX.Y.(Z+1)`. [`PseudoVersion`] exposes the decoded parts for
//! reporting. OSV advisories for the Go ecosystem omit the `v` prefix
//! (`"fixed": "0.7.0"`), so the prefix is optional on input.

use super::semver::{Identifier, SemVer};

/// Parses a Go module version, with or without the leading `v`.
pub fn parse(s: &str) -> Result<SemVer, String> {
    let t = s.trim();
    let t = t.strip_prefix('v').unwrap_or(t);
    if let Ok(v) = SemVer::parse(t) {
        return Ok(v);
    }
    // vMAJOR and vMAJOR.MINOR shorthands (only without pre-release/build).
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() < 3 {
            let mut full = parts.join(".");
            for _ in parts.len()..3 {
                full.push_str(".0");
            }
            return SemVer::parse(&full);
        }
    }
    SemVer::parse(t)
}

/// The decoded parts of a Go pseudo-version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudoVersion {
    /// The tagged version this pseudo-version builds on, if any
    /// (`None` for the `vX.0.0-TIMESTAMP-REV` form).
    pub base: Option<String>,
    /// The UTC commit timestamp, `yyyymmddhhmmss`.
    pub timestamp: String,
    /// The 12-character commit hash prefix.
    pub revision: String,
}

/// Decodes a Go pseudo-version, following the three forms in the Go modules
/// reference: `vX.0.0-TIMESTAMP-REV`, `vX.Y.Z-PRE.0.TIMESTAMP-REV` and
/// `vX.Y.(Z+1)-0.TIMESTAMP-REV`. Returns `None` for ordinary versions.
pub fn pseudo_version(s: &str) -> Option<PseudoVersion> {
    let v = parse(s).ok()?;
    let last = match v.pre.last()? {
        Identifier::Alpha(a) => a,
        Identifier::Numeric(_) => return None,
    };
    let (timestamp, revision) = last.split_once('-')?;
    if timestamp.len() != 14
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
        || revision.is_empty()
        || !revision.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return None;
    }
    let n = v.pre.len();
    let base = if n == 1 {
        // vX.0.0-TIMESTAMP-REV: no base tag.
        if v.minor != 0 || v.patch != 0 {
            return None;
        }
        None
    } else if v.pre[n - 2] == Identifier::Numeric(0) {
        if n == 2 {
            // vX.Y.(Z+1)-0.TIMESTAMP-REV: base is the release vX.Y.Z.
            let patch = v.patch.checked_sub(1)?;
            Some(format!("v{}.{}.{patch}", v.major, v.minor))
        } else {
            // vX.Y.Z-PRE.0.TIMESTAMP-REV: base is the pre-release vX.Y.Z-PRE.
            let pre: Vec<String> = v.pre[..n - 2].iter().map(ToString::to_string).collect();
            Some(format!(
                "v{}.{}.{}-{}",
                v.major,
                v.minor,
                v.patch,
                pre.join(".")
            ))
        }
    } else {
        return None;
    };
    Some(PseudoVersion {
        base,
        timestamp: timestamp.to_string(),
        revision: revision.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_three_pseudo_version_forms() {
        let p = pseudo_version("v0.0.0-20191109021931-daa7c04131f5").unwrap();
        assert_eq!(p.base, None);
        assert_eq!(p.timestamp, "20191109021931");
        assert_eq!(p.revision, "daa7c04131f5");

        let p = pseudo_version("v1.2.4-0.20191109021931-daa7c04131f5").unwrap();
        assert_eq!(p.base.as_deref(), Some("v1.2.3"));

        let p = pseudo_version("v1.2.3-pre.0.20191109021931-daa7c04131f5").unwrap();
        assert_eq!(p.base.as_deref(), Some("v1.2.3-pre"));

        let p = pseudo_version("v2.0.1-0.20200101000000-abcdefabcdef+incompatible").unwrap();
        assert_eq!(p.base.as_deref(), Some("v2.0.0"));
    }

    #[test]
    fn rejects_non_pseudo_versions() {
        for s in [
            "v1.2.3",
            "v1.2.3-rc.1",
            "v1.2.0-20191109021931-daa7c04131f5", // single-id form needs X.0.0
            "v1.2.3-1.20191109021931-daa7c04131f5", // must be .0.
            "v1.2.3-0.2019110902193-daa7c04131f5", // 13-digit timestamp
            "v1.2.0-0.20191109021931-daa7c04131f5x!",
            "v1.2.0-0.5",
            "garbage",
            "v1.2.0-0.20191109021931-",
        ] {
            assert!(pseudo_version(s).is_none(), "{s}");
        }
        // vX.Y.0-0.TS-REV would need base vX.Y.-1
        assert!(pseudo_version("v1.2.0-0.20191109021931-daa7c04131f5").is_none());
    }

    #[test]
    fn shorthand_and_prefix() {
        assert_eq!(parse("v1").unwrap().to_string(), "1.0.0");
        assert_eq!(parse("v1.4").unwrap().to_string(), "1.4.0");
        assert_eq!(parse("0.7.0").unwrap().to_string(), "0.7.0");
        assert!(parse("v1.2.3.4").is_err());
        assert!(parse("vx").is_err());
    }
}
