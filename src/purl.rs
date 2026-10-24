//! Package URL (purl) parsing and canonical formatting.
//!
//! Implements the parsing and building rules of the
//! [purl specification](https://github.com/package-url/purl-spec): components
//! are split right-to-left (subpath, qualifiers, then scheme/type/namespace/
//! name/version), percent-decoded, and normalized according to the
//! type-specific rules that matter for identity (for example `pypi` names are
//! lower-cased with `_` replaced by `-`, `github` names are lower-cased).
//!
//! The canonical string form produced by [`Purl`]'s `Display` impl sorts
//! qualifiers, drops empty qualifier values and percent-encodes everything
//! outside the unreserved set, so two purls that denote the same package
//! compare equal both as values and as strings.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// Errors produced while parsing a purl.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PurlError {
    /// The string does not start with the `pkg:` scheme.
    #[error("purl must start with the 'pkg:' scheme: {0:?}")]
    MissingScheme(String),
    /// No package type segment was found.
    #[error("purl has no type: {0:?}")]
    MissingType(String),
    /// The type contains characters outside `[a-z0-9.+-]` or starts with a digit.
    #[error("invalid purl type {0:?}")]
    InvalidType(String),
    /// The name segment is empty.
    #[error("purl has no name: {0:?}")]
    MissingName(String),
    /// A qualifier key is not valid.
    #[error("invalid qualifier key {0:?}")]
    InvalidQualifierKey(String),
    /// A qualifier is not of the form `key=value`.
    #[error("malformed qualifier {0:?}")]
    MalformedQualifier(String),
    /// The same qualifier key appears twice.
    #[error("duplicate qualifier key {0:?}")]
    DuplicateQualifier(String),
    /// A `%XX` escape is malformed or decodes to invalid UTF-8.
    #[error("invalid percent-encoding in {0:?}")]
    BadEncoding(String),
    /// A type-specific rule is violated (e.g. `swift` requires a namespace).
    #[error("{ty} purl {purl:?}: {reason}")]
    TypeRule {
        /// The purl type.
        ty: String,
        /// The offending purl text.
        purl: String,
        /// Which rule was violated.
        reason: &'static str,
    },
}

/// A parsed, normalized Package URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Purl {
    /// Package type, always lower-case (`npm`, `pypi`, `maven`, ...).
    pub ty: String,
    /// Optional namespace (`@scope` for npm, group id for maven, module path prefix for golang).
    pub namespace: Option<String>,
    /// Package name.
    pub name: String,
    /// Optional version, verbatim after percent-decoding.
    pub version: Option<String>,
    /// Qualifiers with lower-case keys; empty values are dropped.
    pub qualifiers: BTreeMap<String, String>,
    /// Optional subpath with `.`/`..`/empty segments removed.
    pub subpath: Option<String>,
}

impl Purl {
    /// Parses a purl string. Equivalent to `s.parse::<Purl>()`.
    pub fn parse(s: &str) -> Result<Self, PurlError> {
        s.parse()
    }

    /// Builds a purl from parts, applying the same normalization as parsing.
    pub fn new(
        ty: &str,
        namespace: Option<&str>,
        name: &str,
        version: Option<&str>,
    ) -> Result<Self, PurlError> {
        let mut p = Purl {
            ty: ty.to_ascii_lowercase(),
            namespace: namespace.filter(|n| !n.is_empty()).map(str::to_string),
            name: name.to_string(),
            version: version.filter(|v| !v.is_empty()).map(str::to_string),
            qualifiers: BTreeMap::new(),
            subpath: None,
        };
        validate_type(&p.ty)?;
        if p.name.is_empty() {
            return Err(PurlError::MissingName(name.to_string()));
        }
        p.normalize_for_type();
        Ok(p)
    }

    /// The package identity without version, qualifiers or subpath, in canonical
    /// form (e.g. `pkg:npm/%40angular/core`). Two versions of one package share it.
    pub fn package_key(&self) -> String {
        let mut out = format!("pkg:{}/", self.ty);
        if let Some(ns) = &self.namespace {
            for seg in ns.split('/') {
                out.push_str(&encode(seg, false));
                out.push('/');
            }
        }
        out.push_str(&encode(&self.name, false));
        out
    }

    /// The namespace and name joined with `/` (unencoded), e.g. `@angular/core`
    /// or `golang.org/x/net`.
    pub fn full_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{ns}/{}", self.name),
            None => self.name.clone(),
        }
    }

    /// Returns a copy with a different version.
    #[must_use]
    pub fn with_version(&self, version: Option<&str>) -> Purl {
        let mut p = self.clone();
        p.version = version.filter(|v| !v.is_empty()).map(str::to_string);
        p
    }

    fn normalize_for_type(&mut self) {
        match self.ty.as_str() {
            "bitbucket" | "github" | "composer" => {
                self.namespace = self.namespace.as_ref().map(|n| n.to_ascii_lowercase());
                self.name = self.name.to_ascii_lowercase();
            }
            "pypi" => {
                self.name = self.name.to_ascii_lowercase().replace('_', "-");
            }
            "huggingface" => {
                self.version = self.version.as_ref().map(|v| v.to_ascii_lowercase());
            }
            "mlflow" => {
                let databricks = self
                    .qualifiers
                    .get("repository_url")
                    .is_some_and(|u| u.contains("azuredatabricks"));
                if databricks {
                    self.name = self.name.to_ascii_lowercase();
                }
            }
            _ => {}
        }
    }

    fn check_type_rules(&self, raw: &str) -> Result<(), PurlError> {
        let rule = |reason| {
            Err(PurlError::TypeRule {
                ty: self.ty.clone(),
                purl: raw.to_string(),
                reason,
            })
        };
        match self.ty.as_str() {
            "conan" => {
                let has_channel = self.qualifiers.contains_key("channel");
                if self.namespace.is_some() != has_channel {
                    return rule("namespace and the 'channel' qualifier must be given together");
                }
            }
            "cran" if self.version.is_none() => return rule("a version is required"),
            "swift" => {
                if self.namespace.is_none() {
                    return rule("a namespace is required");
                }
                if self.version.is_none() {
                    return rule("a version is required");
                }
            }
            "hackage" if self.version.is_none() => return rule("a version is required"),
            "cpan" => {
                if self.namespace.is_some() && self.name.contains("::") {
                    return rule("a distribution name (with namespace) must not contain '::'");
                }
                if self.namespace.is_none() && self.name.contains('-') {
                    return rule("a module name (no namespace) must not contain '-'");
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn validate_type(ty: &str) -> Result<(), PurlError> {
    let valid = !ty.is_empty()
        && !ty.as_bytes()[0].is_ascii_digit()
        && ty
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(PurlError::InvalidType(ty.to_string()))
    }
}

fn valid_qualifier_key(key: &str) -> bool {
    !key.is_empty()
        && !key.as_bytes()[0].is_ascii_digit()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Percent-decodes `s`. Fails on truncated escapes or invalid UTF-8.
pub fn decode(s: &str) -> Result<String, PurlError> {
    if !s.contains('%') {
        return Ok(s.to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| PurlError::BadEncoding(s.to_string()))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| PurlError::BadEncoding(s.to_string()))
}

/// Percent-encodes everything outside the unreserved set plus `:`;
/// `keep_slash` also leaves `/` unencoded (used for qualifier values).
fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'-' | b'_' | b'~' | b':')
            || (keep_slash && b == b'/');
        if keep {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn clean_segments(path: &str) -> Result<Vec<String>, PurlError> {
    let mut segs = Vec::new();
    for raw in path.split('/') {
        if raw.is_empty() {
            continue;
        }
        let seg = decode(raw)?;
        if seg == "." || seg == ".." {
            continue;
        }
        segs.push(seg);
    }
    Ok(segs)
}

impl FromStr for Purl {
    type Err = PurlError;

    fn from_str(raw: &str) -> Result<Self, PurlError> {
        let s = raw.trim();
        // 1. subpath (right of '#')
        let (rest, subpath) = match s.rsplit_once('#') {
            Some((r, sp)) => {
                let segs = clean_segments(sp)?;
                (r, (!segs.is_empty()).then(|| segs.join("/")))
            }
            None => (s, None),
        };
        // 2. qualifiers (right of '?')
        let (rest, qualifiers) = match rest.rsplit_once('?') {
            Some((r, q)) => (r, parse_qualifiers(q)?),
            None => (rest, BTreeMap::new()),
        };
        // 3. scheme
        let (scheme, rest) = rest
            .split_once(':')
            .ok_or_else(|| PurlError::MissingScheme(raw.to_string()))?;
        if !scheme.eq_ignore_ascii_case("pkg") {
            return Err(PurlError::MissingScheme(raw.to_string()));
        }
        let rest = rest.trim_matches('/');
        // 4. type
        let (ty, rest) = rest
            .split_once('/')
            .ok_or_else(|| PurlError::MissingType(raw.to_string()))?;
        let ty = ty.to_ascii_lowercase();
        validate_type(&ty)?;
        // 5. version (right of the last '@' that follows the last '/')
        let (rest, version) = match rest.rsplit_once('@') {
            Some((r, v)) if !v.contains('/') => {
                (r, Some(decode(v)?).filter(|v| !v.is_empty()))
            }
            _ => (rest, None),
        };
        // 6. name and namespace (an empty last segment means "no name")
        let (ns_raw, name_raw) = match rest.rsplit_once('/') {
            Some((ns, n)) => (Some(ns), n),
            None => (None, rest),
        };
        let name = decode(name_raw)?;
        if name.is_empty() {
            return Err(PurlError::MissingName(raw.to_string()));
        }
        let namespace = match ns_raw {
            Some(ns) => {
                let segs = clean_segments(ns)?;
                (!segs.is_empty()).then(|| segs.join("/"))
            }
            None => None,
        };
        let mut purl = Purl {
            ty,
            namespace,
            name,
            version,
            qualifiers,
            subpath,
        };
        purl.normalize_for_type();
        purl.check_type_rules(raw)?;
        Ok(purl)
    }
}

fn parse_qualifiers(q: &str) -> Result<BTreeMap<String, String>, PurlError> {
    let mut map = BTreeMap::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| PurlError::MalformedQualifier(pair.to_string()))?;
        let key = decode(k)?.to_ascii_lowercase();
        if !valid_qualifier_key(&key) {
            return Err(PurlError::InvalidQualifierKey(key));
        }
        let value = decode(v)?;
        if value.is_empty() {
            continue;
        }
        if map.insert(key.clone(), value).is_some() {
            return Err(PurlError::DuplicateQualifier(key));
        }
    }
    Ok(map)
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.package_key())?;
        if let Some(v) = &self.version {
            write!(f, "@{}", encode(v, false))?;
        }
        if !self.qualifiers.is_empty() {
            let q: Vec<String> = self
                .qualifiers
                .iter()
                .map(|(k, v)| format!("{k}={}", encode(v, true)))
                .collect();
            write!(f, "?{}", q.join("&"))?;
        }
        if let Some(sp) = &self.subpath {
            let segs: Vec<String> = sp.split('/').map(|s| encode(s, false)).collect();
            write!(f, "#{}", segs.join("/"))?;
        }
        Ok(())
    }
}

impl serde::Serialize for Purl {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scoped_npm() {
        let p = Purl::parse("pkg:npm/%40angular/animation@12.3.1").unwrap();
        assert_eq!(p.namespace.as_deref(), Some("@angular"));
        assert_eq!(p.name, "animation");
        assert_eq!(p.full_name(), "@angular/animation");
        assert_eq!(p.to_string(), "pkg:npm/%40angular/animation@12.3.1");
        assert_eq!(p.package_key(), "pkg:npm/%40angular/animation");
    }

    #[test]
    fn unencoded_at_in_namespace_is_accepted() {
        let p = Purl::parse("pkg:npm/@babel/core@7.0.0").unwrap();
        assert_eq!(p.namespace.as_deref(), Some("@babel"));
        assert_eq!(p.version.as_deref(), Some("7.0.0"));
    }

    #[test]
    fn golang_pseudo_version_and_subpath() {
        let p = Purl::parse(
            "pkg:golang/golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110#http2/hpack",
        )
        .unwrap();
        assert_eq!(p.namespace.as_deref(), Some("golang.org/x"));
        assert_eq!(p.name, "net");
        assert_eq!(p.subpath.as_deref(), Some("http2/hpack"));
    }

    #[test]
    fn qualifiers_sorted_and_empty_dropped() {
        let p = Purl::parse("pkg:deb/debian/curl@7.5?distro=jessie&arch=i386&empty=").unwrap();
        assert_eq!(p.to_string(), "pkg:deb/debian/curl@7.5?arch=i386&distro=jessie");
    }

    #[test]
    fn rejects_bad_inputs() {
        assert!(matches!(
            Purl::parse("npm/foo"),
            Err(PurlError::MissingScheme(_))
        ));
        assert!(matches!(
            Purl::parse("pkg:npm/foo?a"),
            Err(PurlError::MalformedQualifier(_))
        ));
        assert!(matches!(
            Purl::parse("pkg:npm/foo?a=1&A=2"),
            Err(PurlError::DuplicateQualifier(_))
        ));
        assert!(matches!(
            Purl::parse("pkg:npm/fo%zzo"),
            Err(PurlError::BadEncoding(_))
        ));
        assert!(matches!(
            Purl::parse("pkg:npm/%FF%FE"),
            Err(PurlError::BadEncoding(_))
        ));
    }

    #[test]
    fn new_normalizes_like_parse() {
        let p = Purl::new("PyPI", None, "Django_Rest", Some("3.0")).unwrap();
        assert_eq!(p.to_string(), "pkg:pypi/django-rest@3.0");
        assert!(Purl::new("pypi", None, "", None).is_err());
        assert!(Purl::new("1x", None, "a", None).is_err());
        assert_eq!(p.with_version(None).to_string(), "pkg:pypi/django-rest");
    }
}
