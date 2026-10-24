//! PEP 440 version parsing, normalization and ordering (PyPI).
//!
//! The parser accepts the permissive syntax PEP 440 defines for
//! normalization (case-insensitive, optional `v` prefix, `-`/`_`/`.`
//! separators, spelled-out pre-release labels, implicit post releases
//! `1.0-1`, implicit numbers) and the ordering follows the PEP's
//! "Summary of permitted suffixes and relative ordering" exactly, including
//! the special case that `X.devN` sorts before `X.aN`.

use std::cmp::Ordering;
use std::fmt;

/// Pre-release phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PreKind {
    /// Alpha (`a`, `alpha`).
    Alpha,
    /// Beta (`b`, `beta`).
    Beta,
    /// Release candidate (`rc`, `c`, `pre`, `preview`).
    Rc,
}

/// One local-version segment (`+ubuntu.1` has two).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LocalSegment {
    /// Numeric segment (sorts after any alphanumeric segment).
    Num(u64),
    /// Alphanumeric segment, lower-cased.
    Str(String),
}

impl Ord for LocalSegment {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (LocalSegment::Num(a), LocalSegment::Num(b)) => a.cmp(b),
            (LocalSegment::Num(_), LocalSegment::Str(_)) => Ordering::Greater,
            (LocalSegment::Str(_), LocalSegment::Num(_)) => Ordering::Less,
            (LocalSegment::Str(a), LocalSegment::Str(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for LocalSegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A parsed PEP 440 version.
#[derive(Debug, Clone)]
pub struct Pep440 {
    /// Epoch (`N!`), 0 when absent.
    pub epoch: u64,
    /// Release segment, as written (trailing zeros are ignored for ordering).
    pub release: Vec<u64>,
    /// Pre-release phase and number.
    pub pre: Option<(PreKind, u64)>,
    /// Post-release number.
    pub post: Option<u64>,
    /// Development-release number.
    pub dev: Option<u64>,
    /// Local version label segments.
    pub local: Vec<LocalSegment>,
}

/// Cursor over the lower-cased input.
struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat_number(&mut self) -> Option<u64> {
        let start = self.i;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.i += 1;
        }
        if start == self.i {
            return None;
        }
        // Digits only; the parse can fail only on overflow, which we cap.
        std::str::from_utf8(&self.s[start..self.i])
            .ok()
            .and_then(|d| d.parse().ok())
            .or(Some(u64::MAX))
    }

    fn eat_label(&mut self, labels: &[&str]) -> Option<usize> {
        let rest = &self.s[self.i..];
        for (idx, l) in labels.iter().enumerate() {
            if rest.starts_with(l.as_bytes()) {
                self.i += l.len();
                return Some(idx);
            }
        }
        None
    }

    fn is_sep(b: u8) -> bool {
        matches!(b, b'-' | b'_' | b'.')
    }

    /// `[-_.]?LABEL[-_.]?N?` — returns the label index and optional number,
    /// or rewinds and returns `None` when no label is present.
    fn eat_labelled(&mut self, labels: &[&str]) -> Option<(usize, Option<u64>)> {
        let save = self.i;
        if self.peek().is_some_and(Self::is_sep) {
            self.i += 1;
        }
        let Some(idx) = self.eat_label(labels) else {
            self.i = save;
            return None;
        };
        // Optional separator, but only if digits follow it.
        let before_sep = self.i;
        if self.peek().is_some_and(Self::is_sep) {
            self.i += 1;
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.i = before_sep;
            }
        }
        Some((idx, self.eat_number()))
    }
}

impl Pep440 {
    /// Parses and normalizes a PEP 440 version string.
    pub fn parse(input: &str) -> Result<Pep440, String> {
        let lower = input.trim().to_ascii_lowercase();
        let mut c = Cursor {
            s: lower.as_bytes(),
            i: 0,
        };
        if c.peek() == Some(b'v') {
            c.i += 1;
        }
        // Epoch and first release number.
        let first = c.eat_number().ok_or("expected a release number")?;
        let (epoch, mut release) = if c.peek() == Some(b'!') {
            c.i += 1;
            let r = c.eat_number().ok_or("expected a release number after the epoch")?;
            (first, vec![r])
        } else {
            (0, vec![first])
        };
        while c.peek() == Some(b'.') && c.s.get(c.i + 1).is_some_and(u8::is_ascii_digit) {
            c.i += 1;
            release.push(c.eat_number().unwrap_or(0));
        }
        // Pre-release.
        const PRE: [&str; 8] = ["alpha", "a", "beta", "b", "preview", "pre", "rc", "c"];
        let pre = c.eat_labelled(&PRE).map(|(idx, n)| {
            let kind = match idx {
                0 | 1 => PreKind::Alpha,
                2 | 3 => PreKind::Beta,
                _ => PreKind::Rc,
            };
            (kind, n.unwrap_or(0))
        });
        // Post-release: implicit `-N` or labelled.
        let mut post = None;
        if c.peek() == Some(b'-') && c.s.get(c.i + 1).is_some_and(u8::is_ascii_digit) {
            c.i += 1;
            post = c.eat_number();
        } else if let Some((_, n)) = c.eat_labelled(&["post", "rev", "r"]) {
            post = Some(n.unwrap_or(0));
        }
        // Development release.
        let dev = c.eat_labelled(&["dev"]).map(|(_, n)| n.unwrap_or(0));
        // Local version.
        let mut local = Vec::new();
        if c.peek() == Some(b'+') {
            c.i += 1;
            let rest = std::str::from_utf8(&c.s[c.i..]).map_err(|_| "invalid UTF-8")?;
            for seg in rest.split(['-', '_', '.']) {
                if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err(format!("invalid local version segment {seg:?}"));
                }
                local.push(if seg.bytes().all(|b| b.is_ascii_digit()) {
                    LocalSegment::Num(seg.parse().unwrap_or(u64::MAX))
                } else {
                    LocalSegment::Str(seg.to_string())
                });
            }
            c.i = c.s.len();
        }
        if c.i != c.s.len() {
            return Err(format!(
                "unexpected trailing text {:?}",
                String::from_utf8_lossy(&c.s[c.i..])
            ));
        }
        Ok(Pep440 {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    /// True for pre-releases and development releases.
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }

    /// Equality key: the normalized form with trailing release zeros removed,
    /// so `1.0` and `1.0.0` share a key exactly as they compare equal.
    pub fn key(&self) -> String {
        let mut v = self.clone();
        v.release = self.trimmed_release().to_vec();
        v.to_string()
    }

    fn trimmed_release(&self) -> &[u64] {
        let mut end = self.release.len();
        while end > 1 && self.release[end - 1] == 0 {
            end -= 1;
        }
        &self.release[..end]
    }
}

/// Sort-key helper: `NegInf < Val(x) < PosInf`.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Bound<T> {
    NegInf,
    Val(T),
    PosInf,
}

impl Ord for Pep440 {
    fn cmp(&self, other: &Self) -> Ordering {
        fn pre_key(v: &Pep440) -> Bound<(PreKind, u64)> {
            match (v.pre, v.post, v.dev) {
                // X.devN sorts before X.aN: treat it as having an infinitely low pre-release.
                (None, None, Some(_)) => Bound::NegInf,
                (None, _, _) => Bound::PosInf,
                (Some(p), _, _) => Bound::Val(p),
            }
        }
        fn post_key(v: &Pep440) -> Bound<u64> {
            v.post.map_or(Bound::NegInf, Bound::Val)
        }
        fn dev_key(v: &Pep440) -> Bound<u64> {
            v.dev.map_or(Bound::PosInf, Bound::Val)
        }
        fn local_key(v: &Pep440) -> Bound<&[LocalSegment]> {
            if v.local.is_empty() {
                Bound::NegInf
            } else {
                Bound::Val(&v.local)
            }
        }
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| self.trimmed_release().cmp(other.trimmed_release()))
            .then_with(|| pre_key(self).cmp(&pre_key(other)))
            .then_with(|| post_key(self).cmp(&post_key(other)))
            .then_with(|| dev_key(self).cmp(&dev_key(other)))
            .then_with(|| local_key(self).cmp(&local_key(other)))
    }
}

impl PartialOrd for Pep440 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Pep440 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Pep440 {}

/// Formats the PEP 440 normalized form.
impl fmt::Display for Pep440 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch != 0 {
            write!(f, "{}!", self.epoch)?;
        }
        let rel: Vec<String> = self.release.iter().map(ToString::to_string).collect();
        f.write_str(&rel.join("."))?;
        if let Some((kind, n)) = self.pre {
            let l = match kind {
                PreKind::Alpha => "a",
                PreKind::Beta => "b",
                PreKind::Rc => "rc",
            };
            write!(f, "{l}{n}")?;
        }
        if let Some(n) = self.post {
            write!(f, ".post{n}")?;
        }
        if let Some(n) = self.dev {
            write!(f, ".dev{n}")?;
        }
        if !self.local.is_empty() {
            let segs: Vec<String> = self
                .local
                .iter()
                .map(|s| match s {
                    LocalSegment::Num(n) => n.to_string(),
                    LocalSegment::Str(s) => s.clone(),
                })
                .collect();
            write!(f, "+{}", segs.join("."))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> String {
        Pep440::parse(s).unwrap().to_string()
    }

    #[test]
    fn normalization_examples_from_pep_440() {
        assert_eq!(norm("1.0-alpha1"), "1.0a1");
        assert_eq!(norm("1.0.ALPHA.1"), "1.0a1");
        assert_eq!(norm("1.0c1"), "1.0rc1");
        assert_eq!(norm("1.0pre1"), "1.0rc1");
        assert_eq!(norm("1.0preview_2"), "1.0rc2");
        assert_eq!(norm("1.0-1"), "1.0.post1");
        assert_eq!(norm("1.0-r4"), "1.0.post4");
        assert_eq!(norm("1.0.rev"), "1.0.post0");
        assert_eq!(norm("1.0.dev"), "1.0.dev0");
        assert_eq!(norm("1.0a"), "1.0a0");
        assert_eq!(norm("v1.0"), "1.0");
        assert_eq!(norm("  1.0  "), "1.0");
        assert_eq!(norm("1.0+ubuntu-1"), "1.0+ubuntu.1");
        assert_eq!(norm("1!2.0b3.post4.dev5+Local_7"), "1!2.0b3.post4.dev5+local.7");
    }

    #[test]
    fn key_matches_equality() {
        let k = |s: &str| Pep440::parse(s).unwrap().key();
        assert_eq!(k("1.0.0"), k("1"));
        assert_eq!(k("1.0-1"), k("1.post1"));
        assert_ne!(k("1.0"), k("1.0+local"));
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "abc", "1.0+", "1.0+a..b", "1.0foo", "1!", "1.0-", "1.0.post1dev2x"] {
            assert!(Pep440::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn prerelease_flag() {
        assert!(Pep440::parse("1.0rc1").unwrap().is_prerelease());
        assert!(Pep440::parse("1.0.dev1").unwrap().is_prerelease());
        assert!(!Pep440::parse("1.0.post1").unwrap().is_prerelease());
    }
}
