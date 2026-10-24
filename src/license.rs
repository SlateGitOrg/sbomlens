//! SPDX license expressions.
//!
//! SBOM producers spell the same licensing in many ways (`MIT OR Apache-2.0`
//! vs `Apache-2.0 OR MIT`, `(MIT)`, `mit`). To report only *real* license
//! changes in a diff, expressions are parsed (SPDX 2.3 Annex D grammar:
//! `OR` binds looser than `AND`, which binds looser than `WITH`) and
//! canonicalized: nested operators of the same kind are flattened, operands
//! are sorted and de-duplicated, and identifiers compare case-insensitively
//! (as SPDX specifies). Free-text license names that are not expressions are
//! kept verbatim as [`License::Text`].

use std::fmt;

use serde::Serialize;

/// A parsed SPDX license expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseExpr {
    /// A single license identifier or `LicenseRef-`, optionally `+` and `WITH` an exception.
    Id {
        /// Identifier as written (case preserved for display).
        id: String,
        /// The `+` ("or later") operator.
        or_later: bool,
        /// The exception after `WITH`.
        exception: Option<String>,
    },
    /// Conjunction: all operands apply.
    And(Vec<LicenseExpr>),
    /// Disjunction: a choice of operands.
    Or(Vec<LicenseExpr>),
}

/// License information attached to a component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum License {
    /// A valid SPDX expression, canonicalized.
    #[serde(serialize_with = "ser_display")]
    Expr(LicenseExpr),
    /// A free-text license name that is not an SPDX expression.
    Text(String),
}

fn ser_display<S: serde::Serializer>(e: &LicenseExpr, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(e)
}

/// Error from the expression parser.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid SPDX expression {input:?}: {reason}")]
pub struct LicenseError {
    /// The rejected input.
    pub input: String,
    /// Why it was rejected.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Open,
    Close,
    And,
    Or,
    With,
    Word(String),
}

fn tokenize(s: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, toks: &mut Vec<Tok>| {
        if word.is_empty() {
            return;
        }
        let w = std::mem::take(word);
        toks.push(match w.to_ascii_uppercase().as_str() {
            "AND" => Tok::And,
            "OR" => Tok::Or,
            "WITH" => Tok::With,
            _ => Tok::Word(w),
        });
    };
    for c in s.chars() {
        match c {
            '(' | ')' => {
                flush(&mut word, &mut toks);
                toks.push(if c == '(' { Tok::Open } else { Tok::Close });
            }
            c if c.is_whitespace() => flush(&mut word, &mut toks),
            c => word.push(c),
        }
    }
    flush(&mut word, &mut toks);
    toks
}

fn valid_id(w: &str) -> bool {
    let body = w.strip_suffix('+').unwrap_or(w);
    !body.is_empty()
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'))
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn or(&mut self) -> Result<LicenseExpr, String> {
        let mut terms = vec![self.and()?];
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            terms.push(self.and()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            LicenseExpr::Or(terms)
        })
    }

    fn and(&mut self) -> Result<LicenseExpr, String> {
        let mut terms = vec![self.primary()?];
        while self.peek() == Some(&Tok::And) {
            self.pos += 1;
            terms.push(self.primary()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            LicenseExpr::And(terms)
        })
    }

    fn primary(&mut self) -> Result<LicenseExpr, String> {
        match self.next() {
            Some(Tok::Open) => {
                let e = self.or()?;
                match self.next() {
                    Some(Tok::Close) => Ok(e),
                    _ => Err("unbalanced parenthesis".into()),
                }
            }
            Some(Tok::Word(w)) => {
                if !valid_id(&w) {
                    return Err(format!("invalid license identifier {w:?}"));
                }
                let (id, or_later) = match w.strip_suffix('+') {
                    Some(base) => (base.to_string(), true),
                    None => (w, false),
                };
                let exception = if self.peek() == Some(&Tok::With) {
                    self.pos += 1;
                    match self.next() {
                        Some(Tok::Word(e)) if valid_id(&e) && !e.ends_with('+') => Some(e),
                        _ => return Err("expected an exception identifier after WITH".into()),
                    }
                } else {
                    None
                };
                Ok(LicenseExpr::Id {
                    id,
                    or_later,
                    exception,
                })
            }
            Some(t) => Err(format!("unexpected token {t:?}")),
            None => Err("unexpected end of expression".into()),
        }
    }
}

impl LicenseExpr {
    /// Parses and canonicalizes an SPDX license expression.
    pub fn parse(input: &str) -> Result<LicenseExpr, LicenseError> {
        let err = |reason: String| LicenseError {
            input: input.to_string(),
            reason,
        };
        let mut p = Parser {
            toks: tokenize(input),
            pos: 0,
        };
        let e = p.or().map_err(err)?;
        if p.pos != p.toks.len() {
            return Err(err("trailing tokens".into()));
        }
        Ok(e.canonical())
    }

    /// Flattens same-operator nesting, sorts operands and removes duplicates.
    #[must_use]
    pub fn canonical(self) -> LicenseExpr {
        fn gather(e: LicenseExpr, is_and: bool, out: &mut Vec<LicenseExpr>) {
            match e {
                LicenseExpr::And(v) if is_and => v.into_iter().for_each(|x| gather(x, true, out)),
                LicenseExpr::Or(v) if !is_and => v.into_iter().for_each(|x| gather(x, false, out)),
                other => out.push(other.canonical()),
            }
        }
        match self {
            id @ LicenseExpr::Id { .. } => id,
            LicenseExpr::And(v) | LicenseExpr::Or(v) if v.len() == 1 => {
                v.into_iter().next().map_or(LicenseExpr::And(Vec::new()), LicenseExpr::canonical)
            }
            e => {
                let is_and = matches!(e, LicenseExpr::And(_));
                let mut out = Vec::new();
                let items = match e {
                    LicenseExpr::And(v) | LicenseExpr::Or(v) => v,
                    LicenseExpr::Id { .. } => unreachable!("handled above"),
                };
                for x in items {
                    gather(x, is_and, &mut out);
                }
                out.sort_by_key(LicenseExpr::key);
                out.dedup_by(|a, b| a.key() == b.key());
                if out.len() == 1 {
                    out.remove(0)
                } else if is_and {
                    LicenseExpr::And(out)
                } else {
                    LicenseExpr::Or(out)
                }
            }
        }
    }

    /// Case-insensitive comparison key of the canonical form.
    pub fn key(&self) -> String {
        self.to_string().to_ascii_lowercase()
    }

    /// All license identifiers mentioned, in canonical order.
    pub fn ids(&self) -> Vec<&str> {
        match self {
            LicenseExpr::Id { id, .. } => vec![id.as_str()],
            LicenseExpr::And(v) | LicenseExpr::Or(v) => v.iter().flat_map(LicenseExpr::ids).collect(),
        }
    }
}

impl fmt::Display for LicenseExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LicenseExpr::Id {
                id,
                or_later,
                exception,
            } => {
                f.write_str(id)?;
                if *or_later {
                    f.write_str("+")?;
                }
                if let Some(e) = exception {
                    write!(f, " WITH {e}")?;
                }
                Ok(())
            }
            LicenseExpr::And(v) => {
                let parts: Vec<String> = v
                    .iter()
                    .map(|x| match x {
                        LicenseExpr::Or(_) => format!("({x})"),
                        _ => x.to_string(),
                    })
                    .collect();
                f.write_str(&parts.join(" AND "))
            }
            LicenseExpr::Or(v) => {
                let parts: Vec<String> = v.iter().map(ToString::to_string).collect();
                f.write_str(&parts.join(" OR "))
            }
        }
    }
}

impl License {
    /// Interprets an SBOM license string: a valid SPDX expression becomes
    /// [`License::Expr`], anything else is kept as [`License::Text`].
    /// `NOASSERTION`/`NONE`/empty mean "no information" and yield `None`.
    pub fn from_sbom(raw: &str) -> Option<License> {
        let t = raw.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("NOASSERTION") || t.eq_ignore_ascii_case("NONE") {
            return None;
        }
        Some(match LicenseExpr::parse(t) {
            Ok(e) => License::Expr(e),
            Err(_) => License::Text(t.to_string()),
        })
    }

    /// Combines several declared licenses (CycloneDX allows a list) into one
    /// conjunction. Text entries make the result text.
    pub fn all_of(items: Vec<License>) -> Option<License> {
        let mut exprs = Vec::new();
        let mut texts = Vec::new();
        for l in items {
            match l {
                License::Expr(e) => exprs.push(e),
                License::Text(t) => texts.push(t),
            }
        }
        if texts.is_empty() {
            return match exprs.len() {
                0 => None,
                1 => exprs.pop().map(License::Expr),
                _ => Some(License::Expr(LicenseExpr::And(exprs).canonical())),
            };
        }
        let mut all: Vec<String> = exprs.iter().map(ToString::to_string).collect();
        all.extend(texts);
        all.sort();
        all.dedup();
        Some(License::Text(all.join(" AND ")))
    }

    /// Comparison key: case-insensitive canonical text.
    pub fn key(&self) -> String {
        match self {
            License::Expr(e) => e.key(),
            License::Text(t) => t.to_ascii_lowercase(),
        }
    }
}

impl fmt::Display for License {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            License::Expr(e) => e.fmt(f),
            License::Text(t) => f.write_str(t),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        LicenseExpr::parse(s).unwrap().to_string()
    }

    #[test]
    fn canonical_ordering_and_flattening() {
        assert_eq!(canon("MIT OR Apache-2.0"), "Apache-2.0 OR MIT");
        assert_eq!(canon("(MIT)"), "MIT");
        assert_eq!(canon("MIT OR (Apache-2.0 OR MIT)"), "Apache-2.0 OR MIT");
        assert_eq!(canon("MIT AND (BSD-3-Clause OR Apache-2.0)"), "(Apache-2.0 OR BSD-3-Clause) AND MIT");
        assert_eq!(canon("GPL-2.0-or-later WITH Classpath-exception-2.0 or mit"), "GPL-2.0-or-later WITH Classpath-exception-2.0 OR mit");
        assert_eq!(canon("LGPL-2.1+"), "LGPL-2.1+");
        assert_eq!(canon("DocumentRef-x:LicenseRef-y"), "DocumentRef-x:LicenseRef-y");
    }

    #[test]
    fn precedence_and_binds_tighter() {
        let e = LicenseExpr::parse("A OR B AND C").unwrap();
        assert!(matches!(e, LicenseExpr::Or(ref v) if v.len() == 2));
        assert_eq!(e.ids(), ["A", "B", "C"]);
    }

    #[test]
    fn keys_are_case_insensitive() {
        assert_eq!(
            LicenseExpr::parse("mit or apache-2.0").unwrap().key(),
            LicenseExpr::parse("Apache-2.0 OR MIT").unwrap().key()
        );
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["", "MIT OR", "(MIT", "MIT)", "MIT WITH", "MIT AND AND BSD", "MIT WITH X+", "MIT/X11", "OR MIT"] {
            assert!(LicenseExpr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sbom_license_interpretation() {
        assert_eq!(License::from_sbom("NOASSERTION"), None);
        assert_eq!(License::from_sbom(" none "), None);
        assert_eq!(License::from_sbom("BSD-like license").unwrap(), License::Text("BSD-like license".into()));
        let all = License::all_of(vec![
            License::from_sbom("MIT").unwrap(),
            License::from_sbom("ISC").unwrap(),
            License::from_sbom("MIT").unwrap(),
        ])
        .unwrap();
        assert_eq!(all.to_string(), "ISC AND MIT");
        let mixed = License::all_of(vec![License::from_sbom("MIT").unwrap(), License::Text("Custom".into())]).unwrap();
        assert_eq!(mixed.to_string(), "Custom AND MIT");
        assert_eq!(mixed.key(), "custom and mit");
        assert_eq!(License::all_of(vec![]), None);
        assert_eq!(serde_json::to_string(&all).unwrap(), "\"ISC AND MIT\"");
    }
}
