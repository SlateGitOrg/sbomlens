//! Best-effort ordering for versions of unknown ecosystems.
//!
//! The string is split into maximal runs of digits and of letters; any other
//! character is a separator. Runs compare pairwise: numbers numerically,
//! words case-insensitively, and a number sorts after a word at the same
//! position (`1.0.1` > `1.0a`). A missing trailing run counts as smaller. This is used only to label
//! SBOM diff entries as upgrades/downgrades for ecosystems without a known
//! scheme, and such labels are marked as best-effort in reports.

use std::cmp::Ordering;

/// One run of the generic tokenizer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Run {
    Num(String),
    Word(String),
}

impl Ord for Run {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Run::Num(a), Run::Num(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (Run::Num(_), Run::Word(_)) => Ordering::Greater,
            (Run::Word(_), Run::Num(_)) => Ordering::Less,
            (Run::Word(a), Run::Word(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Run {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A version tokenized for generic comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GenericVersion {
    runs: Vec<Run>,
}

impl GenericVersion {
    /// Equality key (runs joined with `.`).
    pub fn key(&self) -> String {
        let parts: Vec<&str> = self
            .runs
            .iter()
            .map(|r| match r {
                Run::Num(s) | Run::Word(s) => s.as_str(),
            })
            .collect();
        parts.join(".")
    }

    /// Tokenizes `input`. Fails only when it has no digits or letters at all.
    pub fn parse(input: &str) -> Result<GenericVersion, String> {
        let mut runs = Vec::new();
        let mut cur = String::new();
        let mut cur_digit = false;
        let flush = |cur: &mut String, digit: bool, runs: &mut Vec<Run>| {
            if !cur.is_empty() {
                let s = std::mem::take(cur);
                runs.push(if digit {
                    let t = s.trim_start_matches('0');
                    Run::Num(if t.is_empty() { "0".into() } else { t.into() })
                } else {
                    Run::Word(s.to_ascii_lowercase())
                });
            }
        };
        for c in input.chars() {
            if c.is_ascii_digit() || c.is_alphabetic() {
                let d = c.is_ascii_digit();
                if d != cur_digit {
                    flush(&mut cur, cur_digit, &mut runs);
                    cur_digit = d;
                }
                cur.push(c);
            } else {
                flush(&mut cur, cur_digit, &mut runs);
            }
        }
        flush(&mut cur, cur_digit, &mut runs);
        if runs.is_empty() {
            return Err("no digits or letters".into());
        }
        Ok(GenericVersion { runs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lt(a: &str, b: &str) {
        let (va, vb) = (
            GenericVersion::parse(a).unwrap(),
            GenericVersion::parse(b).unwrap(),
        );
        assert!(va < vb, "{a} < {b}");
    }

    #[test]
    fn orders_common_shapes() {
        lt("1.9", "1.10");
        lt("1.0", "1.0.1");
        lt("7.50.3-1", "7.50.3-2");
        lt("1.0a", "1.0.1");
        lt("2:1.0", "2:1.1");
        assert_eq!(
            GenericVersion::parse("1.01").unwrap(),
            GenericVersion::parse("1-1").unwrap()
        );
        assert!(GenericVersion::parse("...").is_err());
        assert_eq!(GenericVersion::parse("v1-02b").unwrap().key(), "v.1.2.b");
    }
}
