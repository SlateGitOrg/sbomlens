//! Maven version ordering.
//!
//! A faithful re-implementation of Apache Maven 3.9's `ComparableVersion`
//! (the "Version Order Specification" in the POM reference): the version is
//! lower-cased and split into a tree of items on `.`, `-` and digit/letter
//! transitions; `-` and transitions open a nested list; trailing "null"
//! items (`0`, `""`/`ga`/`final`/`release`, empty lists) are removed from
//! each list; and items compare as
//! `alpha < beta < milestone < rc = cr < snapshot < "" = ga = final = release < sp < other qualifiers (lexically) < numbers`.

use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    /// Numeric item; digits with leading zeros stripped (arbitrary size).
    Int(String),
    /// Qualifier, already lower-cased and alias-resolved.
    Str(String),
    /// Nested list opened by `-` or a digit/letter transition.
    List(Vec<Item>),
}

const QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];
const RELEASE_INDEX: usize = 5;

fn comparable_qualifier(q: &str) -> String {
    match QUALIFIERS.iter().position(|x| *x == q) {
        Some(i) => i.to_string(),
        None => format!("{}-{q}", QUALIFIERS.len()),
    }
}

fn string_item(value: &str, followed_by_digit: bool) -> Item {
    let mut v = value;
    if followed_by_digit && value.len() == 1 {
        v = match value {
            "a" => "alpha",
            "b" => "beta",
            "m" => "milestone",
            other => other,
        };
    }
    let v = match v {
        "ga" | "final" | "release" => "",
        "cr" => "rc",
        other => other,
    };
    Item::Str(v.to_string())
}

fn int_item(digits: &str) -> Item {
    let t = digits.trim_start_matches('0');
    Item::Int(if t.is_empty() { "0".into() } else { t.into() })
}

fn parse_item(is_digit: bool, buf: &str) -> Item {
    if is_digit {
        int_item(buf)
    } else {
        string_item(buf, false)
    }
}

impl Item {
    fn is_null(&self) -> bool {
        match self {
            Item::Int(d) => d == "0",
            Item::Str(s) => comparable_qualifier(s) == RELEASE_INDEX.to_string(),
            Item::List(l) => l.is_empty(),
        }
    }

    /// Compares against "padding" (a missing item on the other side).
    fn cmp_null(&self) -> Ordering {
        match self {
            Item::Int(d) => {
                if d == "0" {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                }
            }
            Item::Str(s) => comparable_qualifier(s).cmp(&RELEASE_INDEX.to_string()),
            Item::List(l) => l
                .iter()
                .map(Item::cmp_null)
                .find(|o| *o != Ordering::Equal)
                .unwrap_or(Ordering::Equal),
        }
    }

    fn cmp_item(&self, other: &Item) -> Ordering {
        match (self, other) {
            (Item::Int(a), Item::Int(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (Item::Int(_), _) | (Item::List(_), Item::Str(_)) => Ordering::Greater,
            (Item::Str(_), Item::Int(_) | Item::List(_)) | (Item::List(_), Item::Int(_)) => {
                Ordering::Less
            }
            (Item::Str(a), Item::Str(b)) => comparable_qualifier(a).cmp(&comparable_qualifier(b)),
            (Item::List(a), Item::List(b)) => cmp_lists(a, b),
        }
    }
}

fn cmp_lists(a: &[Item], b: &[Item]) -> Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let r = match (a.get(i), b.get(i)) {
            (Some(l), Some(r)) => l.cmp_item(r),
            (Some(l), None) => l.cmp_null(),
            (None, Some(r)) => r.cmp_null().reverse(),
            (None, None) => Ordering::Equal,
        };
        if r != Ordering::Equal {
            return r;
        }
    }
    Ordering::Equal
}

fn normalize(list: &mut Vec<Item>) {
    let mut i = list.len();
    while i > 0 {
        i -= 1;
        if list[i].is_null() {
            list.remove(i);
        } else if !matches!(list[i], Item::List(_)) {
            break;
        }
    }
}

/// Arena-based builder mirroring Maven's stack of nested `ListItem`s.
struct Builder {
    /// All lists; index 0 is the root. Children are referenced by index.
    lists: Vec<Vec<Node>>,
    /// Creation order, used to normalize innermost lists first.
    stack: Vec<usize>,
    current: usize,
}

enum Node {
    Leaf(Item),
    Child(usize),
}

impl Builder {
    fn new() -> Self {
        Builder {
            lists: vec![Vec::new()],
            stack: vec![0],
            current: 0,
        }
    }

    fn push(&mut self, item: Item) {
        self.lists[self.current].push(Node::Leaf(item));
    }

    fn open_list(&mut self) {
        let idx = self.lists.len();
        self.lists.push(Vec::new());
        self.lists[self.current].push(Node::Child(idx));
        self.stack.push(idx);
        self.current = idx;
    }

    fn current_is_empty(&self) -> bool {
        self.lists[self.current].is_empty()
    }

    /// Normalizes lists innermost-first (reverse creation order, as Maven pops
    /// its stack) and assembles the tree.
    fn finish(mut self) -> Vec<Item> {
        let mut built: Vec<Option<Vec<Item>>> = (0..self.lists.len()).map(|_| None).collect();
        while let Some(idx) = self.stack.pop() {
            let nodes = std::mem::take(&mut self.lists[idx]);
            let mut items: Vec<Item> = nodes
                .into_iter()
                .map(|n| match n {
                    Node::Leaf(i) => i,
                    Node::Child(c) => Item::List(built[c].take().unwrap_or_default()),
                })
                .collect();
            normalize(&mut items);
            built[idx] = Some(items);
        }
        built[0].take().unwrap_or_default()
    }
}

/// A parsed Maven version.
#[derive(Debug, Clone)]
pub struct MavenVersion {
    original: String,
    items: Vec<Item>,
}

impl MavenVersion {
    /// Parses a Maven version. Every string is a valid Maven version, but an
    /// empty or whitespace-only string is rejected as meaningless.
    pub fn parse(input: &str) -> Result<MavenVersion, String> {
        let original = input.trim().to_string();
        if original.is_empty() {
            return Err("empty version".into());
        }
        let version = original.to_lowercase();
        let chars: Vec<char> = version.chars().collect();
        let mut b = Builder::new();
        let mut is_digit = false;
        let mut start = 0;
        let sub = |a: usize, z: usize| chars[a..z].iter().collect::<String>();
        for (i, &c) in chars.iter().enumerate() {
            if c == '.' || c == '-' {
                if i == start {
                    b.push(Item::Int("0".into()));
                } else {
                    b.push(parse_item(is_digit, &sub(start, i)));
                }
                start = i + 1;
                if c == '-' {
                    b.open_list();
                }
            } else if c.is_ascii_digit() {
                if !is_digit && i > start {
                    // 1.0.0.X1 < 1.0.0-X2: treat .X as -X for any qualifier X.
                    if !b.current_is_empty() {
                        b.open_list();
                    }
                    b.push(string_item(&sub(start, i), true));
                    start = i;
                    b.open_list();
                }
                is_digit = true;
            } else {
                if is_digit && i > start {
                    b.push(parse_item(true, &sub(start, i)));
                    start = i;
                    b.open_list();
                }
                is_digit = false;
            }
        }
        if chars.len() > start {
            if !is_digit && !b.current_is_empty() {
                b.open_list();
            }
            b.push(parse_item(is_digit, &sub(start, chars.len())));
        }
        Ok(MavenVersion {
            original,
            items: b.finish(),
        })
    }

    /// The canonical form Maven prints for this version (useful in tests and
    /// for spotting surprising parses).
    pub fn canonical(&self) -> String {
        fn render(items: &[Item], out: &mut String) {
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(if matches!(item, Item::List(_)) {
                        '-'
                    } else {
                        '.'
                    });
                }
                match item {
                    Item::Int(d) => out.push_str(d),
                    Item::Str(s) => out.push_str(s),
                    Item::List(l) => render(l, out),
                }
            }
        }
        let mut s = String::new();
        render(&self.items, &mut s);
        s
    }

    /// True when the version carries a qualifier that sorts before the release
    /// (alpha, beta, milestone, rc, snapshot).
    pub fn is_prerelease(&self) -> bool {
        fn walk(items: &[Item]) -> bool {
            items.iter().any(|i| match i {
                Item::Str(s) => QUALIFIERS
                    .iter()
                    .position(|q| q == s)
                    .is_some_and(|p| p < RELEASE_INDEX),
                Item::List(l) => walk(l),
                Item::Int(_) => false,
            })
        }
        walk(&self.items)
    }
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_lists(&self.items, &other.items)
    }
}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MavenVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MavenVersion {}

impl fmt::Display for MavenVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        MavenVersion::parse(s).unwrap().canonical()
    }

    #[test]
    fn canonical_forms() {
        assert_eq!(canon("1.0.0"), "1");
        assert_eq!(canon("1-ga"), "1");
        assert_eq!(canon("1.0-SNAPSHOT"), "1-snapshot");
        assert_eq!(canon("1a1"), "1-alpha-1");
        assert_eq!(canon("2.12.6.1"), "2.12.6.1");
        assert_eq!(canon("30.1-jre"), "30.1-jre");
    }

    #[test]
    fn prerelease_detection() {
        assert!(MavenVersion::parse("1.0-rc1").unwrap().is_prerelease());
        assert!(MavenVersion::parse("1.0-SNAPSHOT").unwrap().is_prerelease());
        assert!(!MavenVersion::parse("1.0-sp1").unwrap().is_prerelease());
        assert!(!MavenVersion::parse("30.1-jre").unwrap().is_prerelease());
        assert!(MavenVersion::parse("   ").is_err());
        assert_eq!(MavenVersion::parse(" 1.0 ").unwrap().to_string(), "1.0");
    }
}
