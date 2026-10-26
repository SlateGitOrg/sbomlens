//! Property-based tests: round-trips, normalization equivalences, order
//! axioms, panic-free version sorting and an interval-model oracle for OSV
//! range evaluation.

// Test-data generators build strings incrementally and index small tables.
#![allow(
    clippy::format_push_string,
    clippy::cast_possible_truncation,
    clippy::field_reassign_with_default
)]

use std::cmp::Ordering;
use std::collections::BTreeMap;

use proptest::prelude::*;
use sbomlens::ecosystem::Ecosystem;
use sbomlens::license::LicenseExpr;
use sbomlens::osv::range::CompiledRange;
use sbomlens::osv::{Event, Range};
use sbomlens::purl::Purl;
use sbomlens::version::{compare, sort_by_tolerant, Scheme, Version};

fn cmp(s: Scheme, a: &str, b: &str) -> Ordering {
    compare(s, a, b).unwrap()
}

/// Antisymmetry and agreement with equality keys on a pair.
fn pair_axioms(s: Scheme, a: &str, b: &str) {
    let (ab, ba) = (cmp(s, a, b), cmp(s, b, a));
    assert_eq!(ab, ba.reverse(), "antisymmetry {a} {b}");
    let key = |v: &str| Version::parse(s, v).unwrap().key();
    assert_eq!(
        ab == Ordering::Equal,
        key(a) == key(b),
        "key consistency {a} {b}"
    );
}

/// `a <= b <= c` implies `a <= c`.
fn transitive(s: Scheme, a: &str, b: &str, c: &str) -> bool {
    !(cmp(s, a, b) != Ordering::Greater
        && cmp(s, b, c) != Ordering::Greater
        && cmp(s, a, c) == Ordering::Greater)
}

/// Antisymmetry, transitivity and agreement with equality keys on a triple.
fn order_axioms(s: Scheme, a: &str, b: &str, c: &str) {
    pair_axioms(s, a, b);
    assert!(transitive(s, a, b, c), "transitivity {a} <= {b} <= {c}");
}

fn semver() -> impl Strategy<Value = String> {
    let ident = prop_oneof![
        (0u64..20).prop_map(|n| n.to_string()),
        "[a-z][a-z0-9-]{0,3}".prop_map(String::from),
    ];
    (
        0u64..4,
        0u64..4,
        0u64..4,
        prop::collection::vec(ident, 0..3),
        prop::option::of("[a-z0-9]{1,3}"),
    )
        .prop_map(|(a, b, c, pre, build)| {
            let mut s = format!("{a}.{b}.{c}");
            if !pre.is_empty() {
                s.push('-');
                s.push_str(&pre.join("."));
            }
            if let Some(b) = build {
                s.push('+');
                s.push_str(&b);
            }
            s
        })
}

/// PEP 440 components rendered canonically and in a randomly chosen
/// alternative spelling permitted by the PEP's normalization rules.
fn pep440_pair() -> impl Strategy<Value = (String, String)> {
    (
        0u64..3,
        prop::collection::vec(0u64..12, 1..4),
        prop::option::of((0usize..3, 0u64..5)),
        prop::option::of(0u64..4),
        prop::option::of(0u64..4),
        prop::option::of(prop::collection::vec(
            "[a-z][a-z0-9]{0,2}|[1-9][0-9]{0,2}|0",
            1..3,
        )),
        any::<u64>(),
    )
        .prop_map(|(epoch, rel, pre, post, dev, local, seed)| {
            let pick = |n: u64, k: u64| ((seed >> (k * 3)) % n) as usize;
            let mut canon = String::new();
            let mut alt = String::new();
            // The optional "v" prefix precedes the epoch.
            alt.push_str(if pick(2, 0) == 0 { "v" } else { "" });
            if epoch > 0 {
                canon.push_str(&format!("{epoch}!"));
                alt.push_str(&format!("{epoch}!"));
            }
            let r: Vec<String> = rel.iter().map(ToString::to_string).collect();
            canon.push_str(&r.join("."));
            alt.push_str(&r.join("."));
            let seps = ["", ".", "-", "_"];
            if let Some((kind, n)) = pre {
                let (c, spellings): (&str, &[&str]) = match kind {
                    0 => ("a", &["a", "alpha", "A", "ALPHA"]),
                    1 => ("b", &["b", "beta", "Beta"]),
                    _ => ("rc", &["rc", "c", "pre", "preview", "RC"]),
                };
                canon.push_str(&format!("{c}{n}"));
                alt.push_str(&format!(
                    "{}{}{}{n}",
                    seps[pick(4, 1)],
                    spellings[pick(spellings.len() as u64, 2)],
                    seps[pick(4, 3)]
                ));
            }
            if let Some(n) = post {
                canon.push_str(&format!(".post{n}"));
                let spell = ["post", "rev", "r", "POST"][pick(4, 4)];
                if pick(2, 5) == 0 && pre.is_none() {
                    alt.push_str(&format!("-{n}"));
                } else {
                    alt.push_str(&format!(
                        "{}{spell}{}{n}",
                        seps[pick(4, 6)],
                        seps[pick(4, 7)]
                    ));
                }
            }
            if let Some(n) = dev {
                canon.push_str(&format!(".dev{n}"));
                alt.push_str(&format!("{}dev{}{n}", seps[pick(4, 8)], seps[pick(4, 9)]));
            }
            if let Some(l) = local {
                canon.push_str(&format!("+{}", l.join(".")));
                let sep = [".", "-", "_"][pick(3, 10)];
                alt.push_str(&format!("+{}", l.join(sep)));
            }
            (canon, alt)
        })
}

/// Arbitrary Maven spellings, including the null aliases (`0`, `ga`,
/// `final`) and mid-version qualifiers on which Maven's ordering has cycles.
fn maven() -> impl Strategy<Value = String> {
    "[0-9]{1,2}([.-]([0-9]{1,2}|alpha|beta|rc|cr|sp|snapshot|ga|final|a|b|m|x|jre)){0,4}"
        .prop_map(String::from)
}

/// Release-style Maven versions: a dotted numeric release, then up to two
/// `-`-separated qualifiers or numbers, with no null alias (`0`, `ga`,
/// `final`, `release`) after the release part. Maven's ordering is a total
/// order on this shape.
fn maven_release_style() -> impl Strategy<Value = String> {
    "[0-9]{1,2}(\\.[0-9]{1,2}){0,3}(-([1-9][0-9]?|alpha|beta|rc|cr|sp|snapshot|jre|android|m[1-9]|rc[1-9]|b[1-9])){0,2}"
        .prop_map(String::from)
}

fn segment() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9@ %#?&=+:~_-][a-zA-Z0-9 .@%#?&=+:~_-]{0,7}".prop_map(String::from)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn purl_display_parse_roundtrip(
        ty in prop::sample::select(vec!["generic", "npm", "maven", "cargo", "golang", "deb"]),
        ns in prop::collection::vec(segment(), 0..3),
        name in "[^/]{1,10}",
        version in prop::option::of("[a-zA-Z0-9 .@:+~_/-]{1,10}"),
        quals in prop::collection::btree_map("[a-z][a-z0-9._-]{0,5}", "[ -~]{1,8}", 0..3),
        subpath in prop::collection::vec(segment(), 0..3),
    ) {
        let p = Purl {
            ty: ty.to_string(),
            namespace: (!ns.is_empty()).then(|| ns.join("/")),
            name,
            version,
            qualifiers: quals.into_iter().collect::<BTreeMap<_, _>>(),
            subpath: (!subpath.is_empty()).then(|| subpath.join("/")),
        };
        let text = p.to_string();
        let back = Purl::parse(&text).unwrap();
        prop_assert_eq!(&back, &p);
        prop_assert_eq!(back.to_string(), text);
    }

    #[test]
    fn semver_order_axioms(a in semver(), b in semver(), c in semver()) {
        order_axioms(Scheme::SemVer, &a, &b, &c);
        order_axioms(Scheme::Go, &format!("v{a}"), &b, &format!("v{c}"));
    }

    #[test]
    fn pep440_alternative_spellings_normalize((canon, alt) in pep440_pair()) {
        let a = Version::parse(Scheme::Pep440, &canon).unwrap();
        let b = Version::parse(Scheme::Pep440, &alt).unwrap();
        prop_assert_eq!(a.try_cmp(&b), Some(Ordering::Equal), "{} vs {}", canon, alt);
        prop_assert_eq!(a.key(), b.key());
        if let Version::Pep440(p) = &b {
            prop_assert_eq!(p.to_string(), canon);
        }
    }

    #[test]
    fn pep440_order_axioms((a, _) in pep440_pair(), (b, _) in pep440_pair(), (c, _) in pep440_pair()) {
        order_axioms(Scheme::Pep440, &a, &b, &c);
    }

    /// Maven's own ordering is not transitive on arbitrary spellings (Maven
    /// 3.9.9 orders `1-a < 1-ga-alpha < 1 < 1-a`; see `version::maven`), and
    /// sbomlens reproduces it. Antisymmetry and key consistency always hold.
    #[test]
    fn maven_order_axioms(a in maven(), b in maven(), c in maven()) {
        pair_axioms(Scheme::Maven, &a, &b);
        pair_axioms(Scheme::Maven, &b, &c);
        pair_axioms(Scheme::Maven, &a, &c);
    }

    #[test]
    fn maven_release_style_order_axioms(
        a in maven_release_style(),
        b in maven_release_style(),
        c in maven_release_style(),
    ) {
        order_axioms(Scheme::Maven, &a, &b, &c);
        order_axioms(Scheme::Maven, &c, &b, &a);
    }

    /// The tolerant sort never panics on arbitrary Maven spellings, returns a
    /// permutation, and whenever Maven's ordering is consistent on the sample
    /// the result is sorted under it.
    #[test]
    fn tolerant_sort_of_maven_versions(raw in prop::collection::vec(maven(), 0..24)) {
        let mut items: Vec<(String, Version)> = raw
            .iter()
            .map(|v| (v.clone(), Version::parse(Scheme::Maven, v).unwrap()))
            .collect();
        sort_by_tolerant(&mut items, |a, b| a.1.try_cmp(&b.1).unwrap());
        let mut got: Vec<String> = items.iter().map(|(v, _)| v.clone()).collect();
        got.sort();
        let mut want = raw.clone();
        want.sort();
        prop_assert_eq!(got, want);
        // Maven's order on the sample, then a transitivity check over all triples.
        let n = items.len();
        let le: Vec<Vec<bool>> = items
            .iter()
            .map(|a| items.iter().map(|b| a.1.try_cmp(&b.1) != Some(Ordering::Greater)).collect())
            .collect();
        let consistent = (0..n).all(|i| {
            (0..n).all(|j| (0..n).all(|k| !(le[i][j] && le[j][k]) || le[i][k]))
        });
        if consistent {
            for w in items.windows(2) {
                prop_assert_ne!(w[0].1.try_cmp(&w[1].1), Some(Ordering::Greater));
            }
        }
    }

    #[test]
    fn generic_order_axioms(a in "[a-z0-9.:+~-]{1,10}", b in "[a-z0-9.:+~-]{1,10}", c in "[a-z0-9.:+~-]{1,10}") {
        prop_assume!([&a, &b, &c].iter().all(|s| s.chars().any(|ch| ch.is_ascii_alphanumeric())));
        order_axioms(Scheme::Generic, &a, &b, &c);
    }

    /// OSV range evaluation agrees with a plain interval model: random
    /// non-overlapping [introduced, fixed) / [introduced, last_affected]
    /// intervals over 0.0.0..0.0.39, events shuffled.
    #[test]
    fn range_evaluation_matches_interval_model(
        cuts in prop::collection::btree_set(1u64..40, 0..8),
        open_from_zero in any::<bool>(),
        inclusive in prop::collection::vec(any::<bool>(), 8),
        shuffle in any::<u64>(),
    ) {
        let cuts: Vec<u64> = cuts.into_iter().collect();
        let mut points = Vec::new();
        if open_from_zero { points.push(0); }
        points.extend(cuts);
        let mut intervals = Vec::new(); // (lo, hi, inclusive_hi); hi None = unbounded
        for (k, pair) in points.chunks(2).enumerate() {
            intervals.push((pair[0], pair.get(1).copied(), inclusive[k % inclusive.len()]));
        }
        let mut events = Vec::new();
        for &(lo, hi, incl) in &intervals {
            let mut e = Event::default();
            e.introduced = Some(if lo == 0 { "0".into() } else { format!("0.0.{lo}") });
            events.push(e);
            if let Some(h) = hi {
                let mut e = Event::default();
                if incl { e.last_affected = Some(format!("0.0.{}", h - 1)); } else { e.fixed = Some(format!("0.0.{h}")); }
                events.push(e);
            }
        }
        let n = events.len().max(1);
        events.rotate_left((shuffle as usize) % n);
        let range = Range { kind: "SEMVER".into(), events };
        let compiled = CompiledRange::compile(&range, &Ecosystem::Crates).unwrap();
        for v in 0u64..45 {
            let expected = intervals.iter().any(|&(lo, hi, _)| v >= lo && hi.is_none_or(|h| v < h));
            let got = compiled.evaluate(&Version::parse(Scheme::SemVer, &format!("0.0.{v}")).unwrap()).is_some();
            prop_assert_eq!(got, expected, "v=0.0.{} intervals={:?}", v, intervals);
        }
    }

    #[test]
    fn license_canonical_form_is_idempotent_and_commutative(
        ids in prop::collection::vec(prop::sample::select(vec!["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "GPL-2.0-only", "LicenseRef-x"]), 1..5),
        ops in prop::collection::vec(any::<bool>(), 4),
    ) {
        let mut expr = ids[0].to_string();
        let mut rev = ids[0].to_string();
        for (i, id) in ids.iter().enumerate().skip(1) {
            let op = if ops[i - 1] { "AND" } else { "OR" };
            expr = format!("({expr}) {op} {id}");
            rev = format!("{id} {op} ({rev})");
        }
        let a = LicenseExpr::parse(&expr).unwrap();
        let b = LicenseExpr::parse(&rev).unwrap();
        prop_assert_eq!(a.key(), b.key());
        let again = LicenseExpr::parse(&a.to_string()).unwrap();
        prop_assert_eq!(again.to_string(), a.to_string());
    }
}

/// One version string for an npm package: strict SemVer (release or
/// pre-release), a SemVer-looking string that only the generic scheme accepts
/// (`1.0.3.a`), or arbitrary junk. The narrow numeric range makes the three
/// shapes interleave, which is what broke the old comparator's transitivity.
fn mixed_version() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => (1u64..2, 0u64..2, 0u64..50, 0usize..5).prop_map(|(a, b, c, shape)| {
            let base = format!("{a}.{b}.{c}");
            match shape {
                0 => base,
                1 => format!("{base}-rc.1"),
                2 => format!("{base}-beta"),
                3 => format!("{base}.a"),
                _ => format!("{base}.{c}"),
            }
        }),
        1 => semver(),
        1 => "[a-z0-9.+_-]{1,6}".prop_map(String::from),
    ]
}

fn npm_graph(versions: &[String]) -> sbomlens::graph::SbomGraph {
    use sbomlens::graph::{Component, GraphBuilder, SbomFormat};
    let mut b = GraphBuilder::new(SbomFormat::CycloneDx("1.6".into()), None);
    for (i, v) in versions.iter().enumerate() {
        let purl = Purl::parse(&format!("pkg:npm/p@{v}")).unwrap();
        b.add(Component::new(format!("r{i}"), "p").with_purl(purl));
    }
    b.finish()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Regression for the diff sort panic: many versions of one package,
    /// mixing scheme-parseable, generic-only and unparseable strings, must
    /// diff without panicking, and the outcome counts must not depend on the
    /// order components appear in the SBOM.
    #[test]
    fn diff_total_on_mixed_versions(
        (old, shuffled) in prop::collection::vec(mixed_version(), 100..300usize)
            .prop_flat_map(|v| (Just(v.clone()), Just(v).prop_shuffle())),
        new in prop::collection::vec(mixed_version(), 0..40),
    ) {
        use sbomlens::diff::{diff, ChangeKind};
        let new_g = npm_graph(&new);
        let a = diff(&npm_graph(&old), &new_g);
        let b = diff(&npm_graph(&shuffled), &new_g);
        prop_assert_eq!(a.unchanged, b.unchanged);
        for k in [ChangeKind::Added, ChangeKind::Removed] {
            prop_assert_eq!(a.count(k), b.count(k));
        }
        prop_assert_eq!(a.changes.len(), b.changes.len());
    }
}
