//! Per-ecosystem version-ordering suites built from the specifications'
//! own examples. Each `ascending` list must be strictly increasing under the
//! scheme (every pair is checked, not just neighbours), and each `equal`
//! pair must compare equal.
//!
//! Sources:
//! * SemVer 2.0.0, section 11 (precedence) — <https://semver.org/#spec-item-11>
//! * PEP 440, "Summary of permitted suffixes and relative ordering" and the
//!   normalization section — <https://peps.python.org/pep-0440/>
//! * Maven: `ComparableVersionTest` from apache/maven tag `maven-3.9.9`
//!   (Apache-2.0) and the POM reference "Version Order Specification"
//! * Go: the modules reference, "Pseudo-versions" — <https://go.dev/ref/mod#pseudo-versions>

use std::cmp::Ordering;

use sbomlens::version::{compare, Scheme};

fn ascending(scheme: Scheme, versions: &[&str]) {
    for (i, a) in versions.iter().enumerate() {
        for (j, b) in versions.iter().enumerate() {
            let got = compare(scheme, a, b).unwrap_or_else(|e| panic!("{e}"));
            let want = i.cmp(&j);
            assert_eq!(got, want, "{scheme}: expected {a} {want:?} {b}, got {got:?}");
        }
    }
}

fn equal(scheme: Scheme, a: &str, b: &str) {
    assert_eq!(
        compare(scheme, a, b).unwrap_or_else(|e| panic!("{e}")),
        Ordering::Equal,
        "{scheme}: expected {a} == {b}"
    );
    assert_eq!(compare(scheme, b, a).unwrap(), Ordering::Equal);
}

fn less(scheme: Scheme, a: &str, b: &str) {
    assert_eq!(compare(scheme, a, b).unwrap(), Ordering::Less, "{scheme}: {a} < {b}");
    assert_eq!(compare(scheme, b, a).unwrap(), Ordering::Greater, "{scheme}: {b} > {a}");
}

// ---------------------------------------------------------------- SemVer ----

#[test]
fn semver_spec_item_11() {
    // 11.2: numeric comparison of major, minor, patch.
    ascending(Scheme::SemVer, &["1.0.0", "2.0.0", "2.1.0", "2.1.1"]);
    // 11.3: a pre-release has lower precedence than the normal version.
    less(Scheme::SemVer, "1.0.0-alpha", "1.0.0");
    // 11.4: the canonical example chain.
    ascending(
        Scheme::SemVer,
        &[
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ],
    );
    // Section 10: build metadata does not affect precedence.
    equal(Scheme::SemVer, "1.0.0+20130313144700", "1.0.0");
    equal(Scheme::SemVer, "1.0.0-beta+exp.sha.5114f85", "1.0.0-beta");
    // Numeric identifiers sort below alphanumeric ones; ASCII order for text.
    ascending(Scheme::SemVer, &["1.0.0-1", "1.0.0-2", "1.0.0-10", "1.0.0-A", "1.0.0-a"]);
    // Large components are compared numerically, not lexically.
    less(Scheme::SemVer, "2.0.0", "10.0.0");
}

#[test]
fn npm_uses_semver_precedence_with_lenient_input() {
    ascending(
        Scheme::Npm,
        &["0.1.7", "0.1.10", "0.1.12", "1.19.0", "1.20.3", "4.17.1", "4.21.2", "5.0.0-beta.1", "5.0.0"],
    );
    equal(Scheme::Npm, "v1.2.3", "1.2.3");
    equal(Scheme::Npm, "=1.2.3", "1.2.3");
    assert!(compare(Scheme::Npm, "1.2", "1.2.0").is_err(), "npm versions need three parts");
}

#[test]
fn crates_io_is_strict_semver() {
    ascending(Scheme::SemVer, &["0.1.43", "0.2.0", "0.2.23", "1.5.4", "1.5.5", "1.6.0"]);
    assert!(compare(Scheme::SemVer, "v1.0.0", "1.0.0").is_err());
    assert!(compare(Scheme::SemVer, "1.0", "1.0.0").is_err());
}

// -------------------------------------------------------------------- Go ----

#[test]
fn go_pseudo_versions_order_between_their_neighbours() {
    ascending(
        Scheme::Go,
        &[
            // vX.0.0-TIMESTAMP-REV (no base tag): ordered by commit timestamp,
            // and below every tagged v0.x release.
            "v0.0.0-20191109021931-daa7c04131f5",
            "v0.0.0-20210226172049-e18ecbb05110",
            "v0.0.0-20220906165146-f3363e06e74c",
            "v0.1.0",
            "v1.2.3",
            // vX.Y.(Z+1)-0.TIMESTAMP-REV: after v1.2.3, before v1.2.4.
            "v1.2.4-0.20191109021931-daa7c04131f5",
            "v1.2.4-0.20200101000000-0123456789ab",
            "v1.2.4-pre",
            // vX.Y.Z-PRE.0.TIMESTAMP-REV: after v1.2.4-pre, before v1.2.4-pre.1.
            "v1.2.4-pre.0.20191109021931-daa7c04131f5",
            "v1.2.4-pre.1",
            "v1.2.4",
        ],
    );
}

#[test]
fn go_osv_spelling_and_incompatible() {
    // OSV Go advisories write versions without the leading v.
    equal(Scheme::Go, "v0.7.0", "0.7.0");
    // +incompatible is build metadata: no effect on ordering.
    equal(Scheme::Go, "v2.0.0+incompatible", "v2.0.0");
    less(Scheme::Go, "v20.10.7+incompatible", "v20.10.8+incompatible");
    // Shorthands accepted by golang.org/x/mod/semver.
    equal(Scheme::Go, "v1", "v1.0.0");
    equal(Scheme::Go, "v1.4", "v1.4.0");
}

// ---------------------------------------------------------------- PEP 440 ----

#[test]
fn pep440_summary_of_relative_ordering() {
    // Verbatim from PEP 440 "Summary of permitted suffixes and relative ordering".
    ascending(
        Scheme::Pep440,
        &[
            "1.dev0",
            "1.0.dev456",
            "1.0a1",
            "1.0a2.dev456",
            "1.0a12.dev456",
            "1.0a12",
            "1.0b1.dev456",
            "1.0b2",
            "1.0b2.post345.dev456",
            "1.0b2.post345",
            "1.0rc1.dev456",
            "1.0rc1",
            "1.0",
            "1.0+abc.5",
            "1.0+abc.7",
            "1.0+5",
            "1.0.post456.dev34",
            "1.0.post456",
            "1.0.15",
            "1.1.dev1",
        ],
    );
}

#[test]
fn pep440_epochs_release_padding_and_local() {
    // Epochs dominate everything else.
    ascending(Scheme::Pep440, &["2013.10", "2014.04", "1!1.0", "1!1.1", "2!0.1"]);
    // Release segments compare with zero padding.
    equal(Scheme::Pep440, "1.0", "1.0.0");
    equal(Scheme::Pep440, "1", "1.0.0.0");
    less(Scheme::Pep440, "1.0", "1.0.1");
    // Local versions: numeric segments sort after alphanumeric ones,
    // and a longer local label sorts after its prefix.
    ascending(Scheme::Pep440, &["1.0", "1.0+abc", "1.0+abc.1", "1.0+abd", "1.0+1", "1.0+2"]);
    // PEP 440 normalization: alternative spellings are equal.
    equal(Scheme::Pep440, "1.0-alpha1", "1.0a1");
    equal(Scheme::Pep440, "1.0c1", "1.0rc1");
    equal(Scheme::Pep440, "1.0-1", "1.0.post1");
    equal(Scheme::Pep440, "1.0-r1", "1.0.post1");
    equal(Scheme::Pep440, "1.0.dev", "1.0.dev0");
    equal(Scheme::Pep440, "v1.0", "1.0");
    equal(Scheme::Pep440, "1.0+ubuntu-1", "1.0+ubuntu.1");
    equal(Scheme::Pep440, "1.0.0PREVIEW2", "1.0.0rc2");
    // Real versions seen in the bundled PyPI fixture.
    ascending(Scheme::Pep440, &["2022.12.7", "2023.5.7", "2023.7.22", "2024.7.4"]);
    ascending(Scheme::Pep440, &["1.26.14", "1.26.17", "1.26.18", "1.26.19", "2.0.0a1", "2.0.0"]);
}

// ------------------------------------------------------------------ Maven ----

#[test]
fn maven_comparable_version_qualifier_order() {
    // ComparableVersionTest.VERSIONS_QUALIFIER (maven-3.9.9).
    ascending(
        Scheme::Maven,
        &[
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ],
    );
}

#[test]
fn maven_comparable_version_number_order() {
    // ComparableVersionTest.VERSIONS_NUMBER (maven-3.9.9).
    ascending(
        Scheme::Maven,
        &[
            "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1",
            "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11",
            "11.a", "11b", "11c", "11m",
        ],
    );
}

#[test]
fn maven_comparable_version_equality() {
    // ComparableVersionTest.testVersionsEqual (maven-3.9.9).
    for (a, b) in [
        ("1", "1"),
        ("1", "1.0"),
        ("1", "1.0.0"),
        ("1.0", "1.0.0"),
        ("1", "1-0"),
        ("1", "1.0-0"),
        ("1.0", "1.0-0"),
        ("1a", "1-a"),
        ("1a", "1.0-a"),
        ("1a", "1.0.0-a"),
        ("1.0a", "1-a"),
        ("1.0.0a", "1-a"),
        ("1x", "1-x"),
        ("1x", "1.0-x"),
        ("1x", "1.0.0-x"),
        ("1.0x", "1-x"),
        ("1.0.0x", "1-x"),
        ("1ga", "1"),
        ("1release", "1"),
        ("1final", "1"),
        ("1cr", "1rc"),
        ("1a1", "1-alpha-1"),
        ("1b2", "1-beta-2"),
        ("1m3", "1-milestone-3"),
        ("1X", "1x"),
        ("1A", "1a"),
        ("1B", "1b"),
        ("1M", "1m"),
        ("1Ga", "1"),
        ("1GA", "1"),
        ("1RELEASE", "1"),
        ("1RELeaSE", "1"),
        ("1Final", "1"),
        ("1FinaL", "1"),
        ("1FINAL", "1"),
        ("1Cr", "1Rc"),
        ("1cR", "1rC"),
        ("1m3", "1Milestone3"),
        ("1m3", "1MileStone3"),
        ("1m3", "1MILESTONE3"),
        ("1-abcdefghijklmnopqrstuvwxyz", "1-ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ] {
        equal(Scheme::Maven, a, b);
    }
}

#[test]
fn maven_comparable_version_pairwise_order() {
    // ComparableVersionTest.testVersionComparing (maven-3.9.9).
    for (a, b) in [
        ("1", "2"),
        ("1.5", "2"),
        ("1", "2.5"),
        ("1.0", "1.1"),
        ("1.1", "1.2"),
        ("1.0.0", "1.1"),
        ("1.0.1", "1.1"),
        ("1.1", "1.2.0"),
        ("1.0-alpha-1", "1.0"),
        ("1.0-alpha-1", "1.0-alpha-2"),
        ("1.0-alpha-1", "1.0-beta-1"),
        ("1.0-beta-1", "1.0-SNAPSHOT"),
        ("1.0-SNAPSHOT", "1.0"),
        ("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"),
        ("1.0", "1.0-1"),
        ("1.0-1", "1.0-2"),
        ("1.0.0", "1.0-1"),
        ("2.0-1", "2.0.1"),
        ("2.0.1-klm", "2.0.1-lmn"),
        ("2.0.1", "2.0.1-xyz"),
        ("2.0.1", "2.0.1-123"),
        ("2.0.1-xyz", "2.0.1-123"),
        // MNG-5568
        ("6.1.0rc3", "6.1.0"),
        ("6.1.0rc3", "6.1H.5-beta"),
        ("6.1.0", "6.1H.5-beta"),
        // MNG-6572: arbitrarily large numbers
        ("20190126.230843", "1234567890.12345"),
        ("1234567890.12345", "123456789012345.1H.5-beta"),
        ("123456789012345.1H.5-beta", "12345678901234567890.1H.5-beta"),
        // MNG-6964
        ("1-0.alpha", "1"),
        ("1-0.beta", "1"),
        ("1-0.alpha", "1-0.beta"),
    ] {
        less(Scheme::Maven, a, b);
    }
}

#[test]
fn maven_leading_zeroes_and_mng_7644() {
    // testLeadingZeroes / testVersionZeroEqualWithLeadingZeroes.
    for n in 1..=19 {
        equal(Scheme::Maven, &format!("{}1", "0".repeat(n)), "1");
        equal(Scheme::Maven, &"0".repeat(n), "0");
    }
    // MNG-7644: 1.0.0.X1 < 1.0.0-X2 and 2-X == 2.0.X == 2.0.0.X for any X.
    for x in ["abc", "alpha", "a", "beta", "b", "def", "milestone", "m", "RC"] {
        less(Scheme::Maven, &format!("1.0.0.{x}1"), &format!("1.0.0-{x}2"));
        equal(Scheme::Maven, &format!("2-{x}"), &format!("2.0.{x}"));
        equal(Scheme::Maven, &format!("2-{x}"), &format!("2.0.0.{x}"));
        equal(Scheme::Maven, &format!("2.0.{x}"), &format!("2.0.0.{x}"));
    }
}

#[test]
fn maven_pom_reference_examples() {
    // "Version Order Specification" examples from the POM reference that the
    // 3.9 implementation agrees with.
    less(Scheme::Maven, "1", "1.1");
    ascending(Scheme::Maven, &["1-snapshot", "1", "1-sp"]);
    less(Scheme::Maven, "1-foo2", "1-foo10");
    equal(Scheme::Maven, "1.foo", "1-foo");
    ascending(Scheme::Maven, &["1-foo", "1-1", "1.1"]);
    for v in ["1.ga", "1-ga", "1-0", "1.0"] {
        equal(Scheme::Maven, v, "1");
    }
    less(Scheme::Maven, "1-ga", "1-sp");
    less(Scheme::Maven, "1-ga.1", "1-sp.1");
    less(Scheme::Maven, "1-sp-1", "1-ga-1");
    equal(Scheme::Maven, "1-a1", "1-alpha-1");
    // Real advisory boundaries from the bundled OSV subset.
    less(Scheme::Maven, "2.14.1", "2.15.0");
    less(Scheme::Maven, "2.12.6.1", "2.12.7.1");
    less(Scheme::Maven, "30.1-jre", "32.0.0-android");
    less(Scheme::Maven, "5.3.17", "5.3.18");
}
