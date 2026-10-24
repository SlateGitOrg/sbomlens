//! Version-sweep eval: OSV enumerates, in each advisory's `affected[].versions`,
//! every published version that its ranges cover (computed by OSV.dev from
//! the registries). For every affected entry that has both evaluable ranges
//! and an enumeration — and no GIT ranges, whose enumerations come from
//! commit graphs rather than version order — this checks that sbomlens'
//! range evaluation classifies every enumerated version as affected.
//!
//! A second probe checks the other side of each boundary: every `fixed`
//! event version must evaluate as *not* affected, unless the advisory's own
//! enumeration lists it (overlapping ranges). For entries without an
//! enumeration (typical for npm, Go and crates.io) this assumes ranges do
//! not overlap, which is how those databases author them.
//!
//! Run: `cargo run --release --example version_sweep`

#![allow(clippy::cast_precision_loss)] // ratios of small counts, printed for humans

use std::collections::BTreeMap;
use std::path::Path;

use sbomlens::ecosystem::Ecosystem;
use sbomlens::osv::range::CompiledRange;
use sbomlens::osv::OsvDatabase;
use sbomlens::version::Version;

#[derive(Default)]
struct Tally {
    fixed_checked: usize,
    fixed_agree: usize,
    entries: usize,
    versions: usize,
    agree: usize,
    unparseable: usize,
    misses: Vec<String>,
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let db = OsvDatabase::load(&root.join("fixtures/osv/db")).expect("load OSV subset");
    let mut by_eco: BTreeMap<String, Tally> = BTreeMap::new();
    for v in &db.vulns {
        if v.withdrawn.is_some() {
            continue;
        }
        for a in &v.affected {
            let Some(pkg) = &a.package else { continue };
            if a.ranges.iter().any(|r| r.kind == "GIT") {
                continue;
            }
            let eco = Ecosystem::from_osv(&pkg.ecosystem);
            let Ok(ranges) = a
                .ranges
                .iter()
                .map(|r| CompiledRange::compile(r, &eco))
                .collect::<Result<Vec<_>, _>>()
            else {
                continue;
            };
            if ranges.is_empty() {
                continue;
            }
            // SEMVER ranges compile for any ecosystem; enumerations need its ordering.
            let Some(scheme) = eco.scheme() else { continue };
            let t = by_eco.entry(eco.to_string()).or_default();
            let listed: Vec<String> = a
                .versions
                .iter()
                .filter_map(|x| Version::parse(scheme, x).ok().map(|p| p.key()))
                .collect();
            for f in a
                .ranges
                .iter()
                .flat_map(|r| r.events.iter())
                .filter_map(|e| e.fixed.as_ref())
            {
                let affected = ranges
                    .iter()
                    .any(|r| Version::parse(r.scheme, f).is_ok_and(|pv| r.evaluate(&pv).is_some()));
                let expected = Version::parse(scheme, f).is_ok_and(|p| listed.contains(&p.key()));
                t.fixed_checked += 1;
                if affected == expected {
                    t.fixed_agree += 1;
                } else if t.misses.len() < 5 {
                    t.misses.push(format!(
                        "{} {} fixed={f} evaluated affected={affected}",
                        v.id, pkg.name
                    ));
                }
            }
            if a.versions.is_empty() {
                continue;
            }
            t.entries += 1;
            for ver in &a.versions {
                t.versions += 1;
                let mut parsed_any = false;
                let hit = ranges.iter().any(|r| match Version::parse(r.scheme, ver) {
                    Ok(pv) => {
                        parsed_any = true;
                        r.evaluate(&pv).is_some()
                    }
                    Err(_) => false,
                });
                if hit {
                    t.agree += 1;
                } else if !parsed_any {
                    t.unparseable += 1;
                } else if t.misses.len() < 5 {
                    t.misses.push(format!("{} {} {}", v.id, pkg.name, ver));
                }
            }
        }
    }
    println!(
        "{:<10} {:>8} {:>9} {:>9} {:>11} {:>9} {:>11}",
        "ecosystem", "entries", "versions", "in-range", "unparseable", "fixed", "fixed-agree"
    );
    let (mut tv, mut ta, mut tf, mut tfa) = (0, 0, 0, 0);
    for (eco, t) in &by_eco {
        tv += t.versions;
        ta += t.agree;
        tf += t.fixed_checked;
        tfa += t.fixed_agree;
        println!(
            "{eco:<10} {:>8} {:>9} {:>9} {:>11} {:>9} {:>11}",
            t.entries, t.versions, t.agree, t.unparseable, t.fixed_checked, t.fixed_agree
        );
        for m in &t.misses {
            println!("    out-of-range: {m}");
        }
    }
    println!(
        "TOTAL {ta}/{tv} enumerated versions classified as affected ({:.2}%)",
        100.0 * ta as f64 / tv.max(1) as f64
    );
    println!(
        "TOTAL {tfa}/{tf} fixed-event versions classified correctly ({:.2}%)",
        100.0 * tfa as f64 / tf.max(1) as f64
    );
}
