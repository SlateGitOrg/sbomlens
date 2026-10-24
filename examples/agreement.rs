//! Agreement eval: sbomlens' offline matches vs. api.osv.dev's own matches
//! (recorded in fixtures/osv/expected-matches.json at fetch time).
//!
//! Run: `cargo run --release --example agreement -- [--ranges-only] [sbom ...]`
//! With no SBOM arguments it evaluates every SBOM under fixtures/sbom.
//! `--ranges-only` drops every advisory's enumerated `versions` list first,
//! so matches must come from range evaluation (the version-ordering code)
//! alone; this isolates the per-ecosystem comparators from OSV's
//! pre-computed version enumerations.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sbomlens::osv::{scan, OsvDatabase};
use sbomlens::sbom;

fn sboms(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            sboms(&p, out);
        } else if p.extension().is_some_and(|x| x == "json") {
            out.push(p);
        }
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let ranges_only = args.iter().any(|a| a == "--ranges-only");
    args.retain(|a| a != "--ranges-only");
    let mut db = OsvDatabase::load(&root.join("fixtures/osv/db")).expect("load OSV subset");
    if ranges_only {
        let vulns = db
            .vulns
            .into_iter()
            .map(|mut v| {
                for a in &mut v.affected {
                    a.versions.clear();
                }
                v
            })
            .collect();
        db = OsvDatabase::from_vulns(vulns);
    }
    println!("mode: {}", if ranges_only { "ranges only (versions lists dropped)" } else { "ranges + versions lists" });
    let expected: BTreeMap<String, BTreeSet<String>> = serde_json::from_str(
        &std::fs::read_to_string(root.join("fixtures/osv/expected-matches.json")).unwrap(),
    )
    .unwrap();
    let mut files: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
    if files.is_empty() {
        sboms(&root.join("fixtures/sbom"), &mut files);
    }
    println!("{:<44} {:>6} {:>6} {:>6} {:>6} {:>9} {:>7}", "sbom", "truth", "ours", "tp", "fp", "fn", "agree");
    let (mut ttp, mut tfp, mut tfn) = (0, 0, 0);
    for f in &files {
        let g = sbom::load(f).expect("load SBOM");
        let result = scan(&g, &db);
        let mut ours: BTreeSet<(String, String)> = BTreeSet::new();
        for fi in &result.findings {
            ours.insert((fi.purl.clone(), fi.id.clone()));
        }
        let mut truth: BTreeSet<(String, String)> = BTreeSet::new();
        for c in &g.components {
            if let Some(p) = &c.purl {
                if let Some(ids) = expected.get(&p.to_string()) {
                    for id in ids {
                        truth.insert((p.to_string(), id.clone()));
                    }
                }
            }
        }
        let tp = ours.intersection(&truth).count();
        let fp: Vec<_> = ours.difference(&truth).collect();
        let fneg: Vec<_> = truth.difference(&ours).collect();
        ttp += tp;
        tfp += fp.len();
        tfn += fneg.len();
        let name = f.strip_prefix(root).unwrap_or(f).display().to_string();
        let agree = if truth.is_empty() && ours.is_empty() { 1.0 } else {
            tp as f64 / (tp + fp.len() + fneg.len()) as f64
        };
        println!("{name:<44} {:>6} {:>6} {:>6} {:>6} {:>9} {:>6.1}%", truth.len(), ours.len(), tp, fp.len(), fneg.len(), agree * 100.0);
        for (p, id) in &fp {
            println!("    extra   {id:<22} {p}");
        }
        for (p, id) in &fneg {
            println!("    missing {id:<22} {p}");
        }
    }
    let precision = ttp as f64 / (ttp + tfp).max(1) as f64;
    let recall = ttp as f64 / (ttp + tfn).max(1) as f64;
    println!("TOTAL tp={ttp} fp={tfp} fn={tfn} precision={:.3} recall={:.3}", precision, recall);
}
