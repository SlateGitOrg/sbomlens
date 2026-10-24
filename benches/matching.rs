//! Matching benchmark (`make bench` / `cargo bench --bench matching`).
//!
//! 1. Real data: load + index the pinned OSV subset, then scan each bundled
//!    SBOM fixture.
//! 2. Synthetic scale: a deterministic database of 20,000 advisories over
//!    5,000 npm-like packages and an SBOM of 5,000 components, comparing the
//!    indexed matcher (ranges compiled once, hash lookup per component) with
//!    a naive baseline that walks every advisory for every component and
//!    parses event versions on the fly.
//!
//! Reported times are medians over several runs with `std::time::Instant`;
//! they depend on the machine and on concurrent load.

#![allow(clippy::cast_precision_loss)] // ratios of small counts, printed for humans

use std::hint::black_box;
use std::path::Path;
use std::time::{Duration, Instant};

use sbomlens::ecosystem::Ecosystem;
use sbomlens::graph::{Component, GraphBuilder, SbomFormat, SbomGraph};
use sbomlens::osv::range::CompiledRange;
use sbomlens::osv::{scan, Affected, Event, OsvDatabase, Package, Range, Vulnerability};
use sbomlens::purl::Purl;
use sbomlens::version::{Scheme, Version};

fn median<T>(runs: usize, mut f: impl FnMut() -> T) -> Duration {
    let mut times: Vec<Duration> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            black_box(f());
            t.elapsed()
        })
        .collect();
    times.sort();
    times[runs / 2]
}

fn ms(d: Duration) -> String {
    format!("{:.3} ms", d.as_secs_f64() * 1e3)
}

/// xorshift64* — deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn synthetic(packages: usize, advisories: usize, seed: u64) -> (SbomGraph, Vec<Vulnerability>) {
    let mut rng = Rng(seed);
    let ver = |rng: &mut Rng| format!("{}.{}.{}", rng.below(5), rng.below(20), rng.below(30));
    let mut vulns = Vec::with_capacity(advisories);
    for i in 0..advisories {
        // Skewed popularity: a quarter of advisories hit the first 5% of packages.
        let pkg = if rng.below(4) == 0 {
            rng.below((packages / 20) as u64)
        } else {
            rng.below(packages as u64)
        };
        let mut ranges = Vec::new();
        for _ in 0..=rng.below(2) {
            let (a, b) = (ver(&mut rng), ver(&mut rng));
            let (lo, hi) = if Version::parse(Scheme::SemVer, &a)
                .unwrap()
                .try_cmp(&Version::parse(Scheme::SemVer, &b).unwrap())
                == Some(std::cmp::Ordering::Less)
            {
                (a, b)
            } else {
                (b, a)
            };
            let intro = if rng.below(3) == 0 {
                "0".to_string()
            } else {
                lo
            };
            ranges.push(Range {
                kind: "SEMVER".into(),
                events: vec![
                    Event {
                        introduced: Some(intro),
                        ..Event::default()
                    },
                    Event {
                        fixed: Some(hi),
                        ..Event::default()
                    },
                ],
            });
        }
        vulns.push(Vulnerability {
            id: format!("SYN-{i:06}"),
            summary: None,
            details: None,
            aliases: Vec::new(),
            modified: None,
            withdrawn: None,
            affected: vec![Affected {
                package: Some(Package {
                    ecosystem: "npm".into(),
                    name: format!("pkg-{pkg}"),
                    purl: None,
                }),
                ranges,
                versions: Vec::new(),
                severity: Vec::new(),
            }],
            severity: Vec::new(),
            database_specific: None,
            references: Vec::new(),
        });
    }
    let mut b = GraphBuilder::new(
        SbomFormat::CycloneDx("1.6".into()),
        Some("synthetic".into()),
    );
    let root = b.add(Component::new("root", "root"));
    b.root(root);
    let mut prev = root;
    for p in 0..packages {
        let purl = Purl::parse(&format!("pkg:npm/pkg-{p}@{}", ver(&mut rng))).unwrap();
        let idx = b.add(Component::new(format!("c{p}"), format!("pkg-{p}")).with_purl(purl));
        // A chain with fan-out keeps paths realistic (depth grows slowly).
        let parent = if p % 8 == 0 { root } else { prev };
        b.edge(parent, idx);
        prev = idx;
    }
    (b.finish(), vulns)
}

/// Baseline without index or pre-compilation.
fn naive_scan(graph: &SbomGraph, vulns: &[Vulnerability]) -> usize {
    let mut hits = 0;
    for c in &graph.components {
        let (Some(purl), Some(eco)) = (&c.purl, &c.ecosystem) else {
            continue;
        };
        let name = eco.package_name(purl);
        let Some(v) = c.effective_version() else {
            continue;
        };
        for vuln in vulns {
            for a in &vuln.affected {
                let Some(p) = &a.package else { continue };
                if Ecosystem::from_osv(&p.ecosystem) != *eco || p.name != name {
                    continue;
                }
                let affected = a.ranges.iter().any(|r| {
                    CompiledRange::compile(r, eco)
                        .ok()
                        .and_then(|cr| {
                            Version::parse(cr.scheme, v)
                                .ok()
                                .map(|pv| cr.evaluate(&pv).is_some())
                        })
                        .unwrap_or(false)
                });
                if affected {
                    hits += 1;
                }
            }
        }
    }
    hits
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    println!("== real data (pinned OSV subset, bundled SBOMs)");
    let db_path = root.join("fixtures/osv/db");
    let load = median(9, || OsvDatabase::load(&db_path).unwrap());
    let db = OsvDatabase::load(&db_path).unwrap();
    println!(
        "load+index {} advisories ({} indexed entries, {} ranges): {}",
        db.stats.records,
        db.stats.affected_indexed,
        db.stats.ranges_compiled,
        ms(load)
    );
    for f in [
        "fixtures/sbom/real/express-4.17.1.cdx.json",
        "fixtures/sbom/real/express-4.21.2.spdx.json",
        "fixtures/sbom/real/flask-2.2.2.cdx.json",
        "fixtures/sbom/synthetic/polyglot-gateway.cdx.json",
    ] {
        let g = sbomlens::sbom::load(&root.join(f)).unwrap();
        let parse = median(21, || sbomlens::sbom::load(&root.join(f)).unwrap());
        let t = median(51, || scan(&g, &db));
        let n = scan(&g, &db).findings.len();
        println!(
            "{f:<52} parse {:>10}  scan {:>10}  ({} components, {n} findings)",
            ms(parse),
            ms(t),
            g.components.len()
        );
    }

    println!("\n== synthetic scale (seeded, deterministic)");
    let (graph, vulns) = synthetic(5_000, 20_000, 0x5EED_1234);
    let build = median(5, || OsvDatabase::from_vulns(vulns.clone()));
    let db = OsvDatabase::from_vulns(vulns.clone());
    let indexed = median(11, || scan(&graph, &db));
    let indexed_hits = scan(&graph, &db).findings.len();
    let naive = median(3, || naive_scan(&graph, &vulns));
    let naive_hits = naive_scan(&graph, &vulns);
    assert_eq!(
        indexed_hits, naive_hits,
        "indexed and naive matchers must agree"
    );
    println!(
        "advisories: {}, SBOM components: {}",
        vulns.len(),
        graph.components.len()
    );
    println!("index build (compile + index): {}", ms(build));
    println!(
        "indexed scan: {}  ({:.0} components/s, {indexed_hits} findings)",
        ms(indexed),
        graph.components.len() as f64 / indexed.as_secs_f64()
    );
    println!("naive scan:   {}  ({naive_hits} findings)", ms(naive));
    println!(
        "speedup (scan only): {:.0}x; break-even after {:.2} scans including index build",
        naive.as_secs_f64() / indexed.as_secs_f64(),
        build.as_secs_f64() / (naive.as_secs_f64() - indexed.as_secs_f64()).max(f64::EPSILON)
    );
}
