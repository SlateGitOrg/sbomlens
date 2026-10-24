//! Golden-file tests for the rendered reports. Regenerate with
//! `UPDATE_GOLDEN=1 cargo test --test golden` and review the diff.

mod common;

use common::*;
use sbomlens::diff::diff;
use sbomlens::osv::scan;
use sbomlens::report::{self, DiffReport, ScanReport};
use sbomlens::vex::{self, VexDocument};

fn check(name: &str, actual: &str) {
    let file = path(&format!("tests/golden/{name}"));
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&file, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&file)
        .unwrap_or_else(|_| panic!("missing golden file {name}; run with UPDATE_GOLDEN=1"));
    if expected != actual {
        let first = expected
            .lines()
            .zip(actual.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| expected.lines().count().min(actual.lines().count()));
        panic!(
            "{name} differs from golden at line {}:\n  golden: {:?}\n  actual: {:?}",
            first + 1,
            expected.lines().nth(first),
            actual.lines().nth(first)
        );
    }
}

fn scan_report(sbom_rel: &str, vex_rel: Option<&str>) -> ScanReport {
    let g = sbom(sbom_rel);
    let db = osv();
    let mut r = scan(&g, &db);
    let v = vex_rel.map(|p| vex::apply(&mut r, &g, &[VexDocument::load(&path(p)).unwrap()]));
    ScanReport::new(sbom_rel, &g, db.stats.clone(), r, v)
}

#[test]
fn diff_express_markdown() {
    let d = diff(&sbom(EXPRESS_OLD_CDX), &sbom(EXPRESS_NEW_SPDX));
    check("express-diff.md", &report::markdown::diff(&DiffReport::new(EXPRESS_OLD_CDX, EXPRESS_NEW_SPDX, d)));
}

#[test]
fn scan_express_with_vex_markdown() {
    check("express-scan-vex.md", &report::markdown::scan(&scan_report(EXPRESS_OLD_SPDX, Some(EXPRESS_VEX))));
}

#[test]
fn scan_flask_markdown() {
    check("flask-scan.md", &report::markdown::scan(&scan_report(FLASK_CDX, None)));
}

#[test]
fn scan_express_new_sarif() {
    check("express-4.21.2-scan.sarif", &report::sarif::scan(&scan_report(EXPRESS_NEW_CDX, None)));
}
