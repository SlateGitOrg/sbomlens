//! CLI behaviour: in-process command execution plus exit codes of the binary.

mod common;

use std::process::Command as Process;

use clap::Parser;
use common::*;
use sbomlens::cli::{run, Cli, Outcome};

fn exec(args: &[&str]) -> (sbomlens::Result<Outcome>, String) {
    let mut argv = vec!["sbomlens"];
    argv.extend_from_slice(args);
    let cli = Cli::try_parse_from(argv).expect("valid arguments");
    let mut out = Vec::new();
    let r = run(&cli, &mut out);
    (r, String::from_utf8(out).unwrap())
}

fn p(rel: &str) -> String {
    path(rel).display().to_string()
}

#[test]
fn inspect_text_tree_and_json() {
    let (r, out) = exec(&["inspect", &p(EXPRESS_OLD_SPDX), "--tree", "1"]);
    assert_eq!(r.unwrap(), Outcome::Ok);
    assert!(out.contains("(SPDX 2.3)"));
    assert!(out.contains("components: 51 (51 with purl, 51 with license)"));
    assert!(out.contains("\n  express@4.17.1\n"));
    let (_, out) = exec(&["inspect", &p(POLYGLOT_CDX), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["stats"]["components"], 19);
    assert_eq!(v["format"]["format"], "CycloneDx");
    let (_, out) = exec(&["inspect", &p(POLYGLOT_CDX), "--tree", "9"]);
    assert!(out.contains("      golang.org/x/text@v0.3.6"));
}

#[test]
fn diff_markdown_json_and_file_output() {
    let (r, out) = exec(&["diff", &p(EXPRESS_OLD_CDX), &p(EXPRESS_NEW_SPDX)]);
    assert_eq!(r.unwrap(), Outcome::Ok);
    assert!(out.contains("**29 upgraded, 0 downgraded, 19 added, 1 removed, 0 changed, 0 license changes, 21 unchanged.**"));
    assert!(out.contains("| qs | npm | 6.7.0 | 6.13.0 |"));
    let (_, out) = exec(&["diff", &p(EXPRESS_NEW_CDX), &p(EXPRESS_OLD_CDX), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let kinds: Vec<&str> = v["diff"]["changes"].as_array().unwrap().iter().map(|c| c["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds.iter().filter(|k| **k == "downgraded").count(), 29);
    let dir = std::env::temp_dir().join(format!("sbomlens-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("d.md");
    let (_, out) = exec(&["diff", &p(EXPRESS_OLD_CDX), &p(EXPRESS_OLD_SPDX), "-o", &file.display().to_string()]);
    assert!(out.is_empty());
    assert!(std::fs::read_to_string(&file).unwrap().contains("No differences."));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn scan_formats_and_fail_on() {
    let osv = p("fixtures/osv/db");
    let (r, md) = exec(&["scan", &p(EXPRESS_OLD_CDX), "--osv", &osv]);
    assert_eq!(r.unwrap(), Outcome::Ok);
    assert!(md.contains("16 active (15 distinct vulnerabilities after alias merge)"));
    let (r, _) = exec(&["scan", &p(EXPRESS_OLD_CDX), "--osv", &osv, "--fail-on", "critical"]);
    assert_eq!(r.unwrap(), Outcome::PolicyFailed);
    let log4j_only = p("fixtures/osv/db/GHSA-jfh8-c2jp-5v3q.json");
    let (r, sarif) = exec(&["scan", &p(EXPRESS_NEW_CDX), "--osv", &log4j_only, "--fail-on", "low", "--format", "sarif"]);
    assert_eq!(r.unwrap(), Outcome::Ok, "no findings, so no policy failure");
    assert!(sarif.contains("\"results\": []"));
    let (r, json) = exec(&["scan", &p(EXPRESS_OLD_SPDX), "--osv", &osv, "--vex", &p(EXPRESS_VEX), "--format", "json", "--fail-on", "low"]);
    assert_eq!(r.unwrap(), Outcome::PolicyFailed);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["vex"]["applied"]["not_affected"], 3);
    // A single OSV file works as a database too.
    let one = p("fixtures/osv/db/GHSA-jfh8-c2jp-5v3q.json");
    let (r, md) = exec(&["scan", &p(POLYGLOT_CDX), "--osv", &one, "--fail-on", "high"]);
    assert_eq!(r.unwrap(), Outcome::PolicyFailed);
    assert!(md.contains("1 active"));
}

#[test]
fn purl_and_compare_commands() {
    let (_, out) = exec(&["purl", "pkg:golang/golang.org/x/net@v1.2.4-0.20191109021931-daa7c04131f5"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["osv_package_name"], "golang.org/x/net");
    assert_eq!(v["go_pseudo_version"]["base"], "v1.2.3");
    let (_, out) = exec(&["purl", "pkg:pypi/Django_Rest@3.0"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["canonical"], "pkg:pypi/django-rest@3.0");
    assert!(v["go_pseudo_version"].is_null());
    let (_, out) = exec(&["purl", "pkg:deb/debian/curl@7.5"]);
    assert!(serde_json::from_str::<serde_json::Value>(&out).unwrap()["ecosystem"].is_null());
    let (_, out) = exec(&["compare", "PyPI", "1.0.dev1", "1.0a1"]);
    assert_eq!(out, "1.0.dev1 (pre-release) < 1.0a1 (pre-release)   [pep440]\n");
    let (_, out) = exec(&["compare", "maven", "1.0.ga", "1"]);
    assert_eq!(out, "1.0.ga = 1   [maven]\n");
    let (_, out) = exec(&["compare", "cargo", "1.10.0", "1.9.0"]);
    assert!(out.starts_with("1.10.0 > 1.9.0"));
}

#[test]
fn errors_are_reported() {
    for args in [
        vec!["purl", "not-a-purl"],
        vec!["compare", "Debian", "1", "2"],
        vec!["compare", "crates.io", "1.0", "1.0.0"],
        vec!["inspect", "/nonexistent.json"],
        vec!["scan", "/nonexistent.json", "--osv", "/nonexistent"],
    ] {
        let (r, _) = exec(&args);
        assert!(r.is_err(), "{args:?}");
    }
    let (r, _) = exec(&["scan", &p(EXPRESS_OLD_CDX), "--osv", &p("fixtures/osv/db"), "--vex", &p(EXPRESS_OLD_CDX)]);
    assert!(r.unwrap_err().to_string().contains("not an OpenVEX document"));
    assert!(Cli::try_parse_from(["sbomlens", "scan", "x", "--osv", "y", "--fail-on", "none"]).is_err());
}

#[test]
fn binary_exit_codes() {
    let bin = env!("CARGO_BIN_EXE_sbomlens");
    let ok = Process::new(bin).args(["compare", "npm", "1.0.0", "2.0.0"]).output().unwrap();
    assert_eq!(ok.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "1.0.0 < 2.0.0   [npm]");
    let fail = Process::new(bin)
        .args(["scan", &p(POLYGLOT_CDX), "--osv", &p("fixtures/osv/db"), "--fail-on", "critical", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));
    let err = Process::new(bin).args(["inspect", "/nonexistent.json"]).output().unwrap();
    assert_eq!(err.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&err.stderr).contains("sbomlens: error: cannot read"));
    let verbose = Process::new(bin).args(["-v", "inspect", &p(FLASK_CDX)]).output().unwrap();
    assert!(String::from_utf8_lossy(&verbose.stderr).contains("loaded SBOM"));
}
