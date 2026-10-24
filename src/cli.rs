//! Command-line interface (argument model and command execution).
//!
//! Kept in the library so the commands can be exercised in-process by tests;
//! `main.rs` only parses arguments, sets up logging and maps exit codes.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

use crate::cvss::Severity;
use crate::ecosystem::Ecosystem;
use crate::error::{Error, Result};
use crate::graph::SbomGraph;
use crate::osv::{scan, OsvDatabase};
use crate::purl::Purl;
use crate::report::{self, DiffReport, ScanReport};
use crate::version::{self, Version};
use crate::vex::{self, VexDocument};
use crate::{diff, sbom};

/// Offline SBOM toolkit: normalize, diff and vulnerability-match CycloneDX and SPDX SBOMs.
#[derive(Debug, Parser)]
#[command(name = "sbomlens", version, about, long_about = None)]
pub struct Cli {
    /// Increase log verbosity (-v debug, -vv trace). Logs go to stderr.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Output formats for scan reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScanFormat {
    /// GitHub-flavoured Markdown.
    Md,
    /// SARIF 2.1.0.
    Sarif,
    /// sbomlens JSON.
    Json,
}

/// Output formats for diff and inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TextFormat {
    /// Human-readable text / Markdown.
    Md,
    /// sbomlens JSON.
    Json,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Load an SBOM and print its normalized summary (format, counts, ecosystems, warnings).
    Inspect {
        /// CycloneDX or SPDX JSON file.
        sbom: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = TextFormat::Md)]
        format: TextFormat,
        /// Also print the dependency tree up to this depth.
        #[arg(long)]
        tree: Option<usize>,
    },
    /// Compare two SBOMs: added, removed, upgraded, downgraded and license changes.
    Diff {
        /// The baseline SBOM.
        old: PathBuf,
        /// The SBOM to compare against the baseline.
        new: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = TextFormat::Md)]
        format: TextFormat,
        /// Write the report to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Match an SBOM against an offline OSV database, optionally applying OpenVEX.
    Scan {
        /// CycloneDX or SPDX JSON file.
        sbom: PathBuf,
        /// OSV database: a directory of OSV JSON files (searched recursively) or one JSON file.
        #[arg(long)]
        osv: PathBuf,
        /// OpenVEX documents to apply (repeatable; later documents win timestamp ties).
        #[arg(long)]
        vex: Vec<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ScanFormat::Md)]
        format: ScanFormat,
        /// Write the report to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Exit with status 1 when an active finding is at or above this severity
        /// (low, medium, high, critical).
        #[arg(long, value_parser = parse_severity)]
        fail_on: Option<Severity>,
    },
    /// Parse a purl and print its normalized components as JSON.
    Purl {
        /// The package URL.
        purl: String,
    },
    /// Compare two versions with an ecosystem's ordering; prints `<`, `=` or `>`.
    Compare {
        /// Ecosystem: npm, crates.io, PyPI, Maven, Go (OSV names) or a purl type.
        ecosystem: String,
        /// Left version.
        a: String,
        /// Right version.
        b: String,
    },
}

fn parse_severity(s: &str) -> std::result::Result<Severity, String> {
    Severity::parse_threshold(s).ok_or_else(|| format!("unknown severity {s:?} (low, medium, high, critical)"))
}

/// Outcome of a command, mapped to the process exit code by `main`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Success (exit 0).
    Ok,
    /// `--fail-on` threshold reached (exit 1).
    PolicyFailed,
}

fn ecosystem_arg(s: &str) -> Result<Ecosystem> {
    let by_osv = Ecosystem::from_osv(s);
    let eco = if by_osv.scheme().is_some() {
        by_osv
    } else {
        Ecosystem::from_purl_type(&s.to_ascii_lowercase())
    };
    if eco.scheme().is_none() {
        return Err(Error::invalid(s, "unknown ecosystem (use npm, crates.io, PyPI, Maven, Go)"));
    }
    Ok(eco)
}

fn emit(out: &mut dyn Write, output: Option<&Path>, text: &str) -> Result<()> {
    match output {
        Some(p) => std::fs::write(p, text).map_err(|e| Error::io(p, e)),
        None => out.write_all(text.as_bytes()).map_err(|e| Error::io("<stdout>", e)),
    }
}

fn tree(g: &SbomGraph, max_depth: usize) -> String {
    let mut out = String::new();
    let mut seen = vec![false; g.components.len()];
    fn walk(g: &SbomGraph, i: usize, depth: usize, max: usize, seen: &mut [bool], out: &mut String) {
        let c = &g.components[i];
        let v = c.effective_version().unwrap_or("?");
        let again = if seen[i] && !g.edges[i].is_empty() { " (…)" } else { "" };
        out.push_str(&format!("{}{}@{v}{again}\n", "  ".repeat(depth), c.display_name()));
        if seen[i] || depth >= max {
            return;
        }
        seen[i] = true;
        for &child in &g.edges[i] {
            walk(g, child, depth + 1, max, seen, out);
        }
    }
    for &r in &g.roots {
        walk(g, r, 0, max_depth, &mut seen, &mut out);
    }
    out
}

/// Executes a parsed command, writing primary output to `out`.
pub fn run(cli: &Cli, out: &mut dyn Write) -> Result<Outcome> {
    match &cli.command {
        Command::Inspect { sbom: path, format, tree: depth } => {
            let g = sbom::load(path)?;
            let text = match format {
                TextFormat::Json => report::to_json(&serde_json::json!({
                    "sbom": path.display().to_string(),
                    "format": g.format,
                    "name": g.name,
                    "stats": g.stats(),
                    "warnings": g.warnings,
                })),
                TextFormat::Md => {
                    let s = g.stats();
                    let mut t = format!(
                        "{} ({})\n  name: {}\n  components: {} ({} with purl, {} with license)\n  edges: {}, roots: {}, max depth: {}\n  ecosystems: {}\n",
                        path.display(),
                        g.format,
                        g.name.as_deref().unwrap_or("-"),
                        s.components,
                        s.with_purl,
                        s.with_license,
                        s.edges,
                        s.roots,
                        s.max_depth,
                        s.ecosystems.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")
                    );
                    for w in &g.warnings {
                        t.push_str(&format!("  warning: {w}\n"));
                    }
                    if let Some(d) = depth {
                        t.push('\n');
                        t.push_str(&tree(&g, *d));
                    }
                    t
                }
            };
            emit(out, None, &text)?;
            Ok(Outcome::Ok)
        }
        Command::Diff { old, new, format, output } => {
            let (a, b) = (sbom::load(old)?, sbom::load(new)?);
            let r = DiffReport::new(&old.display().to_string(), &new.display().to_string(), diff::diff(&a, &b));
            let text = match format {
                TextFormat::Md => report::markdown::diff(&r),
                TextFormat::Json => report::to_json(&r),
            };
            emit(out, output.as_deref(), &text)?;
            Ok(Outcome::Ok)
        }
        Command::Scan { sbom: path, osv, vex: vex_paths, format, output, fail_on } => {
            let g = sbom::load(path)?;
            let db = OsvDatabase::load(osv)?;
            let mut result = scan(&g, &db);
            let vex_report = if vex_paths.is_empty() {
                None
            } else {
                let docs = vex_paths.iter().map(|p| VexDocument::load(p)).collect::<Result<Vec<_>>>()?;
                Some(vex::apply(&mut result, &g, &docs))
            };
            let r = ScanReport::new(&path.display().to_string(), &g, db.stats.clone(), result, vex_report);
            let text = match format {
                ScanFormat::Md => report::markdown::scan(&r),
                ScanFormat::Sarif => report::sarif::scan(&r),
                ScanFormat::Json => report::to_json(&r),
            };
            emit(out, output.as_deref(), &text)?;
            let failed = match (fail_on, r.max_active_severity()) {
                (Some(threshold), Some(max)) => max >= *threshold,
                _ => false,
            };
            Ok(if failed { Outcome::PolicyFailed } else { Outcome::Ok })
        }
        Command::Purl { purl } => {
            let p = Purl::parse(purl).map_err(|e| Error::invalid(purl, e.to_string()))?;
            let eco = Ecosystem::from_purl_type(&p.ty);
            let text = report::to_json(&serde_json::json!({
                "canonical": p.to_string(),
                "type": p.ty,
                "namespace": p.namespace,
                "name": p.name,
                "version": p.version,
                "qualifiers": p.qualifiers,
                "subpath": p.subpath,
                "ecosystem": eco.scheme().map(|_| eco.osv_name().to_string()),
                "osv_package_name": eco.scheme().map(|_| eco.package_name(&p)),
                "go_pseudo_version": (eco == Ecosystem::Go)
                    .then(|| p.version.as_deref().and_then(version::golang::pseudo_version))
                    .flatten()
                    .map(|pv| serde_json::json!({"base": pv.base, "timestamp": pv.timestamp, "revision": pv.revision})),
            }));
            emit(out, None, &text)?;
            Ok(Outcome::Ok)
        }
        Command::Compare { ecosystem, a, b } => {
            let eco = ecosystem_arg(ecosystem)?;
            let scheme = eco.scheme().expect("ecosystem_arg guarantees a scheme");
            let ord = version::compare(scheme, a, b).map_err(|e| Error::invalid("compare", e.to_string()))?;
            let sym = match ord {
                std::cmp::Ordering::Less => "<",
                std::cmp::Ordering::Equal => "=",
                std::cmp::Ordering::Greater => ">",
            };
            let pre = |v: &str| Version::parse(scheme, v).is_ok_and(|x| x.is_prerelease());
            let note = |v: &str| if pre(v) { " (pre-release)" } else { "" };
            emit(out, None, &format!("{a}{} {sym} {b}{}   [{scheme}]\n", note(a), note(b)))?;
            Ok(Outcome::Ok)
        }
    }
}
