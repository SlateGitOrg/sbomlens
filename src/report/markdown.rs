//! Markdown rendering (GitHub-flavoured tables), suitable for PR comments
//! and CI job summaries.

use std::fmt::Write as _;

use super::{DiffReport, ScanReport};
use crate::diff::ChangeKind;
use crate::osv::MatchReason;

/// Escapes text for a Markdown table cell.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn advisory_link(id: &str, url: Option<&str>) -> String {
    match url {
        Some(u) => format!("[{}]({u})", cell(id)),
        None => cell(id),
    }
}

/// Renders a scan report.
pub fn scan(r: &ScanReport) -> String {
    let mut o = String::new();
    let title = r.sbom_name.as_deref().unwrap_or(&r.sbom);
    let _ = writeln!(o, "# sbomlens scan: {}\n", cell(title));
    let s = &r.scan.stats;
    let active = r.scan.active().count();
    let suppressed = r.scan.findings.len() - active;
    let _ = writeln!(
        o,
        "- **SBOM:** `{}` ({}), {} components, {} edges, max depth {}",
        r.sbom, r.sbom_format, r.graph.components, r.graph.edges, r.graph.max_depth
    );
    let _ = writeln!(
        o,
        "- **Checked:** {} of {} components ({} without purl, {} unsupported ecosystem, {} without version)",
        s.checked, s.components, s.without_purl, s.unsupported_ecosystem, s.without_version
    );
    let _ = writeln!(
        o,
        "- **OSV database:** {} advisories from {} files ({} withdrawn, {} affected entries indexed)",
        r.database.records, r.database.files, r.database.withdrawn, r.database.affected_indexed
    );
    let _ = writeln!(
        o,
        "- **Findings:** {active} active ({} distinct vulnerabilities after alias merge), {suppressed} suppressed by VEX\n",
        r.scan.distinct_vulnerabilities()
    );
    if active > 0 {
        o.push_str("| Severity | Findings |\n|---|---:|\n");
        for (sev, n) in r.severity_counts() {
            let _ = writeln!(o, "| {sev} | {n} |");
        }
        o.push_str("\n## Findings\n\n");
        o.push_str(
            "| Severity | Package | Version | Advisory | Aliases | Fixed in | Introduced via |\n",
        );
        o.push_str("|---|---|---|---|---|---|---|\n");
        for f in r.scan.active() {
            let sev = match f.severity.score {
                Some(score) => format!("{} ({score:.1})", f.severity.level),
                None => f.severity.level.to_string(),
            };
            let aliases: Vec<&str> = f
                .aliases
                .iter()
                .filter(|a| a.starts_with("CVE-"))
                .map(String::as_str)
                .collect();
            let fixed = match (&f.fixed_in, &f.reason) {
                (Some(v), _) => v.clone(),
                (None, MatchReason::Range { hit, .. }) if hit.last_affected.is_some() => {
                    format!("after {}", hit.last_affected.as_deref().unwrap_or_default())
                }
                _ => "-".into(),
            };
            let via = if f.direct {
                "direct".to_string()
            } else {
                f.path.join(" > ")
            };
            let _ = writeln!(
                o,
                "| {sev} | {} | {} | {} | {} | {} | {} |",
                cell(&f.package),
                cell(&f.version),
                advisory_link(&f.id, f.url.as_deref()),
                cell(&aliases.join(", ")),
                cell(&fixed),
                cell(&via)
            );
        }
    } else {
        o.push_str("No active findings.\n");
    }
    if suppressed > 0 {
        o.push_str("\n## Suppressed by VEX\n\n| Package | Version | Advisory | Status | Justification / impact | Statement |\n|---|---|---|---|---|---|\n");
        for f in r.scan.findings.iter().filter(|f| f.is_suppressed()) {
            let Some(v) = &f.vex else { continue };
            let why = v
                .justification
                .clone()
                .or_else(|| v.impact_statement.clone())
                .unwrap_or_default();
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} | `{}` |",
                cell(&f.package),
                cell(&f.version),
                cell(&f.id),
                v.status.as_str(),
                cell(&why),
                cell(&v.statement)
            );
        }
    }
    let annotated: Vec<_> = r.scan.active().filter(|f| f.vex.is_some()).collect();
    if !annotated.is_empty() {
        o.push_str("\n## VEX annotations on active findings\n\n| Package | Advisory | Status | Action |\n|---|---|---|---|\n");
        for f in annotated {
            let Some(v) = &f.vex else { continue };
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} |",
                cell(&f.package),
                cell(&f.id),
                v.status.as_str(),
                cell(v.action_statement.as_deref().unwrap_or("-"))
            );
        }
    }
    if !r.scan.skipped.is_empty() {
        o.push_str("\n## Not fully checked\n\n");
        for sk in &r.scan.skipped {
            let _ = writeln!(o, "- `{}`: {}", sk.reference, cell(&sk.reason));
        }
    }
    let mut notes: Vec<String> = r.sbom_warnings.clone();
    if let Some(v) = &r.vex {
        notes.extend(v.warnings.iter().cloned());
        notes.extend(
            v.unused
                .iter()
                .map(|u| format!("VEX statement {u} matched no finding")),
        );
    }
    if !notes.is_empty() {
        o.push_str("\n## Warnings\n\n");
        for n in notes {
            let _ = writeln!(o, "- {}", cell(&n));
        }
    }
    o
}

/// Renders a diff report.
pub fn diff(r: &DiffReport) -> String {
    let d = &r.diff;
    let mut o = String::new();
    o.push_str("# sbomlens diff\n\n");
    let _ = writeln!(o, "| | Old | New |\n|---|---|---|");
    let _ = writeln!(o, "| SBOM | `{}` | `{}` |", r.old, r.new);
    let _ = writeln!(
        o,
        "| Components | {} | {} |",
        d.old.components, d.new.components
    );
    let _ = writeln!(
        o,
        "| Dependency edges | {} | {} |",
        d.old.edges, d.new.edges
    );
    let _ = writeln!(
        o,
        "| Max depth | {} | {} |\n",
        d.old.max_depth, d.new.max_depth
    );
    let _ = writeln!(
        o,
        "**{} upgraded, {} downgraded, {} added, {} removed, {} changed, {} license changes, {} unchanged.**",
        d.count(ChangeKind::Upgraded),
        d.count(ChangeKind::Downgraded),
        d.count(ChangeKind::Added),
        d.count(ChangeKind::Removed),
        d.count(ChangeKind::Changed),
        d.license_changes.len(),
        d.unchanged
    );
    let sections = [
        (ChangeKind::Upgraded, "Upgraded"),
        (ChangeKind::Downgraded, "Downgraded"),
        (ChangeKind::Added, "Added"),
        (ChangeKind::Removed, "Removed"),
        (ChangeKind::Changed, "Changed (order unknown)"),
    ];
    let mut any_best_effort = false;
    for (kind, title) in sections {
        let rows: Vec<_> = d.changes.iter().filter(|c| c.kind == kind).collect();
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(
            o,
            "\n## {title} ({})\n\n| Package | Ecosystem | From | To |\n|---|---|---|---|",
            rows.len()
        );
        for c in rows {
            let mark =
                if c.best_effort && matches!(kind, ChangeKind::Upgraded | ChangeKind::Downgraded) {
                    any_best_effort = true;
                    " \\*"
                } else {
                    ""
                };
            let _ = writeln!(
                o,
                "| {}{mark} | {} | {} | {} |",
                cell(&c.package),
                cell(&c.ecosystem),
                cell(c.from.as_deref().unwrap_or("-")),
                cell(c.to.as_deref().unwrap_or("-"))
            );
        }
    }
    if any_best_effort {
        o.push_str("\n\\* direction from the generic fallback ordering (ecosystem ordering unknown or version unparseable).\n");
    }
    if !d.license_changes.is_empty() {
        let _ = writeln!(
            o,
            "\n## License changes ({})\n\n| Package | Version | From | To |\n|---|---|---|---|",
            d.license_changes.len()
        );
        for l in &d.license_changes {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} |",
                cell(&l.package),
                cell(l.version.as_deref().unwrap_or("-")),
                cell(l.from.as_deref().unwrap_or("(none)")),
                cell(l.to.as_deref().unwrap_or("(none)"))
            );
        }
    }
    if d.is_empty() {
        o.push_str("\nNo differences.\n");
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_table_cells() {
        assert_eq!(cell("a|b\nc"), "a\\|b c");
        assert_eq!(advisory_link("X", Some("https://u")), "[X](https://u)");
        assert_eq!(advisory_link("X", None), "X");
    }
}
