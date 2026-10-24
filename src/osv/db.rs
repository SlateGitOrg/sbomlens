//! An offline OSV database: loading, compilation of ranges and an index
//! from `(ecosystem, package name)` to affected entries.
//!
//! All range events and enumerated versions are parsed once at load time,
//! so matching a component costs one hash lookup plus a walk over the
//! (already sorted) events of the advisories for that one package.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use super::range::CompiledRange;
use super::Vulnerability;
use crate::ecosystem::Ecosystem;
use crate::error::{Error, Result};
use crate::version::Version;

/// One indexed `affected[]` entry with its compiled ranges.
#[derive(Debug, Clone)]
pub struct IndexedAffected {
    /// Index into [`OsvDatabase::vulns`].
    pub vuln: usize,
    /// Index into that advisory's `affected` list.
    pub affected: usize,
    /// Successfully compiled ranges.
    pub ranges: Vec<CompiledRange>,
    /// Enumerated versions, verbatim.
    pub versions_raw: HashSet<String>,
    /// Enumerated versions as equality keys under the ecosystem's scheme.
    pub versions_keys: HashSet<String>,
    /// True when some range of this entry could not be compiled.
    pub partially_evaluable: bool,
}

/// Counters describing what was loaded and what could not be used.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LoadStats {
    /// JSON files read.
    pub files: usize,
    /// Advisories loaded.
    pub records: usize,
    /// Withdrawn advisories (never matched).
    pub withdrawn: usize,
    /// `affected` entries indexed for matching.
    pub affected_indexed: usize,
    /// `affected` entries for ecosystems without a known version ordering.
    pub affected_unsupported: usize,
    /// Ranges compiled.
    pub ranges_compiled: usize,
    /// Ranges that could not be compiled, by reason.
    pub ranges_skipped: BTreeMap<String, usize>,
}

/// The loaded, indexed database.
#[derive(Debug, Clone, Default)]
pub struct OsvDatabase {
    /// All advisories, in load order (files sorted by path).
    pub vulns: Vec<Vulnerability>,
    index: HashMap<(Ecosystem, String), Vec<IndexedAffected>>,
    /// Load statistics.
    pub stats: LoadStats,
}

impl OsvDatabase {
    /// Builds a database from advisories already in memory.
    pub fn from_vulns(vulns: Vec<Vulnerability>) -> OsvDatabase {
        let mut db = OsvDatabase::default();
        for v in vulns {
            db.insert(v);
        }
        db
    }

    /// Loads every `*.json` file under `path` (recursively, in sorted order),
    /// or a single file. Each file holds one advisory or an array of them.
    pub fn load(path: &Path) -> Result<OsvDatabase> {
        let mut files = Vec::new();
        collect_json(path, &mut files)?;
        files.sort();
        let mut db = OsvDatabase::default();
        for f in &files {
            let text = std::fs::read_to_string(f).map_err(|e| Error::io(f, e))?;
            let what = f.display().to_string();
            let value: Value = serde_json::from_str(&text).map_err(|e| Error::json(&what, e))?;
            let items = match value {
                Value::Array(a) => a,
                other => vec![other],
            };
            for item in items {
                let v: Vulnerability = serde_json::from_value(item).map_err(|e| Error::json(&what, e))?;
                db.insert(v);
            }
            db.stats.files += 1;
        }
        if db.stats.files == 0 {
            return Err(Error::invalid(path.display().to_string(), "no OSV *.json files found"));
        }
        tracing::debug!(records = db.stats.records, files = db.stats.files, "loaded OSV database");
        Ok(db)
    }

    fn insert(&mut self, v: Vulnerability) {
        self.stats.records += 1;
        if v.withdrawn.is_some() {
            self.stats.withdrawn += 1;
            self.vulns.push(v);
            return;
        }
        let vi = self.vulns.len();
        for (ai, a) in v.affected.iter().enumerate() {
            let Some(pkg) = &a.package else { continue };
            let eco = Ecosystem::from_osv(&pkg.ecosystem);
            let Some(scheme) = eco.scheme() else {
                self.stats.affected_unsupported += 1;
                continue;
            };
            let mut entry = IndexedAffected {
                vuln: vi,
                affected: ai,
                ranges: Vec::new(),
                versions_raw: a.versions.iter().cloned().collect(),
                versions_keys: HashSet::new(),
                partially_evaluable: false,
            };
            for r in &a.ranges {
                match CompiledRange::compile(r, &eco) {
                    Ok(c) => {
                        self.stats.ranges_compiled += 1;
                        entry.ranges.push(c);
                    }
                    Err(e) => {
                        entry.partially_evaluable = true;
                        let reason = match e {
                            super::range::RangeError::BadVersion(_) => "unparseable event version".to_string(),
                            other => other.to_string(),
                        };
                        *self.stats.ranges_skipped.entry(reason).or_insert(0) += 1;
                    }
                }
            }
            for raw in &a.versions {
                if let Ok(parsed) = Version::parse(scheme, raw) {
                    entry.versions_keys.insert(parsed.key());
                }
            }
            self.stats.affected_indexed += 1;
            let name = eco.normalize_name(&pkg.name);
            self.index.entry((eco, name)).or_default().push(entry);
        }
        self.vulns.push(v);
    }

    /// Affected entries for a package (name in OSV spelling; normalized here).
    pub fn lookup(&self, ecosystem: &Ecosystem, name: &str) -> &[IndexedAffected] {
        self.index
            .get(&(ecosystem.clone(), ecosystem.normalize_name(name)))
            .map_or(&[], Vec::as_slice)
    }

    /// Number of distinct `(ecosystem, package)` keys in the index.
    pub fn package_count(&self) -> usize {
        self.index.len()
    }
}

fn collect_json(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let meta = std::fs::metadata(path).map_err(|e| Error::io(path, e))?;
    if meta.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(path).map_err(|e| Error::io(path, e))? {
        let p = entry.map_err(|e| Error::io(path, e))?.path();
        if p.is_dir() {
            collect_json(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "json") {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vuln(v: Value) -> Vulnerability {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn indexes_and_counts() {
        let db = OsvDatabase::from_vulns(vec![
            vuln(json!({"id": "A", "affected": [
                {"package": {"ecosystem": "PyPI", "name": "Foo_Bar"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]},
                            {"type": "GIT", "events": [{"introduced": "abc"}]}],
                 "versions": ["0.9", "not a version"]},
                {"package": {"ecosystem": "Debian:12", "name": "foo"}},
                {"ranges": []}
            ]})),
            vuln(json!({"id": "W", "withdrawn": "2024-01-01T00:00:00Z",
                        "affected": [{"package": {"ecosystem": "npm", "name": "x"}}]})),
            vuln(json!({"id": "B", "affected": [{"package": {"ecosystem": "crates.io", "name": "c"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "x.y"}]}]}]})),
        ]);
        assert_eq!(db.stats.records, 3);
        assert_eq!(db.stats.withdrawn, 1);
        assert_eq!(db.stats.affected_indexed, 2);
        assert_eq!(db.stats.affected_unsupported, 1);
        assert_eq!(db.stats.ranges_compiled, 1);
        assert_eq!(db.stats.ranges_skipped.values().sum::<usize>(), 2);
        let hits = db.lookup(&Ecosystem::PyPI, "foo.bar");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].partially_evaluable);
        assert!(hits[0].versions_keys.contains("0.9"));
        assert!(hits[0].versions_raw.contains("not a version"));
        assert!(db.lookup(&Ecosystem::Npm, "x").is_empty());
        assert_eq!(db.package_count(), 2);
    }

    #[test]
    fn load_errors() {
        assert!(matches!(
            OsvDatabase::load(Path::new("/nonexistent/osv")),
            Err(Error::Io { .. })
        ));
        let dir = std::env::temp_dir().join(format!("sbomlens-db-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(matches!(OsvDatabase::load(&dir), Err(Error::Invalid { .. })));
        std::fs::write(dir.join("bad.json"), "{").unwrap();
        assert!(matches!(OsvDatabase::load(&dir), Err(Error::Json { .. })));
        std::fs::write(dir.join("bad.json"), r#"[{"id": "A"}, {"id": "B"}]"#).unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/c.json"), r#"{"id": "C"}"#).unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let db = OsvDatabase::load(&dir).unwrap();
        assert_eq!((db.stats.files, db.stats.records), (2, 3));
        std::fs::write(dir.join("bad.json"), r#"{"no_id": true}"#).unwrap();
        assert!(matches!(OsvDatabase::load(&dir), Err(Error::Json { .. })));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
