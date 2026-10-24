//! The normalized component graph every SBOM format is converted into.
//!
//! Components are de-duplicated (same canonical purl, or same source
//! reference when there is no purl), dependency and containment edges are
//! stored as adjacency lists, and roots are the documents' described
//! components. Graph queries (shortest dependency path from a root, direct vs
//! transitive) power the "introduced via" column of vulnerability reports.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;

use serde::Serialize;

use crate::ecosystem::Ecosystem;
use crate::license::License;
use crate::purl::Purl;

/// Which document format a graph was loaded from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "format", content = "spec_version")]
pub enum SbomFormat {
    /// CycloneDX JSON with its `specVersion`.
    CycloneDx(String),
    /// SPDX JSON with its `spdxVersion` (without the `SPDX-` prefix).
    Spdx(String),
}

impl fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SbomFormat::CycloneDx(v) => write!(f, "CycloneDX {v}"),
            SbomFormat::Spdx(v) => write!(f, "SPDX {v}"),
        }
    }
}

/// A component (package) in the normalized graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Component {
    /// The identifier the source document used (`bom-ref` or `SPDXID`).
    pub source_ref: String,
    /// Optional group / namespace given separately from the purl (CycloneDX `group`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Package name as given by the document.
    pub name: String,
    /// Version as given by the document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Parsed purl, when the document provided a valid one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<Purl>,
    /// Ecosystem derived from the purl type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<Ecosystem>,
    /// Declared/concluded license.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<License>,
    /// Component kind (`library`, `application`, ...), lower-case.
    pub kind: String,
}

impl Component {
    /// Creates a bare component; fill the optional fields directly.
    pub fn new(source_ref: impl Into<String>, name: impl Into<String>) -> Component {
        Component {
            source_ref: source_ref.into(),
            group: None,
            name: name.into(),
            version: None,
            purl: None,
            ecosystem: None,
            license: None,
            kind: "library".into(),
        }
    }

    /// Attaches a purl (and the ecosystem it implies).
    #[must_use]
    pub fn with_purl(mut self, purl: Purl) -> Component {
        self.ecosystem = Some(Ecosystem::from_purl_type(&purl.ty));
        self.purl = Some(purl);
        self
    }

    /// The effective version: the purl's version, else the document's.
    pub fn effective_version(&self) -> Option<&str> {
        self.purl
            .as_ref()
            .and_then(|p| p.version.as_deref())
            .or(self.version.as_deref())
    }

    /// Human-readable package name (`@scope/name`, `group:artifact`, module path).
    pub fn display_name(&self) -> String {
        match (&self.purl, &self.ecosystem) {
            (Some(p), Some(Ecosystem::Maven)) => Ecosystem::Maven.package_name(p),
            (Some(p), _) => p.full_name(),
            (None, _) => match &self.group {
                Some(g) => format!("{g}/{}", self.name),
                None => self.name.clone(),
            },
        }
    }

    /// Version-independent identity used to pair components across SBOMs:
    /// the purl package key (with PyPI names PEP 503-normalized), or a
    /// `name:` key for purl-less components.
    pub fn identity(&self) -> String {
        match &self.purl {
            Some(p) => p.package_key(),
            None => format!("name:{}", self.display_name().to_ascii_lowercase()),
        }
    }

    /// Identity including the version, used to de-duplicate within one SBOM.
    fn dedup_key(&self) -> Option<String> {
        self.purl.as_ref().map(|p| {
            let mut q = p.clone();
            q.subpath = None;
            q.to_string()
        })
    }
}

/// A normalized SBOM: components, dependency edges and roots.
#[derive(Debug, Clone, Serialize)]
pub struct SbomGraph {
    /// Source format and spec version.
    pub format: SbomFormat,
    /// Document or primary-component name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// All components; indices are stable for the life of the graph.
    pub components: Vec<Component>,
    /// `edges[i]` lists the components `i` depends on or contains (sorted, unique).
    pub edges: Vec<Vec<usize>>,
    /// Root components (what the document describes).
    pub roots: Vec<usize>,
    /// Non-fatal problems found while loading (bad purls, dangling refs, ...).
    pub warnings: Vec<String>,
}

/// Summary statistics of a graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphStats {
    /// Number of components.
    pub components: usize,
    /// Number of edges.
    pub edges: usize,
    /// Number of roots.
    pub roots: usize,
    /// Components carrying a valid purl.
    pub with_purl: usize,
    /// Components carrying license information.
    pub with_license: usize,
    /// Component count per ecosystem (`unknown` when no purl).
    pub ecosystems: BTreeMap<String, usize>,
    /// Longest shortest-path depth from any root.
    pub max_depth: usize,
}

impl SbomGraph {
    /// Reverse adjacency: `dependents()[i]` lists components that depend on `i`.
    pub fn dependents(&self) -> Vec<Vec<usize>> {
        let mut rev = vec![Vec::new(); self.components.len()];
        for (from, tos) in self.edges.iter().enumerate() {
            for &to in tos {
                rev[to].push(from);
            }
        }
        rev
    }

    /// Breadth-first shortest paths from the roots: `parent[i]` is the
    /// predecessor on one shortest path, `depth[i]` the distance (roots are 0).
    /// Unreachable components have `depth == usize::MAX`.
    pub fn bfs_from_roots(&self) -> (Vec<Option<usize>>, Vec<usize>) {
        let n = self.components.len();
        let mut parent = vec![None; n];
        let mut depth = vec![usize::MAX; n];
        let mut q = VecDeque::new();
        for &r in &self.roots {
            if depth[r] == usize::MAX {
                depth[r] = 0;
                q.push_back(r);
            }
        }
        while let Some(u) = q.pop_front() {
            for &v in &self.edges[u] {
                if depth[v] == usize::MAX {
                    depth[v] = depth[u] + 1;
                    parent[v] = Some(u);
                    q.push_back(v);
                }
            }
        }
        (parent, depth)
    }

    /// One shortest path from a root to `target` (inclusive), using the
    /// output of [`SbomGraph::bfs_from_roots`]. `None` when unreachable.
    pub fn path_to(
        &self,
        target: usize,
        parent: &[Option<usize>],
        depth: &[usize],
    ) -> Option<Vec<usize>> {
        if depth.get(target).copied().unwrap_or(usize::MAX) == usize::MAX {
            return None;
        }
        let mut path = vec![target];
        let mut cur = target;
        while let Some(p) = parent[cur] {
            path.push(p);
            cur = p;
        }
        path.reverse();
        Some(path)
    }

    /// Index of components by version-independent identity.
    pub fn by_identity(&self) -> BTreeMap<String, Vec<usize>> {
        let mut m: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, c) in self.components.iter().enumerate() {
            m.entry(c.identity()).or_default().push(i);
        }
        m
    }

    /// Computes summary statistics.
    pub fn stats(&self) -> GraphStats {
        let mut ecosystems = BTreeMap::new();
        for c in &self.components {
            let k = c
                .ecosystem
                .as_ref()
                .map_or_else(|| "unknown".to_string(), ToString::to_string);
            *ecosystems.entry(k).or_insert(0) += 1;
        }
        let (_, depth) = self.bfs_from_roots();
        GraphStats {
            components: self.components.len(),
            edges: self.edges.iter().map(Vec::len).sum(),
            roots: self.roots.len(),
            with_purl: self.components.iter().filter(|c| c.purl.is_some()).count(),
            with_license: self
                .components
                .iter()
                .filter(|c| c.license.is_some())
                .count(),
            ecosystems,
            max_depth: depth
                .into_iter()
                .filter(|d| *d != usize::MAX)
                .max()
                .unwrap_or(0),
        }
    }
}

/// Incrementally builds an [`SbomGraph`], resolving source references and
/// de-duplicating components.
#[derive(Debug)]
pub struct GraphBuilder {
    format: SbomFormat,
    name: Option<String>,
    components: Vec<Component>,
    edges: Vec<Vec<usize>>,
    roots: Vec<usize>,
    by_ref: HashMap<String, usize>,
    by_key: HashMap<String, usize>,
    pending_edges: Vec<(String, String)>,
    pending_roots: Vec<String>,
    warnings: Vec<String>,
}

impl GraphBuilder {
    /// Starts a graph for a document of the given format.
    pub fn new(format: SbomFormat, name: Option<String>) -> GraphBuilder {
        GraphBuilder {
            format,
            name,
            components: Vec::new(),
            edges: Vec::new(),
            roots: Vec::new(),
            by_ref: HashMap::new(),
            by_key: HashMap::new(),
            pending_edges: Vec::new(),
            pending_roots: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Records a non-fatal loading problem.
    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Adds a component and returns its index. A component whose purl (minus
    /// subpath) was already seen is merged into the earlier one: its source
    /// reference becomes an alias and missing fields are filled in.
    pub fn add(&mut self, c: Component) -> usize {
        if let Some(&idx) = self.by_ref.get(&c.source_ref) {
            self.warn(format!(
                "duplicate reference {:?}; keeping the first",
                c.source_ref
            ));
            return idx;
        }
        if let Some(key) = c.dedup_key() {
            if let Some(&idx) = self.by_key.get(&key) {
                let existing = &mut self.components[idx];
                if existing.license.is_none() {
                    existing.license = c.license;
                }
                self.by_ref.insert(c.source_ref, idx);
                return idx;
            }
            self.by_key.insert(key, self.components.len());
        }
        let idx = self.components.len();
        self.by_ref.insert(c.source_ref.clone(), idx);
        self.components.push(c);
        self.edges.push(Vec::new());
        idx
    }

    /// Adds an edge by index.
    pub fn edge(&mut self, from: usize, to: usize) {
        if from != to {
            self.edges[from].push(to);
        }
    }

    /// Adds an edge by source reference; resolved in [`GraphBuilder::finish`].
    pub fn edge_ref(&mut self, from: impl Into<String>, to: impl Into<String>) {
        self.pending_edges.push((from.into(), to.into()));
    }

    /// Marks a component (by index) as a root.
    pub fn root(&mut self, idx: usize) {
        self.roots.push(idx);
    }

    /// Marks a component (by source reference) as a root.
    pub fn root_ref(&mut self, r: impl Into<String>) {
        self.pending_roots.push(r.into());
    }

    /// Resolves references, sorts and de-duplicates edges and roots, and
    /// falls back to "components nobody depends on" as roots when the
    /// document named none.
    pub fn finish(mut self) -> SbomGraph {
        let mut dangling = 0usize;
        for (from, to) in std::mem::take(&mut self.pending_edges) {
            match (self.by_ref.get(&from), self.by_ref.get(&to)) {
                (Some(&a), Some(&b)) => self.edge(a, b),
                _ => dangling += 1,
            }
        }
        if dangling > 0 {
            self.warn(format!(
                "{dangling} relationship(s) reference unknown elements and were ignored"
            ));
        }
        for r in std::mem::take(&mut self.pending_roots) {
            match self.by_ref.get(&r) {
                Some(&i) => self.roots.push(i),
                None => self.warn(format!("root {r:?} is not a known component")),
            }
        }
        for e in &mut self.edges {
            e.sort_unstable();
            e.dedup();
        }
        if self.roots.is_empty() {
            let mut has_parent = vec![false; self.components.len()];
            for tos in &self.edges {
                for &t in tos {
                    has_parent[t] = true;
                }
            }
            self.roots = (0..self.components.len())
                .filter(|&i| !has_parent[i])
                .collect();
        }
        self.roots.sort_unstable();
        self.roots.dedup();
        SbomGraph {
            format: self.format,
            name: self.name,
            components: self.components,
            edges: self.edges,
            roots: self.roots,
            warnings: self.warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(r: &str, purl: &str) -> Component {
        Component::new(r, r).with_purl(Purl::parse(purl).unwrap())
    }

    #[test]
    fn dedups_by_purl_and_resolves_aliases() {
        let mut b = GraphBuilder::new(SbomFormat::CycloneDx("1.6".into()), None);
        let app = b.add(Component::new("app", "app"));
        let a1 = b.add(comp("a", "pkg:npm/a@1.0.0"));
        let a2 = b.add(comp("a-again", "pkg:npm/a@1.0.0#sub"));
        assert_eq!(a1, a2);
        b.add(comp("b", "pkg:npm/b@2.0.0"));
        b.root(app);
        b.edge_ref("app", "a-again");
        b.edge_ref("a", "b");
        b.edge_ref("a", "b");
        b.edge_ref("a", "missing");
        b.root_ref("nope");
        let g = b.finish();
        assert_eq!(g.components.len(), 3);
        assert_eq!(g.edges[a1], vec![2]);
        assert_eq!(g.warnings.len(), 2);
        let (parent, depth) = g.bfs_from_roots();
        let path = g.path_to(2, &parent, &depth).unwrap();
        assert_eq!(path, vec![0, 1, 2]);
        let s = g.stats();
        assert_eq!(s.max_depth, 2);
        assert_eq!(s.with_purl, 2);
        assert_eq!(s.ecosystems["npm"], 2);
        assert_eq!(s.ecosystems["unknown"], 1);
        assert_eq!(g.dependents()[2], vec![1]);
    }

    #[test]
    fn roots_default_to_unreferenced_components() {
        let mut b = GraphBuilder::new(SbomFormat::Spdx("2.3".into()), Some("doc".into()));
        let x = b.add(comp("x", "pkg:cargo/x@1.0.0"));
        let y = b.add(comp("y", "pkg:cargo/y@1.0.0"));
        let z = b.add(Component::new("z", "z"));
        b.edge(x, y);
        b.edge(x, x);
        let g = b.finish();
        assert_eq!(g.roots, vec![x, z]);
        let (parent, depth) = g.bfs_from_roots();
        assert!(g.path_to(y, &parent, &depth).is_some());
        assert_eq!(g.format.to_string(), "SPDX 2.3");
    }

    #[test]
    fn identity_and_display_names() {
        let c = comp("m", "pkg:maven/org.example/lib@1.0");
        assert_eq!(c.display_name(), "org.example:lib");
        assert_eq!(c.identity(), "pkg:maven/org.example/lib");
        let mut bare = Component::new("r", "Thing");
        bare.group = Some("acme".into());
        bare.version = Some("2".into());
        assert_eq!(bare.display_name(), "acme/Thing");
        assert_eq!(bare.identity(), "name:acme/thing");
        assert_eq!(bare.effective_version(), Some("2"));
        assert_eq!(c.effective_version(), Some("1.0"));
    }
}
