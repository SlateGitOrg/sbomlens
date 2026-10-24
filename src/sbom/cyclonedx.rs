//! CycloneDX JSON (1.5 and 1.6; 1.2–1.4 accepted with a warning).
//!
//! Mapping:
//! * `metadata.component` becomes the root; when the document has no
//!   `dependencies` section, every top-level component hangs off it.
//! * `components[]` are flattened depth-first; a nested component is linked
//!   from its parent with a containment edge.
//! * `dependencies[].ref → dependsOn[]` become dependency edges.
//! * `licenses[]` entries (`license.id`, `license.name`, `expression`) are
//!   combined into one canonical expression.

use serde::Deserialize;
use serde_json::Value;

use super::{attach_purl, parse_purl};
use crate::error::{Error, Result};
use crate::graph::{Component, GraphBuilder, SbomFormat, SbomGraph};
use crate::license::License;

const SUPPORTED: &str = "1.5, 1.6 (1.2-1.4 read with a warning)";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bom {
    spec_version: String,
    #[serde(default)]
    metadata: Option<Metadata>,
    #[serde(default)]
    components: Vec<CdxComponent>,
    #[serde(default)]
    dependencies: Option<Vec<Dependency>>,
}

#[derive(Deserialize)]
struct Metadata {
    #[serde(default)]
    component: Option<CdxComponent>,
}

#[derive(Deserialize)]
struct CdxComponent {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(rename = "bom-ref", default)]
    bom_ref: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    licenses: Vec<LicenseChoice>,
    #[serde(default)]
    components: Vec<CdxComponent>,
}

#[derive(Deserialize)]
struct LicenseChoice {
    #[serde(default)]
    license: Option<LicenseObj>,
    #[serde(default)]
    expression: Option<String>,
}

#[derive(Deserialize)]
struct LicenseObj {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Dependency {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(default)]
    depends_on: Vec<String>,
}

fn license_of(choices: &[LicenseChoice]) -> Option<License> {
    let items: Vec<License> = choices
        .iter()
        .filter_map(|c| {
            if let Some(e) = &c.expression {
                return License::from_sbom(e);
            }
            let l = c.license.as_ref()?;
            match (&l.id, &l.name) {
                (Some(id), _) => License::from_sbom(id),
                (None, Some(name)) => {
                    let n = name.trim();
                    (!n.is_empty()).then(|| License::Text(n.to_string()))
                }
                (None, None) => None,
            }
        })
        .collect();
    License::all_of(items)
}

struct Walker<'a> {
    builder: GraphBuilder,
    what: &'a str,
    anon: usize,
}

impl Walker<'_> {
    fn component(&mut self, c: &CdxComponent) -> usize {
        let source_ref = c.bom_ref.clone().unwrap_or_else(|| {
            self.anon += 1;
            format!("{}#anonymous-{}", self.what, self.anon)
        });
        let mut comp = Component::new(source_ref.clone(), c.name.clone());
        comp.group = c.group.clone().filter(|g| !g.is_empty());
        comp.version = c.version.clone().filter(|v| !v.is_empty());
        comp.kind = c
            .kind
            .clone()
            .unwrap_or_else(|| "library".into())
            .to_ascii_lowercase();
        comp.license = license_of(&c.licenses);
        let mut warnings = Vec::new();
        let purl = c
            .purl
            .as_deref()
            .and_then(|p| parse_purl(p, &source_ref, &mut warnings));
        let comp = attach_purl(comp, purl, &mut warnings);
        for w in warnings {
            self.builder.warn(w);
        }
        let idx = self.builder.add(comp);
        for child in &c.components {
            let ci = self.component(child);
            self.builder.edge(idx, ci);
        }
        idx
    }
}

/// Converts a decoded CycloneDX document into a graph.
pub fn parse(value: Value, what: &str) -> Result<SbomGraph> {
    let bom: Bom = serde_json::from_value(value).map_err(|e| Error::json(what, e))?;
    let spec = bom.spec_version.trim().to_string();
    let mut warn_old = false;
    match spec.as_str() {
        "1.5" | "1.6" => {}
        "1.2" | "1.3" | "1.4" => warn_old = true,
        _ => {
            return Err(Error::UnsupportedVersion {
                what: what.to_string(),
                format: "CycloneDX",
                version: spec,
                supported: SUPPORTED,
            })
        }
    }
    let root_meta = bom.metadata.and_then(|m| m.component);
    let name = root_meta.as_ref().map(|c| c.name.clone());
    let mut w = Walker {
        builder: GraphBuilder::new(SbomFormat::CycloneDx(spec.clone()), name),
        what,
        anon: 0,
    };
    if warn_old {
        w.builder.warn(format!(
            "CycloneDX {spec} is older than 1.5; fields were read with 1.5 semantics"
        ));
    }
    let root = root_meta.as_ref().map(|c| w.component(c));
    if let Some(r) = root {
        w.builder.root(r);
    }
    let top: Vec<usize> = bom.components.iter().map(|c| w.component(c)).collect();
    match &bom.dependencies {
        Some(deps) if !deps.is_empty() => {
            for d in deps {
                for to in &d.depends_on {
                    w.builder.edge_ref(d.reference.clone(), to.clone());
                }
            }
        }
        _ => {
            if let Some(r) = root {
                for t in top {
                    w.builder.edge(r, t);
                }
            }
        }
    }
    Ok(w.builder.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn version_gate() {
        let doc = json!({"bomFormat": "CycloneDX", "specVersion": "2.0"});
        assert!(matches!(
            parse(doc, "t"),
            Err(Error::UnsupportedVersion { .. })
        ));
        let doc = json!({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []});
        let g = parse(doc, "t").unwrap();
        assert_eq!(g.warnings.len(), 1);
        let doc = json!({"bomFormat": "CycloneDX"});
        assert!(matches!(parse(doc, "t"), Err(Error::Json { .. })));
    }

    #[test]
    fn root_links_top_level_without_dependencies() {
        let doc = json!({
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": {"bom-ref": "app", "name": "app", "type": "Application"}},
            "components": [
                {"bom-ref": "a", "name": "a", "version": "1.0.0", "purl": "pkg:npm/a@1.0.0",
                 "licenses": [{"license": {"name": "Custom EULA"}}, {"license": {}}]},
                {"name": "anon", "purl": "not-a-purl",
                 "components": [{"bom-ref": "inner", "name": "inner", "licenses": [{"expression": "MIT OR ISC"}]}]}
            ]
        });
        let g = parse(doc, "t").unwrap();
        assert_eq!(g.roots, vec![0]);
        assert_eq!(g.components[0].kind, "application");
        assert_eq!(g.edges[0], vec![1, 2]);
        assert_eq!(g.edges[2], vec![3]);
        assert_eq!(
            g.components[1].license.as_ref().unwrap().to_string(),
            "Custom EULA"
        );
        assert_eq!(
            g.components[3].license.as_ref().unwrap().to_string(),
            "ISC OR MIT"
        );
        assert!(g.components[2].source_ref.contains("anonymous"));
        assert!(g.warnings.iter().any(|w| w.contains("invalid purl")));
    }
}
