//! SPDX 2.3 JSON (2.2 accepted with a warning).
//!
//! Mapping:
//! * every `packages[]` entry becomes a component keyed by its `SPDXID`;
//!   the purl comes from an `externalRefs` entry with `referenceType: purl`;
//! * license = `licenseConcluded`, falling back to `licenseDeclared` when the
//!   concluded value is `NOASSERTION`/`NONE`/absent;
//! * relationships are normalized to "A depends on / contains B" edges
//!   (`DEPENDS_ON`, `CONTAINS`, `HAS_PREREQUISITE`, `*_LINK` forward;
//!   `DEPENDENCY_OF`, `*_DEPENDENCY_OF`, `CONTAINED_BY`, `PREREQUISITE_FOR`
//!   reversed);
//! * roots come from `documentDescribes` and `DESCRIBES` / `DESCRIBED_BY`.

use serde::Deserialize;
use serde_json::Value;

use super::{attach_purl, parse_purl};
use crate::error::{Error, Result};
use crate::graph::{Component, GraphBuilder, SbomFormat, SbomGraph};
use crate::license::License;

const SUPPORTED: &str = "SPDX-2.3 (SPDX-2.2 read with a warning)";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    spdx_version: String,
    #[serde(rename = "SPDXID", default)]
    spdx_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    document_describes: Vec<String>,
    #[serde(default)]
    packages: Vec<Package>,
    #[serde(default)]
    relationships: Vec<Relationship>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Package {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version_info: Option<String>,
    #[serde(default)]
    supplier: Option<String>,
    #[serde(default)]
    license_concluded: Option<String>,
    #[serde(default)]
    license_declared: Option<String>,
    #[serde(default)]
    primary_package_purpose: Option<String>,
    #[serde(default)]
    external_refs: Vec<ExternalRef>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalRef {
    #[serde(default)]
    reference_type: String,
    #[serde(default)]
    reference_locator: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Relationship {
    spdx_element_id: String,
    related_spdx_element: String,
    relationship_type: String,
}

/// Direction of a relationship once normalized to "from depends on/contains to".
enum Direction {
    Forward,
    Reverse,
    Describes,
    DescribedBy,
    Ignore,
}

fn direction(rel: &str) -> Direction {
    match rel {
        "DEPENDS_ON" | "CONTAINS" | "HAS_PREREQUISITE" | "STATIC_LINK" | "DYNAMIC_LINK" => {
            Direction::Forward
        }
        "DEPENDENCY_OF"
        | "DEV_DEPENDENCY_OF"
        | "OPTIONAL_DEPENDENCY_OF"
        | "BUILD_DEPENDENCY_OF"
        | "TEST_DEPENDENCY_OF"
        | "RUNTIME_DEPENDENCY_OF"
        | "PROVIDED_DEPENDENCY_OF"
        | "CONTAINED_BY"
        | "PREREQUISITE_FOR" => Direction::Reverse,
        "DESCRIBES" => Direction::Describes,
        "DESCRIBED_BY" => Direction::DescribedBy,
        _ => Direction::Ignore,
    }
}

fn license_of(p: &Package) -> Option<License> {
    p.license_concluded
        .as_deref()
        .and_then(License::from_sbom)
        .or_else(|| p.license_declared.as_deref().and_then(License::from_sbom))
}

/// Converts a decoded SPDX document into a graph.
pub fn parse(value: Value, what: &str) -> Result<SbomGraph> {
    let doc: Document = serde_json::from_value(value).map_err(|e| Error::json(what, e))?;
    let version = doc.spdx_version.trim().to_string();
    let short = version.strip_prefix("SPDX-").unwrap_or(&version).to_string();
    let old = match short.as_str() {
        "2.3" => false,
        "2.2" => true,
        _ => {
            return Err(Error::UnsupportedVersion {
                what: what.to_string(),
                format: "SPDX",
                version,
                supported: SUPPORTED,
            })
        }
    };
    let doc_id = doc.spdx_id.clone().unwrap_or_else(|| "SPDXRef-DOCUMENT".into());
    let mut b = GraphBuilder::new(SbomFormat::Spdx(short.clone()), doc.name.clone());
    if old {
        b.warn(format!("SPDX {short} is older than 2.3; fields were read with 2.3 semantics"));
    }
    for p in &doc.packages {
        let mut c = Component::new(p.spdx_id.clone(), p.name.clone());
        c.version = p
            .version_info
            .clone()
            .filter(|v| !v.is_empty() && v != "NOASSERTION");
        c.kind = p
            .primary_package_purpose
            .clone()
            .unwrap_or_else(|| "LIBRARY".into())
            .to_ascii_lowercase();
        c.license = license_of(p);
        if let Some(s) = p.supplier.as_deref() {
            // "Organization: Acme" -> group-like attribution for purl-less packages.
            if let Some((_, org)) = s.split_once(':') {
                let org = org.trim();
                if !org.is_empty() && org != "NOASSERTION" {
                    c.group = Some(org.to_string());
                }
            }
        }
        let mut warnings = Vec::new();
        let purl = p
            .external_refs
            .iter()
            .find(|r| r.reference_type.eq_ignore_ascii_case("purl"))
            .and_then(|r| parse_purl(&r.reference_locator, &p.spdx_id, &mut warnings));
        let c = attach_purl(c, purl, &mut warnings);
        for w in warnings {
            b.warn(w);
        }
        b.add(c);
    }
    for d in &doc.document_describes {
        b.root_ref(d.clone());
    }
    let mut ignored = 0usize;
    for r in &doc.relationships {
        let (a, z) = (&r.spdx_element_id, &r.related_spdx_element);
        match direction(r.relationship_type.as_str()) {
            Direction::Forward => b.edge_ref(a.clone(), z.clone()),
            Direction::Reverse => b.edge_ref(z.clone(), a.clone()),
            Direction::Describes if *a == doc_id => b.root_ref(z.clone()),
            Direction::DescribedBy if *z == doc_id => b.root_ref(a.clone()),
            Direction::Describes | Direction::DescribedBy => {}
            Direction::Ignore => ignored += 1,
        }
    }
    if ignored > 0 {
        tracing::debug!(ignored, "SPDX relationships without dependency meaning ignored");
    }
    Ok(b.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pkg(id: &str, purl: &str) -> Value {
        json!({"SPDXID": id, "name": id, "versionInfo": "1.0.0",
               "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]})
    }

    #[test]
    fn relationship_directions_and_roots() {
        let doc = json!({
            "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "doc",
            "packages": [
                pkg("SPDXRef-app", "pkg:npm/app@1.0.0"),
                pkg("SPDXRef-a", "pkg:npm/a@1.0.0"),
                pkg("SPDXRef-b", "pkg:npm/b@1.0.0"),
                pkg("SPDXRef-c", "pkg:npm/c@1.0.0"),
                {"SPDXID": "SPDXRef-d", "name": "d", "versionInfo": "NOASSERTION",
                 "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT",
                 "supplier": "Organization: Acme", "primaryPackagePurpose": "APPLICATION"}
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-app", "relationshipType": "DESCRIBES"},
                {"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-app", "relationshipType": "DEPENDENCY_OF"},
                {"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-b", "relationshipType": "DEPENDS_ON"},
                {"spdxElementId": "SPDXRef-c", "relatedSpdxElement": "SPDXRef-b", "relationshipType": "DEV_DEPENDENCY_OF"},
                {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-d", "relationshipType": "OTHER"},
                {"spdxElementId": "SPDXRef-d", "relatedSpdxElement": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBED_BY"},
                {"spdxElementId": "SPDXRef-x", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "DESCRIBES"},
                {"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-File-1", "relationshipType": "CONTAINS"}
            ]
        });
        let g = parse(doc, "t").unwrap();
        assert_eq!(g.roots, vec![0, 4]);
        assert_eq!(g.edges[0], vec![1]);
        assert_eq!(g.edges[1], vec![2]);
        assert_eq!(g.edges[2], vec![3]);
        let d = &g.components[4];
        assert_eq!(d.version, None);
        assert_eq!(d.license.as_ref().unwrap().to_string(), "MIT");
        assert_eq!(d.group.as_deref(), Some("Acme"));
        assert_eq!(d.kind, "application");
        assert_eq!(g.warnings.len(), 1, "{:?}", g.warnings);
    }

    #[test]
    fn version_gate() {
        let g = parse(json!({"spdxVersion": "SPDX-2.2"}), "t").unwrap();
        assert_eq!(g.warnings.len(), 1);
        assert!(matches!(
            parse(json!({"spdxVersion": "SPDX-3.0"}), "t"),
            Err(Error::UnsupportedVersion { .. })
        ));
        assert!(matches!(parse(json!({"spdxVersion": 3}), "t"), Err(Error::Json { .. })));
    }
}
