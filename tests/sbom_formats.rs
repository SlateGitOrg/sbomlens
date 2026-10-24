//! Loading real SBOMs: CycloneDX and SPDX renderings of the same dependency
//! closure must normalize to the same component graph.

mod common;

use std::collections::BTreeSet;

use common::*;
use sbomlens::graph::{SbomFormat, SbomGraph};

fn purl_set(g: &SbomGraph) -> BTreeSet<String> {
    g.components.iter().filter_map(|c| c.purl.as_ref().map(ToString::to_string)).collect()
}

fn edge_set(g: &SbomGraph) -> BTreeSet<(String, String)> {
    let name = |i: usize| g.components[i].purl.as_ref().map(ToString::to_string).unwrap_or_default();
    g.edges
        .iter()
        .enumerate()
        .flat_map(|(from, tos)| tos.iter().map(move |&to| (name(from), name(to))))
        .collect()
}

#[test]
fn cyclonedx_and_spdx_of_one_closure_agree() {
    for (cdx, spdx) in [(EXPRESS_OLD_CDX, EXPRESS_OLD_SPDX), (EXPRESS_NEW_CDX, EXPRESS_NEW_SPDX)] {
        let a = sbom(cdx);
        let b = sbom(spdx);
        assert_eq!(a.format, SbomFormat::CycloneDx("1.5".into()));
        assert_eq!(b.format, SbomFormat::Spdx("2.3".into()));
        assert_eq!(purl_set(&a), purl_set(&b), "{cdx} vs {spdx}: components");
        assert_eq!(edge_set(&a), edge_set(&b), "{cdx} vs {spdx}: dependency edges");
        assert_eq!(a.stats().max_depth, b.stats().max_depth);
        assert_eq!(a.roots.len(), 1);
        assert_eq!(b.roots.len(), 1);
        assert!(a.warnings.is_empty(), "{:?}", a.warnings);
        assert!(b.warnings.is_empty(), "{:?}", b.warnings);
        // Licenses agree component by component.
        for c in &a.components {
            let other = b.components.iter().find(|x| x.purl == c.purl).unwrap();
            assert_eq!(c.license, other.license, "{:?}", c.purl);
        }
    }
}

#[test]
fn express_closure_shape() {
    let g = sbom(EXPRESS_OLD_CDX);
    let s = g.stats();
    assert_eq!(s.components, 51);
    assert_eq!(s.with_purl, 51);
    assert_eq!(s.ecosystems.get("npm"), Some(&51));
    let express = g.components.iter().position(|c| c.display_name() == "express").unwrap();
    let (parent, depth) = g.bfs_from_roots();
    assert_eq!(depth[express], 1);
    let qs = g.components.iter().position(|c| c.display_name() == "qs").unwrap();
    let path: Vec<String> = g
        .path_to(qs, &parent, &depth)
        .unwrap()
        .into_iter()
        .map(|i| g.components[i].display_name())
        .collect();
    assert_eq!(path.last().map(String::as_str), Some("qs"));
    assert!(path.contains(&"express".to_string()));
}

#[test]
fn uv_exported_pypi_closure() {
    let g = sbom(FLASK_CDX);
    assert_eq!(g.components.len(), 13);
    assert_eq!(g.stats().ecosystems.get("PyPI"), Some(&12));
    let flask = g.components.iter().find(|c| c.name == "flask").unwrap();
    assert_eq!(flask.effective_version(), Some("2.2.2"));
    // uv's root component carries no purl.
    assert_eq!(g.components[g.roots[0]].purl, None);
    assert_eq!(g.stats().max_depth, 3);
}

#[test]
fn polyglot_cyclonedx_16_nested_components() {
    let g = sbom(POLYGLOT_CDX);
    let s = g.stats();
    assert_eq!(g.format, SbomFormat::CycloneDx("1.6".into()));
    assert_eq!(s.components, 19);
    for (eco, n) in [("crates.io", 5), ("Go", 5), ("Maven", 6), ("PyPI", 1), ("npm", 1)] {
        assert_eq!(s.ecosystems.get(eco), Some(&n), "{eco}");
    }
    let net = g.components.iter().find(|c| c.display_name() == "golang.org/x/net").unwrap();
    assert_eq!(net.effective_version(), Some("v0.0.0-20210226172049-e18ecbb05110"));
    let root = &g.components[g.roots[0]];
    assert_eq!(root.license.as_ref().unwrap().to_string(), "Apache-2.0 OR MIT");
}
