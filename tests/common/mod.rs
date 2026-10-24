//! Shared helpers for integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

use sbomlens::graph::SbomGraph;
use sbomlens::osv::OsvDatabase;

/// Absolute path of a file under the crate root.
pub fn path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Loads an SBOM fixture.
pub fn sbom(rel: &str) -> SbomGraph {
    sbomlens::sbom::load(&path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Loads the pinned OSV subset.
pub fn osv() -> OsvDatabase {
    OsvDatabase::load(&path("fixtures/osv/db")).expect("OSV subset")
}

pub const EXPRESS_OLD_CDX: &str = "fixtures/sbom/real/express-4.17.1.cdx.json";
pub const EXPRESS_OLD_SPDX: &str = "fixtures/sbom/real/express-4.17.1.spdx.json";
pub const EXPRESS_NEW_CDX: &str = "fixtures/sbom/real/express-4.21.2.cdx.json";
pub const EXPRESS_NEW_SPDX: &str = "fixtures/sbom/real/express-4.21.2.spdx.json";
pub const FLASK_CDX: &str = "fixtures/sbom/real/flask-2.2.2.cdx.json";
pub const POLYGLOT_CDX: &str = "fixtures/sbom/synthetic/polyglot-gateway.cdx.json";
pub const EXPRESS_VEX: &str = "fixtures/vex/express-4.17.1.openvex.json";
