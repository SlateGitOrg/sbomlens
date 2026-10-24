//! # sbomlens
//!
//! An offline SBOM toolkit:
//!
//! * [`sbom`] reads CycloneDX 1.5/1.6 and SPDX 2.3 JSON into one normalized
//!   [`graph::SbomGraph`] with spec-conformant [`purl::Purl`]s;
//! * [`diff`] compares two SBOMs (added / removed / upgraded / downgraded /
//!   license changes) using each ecosystem's own version ordering;
//! * [`osv`] matches components against an offline OSV database with correct
//!   per-ecosystem semantics ([`version`]: SemVer, PEP 440, Maven, Go);
//! * [`vex`] applies OpenVEX statements to the findings;
//! * [`report`] renders SARIF 2.1.0, Markdown and JSON.
#![forbid(unsafe_code)]

pub mod cli;
pub mod cvss;
pub mod diff;
pub mod ecosystem;
pub mod error;
pub mod graph;
pub mod license;
pub mod osv;
pub mod purl;
pub mod report;
pub mod sbom;
pub mod version;
pub mod vex;

pub use error::{Error, Result};
