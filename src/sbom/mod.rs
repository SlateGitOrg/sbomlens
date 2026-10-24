//! SBOM document loading: format detection and conversion into an
//! [`SbomGraph`](crate::graph::SbomGraph).

pub mod cyclonedx;
pub mod spdx;

use std::path::Path;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::graph::{Component, SbomGraph};
use crate::purl::Purl;

/// Parses an SBOM from JSON text, detecting CycloneDX vs SPDX.
/// `what` names the source in error messages and warnings.
pub fn parse_str(text: &str, what: &str) -> Result<SbomGraph> {
    let value: Value = serde_json::from_str(text).map_err(|e| Error::json(what, e))?;
    parse_value(value, what)
}

/// Parses an already-decoded JSON document.
pub fn parse_value(value: Value, what: &str) -> Result<SbomGraph> {
    if value.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        cyclonedx::parse(value, what)
    } else if value.get("spdxVersion").is_some() {
        spdx::parse(value, what)
    } else {
        Err(Error::UnknownFormat(what.to_string()))
    }
}

/// Reads and parses an SBOM file.
pub fn load(path: &Path) -> Result<SbomGraph> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let what = path.display().to_string();
    let g = parse_str(&text, &what)?;
    tracing::debug!(
        file = %what,
        format = %g.format,
        components = g.components.len(),
        warnings = g.warnings.len(),
        "loaded SBOM"
    );
    Ok(g)
}

/// Parses a purl found in a document, recording a warning when it is invalid.
pub(crate) fn parse_purl(raw: &str, owner: &str, warnings: &mut Vec<String>) -> Option<Purl> {
    match Purl::parse(raw) {
        Ok(p) => Some(p),
        Err(e) => {
            warnings.push(format!("component {owner:?}: ignoring invalid purl: {e}"));
            None
        }
    }
}

/// Applies a purl to a component, warning when the purl version disagrees
/// with the document's version field.
pub(crate) fn attach_purl(c: Component, purl: Option<Purl>, warnings: &mut Vec<String>) -> Component {
    let Some(p) = purl else { return c };
    if let (Some(pv), Some(dv)) = (p.version.as_deref(), c.version.as_deref()) {
        if pv != dv && pv.trim_start_matches('v') != dv.trim_start_matches('v') {
            warnings.push(format!(
                "component {:?}: purl version {pv:?} differs from version field {dv:?}; using the purl",
                c.source_ref
            ));
        }
    }
    c.with_purl(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unknown_and_bad_json() {
        assert!(matches!(parse_str("{}", "x"), Err(Error::UnknownFormat(_))));
        assert!(matches!(parse_str("not json", "x"), Err(Error::Json { .. })));
        let err = load(Path::new("/nonexistent/sbom.json")).unwrap_err();
        assert!(matches!(err, Error::Io { .. }));
        assert!(err.to_string().contains("cannot read"));
    }

    #[test]
    fn purl_helpers_warn() {
        let mut w = Vec::new();
        assert!(parse_purl("nope", "c", &mut w).is_none());
        let mut c = Component::new("r", "n");
        c.version = Some("2.0.0".into());
        let p = Purl::parse("pkg:npm/n@1.0.0").ok();
        let c = attach_purl(c, p, &mut w);
        assert_eq!(c.effective_version(), Some("1.0.0"));
        assert_eq!(w.len(), 2);
        let mut c2 = Component::new("g", "x");
        c2.version = Some("1.2.3".into());
        let _ = attach_purl(c2, Purl::parse("pkg:golang/x@v1.2.3").ok(), &mut w);
        assert_eq!(w.len(), 2, "v-prefix differences are not reported");
    }
}
