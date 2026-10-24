//! Crate-wide error type.

use std::path::PathBuf;

/// Errors returned by sbomlens' loading and processing APIs.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading a file failed.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The file that failed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// A document is not valid JSON or does not match the expected schema.
    #[error("{what}: invalid JSON: {source}")]
    Json {
        /// What was being parsed (file name or document kind).
        what: String,
        /// The underlying parser error.
        source: serde_json::Error,
    },
    /// The document is neither CycloneDX nor SPDX JSON.
    #[error("{0}: not a CycloneDX or SPDX JSON document")]
    UnknownFormat(String),
    /// The document's format version is not supported.
    #[error("{what}: unsupported {format} version {version:?} (supported: {supported})")]
    UnsupportedVersion {
        /// What was being parsed.
        what: String,
        /// Format name.
        format: &'static str,
        /// The version found.
        version: String,
        /// Human-readable list of supported versions.
        supported: &'static str,
    },
    /// A semantic problem in an input document.
    #[error("{what}: {reason}")]
    Invalid {
        /// What was being parsed.
        what: String,
        /// The problem.
        reason: String,
    },
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn json(what: impl Into<String>, source: serde_json::Error) -> Error {
        Error::Json {
            what: what.into(),
            source,
        }
    }

    pub(crate) fn invalid(what: impl Into<String>, reason: impl Into<String>) -> Error {
        Error::Invalid {
            what: what.into(),
            reason: reason.into(),
        }
    }
}

/// Convenience result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;
