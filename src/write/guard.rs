//! The guard that keeps acquisition sources unwritable.
//!
//! Denying the write APIs outside `src/write/` proves the *reader* cannot
//! modify anything. It does not stop the *writer* from opening the acquisition
//! source for writing, which is the mistake that would actually destroy
//! evidence. This module closes that gap: every path opened as a source is
//! registered, and every write handle is checked against the registry at
//! [`crate::write::sink::WriteSink::create`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::{Error, Locus, Result};

/// Paths opened as acquisition sources, which must never be written.
///
/// Paths are canonicalized on entry so that two spellings of one file — a
/// relative path, a `.` component, a symlink — cannot let a write slip past the
/// check.
#[derive(Debug, Default)]
pub struct SourceRegistry {
    sources: HashSet<PathBuf>,
}

impl SourceRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `path` as an acquisition source.
    ///
    /// # Errors
    ///
    /// Propagates a canonicalization failure, which means the path does not
    /// exist or is not readable — either way it cannot be acquired.
    pub fn register(&mut self, path: &Path) -> std::io::Result<()> {
        self.sources.insert(path.canonicalize()?);
        Ok(())
    }

    /// How many sources are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether no source has been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Whether `path` names a registered source.
    ///
    /// An uncanonicalizable path is not a source: it cannot name an existing
    /// file, so nothing registered can refer to it.
    #[must_use]
    pub fn is_source(&self, path: &Path) -> bool {
        path.canonicalize()
            .is_ok_and(|canonical| self.sources.contains(&canonical))
    }

    /// Refuse if `path` is a registered acquisition source.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] naming the path. This is deliberately a hard error
    /// rather than a warning: writing to the evidence being acquired is not a
    /// condition any run should continue past.
    pub fn assert_not_source(&self, path: &Path) -> Result<()> {
        if self.is_source(path) {
            return Err(Error::malformed(
                Locus::new(path),
                "refusing to open a write handle on an acquisition source; \
                 writing here would modify the evidence being acquired",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Create a file for a test fixture. Tests may write; the library may not.
    fn touch(path: &Path, body: &[u8]) {
        #[allow(clippy::disallowed_methods)]
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body).unwrap();
    }

    /// The guard must refuse a write to a registered source, and must compare
    /// canonical paths so an equivalent spelling cannot slip past it.
    #[test]
    fn a_registered_source_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("evidence.dd");
        touch(&source, b"evidence");

        let mut registry = SourceRegistry::new();
        registry.register(&source).unwrap();

        assert!(registry.is_source(&source));
        assert!(registry.assert_not_source(&source).is_err());

        // An equivalent spelling of the same file must also be refused.
        let equivalent = dir.path().join(".").join("evidence.dd");
        assert!(
            registry.assert_not_source(&equivalent).is_err(),
            "a different spelling of the same path must still be refused"
        );
    }

    /// A symlink to a source resolves to the same file and is refused too.
    #[test]
    fn a_symlink_to_a_source_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("evidence.dd");
        touch(&source, b"evidence");

        let link = dir.path().join("link.dd");
        std::os::unix::fs::symlink(&source, &link).unwrap();

        let mut registry = SourceRegistry::new();
        registry.register(&source).unwrap();

        assert!(
            registry.assert_not_source(&link).is_err(),
            "a symlink to the source is the source"
        );
    }

    /// An unrelated path is writable.
    #[test]
    fn an_unregistered_path_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("evidence.dd");
        touch(&source, b"");

        let mut registry = SourceRegistry::new();
        registry.register(&source).unwrap();

        let output = dir.path().join("case.aff4");
        assert!(!registry.is_source(&output));
        assert!(registry.assert_not_source(&output).is_ok());
    }

    /// Registering a path that does not exist is an error, not a silent no-op:
    /// a source we cannot canonicalize is a source we cannot protect.
    #[test]
    fn registering_a_missing_path_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = SourceRegistry::new();
        assert!(registry.register(&dir.path().join("nope.dd")).is_err());
        assert!(registry.is_empty());
    }
}
