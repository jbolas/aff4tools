//! The single place this crate creates a file.
//!
//! Every byte aff4tools writes passes through [`WriteSink`]. Keeping creation
//! to one site is what makes the source-registry check enforceable: a second
//! `File::create` elsewhere in `src/write/` would bypass it silently, so
//! `tests/read_only_guard.rs` asserts this file is the only one.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Locus, Result};
use crate::write::guard::SourceRegistry;

/// A file being written, with its byte position tracked.
///
/// Position is tracked here rather than by seeking, because the ZIP writer
/// needs each member's local-header offset and a forensic writer should never
/// seek backwards over evidence it has already committed.
#[derive(Debug)]
pub struct WriteSink {
    path: PathBuf,
    file: BufWriter<std::fs::File>,
    position: u64,
}

impl WriteSink {
    /// Create `path` for writing, refusing an acquisition source.
    ///
    /// Refuses an existing file outright: overwriting evidence is the one
    /// mistake that cannot be undone, so it is an error rather than a prompt.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `path` is a registered source or already exists;
    /// [`Error::Io`] if creation fails.
    pub fn create(path: &Path, registry: &SourceRegistry) -> Result<Self> {
        registry.assert_not_source(path)?;

        if path.exists() {
            return Err(Error::malformed(
                Locus::new(path),
                "refusing to overwrite an existing file; choose a path that \
                 does not exist",
            ));
        }

        // The one permitted creation site in this crate. Guarded above: the
        // path is not an acquisition source and does not already exist.
        #[allow(clippy::disallowed_methods)]
        let file =
            std::fs::File::create(path).map_err(|source| Error::io(path.to_path_buf(), source))?;

        Ok(Self {
            path: path.to_path_buf(),
            file: BufWriter::with_capacity(1 << 20, file),
            position: 0,
        })
    }

    /// Append `bytes`, advancing the position.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the write fails.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.file
            .write_all(bytes)
            .map_err(|source| Error::io(self.path.clone(), source))?;
        self.position += bytes.len() as u64;
        Ok(())
    }

    /// Bytes written so far — a member's local-header offset.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }

    /// The path being written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flush and close.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the flush fails. Called explicitly rather than left to
    /// `Drop`, because a flush failure on the last bytes of evidence must be
    /// reported, and `Drop` cannot return an error.
    pub fn finish(mut self) -> Result<()> {
        self.file
            .flush()
            .map_err(|source| Error::io(self.path.clone(), source))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn writing_tracks_position_and_produces_the_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        let registry = SourceRegistry::new();

        let mut sink = WriteSink::create(&path, &registry).unwrap();
        assert_eq!(sink.position(), 0);
        sink.write_all(b"hello ").unwrap();
        sink.write_all(b"world").unwrap();
        assert_eq!(sink.position(), 11);
        sink.finish().unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
    }

    /// An acquisition source can never be opened for writing.
    #[test]
    fn creating_over_a_source_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("evidence.dd");
        #[allow(clippy::disallowed_methods)]
        std::fs::File::create(&source).unwrap();

        let mut registry = SourceRegistry::new();
        registry.register(&source).unwrap();

        assert!(WriteSink::create(&source, &registry).is_err());
    }

    /// Overwriting is refused even when the target is not evidence: the one
    /// mistake that cannot be undone.
    #[test]
    fn creating_over_an_existing_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exists.aff4");
        #[allow(clippy::disallowed_methods)]
        std::fs::File::create(&path).unwrap();

        let registry = SourceRegistry::new();
        let err = WriteSink::create(&path, &registry).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"), "{err}");
    }
}
