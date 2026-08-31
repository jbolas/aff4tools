//! Acquisition sources and the re-imaging path.
//!
//! Phase 2 accepts inputs that are, or trivially yield, a flat bytestream:
//! raw/`dd` images and split-raw sets. They share the property that makes the
//! accuracy claim provable — the source is a stable file that can be re-read
//! as many times as verification needs.
//!
//! # Split raw carries a gap
//!
//! Nothing inside a split set records how many segments there should be, so a
//! missing final segment yields a shorter image that is internally consistent
//! and verifies clean. This module therefore refuses a set with a gap in its
//! numbering and reports the segment count, rather than inferring completeness.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use crate::error::{Error, Locus, Result};

/// A source of bytes to acquire, plus what is known about it.
#[derive(Debug)]
pub struct ImageSource {
    /// Every file making up the source, in read order.
    segments: Vec<PathBuf>,
    /// Total bytes across all segments.
    total_size: u64,
}

impl ImageSource {
    /// Open a raw image, or a split-raw set given in order.
    ///
    /// Every path is registered as an acquisition source, so no write handle
    /// can later target one.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a segment cannot be opened or measured.
    pub fn open(
        paths: &[PathBuf],
        registry: &mut crate::write::guard::SourceRegistry,
    ) -> Result<Self> {
        if paths.is_empty() {
            return Err(Error::malformed(
                Locus::new("<no input>"),
                "no source path was given",
            ));
        }

        let mut segments = Vec::with_capacity(paths.len());
        let mut total_size = 0u64;

        for path in paths {
            let metadata = std::fs::metadata(path).map_err(|e| Error::io(path.clone(), e))?;
            if !metadata.is_file() {
                return Err(Error::malformed(
                    Locus::new(path),
                    "source is not a regular file",
                ));
            }
            registry
                .register(path)
                .map_err(|e| Error::io(path.clone(), e))?;
            total_size += metadata.len();
            segments.push(path.clone());
        }

        Ok(Self {
            segments,
            total_size,
        })
    }

    /// Discover a split-raw set from its first segment.
    ///
    /// Accepts `name.001`, `name.002`, … and stops at the first missing
    /// number. **A gap is an error**, not a stopping point: silently acquiring
    /// a prefix of the evidence is the failure this guards against.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the first segment's name has no numeric suffix,
    /// or if the discovered set has a gap.
    pub fn discover_split(first: &Path) -> Result<Vec<PathBuf>> {
        let name = first
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::malformed(Locus::new(first), "unreadable file name"))?;

        let (stem, suffix) = name.rsplit_once('.').ok_or_else(|| {
            Error::malformed(
                Locus::new(first),
                "a split set's first segment must end in a numeric suffix, e.g. .001",
            )
        })?;

        if !suffix.chars().all(|c| c.is_ascii_digit()) || suffix.is_empty() {
            return Err(Error::malformed(
                Locus::new(first),
                format!("suffix {suffix:?} is not numeric; not a split set"),
            ));
        }

        let width = suffix.len();
        let start: u32 = suffix.parse().map_err(|_| {
            Error::malformed(
                Locus::new(first),
                format!("suffix {suffix:?} is not a number"),
            )
        })?;
        let dir = first.parent().unwrap_or(Path::new("."));

        let mut found = Vec::new();
        let mut n = start;
        loop {
            let candidate = dir.join(format!("{stem}.{n:0width$}"));
            if !candidate.is_file() {
                break;
            }
            found.push(candidate);
            n += 1;
        }

        // A higher-numbered segment beyond the break means a gap: the set is
        // incomplete in the middle, which no acquisition should proceed past.
        let after_gap = dir.join(format!("{stem}.{:0width$}", n + 1));
        if after_gap.is_file() {
            return Err(Error::malformed(
                Locus::new(&after_gap),
                format!(
                    "split set has a gap: {stem}.{n:0width$} is missing but a \
                     later segment exists; the acquisition would silently omit data"
                ),
            ));
        }

        Ok(found)
    }

    /// Every segment, in read order.
    #[must_use]
    pub fn segments(&self) -> &[PathBuf] {
        &self.segments
    }

    /// Total bytes across the whole source.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// A reader over the whole source, segments concatenated in order.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the first segment cannot be opened.
    pub fn reader(&self) -> Result<ConcatReader> {
        ConcatReader::open(self.segments.clone())
    }
}

/// Reads a sequence of files as one continuous bytestream.
#[derive(Debug)]
pub struct ConcatReader {
    segments: Vec<PathBuf>,
    index: usize,
    current: Option<BufReader<File>>,
}

impl ConcatReader {
    /// Open the first segment; the rest follow as reads exhaust each.
    fn open(segments: Vec<PathBuf>) -> Result<Self> {
        let mut reader = Self {
            segments,
            index: 0,
            current: None,
        };
        reader.advance()?;
        Ok(reader)
    }

    /// Open the next segment, or leave `current` empty at the end.
    fn advance(&mut self) -> Result<()> {
        self.current = match self.segments.get(self.index) {
            Some(path) => {
                let file = File::open(path).map_err(|e| Error::io(path.clone(), e))?;
                self.index += 1;
                Some(BufReader::with_capacity(1 << 20, file))
            }
            None => None,
        };
        Ok(())
    }
}

impl Read for ConcatReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let Some(current) = self.current.as_mut() else {
                return Ok(0);
            };
            let n = current.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            // This segment is exhausted; continue into the next one.
            self.advance()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::write::guard::SourceRegistry;
    use std::io::Write as _;

    fn write_file(path: &Path, body: &[u8]) {
        #[allow(clippy::disallowed_methods)]
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body).unwrap();
    }

    #[test]
    fn a_split_set_reads_as_one_stream() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("img.001"), b"aaaa");
        write_file(&dir.path().join("img.002"), b"bbbb");
        write_file(&dir.path().join("img.003"), b"cc");

        let found = ImageSource::discover_split(&dir.path().join("img.001")).unwrap();
        assert_eq!(found.len(), 3);

        let mut registry = SourceRegistry::new();
        let source = ImageSource::open(&found, &mut registry).unwrap();
        assert_eq!(source.total_size(), 10);

        let mut all = Vec::new();
        source.reader().unwrap().read_to_end(&mut all).unwrap();
        assert_eq!(all, b"aaaabbbbcc");
    }

    /// A gap must be an error. Acquiring a prefix of the evidence and calling
    /// it complete is the failure this exists to prevent.
    #[test]
    fn a_gap_in_a_split_set_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("img.001"), b"aaaa");
        // .002 deliberately missing
        write_file(&dir.path().join("img.003"), b"cccc");

        let err = ImageSource::discover_split(&dir.path().join("img.001")).unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
    }

    /// Opening a source registers it, so it can never be written.
    #[test]
    fn opening_a_source_registers_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.dd");
        write_file(&path, b"evidence");

        let mut registry = SourceRegistry::new();
        ImageSource::open(std::slice::from_ref(&path), &mut registry).unwrap();

        assert!(registry.is_source(&path));
        assert!(
            crate::write::sink::WriteSink::create(&path, &registry).is_err(),
            "the source must not be writable once registered"
        );
    }

    #[test]
    fn a_directory_is_not_a_source() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = SourceRegistry::new();
        assert!(ImageSource::open(&[dir.path().to_path_buf()], &mut registry).is_err());
    }
}
