//! Writing a complete AFF4 volume.
//!
//! Member order is the point of this module. §5.4 requires
//! `container.description` to be the first file *stored* in the volume, and
//! because [`ZipWriter`] writes members in call order, satisfying it is simply
//! a matter of calling it first — which is exactly what pyaff4 fails to do,
//! creating the segment first but flushing it from an object cache later.
//!
//! Everything a caller adds to the graph is buffered until [`ContainerWriter::finish`],
//! because `information.turtle` must describe members that do not exist yet
//! when the first byte is written.

use std::path::Path;

use crate::arn::Arn;
use crate::error::{Error, Locus, Result};
use crate::write::guard::SourceRegistry;
use crate::write::sink::WriteSink;
use crate::write::turtle::TurtleWriter;
use crate::write::zip_writer::ZipWriter;

/// The producing tool, recorded in `version.txt` as `tool=`.
///
/// Name and version, the convention every writer in the corpus follows:
/// Evimetry writes `Evimetry 2.2.0`, and a bare name cannot distinguish a
/// container written by one release from another. That matters for evidence —
/// "which build produced this" is a provenance question, and answering it from
/// the container beats inferring it from when the file was created.
///
/// The version comes from `CARGO_PKG_VERSION`, so it tracks `Cargo.toml`
/// without a second place to update.
///
/// Deliberately not public: the binary's acquisition log builds its own header
/// from the same `CARGO_PKG_VERSION`, and a container's `tool=` is written here
/// or nowhere. A caller wanting to know what wrote a container should read the
/// container.
#[must_use]
fn producing_tool() -> String {
    format!("aff4tools {}", env!("CARGO_PKG_VERSION"))
}

/// Which AFF4 minor version a container declares.
///
/// The minor version is a **feature marker**, not a format revision, and every
/// implementation treats it that way. pyaff4 writes `minor=1` from
/// `createURN`, whose docstring says "create a new writable *logical* AFF4
/// container", and `minor=2` for encrypted ones; Evimetry writes `minor=0` on
/// every physical image it produces. The corpus splits exactly along that line:
/// 12 physical containers at 1.0, 3 logical containers at 1.1.
///
/// It matters beyond bookkeeping, because consumers dispatch on it. pyaff4's
/// `Container.identifyURN` selects `lexicon.standard11` when `version.is11()`
/// and `lexicon.standard` otherwise, and its `block_hasher.Validator` handles
/// only the latter — so a physical image declaring 1.1 cannot be validated by
/// the one external implementation that recomputes AFF4 hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionProfile {
    /// A physical image: `major=1 minor=0`.
    ///
    /// Verified accurate for this writer's output — a physical container uses
    /// 18 distinct `aff4:` terms, every one of them v1.0, and v1.1 adds
    /// logical-imaging vocabulary rather than changing existing spellings (see
    /// `crate::lexicon::STANDARD11`, which is literally `= STANDARD`).
    Physical,
    /// A logical (AFF4-L) image: `major=1 minor=1`.
    ///
    /// Genuinely v1.1: these containers carry `FileImage`, `FolderImage`,
    /// `originalFileName`, and the filesystem timestamps, none of which exist
    /// in v1.0.
    Logical,
}

impl VersionProfile {
    /// The minor version this profile declares.
    #[must_use]
    fn minor(self) -> u8 {
        match self {
            Self::Physical => 0,
            Self::Logical => 1,
        }
    }
}

/// The `version.txt` this writer emits.
fn version_text(profile: VersionProfile) -> String {
    format!(
        "major=1\nminor={}\ntool={}\n",
        profile.minor(),
        producing_tool()
    )
}

/// Builds one AFF4 volume.
///
/// The volume's own ARN is generated at construction and is what every object
/// written into it is `aff4:stored` in.
///
/// # Members stream; only the metadata waits
///
/// Each member is written to the sink as it arrives, so peak memory is one
/// member rather than the whole container and the file grows visibly during a
/// long acquisition. `information.turtle` is the sole exception — it describes
/// members that do not exist yet when the first byte is written, so the graph
/// accumulates and is serialized last.
///
/// Buffering until [`ContainerWriter::finish`] would mean a 16 GB acquisition
/// held ~15 GB of compressed bevies in RAM with the output file at zero bytes
/// until the very end. `zip_writer`'s module documentation names "no member may
/// be buffered whole in memory" as a requirement.
#[derive(Debug)]
pub struct ContainerWriter {
    zip: ZipWriter,
    sink: WriteSink,
    volume_arn: Arn,
    graph: TurtleWriter,
}

impl ContainerWriter {
    /// Create a new volume at `path` with a freshly generated volume ARN.
    ///
    /// Declares [`VersionProfile::Physical`]. Logical acquisitions must use
    /// [`ContainerWriter::create_logical`], because they carry v1.1 vocabulary
    /// this profile does not claim.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `path` is an acquisition source or already
    /// exists; [`Error::Io`] if creation fails.
    pub fn create(path: &Path, registry: &SourceRegistry) -> Result<Self> {
        Self::create_with_profile(path, registry, VersionProfile::Physical)
    }

    /// Create a new volume that will hold a logical (AFF4-L) image.
    ///
    /// Declares [`VersionProfile::Logical`], which is accurate only if the
    /// caller goes on to write v1.1 vocabulary into it.
    ///
    /// # Errors
    ///
    /// As [`ContainerWriter::create`].
    pub fn create_logical(path: &Path, registry: &SourceRegistry) -> Result<Self> {
        Self::create_with_profile(path, registry, VersionProfile::Logical)
    }

    /// Create a new volume declaring `profile`'s minor version.
    ///
    /// # Errors
    ///
    /// As [`ContainerWriter::create`].
    pub fn create_with_profile(
        path: &Path,
        registry: &SourceRegistry,
        profile: VersionProfile,
    ) -> Result<Self> {
        let mut sink = WriteSink::create(path, registry)?;
        let arn_text = format!("aff4://{}", new_uuid(path)?);
        let volume_arn = Arn::parse(&arn_text, &Locus::new(path))?;

        let mut graph = TurtleWriter::new();
        // Bind `:` to the volume so `aff4:stored :` renders as Evimetry does.
        graph.set_volume(volume_arn.as_str());

        // §5.4: `container.description` is the FIRST file stored in the volume.
        // Writing it here rather than at `finish` is what satisfies the rule
        // while members stream: nothing can precede it, because nothing else
        // has been written yet.
        let mut zip = ZipWriter::new();
        zip.add_stored_member(
            &mut sink,
            crate::zip::DESCRIPTION_SEGMENT,
            arn_text.as_bytes(),
        )?;
        zip.add_stored_member(
            &mut sink,
            crate::version::SEGMENT_NAME,
            version_text(profile).as_bytes(),
        )?;

        Ok(Self {
            zip,
            sink,
            volume_arn,
            graph,
        })
    }

    /// The volume's ARN.
    #[must_use]
    pub fn volume_arn(&self) -> &Arn {
        &self.volume_arn
    }

    /// Mutable access to the metadata graph.
    pub fn graph_mut(&mut self) -> &mut TurtleWriter {
        &mut self.graph
    }

    /// Write a stored (uncompressed) member immediately.
    ///
    /// Used for bevies and block-hash segments, whose contents are already
    /// compressed or are digests — deflating either would waste time for no
    /// gain.
    ///
    /// The bytes reach the sink before this returns, so `data` is freed as soon
    /// as the caller drops it.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the write fails.
    pub fn add_stored_segment(&mut self, name: &str, data: &[u8]) -> Result<()> {
        self.zip.add_stored_member(&mut self.sink, name, data)
    }

    /// Write a deflate-compressed member immediately.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the write fails.
    pub fn add_deflated_segment(&mut self, name: &str, data: &[u8]) -> Result<()> {
        self.zip.add_deflated_member(&mut self.sink, name, data)
    }

    /// Bytes written to the container so far.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.sink.position()
    }

    /// Write every member and close the volume.
    ///
    /// Order is fixed and load-bearing: `container.description` first per §5.4,
    /// then `version.txt`, then queued members, then `information.turtle`.
    /// The metadata goes last because it describes everything before it.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a write fails.
    pub fn finish(mut self) -> Result<()> {
        let arn = self.volume_arn.as_str().to_owned();
        let turtle = self.graph.serialize();

        // The metadata is the one member that cannot stream: it describes every
        // member before it, so it is written last. Deflated — highly repetitive
        // RDF, and pyaff4 stores it deflated too.
        self.zip.add_deflated_member(
            &mut self.sink,
            crate::container::METADATA_SEGMENT,
            turtle.as_bytes(),
        )?;

        // No NUL padding: one corpus writer pads its comment and this crate
        // records that as a deviation on read.
        self.zip.finish(&mut self.sink, &arn)?;

        self.sink.finish()
    }
}

/// A version 4 UUID, rendered lowercase with hyphens.
///
/// Hand-rolled rather than pulling in the `uuid` crate for one call site. The
/// randomness source is the OS, via `getrandom`, already in the tree.
///
/// # Errors
///
/// [`Error::Io`] if the OS entropy source is unavailable. That is returned
/// rather than fallen back on, because a predictable volume ARN could collide
/// across containers, and two containers sharing an ARN is unrecoverable
/// confusion about which evidence is which.
pub(crate) fn new_uuid(path: &Path) -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| {
        Error::io(
            path.to_path_buf(),
            std::io::Error::other(format!(
                "the OS entropy source is unavailable, so no volume ARN can be \
                 generated: {e}"
            )),
        )
    })?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generated_uuids_are_version_4_and_unique() {
        let p = Path::new("/synthetic/out.aff4");
        let a = new_uuid(p).unwrap();
        let b = new_uuid(p).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4", "version nibble");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"), "variant");
    }
}
