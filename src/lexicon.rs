//! Per-generation RDF vocabulary.
//!
//! AFF4 metadata uses different term spellings depending on which era of the
//! format wrote the container. A property lookup must therefore be
//! generation-aware: asking for "the chunk size predicate" has three different
//! answers.
//!
//! # The three vocabularies
//!
//! Verified by extracting every `aff4:` term from the reference corpus:
//!
//! | | Standard v1.0/v1.1 | Pre-standard | Rekall/winpmem |
//! |---|---|---|---|
//! | Namespace | `http://aff4.org/Schema#` | `http://afflib.org/2009/aff4#` | `http://aff4.org/Schema#` |
//! | Chunk size | `chunkSize` | `chunk_size` | `chunk_size` |
//! | Chunks/segment | `chunksInSegment` | `chunks_in_segment` | `chunks_per_segment` |
//! | Compression | `compressionMethod` | `CompressionMethod` | `compression` |
//! | Map class | `Map` | `map` | `map` |
//! | Stream class | `ImageStream` | `stream` | `ImageStream` |
//!
//! The pre-standard vocabulary diverges far more than a handful of properties:
//! comparing the corpus, 65 of its terms have no Standard counterpart, and it
//! uses `PascalCase` where the Standard uses camel case (`CreationTime`, `StartTime`,
//! `EndTime`, `Operation`, `TimeSource`). Only seven terms — `Image`, `MD5`,
//! `SHA1`, `hash`, `size`, `stored`, `contains` — are common to all generations.
//!
//! # Structure
//!
//! A [`Lexicon`] is a plain struct of `&'static str`, with one `const` per
//! generation. No traits, no dynamic dispatch: the divergence is in the data,
//! not the behaviour.

use crate::version::ContainerVersion;

/// The RDF namespace used by AFF4 Standard v1.0/v1.1 and by Rekall/winpmem.
pub const STANDARD_NAMESPACE: &str = "http://aff4.org/Schema#";

/// The RDF namespace used by pre-standard (Evimetry/Wirespeed) containers.
pub const LEGACY_NAMESPACE: &str = "http://afflib.org/2009/aff4#";

/// Which era of the AFF4 format wrote a container.
///
/// Serializes as a stable `snake_case` token (`"standard10"`, `"standard11"`,
/// `"rekall"`, `"legacy"`) — a short machine-checkable value, deliberately
/// distinct from [`Generation::name`]'s prose (`"AFF4 Standard v1.0"`,
/// `"pre-standard (Evimetry/Wirespeed)"`) which text output uses via
/// [`std::fmt::Display`]. A script matching on generation should not have to
/// parse a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Generation {
    /// AFF4 Standard v1.0. Has `version.txt` declaring `major=1 minor=0`.
    Standard10,
    /// AFF4 Standard v1.1, which adds logical (AFF4-L) imaging.
    Standard11,
    /// The Rekall/winpmem dialect: the standard namespace, but no `version.txt`
    /// and `snake_case` property names.
    ///
    /// Detected so it can be named in an error, then rejected — see
    /// [`Generation::is_supported`].
    Rekall,
    /// Pre-standard Evimetry/Wirespeed. No `version.txt`, and its own namespace.
    Legacy,
}

impl Generation {
    /// The generation implied by a parsed `version.txt`.
    ///
    /// Returns [`None`] for a version this build does not recognise; the caller
    /// should raise [`crate::Error::Unsupported`], since a future-version
    /// container is intact rather than damaged.
    #[must_use]
    pub fn from_version(version: &ContainerVersion) -> Option<Self> {
        if version.is_v1_0() {
            Some(Self::Standard10)
        } else if version.is_v1_1() {
            Some(Self::Standard11)
        } else {
            None
        }
    }

    /// The generation implied by the `aff4:` namespace of a container that has
    /// no `version.txt`.
    ///
    /// `version.txt` arrived with Standard v1.0, so its absence means one of
    /// the two pre-standard dialects. They are told apart by namespace: Rekall
    /// adopted the new one, Evimetry kept the original.
    #[must_use]
    pub fn from_namespace(namespace: &str) -> Option<Self> {
        match namespace {
            STANDARD_NAMESPACE => Some(Self::Rekall),
            LEGACY_NAMESPACE => Some(Self::Legacy),
            _ => None,
        }
    }

    /// The vocabulary this generation uses.
    #[must_use]
    pub fn lexicon(self) -> &'static Lexicon {
        match self {
            Self::Standard10 => &STANDARD,
            Self::Standard11 => &STANDARD11,
            Self::Rekall => &REKALL,
            Self::Legacy => &LEGACY,
        }
    }

    /// Whether this build can interpret the generation.
    ///
    /// Rekall is detected but not supported: no container of that dialect
    /// exists in the reference corpus, so any implementation would ship
    /// untested. pyaff4 likewise refuses to block-verify them
    /// (`block_hasher.py` raises for any lexicon but standard and legacy).
    /// Claiming untested support for evidence is worse than declining.
    #[must_use]
    pub fn is_supported(self) -> bool {
        !matches!(self, Self::Rekall)
    }

    /// A short name for messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Standard10 => "AFF4 Standard v1.0",
            Self::Standard11 => "AFF4 Standard v1.1",
            Self::Rekall => "Rekall/winpmem dialect",
            Self::Legacy => "pre-standard (Evimetry/Wirespeed)",
        }
    }
}

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The RDF terms one generation uses.
///
/// Fields hold *local names* — the part after the namespace. Use
/// [`Lexicon::iri`] for a full IRI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lexicon {
    /// The namespace these terms belong to.
    pub namespace: &'static str,

    // Classes.
    /// A stored image.
    pub image: &'static str,
    /// A contiguous image (spec §2.1).
    pub contiguous_image: &'static str,
    /// A disk image (spec §2.1).
    pub disk_image: &'static str,
    /// A chunked, optionally compressed data stream.
    pub image_stream: &'static str,
    /// A virtual address space over other streams.
    pub map: &'static str,
    /// The volume itself.
    pub volume: &'static str,
    /// A concatenation of per-chunk hashes.
    pub block_hashes: &'static str,

    // Properties.
    /// Length of a stream in bytes.
    pub size: &'static str,
    /// Bytes per chunk.
    pub chunk_size: &'static str,
    /// Chunks per bevy segment.
    pub chunks_in_segment: &'static str,
    /// The compression codec applied to chunks.
    pub compression_method: &'static str,
    /// A stored digest.
    pub hash: &'static str,
    /// The volume an object is stored in.
    pub stored: &'static str,
    /// The stream backing an image.
    pub data_stream: &'static str,
    /// A stream a map depends on.
    pub dependent_stream: &'static str,
    /// The target of a map entry or annotation.
    pub target: &'static str,
    /// The stream filling gaps in a discontiguous map.
    pub map_gap_default_stream: &'static str,
    /// The volume's own declaration of which ARNs it holds.
    pub contains: &'static str,
}

impl Lexicon {
    /// The full IRI for a local name in this vocabulary.
    #[must_use]
    pub fn iri(&self, local_name: &str) -> String {
        format!("{}{local_name}", self.namespace)
    }

    /// The local name of an IRI, if it belongs to this vocabulary.
    #[must_use]
    pub fn local_name<'a>(&self, iri: &'a str) -> Option<&'a str> {
        iri.strip_prefix(self.namespace)
    }

    /// Whether `iri` is one of this vocabulary's terms.
    #[must_use]
    pub fn owns(&self, iri: &str) -> bool {
        iri.starts_with(self.namespace)
    }
}

/// AFF4 Standard v1.0 (spec §2).
pub const STANDARD: Lexicon = Lexicon {
    namespace: STANDARD_NAMESPACE,
    image: "Image",
    contiguous_image: "ContiguousImage",
    disk_image: "DiskImage",
    image_stream: "ImageStream",
    map: "Map",
    volume: "ZipVolume",
    block_hashes: "BlockHashes",
    size: "size",
    chunk_size: "chunkSize",
    chunks_in_segment: "chunksInSegment",
    compression_method: "compressionMethod",
    hash: "hash",
    stored: "stored",
    data_stream: "dataStream",
    dependent_stream: "dependentStream",
    target: "target",
    map_gap_default_stream: "mapGapDefaultStream",
    contains: "contains",
};

/// AFF4 Standard v1.1.
///
/// Identical to v1.0 for the terms modelled here; v1.1 adds logical-imaging
/// vocabulary (`FileImage`, `FolderImage`, `originalFileName`, and the four
/// filesystem timestamps) rather than changing existing spellings.
pub const STANDARD11: Lexicon = STANDARD;

/// The Rekall/winpmem dialect.
///
/// Reconstructed from pyaff4's lexicon for this dialect (the class is named
/// `ScudetteLexicon` there, after its original author). **Untested** —
/// the reference corpus contains no such container, which is why
/// [`Generation::is_supported`] returns false for it. Present so a container
/// can be named accurately in an error rather than reported as unrecognised.
pub const REKALL: Lexicon = Lexicon {
    namespace: STANDARD_NAMESPACE,
    image: "Image",
    contiguous_image: "ContiguousImage",
    disk_image: "DiskImage",
    image_stream: "ImageStream",
    map: "map",
    volume: "ZipVolume",
    block_hashes: "BlockHashes",
    size: "size",
    chunk_size: "chunk_size",
    chunks_in_segment: "chunks_per_segment",
    compression_method: "compression",
    hash: "hash",
    stored: "stored",
    data_stream: "dataStream",
    dependent_stream: "dependentStream",
    target: "target",
    map_gap_default_stream: "mapGapDefaultStream",
    contains: "contains",
};

/// Pre-standard Evimetry/Wirespeed.
///
/// Term spellings taken from the corpus `.af4` containers, not from the spec —
/// this dialect predates it. Note the lowercase classes (`map`, `stream`,
/// `volume`) and the `PascalCase` spelling of `CompressionMethod`.
pub const LEGACY: Lexicon = Lexicon {
    namespace: LEGACY_NAMESPACE,
    image: "Image",
    contiguous_image: "ContiguousImage",
    disk_image: "DiskImage",
    image_stream: "stream",
    map: "map",
    volume: "zip_volume",
    block_hashes: "blockHashesHash",
    size: "size",
    chunk_size: "chunk_size",
    chunks_in_segment: "chunks_in_segment",
    compression_method: "CompressionMethod",
    hash: "hash",
    stored: "stored",
    data_stream: "dataStream",
    dependent_stream: "dependentStream",
    target: "target",
    map_gap_default_stream: "mapGapDefaultStream",
    contains: "contains",
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::error::Locus;

    fn version(major: u32, minor: u32) -> ContainerVersion {
        ContainerVersion::parse(
            format!("major={major}\nminor={minor}\ntool=test\n").as_bytes(),
            &Locus::new("/x.aff4"),
        )
        .unwrap()
    }

    #[test]
    fn maps_declared_versions_to_generations() {
        assert_eq!(
            Generation::from_version(&version(1, 0)),
            Some(Generation::Standard10)
        );
        assert_eq!(
            Generation::from_version(&version(1, 1)),
            Some(Generation::Standard11)
        );
    }

    /// A future version is intact, not damaged: detection declines rather than
    /// guessing, so the caller can raise Unsupported.
    #[test]
    fn an_unknown_version_has_no_generation() {
        assert_eq!(Generation::from_version(&version(1, 2)), None);
        assert_eq!(Generation::from_version(&version(2, 0)), None);
    }

    /// `version.txt` arrived with Standard v1.0, so its absence means a
    /// pre-standard dialect, told apart by namespace.
    #[test]
    fn distinguishes_the_two_pre_standard_dialects_by_namespace() {
        assert_eq!(
            Generation::from_namespace(STANDARD_NAMESPACE),
            Some(Generation::Rekall)
        );
        assert_eq!(
            Generation::from_namespace(LEGACY_NAMESPACE),
            Some(Generation::Legacy)
        );
        assert_eq!(Generation::from_namespace("http://example.com/#"), None);
    }

    /// Rekall is named accurately but refused: no fixture exists, so any
    /// implementation would ship untested.
    #[test]
    fn rekall_is_detected_but_not_supported() {
        assert!(!Generation::Rekall.is_supported());
        assert!(Generation::Rekall.name().contains("Rekall"));

        for g in [
            Generation::Standard10,
            Generation::Standard11,
            Generation::Legacy,
        ] {
            assert!(g.is_supported(), "{g} must be supported");
        }
    }

    /// The spellings that actually differ between generations. Each value was
    /// read out of a reference container (or, for Rekall, out of pyaff4's
    /// lexicon).
    #[test]
    fn property_spellings_differ_per_generation() {
        assert_eq!(STANDARD.chunk_size, "chunkSize");
        assert_eq!(LEGACY.chunk_size, "chunk_size");
        assert_eq!(REKALL.chunk_size, "chunk_size");

        assert_eq!(STANDARD.chunks_in_segment, "chunksInSegment");
        assert_eq!(LEGACY.chunks_in_segment, "chunks_in_segment");
        assert_eq!(REKALL.chunks_in_segment, "chunks_per_segment");

        assert_eq!(STANDARD.compression_method, "compressionMethod");
        assert_eq!(LEGACY.compression_method, "CompressionMethod");
        assert_eq!(REKALL.compression_method, "compression");
    }

    /// Pre-standard lowercases what the standard capitalises.
    #[test]
    fn legacy_class_names_are_lowercase() {
        assert_eq!(STANDARD.map, "Map");
        assert_eq!(LEGACY.map, "map");
        assert_eq!(STANDARD.image_stream, "ImageStream");
        assert_eq!(LEGACY.image_stream, "stream");
        assert_eq!(LEGACY.volume, "zip_volume");
    }

    /// Only seven terms are spelled identically across all generations; these
    /// are the ones a generation-agnostic reader could rely on.
    #[test]
    fn the_universal_terms_agree() {
        for lex in [&STANDARD, &LEGACY, &REKALL] {
            assert_eq!(lex.size, "size");
            assert_eq!(lex.hash, "hash");
            assert_eq!(lex.stored, "stored");
            assert_eq!(lex.image, "Image");
            assert_eq!(lex.contains, "contains");
        }
    }

    #[test]
    fn builds_and_splits_iris() {
        assert_eq!(
            STANDARD.iri("chunkSize"),
            "http://aff4.org/Schema#chunkSize"
        );
        assert_eq!(
            LEGACY.iri("chunk_size"),
            "http://afflib.org/2009/aff4#chunk_size"
        );

        assert_eq!(
            STANDARD.local_name("http://aff4.org/Schema#size"),
            Some("size")
        );
        assert_eq!(
            STANDARD.local_name("http://afflib.org/2009/aff4#size"),
            None,
            "a legacy IRI does not belong to the standard vocabulary"
        );
    }

    /// The two pre-standard dialects share the Standard's namespace or their
    /// own; `owns` must not confuse them.
    #[test]
    fn ownership_follows_the_namespace() {
        assert!(STANDARD.owns("http://aff4.org/Schema#hash"));
        assert!(!STANDARD.owns("http://afflib.org/2009/aff4#hash"));
        assert!(LEGACY.owns("http://afflib.org/2009/aff4#hash"));
        assert!(!LEGACY.owns("http://aff4.org/Schema#hash"));
        // Rekall shares the standard namespace; only spellings differ.
        assert!(REKALL.owns("http://aff4.org/Schema#chunk_size"));
    }

    #[test]
    fn every_generation_resolves_to_a_lexicon() {
        assert_eq!(Generation::Standard10.lexicon(), &STANDARD);
        assert_eq!(Generation::Standard11.lexicon(), &STANDARD11);
        assert_eq!(Generation::Rekall.lexicon(), &REKALL);
        assert_eq!(Generation::Legacy.lexicon(), &LEGACY);
    }

    #[test]
    fn generation_names_are_readable() {
        assert_eq!(Generation::Standard10.to_string(), "AFF4 Standard v1.0");
        assert_eq!(Generation::Standard11.to_string(), "AFF4 Standard v1.1");
        assert!(Generation::Legacy.to_string().contains("pre-standard"));
    }
}
