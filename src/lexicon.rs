//! Per-generation RDF vocabulary.
//!
//! AFF4 metadata uses different term spellings depending on which era of the
//! format wrote the container. A property lookup must therefore be
//! generation-aware: asking for "the chunk size predicate" has two different
//! answers.
//!
//! # The two vocabularies
//!
//! Verified by extracting every `aff4:` term from the reference corpus:
//!
//! | | Standard (v1.0a, and pyaff4-era AFF4-L) | Pre-standard |
//! |---|---|---|
//! | Namespace | `http://aff4.org/Schema#` | `http://afflib.org/2009/aff4#` |
//! | Chunk size | `chunkSize` | `chunk_size` |
//! | Chunks/segment | `chunksInSegment` | `chunks_in_segment` |
//! | Compression | `compressionMethod` | `CompressionMethod` |
//! | Map class | `Map` | `map` |
//! | Stream class | `ImageStream` | `stream` |
//!
//! The pre-standard vocabulary diverges far more than a handful of properties:
//! comparing the corpus, 65 of its terms have no Standard counterpart, and it
//! uses `PascalCase` where the Standard uses camel case (`CreationTime`, `StartTime`,
//! `EndTime`, `Operation`, `TimeSource`). Only seven terms — `Image`, `MD5`,
//! `SHA1`, `hash`, `size`, `stored`, `contains` — are common to both.
//!
//! # Structure
//!
//! A [`Lexicon`] is a plain struct of `&'static str`, with one `const` per
//! generation. No traits, no dynamic dispatch: the divergence is in the data,
//! not the behaviour.

use crate::version::ContainerVersion;

/// The RDF namespace used by AFF4 Standard v1.0a and by pyaff4-era AFF4-L.
pub const STANDARD_NAMESPACE: &str = "http://aff4.org/Schema#";

/// The RDF namespace used by pre-standard (Evimetry/Wirespeed) containers.
pub const LEGACY_NAMESPACE: &str = "http://afflib.org/2009/aff4#";

/// Which era of the AFF4 format wrote a container.
///
/// Serializes as a stable `snake_case` token (`"standard10"`,
/// `"pyaff4_logical"`, `"aff4l10"`, `"legacy"`) — a short machine-checkable
/// value, deliberately distinct from [`Generation::name`]'s prose which text
/// output uses via [`std::fmt::Display`]. A script matching on generation
/// should not have to parse a sentence.
///
/// # Which document governs each
///
/// See `docs/working/AFF4-L-Standard-v1.0-ALPHA-design-phases.md`. The mapping
/// is [`Generation::governing_spec`], and it is what `conformance` measures
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Generation {
    /// AFF4 Standard v1.0a. Has `version.txt` declaring `major=1 minor=0`.
    Standard10,
    /// pyaff4-era AFF4-L. `version.txt` declares `major=1 minor=1`.
    ///
    /// **No specification defines version 1.1.** v1.0a states only "For AFF4
    /// Standard v1.0, Major is 1, Minor is 0", and the AFF4-L Standard
    /// v1.0-ALPHA assigns AFF4-L major 2, minor 1. Version 1.1 is what pyaff4
    /// wrote when it added logical imaging, and every AFF4-L container in the
    /// reference corpus carries it. It is a de facto marker for pyaff4-era
    /// AFF4-L, not a standard version — naming it "AFF4 Standard v1.1" would
    /// assert a document that has never existed.
    ///
    /// Governed by v1.0a for the base container, plus the AFF4-L 2019 paper
    /// for logical constructs.
    ///
    /// The wire token is spelled `pyaff4_logical` rather than serde's derived
    /// `py_aff4_logical`: `pyaff4` is one word, the name of the tool.
    #[serde(rename = "pyaff4_logical")]
    PyAff4Logical,
    /// AFF4-L Standard v1.0-ALPHA. `version.txt` declares `major=2 minor=1`.
    ///
    /// Recognised and named so a report can say what the container is, then
    /// declined: the v2.1 rules are not implemented, and the standard is a
    /// pre-release whose Canonical Reference Images — which it says take
    /// precedence over its own text — are not yet published. See
    /// [`Generation::is_supported`].
    Aff4L10,
    /// Pre-standard Evimetry/Wirespeed. No `version.txt`, and its own namespace.
    ///
    /// Detected so it can be named in an error, then rejected — see
    /// [`Generation::is_supported`].
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
            Some(Self::PyAff4Logical)
        } else if version.is_v2_1() {
            Some(Self::Aff4L10)
        } else {
            None
        }
    }

    /// The generation implied by the `aff4:` namespace of a container that has
    /// no `version.txt`.
    ///
    /// `version.txt` arrived with Standard v1.0, so its absence means the
    /// container predates the standard. Both pre-standard namespaces resolve
    /// to [`Self::Legacy`]: the dialects are told apart in the corpus by
    /// namespace, but neither is supported, so drawing the distinction would
    /// only produce two names for one outcome.
    #[must_use]
    pub fn from_namespace(namespace: &str) -> Option<Self> {
        match namespace {
            STANDARD_NAMESPACE | LEGACY_NAMESPACE => Some(Self::Legacy),
            _ => None,
        }
    }

    /// The vocabulary this generation uses.
    #[must_use]
    pub fn lexicon(self) -> &'static Lexicon {
        match self {
            Self::Standard10 | Self::PyAff4Logical => &STANDARD,
            // The v2.1 lexicon is not modelled: AFF4-L v1.0-ALPHA §4.1 adds a
            // second namespace
            // and nineteen properties this build does not implement. The base
            // vocabulary is returned so the type is total, never so a v2.1
            // container can be read — `is_supported` declines first. Kept as
            // its own arm because merging it would assert that v2.1 *uses*
            // the base vocabulary, which is exactly what is not yet known.
            #[allow(clippy::match_same_arms)]
            Self::Aff4L10 => &STANDARD,
            Self::Legacy => &LEGACY,
        }
    }

    /// Whether this build can interpret the generation.
    ///
    /// Two are detected but not supported, for different reasons.
    ///
    /// [`Self::Legacy`] predates the standard. Its containers are read by no
    /// specification this tool cites, so any behaviour would be reverse
    /// engineering presented as conformance.
    ///
    /// [`Self::Aff4L10`] is the AFF4-L Standard v1.0-ALPHA. Its rules are not
    /// implemented, and the standard is a pre-release stating that its
    /// Canonical Reference Images take precedence over its own text — those
    /// images are unpublished, so no rule could be validated against evidence.
    ///
    /// In both cases the container is named accurately and declined. Claiming
    /// untested support for evidence is worse than declining.
    #[must_use]
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Standard10 | Self::PyAff4Logical)
    }

    /// Whether `conformance` will read a container of this generation.
    ///
    /// Wider than [`Self::is_supported`] by exactly one generation. A v2.1
    /// container is read so `conformance` can report which of its rules went
    /// unevaluated; `info` and `verify` still decline it, because those
    /// commands describe and check evidence, and a partial reading of evidence
    /// misleads in a way a coverage report does not.
    ///
    /// Pre-standard containers stay refused here too: no document aff4tools
    /// cites describes them, so there is no rule set to report coverage
    /// against.
    #[must_use]
    pub fn is_conformance_readable(self) -> bool {
        self.is_supported() || matches!(self, Self::Aff4L10)
    }

    /// A short name for messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Standard10 => "AFF4 Standard v1.0a",
            Self::PyAff4Logical => "AFF4-L (pyaff4, version 1.1, unspecified)",
            Self::Aff4L10 => "AFF4-L Standard v1.0-ALPHA",
            Self::Legacy => "pre-standard (Evimetry/Wirespeed)",
        }
    }

    /// The document or documents that govern a container of this generation.
    ///
    /// Returns the base document and, where a second document governs a layer
    /// above it, that document too. This is the mapping table from the design,
    /// expressed as a function so it cannot drift from the prose. See
    /// `docs/working/AFF4-L-Standard-v1.0-ALPHA-design-phases.md`.
    #[must_use]
    pub fn governing_spec(self) -> (crate::rules::Document, Option<crate::rules::Document>) {
        use crate::rules::Document;
        match self {
            Self::Standard10 => (Document::Aff4Standard10a, None),
            // v1.0a governs the container; the paper governs the logical layer
            // above it. Two documents, each authoritative for its own layer.
            Self::PyAff4Logical => (Document::Aff4Standard10a, Some(Document::Aff4LPaper2019)),
            // Base-plus-delta: AFF4-L v1.0-ALPHA §3 says its versioning
            // extends the v1.0 scheme, and AFF4-L v1.0-ALPHA §4.1 says its
            // classes supplement the base lexicon, so v1.0a still governs the
            // ZIP structure and map rules.
            Self::Aff4L10 => (
                Document::Aff4Standard10a,
                Some(Document::Aff4LStandard10Alpha),
            ),
            // Nothing this tool cites describes a pre-standard container. The
            // base document is named only so the type is total; a Legacy
            // container is declined before any citation is printed. Kept
            // separate from Standard10, whose identical value means the
            // opposite: that v1.0a genuinely governs it.
            #[allow(clippy::match_same_arms)]
            Self::Legacy => (Document::Aff4Standard10a, None),
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
    /// A contiguous image (v1.0a §2.1).
    pub contiguous_image: &'static str,
    /// A disk image (v1.0a §2.1).
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

/// AFF4 Standard v1.0a (spec §2).
///
/// Also the base vocabulary for pyaff4-era AFF4-L, which adds logical terms
/// (`FileImage`, `FolderImage`, `originalFileName`, the filesystem timestamps)
/// rather than changing any spelling modelled here.
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
            Some(Generation::PyAff4Logical)
        );
        assert_eq!(
            Generation::from_version(&version(2, 1)),
            Some(Generation::Aff4L10)
        );
    }

    /// A future version is intact, not damaged: detection declines rather than
    /// guessing, so the caller can raise Unsupported.
    #[test]
    fn an_unknown_version_has_no_generation() {
        assert_eq!(Generation::from_version(&version(1, 2)), None);
        assert_eq!(Generation::from_version(&version(2, 0)), None);
        assert_eq!(Generation::from_version(&version(3, 0)), None);
    }

    /// `version.txt` arrived with Standard v1.0, so its absence means the
    /// container is pre-standard. Either pre-standard namespace resolves to
    /// Legacy; neither is supported, so one name suffices.
    #[test]
    fn either_pre_standard_namespace_is_legacy() {
        assert_eq!(
            Generation::from_namespace(STANDARD_NAMESPACE),
            Some(Generation::Legacy)
        );
        assert_eq!(
            Generation::from_namespace(LEGACY_NAMESPACE),
            Some(Generation::Legacy)
        );
        assert_eq!(Generation::from_namespace("http://example.com/#"), None);
    }

    /// Legacy and the AFF4-L v1.0-ALPHA standard are named accurately and
    /// refused. Legacy is described by no specification this tool cites;
    /// v2.1's rules are unimplemented and its reference images unpublished.
    #[test]
    fn unsupported_generations_are_named_but_refused() {
        assert!(!Generation::Legacy.is_supported());
        assert!(Generation::Legacy.name().contains("pre-standard"));

        assert!(!Generation::Aff4L10.is_supported());
        assert!(Generation::Aff4L10.name().contains("v1.0-ALPHA"));

        for g in [Generation::Standard10, Generation::PyAff4Logical] {
            assert!(g.is_supported(), "{g} must be supported");
        }
    }

    /// `conformance` reads a v2.1 container to report what it could not check.
    /// `info` and `verify` still decline it, because a partial read of evidence
    /// could mislead in a way a coverage report cannot.
    #[test]
    fn v2_1_is_readable_by_conformance_only() {
        assert!(!Generation::Aff4L10.is_supported());
        assert!(Generation::Aff4L10.is_conformance_readable());

        // Pre-standard stays refused by everything: no document describes it.
        assert!(!Generation::Legacy.is_supported());
        assert!(!Generation::Legacy.is_conformance_readable());

        // Everything already supported is readable by conformance too.
        for generation in [Generation::Standard10, Generation::PyAff4Logical] {
            assert!(generation.is_conformance_readable());
        }
    }

    /// The mapping table from the design, as a function.
    #[test]
    fn governing_specs_follow_the_mapping_table() {
        use crate::rules::Document;

        assert_eq!(
            Generation::Standard10.governing_spec(),
            (Document::Aff4Standard10a, None)
        );
        assert_eq!(
            Generation::PyAff4Logical.governing_spec(),
            (Document::Aff4Standard10a, Some(Document::Aff4LPaper2019))
        );
        assert_eq!(
            Generation::Aff4L10.governing_spec(),
            (
                Document::Aff4Standard10a,
                Some(Document::Aff4LStandard10Alpha)
            )
        );
        assert_eq!(
            Generation::Legacy.governing_spec(),
            (Document::Aff4Standard10a, None)
        );
    }

    /// The spellings that actually differ between generations. Each value was
    /// read out of a reference container.
    #[test]
    fn property_spellings_differ_per_generation() {
        assert_eq!(STANDARD.chunk_size, "chunkSize");
        assert_eq!(LEGACY.chunk_size, "chunk_size");

        assert_eq!(STANDARD.chunks_in_segment, "chunksInSegment");
        assert_eq!(LEGACY.chunks_in_segment, "chunks_in_segment");

        assert_eq!(STANDARD.compression_method, "compressionMethod");
        assert_eq!(LEGACY.compression_method, "CompressionMethod");
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

    /// Only seven terms are spelled identically in both vocabularies; these
    /// are the ones a generation-agnostic reader could rely on.
    #[test]
    fn the_universal_terms_agree() {
        for lex in [&STANDARD, &LEGACY] {
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

    /// The vocabularies use different namespaces; `owns` must not confuse them.
    #[test]
    fn ownership_follows_the_namespace() {
        assert!(STANDARD.owns("http://aff4.org/Schema#hash"));
        assert!(!STANDARD.owns("http://afflib.org/2009/aff4#hash"));
        assert!(LEGACY.owns("http://afflib.org/2009/aff4#hash"));
        assert!(!LEGACY.owns("http://aff4.org/Schema#hash"));
    }

    #[test]
    fn every_generation_resolves_to_a_lexicon() {
        assert_eq!(Generation::Standard10.lexicon(), &STANDARD);
        assert_eq!(Generation::PyAff4Logical.lexicon(), &STANDARD);
        assert_eq!(Generation::Aff4L10.lexicon(), &STANDARD);
        assert_eq!(Generation::Legacy.lexicon(), &LEGACY);
    }

    #[test]
    fn generation_names_are_readable() {
        assert_eq!(Generation::Standard10.to_string(), "AFF4 Standard v1.0a");
        assert!(Generation::Legacy.to_string().contains("pre-standard"));
    }

    /// No specification defines version 1.1, so no name may imply one does.
    #[test]
    fn no_generation_claims_a_standard_v1_1() {
        for g in [
            Generation::Standard10,
            Generation::PyAff4Logical,
            Generation::Aff4L10,
            Generation::Legacy,
        ] {
            let name = g.name();
            assert!(
                !name.contains("Standard v1.1"),
                "{name} names a standard that does not exist"
            );
        }
        assert!(Generation::PyAff4Logical.name().contains("pyaff4"));
    }
}
