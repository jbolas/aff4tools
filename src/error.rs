//! Error and deviation types.
//!
//! # Taxonomy
//!
//! The five [`Error`] variants exist to keep three situations distinct, because
//! confusing them would mislead an examiner about the evidence:
//!
//! - [`Error::Io`] / [`Error::Zip`] — the environment failed us. Nothing is
//!   known about the container's contents.
//! - [`Error::NotAff4`] — a readable ZIP that is not an AFF4 volume at all.
//! - [`Error::Malformed`] — it *is* an AFF4 volume and it violates the format.
//!   This is an integrity finding about the evidence.
//! - [`Error::Unsupported`] — well-formed, but uses a capability this build
//!   does not implement. **Never** an integrity finding.
//!
//! The last distinction is the important one. Reporting "malformed container"
//! for an encrypted or Rekall-dialect container would invite a false conclusion
//! about the evidence, so [`Error::Unsupported`] must never be folded into
//! [`Error::Malformed`].
//!
//! # Where, not just what
//!
//! Every format-level failure carries a [`Locus`] naming the container, the
//! segment, the byte offset, and the RDF subject/predicate under inspection
//! where each is known. "Malformed container" is useless in a forensic report;
//! "malformed at `information.turtle` offset 2841, subject `aff4://c215…`,
//! predicate `aff4:size`" is actionable.
//!
//! # Nothing prints
//!
//! These types never write to stdout or stderr and never terminate the process.
//! `Display` produces a bare fragment with no trailing newline and no `error:`
//! prefix, so the binary alone decides presentation. See CLAUDE.md.

use std::path::{Path, PathBuf};

/// Result alias for all fallible operations in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Where in a container something was found.
///
/// Fields are progressively optional: a failure while opening `version.txt`
/// knows the segment but no RDF subject; a failure coercing a literal knows
/// all five. Construct with [`Locus::new`] and refine with the builder methods.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Locus {
    /// The container file on disk.
    pub path: PathBuf,
    /// Segment (ZIP member) name, e.g. `information.turtle`.
    pub segment: Option<String>,
    /// Byte offset within the segment, where the source reports one.
    pub byte_offset: Option<u64>,
    /// RDF subject under inspection, as a lexical ARN.
    pub subject: Option<String>,
    /// RDF predicate under inspection, as a lexical IRI or prefixed name.
    pub predicate: Option<String>,
}

impl Locus {
    /// A locus naming only the container file.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            segment: None,
            byte_offset: None,
            subject: None,
            predicate: None,
        }
    }

    /// Name the ZIP member this concerns.
    #[must_use]
    pub fn segment(mut self, segment: impl Into<String>) -> Self {
        self.segment = Some(segment.into());
        self
    }

    /// Record the byte offset within the segment.
    #[must_use]
    pub fn byte_offset(mut self, offset: u64) -> Self {
        self.byte_offset = Some(offset);
        self
    }

    /// Record the RDF subject under inspection.
    #[must_use]
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Record the RDF predicate under inspection.
    #[must_use]
    pub fn predicate(mut self, predicate: impl Into<String>) -> Self {
        self.predicate = Some(predicate.into());
        self
    }
}

impl std::fmt::Display for Locus {
    /// Renders as a single line: `path[!segment][@offset][ subject][ predicate]`.
    ///
    /// The binary is free to render the fields multi-line instead; this exists
    /// so an error embedded in a one-line message stays readable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.display())?;
        if let Some(segment) = &self.segment {
            write!(f, "!{segment}")?;
        }
        if let Some(offset) = self.byte_offset {
            write!(f, "@{offset}")?;
        }
        if let Some(subject) = &self.subject {
            write!(f, " subject {subject}")?;
        }
        if let Some(predicate) = &self.predicate {
            write!(f, " predicate {predicate}")?;
        }
        Ok(())
    }
}

/// Why a readable ZIP is not an AFF4 volume.
///
/// Every variant's payload is either empty or a set of named fields, so
/// internal tagging (`{"kind": "unknown_namespace", "found": "..."}`) needs
/// no `content` wrapper — unlike [`crate::HashAlgorithm`] or
/// [`crate::ObjectRole`], which carry a bare string payload on their `Other`
/// variant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotAff4Reason {
    /// The archive contains no members.
    EmptyArchive,
    /// No `information.turtle` segment is present.
    NoMetadata,
    /// The RDF namespace matches no known AFF4 generation.
    UnknownNamespace {
        /// The namespace IRI actually found.
        found: String,
    },
    /// No volume ARN in the ZIP comment, `container.description`, or metadata.
    NoVolumeArn,
}

impl std::fmt::Display for NotAff4Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyArchive => f.write_str("the archive contains no members"),
            Self::NoMetadata => f.write_str("no information.turtle segment"),
            Self::UnknownNamespace { found } => {
                write!(f, "unrecognised RDF namespace {found}")
            }
            Self::NoVolumeArn => {
                f.write_str("no volume ARN in the ZIP comment, container.description, or metadata")
            }
        }
    }
}

/// A capability this build does not implement.
///
/// Distinct from [`Error::Malformed`] on purpose: a container needing one of
/// these is intact, not damaged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Feature {
    /// A container generation this build cannot interpret, e.g. the
    /// Rekall/winpmem dialect or a future standard version.
    Generation {
        /// How the generation identified itself.
        named: String,
    },
    /// An encrypted container or stream.
    Encryption,
    /// A compression codec that is not implemented.
    Codec {
        /// The codec resource IRI from the metadata.
        iri: String,
    },
    /// A storage layer other than ZIP, e.g. the spec's Directory volumes.
    StorageLayer {
        /// The storage layer encountered.
        named: String,
    },
}

impl std::fmt::Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generation { named } => write!(f, "container generation {named}"),
            Self::Encryption => f.write_str("encrypted containers"),
            Self::Codec { iri } => write!(f, "compression codec {iri}"),
            Self::StorageLayer { named } => write!(f, "{named} storage layer"),
        }
    }
}

/// A failure.
///
/// See the [module documentation](self) for why the variants are split this way.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The host filesystem failed. Says nothing about the evidence.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The file is not a readable ZIP archive.
    #[error("{path} is not a readable ZIP archive: {source}")]
    Zip {
        /// The path being read.
        path: PathBuf,
        /// The underlying ZIP failure.
        #[source]
        source: zip::result::ZipError,
    },

    /// A readable ZIP that is not an AFF4 volume.
    #[error("{path} is not an AFF4 volume: {reason}")]
    NotAff4 {
        /// The path being read.
        path: PathBuf,
        /// Why it was rejected.
        reason: NotAff4Reason,
    },

    /// An AFF4 volume that violates the format. An integrity finding.
    #[error("malformed AFF4 container at {locus}: {detail}")]
    Malformed {
        /// Where the violation was found.
        locus: Box<Locus>,
        /// What is wrong, in terms an examiner can act on.
        detail: String,
    },

    /// A well-formed container using a capability this build lacks.
    ///
    /// Not an integrity finding. Never conflate with [`Error::Malformed`].
    #[error("{feature} is not supported ({context})")]
    Unsupported {
        /// The missing capability.
        feature: Feature,
        /// Where it was encountered, and any detail worth reporting.
        context: String,
    },
}

impl Error {
    /// Build an [`Error::Io`] for `path`.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Build an [`Error::Zip`] for `path`.
    pub fn zip(path: impl Into<PathBuf>, source: zip::result::ZipError) -> Self {
        Self::Zip {
            path: path.into(),
            source,
        }
    }

    /// Build an [`Error::NotAff4`] for `path`.
    pub fn not_aff4(path: impl Into<PathBuf>, reason: NotAff4Reason) -> Self {
        Self::NotAff4 {
            path: path.into(),
            reason,
        }
    }

    /// Build an [`Error::Malformed`] at `locus`.
    pub fn malformed(locus: Locus, detail: impl Into<String>) -> Self {
        Self::Malformed {
            locus: Box::new(locus),
            detail: detail.into(),
        }
    }

    /// Build an [`Error::Unsupported`].
    pub fn unsupported(feature: Feature, context: impl Into<String>) -> Self {
        Self::Unsupported {
            feature,
            context: context.into(),
        }
    }

    /// The container path this concerns, when the error names one.
    ///
    /// [`Error::Malformed`] carries its path inside its [`Locus`].
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Io { path, .. } | Self::Zip { path, .. } | Self::NotAff4 { path, .. } => {
                Some(path)
            }
            Self::Malformed { locus, .. } => Some(&locus.path),
            Self::Unsupported { .. } => None,
        }
    }

    /// Whether this error is a finding about the evidence itself.
    ///
    /// True only for [`Error::Malformed`]. I/O and ZIP failures are environment
    /// problems, [`Error::NotAff4`] means we were handed the wrong kind of file,
    /// and [`Error::Unsupported`] is a gap in this tool — none of which say the
    /// evidence is damaged.
    #[must_use]
    pub fn is_integrity_finding(&self) -> bool {
        matches!(self, Self::Malformed { .. })
    }

    /// Process exit code for this error.
    ///
    /// Distinct codes let scripts distinguish "the container is damaged" from
    /// "this build cannot read that codec".
    ///
    /// `0` means success and `2` is what clap emits for a usage error (the Unix
    /// convention), so library codes start at `3` and no library failure can be
    /// confused with a mistyped command line. `1` is left unused rather than
    /// assigned, since a bare `1` is what a panicking process would produce.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Io { .. } | Self::Zip { .. } => 3,
            Self::NotAff4 { .. } => 4,
            Self::Malformed { .. } => 5,
            Self::Unsupported { .. } => 6,
        }
    }
}

/// A departure from the AFF4 standard that does not invalidate the container.
///
/// Real containers deviate from the spec in ways that are legal RDF and
/// unambiguous in meaning — an untyped integer, a mis-cased datatype IRI.
/// Rejecting them would make the tool useless on real evidence; normalising
/// them silently would hide the deviation from the examiner. So they are
/// recorded and always reported.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Deviation {
    /// Where the deviation was found.
    pub locus: Locus,
    /// What kind of deviation it is.
    pub kind: DeviationKind,
    /// The specifics, including the offending lexical value.
    pub detail: String,
}

impl Deviation {
    /// Record a deviation.
    pub fn new(locus: Locus, kind: DeviationKind, detail: impl Into<String>) -> Self {
        Self {
            locus,
            kind,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for Deviation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.locus, self.detail)
    }
}

/// The kinds of deviation this crate reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviationKind {
    /// A numeric literal with no explicit datatype, where the standard's own
    /// containers use one (e.g. `aff4:size 8688` rather than `"8688"^^xsd:long`).
    /// A number written without an explicit datatype.
    ///
    /// **Deliberately no longer emitted.** Turtle types a bare integer as
    /// `xsd:integer`, so `aff4:size 8688` and `"8688"^^xsd:long` denote the
    /// same value and parse identically — nothing is normalised and no
    /// interpretation can turn on the difference. Reporting it buried real
    /// findings on containers that write every size that way.
    ///
    /// The variant is kept rather than removed: it is public and serialised, so
    /// dropping it would break the API and remove the term from reports already
    /// archived. If a lexical form ever turns up that *does* parse differently,
    /// re-emitting is a one-line change.
    UntypedNumericLiteral,
    /// A datatype IRI that is not the one the standard defines, but whose
    /// intent is unambiguous (e.g. `xsd:datetime` for `xsd:dateTime`).
    ///
    /// **Deliberately never emitted.** The only form that would raise it is
    /// pyaff4's lowercase `xsd:datetime`, accepted in silence: the lexical form
    /// is preserved verbatim either way, so no reading of the evidence turns on
    /// the capital `T`.
    ///
    /// Kept rather than removed for the same reason as
    /// [`Self::UntypedNumericLiteral`]: it is public and serialised, so
    /// dropping it would break the API and remove the term from reports
    /// already archived.
    NonstandardDatatype,
    /// A literal whose datatype is defined but not the one expected here.
    UnexpectedDatatype,
    /// A digest whose length does not match its declared algorithm.
    DigestLengthMismatch,
    /// A ZIP comment carrying trailing NUL bytes after the volume ARN.
    NulPaddedComment,
    /// The ZIP comment and `container.description` disagree on the volume ARN.
    InconsistentVolumeArn,
    /// An ARN using the byte-range extension `aff4://uuid[0xSTART:0xLEN]`,
    /// which is not in the standard but is produced by pyaff4.
    ByteRangeArn,
    /// A content-addressed subject of the form `aff4:sha512:<digest>`.
    ///
    /// pyaff4's deduplicating writer uses these to index stored blocks by
    /// content hash. They are a deliberate extension, not damage, but they are
    /// not AFF4 resource names either — they carry no `aff4://` authority — so
    /// they cannot be summarised as objects.
    ContentAddressedSubject,
    /// Two ZIP members share a name, so the later one is unreachable.
    DuplicateSegmentName,
    /// A discontiguous map left holes, filled from its gap stream (v1.0a §4).
    ///
    /// Legal for an `aff4:DiscontiguousImage`, but always worth reporting: the
    /// filled bytes were never recorded by the acquisition, so a digest over
    /// the image covers content the spec supplied rather than content the
    /// imager measured.
    MapGap,
    /// A logical file stored as a ZIP segment without `aff4:zip_segment`.
    ///
    /// AFF4-L 2019 §3.8's recipe ends by adding `aff4:zip_segment` to the
    /// `rdf:type` list "to indicate that it is stored as a Zip Segment". The
    /// type is what tells a consumer where a `FileImage`'s bytes live: without
    /// it a reader that dispatches on type finds neither a segment nor an
    /// `ImageStream` and has nothing to read.
    ///
    /// **This is not hypothetical.** pyaff4's own `unicode.aff4` omits it on
    /// `README.txt`, the one file it stores as a segment, while `dream.aff4`
    /// writes it — so the same implementation is inconsistent with itself. Left
    /// unreported, `verify` silently declined that file's two recorded digests
    /// even though its bytes were present and matched.
    MissingZipSegmentType,
    /// A reference to an object stored in another volume, e.g. one stripe of a
    /// striped container. Expected when inspecting a single stripe.
    ExternalReference,
    /// Two volumes of one striped set declare different values for the same
    /// predicate of the same stream (e.g. `chunkSize` 512 in one and 1024 in
    /// the other).
    ///
    /// The set cannot be read as one image, because no choice between the two
    /// values is defensible. `verify` already declines on this; before this
    /// variant existed `info` absorbed it silently and reported a clean
    /// container.
    ConflictingStreamValue,
    /// A `target`, `dataStream`, or `dependentStream` edge naming an ARN that
    /// no triple in the graph describes, and which carries no `aff4:stored`
    /// pointer identifying it as held elsewhere.
    ///
    /// The reference cannot be resolved or attributed: it is neither a
    /// described object nor a declared external one.
    DanglingReference,
    /// An object local to this volume is described in `information.turtle`,
    /// but the volume's own `aff4:contains` manifest never names it.
    ///
    /// The manifest is the volume's authoritative statement of what it holds
    /// (v1.0a §5.4); an object outside it is legal RDF but not accounted for by
    /// the container's own bookkeeping. Sub-resources named by suffixing a
    /// declared ARN's path (`BlockHashes` objects, `<stream>/blockhash.sha1`)
    /// are not undeclared — every corpus writer omits those from `contains` as
    /// a matter of course — nor is the volume's own ARN, which does not list
    /// itself.
    UndeclaredObject,
}

impl DeviationKind {
    /// Whether this condition is one the format routinely produces.
    ///
    /// A *routine* deviation is worth recording but does not by itself mean the
    /// container is questionable: inspecting one stripe of a striped set always
    /// yields [`Self::ExternalReference`], and one writer NUL-pads every ZIP
    /// comment it produces. `--strict` ignores these, because an exit code that
    /// fires on every striped container carries no information — see the
    /// A case where `--strict` returned 7 on a container whose real
    /// defect went unreported, from an unrelated routine note.
    ///
    /// Frequency alone does not make a condition routine. Three of the four
    /// corpus writers violate v1.0a §5.4's `container.description` ordering and
    /// so does one commercial tool, but member order can affect how another
    /// implementation reads the volume, so [`Self::InconsistentVolumeArn`]
    /// stays noteworthy. The test is whether the condition can affect
    /// interpretation, not how often it occurs.
    #[must_use]
    pub fn is_routine(self) -> bool {
        crate::rules::rule_for_kind(self).is_some_and(|rule| rule.routine)
    }

    /// The specification section this condition departs from, as a section
    /// number within the base document governing `generation`.
    ///
    /// Section numbers are identical in v1.0 and v1.0a for every section cited
    /// here; the draft renumbers nothing, so these citations are checkable
    /// against either document. Where the two differ in *content* the draft is
    /// the fuller statement, which is why `conformance` names it.
    ///
    /// The numbers come from the rule registry, which is the single place a
    /// citation is declared.
    ///
    /// [`None`] is not "no rule applies" — it marks a condition the standard
    /// does not legislate at all, or one another document legislates instead.
    /// Extensions that no section prohibits are reported because an examiner
    /// should know the container uses them, not because a clause was broken.
    /// Presenting an invented section number against either would be worse
    /// than citing nothing.
    ///
    /// # Generation
    ///
    /// The base document is v1.0a for every generation this build checks, so
    /// the registry's section numbers hold for all of them. `generation` is taken
    /// anyway, because it is what decides which document the number is read
    /// *in*: when a generation arrives whose base is not v1.0a, this signature
    /// already carries what the answer depends on, and every caller already
    /// supplies it. A citation is a claim about a specific document, and the
    /// document must be part of the question.
    #[must_use]
    pub fn spec_section(self, generation: crate::lexicon::Generation) -> Option<&'static str> {
        // The AFF4-L v1.0-ALPHA rules are not implemented: a v2.1 container is
        // declined before any deviation is recorded, so no section of that
        // document may be cited. Returning None here keeps a v1.0a section
        // number from being printed against a document that does not contain
        // it, should a deviation ever reach this path. The registry cannot make
        // this decision: it is keyed by kind alone and knows no generation.
        if matches!(generation, crate::lexicon::Generation::Aff4L10) {
            return None;
        }
        let rule = crate::rules::rule_for_kind(self)?;
        // Two cases yield no section in the base document, and they mean
        // different things. A rule belonging to another document is legislated
        // elsewhere, and `other_specification` names where. A rule carrying the
        // "none" clause is an extension no clause legislates at all, reported
        // so an examiner knows the container uses it.
        if rule.id.document != crate::rules::Document::Aff4Standard10a || rule.id.clause == "none" {
            return None;
        }
        // Returned as stored: the catalog keeps the section sign, so a report
        // prints the clause with no allocation.
        Some(rule.id.clause)
    }

    /// The section of a *different* normative document this cites, if any.
    ///
    /// AFF4-L logical constructs are specified in Schatz (2019), not in the
    /// Standard, so a deviation from them has no Standard section to name.
    /// Returning the paper's section here keeps the report from printing
    /// either an invented Standard citation or "the Standard does not address
    /// this" — the latter is true but misleading, since another specification
    /// addresses it squarely.
    ///
    /// # Generation
    ///
    /// Only [`Generation::PyAff4Logical`] is governed by the paper, per the
    /// mapping table: version 1.1 is v1.0a as base *plus* the 2019 paper for
    /// logical constructs. A v1.0a container carries no logical layer, so a
    /// logical citation against one would name a document that does not govern
    /// it.
    ///
    /// [`Generation::PyAff4Logical`]: crate::lexicon::Generation::PyAff4Logical
    #[must_use]
    pub fn other_specification(
        self,
        generation: crate::lexicon::Generation,
    ) -> Option<(&'static str, &'static str)> {
        // Only a pyaff4-era logical container is governed by the paper. The
        // registry is keyed by kind alone, so this gate stays here.
        if !matches!(generation, crate::lexicon::Generation::PyAff4Logical) {
            return None;
        }
        let rule = crate::rules::rule_for_kind(self)?;
        if rule.id.document != crate::rules::Document::Aff4LPaper2019 {
            return None;
        }
        Some((rule.id.document.name(), rule.id.clause))
    }
}

/// The AFF4-L specification, which is a paper rather than a standard document.
///
/// Cited in full because an examiner reading a report should be able to find
/// it: it is not the document `SPEC_NAME` names, and searching the Standard for
/// these rules finds nothing.
///
/// A thin alias for [`crate::rules::Document::Aff4LPaper2019`]'s name, so the
/// registry stays the single place a document is named.
pub const AFF4_L_SPEC_NAME: &str = crate::rules::Document::Aff4LPaper2019.name();

/// The base specification `aff4tools conformance` checks against.
///
/// v1.0a is an unofficial draft (Schatz, Feb 2022), and it is the fuller
/// document: it specifies chunk padding (v1.0a §3.2), the `mapPath` segment
/// (v1.0a §6.3), and striped multi-ZIP containers (v1.0a §7), none of which the
/// v1.0 PDF covers.
/// Every section number cited in this crate was verified against it.
///
/// It governs the base container for both AFF4 Standard v1.0a containers and
/// pyaff4-era AFF4-L; see [`crate::lexicon::Generation::governing_spec`].
///
/// A thin alias for [`crate::rules::Document::Aff4Standard10a`]'s name, so the
/// registry stays the single place a document is named.
pub const SPEC_NAME: &str = crate::rules::Document::Aff4Standard10a.name();

/// The AFF4-L Standard v1.0-ALPHA (Schatz, Apple Inc., September 2026).
///
/// Named so a v2.1 container can be identified accurately, then declined: its
/// rules are not implemented here. The document is a pre-release that states
/// its Canonical Reference Images take precedence over its own text, and those
/// images are not yet published — so no rule from it could be validated
/// against evidence. See `docs/working/AFF4-L-Standard-v1.0-ALPHA-design-phases.md`.
///
/// A thin alias for [`crate::rules::Document::Aff4LStandard10Alpha`]'s name, so
/// the registry stays the single place a document is named.
pub const AFF4_L_STANDARD_NAME: &str = crate::rules::Document::Aff4LStandard10Alpha.name();

impl std::fmt::Display for DeviationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::UntypedNumericLiteral => "untyped numeric literal",
            Self::NonstandardDatatype => "nonstandard datatype IRI",
            Self::UnexpectedDatatype => "unexpected datatype",
            Self::DigestLengthMismatch => "digest length mismatch",
            Self::NulPaddedComment => "NUL-padded ZIP comment",
            Self::InconsistentVolumeArn => "inconsistent volume ARN",
            Self::ByteRangeArn => "byte-range ARN extension",
            Self::ContentAddressedSubject => "content-addressed dedupe subject",
            Self::MapGap => "discontiguous map gap",
            Self::DuplicateSegmentName => "duplicate segment name",
            Self::MissingZipSegmentType => "segment-stored file missing aff4:zip_segment",
            Self::ExternalReference => "reference to another volume",
            Self::ConflictingStreamValue => "volumes disagree about a stream",
            Self::DanglingReference => "reference to an object nothing describes",
            Self::UndeclaredObject => "object outside the volume's own manifest",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locus_renders_progressively() {
        let bare = Locus::new("/evidence/case1.aff4");
        assert_eq!(bare.to_string(), "/evidence/case1.aff4");

        let full = Locus::new("/evidence/case1.aff4")
            .segment("information.turtle")
            .byte_offset(2841)
            .subject("aff4://c215ba20-5648-4209-a793-1f918c723610")
            .predicate("aff4:size");
        assert_eq!(
            full.to_string(),
            "/evidence/case1.aff4!information.turtle@2841 \
             subject aff4://c215ba20-5648-4209-a793-1f918c723610 predicate aff4:size"
        );
    }

    #[test]
    fn malformed_message_names_the_location() {
        let err = Error::malformed(
            Locus::new("/evidence/case1.aff4")
                .segment("information.turtle")
                .predicate("aff4:size"),
            "literal \"32k\" is not a valid xsd:long",
        );
        let rendered = err.to_string();
        assert!(rendered.contains("information.turtle"), "{rendered}");
        assert!(rendered.contains("aff4:size"), "{rendered}");
        assert!(rendered.contains("32k"), "{rendered}");
    }

    /// The taxonomy's load-bearing distinction: a container needing a feature
    /// we lack must never be reported as damaged evidence.
    #[test]
    fn unsupported_is_not_an_integrity_finding() {
        let unsupported = Error::unsupported(
            Feature::Generation {
                named: "Rekall/winpmem".into(),
            },
            "detected at /evidence/mem.aff4",
        );
        assert!(!unsupported.is_integrity_finding());
        assert_eq!(unsupported.exit_code(), 6);

        let malformed = Error::malformed(Locus::new("/evidence/case1.aff4"), "bad index");
        assert!(malformed.is_integrity_finding());
        assert_eq!(malformed.exit_code(), 5);
    }

    #[test]
    fn exit_codes_are_distinct_per_class() {
        let io = Error::io(
            "/x.aff4",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        let not_aff4 = Error::not_aff4("/x.zip", NotAff4Reason::EmptyArchive);
        let malformed = Error::malformed(Locus::new("/x.aff4"), "bad");
        let unsupported = Error::unsupported(Feature::Encryption, "at /x.aff4");

        let codes = [
            io.exit_code(),
            not_aff4.exit_code(),
            malformed.exit_code(),
            unsupported.exit_code(),
        ];
        assert_eq!(codes, [3, 4, 5, 6]);
        // 1 is reserved for CLI usage errors and must not be produced here.
        assert!(!codes.contains(&1));
    }

    #[test]
    fn errors_expose_the_container_path() {
        let malformed = Error::malformed(
            Locus::new("/evidence/case1.aff4").segment("version.txt"),
            "missing major",
        );
        assert_eq!(
            malformed.path(),
            Some(Path::new("/evidence/case1.aff4")),
            "Malformed must surface the path from its Locus"
        );

        let unsupported = Error::unsupported(Feature::Encryption, "no path known");
        assert_eq!(unsupported.path(), None);
    }

    /// The library never decorates its own messages; the binary owns
    /// presentation. A stray newline here would corrupt any caller's layout.
    #[test]
    fn messages_are_bare_fragments() {
        let err = Error::not_aff4("/x.zip", NotAff4Reason::NoMetadata);
        let rendered = err.to_string();
        assert!(!rendered.ends_with('\n'), "{rendered}");
        assert!(!rendered.starts_with("error"), "{rendered}");
    }

    #[test]
    fn deviation_reports_where_and_what() {
        let dev = Deviation::new(
            Locus::new("/evidence/dream.aff4")
                .segment("information.turtle")
                .subject("aff4://5aea2dd0-32b4-4c61-a9db-677654be6f83/dream.txt")
                .predicate("aff4:size"),
            DeviationKind::UntypedNumericLiteral,
            "aff4:size 8688 has no explicit datatype (AFF4Std uses \"8688\"^^xsd:long)",
        );
        let rendered = dev.to_string();
        assert!(rendered.contains("information.turtle"), "{rendered}");
        assert!(rendered.contains("8688"), "{rendered}");
        assert_eq!(dev.kind, DeviationKind::UntypedNumericLiteral);
    }

    /// The registry must return exactly what the hand-written match arms did.
    ///
    /// This is the phase gate in miniature: every citation the tool has ever
    /// printed must still be printed, character for character.
    #[test]
    fn registry_delegation_preserves_every_citation() {
        use crate::lexicon::Generation;

        let cases = [
            (
                DeviationKind::UnexpectedDatatype,
                Generation::Standard10,
                Some("§2.2"),
            ),
            (
                DeviationKind::DigestLengthMismatch,
                Generation::Standard10,
                Some("§6.1"),
            ),
            (
                DeviationKind::NulPaddedComment,
                Generation::Standard10,
                Some("§5.4"),
            ),
            (
                DeviationKind::InconsistentVolumeArn,
                Generation::Standard10,
                Some("§5.4"),
            ),
            (
                DeviationKind::UndeclaredObject,
                Generation::Standard10,
                Some("§5.4"),
            ),
            (
                DeviationKind::ByteRangeArn,
                Generation::Standard10,
                Some("§5.1"),
            ),
            (DeviationKind::MapGap, Generation::Standard10, Some("§4")),
            (
                DeviationKind::DuplicateSegmentName,
                Generation::Standard10,
                Some("§5"),
            ),
            (
                DeviationKind::ExternalReference,
                Generation::Standard10,
                Some("§7.1"),
            ),
            (
                DeviationKind::ConflictingStreamValue,
                Generation::Standard10,
                Some("§7.1"),
            ),
            (
                DeviationKind::ContentAddressedSubject,
                Generation::Standard10,
                None,
            ),
            (
                DeviationKind::DanglingReference,
                Generation::Standard10,
                None,
            ),
            (
                DeviationKind::MissingZipSegmentType,
                Generation::Standard10,
                None,
            ),
        ];

        for (kind, generation, expected) in cases {
            assert_eq!(
                kind.spec_section(generation),
                expected,
                "{kind:?} under {generation:?}"
            );
        }
    }

    /// A v2.1 container cites no v1.0a section, which the current code enforces
    /// by an early return. That behavior must survive the refactor.
    #[test]
    fn v2_1_containers_cite_no_v1_0a_section() {
        use crate::lexicon::Generation;

        for kind in [
            DeviationKind::NulPaddedComment,
            DeviationKind::MapGap,
            DeviationKind::DigestLengthMismatch,
        ] {
            assert_eq!(
                kind.spec_section(Generation::Aff4L10),
                None,
                "{kind:?} must cite no v1.0a section in a v2.1 container"
            );
        }
    }

    /// The paper citation appears only for the generation the paper governs.
    #[test]
    fn the_paper_is_cited_only_for_pyaff4_logical() {
        use crate::lexicon::Generation;

        assert_eq!(
            DeviationKind::MissingZipSegmentType.other_specification(Generation::PyAff4Logical),
            Some((AFF4_L_SPEC_NAME, "§3.8"))
        );
        assert_eq!(
            DeviationKind::MissingZipSegmentType.other_specification(Generation::Standard10),
            None
        );
    }

    /// Exactly two conditions are routine today, and `--strict` depends on it.
    #[test]
    fn routine_kinds_are_unchanged() {
        assert!(DeviationKind::ExternalReference.is_routine());
        assert!(DeviationKind::NulPaddedComment.is_routine());
        assert!(!DeviationKind::MapGap.is_routine());
        assert!(!DeviationKind::DigestLengthMismatch.is_routine());
    }
}
