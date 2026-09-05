//! These are the `conformance` rules, grouped by governing document.
//!
//! One `declare_rule!` invocation per rule. Adding a new rule
//! requires adding one declaration here.
//!
//! Statements are written in this project's own words rather than quoted from
//! the documents they cite. Two of the three are FDL 1.3 and the third is
//! Apache-2.0, and transcribing any of them would trigger license obligations
//! that a short original sentence does not.

use crate::error::DeviationKind as K;
use crate::rules::{Document, RuleInfo};

/// Rules from the AFF4 Standard v1.0a.
pub(super) const AFF4_V1_0A: &[RuleInfo] = &[
    declare_rule! {
        id: (Document::Aff4Standard10a, "§2.2", 1),
        requirement: Should,
        state: NotImplemented,
        statement: "Numeric literals carry an explicit datatype, as the standard's own containers write them.",
        kind: Some(K::UntypedNumericLiteral),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§2.2", 2),
        requirement: Should,
        state: NotImplemented,
        statement: "Datatype IRIs are spelled as the standard defines them, not in a variant case.",
        kind: Some(K::NonstandardDatatype),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§2.2", 3),
        requirement: Must,
        state: Detected,
        statement: "A literal's datatype is the one its property expects.",
        kind: Some(K::UnexpectedDatatype),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.1", 1),
        requirement: Must,
        state: Detected,
        statement: "A digest's length matches the algorithm its datatype declares.",
        kind: Some(K::DigestLengthMismatch),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5.4", 1),
        requirement: Must,
        state: Detected,
        statement: "The ZIP comment carries the volume ARN starting at offset 0, with nothing appended.",
        kind: Some(K::NulPaddedComment),
        routine: true,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5.4", 2),
        requirement: Must,
        state: Detected,
        statement: "The ZIP comment and container.description agree on the volume ARN.",
        kind: Some(K::InconsistentVolumeArn),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5.4", 3),
        requirement: Must,
        state: Detected,
        statement: "Every object the volume holds appears in its own aff4:contains manifest.",
        kind: Some(K::UndeclaredObject),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5.1", 1),
        requirement: Must,
        state: Detected,
        statement: "An ARN maps to a storage path by the URI-to-path rules, which admit no byte-range suffix.",
        kind: Some(K::ByteRangeArn),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§4", 1),
        requirement: May,
        state: Detected,
        statement: "A discontiguous map's holes are filled from its declared gap stream.",
        kind: Some(K::MapGap),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5", 1),
        requirement: Must,
        state: Detected,
        statement: "Each storage path holds one segment, so a repeated member name leaves the earlier one unreachable.",
        kind: Some(K::DuplicateSegmentName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§7.1", 1),
        requirement: May,
        state: Detected,
        statement: "A stripe may reference streams held in a sibling volume of the same set.",
        kind: Some(K::ExternalReference),
        routine: true,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§7.1", 2),
        requirement: Must,
        state: Detected,
        statement: "Volumes of one striped set agree on every property of a commonly-named stream.",
        kind: Some(K::ConflictingStreamValue),
        routine: false,
    },
];

/// Rules from the 2019 AFF4-L paper (Schatz).
pub(super) const AFF4L_PAPER_2019: &[RuleInfo] = &[declare_rule! {
    id: (Document::Aff4LPaper2019, "§3.8", 1),
    requirement: Must,
    state: Detected,
    statement: "A file stored directly as a ZIP segment declares aff4:zip_segment in its type list.",
    kind: Some(K::MissingZipSegmentType),
    routine: false,
}];

/// Conditions no document legislates, reported so an examiner knows the
/// container uses them.
///
/// These carry a document for grouping only. Their citation renders as "the
/// document does not address this", which is what the report says today.
pub(super) const UNLEGISLATED: &[RuleInfo] = &[
    declare_rule! {
        id: (Document::Aff4Standard10a, "none", 1),
        requirement: May,
        state: Detected,
        statement: "Content-addressed dedupe subjects are an extension no clause prohibits.",
        kind: Some(K::ContentAddressedSubject),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "none", 2),
        requirement: May,
        state: Detected,
        statement: "A reference to an undescribed ARN with no aff4:stored pointer cannot be resolved or attributed.",
        kind: Some(K::DanglingReference),
        routine: false,
    },
];

/// Rules from the AFF4-L Standard v1.0-ALPHA.
///
/// Declared in full so the catalog inventories the standard rather than only
/// the implemented subset. Every rule is currently unevaluated: `conformance`
/// reports the gap, and no checker is implemented yet.
///
/// The `NotCheckable` rules are those the owner placed out of scope for this
/// phase — AFF4-L v1.0-ALPHA §9, §9a, §9a.1, §10.2 and §10.3 govern secondary
/// information stores, the HDT-accelerated store, and X509 signing, none of
/// which aff4tools reads or writes. They are declared so the coverage figure
/// counts the whole standard.
pub(super) const AFF4L_V1_ALPHA: &[RuleInfo] = &[
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§1.1", 1),
        requirement: Must,
        state: NotImplemented,
        statement: "AFF4 objects are named by ARN, with the suspect's path and file name carried in properties rather than encoded into the name.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.1", 1),
        requirement: Must,
        state: NotImplemented,
        statement: "A writer emits new lexicon terms under the namespace its governing standard assigns them.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.1", 2),
        requirement: May,
        state: NotImplemented,
        statement: "A reader may accept either namespace prefix for a lexicon term, so that containers written against the earlier schema still read.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6", 1),
        requirement: Must,
        state: NotImplemented,
        statement: "A reader handles every storage stream form this section describes, not a chosen subset.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6", 2),
        requirement: Must,
        state: NotImplemented,
        statement: "A writer implements at least one of the storage stream forms this section describes.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.1", 1),
        requirement: Must,
        state: NotImplemented,
        statement: "A stream held as a ZIP segment is compressed with Stored or Deflate and no other method.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.1", 2),
        requirement: ShouldNot,
        state: NotImplemented,
        statement: "A ZIP segment storage stream holds no stream of one gibibyte or more.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.1", 3),
        requirement: Must,
        state: NotImplemented,
        statement: "A writer records a linear digest of each ZIP segment storage stream in that stream's hash property.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.2", 1),
        requirement: MustNot,
        state: NotImplemented,
        statement: "An in-metadata storage stream holds no stream larger than one kilobyte.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.2", 2),
        requirement: May,
        state: NotImplemented,
        statement: "A stream carried inside the metadata need not record its own digests, since the metadata integrity hash covers it.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.3.1", 1),
        requirement: Must,
        state: NotImplemented,
        statement: "A writer computes and records a block map digest for every map, under either of the two property spellings the standard allows.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.3.1", 2),
        requirement: Must,
        state: NotImplemented,
        statement: "A reader accepts either block map digest spelling and can verify the block map digests of every map and dependent image stream.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§9", 1),
        requirement: Must,
        state: NotCheckable,
        statement: "Triples from the primary metadata segment and from every store it imports are read as one graph.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§9a", 1),
        requirement: May,
        state: NotCheckable,
        statement: "A container may carry an accelerated metadata store beside the primary one, holding everything the primary and any secondary stores hold.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§9a", 2),
        requirement: May,
        state: NotCheckable,
        statement: "A reader may take its metadata from the accelerated store in place of the primary and secondary stores.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§9a.1", 1),
        requirement: Must,
        state: NotCheckable,
        statement: "An implementation of the accelerated serialization confines itself to the triple, dictionary, and dictionary-section encodings the standard names.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.1", 1),
        requirement: Must,
        state: NotImplemented,
        statement: "The digest of the primary metadata segment is recorded in a companion segment beside it, written in the turtle datatype syntax.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.1", 2),
        requirement: Must,
        state: NotImplemented,
        statement: "That digest uses SHA-256, SHA-512, or a stronger algorithm the standard supports.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.2", 1),
        requirement: May,
        state: NotCheckable,
        statement: "A container may carry an X509 signature of the primary metadata segment in a companion segment beside it.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.2", 2),
        requirement: Must,
        state: NotCheckable,
        statement: "A signature is PEM encoded, and the certificate chain stored with it is complete down to the root and likewise PEM encoded.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.2", 3),
        requirement: Must,
        state: NotCheckable,
        statement: "Where several keys sign the metadata, each signature and certificate segment is named by the pattern the standard fixes.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.2", 4),
        requirement: Must,
        state: NotCheckable,
        statement: "A signature and its certificate chain share one extensible name part, itself valid UTF-8.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.3", 1),
        requirement: Must,
        state: NotCheckable,
        statement: "The digest of each secondary metadata store is recorded in the primary store, against that secondary store's own resource name.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.3", 2),
        requirement: Must,
        state: NotCheckable,
        statement: "A digest recorded for a secondary metadata store uses SHA-256, SHA-512, or a stronger algorithm the standard supports.",
        kind: None,
        routine: false,
    },
];
