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
