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
    // Deliberately says nothing about *which* version the file declares.
    // The declared version is what selects the governing document, and so
    // what selects this rule set — checking the value here would assert as a
    // finding the very premise the check was chosen from. AFF4-L
    // v1.0-ALPHA §3's `major=2 minor=1` is covered by this rule for the same
    // reason: it is the same requirement, stated by whichever document
    // governs.
    //
    // `Honored` rather than `Detected` because every way of breaking it is
    // already refused before conformance runs. A container with no
    // `version.txt` is the pre-standard generation, recognized and declined;
    // one whose file omits `major` or `minor` is `Error::Malformed`, exit 5.
    // A `Detected` rule here would carry a deviation kind that no input could
    // ever raise.
    declare_rule! {
        id: (Document::Aff4Standard10a, "§1.1", 1),
        requirement: Must,
        state: Honored,
        statement: "A container declares its format version in a version.txt segment at its root, giving a major and a minor number.",
        kind: None,
        routine: false,
    },
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
        state: Detected,
        statement: "AFF4 objects are named by ARN, with the suspect's path and file name carried in properties rather than encoded into the name.",
        kind: Some(K::NonGuidArn),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§1.1", 2),
        requirement: Must,
        state: Detected,
        statement: "A logical file records its name and path in properties, since its resource name no longer carries them.",
        kind: Some(K::MissingRecordedPath),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§1.2", 1),
        requirement: Must,
        state: Detected,
        statement: "A segment name derived from an object's resource name leaves the scheme and authority unescaped.",
        kind: Some(K::EscapedV21MemberName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§2", 1),
        requirement: Must,
        state: Detected,
        statement: "An object's resource name is the AFF4 scheme followed by a lower-case GUID.",
        kind: Some(K::UppercaseGuidArn),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§2", 2),
        requirement: May,
        state: NotCheckable,
        statement: "A resource name may carry a further part after its GUID, provided the whole remains a valid IRI.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.1", 1),
        requirement: Must,
        state: Detected,
        statement: "A writer emits new lexicon terms under the namespace its governing standard assigns them.",
        kind: Some(K::WrongTermNamespace),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.1", 2),
        requirement: May,
        state: Honored,
        statement: "A reader may accept either namespace prefix for a lexicon term, so that containers written against the earlier schema still read.",
        kind: None,
        routine: false,
    },
    // AFF4-L v1.0-ALPHA §4.2 and §4.3 state no normative language at all.
    //
    // Read them closely before adding a MUST here. AFF4-L v1.0-ALPHA §4.1
    // spells its requirement out — "Compliant implementations MUST use the
    // correct namespace" — and the two clauses after it state nothing of the
    // kind. They say the classes and properties "supplement those defined in
    // AFF4 Standard v1.0" and then tabulate what each term means.
    //
    // So these clauses define a vocabulary; they do not require any object to
    // carry any term. A rule asserting that a FileImage MUST record a
    // timestamp would be this project inventing a requirement and then
    // reporting containers for departing from it — the opposite of measuring a
    // container against its document.
    //
    // What the terms are *for* is settled elsewhere and already checked:
    // AFF4-L v1.0-ALPHA §1.1 carries the MUST that files record their name and
    // path, and its rules are Detected.
    //
    // Each clause is therefore one rule at MAY, describing the vocabulary the
    // writer draws on. `Honored` for the terms aff4tools writes today;
    // `NotImplemented` for those it does not, so the gap stays visible.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.2", 1),
        requirement: May,
        state: Honored,
        statement: "A writer describes acquired files, folders and the acquisition itself with the classes this clause supplies.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.2", 2),
        requirement: May,
        state: NotImplemented,
        statement: "A writer describes a file's non-primary data streams and extended attributes with the classes this clause supplies.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 1),
        requirement: May,
        state: Honored,
        statement: "A writer records an acquired object's filesystem timestamps and an acquisition's roots with the properties this clause supplies.",
        kind: None,
        routine: false,
    },
    // The clause gives `recordChanged` and `lastWritten` the same description,
    // so what distinguishes them is not stated. aff4tools writes the AFF4-L
    // 2019 paper's meanings — content modification and metadata modification —
    // but a container written to the clause as it stands could carry either in
    // either property, and nothing in the document decides which is right.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 2),
        requirement: May,
        state: NotCheckable,
        statement: "Two of the timestamp properties carry the same description, so which moment each records cannot be judged from the document.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 3),
        requirement: May,
        state: Honored,
        statement: "A writer records the separator its acquisition's paths use, with the property this clause supplies.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 4),
        requirement: May,
        state: Honored,
        statement: "A writer records an acquired object's Unix file mode, with the property this clause supplies.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 5),
        requirement: May,
        state: NotImplemented,
        statement: "A writer references a file's alternate data streams and extended attributes with the properties this clause supplies.",
        kind: None,
        routine: false,
    },
    // The clause lists `name` and `value` twice, once for each substream
    // class, with descriptions that differ in wording but not in what a writer
    // would do. Whether that is one property used in two contexts or two
    // distinct properties decides whether a reader may treat the term
    // uniformly or must dispatch on the subject's type, and the document does
    // not say.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 6),
        requirement: May,
        state: NotCheckable,
        statement: "The naming and content properties of a substream appear twice under different contexts, so whether they are one term or two cannot be judged from the document.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.4", 1),
        requirement: May,
        state: Honored,
        statement: "A digest property may carry any of the additional algorithms this clause names, and a reader computes each of them.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.4", 2),
        requirement: May,
        state: NotCheckable,
        statement: "The clause names two extendable-output functions without fixing an output length, so the length a container uses cannot be judged.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 1),
        requirement: Must,
        state: Detected,
        statement: "A name that is valid UTF-8 without control characters is recorded as it is, with no raw form.",
        kind: Some(K::RedundantRawName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 2),
        requirement: Must,
        state: Detected,
        statement: "A name that is not valid UTF-8, or carries a control character, records its raw bytes base64-encoded alongside the display form.",
        kind: Some(K::MissingRawName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 3),
        requirement: Must,
        state: Detected,
        statement: "A raw name is well-formed base64, so the bytes it records can be read.",
        kind: Some(K::MalformedRawName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 4),
        requirement: Must,
        state: Detected,
        statement: "A name's raw form and display form describe the same name, so the two never contradict each other.",
        kind: Some(K::ContradictoryRawName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 5),
        requirement: Must,
        state: Detected,
        statement: "Percent escapes in a display name use uppercase hexadecimal.",
        kind: Some(K::LowercaseNameEscape),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 6),
        requirement: May,
        state: NotCheckable,
        statement: "Two encoded names in one folder may share a display form, so a reader must not assume a display name is unique.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 7),
        requirement: Must,
        state: NotImplemented,
        statement: "A name is recorded byte for byte on a platform whose paths are not byte-oriented, in the encoding the standard names.",
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
    // A permission aff4tools takes up on both sides. The writer stores a
    // logical file above the AFF4-L 2019 §3.3 threshold as one subject typed
    // `FileImage, Image, ImageStream`, and the reader resolves that shape.
    // Nothing a container carries could depart from a permission, so there is
    // no deviation to raise.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.4", 1),
        requirement: May,
        state: Honored,
        statement: "A file image may additionally be typed as an image stream, storing its primary stream that way.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§7", 1),
        requirement: May,
        state: Honored,
        statement: "A container may signal its format by file extension, which is a hint and never decides how the container is read.",
        kind: None,
        routine: false,
    },
    // The clause calls the scheme "purely a hint" and requires conformance to
    // the base standard instead, so a set named otherwise is not thereby
    // non-conformant — hence SHOULD, not MUST.
    //
    // `NotImplemented`, not `Honored`: unlike the AFF4-L v1.0-ALPHA §7
    // extension hint, this one *is* a property of what is on disk, so a
    // checker could exist. It would have to judge the whole set, and a scan is
    // handed one container at a time, with the sibling parts reached through
    // the volume set rather than named by the finding. That is a real check
    // with a real design question behind it, so it is reported as work not
    // done rather than quietly claimed.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§8", 1),
        requirement: Should,
        state: NotImplemented,
        statement: "Parts of a multi-part container signal their membership by sharing one file name, the second and later parts carrying an ordinal suffix counting from one.",
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
        state: Detected,
        statement: "The digest of the primary metadata segment is recorded in a companion segment beside it, written in the turtle datatype syntax.",
        kind: Some(K::MissingMetadataHash),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.1", 2),
        requirement: Must,
        state: Detected,
        statement: "That digest uses SHA-256, SHA-512, or a stronger algorithm the standard supports.",
        kind: Some(K::WeakMetadataHash),
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
