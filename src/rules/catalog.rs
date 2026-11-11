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
///
/// Declared in the order the document reads: a section's own rules first, then
/// its subsections in numerical order.
pub(super) const AFF4_V1_0A: &[RuleInfo] = &[
    // The bootstrap rule, split in two because the container's obligation and
    // the reader's obligation have different states.
    //
    // 1.1/1 says nothing about *which* version the file declares. The declared
    // version is what selects the governing document, and so what selects this
    // rule set — checking the value here would assert as a finding the very
    // premise the check was chosen from. AFF4-L v1.0-ALPHA §3's
    // `major=2 minor=1` is covered by this rule for the same reason: it is the
    // same requirement, stated by whichever document governs.
    //
    // `Honored`, not `Detected`, because a container reaching the conformance
    // pass has already satisfied it: parsing a `version.txt` giving both
    // numbers is what let the container open. There is no deviation kind for a
    // missing version, and adding one would be wrong — the failure is
    // `Malformed`, not a departure recorded in the report.
    declare_rule! {
        id: (Document::Aff4Standard10a, "§1.1", 1),
        requirement: Must,
        state: Honored,
        governs: Container,
        statement: "A container declares its format version in a version.txt segment at its root, giving a major and a minor number.",
        kind: None,
        routine: false,
    },
    // 1.1/2 is the reader's half, and it is `Enforced`: the check runs in
    // `container.rs`'s `identify`, before conformance, and a failure refuses
    // the container rather than recording a deviation. A `version.txt` that
    // omits `major` or `minor` is `Error::Malformed` (exit 5); a container with
    // no `version.txt` at all is the pre-standard generation, named and
    // declined as `Error::Unsupported` (exit 6). Neither reaches the report.
    //
    // "Unimplemented" is deliberately absent from the statement: a valid but
    // unimplemented version (1.2, 3.0) is a limitation of aff4tools, not a
    // departure by the container.
    declare_rule! {
        id: (Document::Aff4Standard10a, "§1.1", 2),
        requirement: Must,
        state: Enforced,
        governs: Reader,
        statement: "A reader gives an error if a container format version is missing or invalid, and otherwise uses the format version to parse the container.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§2.2", 1),
        requirement: Should,
        state: NotImplemented,
        governs: Container,
        statement: "Numeric literals carry an explicit datatype, as the standard's own containers write them.",
        kind: Some(K::UntypedNumericLiteral),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§2.2", 2),
        requirement: Should,
        state: NotImplemented,
        governs: Container,
        statement: "Datatype IRIs are spelled as the standard defines them, not in a variant case.",
        kind: Some(K::NonstandardDatatype),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§2.2", 3),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A literal's datatype is the one its property expects.",
        kind: Some(K::UnexpectedDatatype),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§4", 1),
        requirement: May,
        state: Detected,
        governs: Container,
        statement: "A discontiguous map's holes are filled from its declared gap stream.",
        kind: Some(K::MapGap),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "Each storage path holds one segment, so a repeated member name leaves the earlier one unreachable.",
        kind: Some(K::DuplicateSegmentName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5.1", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "An ARN maps to a storage path by the URI-to-path rules, which admit no byte-range suffix.",
        kind: Some(K::ByteRangeArn),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5.4", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "Where the ZIP comment carries the volume ARN, the ARN starts at offset 0 of the comment; the clause says nothing about bytes after it.",
        kind: Some(K::ArnNotAtCommentStart),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5.4", 2),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "The ZIP comment and container.description agree on the volume ARN.",
        kind: Some(K::InconsistentVolumeArn),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§5.4", 3),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "Where the volume ARN is stored in a container.description segment, that segment is the first member of the ZIP volume.",
        kind: Some(K::DescriptionNotFirst),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.1", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A digest's length matches the algorithm its datatype declares.",
        kind: Some(K::DigestLengthMismatch),
        routine: false,
    },
    // AFF4 Standard v1.0a §6.2 opens by making the whole approach optional:
    // implementations MAY adopt block map hashing. Every other rule in the
    // section is conditional on that adoption, and a container that never
    // adopted it satisfies them all trivially. The registry has no conditional
    // requirement level, so each rule states its condition in its statement.
    //
    // A container has adopted block map hashing when it holds a block-hash
    // segment or a literal typed aff4:blockMapHashSHA512 or
    // aff4:blockMapHashSHA256. Map digests alone are not adoption: the section
    // defines those properties without tying them to the rest of the
    // construction, and nothing requires a map to record them.
    //
    // Only four clauses carry a keyword. The rest define the construction
    // without one, and are declared MUST because a container departing from a
    // definition cannot be read by it. The clause naming the digest algorithm
    // says implementations "WILL employ" them; WILL is read as SHALL, which
    // RFC 2119 makes equivalent to MUST.
    //
    // The section's slips are resolved as follows. mapPointHash is defined over
    // a "point" segment v1.0a §4.2 does not name; it is the map segment, as the
    // value pyaff4 recorded in Base-Linear confirms. The mapHash formula's
    // parentheses do not balance; it covers the three segments' bytes in order.
    //
    // Declared in ordinal order, which the reading-order test requires. 6.2/4
    // is not declared: it required every map to record its segment digests,
    // which no clause does. Its number is not reused.
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 1),
        requirement: May,
        state: Honored,
        governs: ReaderWriter,
        statement: "An implementation may adopt block map hashing: per-chunk block hashes, digests over the map's segments, and one block map hash composed from both.",
        kind: None,
        routine: false,
    },
    // The approach is the whole construction, so block hashes recorded without
    // the hash they compose are a partial adoption, and the clause storing the
    // block map hash is a MUST.
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 2),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "A container that records block-hash segments for an image's stream also records that image's block map hash.",
        kind: None,
        routine: false,
    },
    // The clause names the datatypes but no property. pyaff4 writes aff4:hash,
    // matching v1.0a §6's statement that both hashing methods use it.
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 3),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "A recorded block map hash is stored on the aff4:Image, as a literal typed aff4:blockMapHashSHA512 or aff4:blockMapHashSHA256.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 5),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "If block map hashing is adopted, the digests it composes are SHA-512 or SHA-256: the digest over each aff4:BlockHashes resource, the map digests, and the block map hash.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 6),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "If block map hashing is adopted, each bevy's block hashes are held in a segment named after that bevy with the algorithm's extension: md5, sha1, sha256, sha512, or blake2b.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 7),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "For each block-hash algorithm used on a stream, every bevy of that stream has its block-hash segment, so the segments join into one unbroken sequence.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 8),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "A block-hash segment holds one raw digest per chunk, not hex-encoded, in the order of the chunks in its bevy, so its length is the bevy's chunk count times the digest size.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 9),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "A digest over a stream's concatenated block hashes is recorded as aff4:hash on the resource formed by appending /blockhash.<extension> to the stream's ARN, whose rdf:type is aff4:BlockHashes.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 10),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "Block hashes may be generated with more than one algorithm.",
        kind: None,
        routine: false,
    },
    // Value definitions. Recomputing a recorded value is verify's work, where a
    // mismatch is an integrity finding; conformance reads no segment bytes.
    // Honored: aff4tools writes and verifies these values by this definition.
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 11),
        requirement: Must,
        state: Honored,
        governs: ReaderWriter,
        statement: "Where recorded, aff4:mapPointHash is the digest of the map's map segment, aff4:mapIdxHash of its idx segment, aff4:mapPathHash of its mapPath segment, and aff4:mapHash of those segments' bytes concatenated in that order, mapPath only when present.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 12),
        requirement: Must,
        state: Honored,
        governs: ReaderWriter,
        statement: "The block map hash is the digest of these raw digests concatenated: the aff4:BlockHashes digest for every block-hash algorithm on the stream, shortest first (MD5, SHA-1, SHA-256, then SHA-512 before BLAKE2b), followed by mapPointHash, mapIdxHash, and mapPathHash when the map has a mapPath segment.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 13),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "The block map hash may also be stored on the aff4:Map, typed aff4:SHA512 or aff4:SHA256.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 14),
        requirement: May,
        state: NotCheckable,
        governs: Unsettled,
        statement: "The clause permitting a block map hash on the map names its datatype but not its property; by v1.0a's own convention that is aff4:hash, where aff4:SHA512 already means a linear digest of the map's stream, so a reader could not tell the two apart.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§6.2", 15),
        requirement: Must,
        state: NotCheckable,
        governs: Unsettled,
        statement: "The composition assumes one image stream behind one map, and does not say which aff4:BlockHashes digests enter it when a map targets several streams, or what replaces the map digests when an image's data stream has no map.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§7.1", 1),
        requirement: May,
        state: Detected,
        governs: Container,
        statement: "A stripe may reference streams held in a sibling volume of the same set.",
        kind: Some(K::ExternalReference),
        routine: true,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "§7.1", 2),
        requirement: Must,
        state: Detected,
        governs: Container,
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
    governs: Container,
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
        governs: Container,
        statement: "Content-addressed dedupe subjects are an extension no clause prohibits.",
        kind: Some(K::ContentAddressedSubject),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4Standard10a, "none", 2),
        requirement: May,
        state: Detected,
        governs: Container,
        statement: "A reference to an undescribed ARN with no aff4:stored pointer cannot be resolved or attributed.",
        kind: Some(K::DanglingReference),
        routine: false,
    },
    // `Honored` with no kind because nothing about this can be violated: a
    // volume that omits `aff4:contains` is as correct as one that states it,
    // so no input could raise a deviation of its own. Where a stated entry
    // names an ARN nothing describes, that is an unresolvable reference and is
    // reported under `none/2`, which covers it in general terms.
    declare_rule! {
        id: (Document::Aff4Standard10a, "none", 3),
        requirement: May,
        state: Honored,
        governs: Container,
        statement: "A volume may enumerate the ARNs it holds via an aff4:contains predicate, though this is not defined by any specification.",
        kind: None,
        routine: false,
    },
];

/// Rules from the AFF4-L Standard v1.0-ALPHA.
///
/// Declared in full so the catalog inventories the standard rather than only
/// the implemented subset, and in the order the document reads: a section's own
/// rules first, then its subsections in numerical order.
///
/// The `NotImplemented` rules cover secondary information stores, the
/// HDT-accelerated store, and X509 signing — the later clauses of AFF4-L
/// v1.0-ALPHA. These are features the owner deferred, not questions the
/// standard leaves open. Each clause is specified plainly enough to check; the
/// work has not been done. They are declared so the coverage figure counts the
/// whole standard.
///
/// The `NotCheckable` rules are the genuinely unsettled ones (AFF4-L
/// v1.0-ALPHA §2/2, §4.3/2, §4.3/6, §4.4/3, §5/6), where the document does not
/// answer what a container would have to do to conform.
pub(super) const AFF4L_V1_ALPHA: &[RuleInfo] = &[
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§1.1", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "AFF4 objects are named by ARN, with the suspect's path and file name carried in properties rather than encoded into the name.",
        kind: Some(K::NonGuidArn),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§1.1", 2),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A logical file records its name and path in properties, since its resource name no longer carries them.",
        kind: Some(K::MissingRecordedPath),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§1.2", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A segment name derived from an object's resource name leaves the scheme and authority unescaped.",
        kind: Some(K::EscapedV21MemberName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§2", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "An object's resource name is the AFF4 scheme followed by a lower-case GUID.",
        kind: Some(K::UppercaseGuidArn),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§2", 2),
        requirement: May,
        state: NotCheckable,
        governs: Unsettled,
        statement: "A resource name may carry a further part after its GUID, provided the whole remains a valid IRI.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.1", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A writer emits new lexicon terms under the namespace its governing standard assigns them.",
        kind: Some(K::WrongTermNamespace),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.1", 2),
        requirement: May,
        state: Honored,
        governs: Reader,
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
    // writer draws on, and `Honored` because a permission is met by taking it
    // up rather than by anything a container carries.
    //
    // The substream rules are Honored on the extended-attribute half, which
    // `write_xattrs` emits as `FileExtendedAttribute` subjects reached by
    // `aff4l:extendedAttribute`. The clause's other half names NTFS alternate
    // data streams, which no acquisition path on a Unix host produces; a
    // permission left unexercised is still a permission met, so this is not a
    // coverage gap.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.2", 1),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "A writer describes acquired files, folders and the acquisition itself with the classes this clause supplies.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.2", 2),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "A writer describes a file's non-primary data streams and extended attributes with the classes this clause supplies.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 1),
        requirement: May,
        state: Honored,
        governs: Writer,
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
        governs: Unsettled,
        statement: "Two of the timestamp properties carry the same description, so which moment each records cannot be judged from the document.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 3),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "A writer records the separator its acquisition's paths use, with the property this clause supplies.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 4),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "A writer records an acquired object's Unix file mode, with the property this clause supplies.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.3", 5),
        requirement: May,
        state: Honored,
        governs: Writer,
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
        governs: Unsettled,
        statement: "The naming and content properties of a substream appear twice under different contexts, so whether they are one term or two cannot be judged from the document.",
        kind: None,
        routine: false,
    },
    // AFF4-L v1.0-ALPHA §4.4 is one clause binding two actors at different
    // levels, so it splits into 4.4/1 (writer) and 4.4/2 (reader). The clause
    // carries no MUST/MAY keyword — it is a table of five datatypes under "The
    // following additional datatypes are supported for digest properties". The
    // writer half is a MAY: a writer may record a digest under any of them. The
    // reader half is a MUST read from "are supported": a datatype the standard
    // supports is one a reader must be able to compute, since a digest nothing
    // can verify is useless. Both are Honored — `hash.rs` constructs hashers for
    // SHA3-256/384/512 and SHAKE128/256, and `hash_selection.rs` exposes them
    // for writing, so aff4tools both writes and recomputes all five.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.4", 1),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "A writer may record a digest using any of the additional algorithms this clause names.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.4", 2),
        requirement: Must,
        state: Honored,
        governs: Reader,
        statement: "A reader computes each additional algorithm a digest property records.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§4.4", 3),
        requirement: May,
        state: NotCheckable,
        governs: Unsettled,
        statement: "The clause names two extendable-output functions without fixing an output length, so the length a container uses cannot be judged.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A name that is valid UTF-8 without control characters is recorded as it is, with no raw form.",
        kind: Some(K::RedundantRawName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 2),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A name that is not valid UTF-8, or carries a control character, records its raw bytes base64-encoded alongside the display form.",
        kind: Some(K::MissingRawName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 3),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A raw name is well-formed base64, so the bytes it records can be read.",
        kind: Some(K::MalformedRawName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 4),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A name's raw form and display form describe the same name, so the two never contradict each other.",
        kind: Some(K::ContradictoryRawName),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 5),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "Percent escapes in a display name use uppercase hexadecimal.",
        kind: Some(K::LowercaseNameEscape),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§5", 6),
        requirement: May,
        state: NotCheckable,
        governs: Unsettled,
        statement: "Two encoded names in one folder may share a display form, so a reader must not assume a display name is unique.",
        kind: None,
        routine: false,
    },
    // Honored rather than Detected: this rule binds the *reader*, so what
    // satisfies it is aff4tools' own behaviour and not anything a container
    // carries. Phase 9a made all four forms readable — in-metadata streams,
    // ZIP segments, both AFF4-L v1.0-ALPHA §6.3 map shapes, and a file image
    // typed as an image stream — each covered by `tests/storage_forms.rs`
    // against fixtures this project's writer did not produce.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6", 1),
        requirement: Must,
        state: Honored,
        governs: Reader,
        statement: "A reader handles every storage stream form this section describes, not a chosen subset.",
        kind: None,
        routine: false,
    },
    // Honored: this binds the writer, and what satisfies it is aff4tools' own
    // behaviour rather than anything a container carries. Phase 9c writes three
    // of the four forms — ZIP segments and image streams for primary content,
    // in-metadata streams for extended attributes — where the clause asks for
    // at least one.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6", 2),
        requirement: Must,
        state: Honored,
        governs: Writer,
        statement: "A writer implements at least one of the storage stream forms this section describes.",
        kind: None,
        routine: false,
    },
    // AFF4-L v1.0-ALPHA §6/3 and §6/4 are §6's own rules — the container-side
    // half of the dispatch model — so in reading order they sit with the other
    // v1.0-ALPHA §6 rules, before the subsections. The clause tells a reader to
    // support every storage form; these two say the container must name exactly
    // one of them per stream, since a reader dispatching on the type list can
    // do nothing with none or with two.
    //
    // Reported per subject and never raised as a whole-container failure: one
    // self-contradicting subject must not suppress the findings about every
    // other object, which is the same rule `build_object` follows for a
    // subject that is not a valid ARN.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6", 3),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A stream's declared storage form holds the bytes that form is said to store.",
        kind: Some(K::StorageFormNotFound),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6", 4),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A stream declares one storage form, not several, so where its bytes are stored is unambiguous.",
        kind: Some(K::AmbiguousStorageForm),
        routine: false,
    },
    // All three read the ZIP central directory rather than the metadata, since
    // the compression method and the stored size are not stated anywhere in the
    // RDF. A container whose metadata and directory disagree is measured
    // against what it actually did.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.1", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A stream held as a ZIP segment is compressed with Stored or Deflate and no other method.",
        kind: Some(K::UnsupportedSegmentCompression),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.1", 2),
        requirement: ShouldNot,
        state: Detected,
        governs: Container,
        statement: "A ZIP segment storage stream holds no stream of one gibibyte or more.",
        kind: Some(K::OversizedZipSegment),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.1", 3),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "A writer records a linear digest of each ZIP segment storage stream in that stream's hash property.",
        kind: Some(K::MissingZipSegmentHash),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.2", 1),
        requirement: MustNot,
        state: Detected,
        governs: Container,
        statement: "An in-metadata storage stream holds no stream larger than one kilobyte.",
        kind: Some(K::OversizedResidentStream),
        routine: false,
    },
    // A writer's permission: it may omit calculation and storage of hashes for
    // an in-metadata substream, relying on the metadata integrity hash. Omitting
    // calculation and storage is purely a writing act, so this governs the
    // writer. That a reader then verifies a substream carrying no digest without
    // reporting a missing one is a consequence of the permission, not the
    // permission itself. Nothing a container holds could depart from a
    // permission, so there is no deviation to raise.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.2", 2),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "A stream carried inside the metadata need not record its own digests, since the metadata integrity hash covers it.",
        kind: None,
        routine: false,
    },
    // A permission, so nothing a container carries could depart from it. Both
    // shapes AFF4-L v1.0-ALPHA §6.3 shows are read: the aff4:Map type added to
    // the FileImage instance, which is the form this project writes, and the
    // separate Map subject reached through aff4l:dataStream, which it does not
    // write and must still read.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.3", 1),
        requirement: May,
        state: Honored,
        governs: Writer,
        statement: "A file image may carry the map type, storing its primary stream through a map over a shared image stream.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.3.1", 1),
        requirement: Must,
        state: NotImplemented,
        governs: Writer,
        statement: "A writer computes and records a block map digest for every map, under either of the two property spellings the standard allows.",
        kind: None,
        routine: false,
    },
    // Also a reader-side obligation, so Honored for the same reason as
    // AFF4-L v1.0-ALPHA §6/1. Both spellings were already accepted before
    // Phase 9 — `aff4:hash` carrying a `blockMapHashSHA512`-style datatype and
    // a plain `aff4:blockMapHash` — and Phase 9a made the maps they sit on
    // reachable in both AFF4-L v1.0-ALPHA §6.3 shapes.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§6.3.1", 2),
        requirement: Must,
        state: Honored,
        governs: Reader,
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
        governs: ReaderWriter,
        statement: "A file image may additionally be typed as an image stream, storing its primary stream that way.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§7", 1),
        requirement: May,
        state: Honored,
        governs: Reader,
        statement: "A container may signal its format by file extension, which is a hint and never decides how the container is read.",
        kind: None,
        routine: false,
    },
    // The clause calls the scheme "purely a hint" and requires conformance to
    // the base standard instead, so a set named otherwise is not thereby
    // non-conformant — hence SHOULD, not MUST.
    //
    // Judged from the file names beside the container, which is the only place
    // the answer lives: the scheme exists so that membership can be told from
    // names alone, so nothing inside any volume could settle it. Reported once
    // for the set rather than once per file, since what departs is how the
    // names relate to each other.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§8", 1),
        requirement: Should,
        state: Detected,
        governs: Container,
        statement: "Parts of a multi-part container signal their membership by sharing one file name, the second and later parts carrying an ordinal suffix counting from one.",
        kind: Some(K::MultiPartNamingScheme),
        routine: false,
    },
    // AFF4-L v1.0-ALPHA §9 through §10.3, except the §10.1 metadata-integrity
    // rules already checked, are deferred features rather than unsettled
    // requirements. Each clause is specified plainly — v1.0-ALPHA §9 states a
    // MUST that imported stores join one graph, v1.0-ALPHA §9a.1 gives the
    // exact HDT encodings and byte layout, v1.0-ALPHA §10.2 and §10.3 fix
    // filenames, encodings and algorithms — so the state is `NotImplemented`,
    // not `NotCheckable`, and each names its governed actor.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§9", 1),
        requirement: Must,
        state: NotImplemented,
        governs: Reader,
        statement: "Triples from the primary metadata segment and from every store it imports are read as one graph.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§9a", 1),
        requirement: May,
        state: NotImplemented,
        governs: Container,
        statement: "A container may carry an accelerated metadata store beside the primary one, holding everything the primary and any secondary stores hold.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§9a", 2),
        requirement: May,
        state: NotImplemented,
        governs: Reader,
        statement: "A reader may take its metadata from the accelerated store in place of the primary and secondary stores.",
        kind: None,
        routine: false,
    },
    // Governed by the container: the HDT encodings are observable in the
    // `information.hdt` file, so the constraint is on what the container carries
    // rather than on reader or writer behavior.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§9a.1", 1),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "An implementation of the accelerated serialization confines itself to the triple, dictionary, and dictionary-section encodings the standard names.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.1", 1),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "The digest of the primary metadata segment is recorded in a companion segment beside it, written in the turtle datatype syntax.",
        kind: Some(K::MissingMetadataHash),
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.1", 2),
        requirement: Must,
        state: Detected,
        governs: Container,
        statement: "That digest uses SHA-256, SHA-512, or a stronger algorithm the standard supports.",
        kind: Some(K::WeakMetadataHash),
        routine: false,
    },
    // AFF4-L v1.0-ALPHA §10.2/1 is the container's permission to carry a
    // signature; v1.0-ALPHA §10.2/2-4 are the writer obligations that follow
    // once it does.
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.2", 1),
        requirement: May,
        state: NotImplemented,
        governs: Container,
        statement: "A container may carry an X509 signature of the primary metadata segment in a companion segment beside it.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.2", 2),
        requirement: Must,
        state: NotImplemented,
        governs: Writer,
        statement: "A signature is PEM encoded, and the certificate chain stored with it is complete down to the root and likewise PEM encoded.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.2", 3),
        requirement: Must,
        state: NotImplemented,
        governs: Writer,
        statement: "Where several keys sign the metadata, each signature and certificate segment is named by the pattern the standard fixes.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.2", 4),
        requirement: Must,
        state: NotImplemented,
        governs: Writer,
        statement: "A signature and its certificate chain share one extensible name part, itself valid UTF-8.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.3", 1),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "The digest of each secondary metadata store is recorded in the primary store, against that secondary store's own resource name.",
        kind: None,
        routine: false,
    },
    declare_rule! {
        id: (Document::Aff4LStandard10Alpha, "§10.3", 2),
        requirement: Must,
        state: NotImplemented,
        governs: Container,
        statement: "A digest recorded for a secondary metadata store uses SHA-256, SHA-512, or a stronger algorithm the standard supports.",
        kind: None,
        routine: false,
    },
];
