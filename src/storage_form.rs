//! Where a logical stream's bytes are stored.
//!
//! Governed by AFF4-L Standard v1.0-ALPHA §6, which defines four
//! Data Storage forms and requires a reader to support all of them.
//!
//! Dispatch is strict. The inverse direction stays lenient and is handled elsewhere: bytes present
//! in a member named exactly by the subject's ARN, with the type absent, is an
//! identity match rather than a search. `verify` reports that as
//! [`crate::error::DeviationKind::MissingZipSegmentType`] and reads the bytes.

use crate::error::{Error, Locus, Result};

/// One of the storage forms AFF4-L v1.0-ALPHA §6 defines.
///
/// Five variants for four clauses: AFF4-L v1.0-ALPHA §6.3 covers both a map
/// over a stream several files share and a map over a stream one file has to
/// itself, and a writer has to be told which of the two to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageForm {
    /// Base64 inside `information.turtle` (AFF4-L v1.0-ALPHA §6.2).
    InMetadata,
    /// One ZIP member named by the ARN (AFF4-L v1.0-ALPHA §6.1).
    ZipSegment,
    /// A map addressing a shared image stream (AFF4-L v1.0-ALPHA §6.3).
    SharedMap,
    /// A map addressing an image stream this subject alone uses
    /// (AFF4-L v1.0-ALPHA §6.3).
    ///
    /// The same clause as [`Self::SharedMap`] and a different construct.
    /// AFF4-L v1.0-ALPHA §6.3 permits several files to share one stream; when
    /// they do not, the stream's block hashes describe one file's bytes, so
    /// AFF4-L v1.0-ALPHA §6.3.1's block map digest is computable. Over a shared
    /// stream it is not.
    OwnMap,
    /// The subject's own image stream (AFF4-L v1.0-ALPHA §6.4).
    OwnImageStream,
}

impl StorageForm {
    /// The form's name, for reports and error messages.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::InMetadata => "in-metadata",
            Self::ZipSegment => "ZIP segment",
            Self::SharedMap => "map",
            Self::OwnMap => "own map",
            Self::OwnImageStream => "image stream",
        }
    }
}

/// Whether one `rdf:type` IRI names the given local name.
///
/// Types are stored as full IRIs, so a comparison against a local name has to
/// strip the namespace. Mirrors the same rule `verify` applies.
fn names_type(iri: &str, local_name: &str) -> bool {
    let local = iri.rsplit_once(['#', '/']).map_or(iri, |(_, n)| n);
    local == local_name
}

/// Which storage form a subject's `rdf:type` list names.
///
/// `types` is the subject's full type list, as IRIs.
/// `has_resident_literal` is true when the subject carries an
/// `aff4l:dataStream` whose object is a base64 literal rather than an IRI:
/// AFF4-L v1.0-ALPHA §6.2 marks in-metadata storage by that property and not
/// by a type, so it is the one form the type list alone cannot name.
///
/// # Errors
///
/// [`Error::Malformed`] when the list names no storage form, or more than one.
pub fn storage_form_of<S: AsRef<str>>(
    types: &[S],
    has_resident_literal: bool,
    locus: &Locus,
) -> Result<StorageForm> {
    storage_form_of_with_reference(types, has_resident_literal, false, locus)
}

/// As [`storage_form_of`], for a subject that may name its storage indirectly.
///
/// `has_stream_reference` is true when the subject carries an
/// `aff4l:dataStream` whose object is an **IRI**. That is the second form
/// AFF4-L v1.0-ALPHA §6.3 shows, where a file image holds no storage type of
/// its own and points at a separate map subject that does. The bytes are still
/// in a map, so the form is [`StorageForm::SharedMap`].
///
/// # Errors
///
/// As [`storage_form_of`].
pub fn storage_form_of_with_reference<S: AsRef<str>>(
    types: &[S],
    has_resident_literal: bool,
    has_stream_reference: bool,
    locus: &Locus,
) -> Result<StorageForm> {
    let declares = |name: &str| types.iter().any(|t| names_type(t.as_ref(), name));

    let mut found: Vec<StorageForm> = Vec::new();

    // Both spellings. AFF4-L 2019 §3.8 wrote `zip_segment`; AFF4-L
    // v1.0-ALPHA §6.1 writes `ZipSegment`. A reader accepts either, which
    // AFF4-L v1.0-ALPHA §4.1 permits for backwards compatibility.
    if declares("ZipSegment") || declares("zip_segment") {
        found.push(StorageForm::ZipSegment);
    }
    // A Map over its own stream and a Map over a shared one are the same
    // types and the same properties; they differ only in how many subjects
    // name the same `aff4:dependentStream`. The reader does not need to tell
    // them apart, because AFF4-L v1.0-ALPHA §6.3 gives both the same meaning,
    // so this reports `SharedMap` for either.
    if declares("Map") {
        found.push(StorageForm::SharedMap);
    }
    if declares("ImageStream") {
        found.push(StorageForm::OwnImageStream);
    }
    if has_resident_literal {
        found.push(StorageForm::InMetadata);
    }
    // The AFF4-L v1.0-ALPHA §6.3 indirect form. Counted only when no type on
    // this subject already named a form: a file image typed `Map` that also
    // points at its own map is stating one thing twice, not two things.
    if has_stream_reference && found.is_empty() {
        found.push(StorageForm::SharedMap);
    }

    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(Error::malformed(
            locus.clone(),
            "the rdf:type list names none of the storage forms AFF4-L \
             v1.0-ALPHA §6 defines, and no aff4l:dataStream literal carries \
             the bytes, so where this stream is stored is unstated",
        )),
        many => Err(Error::malformed(
            locus.clone(),
            format!(
                "the rdf:type list names {}, so where this stream is stored \
                 is ambiguous; AFF4-L v1.0-ALPHA §6 gives one form per stream",
                many.iter()
                    .map(|f| f.label())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn locus() -> Locus {
        Locus::new("/evidence/case.aff4").segment("information.turtle")
    }

    /// Full IRIs, as a parsed container carries them.
    fn types(list: &[&str]) -> Vec<String> {
        list.iter()
            .map(|n| format!("http://aff4.org/Schema#{n}"))
            .collect()
    }

    #[test]
    fn a_zip_segment_type_selects_that_form() {
        let t = types(&["FileImage", "Image", "ZipSegment"]);
        assert_eq!(
            storage_form_of(&t, false, &locus()).expect("a single storage form"),
            StorageForm::ZipSegment
        );
    }

    #[test]
    fn the_2019_spelling_selects_the_same_form() {
        let t = types(&["FileImage", "Image", "zip_segment"]);
        assert_eq!(
            storage_form_of(&t, false, &locus()).expect("a single storage form"),
            StorageForm::ZipSegment
        );
    }

    #[test]
    fn a_resident_literal_selects_in_metadata() {
        let t = types(&["FileImage", "Image"]);
        assert_eq!(
            storage_form_of(&t, true, &locus()).expect("a single storage form"),
            StorageForm::InMetadata
        );
    }

    #[test]
    fn a_map_type_selects_the_map_form() {
        let t = types(&["FileImage", "Image", "Map"]);
        assert_eq!(
            storage_form_of(&t, false, &locus()).expect("a single storage form"),
            StorageForm::SharedMap
        );
    }

    #[test]
    fn an_image_stream_type_selects_its_own_stream() {
        let t = types(&["FileImage", "Image", "ImageStream"]);
        assert_eq!(
            storage_form_of(&t, false, &locus()).expect("a single storage form"),
            StorageForm::OwnImageStream
        );
    }

    // The AFF4-L v1.0-ALPHA §6.3 form this project writes: one subject carrying
    // both Image and Map. `ContiguousImage` is not a storage form and must not
    // be counted as one.
    #[test]
    fn a_file_image_typed_as_a_map_is_not_ambiguous() {
        let t = types(&["FileImage", "Image", "Map", "ContiguousImage"]);
        assert_eq!(
            storage_form_of(&t, false, &locus()).expect("a single storage form"),
            StorageForm::SharedMap
        );
    }

    // The AFF4-L v1.0-ALPHA §6.3 indirect form: no storage type on the file
    // image itself, which instead points at a map subject.
    #[test]
    fn a_stream_reference_selects_the_map_form() {
        let t = types(&["FileImage", "Image", "ContiguousImage"]);
        assert_eq!(
            storage_form_of_with_reference(&t, false, true, &locus())
                .expect("a single storage form"),
            StorageForm::SharedMap
        );
    }

    // A subject typed `Map` that also points at a map states one thing twice.
    // Counting the reference again would make the first AFF4-L v1.0-ALPHA §6.3
    // form report as ambiguous against itself.
    #[test]
    fn a_map_type_beside_a_stream_reference_is_not_ambiguous() {
        let t = types(&["FileImage", "Image", "Map"]);
        assert_eq!(
            storage_form_of_with_reference(&t, false, true, &locus())
                .expect("a single storage form"),
            StorageForm::SharedMap
        );
    }

    #[test]
    fn two_storage_types_are_malformed() {
        let t = types(&["FileImage", "ZipSegment", "ImageStream"]);
        let err = storage_form_of(&t, false, &locus()).expect_err("two forms are refused");
        assert!(matches!(err, Error::Malformed { .. }));
        assert!(err.to_string().contains("ambiguous"), "{err}");
    }

    // A resident literal alongside a storage type is the same ambiguity: the
    // bytes would be in two places.
    #[test]
    fn a_resident_literal_beside_a_storage_type_is_malformed() {
        let t = types(&["FileImage", "ZipSegment"]);
        assert!(storage_form_of(&t, true, &locus()).is_err());
    }

    #[test]
    fn no_storage_type_at_all_is_malformed() {
        let t = types(&["FileImage", "Image"]);
        let err = storage_form_of(&t, false, &locus()).expect_err("no form is refused");
        assert!(matches!(err, Error::Malformed { .. }));
    }

    // The type list carries full IRIs, so a local-name comparison has to strip
    // the namespace. A bare local name is accepted too, since a fixture or an
    // internal caller may hold one.
    #[test]
    fn a_bare_local_name_is_recognized() {
        let t = ["ZipSegment"];
        assert_eq!(
            storage_form_of(&t, false, &locus()).expect("a single storage form"),
            StorageForm::ZipSegment
        );
    }

    // A type whose local name merely ends with a form's name is a different
    // type and must not match.
    #[test]
    fn a_similar_type_name_does_not_match() {
        let t = types(&["FileImage", "NotAZipSegment"]);
        assert!(storage_form_of(&t, false, &locus()).is_err());
    }
}
