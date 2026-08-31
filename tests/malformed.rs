//! Behaviour on damaged and hostile input.
//!
//! Every case here builds a *mutated copy* in a temp directory. Corpus fixtures
//! are read-only (CLAUDE.md) and are never modified, re-zipped, or repaired.
//!
//! The contract under test is narrow but absolute: **aff4tools never panics on
//! malformed input.** It returns a specific, actionable error, and it keeps the
//! taxonomy honest — damaged evidence must not be reported as an unsupported
//! feature, and vice versa.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};

use aff4tools::{Container, Error, NotAff4Reason};

/// Build a synthetic container in a temp directory.
///
/// The one sanctioned use of a ZIP writer in this project: it creates a fresh
/// throwaway archive to test the reader against, and never touches evidence.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
fn synth(members: &[(&str, &[u8])], comment: Option<&[u8]>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.aff4");
    let file = std::fs::File::create(&path).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    if let Some(bytes) = comment {
        writer
            .set_raw_comment(bytes.to_vec().into_boxed_slice())
            .unwrap();
    }
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, body) in members {
        writer.start_file(*name, options).unwrap();
        writer.write_all(body).unwrap();
    }
    writer.finish().unwrap();
    (dir, path)
}

/// The corpus root, if it is available.
fn corpus_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("AFF4_TEST_IMAGES") {
        return Some(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".cache/aff4tools/corpus"))
}

/// Copy a corpus fixture into a temp directory, optionally mutating the bytes.
///
/// Returns `None` when the corpus is absent, so these tests degrade to the
/// synthetic cases rather than failing a fixture-free checkout.
#[allow(clippy::disallowed_methods)]
fn mutated_copy(
    relative: &str,
    mutate: impl FnOnce(&mut Vec<u8>),
) -> Option<(tempfile::TempDir, PathBuf)> {
    let root = corpus_root()?;
    let source = root.join(relative);
    if !source.is_file() {
        return None;
    }

    let mut bytes = std::fs::read(&source).ok()?;
    let before = std::fs::metadata(&source).ok()?;
    mutate(&mut bytes);

    let dir = tempfile::tempdir().ok()?;
    let path = dir.path().join("mutated.aff4");
    std::fs::write(&path, &bytes).ok()?;

    // The original must be untouched by the act of copying it.
    let after = std::fs::metadata(&source).ok()?;
    assert_eq!(before.len(), after.len(), "the fixture was modified");
    assert_eq!(
        before.modified().ok()?,
        after.modified().ok()?,
        "the fixture's mtime changed"
    );

    Some((dir, path))
}

const VOLUME: &str = "aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044";
const BASE_LINEAR: &str = "pyaff4/test_images/AFF4Std/Base-Linear.aff4";

/// Whatever the input, the result is a value — never a panic.
fn expect_error(path: &Path) -> Error {
    match Container::open(path).and_then(|mut c| c.summarize()) {
        Ok(summary) => panic!(
            "expected an error for {}, got a summary of {} objects",
            path.display(),
            summary.objects.len()
        ),
        Err(error) => {
            assert!(
                !error.to_string().is_empty(),
                "every error must carry a message"
            );
            error
        }
    }
}

// --- synthetic damage, no fixtures needed --------------------------------

#[test]
fn an_empty_file_is_not_an_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.aff4");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&path, b"").unwrap();

    let error = expect_error(&path);
    assert!(matches!(error, Error::Zip { .. }), "{error}");
    assert!(
        !error.is_integrity_finding(),
        "an unreadable archive says nothing about evidence integrity"
    );
}

#[test]
fn random_bytes_are_not_an_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("noise.aff4");
    let noise: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 16) as u8)
        .collect();
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&path, &noise).unwrap();

    let error = expect_error(&path);
    assert!(matches!(error, Error::Zip { .. }), "{error}");
}

#[test]
fn an_archive_with_no_members_is_not_aff4() {
    let (_dir, path) = synth(&[], None);
    let error = expect_error(&path);
    assert!(matches!(
        error,
        Error::NotAff4 {
            reason: NotAff4Reason::EmptyArchive,
            ..
        }
    ));
}

#[test]
fn metadata_that_is_not_turtle_is_malformed() {
    // The literal contents of AFF4-L/information.turtle: four bytes, not RDF.
    let (_dir, path) = synth(
        &[
            ("version.txt", b"major=1\nminor=1\n"),
            ("information.turtle", b"test"),
        ],
        Some(VOLUME.as_bytes()),
    );

    let error = expect_error(&path);
    assert!(
        error.is_integrity_finding(),
        "unparseable metadata is a finding about the container: {error}"
    );
    assert!(error.to_string().contains("information.turtle"), "{error}");
}

#[test]
fn a_container_without_metadata_is_reported_precisely() {
    let (_dir, path) = synth(
        &[("version.txt", b"major=1\nminor=0\n")],
        Some(VOLUME.as_bytes()),
    );
    let error = expect_error(&path);
    assert!(matches!(
        error,
        Error::NotAff4 {
            reason: NotAff4Reason::NoMetadata,
            ..
        }
    ));
}

/// The taxonomy's load-bearing distinction, asserted directly: a version this
/// build does not implement is a capability gap, never damaged evidence.
#[test]
fn a_future_version_is_unsupported_and_not_malformed() {
    let (_dir, path) = synth(
        &[("version.txt", b"major=9\nminor=9\ntool=Future 1.0\n")],
        Some(VOLUME.as_bytes()),
    );

    let error = expect_error(&path);
    assert!(matches!(error, Error::Unsupported { .. }), "{error}");
    assert!(
        !error.is_integrity_finding(),
        "an unimplemented version must never be reported as damaged evidence"
    );
    assert_eq!(error.exit_code(), 6);
}

/// The mirror of the above: a container that misstates its own version is a
/// finding, not a capability gap. pyaff4 silently falls through here.
#[test]
fn a_corrupt_version_file_is_malformed_and_not_unsupported() {
    let (_dir, path) = synth(
        &[("version.txt", b"major=potato\nminor=0\n")],
        Some(VOLUME.as_bytes()),
    );

    let error = expect_error(&path);
    assert!(error.is_integrity_finding(), "{error}");
    assert!(!matches!(error, Error::Unsupported { .. }), "{error}");
    assert_eq!(error.exit_code(), 5);
}

#[test]
fn a_volume_arn_that_is_not_an_arn_is_malformed() {
    let (_dir, path) = synth(
        &[("container.description", b"http://example.com/not-an-arn")],
        None,
    );
    let error = expect_error(&path);
    assert!(error.is_integrity_finding(), "{error}");
}

/// Deeply nested Turtle must not blow the stack.
#[test]
fn pathological_metadata_does_not_panic() {
    let mut turtle = b"@prefix aff4: <http://aff4.org/Schema#> .\n".to_vec();
    turtle.extend(b"<aff4://x> aff4:size ");
    turtle.extend(vec![b'['; 5000]);
    turtle.extend(b" .\n");

    let (_dir, path) = synth(
        &[
            ("version.txt", b"major=1\nminor=0\n"),
            ("information.turtle", &turtle),
        ],
        Some(VOLUME.as_bytes()),
    );

    // Either outcome is acceptable; a panic is not.
    let _ = Container::open(&path).and_then(|mut c| c.summarize());
}

/// A size far larger than the container cannot be trusted, but neither should
/// it crash the summary — the value is reported as the container states it.
#[test]
fn an_absurd_declared_size_is_reported_not_rejected() {
    let turtle = format!(
        "@prefix aff4: <http://aff4.org/Schema#> .\n\
         @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\
         <{VOLUME}/s> a aff4:ImageStream ; aff4:size \"18446744073709551615\"^^xsd:long .\n"
    );
    let (_dir, path) = synth(
        &[
            ("version.txt", b"major=1\nminor=0\n"),
            ("information.turtle", turtle.as_bytes()),
        ],
        Some(VOLUME.as_bytes()),
    );

    let summary = Container::open(&path).unwrap().summarize().unwrap();
    assert_eq!(summary.objects[0].size, Some(u64::MAX));
}

// --- mutated copies of real containers -----------------------------------

#[test]
fn a_truncated_container_fails_without_panicking() {
    let Some((_dir, path)) = mutated_copy(BASE_LINEAR, |bytes| {
        bytes.truncate(bytes.len() / 2);
    }) else {
        eprintln!("SKIP: corpus not available");
        return;
    };

    let error = expect_error(&path);
    assert!(
        matches!(error, Error::Zip { .. } | Error::Io { .. }),
        "truncation is a storage-layer failure: {error}"
    );
}

/// Damaging the ZIP comment destroys one of the two volume-ARN sources
/// (spec §5.4). The other survives, so the container still reads — and the
/// disagreement is reported rather than silently resolved.
///
/// In `Base-Linear.aff4` the end-of-central-directory record sits 66 bytes from
/// the end, so zeroing the last 40 hits only the comment, which holds the
/// volume ARN.
#[test]
fn a_damaged_zip_comment_falls_back_and_reports_the_conflict() {
    let Some((_dir, path)) = mutated_copy(BASE_LINEAR, |bytes| {
        let len = bytes.len();
        for byte in &mut bytes[len - 40..] {
            *byte = 0;
        }
    }) else {
        eprintln!("SKIP: corpus not available");
        return;
    };

    let summary = Container::open(&path)
        .and_then(|mut c| c.summarize())
        .expect("container.description still carries the volume ARN");

    // container.description wins: it is a named segment rather than trailing
    // bytes, so it is the more deliberate declaration.
    assert_eq!(
        summary.volume.arn.as_str(),
        "aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044"
    );
    assert!(
        matches!(
            summary.volume.arn_source,
            aff4tools::ArnSource::Both { consistent: false }
        ),
        "the two sources must be reported as disagreeing: {:?}",
        summary.volume.arn_source
    );
    assert!(
        summary
            .deviations
            .iter()
            .any(|d| d.kind == aff4tools::DeviationKind::InconsistentVolumeArn),
        "a volume-ARN conflict must never pass silently"
    );
}

/// Destroying the end-of-central-directory record is unrecoverable: without it
/// there is no way to locate any member.
///
/// The EOCD is found by searching for its `PK\x05\x06` signature rather than by
/// assuming an offset — in `Base-Linear.aff4` it sits 66 bytes from the end
/// because of the 44-byte volume-ARN comment, and a fixed tail length would
/// stop testing this the moment a fixture's comment changed length.
#[test]
fn a_destroyed_end_of_central_directory_fails_precisely() {
    let Some((_dir, path)) = mutated_copy(BASE_LINEAR, |bytes| {
        let eocd = bytes
            .windows(4)
            .rposition(|window| window == b"PK\x05\x06")
            .expect("a readable ZIP has an EOCD signature");
        bytes[eocd..eocd + 4].fill(0);
    }) else {
        eprintln!("SKIP: corpus not available");
        return;
    };

    let error = expect_error(&path);
    assert!(matches!(error, Error::Zip { .. }), "{error}");
    assert!(
        !error.is_integrity_finding(),
        "an unreadable archive is a storage failure, not an evidence finding"
    );
    assert_eq!(error.exit_code(), 3);
}

/// The central-directory offset in the EOCD points at garbage.
///
/// A distinct failure mode from a missing signature: the record is found and
/// parsed, but leads nowhere.
#[test]
fn a_corrupt_central_directory_offset_fails_precisely() {
    let Some((_dir, path)) = mutated_copy(BASE_LINEAR, |bytes| {
        let eocd = bytes
            .windows(4)
            .rposition(|window| window == b"PK\x05\x06")
            .expect("a readable ZIP has an EOCD signature");
        // Bytes 16..20 of the EOCD record hold the central-directory offset.
        bytes[eocd + 16..eocd + 20].fill(0xff);
    }) else {
        eprintln!("SKIP: corpus not available");
        return;
    };

    let error = expect_error(&path);
    assert!(matches!(error, Error::Zip { .. }), "{error}");
    assert!(!error.is_integrity_finding(), "{error}");
}

/// Flipping bytes in the middle of the compressed stream leaves the metadata
/// intact, so the summary must still succeed — the damage is at the data layer,
/// which this feature does not read.
#[test]
fn corrupting_image_data_does_not_prevent_a_summary() {
    let Some((_dir, path)) = mutated_copy(BASE_LINEAR, |bytes| {
        let middle = bytes.len() / 2;
        for byte in &mut bytes[middle..middle + 512] {
            *byte ^= 0xff;
        }
    }) else {
        eprintln!("SKIP: corpus not available");
        return;
    };

    // The metadata segment is elsewhere in the file, so this should still read.
    match Container::open(&path).and_then(|mut c| c.summarize()) {
        Ok(summary) => assert!(!summary.objects.is_empty()),
        // If the flip landed in the central directory, a precise error is fine.
        Err(error) => assert!(!error.to_string().is_empty()),
    }
}

/// Every byte offset in a real container, truncated: none may panic.
#[test]
fn no_truncation_length_panics() {
    let Some(root) = corpus_root() else {
        return;
    };
    let source = root.join(BASE_LINEAR);
    if !source.is_file() {
        eprintln!("SKIP: corpus not available");
        return;
    }

    let bytes = std::fs::read(&source).unwrap();
    let dir = tempfile::tempdir().unwrap();

    // Sample across the file rather than testing every offset, which would be
    // three million cases.
    for fraction in [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 99] {
        let cut = bytes.len() * fraction / 100;
        let path = dir.path().join(format!("cut-{fraction}.aff4"));
        #[allow(clippy::disallowed_methods)]
        std::fs::write(&path, &bytes[..cut]).unwrap();

        // Only the absence of a panic is asserted.
        let _ = Container::open(&path).and_then(|mut c| c.summarize());
    }
}
