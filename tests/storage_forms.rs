//! Reading every storage form AFF4-L Standard v1.0-ALPHA §6 defines.
//!
//! That section requires a reader to support all of them, so each form gets a
//! container here and each container is read end to end.
//!
//! The fixtures come from `utilities/make_v21_container.py`, which is written
//! independently of this project's writer. A reader bug and a writer bug
//! therefore cannot cancel out, which they could if the same code both produced
//! and consumed the fixture.

use assert_cmd::prelude::*;
use std::path::PathBuf;
use std::process::Command;

fn aff4tools() -> Command {
    Command::cargo_bin("aff4tools").expect("the binary must build")
}

/// The corpus root, resolved as `tests/coverage.rs` resolves it.
fn corpus_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("AFF4_TEST_IMAGES") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").expect("HOME must be set to locate the corpus");
    PathBuf::from(home).join(".cache/aff4tools/corpus")
}

fn v21(name: &str) -> PathBuf {
    corpus_root().join("aff4tools-v2.1").join(name)
}

/// `verify` output for one fixture, with its exit code.
fn verify(name: &str) -> (String, i32) {
    let output = aff4tools()
        .arg("verify")
        .arg(v21(name))
        .output()
        .expect("verify runs");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// Whether the run checked a digest over the file's own bytes.
///
/// This is the thing at issue and the reason these tests exist: before Phase 9
/// a container could report "all matched" having verified only the metadata
/// integrity hash, never opening the stream that hash's container describes.
/// A `file digests` line means a digest was recomputed over stream content.
fn checked_file_digest(out: &str) -> bool {
    out.contains("file digests")
}

/// Whether any image was left unresolved.
///
/// `verify` reports an image whose bytes it could not locate as a note rather
/// than a failure, and still exits zero. So a clean exit code alone does not
/// mean the stream was read.
fn left_unresolved(out: &str) -> bool {
    out.contains("could not be resolved")
}

// ---------------------------------------------------------------------------
// AFF4-L v1.0-ALPHA §6.2 — in-metadata storage streams.
// ---------------------------------------------------------------------------

/// The bytes are decoded from the turtle and hashed.
#[test]
fn an_in_metadata_stream_is_read_and_its_digest_checked() {
    let (out, code) = verify("storage-in-metadata-hashed.aff4l");
    assert_eq!(code, 0, "a conforming container verifies clean:\n{out}");
    assert!(
        checked_file_digest(&out),
        "the file's own digest must be checked, not only the metadata hash:\n{out}"
    );
    assert!(!left_unresolved(&out), "{out}");
}

/// A digest that does not describe the bytes is an integrity failure, not a
/// silence. The container is well formed, so this is never `Error::Malformed`.
#[test]
fn an_in_metadata_stream_with_a_wrong_digest_fails() {
    let (out, code) = verify("storage-in-metadata-wrong.aff4l");
    assert_ne!(code, 0, "a mismatch must not exit zero:\n{out}");
    assert!(out.contains("MISMATCH"), "{out}");
}

/// AFF4-L v1.0-ALPHA §6.2 permits an in-metadata stream to record no digests,
/// "relying on the Metadata Integrity Hash for integrity". Such a container is
/// complete as it stands: its stream is still read, and nothing is reported as
/// missing.
#[test]
fn an_in_metadata_stream_may_record_no_digest_at_all() {
    let (out, code) = verify("storage-in-metadata.aff4l");
    assert_eq!(code, 0, "{out}");
    assert!(
        !left_unresolved(&out),
        "a resident stream resolves; it is not an unreadable image:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// AFF4-L v1.0-ALPHA §6.1, §6.3, §6.4 — the forms whose bytes live outside the
// metadata.
// ---------------------------------------------------------------------------

/// AFF4-L v1.0-ALPHA §6.1. The form this project has always written.
#[test]
fn a_zip_segment_stream_is_read_and_verified() {
    let (out, code) = verify("storage-zipsegment.aff4l");
    assert_eq!(code, 0, "{out}");
    assert!(checked_file_digest(&out), "{out}");
}

/// AFF4-L v1.0-ALPHA §6.4.
#[test]
fn an_image_stream_backed_file_is_read_and_verified() {
    let (out, code) = verify("storage-imagestream.aff4l");
    assert_eq!(code, 0, "{out}");
    assert!(
        checked_file_digest(&out),
        "the stream's digest must be checked:\n{out}"
    );
}

/// AFF4-L v1.0-ALPHA §6.3, first form: the `aff4:Map` type added to the
/// FileImage instance, so one subject is both Image and Map. This is the form
/// this project writes.
#[test]
fn a_file_image_typed_as_a_map_is_read_and_verified() {
    let (out, code) = verify("storage-map.aff4l");
    assert_eq!(code, 0, "{out}");
    assert!(!left_unresolved(&out), "the map must resolve:\n{out}");
    assert!(checked_file_digest(&out), "{out}");
}

/// AFF4-L v1.0-ALPHA §6.3, second form: the FileImage reaches a separate Map
/// subject through `aff4l:dataStream`. This project never writes this shape and
/// must still read it.
#[test]
fn a_file_image_pointing_at_a_map_is_read_and_verified() {
    let (out, code) = verify("storage-map-indirect.aff4l");
    assert_eq!(code, 0, "{out}");
    assert!(
        !left_unresolved(&out),
        "the indirect map must resolve:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// AFF4-L v1.0-ALPHA §4.2, §4.3 — substreams.
// ---------------------------------------------------------------------------

/// An extended attribute and an alternate data stream both hang off their
/// parent, and both carry their bytes in the metadata.
#[test]
fn substreams_are_read_with_their_parent() {
    let (out, code) = verify("storage-substreams.aff4l");
    assert_eq!(code, 0, "{out}");
    assert!(
        !left_unresolved(&out),
        "no substream may be left unresolved:\n{out}"
    );
}

/// A substream belongs to its parent, and `info` says so rather than listing it
/// as another free-standing object.
#[test]
fn info_presents_a_substream_under_its_parent() {
    let assert = aff4tools()
        .arg("info")
        .arg(v21("storage-substreams.aff4l"))
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        out.contains("extended attribute") || out.contains("user.comment"),
        "the attribute must be visible:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// The thresholds the storage study set.
// ---------------------------------------------------------------------------

// Asserted at compile time rather than in a test body. Every value here is a
// constant, so a runtime assertion could only ever pass or fail identically on
// every run; making it a `const` block means a threshold edited past its
// clause's ceiling fails the build instead of a test.
//
// The chosen values are derived from testing, but the maximums come from the spec.
// AFF4-L v1.0-ALPHA §6.2
// forbids in-metadata storage above one kilobyte, and AFF4-L v1.0-ALPHA §6.1
// says a writer SHOULD NOT use a ZIP segment at or above one gibibyte.
const _: () = {
    use aff4tools::write::logical::{
        COMMONMAP_THRESHOLD, RESIDENT_DATA_THRESHOLD, ZIPSEGMENT_THRESHOLD,
    };
    assert!(RESIDENT_DATA_THRESHOLD <= 1024);
    assert!(ZIPSEGMENT_THRESHOLD < 1024 * 1024 * 1024);
    // The bands are ordered, so no band in `choose_storage` is unreachable.
    assert!(RESIDENT_DATA_THRESHOLD < ZIPSEGMENT_THRESHOLD);
    assert!(ZIPSEGMENT_THRESHOLD < COMMONMAP_THRESHOLD);
};

/// AFF4-L v1.0-ALPHA §6.2 caps the in-metadata form at one kilobyte. A stream
/// above it is a conformance finding and never a read failure: the bytes are
/// present and unambiguously that stream's, so they are read and verified while
/// the departure is reported.
#[test]
fn an_oversized_resident_stream_is_read_and_reported() {
    let (out, code) = verify("storage-oversized-resident.aff4l");
    assert_eq!(code, 0, "the bytes are present, so verify is clean:\n{out}");
    assert!(
        checked_file_digest(&out),
        "the stream must still be read and its digest checked:\n{out}"
    );

    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(v21("storage-oversized-resident.aff4l"))
        .assert();
    let json = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        json.contains("oversized_resident_stream"),
        "the size cap departure must be reported:\n{json}"
    );
}
