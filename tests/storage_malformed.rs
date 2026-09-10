//! AFF4-L Standard v1.0-ALPHA §6 dispatch is strict.
//!
//! A subject's `rdf:type` list states where its bytes are. A list naming a form
//! whose bytes are absent, or naming two forms, is a departure from that
//! section and never an invitation to search: bytes found somewhere other than
//! where the container said would be some other stream's, and a verification
//! reported over them would be a clean result computed on the wrong data.
//!
//! Both are reported per subject rather than failing the whole container. One
//! self-contradicting object must not suppress the findings about every other
//! object, which is the rule the parser already follows for a subject that is
//! not a valid ARN.

use assert_cmd::prelude::*;
use std::path::PathBuf;
use std::process::Command;

fn aff4tools() -> Command {
    Command::cargo_bin("aff4tools").expect("the binary must build")
}

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

/// The distinct deviation kinds `conformance` reported, sorted.
fn deviation_kinds(name: &str) -> Vec<String> {
    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(v21(name))
        .assert();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("conformance JSON: {e}\n{out}"));
    let mut kinds: Vec<String> = parsed["containers"]
        .as_array()
        .map(|containers| {
            containers
                .iter()
                .flat_map(|c| c["deviations"].as_array().cloned().unwrap_or_default())
                .filter_map(|d| d["kind"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    kinds.sort();
    kinds.dedup();
    kinds
}

/// `--strict` exit code for one fixture.
fn strict_exit(name: &str) -> i32 {
    aff4tools()
        .args(["conformance", "--strict"])
        .arg(v21(name))
        .output()
        .expect("conformance runs")
        .status
        .code()
        .unwrap_or(-1)
}

// ---------------------------------------------------------------------------
// A declared form that holds no bytes.
// ---------------------------------------------------------------------------

/// Typed a ZIP segment, with no member of that name in the volume.
#[test]
fn a_declared_segment_with_no_member_is_reported() {
    assert_eq!(
        deviation_kinds("bad-missing-member.aff4l"),
        ["storage_form_not_found"]
    );
}

/// A resident literal that is not valid base64. The container states where its
/// bytes are and then does not supply them, which is the same failure as an
/// absent member.
#[test]
fn an_undecodable_resident_literal_is_reported() {
    assert_eq!(
        deviation_kinds("bad-undecodable-base64.aff4l"),
        ["storage_form_not_found"]
    );
}

// ---------------------------------------------------------------------------
// Two declared forms.
// ---------------------------------------------------------------------------

/// Typed both `ZipSegment` and `ImageStream`: the bytes are named in two
/// places, with nothing to say which is authoritative.
#[test]
fn two_storage_types_are_reported() {
    assert_eq!(
        deviation_kinds("bad-two-storage-types.aff4l"),
        ["ambiguous_storage_form"]
    );
}

/// The bytes of an ambiguous stream are not read at all, even though one of the
/// two declared forms would resolve. Reading either would produce a digest
/// result over bytes that may not be this stream's.
#[test]
fn an_ambiguous_stream_is_not_read() {
    let assert = aff4tools()
        .arg("verify")
        .arg(v21("bad-two-storage-types.aff4l"))
        .assert();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        out.contains("declares more than one storage form"),
        "verify must say why it did not read the stream:\n{out}"
    );
    assert!(
        !out.contains("file digests"),
        "no digest may be recomputed over an ambiguous stream:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// Exit codes.
// ---------------------------------------------------------------------------

/// Each of the three sets the strict exit code, so a script cannot mistake a
/// container whose bytes could not be located for a clean one.
#[test]
fn every_storage_departure_fails_strict() {
    for name in [
        "bad-missing-member.aff4l",
        "bad-undecodable-base64.aff4l",
        "bad-two-storage-types.aff4l",
    ] {
        assert_eq!(strict_exit(name), 7, "{name} must fail --strict");
    }
}

// ---------------------------------------------------------------------------
// What stays lenient.
// ---------------------------------------------------------------------------

/// The inverse direction, which is not a search and stays lenient: the bytes
/// are present in a member named exactly by the subject's ARN, and only the
/// type is missing. AFF4-L 2019 §3.8 requires that type and pyaff4's own
/// `unicode.aff4` omits it. Reported as a deviation, never as a read failure.
#[test]
fn bytes_present_with_the_type_absent_stays_a_deviation() {
    let path = corpus_root().join("pyaff4/test_images/AFF4-L/unicode.aff4");
    if !path.exists() {
        // The corpus is fetched separately; this assertion needs it.
        return;
    }
    let assert = aff4tools().arg("verify").arg(&path).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        out.contains("14 of 14 matched"),
        "every file's digest is still verified:\n{out}"
    );
}

/// A conforming container of each form reports nothing about its storage.
#[test]
fn a_conforming_storage_form_reports_no_deviation() {
    for name in [
        "storage-in-metadata.aff4l",
        "storage-zipsegment.aff4l",
        "storage-imagestream.aff4l",
        "storage-map.aff4l",
        "storage-map-indirect.aff4l",
        "storage-substreams.aff4l",
    ] {
        let kinds = deviation_kinds(name);
        assert!(
            !kinds.iter().any(|k| k.contains("storage_form")),
            "{name} must report no storage finding, got {kinds:?}"
        );
    }
}

/// A file recorded without content is not a container contradicting itself.
///
/// An acquisition that cannot read a file still records that it existed, with
/// its name, times, and mode, and stores no bytes. There is no storage form to
/// declare, so AFF4-L v1.0-ALPHA §6 has nothing to say about it.
///
/// **The omission is a completeness finding, and the acquisition already makes
/// it**: every unreadable path is listed individually with its reason in the
/// SKIPPED report, which raises the strict exit code. Reporting it again here
/// would describe an honest record of an unreadable file as a malformed one.
///
/// Not hypothetical: acquiring `/Library` on a stock macOS system produced 23
/// such records, and an earlier version of this check reported every one.
#[test]
fn a_file_recorded_without_content_is_not_a_storage_finding() {
    let kinds = deviation_kinds("storage-unreadable-record.aff4l");
    assert!(
        !kinds.iter().any(|k| k.contains("storage_form")),
        "a content-free record must raise no storage finding, got {kinds:?}"
    );
}

/// The exemption is narrow: a subject that declares a size *has* content, so a
/// declared form with no bytes behind it is still reported.
#[test]
fn the_exemption_does_not_cover_a_file_that_declares_a_size() {
    assert_eq!(
        deviation_kinds("bad-missing-member.aff4l"),
        ["storage_form_not_found"],
        "a file declaring a size and a segment must still be checked"
    );
}
