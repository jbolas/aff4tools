//! Checks for AFF4-L Standard v1.0-ALPHA §6.1 and §8.
//!
//! Both clauses are judged from what the container *did* rather than what its
//! metadata says it did. The AFF4-L v1.0-ALPHA §6.1 compression method and
//! stream size are recorded only in the ZIP central directory, and the AFF4-L
//! v1.0-ALPHA §8 naming scheme is a property of the file names beside the
//! container. Neither answer exists in the RDF, which is why these checks read
//! the archive and the directory instead.
//!
//! The fixtures come from `utilities/make_v21_container.py`, written
//! independently of this project's writer.

use assert_cmd::prelude::*;
use std::path::PathBuf;
use std::process::Command;

fn aff4tools() -> Command {
    Command::cargo_bin("aff4tools").expect("the binary must build")
}

/// The corpus root, resolved as the other corpus tests resolve it.
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

/// The distinct deviation kinds `conformance` reported for one fixture, sorted.
fn deviation_kinds(path: PathBuf) -> Vec<String> {
    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(path)
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

// ---------------------------------------------------------------------------
// AFF4-L v1.0-ALPHA §6.1: how a ZIP segment storage stream is stored.
// ---------------------------------------------------------------------------

/// A method other than Stored or Deflate is reported.
///
/// The clause permits exactly those two, so a reader built to it cannot get at
/// bytes held under any other. The container is otherwise well formed and the
/// bytes are all present, which is why this is a deviation rather than a
/// refusal.
#[test]
fn a_segment_under_an_excluded_compression_method_is_reported() {
    let kinds = deviation_kinds(v21("storage-bzip2-segment.aff4l"));
    assert_eq!(
        kinds,
        ["unsupported_segment_compression"],
        "a BZIP2 member must be reported and nothing else with it"
    );
}

/// A segment storage stream with no recorded digest is reported.
///
/// The bytes are present and readable; what is missing is anything attesting to
/// what they were at acquisition.
#[test]
fn a_segment_without_a_recorded_digest_is_reported() {
    let kinds = deviation_kinds(v21("storage-unhashed-segment.aff4l"));
    assert_eq!(
        kinds,
        ["missing_zip_segment_hash"],
        "a segment recording no aff4:hash must be reported"
    );
}

/// A conforming segment raises none of the three.
///
/// The negative case matters as much as the positives: a check that fires on
/// every container reports nothing.
#[test]
fn a_conforming_segment_raises_no_section_6_1_finding() {
    let kinds = deviation_kinds(v21("storage-zipsegment.aff4l"));
    assert!(
        kinds.is_empty(),
        "a deflated segment carrying a digest conforms, got {kinds:?}"
    );
}

/// A stream whose declared member is absent is reported once, not three times.
///
/// All three AFF4-L v1.0-ALPHA §6.1 requirements are about a stream that is
/// stored. When the member is missing there is no compression method and no
/// size to judge, and the missing digest is the least of what is wrong: the
/// container's own statement about where its bytes live is already
/// contradicted, which `storage_form_not_found` says.
#[test]
fn an_absent_member_is_not_also_reported_for_its_missing_digest() {
    let kinds = deviation_kinds(v21("bad-missing-member.aff4l"));
    assert_eq!(
        kinds,
        ["storage_form_not_found"],
        "an absent member must be reported once, got {kinds:?}"
    );
}

// ---------------------------------------------------------------------------
// AFF4-L v1.0-ALPHA §8: how the parts of one set are named.
// ---------------------------------------------------------------------------

/// A set named by the older trailing-digit convention is reported.
///
/// The clause names a set `foo.aff4l`, `foo.aff4l.1`. The fixture uses
/// `evidence_1.aff4l`, `evidence_2.aff4l` instead, which is pyaff4's
/// convention and the one this scheme was written to replace.
#[test]
fn a_set_named_outside_the_scheme_is_reported() {
    let path = corpus_root()
        .join("aff4tools-v2.1")
        .join("section8-set")
        .join("evidence_1.aff4l");
    let kinds = deviation_kinds(path);
    assert_eq!(
        kinds,
        ["multi_part_naming_scheme"],
        "a misnamed set must be reported"
    );
}

/// A lone container is a conformant set of one.
///
/// The clause is about how a set's names relate to each other, so a single file
/// cannot depart from it however it is named. Without this rule the check would
/// fire on every container that is not part of a set, which is nearly all of
/// them.
#[test]
fn a_lone_container_is_not_a_misnamed_set() {
    let kinds = deviation_kinds(v21("minimal.aff4l"));
    assert!(
        !kinds.iter().any(|k| k == "multi_part_naming_scheme"),
        "a lone container is a set of one, got {kinds:?}"
    );
}

/// Unrelated containers sharing a directory are not read as one set.
///
/// The fixture directory holds more than thirty containers with unrelated
/// names. Treating a shared directory as a shared set would report every one of
/// them, which is the failure mode this check has to avoid to be worth having.
#[test]
fn unrelated_containers_in_one_directory_are_not_a_set() {
    for name in [
        "conformant.aff4l",
        "tree.aff4l",
        "storage-zipsegment.aff4l",
        "storage-map.aff4l",
    ] {
        let kinds = deviation_kinds(v21(name));
        assert!(
            !kinds.iter().any(|k| k == "multi_part_naming_scheme"),
            "{name} shares a directory with unrelated containers, not a set; got {kinds:?}"
        );
    }
}
