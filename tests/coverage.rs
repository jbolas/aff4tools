//! Coverage reporting: what `conformance` could not evaluate, and how
//! `--strict` accounts for it.
#![cfg(feature = "corpus")]

use std::path::PathBuf;

use assert_cmd::Command;

/// The binary under test.
///
/// Each integration test file defines its own helpers; there is no shared
/// `common` module in this suite, and adding one for two functions would be a
/// larger change than this task needs.
fn aff4tools() -> Command {
    Command::cargo_bin("aff4tools").expect("the binary must build")
}

/// The corpus root, copied from `tests/corpus.rs` so both resolve it the same
/// way.
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

/// A v2.1 container is read, and every rule it could not check is named.
#[test]
fn a_v2_1_container_reports_its_coverage_gaps() {
    let assert = aff4tools()
        .args(["conformance"])
        .arg(v21("minimal.aff4l"))
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(out.contains("Not evaluated"), "{out}");
    assert!(
        out.contains("AFF4L_V1_ALPHA/"),
        "a rule ID must appear:\n{out}"
    );
    assert!(
        out.contains("not implemented") || out.contains("not checkable"),
        "each gap states why:\n{out}"
    );
}

/// The central claim of the phase: incomplete coverage must never read as a
/// clean result.
#[test]
fn a_v2_1_container_is_never_reported_as_conformant() {
    let assert = aff4tools()
        .args(["conformance"])
        .arg(v21("minimal.aff4l"))
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        !out.contains("No deviations. This container's metadata conforms"),
        "a container whose rules were never checked must not be called conformant:\n{out}"
    );
}

/// An unevaluated MUST fails --strict, so a script cannot mistake incomplete
/// coverage for conformance.
#[test]
fn strict_fails_on_an_unevaluated_must() {
    aff4tools()
        .args(["conformance", "--strict"])
        .arg(v21("minimal.aff4l"))
        .assert()
        .code(7);
}

/// A v1.0 container's two unevaluated rules are SHOULD-level, so --strict is
/// unaffected by them.
#[test]
fn strict_ignores_unevaluated_shoulds() {
    let path = corpus_root().join("pyaff4/test_images/AFF4Std/Base-Linear.aff4");
    let assert = aff4tools()
        .args(["conformance", "--strict"])
        .arg(&path)
        .assert();
    // Base-Linear has a routine deviation only, so --strict passes it today
    // and must keep passing it: its unevaluated rules are both SHOULD.
    assert.code(0);
}

/// The JSON envelope carries coverage too, so automation sees what the text
/// report shows.
#[test]
fn json_carries_the_coverage_block() {
    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(v21("minimal.aff4l"))
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");

    let container = &value["containers"][0];
    assert!(container["coverage"].is_array(), "{out}");
    assert!(
        !container["coverage"].as_array().unwrap().is_empty(),
        "a v2.1 container has unevaluated rules:\n{out}"
    );
}

/// The field automation reads. A script asking `conformant` is asking "was
/// this shown to conform", and a scan that never evaluated 26 of the
/// container's rules did not show that. Rendering a coverage block beside a
/// `true` would leave the one reader most likely to act without seeing the
/// prose still misled.
#[test]
fn json_conformant_is_false_while_any_rule_is_unevaluated() {
    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(v21("minimal.aff4l"))
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");

    let container = &value["containers"][0];
    assert_eq!(
        container["deviations"].as_array().map(Vec::len),
        Some(0),
        "this container has no deviations, so `conformant` turns purely on \
         coverage:\n{out}"
    );
    assert_eq!(
        container["conformant"],
        serde_json::Value::Bool(false),
        "no deviations is not the same as shown to conform:\n{out}"
    );
}

/// Each coverage entry says which rule, how binding it is, why it went
/// unchecked, and what it requires — enough for a reader to judge the gap
/// without consulting the catalog.
#[test]
fn each_coverage_entry_is_self_describing() {
    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(v21("minimal.aff4l"))
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");

    let coverage = value["containers"][0]["coverage"]
        .as_array()
        .expect("coverage is an array")
        .clone();

    for entry in &coverage {
        for field in ["rule", "requirement", "state", "statement"] {
            assert!(
                entry[field].is_string() && !entry[field].as_str().unwrap().is_empty(),
                "every entry carries a non-empty `{field}`:\n{entry}"
            );
        }
        assert_ne!(
            entry["state"], "detected",
            "a rule with a checker is not a coverage gap:\n{entry}"
        );
    }

    assert!(
        coverage
            .iter()
            .any(|entry| entry["requirement"] == "must" || entry["requirement"] == "must_not"),
        "the binding gaps are what --strict acts on:\n{out}"
    );
}

/// A v1.0 container gains a coverage block and nothing else: its deviations,
/// citations, and exit code are what they were before coverage existed.
#[test]
fn a_v1_0_container_still_reports_its_deviations() {
    let path = corpus_root().join("pyaff4/test_images/AFF4Std/Base-Linear.aff4");
    let assert = aff4tools()
        .args(["conformance"])
        .arg(&path)
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        out.contains("Deviations ("),
        "the deviation list is unchanged:\n{out}"
    );
    assert!(
        out.contains("Not evaluated"),
        "its two SHOULD-level gaps are still reported:\n{out}"
    );
}
