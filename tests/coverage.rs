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

// ---------------------------------------------------------------------------
// Phase 3: identity, escaping, and the rules that check them.
//
// Each fixture below is written by `utilities/make_v21_container.py`, not by
// the aff4tools writer, so a reader that encodes a misreading cannot make its
// own output pass.
// ---------------------------------------------------------------------------

/// Deviation kinds reported by a conformance run, from its JSON output.
fn deviation_kinds(path: &std::path::Path) -> Vec<String> {
    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(path)
        .assert();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("conformance JSON: {e}\n{out}"));
    // Deviations nest under the container they were found in: one run may
    // name several containers, and a kind means nothing without knowing which.
    parsed["containers"]
        .as_array()
        .map(|containers| {
            containers
                .iter()
                .flat_map(|c| c["deviations"].as_array().cloned().unwrap_or_default())
                .filter_map(|d| d["kind"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A conforming v2.1 container reports no deviation at all.
///
/// The check that matters most here is the negative one: none of the three
/// identity rules may fire on a container that satisfies them.
#[test]
fn a_conforming_v2_1_container_reports_no_deviations() {
    for name in ["conformant.aff4l", "tree.aff4l", "minimal.aff4l"] {
        let kinds = deviation_kinds(&v21(name));
        assert!(kinds.is_empty(), "{name} must be clean, got {kinds:?}");
    }
}

/// AFF4-L v1.0-ALPHA §2: a GUID is spelled in lower case.
///
/// Accepted and recorded rather than refused — the container is well formed,
/// and refusing it would decline evidence over a spelling.
#[test]
fn an_uppercase_guid_is_recorded_not_refused() {
    let kinds = deviation_kinds(&v21("uppercase-guid.aff4l"));
    assert_eq!(kinds, ["uppercase_guid_arn"]);

    aff4tools()
        .args(["info"])
        .arg(v21("uppercase-guid.aff4l"))
        .assert()
        .success();
}

/// AFF4-L v1.0-ALPHA §1.2: the scheme and identifier are not escaped into the
/// member name.
#[test]
fn an_escaped_member_name_is_reported() {
    let kinds = deviation_kinds(&v21("escaped-member.aff4l"));
    assert_eq!(kinds, ["escaped_v21_member_name"]);
}

/// AFF4-L v1.0-ALPHA §1.1: the path lives in properties once the name is a
/// GUID.
#[test]
fn a_file_recording_no_path_is_reported() {
    let kinds = deviation_kinds(&v21("nameless.aff4l"));
    assert_eq!(kinds, ["missing_recorded_path"]);
}

/// A v2.1 container's members resolve by their literal resource name, so a
/// nested acquisition exports with its tree and names intact.
///
/// This is the reader half of the phase end to end: identity, member
/// resolution, and path recovery from properties all have to be right for the
/// three files to land where they belong.
#[test]
fn a_v2_1_tree_exports_with_its_paths() {
    let out = tempfile::tempdir().expect("a temp dir");
    let target = out.path().join("exported");

    aff4tools()
        .args(["export"])
        .arg(v21("tree.aff4l"))
        .arg("--logical")
        .arg(&target)
        .assert()
        .success();

    for (relative, expected) in [
        ("case/notes.txt", "top level\n"),
        ("case/sub/a.txt", "nested one\n"),
        ("case/sub/deeper/b.txt", "nested two\n"),
    ] {
        let path = target.join(relative);
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must exist: {e}", path.display()));
        assert_eq!(body, expected, "{relative}");
    }
}

/// A v2.1 file with no recorded name is skipped and counted, never written
/// under its GUID.
///
/// A run that loses the acquired tree must not report success, so the exit
/// code carries the gap as well as the listing.
#[test]
fn an_unnamed_v2_1_file_is_skipped_rather_than_named_by_guid() {
    let out = tempfile::tempdir().expect("a temp dir");
    let target = out.path().join("exported");

    let assert = aff4tools()
        .args(["export"])
        .arg(v21("nameless.aff4l"))
        .arg("--logical")
        .arg(&target)
        .assert()
        .failure();
    let text = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(text.contains("Skipped"), "the gap is reported:\n{text}");

    let written: Vec<_> = walk(&target);
    assert!(
        written.is_empty(),
        "nothing may be written under a GUID: {written:?}"
    );
}

/// Every regular file beneath `root`, for asserting what an export produced.
fn walk(root: &std::path::Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// v1.0 and v1.1 containers keep the escaped mapping.
///
/// The invariant most at risk in this phase: `member_name` became
/// version-aware, and a regression would misresolve every member of an
/// existing container. Reading real evidence back is what proves it did not.
#[test]
fn existing_generations_still_resolve_their_members() {
    for relative in [
        "pyaff4/test_images/AFF4Std/Base-Linear.aff4",
        "pyaff4/test_images/AFF4-L/dream.aff4",
        "pyaff4/test_images/AFF4-L/unicode.aff4",
    ] {
        let path = corpus_root().join(relative);
        aff4tools().args(["verify"]).arg(&path).assert().success();
    }
}
