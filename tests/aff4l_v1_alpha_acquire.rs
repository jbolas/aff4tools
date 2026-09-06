//! Writing AFF4-L Standard v1.0-ALPHA containers with `acquire --logical`.
//!
//! The reader half of this work is exercised in `tests/coverage.rs` against
//! fixtures written by `utilities/make_v21_container.py`. These tests cover
//! the writer, and the two halves are deliberately kept apart: a container
//! this writer produced cannot prove the reader right if both share a
//! misreading of the standard.

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn aff4tools() -> Command {
    Command::cargo_bin("aff4tools").expect("the binary must build")
}

/// A small tree: one file at the top, two nested deeper.
///
/// Nesting matters. A flat set of files would pass even if the acquired tree
/// were lost, and losing the tree is the specific risk when object names stop
/// carrying paths.
fn source_tree() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(root.join("sub/deeper")).expect("the fixture tree");
    std::fs::write(root.join("notes.txt"), b"top level\n").expect("a file");
    std::fs::write(root.join("sub/a.txt"), b"nested one\n").expect("a file");
    std::fs::write(root.join("sub/deeper/b.txt"), b"nested two\n").expect("a file");
    (dir, root)
}

/// Acquire `root` into a new container beside it, returning its path.
fn acquire(root: &Path, extra: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let out = tempfile::tempdir().expect("a temp dir");
    let container = out.path().join("evidence.aff4l");
    let mut command = aff4tools();
    command
        .args(["acquire", "--logical"])
        .arg(root)
        .arg("--output")
        .arg(&container);
    for arg in extra {
        command.arg(arg);
    }
    command.assert().success();
    (out, container)
}

/// One member name from the written container, and the metadata.
fn members(path: &Path) -> Vec<String> {
    let file = std::fs::File::open(path).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a ZIP archive");
    (0..zip.len())
        .map(|i| zip.by_index(i).expect("a member").name().to_owned())
        .collect()
}

fn turtle(path: &Path) -> String {
    let file = std::fs::File::open(path).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a ZIP archive");
    let mut body = String::new();
    std::io::Read::read_to_string(
        &mut zip.by_name("information.turtle").expect("the metadata"),
        &mut body,
    )
    .expect("the metadata reads");
    body
}

fn version_text(path: &Path) -> String {
    let file = std::fs::File::open(path).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a ZIP archive");
    let mut body = String::new();
    std::io::Read::read_to_string(
        &mut zip.by_name("version.txt").expect("version.txt"),
        &mut body,
    )
    .expect("version.txt reads");
    body
}

/// The default is unchanged, and that is the point of having two flags.
///
/// A script that never names a flag must keep getting the format it has always
/// got, until the standard and its reference images settle.
#[test]
fn the_default_still_writes_the_legacy_format() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root, &[]);

    assert!(
        version_text(&container).contains("major=1\nminor=1"),
        "the default declares version 1.1"
    );
    let body = turtle(&container);
    assert!(
        body.contains("aff4:originalFileName"),
        "the legacy format records the path in originalFileName"
    );
    assert!(
        !body.contains("aff4:originalPathName"),
        "and not in the v1.0-ALPHA property"
    );
}

/// `--aff4l-legacy` selects what the absent case already selects.
///
/// It exists so a script can pin today's format across the change of default,
/// so what matters is that it produces the same container shape.
#[test]
fn the_legacy_flag_matches_the_default() {
    let (_src, root) = source_tree();
    let (_a, default) = acquire(&root, &[]);
    let (_b, explicit) = acquire(&root, &["--aff4l-legacy"]);

    assert_eq!(version_text(&default), version_text(&explicit));
    assert_eq!(members(&default).len(), members(&explicit).len());
}

/// AFF4-L v1.0-ALPHA §3: version 2.1 is major 2, minor 1.
#[test]
fn the_v1_alpha_flag_declares_version_2_1() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);

    assert!(
        version_text(&container).contains("major=2\nminor=1"),
        "got {:?}",
        version_text(&container)
    );
}

/// AFF4-L v1.0-ALPHA §2: objects are named by a lower-case GUID, and §1.2:
/// the member name keeps the scheme and identifier unescaped.
#[test]
fn v1_alpha_names_objects_by_guid_and_stores_them_literally() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);

    let stored: Vec<String> = members(&container)
        .into_iter()
        .filter(|name| name.starts_with("aff4:"))
        .collect();
    assert_eq!(stored.len(), 3, "one member per file: {stored:?}");

    for name in &stored {
        assert!(
            name.starts_with("aff4://"),
            "the member keeps its scheme and slashes: {name}"
        );
        assert!(
            !name.contains('%'),
            "nothing is percent-escaped under §1.2: {name}"
        );
        let guid = name.trim_start_matches("aff4://");
        assert_eq!(guid.len(), 36, "a GUID names it: {name}");
        assert!(
            !guid.chars().any(|c| c.is_ascii_uppercase()),
            "§2 requires lower case: {name}"
        );
    }

    // No object may be named by a path any more.
    let body = turtle(&container);
    assert!(
        !body.contains("notes.txt>"),
        "no resource name carries a suspect path:\n{body}"
    );
}

/// AFF4-L v1.0-ALPHA §1.1: the path moves into properties, both of them.
#[test]
fn v1_alpha_records_the_path_in_properties() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);
    let body = turtle(&container);

    assert!(body.contains("aff4:fileName"), "\n{body}");
    assert!(body.contains("aff4:originalPathName"), "\n{body}");
    assert!(
        !body.contains("aff4:originalFileName"),
        "the legacy property is not written alongside:\n{body}"
    );

    // The entry's own name, derived from the full path so the two agree.
    for name in ["notes.txt", "a.txt", "b.txt"] {
        assert!(
            body.contains(&format!("\"{name}\"")),
            "{name} is recorded as a file name:\n{body}"
        );
    }
    assert!(
        body.contains("sub/deeper/b.txt"),
        "the full path is recorded too:\n{body}"
    );
}

/// The output of this writer must pass `conformance` with zero deviations.
///
/// The coverage block will not be empty, and that is the honest result:
/// nothing observed departed, and rules from clauses this phase does not
/// implement were not evaluated. The two claims are kept apart.
#[test]
fn v1_alpha_output_has_no_deviations() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);

    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(&container)
        .assert();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("conformance JSON");

    let deviations = parsed["containers"][0]["deviations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(deviations.is_empty(), "expected none, got {deviations:#?}");

    assert!(
        !parsed["containers"][0]["coverage"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "unevaluated rules are still reported, so a clean list cannot imply coverage"
    );
}

/// The whole phase end to end: what this writer wrote, its own reader reads
/// back byte for byte, with the acquired tree intact.
#[test]
fn v1_alpha_output_round_trips_through_export() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);

    aff4tools()
        .args(["verify"])
        .arg(&container)
        .assert()
        .success();

    let exported = tempfile::tempdir().expect("a temp dir");
    let target = exported.path().join("out");
    aff4tools()
        .args(["export"])
        .arg(&container)
        .arg("--logical")
        .arg(&target)
        .assert()
        .success();

    // The recorded paths are absolute, so `export` rebases them beneath the
    // target. Finding each source file by its own tail is what proves the tree
    // survived rather than the exact prefix.
    for (tail, expected) in [
        ("evidence/notes.txt", "top level\n"),
        ("evidence/sub/a.txt", "nested one\n"),
        ("evidence/sub/deeper/b.txt", "nested two\n"),
    ] {
        let found = find_ending_with(&target, tail);
        let path = found.unwrap_or_else(|| panic!("{tail} must be exported beneath the target"));
        let body = std::fs::read_to_string(&path).expect("the exported file reads");
        assert_eq!(body, expected, "{tail}");
    }
}

/// The first file beneath `root` whose path ends with `tail`.
fn find_ending_with(root: &Path, tail: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.to_string_lossy().ends_with(tail) {
                return Some(path);
            }
        }
    }
    None
}

/// The two flags are mutually exclusive, so a container's format is never
/// ambiguous.
#[test]
fn the_two_profile_flags_conflict() {
    let (_src, root) = source_tree();
    let out = tempfile::tempdir().expect("a temp dir");

    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&root)
        .arg("--output")
        .arg(out.path().join("evidence.aff4l"))
        .args(["--aff4l-legacy", "--aff4l-v1.0"])
        .assert()
        .failure();
}

/// Neither flag applies to a physical acquisition, which has no AFF4-L format
/// to choose.
#[test]
fn the_profile_flags_are_refused_without_logical() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let source = dir.path().join("image.dd");
    std::fs::write(&source, vec![0u8; 4096]).expect("a source image");

    aff4tools()
        .args(["acquire", "--image"])
        .arg(&source)
        .arg("--output")
        .arg(dir.path().join("out.aff4"))
        .arg("--aff4l-v1.0")
        .assert()
        .failure();
}

/// A file too large for a ZIP segment becomes an `ImageStream`, and its bevy,
/// index, and block-hash segments all take the literal member name too.
///
/// The storage split is unchanged by this phase, which means both halves of it
/// have to keep working. A test covering only small files would pass while
/// every stream-backed file in a real acquisition was unreadable.
#[test]
fn a_stream_backed_file_round_trips_under_its_literal_name() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(&root).expect("the fixture tree");

    // Above the 1 MiB threshold, so this file is stored as an ImageStream.
    // Compressible content keeps the fixture cheap; the storage form is what
    // is under test, not the codec.
    let large: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(root.join("large.bin"), &large).expect("a large file");
    std::fs::write(root.join("small.txt"), b"small\n").expect("a small file");

    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);

    let bevy: Vec<String> = members(&container)
        .into_iter()
        .filter(|name| name.ends_with("/00000000"))
        .collect();
    assert_eq!(bevy.len(), 1, "one stream-backed file: {bevy:?}");
    assert!(
        bevy[0].starts_with("aff4://") && !bevy[0].contains('%'),
        "the stream's segments keep the literal name: {}",
        bevy[0]
    );

    aff4tools()
        .args(["verify"])
        .arg(&container)
        .assert()
        .success();

    let exported = tempfile::tempdir().expect("a temp dir");
    let target = exported.path().join("out");
    aff4tools()
        .args(["export"])
        .arg(&container)
        .arg("--logical")
        .arg(&target)
        .assert()
        .success();

    let path = find_ending_with(&target, "evidence/large.bin").expect("the large file is exported");
    assert_eq!(
        std::fs::read(&path).expect("the exported file reads"),
        large,
        "the stream-backed file must round-trip byte for byte"
    );
}

// ---------------------------------------------------------------------------
// AFF4-L v1.0-ALPHA §5: filename and path normalization.
// ---------------------------------------------------------------------------

/// AFF4-L v1.0-ALPHA §5 rule 1: an ordinary name, including a non-ASCII one, is recorded as it
/// is with no raw form.
///
/// The non-ASCII case is the one a careless reading gets wrong. Rule 2b
/// AFF4-L v1.0-ALPHA §5 rule 2b escapes bytes 0x80-0xff, which could be misread as covering every accented
/// name; it does not, because rule 2b applies only once rule 2 has triggered,
/// and a valid-UTF-8 name without control characters never triggers it.
#[test]
fn v1_alpha_leaves_a_clean_name_alone() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(&root).expect("the fixture tree");
    std::fs::write(root.join("café.txt"), b"accented\n").expect("a file");
    std::fs::write(root.join("100%.txt"), b"percent\n").expect("a file");

    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);
    let body = turtle(&container);

    assert!(body.contains("\"café.txt\""), "recorded as read:\n{body}");
    assert!(
        body.contains("\"100%.txt\""),
        "a literal percent is not an escape:\n{body}"
    );
    assert!(
        !body.contains("fileNameRaw"),
        "§5 rule 1 writes no raw form:\n{body}"
    );
}

/// AFF4-L v1.0-ALPHA §5 rule 2: a control character produces both properties, and the raw form
/// reconstructs the name exactly.
#[test]
fn v1_alpha_records_a_control_character_name_twice() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(&root).expect("the fixture tree");
    std::fs::write(root.join("ctrl\ttab.txt"), b"tabbed\n").expect("a file");

    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);
    let body = turtle(&container);

    assert!(
        body.contains("\"ctrl%09tab.txt\""),
        "the display form escapes the tab:\n{body}"
    );
    assert!(
        body.contains("fileNameRaw"),
        "and a raw form is written:\n{body}"
    );
    assert!(
        body.contains("xsd:base64Binary"),
        "typed as base64:\n{body}"
    );
}

/// The whole of AFF4-L v1.0-ALPHA §5, end to end: a name needing encoding survives acquisition
/// and export with its bytes intact.
///
/// The tab is replaced on the way out because a control character is illegal
/// in a portable filename, and that substitution is reported. What matters
/// here is that the *recorded* name is the real one, decoded from the raw
/// form, rather than the escaped display string.
#[test]
fn a_control_character_name_round_trips_through_export() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(&root).expect("the fixture tree");
    std::fs::write(root.join("ctrl\ttab.txt"), b"tabbed\n").expect("a file");
    std::fs::write(root.join("plain.txt"), b"plain\n").expect("a file");

    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);

    let exported = tempfile::tempdir().expect("a temp dir");
    let target = exported.path().join("out");
    let assert = aff4tools()
        .args(["export"])
        .arg(&container)
        .arg("--logical")
        .arg(&target)
        .assert()
        .success();
    let report = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // The alteration names the real tab, which is only possible if the raw
    // form was decoded rather than the display form used.
    assert!(
        report.contains("ctrl\\ttab.txt"),
        "the report shows the recorded name:\n{report}"
    );

    let plain = find_ending_with(&target, "evidence/plain.txt").expect("the clean file");
    assert_eq!(std::fs::read_to_string(plain).expect("reads"), "plain\n");

    let tabbed = find_ending_with(&target, "ctrl_tab.txt").expect("the encoded file");
    assert_eq!(
        std::fs::read_to_string(tabbed).expect("reads"),
        "tabbed\n",
        "content survives even where the name had to be adjusted"
    );
}

/// A container this writer produced satisfies its own AFF4-L v1.0-ALPHA §5 checkers.
#[test]
fn v1_alpha_name_output_has_no_deviations() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(&root).expect("the fixture tree");
    std::fs::write(root.join("ctrl\ttab.txt"), b"tabbed\n").expect("a file");
    std::fs::write(root.join("café.txt"), b"accented\n").expect("a file");

    let (_out, container) = acquire(&root, &["--aff4l-v1.0"]);

    let assert = aff4tools()
        .args(["conformance", "--format", "json"])
        .arg(&container)
        .assert();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("conformance JSON");
    let deviations = parsed["containers"][0]["deviations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(deviations.is_empty(), "expected none, got {deviations:#?}");
}

// ---------------------------------------------------------------------------
// AFF4-L v1.0-ALPHA §7: the .aff4l extension.
// ---------------------------------------------------------------------------

/// Acquire into `out_dir` under `name`, returning what the run printed and
/// the paths that exist afterwards.
fn acquire_to(
    name: &str,
    extra: &[&str],
) -> (tempfile::TempDir, tempfile::TempDir, String, Vec<String>) {
    let (src, root) = source_tree();
    let out = tempfile::tempdir().expect("a temp dir");
    let mut command = aff4tools();
    command
        .args(["acquire", "--logical"])
        .arg(&root)
        .arg("--output")
        .arg(out.path().join(name));
    for arg in extra {
        command.arg(arg);
    }
    let assert = command.assert().success();
    let report = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    let mut found: Vec<String> = std::fs::read_dir(out.path())
        .expect("the output dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    // The source tree is returned rather than dropped here: a `TempDir` deletes
    // its contents when it falls, and the caller may still be inspecting what
    // was acquired from it.
    (src, out, report, found)
}

/// A path already carrying the extension is used unchanged.
#[test]
fn a_v1_alpha_output_named_aff4l_is_left_alone() {
    let (_src, _out, report, found) = acquire_to("evidence.aff4l", &["--aff4l-v1.0"]);
    assert!(
        found.contains(&"evidence.aff4l".to_owned()),
        "written where asked: {found:?}"
    );
    assert!(
        !report.contains("adding the .aff4l extension"),
        "and nothing was adjusted:\n{report}"
    );
}

/// A path without the extension gains it, appended rather than substituted.
///
/// Appending is total: replacing an extension would mean guessing which part
/// of a name was meant as one, and `case.2026.11.03` has no answer.
#[test]
fn a_v1_alpha_output_gains_the_extension() {
    let (_src, _out, report, found) = acquire_to("evidence.aff4", &["--aff4l-v1.0"]);
    assert!(
        found.contains(&"evidence.aff4.aff4l".to_owned()),
        "appended, not substituted: {found:?}"
    );
    assert!(
        report.contains("adding the .aff4l extension"),
        "and the adjustment is reported:\n{report}"
    );
}

/// A path with no extension at all gains it too.
#[test]
fn a_v1_alpha_output_with_no_extension_gains_one() {
    let (_src, _out, _report, found) = acquire_to("evidence", &["--aff4l-v1.0"]);
    assert!(found.contains(&"evidence.aff4l".to_owned()), "{found:?}");
}

/// The legacy profile is left alone entirely.
///
/// AFF4-L v1.0-ALPHA §7 makes the extension a hint for the format it describes. Enforcing a
/// *negative* convention on the other format would invent a rule the standard
/// does not state.
#[test]
fn the_legacy_profile_is_not_adjusted() {
    let (_src, _out, report, found) = acquire_to("evidence.aff4l", &["--aff4l-legacy"]);
    assert!(found.contains(&"evidence.aff4l".to_owned()), "{found:?}");
    assert!(
        !report.contains("adding the .aff4l extension"),
        "no adjustment and no complaint:\n{report}"
    );
}

/// AFF4-L v1.0-ALPHA §7 is a hint, so a reader never dispatches on it.
///
/// Both mismatches must read correctly: generation comes from `version.txt`
/// and nothing else.
#[test]
fn the_extension_never_decides_how_a_container_is_read() {
    let (_src, root) = source_tree();
    let out = tempfile::tempdir().expect("a temp dir");

    // A legacy (version 1.1) container carrying the v2.1 extension.
    let mislabelled = out.path().join("legacy.aff4l");
    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&root)
        .arg("--output")
        .arg(&mislabelled)
        .arg("--aff4l-legacy")
        .assert()
        .success();

    let assert = aff4tools()
        .args(["info"])
        .arg(&mislabelled)
        .assert()
        .success();
    let out_text = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        out_text.contains("AFF4 Version: 1.1"),
        "the version line decides, not the extension:\n{out_text}"
    );
}
