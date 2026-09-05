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
