//! A linear `aff4:hash` recorded on the volume rather than on the image.
//!
//! No AFF4 document defines a digest on a volume: v1.0a §6.1 places the linear
//! hash on the `Image`. Evimetry 3.2.6 records the image's only linear digest
//! on the `ZipVolume`, over the whole image. aff4tools reads and checks such a
//! digest but never writes one.
//!
//! No public container records one, so each test builds its own fixture: it
//! copies an aff4tools acquisition into a temp directory and, in test code,
//! appends a volume digest to the copy's turtle, the way a third-party writer
//! would. `acquire` itself is unchanged, and
//! `conformance_reports_a_volume_digest` asserts that an unmodified
//! acquisition carries no volume digest.

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::disallowed_methods)]

use std::io::Read as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

/// Acquire `bytes` as a raw image.
fn acquire_image(dir: &Path, bytes: &[u8]) -> PathBuf {
    let source = dir.join("source.raw");
    std::fs::write(&source, bytes).expect("the source image");
    let container = dir.join("image.aff4");
    run_acquire(&["--image"], &source, &container);
    container
}

/// Acquire a directory of two files as an AFF4-L.
fn acquire_logical(dir: &Path) -> PathBuf {
    let tree = dir.join("tree");
    std::fs::create_dir(&tree).expect("the tree");
    std::fs::write(tree.join("a.txt"), b"one\n").expect("a file");
    std::fs::write(tree.join("b.txt"), b"two\n").expect("a file");
    let container = dir.join("logical.aff4");
    run_acquire(&["--logical"], &tree, &container);
    container
}

fn run_acquire(mode: &[&str], source: &Path, container: &Path) {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("acquire")
        .args(mode)
        .arg(source)
        .arg("--output")
        .arg(container)
        .output()
        .expect("aff4tools ran")
        .status;
    assert!(status.success(), "acquisition must succeed");
}

/// Copy `from` to `to`, recording `aff4:hash` `"<hex>"^^aff4:SHA256` on the
/// volume.
fn add_volume_hash(from: &Path, to: &Path, hex: &str) {
    let file = std::fs::File::open(from).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a zip");
    let comment = zip.comment().to_vec();
    let volume = String::from_utf8(comment.clone()).expect("a UTF-8 comment");
    let mut members = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).expect("a member");
        let name = entry.name().expect("a UTF-8 name").into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("readable");
        members.push((name, bytes));
    }

    let (_, turtle) = members
        .iter_mut()
        .find(|(name, _)| name == "information.turtle")
        .expect("information.turtle");
    let mut text = String::from_utf8(std::mem::take(turtle)).expect("UTF-8");
    assert!(
        !text.contains("ZipVolume"),
        "the acquisition must not already describe its volume:\n{text}"
    );
    text.push_str(&format!(
        "\n<{volume}>\n        a aff4:ZipVolume ;\n        aff4:hash \"{hex}\"^^aff4:SHA256 .\n"
    ));
    *turtle = text.into_bytes();

    let out = std::fs::File::create(to).expect("the copy is created");
    // A test fixture, written to a temp path: the read-only guard scans `src/`,
    // so this cannot reach library code.
    #[allow(clippy::disallowed_types)]
    let mut writer = zip::ZipWriter::new(out);
    writer
        .set_raw_comment(comment.into_boxed_slice())
        .expect("the comment is copied");
    for (name, bytes) in &members {
        // The metadata digest covers the turtle this rewrote, so it is left
        // out rather than recorded stale.
        if name == "information.turtle.hashes" {
            continue;
        }
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file(name, options).expect("a member starts");
        std::io::Write::write_all(&mut writer, bytes).expect("written");
    }
    writer.finish().expect("the copy closes");
}

/// Run `<command> --format json`, returning the exit code and the report.
fn run_json(command: &str, path: &Path) -> (Option<i32>, serde_json::Value) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args([command, "--format", "json"])
        .arg(path)
        .output()
        .expect("aff4tools ran");
    let report = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{command} printed no JSON report ({e})\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code(), report)
}

/// The checks recorded against the volume.
fn volume_checks(report: &serde_json::Value) -> Vec<serde_json::Value> {
    report["checks"]
        .as_array()
        .expect("a checks array")
        .iter()
        .filter(|c| c["role"] == "volume")
        .cloned()
        .collect()
}

fn source_bytes() -> Vec<u8> {
    (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

#[test]
fn a_volume_digest_over_the_whole_image_matches() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let bytes = source_bytes();
    let acquired = acquire_image(dir.path(), &bytes);
    let path = dir.path().join("volume-hash.aff4");
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    add_volume_hash(&acquired, &path, &digest);

    let (code, report) = run_json("verify", &path);
    let checks = volume_checks(&report);
    assert_eq!(
        checks.len(),
        1,
        "the volume's digest is checked:\n{report:#}"
    );
    assert_eq!(checks[0]["outcome"], "Match", "{:#}", checks[0]);
    assert_eq!(checks[0]["coverage"], "WholeImage", "{:#}", checks[0]);
    assert_eq!(checks[0]["actual"], digest.as_str());
    assert_eq!(code, Some(0), "{report:#}");

    let notes = report["notes"].to_string();
    assert!(
        notes.contains("no AFF4 document defines a digest on a volume"),
        "the basis for the check must be stated: {notes}"
    );
}

#[test]
fn a_wrong_volume_digest_is_a_mismatch() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let acquired = acquire_image(dir.path(), &source_bytes());
    let path = dir.path().join("volume-hash-wrong.aff4");
    add_volume_hash(&acquired, &path, &"0".repeat(64));

    let (code, report) = run_json("verify", &path);
    let checks = volume_checks(&report);
    assert_eq!(checks.len(), 1, "{report:#}");
    assert_eq!(checks[0]["outcome"], "Mismatch", "{:#}", checks[0]);
    assert_eq!(code, Some(8), "a mismatch sets exit 8:\n{report:#}");
}

/// Two files leave no way to tell which one a volume's digest covers, so it
/// is declined with the reason, never guessed at or dropped.
#[test]
fn a_volume_digest_over_several_images_is_declined() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let acquired = acquire_logical(dir.path());
    let path = dir.path().join("logical-volume-hash.aff4");
    add_volume_hash(&acquired, &path, &"0".repeat(64));

    let (code, report) = run_json("verify", &path);
    let checks = volume_checks(&report);
    assert_eq!(
        checks.len(),
        1,
        "a declined digest is still listed:\n{report:#}"
    );
    let reason = checks[0]["outcome"]["NotVerifiable"]["reason"].to_string();
    assert!(
        reason.contains("describes 2"),
        "the reason must say why: {:#}",
        checks[0]
    );
    assert_eq!(code, Some(0), "a decline is not a finding:\n{report:#}");
}

#[test]
fn conformance_reports_a_volume_digest() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let acquired = acquire_image(dir.path(), &source_bytes());
    let path = dir.path().join("volume-hash.aff4");
    add_volume_hash(&acquired, &path, &"0".repeat(64));

    let kinds = |path: &Path| -> Vec<String> {
        let (_, report) = run_json("conformance", path);
        report["containers"][0]["deviations"]
            .as_array()
            .expect("a deviations array")
            .iter()
            .map(|d| d["kind"].as_str().unwrap_or_default().to_owned())
            .collect()
    };
    assert!(
        kinds(&path).iter().any(|k| k == "volume_digest"),
        "{:?}",
        kinds(&path)
    );
    assert!(
        !kinds(&acquired).iter().any(|k| k == "volume_digest"),
        "the unmodified acquisition records none"
    );
}
