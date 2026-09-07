//! AFF4-L v1.0-ALPHA §10.1: the metadata integrity hash.
//!
//! The companion segment digests `information.turtle`, so these tests recompute
//! that digest independently and compare, rather than trusting the value the
//! writer recorded.

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::disallowed_methods)]

use std::io::Read as _;

/// Acquire a small tree, returning the container path and its temp dir.
fn acquire(extra: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let source = dir.path().join("evidence");
    std::fs::create_dir_all(&source).expect("the tree");
    std::fs::write(source.join("a.txt"), b"content\n").expect("a file");

    let container = dir.path().join("out.aff4l");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"));
    command
        .args(["acquire", "--logical"])
        .arg(&source)
        .arg("--output")
        .arg(&container);
    for arg in extra {
        command.arg(arg);
    }
    let status = command.status().expect("aff4tools ran");
    assert!(status.success(), "acquisition must succeed");
    (dir, container)
}

/// Read one member's bytes from a container.
fn member(container: &std::path::Path, name: &str) -> Vec<u8> {
    let file = std::fs::File::open(container).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a zip");
    let mut entry = zip
        .by_name(name)
        .unwrap_or_else(|_| panic!("the container has no member named {name}"));
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).expect("readable");
    bytes
}

/// The companion segment exists, and its digest is the true digest of the
/// metadata segment's bytes.
#[test]
fn the_metadata_hash_segment_matches_the_metadata() {
    let (_dir, container) = acquire(&["--aff4l-v1.0"]);

    let turtle = member(&container, "information.turtle");
    let hashes = String::from_utf8(member(&container, "information.turtle.hashes"))
        .expect("the companion segment is UTF-8");

    // Recomputed here from the stored bytes, not read from the container.
    let expected = {
        use sha2::Digest as _;
        let mut h = sha2::Sha512::new();
        h.update(&turtle);
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    assert!(
        hashes.contains(&expected),
        "the recorded SHA-512 must be the true digest of information.turtle\n\
         expected {expected}\ngot:\n{hashes}"
    );
    assert!(
        hashes.contains("information.turtle"),
        "the subject names the segment being hashed:\n{hashes}"
    );
}

/// AFF4-L v1.0-ALPHA §10.1 requires SHA-256 or stronger, so the default
/// selection must not produce a weaker-only companion segment.
#[test]
fn the_default_metadata_hash_satisfies_the_clause() {
    let (_dir, container) = acquire(&["--aff4l-v1.0"]);

    let hashes = String::from_utf8(member(&container, "information.turtle.hashes")).expect("UTF-8");
    assert!(
        hashes.contains("SHA512") || hashes.contains("SHA256"),
        "a clause-satisfying algorithm must appear:\n{hashes}"
    );
}

/// The companion segment parses as Turtle, since AFF4-L v1.0-ALPHA §10.1
/// fixes that syntax.
#[test]
fn the_metadata_hash_segment_is_well_formed_turtle() {
    let (_dir, container) = acquire(&["--aff4l-v1.0"]);
    let hashes = String::from_utf8(member(&container, "information.turtle.hashes")).expect("UTF-8");

    let mut triples = 0;
    for triple in oxttl::TurtleParser::new().for_reader(hashes.as_bytes()) {
        triple.expect("the companion segment must parse as Turtle");
        triples += 1;
    }
    assert!(
        triples >= 2,
        "one triple per default algorithm, got {triples}:\n{hashes}"
    );
}

/// The selection reaches the companion segment, not only the file digests.
#[test]
fn the_selected_algorithms_compute_the_metadata_hash() {
    let (_dir, container) = acquire(&["--aff4l-v1.0", "--hash", "sha3-512"]);
    let hashes = String::from_utf8(member(&container, "information.turtle.hashes")).expect("UTF-8");

    assert!(
        hashes.contains("SHA3-512"),
        "the chosen algorithm computes the metadata hash too:\n{hashes}"
    );
    assert!(
        !hashes.contains("SHA512\"") && !hashes.contains("^^aff4:SHA512"),
        "an algorithm that was not chosen must not appear:\n{hashes}"
    );
}

/// A legacy container carries the segment too.
///
/// AFF4-L v1.0-ALPHA §10.1 governs v2.1, but the segment is a plain integrity
/// improvement costing one small member, and no clause of the AFF4-L 2019 paper
/// or the base standard forbids an extra segment. Written for both profiles so
/// an examiner gets the same assurance whichever format they acquire.
#[test]
fn a_legacy_container_also_carries_the_segment() {
    let (_dir, container) = acquire(&["--aff4l-legacy"]);
    let hashes = String::from_utf8(member(&container, "information.turtle.hashes")).expect("UTF-8");
    assert!(
        hashes.contains("information.turtle"),
        "the subject names the segment being hashed:\n{hashes}"
    );
}

/// A tampered metadata segment is caught by its recorded digest.
///
/// The container is rebuilt rather than patched in place, because editing bytes
/// inside a ZIP breaks the member's CRC and the container would be refused
/// before the digest was ever compared — which would pass this test for the
/// wrong reason.
#[test]
fn a_tampered_metadata_segment_is_detected() {
    let (dir, good) = acquire(&["--aff4l-v1.0"]);

    let tampered = dir.path().join("tampered.aff4l");
    rebuild_with_altered_metadata(&good, &tampered);

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("verify")
        .arg(&tampered)
        .output()
        .expect("aff4tools ran");

    // Exit 8, not 5: a recomputed digest that does not match is a mismatch,
    // deliberately distinct from a container that could not be read.
    assert_eq!(
        out.status.code(),
        Some(8),
        "a metadata digest mismatch must exit 8\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An untampered container still verifies clean, so the check above is not
/// simply failing everything.
#[test]
fn an_untouched_container_still_verifies_clean() {
    let (_dir, container) = acquire(&["--aff4l-v1.0"]);

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("verify")
        .arg(&container)
        .output()
        .expect("aff4tools ran");

    assert!(
        out.status.success(),
        "an intact container must verify clean\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Copy a container, altering one byte of `information.turtle` and leaving the
/// recorded digest stale.
fn rebuild_with_altered_metadata(from: &std::path::Path, to: &std::path::Path) {
    let file = std::fs::File::open(from).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a zip");

    let out = std::fs::File::create(to).expect("the copy is created");
    // A test fixture, written to a temp path: the read-only guard scans `src/`,
    // so this cannot reach library code.
    #[allow(clippy::disallowed_types)]
    let mut writer = zip::ZipWriter::new(out);
    // The volume ARN lives in the ZIP comment; a copy without it would fail for
    // a reason unrelated to what this test is checking.
    writer
        .set_raw_comment(zip.comment().to_vec().into_boxed_slice())
        .expect("the comment is copied");

    let names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).expect("a member").name().to_owned())
        .collect();

    for name in names {
        let mut entry = zip.by_name(&name).expect("a member");
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("readable");
        if name == "information.turtle" {
            // Append a comment: still well-formed Turtle, so the container
            // parses and the recorded digest is what catches the change.
            // Asserted rather than attempted, because a tamper that silently
            // did nothing would make this test pass for the wrong reason.
            let before = bytes.len();
            bytes.extend_from_slice(b"\n# altered\n");
            assert!(bytes.len() > before, "the metadata must actually change");
        }
        let options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.start_file(&name, options).expect("a member starts");
        std::io::Write::write_all(&mut writer, &bytes).expect("written");
    }
    writer.finish().expect("the copy closes");
}
