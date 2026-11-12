//! AFF4 Standard v1.0a §6.2: a block map hash built with SHA-256.
//!
//! v1.0a §6.2 allows SHA-512 or SHA-256 for the block map hash and the map digests
//! beneath it. aff4tools writes SHA-512, so these tests rebuild an acquired
//! container with every one of those digests recomputed independently as
//! SHA-256 and recorded under SHA-256 datatypes: `aff4:SHA256` on the map and
//! the block-hash object, `aff4:blockMapHashSHA256` on the image.

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::disallowed_methods)]

use std::io::Read as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256, Sha512};

/// Acquire a small raw image with several bevies, so the block-hash input
/// spans more than one segment.
fn acquire() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let source = dir.path().join("source.raw");
    let bytes: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(&source, bytes).expect("the source image");

    let container = dir.path().join("sha512.aff4");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["acquire", "--chunks-per-bevy", "4", "--image"])
        .arg(&source)
        .arg("--output")
        .arg(&container)
        .output()
        .expect("aff4tools ran")
        .status;
    assert!(status.success(), "acquisition must succeed");
    (dir, container)
}

/// Every member, in archive order, with the archive comment.
fn members(path: &Path) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let file = std::fs::File::open(path).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a zip");
    let comment = zip.comment().to_vec();
    let members = (0..zip.len())
        .map(|i| {
            let mut entry = zip.by_index(i).expect("a member");
            let name = entry.name().expect("a UTF-8 name").into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).expect("readable");
            (name, bytes)
        })
        .collect();
    (comment, members)
}

fn member<'m>(members: &'m [(String, Vec<u8>)], name: &str) -> &'m [u8] {
    members
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, bytes)| bytes.as_slice())
        .unwrap_or_else(|| panic!("no member named {name}"))
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn sha512(bytes: &[u8]) -> Vec<u8> {
    Sha512::digest(bytes).to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The digests v1.0a §6.2 composes, under one algorithm.
struct Composition {
    block_hashes: String,
    map_point: String,
    map_idx: String,
    map_path: String,
    map: String,
    block_map: String,
}

/// Compute the v1.0a §6.2 composition over the container's own segments.
fn compose(members: &[(String, Vec<u8>)], digest: fn(&[u8]) -> Vec<u8>) -> Composition {
    let mut block_hash_names: Vec<&String> = members
        .iter()
        .map(|(n, _)| n)
        .filter(|n| n.starts_with("data/") && n.ends_with(".blockHash.sha512"))
        .collect();
    block_hash_names.sort();
    assert!(
        block_hash_names.len() > 1,
        "the image must span several bevies"
    );
    let block_hashes: Vec<u8> = block_hash_names
        .iter()
        .flat_map(|n| member(members, n).to_vec())
        .collect();

    let map = member(members, "map/map");
    let idx = member(members, "map/idx");
    let path = member(members, "map/mapPath");

    let inputs = [
        digest(&block_hashes),
        digest(map),
        digest(idx),
        digest(path),
    ];
    Composition {
        block_hashes: hex(&inputs[0]),
        map_point: hex(&inputs[1]),
        map_idx: hex(&inputs[2]),
        map_path: hex(&inputs[3]),
        map: hex(&digest(&[map, idx, path].concat())),
        block_map: hex(&digest(&inputs.concat())),
    }
}

/// Replace one recorded literal, asserting it was there exactly `count` times.
///
/// Asserted rather than attempted: a rewrite that silently did nothing would
/// leave a SHA-512 container that passes for the wrong reason.
fn replace(turtle: &mut String, old: &str, new: &str, count: usize) {
    assert_eq!(
        turtle.matches(old).count(),
        count,
        "expected {old} {count} time(s) in:\n{turtle}"
    );
    *turtle = turtle.replace(old, new);
}

/// Copy `from` with every v1.0a §6.2 digest recorded as SHA-256 instead.
///
/// `block_map` overrides the recorded block map hash, to plant a mismatch.
fn rebuild_as_sha256(from: &Path, to: &Path, block_map: Option<&str>) {
    let (comment, members) = members(from);
    let old = compose(&members, sha512);
    let new = compose(&members, sha256);
    let recorded_block_map = block_map.map_or_else(|| new.block_map.clone(), str::to_owned);

    let mut turtle =
        String::from_utf8(member(&members, "information.turtle").to_vec()).expect("UTF-8");
    for (old, new) in [
        (&old.block_hashes, &new.block_hashes),
        (&old.map_point, &new.map_point),
        (&old.map_idx, &new.map_idx),
        (&old.map_path, &new.map_path),
        (&old.map, &new.map),
        (&old.block_map, &recorded_block_map),
    ] {
        replace(
            &mut turtle,
            &format!("\"{old}\"^^aff4:SHA512"),
            &format!("\"{new}\"^^aff4:SHA256"),
            1,
        );
    }
    replace(
        &mut turtle,
        &format!("\"{}\"^^aff4:blockMapHashSHA512", old.block_map),
        &format!("\"{recorded_block_map}\"^^aff4:blockMapHashSHA256"),
        1,
    );
    assert!(
        !turtle.contains("SHA512"),
        "every SHA-512 digest must be rewritten:\n{turtle}"
    );

    let out = std::fs::File::create(to).expect("the copy is created");
    // A test fixture, written to a temp path: the read-only guard scans `src/`,
    // so this cannot reach library code.
    #[allow(clippy::disallowed_types)]
    let mut writer = zip::ZipWriter::new(out);
    // The volume ARN lives in the ZIP comment.
    writer
        .set_raw_comment(comment.into_boxed_slice())
        .expect("the comment is copied");
    for (name, bytes) in &members {
        let bytes = match name.as_str() {
            "information.turtle" => turtle.as_bytes(),
            // The metadata digest covers the turtle this rebuild rewrote, and
            // AFF4 Standard v1.0a does not define it, so it is left out
            // rather than recorded stale.
            "information.turtle.hashes" => continue,
            _ => bytes.as_slice(),
        };
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file(name, options).expect("a member starts");
        std::io::Write::write_all(&mut writer, bytes).expect("written");
    }
    writer.finish().expect("the copy closes");
}

/// Run `verify --format json`, returning the exit code and the checks.
fn verify(path: &Path) -> (Option<i32>, Vec<serde_json::Value>) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["verify", "--format", "json"])
        .arg(path)
        .output()
        .expect("aff4tools ran");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "verify printed no JSON report ({e})\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let checks = report["checks"].as_array().expect("a checks array").clone();
    (out.status.code(), checks)
}

/// The two block map hash checks: the map's copy and the image's.
fn block_map_checks(checks: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    checks
        .iter()
        .filter(|c| c["predicate"] == "blockMapHash" || c["algorithm"] == "blockMapHashSHA256")
        .collect()
}

#[test]
fn a_sha256_block_map_hash_verifies_clean() {
    let (dir, sha512) = acquire();
    let path = dir.path().join("sha256.aff4");
    rebuild_as_sha256(&sha512, &path, None);

    let (code, checks) = verify(&path);
    assert_eq!(
        code,
        Some(0),
        "an intact SHA-256 container must verify clean:\n{checks:#?}"
    );

    let block_map = block_map_checks(&checks);
    assert_eq!(
        block_map.len(),
        2,
        "the map's and the image's copies are both checked:\n{checks:#?}"
    );
    for check in block_map {
        assert_eq!(check["outcome"], "Match", "{check:#?}");
        assert_eq!(
            check["actual"].as_str().map(str::len),
            Some(64),
            "a SHA-256 is computed, not a SHA-512: {check:#?}"
        );
    }
}

#[test]
fn a_wrong_sha256_block_map_hash_is_a_mismatch() {
    let (dir, sha512) = acquire();
    let path = dir.path().join("sha256-wrong.aff4");
    let wrong = hex(&sha256(b"not this container"));
    rebuild_as_sha256(&sha512, &path, Some(&wrong));

    let (code, checks) = verify(&path);
    assert_eq!(code, Some(8), "a mismatch exits 8:\n{checks:#?}");

    let block_map = block_map_checks(&checks);
    assert_eq!(block_map.len(), 2, "{checks:#?}");
    for check in block_map {
        assert_eq!(check["outcome"], "Mismatch", "{check:#?}");
        assert_eq!(
            check["actual"].as_str().map(str::len),
            Some(64),
            "{check:#?}"
        );
    }

    // Only the planted value differs: every map digest beneath it still
    // matches, so the mismatch is attributable to the block map hash alone.
    let others_match = checks
        .iter()
        .filter(|c| c["predicate"] != "blockMapHash" && c["algorithm"] != "blockMapHashSHA256")
        .all(|c| c["outcome"] == "Match");
    assert!(others_match, "{checks:#?}");
}
