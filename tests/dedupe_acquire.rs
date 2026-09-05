//! Phase 6: deduplicated logical writing, per AFF4-L 2019 §4.
//!
//! > Schatz, B.L. *AFF4-L: A Scalable Open Logical Evidence Container.*
//! > Digital Investigation 29, S143-S149. DFRWS USA 2019.
//!
//! **Every bare section number below cites that paper**, not the AFF4
//! Standard. This file cites no other document.
//!
//! The property that matters is not that the container is smaller — that is
//! easy and unfalsifiable on its own. It is that **every file still reads back
//! byte-for-byte** after its bytes have been dissolved into a shared pool and
//! reassembled from content-addressed references. A dedupe writer that loses a
//! byte produces a container that looks fine and is evidence of nothing.
//!
//! These containers deliberately do **not** reach zero deviations: §4's
//! `aff4:sha512:` subjects and `[0x0:0x8000]` slice ARNs are extensions, and
//! `conformance` reports both.

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::disallowed_methods)]

use std::io::Write as _;
use std::path::Path;

use aff4tools::verify::{VerifyOptions, verify_container};
use aff4tools::write::container_writer::ContainerWriter;
use aff4tools::write::guard::SourceRegistry;
use aff4tools::write::logical::{LogicalOptions, acquire_logical};
use aff4tools::{Container, Locus};

fn write_file(path: &Path, body: &[u8]) {
    #[allow(clippy::disallowed_methods)]
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body).unwrap();
}

/// Deterministic, poorly-compressible bytes, so savings come from dedupe rather
/// than from the codec.
fn pseudorandom(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u8::try_from(state & 0xff).unwrap_or(0)
        })
        .collect()
}

/// Acquire `tree` with deduplication on, returning the container path.
fn acquire_deduped(dir: &Path, tree: &Path) -> std::path::PathBuf {
    let out = dir.join("dedupe.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(tree).unwrap();

    let options = LogicalOptions {
        deduplicate: true,
        ..LogicalOptions::default()
    };

    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree.to_path_buf()),
        options,
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert!(
        acquired.skipped.is_empty(),
        "nothing should be skipped: {:?}",
        acquired.skipped
    );
    assert!(
        acquired.dedupe.is_some(),
        "a deduplicated acquisition must report what it saved"
    );
    out
}

/// Identical files must be stored once, and the saving must be real.
#[test]
fn identical_files_are_stored_only_once() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // Three copies of the same content, chunk-aligned so they dedupe exactly.
    let body = pseudorandom(64 * 1024, 0x1234);
    for name in ["a.bin", "b.bin", "c.bin"] {
        write_file(&tree.join(name), &body);
    }

    let out = dir.path().join("dedupe.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions {
            deduplicate: true,
            ..LogicalOptions::default()
        },
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    let dedupe = acquired.dedupe.unwrap();
    assert_eq!(
        dedupe.presented,
        3 * 64 * 1024,
        "three files' worth was presented"
    );
    assert_eq!(
        dedupe.stored,
        64 * 1024,
        "but only one file's worth was stored"
    );
    assert_eq!(dedupe.saved(), 2 * 64 * 1024);
    assert_eq!(dedupe.unique_chunks, 2, "64 KiB at 32 KiB chunks");
}

/// **The property that matters.** Every deduplicated file must read back
/// byte-for-byte, reassembled from the shared pool.
#[test]
fn deduplicated_files_read_back_byte_identically() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // A mix that exercises the hard cases: shared content, unique content, a
    // file whose length is not a chunk multiple (so its tail is NUL-padded in
    // the pool and must be trimmed on read), and a file smaller than a chunk.
    let shared = pseudorandom(96 * 1024, 0xAAAA);
    let mut overlapping = shared.clone();
    overlapping.extend_from_slice(&pseudorandom(5000, 0xBBBB));

    let files: Vec<(&str, Vec<u8>)> = vec![
        ("shared_a.bin", shared.clone()),
        ("shared_b.bin", shared.clone()),
        ("overlapping.bin", overlapping),
        ("unique.bin", pseudorandom(40_000, 0xCCCC)),
        ("tiny.txt", b"just a few bytes\n".to_vec()),
        ("empty.txt", Vec::new()),
    ];
    for (name, body) in &files {
        write_file(&tree.join(name), body);
    }

    let out = acquire_deduped(dir.path(), &tree);
    let locus = Locus::new(&out);
    let mut container = Container::open(&out).unwrap();

    for (name, expected) in &files {
        let summary = container.summarize().unwrap();
        let arn = summary
            .objects
            .iter()
            .find(|o| o.arn.as_str().ends_with(name))
            .unwrap_or_else(|| panic!("{name} must be described"))
            .arn
            .clone();

        // An empty file has no chunks and so no map to read; its digests still
        // describe it, which the verify test covers.
        if expected.is_empty() {
            continue;
        }

        let lexicon = container.lexicon();
        let image = aff4tools::Image::open_in_set(&arn, container.volumes_mut(), lexicon, &locus)
            .unwrap_or_else(|e| panic!("{name} must resolve through its map: {e}"));

        let mut back = Vec::new();
        image
            .read_from_set(
                container.volumes_mut(),
                &mut |bytes: &[u8]| {
                    back.extend_from_slice(bytes);
                    Ok(())
                },
                &locus,
            )
            .unwrap_or_else(|e| panic!("{name} must read: {e}"));

        assert_eq!(back.len(), expected.len(), "{name}: length must match");
        assert!(
            back == *expected,
            "{name}: deduplicated content must reproduce the source exactly"
        );
    }
}

/// Every recorded digest must be recomputable from the deduplicated storage.
///
/// This is gate 1 for the dedupe path: the hashes were computed over the file's
/// true bytes as they streamed into the pool, and verifying them means
/// reassembling each file from content-addressed chunks and getting the same
/// values back.
#[test]
fn a_deduplicated_container_verifies_clean() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    let body = pseudorandom(70_000, 0x5EED);
    write_file(&tree.join("one.bin"), &body);
    write_file(&tree.join("two.bin"), &body);
    write_file(&tree.join("three.bin"), &pseudorandom(12_345, 0xF00D));

    let out = acquire_deduped(dir.path(), &tree);
    let mut container = Container::open(&out).unwrap();
    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    assert!(
        !report.has_mismatch(),
        "a deduplicated container must verify clean: {:#?}",
        report
            .checks
            .iter()
            .filter(|c| c.outcome.is_mismatch())
            .collect::<Vec<_>>()
    );
    assert!(
        report.match_count() >= 6,
        "three files x two hashes must all be recomputed, got {}",
        report.match_count()
    );
}

/// Digests recorded for a deduplicated file must be the file's own — the same
/// values a non-deduplicated acquisition records, and the same values `sha1sum`
/// reports of the original.
///
/// The NUL padding §4 applies to short final chunks is inside the *pool*, never
/// inside the file's hash; getting this wrong would produce digests that agree
/// with nothing outside this tool.
#[test]
fn recorded_digests_are_of_the_true_file_not_the_padded_chunks() {
    use md5::Digest as _;

    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // Deliberately not a chunk multiple, so the tail is padded in the pool.
    let body = pseudorandom(1000, 0x99);
    write_file(&tree.join("odd.bin"), &body);

    let expected_md5 = format!("{:x}", md5::Md5::digest(&body));
    let expected_sha1 = format!("{:x}", sha1::Sha1::digest(&body));

    let out = acquire_deduped(dir.path(), &tree);
    let turtle = {
        let file = std::fs::File::open(&out).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        let mut buf = String::new();
        use std::io::Read as _;
        zip.by_name("information.turtle")
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        buf
    };

    assert!(
        turtle.contains(&expected_md5),
        "the recorded MD5 must be the true file's {expected_md5}:\n{turtle}"
    );
    assert!(
        turtle.contains(&expected_sha1),
        "the recorded SHA1 must be the true file's {expected_sha1}:\n{turtle}"
    );
    // And the size must be the true length, not the padded chunk length.
    assert!(
        turtle.contains("1000"),
        "the recorded size must be the true 1000 bytes, not a padded 32768:\n{turtle}"
    );
}

/// **Scaling regression.** A file's `idx` must list only its own chunks.
///
/// Carrying the acquisition-wide target list in every file's `idx` costs
/// N files × N targets. Measured at 10,000 files that produces a 14.2 GB
/// container for 101 MiB of evidence — 129× larger than the same tree stored
/// without deduplication, and ~564 TB extrapolated to 2 million files.
///
/// Asserted by growing the file count and checking that per-file `idx` size
/// does **not** grow with it. A count-based assertion rather than a size
/// threshold: the defect was asymptotic, so what matters is the shape.
#[test]
fn a_files_idx_lists_only_its_own_chunks() {
    fn idx_sizes(file_count: usize) -> (u64, u64) {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        // Distinct content per file, so every file contributes a unique chunk
        // and the acquisition-wide target list really does grow.
        for i in 0..file_count {
            write_file(
                &tree.join(format!("f{i}.bin")),
                &pseudorandom(4096, 1000 + i as u64),
            );
        }

        let out = acquire_deduped(dir.path(), &tree);
        let file = std::fs::File::open(&out).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        let mut total = 0u64;
        let mut count = 0u64;
        for i in 0..zip.len() {
            let m = zip.by_index(i).unwrap();
            if m.name().ends_with("/idx") {
                total += m.size();
                count += 1;
            }
        }
        assert!(count > 0, "the container must hold idx segments");
        (total / count, count)
    }

    let (small, n_small) = idx_sizes(4);
    let (large, n_large) = idx_sizes(32);

    assert_eq!(n_small, 4, "one idx per file");
    assert_eq!(n_large, 32, "one idx per file");

    // Each 4 KiB file uses exactly one chunk, so its idx is one ARN line
    // whatever the acquisition holds. Allowing 2x slack for incidental
    // variation; the defect made this grow 8x between these two sizes.
    assert!(
        large <= small * 2,
        "per-file idx must not grow with the acquisition: {small} bytes at 4 \
         files became {large} bytes at 32 — the idx is carrying other files' \
         chunks"
    );
}

/// §4's two constructs must both appear, in the corpus's spelling.
#[test]
fn the_container_carries_block_hash_arns_and_slice_maps() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_file(&tree.join("x.bin"), &pseudorandom(40_000, 7));

    let out = acquire_deduped(dir.path(), &tree);
    let file = std::fs::File::open(&out).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let mut turtle = String::new();
    use std::io::Read as _;
    zip.by_name("information.turtle")
        .unwrap()
        .read_to_string(&mut turtle)
        .unwrap();

    assert!(
        turtle.contains("aff4:sha512:"),
        "Block Hash ARNs must be present:\n{turtle}"
    );
    assert!(
        turtle.contains("[0x0:0x8000]"),
        "a Slice Map naming the first chunk must be present:\n{turtle}"
    );
    // The file must be map-backed: `FileImage, Image, Map`, as broken-dedupe is.
    assert!(
        turtle.contains("aff4:Map"),
        "a deduplicated file is assembled by a Map:\n{turtle}"
    );
}

/// Deduplication is **off** unless asked for.
///
/// A default acquisition must produce ordinary per-file storage — no shared
/// pool, no content-addressed subjects, and therefore no deviations.
#[test]
fn deduplication_is_off_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let body = pseudorandom(50_000, 3);
    write_file(&tree.join("a.bin"), &body);
    write_file(&tree.join("b.bin"), &body);

    let out = dir.path().join("plain.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert!(
        acquired.dedupe.is_none(),
        "the default acquisition must not deduplicate"
    );

    let mut container = Container::open(&out).unwrap();
    let summary = container.summarize().unwrap();
    assert!(
        summary.deviations.is_empty(),
        "a non-deduplicated container must still reach zero deviations: {:#?}",
        summary.deviations
    );
}

/// A deduplicated container reports exactly the two expected deviations.
///
/// Pinned so the count cannot drift silently: §4's syntax is an extension, and
/// `conformance` must keep saying so rather than quietly accepting it.
#[test]
fn deduplication_reports_its_two_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_file(&tree.join("x.bin"), &pseudorandom(40_000, 11));

    let out = acquire_deduped(dir.path(), &tree);
    let mut container = Container::open(&out).unwrap();
    let summary = container.summarize().unwrap();

    let kinds: Vec<String> = summary
        .deviations
        .iter()
        .map(|d| format!("{:?}", d.kind))
        .collect();
    assert_eq!(
        summary.deviations.len(),
        2,
        "exactly the two §4 extensions, no more: {kinds:?}"
    );
    assert!(
        kinds.iter().any(|k| k.contains("ByteRangeArn")),
        "the slice ARN extension must be reported: {kinds:?}"
    );
    assert!(
        kinds.iter().any(|k| k.contains("ContentAddressedSubject")),
        "the content-addressed subject extension must be reported: {kinds:?}"
    );
}
