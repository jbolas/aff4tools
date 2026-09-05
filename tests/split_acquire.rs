//! Split-file output: one image written across several `.aff4` parts.
//!
//! A *part* is one file of a split set; a *segment* is a member inside a
//! volume (`docs/glossary.md`).

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use aff4tools::write::guard::SourceRegistry;
use aff4tools::write::split_writer::{SplitOptions, part_path, preflight, write_split_set};
use aff4tools::write::stream_writer::StreamOptions;
use aff4tools::{Codec, HashAlgorithm, Locus};

/// Incompressible, so a threshold in compressed bytes is reached predictably.
fn incompressible(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn options(split_after: u64) -> SplitOptions {
    SplitOptions {
        stream: StreamOptions {
            chunk_size: 32 * 1024,
            chunks_per_segment: 2,
            codec: Codec::Stored,
            block_hashes: true,
        },
        split_after,
    }
}

#[test]
fn part_paths_are_zero_padded_to_three_digits() {
    let base = Path::new("/tmp/evidence.aff4");
    assert_eq!(part_path(base, 1), Path::new("/tmp/evidence_001.aff4"));
    assert_eq!(part_path(base, 42), Path::new("/tmp/evidence_042.aff4"));
    assert_eq!(part_path(base, 999), Path::new("/tmp/evidence_999.aff4"));
}

#[test]
fn a_source_needing_more_than_999_parts_is_refused_up_front() {
    // 1 TB at 1 GiB is 1024 parts.
    let err = preflight(1_099_511_627_776, 1 << 30, &Locus::new("x")).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("999"), "{text}");
    assert!(text.contains("--split-file"), "must name the fix: {text}");
}

#[test]
fn a_source_fitting_within_999_parts_is_accepted() {
    preflight(16 * (1 << 30), 1 << 30, &Locus::new("x")).unwrap();
}

#[test]
fn a_split_set_is_written_as_several_parts() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let data = incompressible(768 * 1024);
    let registry = SourceRegistry::new();
    let mut src = &data[..];

    let set = write_split_set(
        &output,
        &mut src,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();

    assert!(set.parts.len() > 1, "expected several parts");
    assert_eq!(set.total_size, data.len() as u64);
    assert!(!output.exists(), "the base name itself must not be written");
    for (i, part) in set.parts.iter().enumerate() {
        let expected = part_path(&output, u32::try_from(i + 1).unwrap());
        assert_eq!(part.path, expected);
        assert!(part.path.is_file());
    }
    // Every part shares one DiskImage: v1.0a §7.1's point of commonality.
    assert!(set.image_arn.starts_with("aff4://"));
    assert_eq!(set.digests.len(), 2);
}

#[test]
fn every_part_but_the_first_carries_only_a_stub() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let data = incompressible(768 * 1024);
    let registry = SourceRegistry::new();
    let mut src = &data[..];

    let set = write_split_set(
        &output,
        &mut src,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 2, "need at least three parts");

    // `zip::Volume` is a TRAIT, not a type: the concrete type is `ZipVolume`,
    // and `read_segment` needs `&mut self`. This is the idiom `src/zip.rs`'s
    // own tests use.
    let turtle_of = |p: &Path| -> String {
        let mut volume = aff4tools::zip::ZipVolume::open(p).unwrap();
        String::from_utf8(
            aff4tools::zip::Volume::read_segment(&mut volume, "information.turtle").unwrap(),
        )
        .unwrap()
    };

    let first = turtle_of(&set.parts[0].path);
    assert!(first.contains("aff4:Map"), "part 001 holds the map");
    assert!(first.contains("aff4:DiskImage"), "part 001 holds the image");
    assert!(
        first.contains("dependentStream"),
        "part 001 lists every stream"
    );

    for part in &set.parts[1..] {
        let stub = turtle_of(&part.path);
        assert!(
            stub.contains("aff4:ImageStream"),
            "spec line 142: MUST declare its stream"
        );
        assert!(
            stub.contains("chunkSize"),
            "spec line 154: MUST carry chunkSize"
        );
        assert!(
            stub.contains(&set.image_arn),
            "§7.1: names the shared DiskImage"
        );
        // The map's two-triple declaration (type + `aff4:stored`) is required
        // so this part's `aff4:target` resolves — see
        // `cross_part_references_resolve`. What a stub must not repeat is the
        // map's full DESCRIPTION, which is these two predicates' absence.
        assert!(
            !stub.contains("mapGapDefaultStream"),
            "a stub must not repeat the map's description"
        );
        assert!(
            !stub.contains("aff4:size                       \"786432\""),
            "a stub must not repeat the map's size"
        );
        assert!(
            !stub.contains("dependentStream"),
            "a stub must not repeat the stream list"
        );
        assert!(
            stub.len() < 2000,
            "a stub must stay small, was {}",
            stub.len()
        );
    }
}

/// Every cross-part reference must name an object the part also declares,
/// with `aff4:stored` saying which volume holds it. Without that a reader —
/// and `conformance` — cannot resolve the reference.
#[test]
fn cross_part_references_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("ev.aff4");
    let data = incompressible(768 * 1024);
    let registry = SourceRegistry::new();
    let mut src = &data[..];

    let set = write_split_set(
        &output,
        &mut src,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 2, "need at least three parts");

    let turtle_of = |p: &Path| -> String {
        let mut volume = aff4tools::zip::ZipVolume::open(p).unwrap();
        String::from_utf8(
            aff4tools::zip::Volume::read_segment(&mut volume, "information.turtle").unwrap(),
        )
        .unwrap()
    };

    // A mention is not a declaration. `dependentStream` and `aff4:target`
    // already carry these ARNs as references, so the assertions below look for
    // the ARN in SUBJECT position — a block of its own — which is what the
    // dangling-reference check in `src/container.rs` actually requires.
    let declares = |turtle: &str, arn: &str| -> bool {
        turtle
            .split("\n\n")
            .any(|block| block.trim_start().starts_with(&format!("<{arn}>")))
    };

    // Part 001 declares every foreign stream it depends on.
    let first = turtle_of(&set.parts[0].path);
    for part in &set.parts[1..] {
        assert!(
            declares(&first, &part.stream_arn),
            "part 001 names {} in dependentStream but must also declare it",
            part.stream_arn
        );
        assert!(
            first.contains(&part.volume_arn),
            "part 001 must say which volume holds {}",
            part.stream_arn
        );
    }

    // Each later part declares the map it targets, and where that map lives.
    for part in &set.parts[1..] {
        let stub = turtle_of(&part.path);
        assert!(
            declares(&stub, &set.map_arn),
            "a stub must declare the map it targets, not merely name it"
        );
        assert!(
            stub.contains(&set.parts[0].volume_arn),
            "a stub must say which volume holds the map"
        );
        // Still a stub, not a copy of the full graph.
        assert!(
            !stub.contains("dependentStream"),
            "a stub must not repeat the stream list"
        );
        assert!(
            stub.len() < 2500,
            "a stub must stay small, was {}",
            stub.len()
        );
    }
}

/// The guarantee: **the digests of the stored data do not depend on how the
/// image is divided across files.**
///
/// Covers the image digest and every block hash. `blockMapHash` is excluded by
/// construction — v1.0a §6.2 derives it from each stream's ordinal in the map
/// index, so N streams cannot produce a single stream's value. It is a digest
/// of map structure, not of stored data, and aff4tools does not write it.
#[test]
fn splitting_does_not_change_the_digests_of_the_stored_data() {
    let dir = tempfile::tempdir().unwrap();
    let data = incompressible(768 * 1024);
    let registry = SourceRegistry::new();

    // Whole: a threshold no run can reach, so one part.
    let whole_out = dir.path().join("whole.aff4");
    let mut src = &data[..];
    let whole = write_split_set(
        &whole_out,
        &mut src,
        data.len() as u64,
        options(1 << 40),
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &registry,
        &mut |_, _| {},
        &Locus::new(&whole_out),
    )
    .unwrap();
    assert_eq!(whole.parts.len(), 1, "expected a single part");

    // Split.
    let split_out = dir.path().join("split.aff4");
    let mut src = &data[..];
    let split = write_split_set(
        &split_out,
        &mut src,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &registry,
        &mut |_, _| {},
        &Locus::new(&split_out),
    )
    .unwrap();
    assert!(split.parts.len() > 1, "expected several parts");

    // The image digest is identical.
    let hexes = |d: &[aff4tools::Digest]| -> Vec<String> {
        d.iter()
            .map(|x| format!("{}:{}", x.algorithm(), x.hex()))
            .collect()
    };
    assert_eq!(
        hexes(&whole.digests),
        hexes(&split.digests),
        "the image digest changed"
    );
    assert_eq!(whole.total_size, split.total_size);

    // Every block hash is identical, concatenated in part order.
    //
    // Read with the `zip` crate directly, the established pattern in this
    // suite (`tests/codecs.rs`, `tests/cli.rs`): `ZipVolume` exposes no member
    // listing, and `ContainerSummary::segments` holds counts by kind rather
    // than names. Bevy names are eight zero-padded digits, so a lexicographic
    // sort within a part is stream order.
    let block_hashes = |paths: &[std::path::PathBuf]| -> Vec<u8> {
        let mut all = Vec::new();
        for path in paths {
            let file = std::fs::File::open(path).unwrap();
            let mut archive = zip::ZipArchive::new(file).unwrap();
            let mut names: Vec<String> = archive
                .file_names()
                .filter(|n| n.ends_with(".blockHash.sha1"))
                .map(str::to_owned)
                .collect();
            names.sort();
            for name in names {
                let mut member = archive.by_name(&name).unwrap();
                std::io::copy(&mut member, &mut all).unwrap();
            }
        }
        all
    };
    let whole_paths: Vec<_> = whole.parts.iter().map(|p| p.path.clone()).collect();
    let split_paths: Vec<_> = split.parts.iter().map(|p| p.path.clone()).collect();
    let whole_blocks = block_hashes(&whole_paths);
    assert!(
        !whole_blocks.is_empty(),
        "the whole container must carry block hashes for this to prove anything"
    );
    assert_eq!(
        whole_blocks,
        block_hashes(&split_paths),
        "the per-chunk block hashes changed"
    );
}

/// Every part must conform, stubs included, apart from the one note v1.0a §7.1
/// makes
/// unavoidable: a part read alone says it references its siblings. The stub is
/// the minimum v1.0a §3 allows (lines 142, 152, 154), not an abbreviation of it.
#[test]
fn every_part_conforms_with_zero_deviations() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("ev.aff4");
    let data = incompressible(768 * 1024);
    let registry = SourceRegistry::new();
    let mut src = &data[..];

    let set = write_split_set(
        &output,
        &mut src,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 1);

    for part in &set.parts {
        let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
        cmd.args(["conformance", part.path.to_str().unwrap()]);
        let out = cmd.assert().get_output().stdout.clone();
        let text = String::from_utf8(out).unwrap();
        // A part read alone necessarily references its siblings (v1.0a §7.1), so
        // `ExternalReference` is expected here. Nothing else is: this pins that
        // no other deviation creeps into split output.
        let others: Vec<&str> = text
            .lines()
            .filter(|l| l.trim_start().starts_with('['))
            .filter(|l| !l.contains("reference to another volume"))
            .collect();
        assert!(
            others.is_empty(),
            "part {} has unexpected deviation(s): {others:?}\n{text}",
            part.path.display()
        );
    }
}

/// Write a set of several parts into `dir`, returning it.
fn a_split_set(
    dir: &Path,
    registry: &SourceRegistry,
) -> aff4tools::write::split_writer::WrittenSet {
    let output = dir.join("ev.aff4");
    let data = incompressible(768 * 1024);
    let mut src = &data[..];
    let set = write_split_set(
        &output,
        &mut src,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256],
        registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 1);
    set
}

/// One part alone: the note is useful, and says the view is incomplete.
#[test]
fn a_lone_part_reports_its_cross_part_references() {
    let dir = tempfile::tempdir().unwrap();
    let registry = SourceRegistry::new();
    let set = a_split_set(dir.path(), &registry);

    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    cmd.args(["conformance", set.parts[0].path.to_str().unwrap()]);
    let text = String::from_utf8(cmd.assert().get_output().stdout.clone()).unwrap();
    assert!(
        text.contains("reference to another volume"),
        "a lone part should say it references siblings:\n{text}"
    );
}

/// The whole set: every reference resolves, so nothing is reported. Any other
/// deviation appearing here is a regression, which is what this pins.
#[test]
fn a_complete_set_conforms_with_no_deviations() {
    let dir = tempfile::tempdir().unwrap();
    let registry = SourceRegistry::new();
    // Writes the parts into `dir`; the set itself is not named again, because
    // the folder is now what identifies it.
    let _ = a_split_set(dir.path(), &registry);

    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    // The whole set is named by the folder holding it: `--split-file` takes a
    // directory and orders the parts by the numbers in their names, where
    // `--stripe` once took each part as its own repeated flag.
    cmd.arg("conformance");
    cmd.args(["--split-file", dir.path().to_str().unwrap()]);
    let out = cmd.output().unwrap();
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(
        text.contains("No deviations"),
        "a complete set must conform cleanly (status {:?}):\nSTDOUT:\n{text}\nSTDERR:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A device acquired whole and the same device acquired split must produce
/// identical digests. Only the division across files may differ.
///
/// `DeviceReader` needs a `Read + Seek` source, so a file stands in for the
/// device node; the code path under test is the same one `/dev/rdiskN` takes.
#[test]
fn device_split_digests_match_whole_device() {
    use aff4tools::write::device::{DeviceOptions, DeviceReader};

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.raw");
    // Three parts' worth at the threshold chosen below.
    let data = incompressible(300 * 1024);
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&source, &data).unwrap();
    let total = data.len() as u64;

    // Whole.
    let whole_out = dir.path().join("whole.aff4");
    let whole_digests = {
        let registry = SourceRegistry::new();
        let file = std::fs::File::open(&source).unwrap();
        let mut reader = DeviceReader::new(file, total, DeviceOptions::default());
        let set = write_split_set(
            &whole_out,
            &mut reader,
            total,
            options(u64::MAX),
            &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
            &registry,
            &mut |_, _| {},
            &Locus::new(&whole_out),
        )
        .unwrap();
        assert_eq!(set.parts.len(), 1, "u64::MAX threshold must not split");
        set.digests
    };

    // Split.
    let split_out = dir.path().join("split.aff4");
    let split_digests = {
        let registry = SourceRegistry::new();
        let file = std::fs::File::open(&source).unwrap();
        let mut reader = DeviceReader::new(file, total, DeviceOptions::default());
        let set = write_split_set(
            &split_out,
            &mut reader,
            total,
            options(128 * 1024),
            &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
            &registry,
            &mut |_, _| {},
            &Locus::new(&split_out),
        )
        .unwrap();
        assert!(set.parts.len() > 1, "expected several parts");
        set.digests
    };

    let hex = |ds: &[aff4tools::Digest]| -> Vec<String> {
        let mut v: Vec<String> = ds
            .iter()
            .map(|d| format!("{}:{}", d.algorithm(), d.hex()))
            .collect();
        v.sort();
        v
    };
    assert_eq!(hex(&whole_digests), hex(&split_digests));
}

/// A clean device split across parts reports no read errors, using the exact
/// wording the single-file path uses, so an examiner's notes stay comparable.
/// This is a happy-path check of that wording; it does not exercise the
/// unreadable-sector report — see `split_write_records_unreadable_regions` for
/// that.
#[test]
fn split_device_clean_source_reports_no_read_errors() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.raw");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&source, incompressible(300 * 1024)).unwrap();
    let output = dir.path().join("evidence.aff4");

    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    let assert = cmd
        .arg("acquire")
        .arg("--device")
        .arg(&source)
        .arg("--split-file")
        .arg("1G")
        .arg("--output")
        .arg(&output)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // A clean source reports no read errors, and the wording must match the
    // single-file path exactly so an examiner's notes stay comparable.
    assert!(
        stdout.contains("Read errors: none; every sector was returned"),
        "missing the read-error line: {stdout}"
    );
}

/// A split write over a source with a genuinely bad range must accumulate that
/// range in `DeviceReader`'s unreadable state. This is the library-level
/// counterpart to the CLI's "Read errors: none" happy path: it is the only
/// test that drives a nonempty unreadable report through `write_split_set`,
/// which is what `src/main.rs`'s device split branch reads back to decide
/// whether to raise the exit code.
#[test]
fn split_write_records_unreadable_regions() {
    use aff4tools::write::device::{DeviceOptions, DeviceReader, FaultyReader};

    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let data = incompressible(300 * 1024);
    let total = data.len() as u64;
    let bad = (64 * 1024)..(96 * 1024);
    let bad_len = bad.end - bad.start;

    let registry = SourceRegistry::new();
    let faulty = FaultyReader::new(data, bad);
    let mut reader = DeviceReader::new(faulty, total, DeviceOptions::default());
    let set = write_split_set(
        &output,
        &mut reader,
        total,
        options(128 * 1024),
        &[HashAlgorithm::Sha256],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 1, "expected several parts");

    assert!(
        !reader.unreadable().is_empty(),
        "a genuinely bad range must be recorded as unreadable"
    );
    assert!(reader.unreadable_bytes() > 0);
    assert_eq!(
        reader.unreadable_bytes(),
        bad_len,
        "the accumulated unreadable total must equal the injected bad-range length"
    );
}

/// An unreadable region straddling a part boundary must produce the same bytes
/// and the same digests as the identical region acquired whole. This is the
/// case unique to splitting: if placeholder content needed boundary-aware
/// handling, this is where it would break.
#[test]
fn unreadable_region_straddling_a_part_boundary_matches_whole() {
    use aff4tools::write::device::{DeviceOptions, DeviceReader, FaultyReader};

    let dir = tempfile::tempdir().unwrap();
    let data = incompressible(300 * 1024);
    let total = data.len() as u64;
    // Chosen to sit across the 128 KiB cut point used below.
    let bad = (128 * 1024 - 2048)..(128 * 1024 + 2048);

    let whole_out = dir.path().join("whole.aff4");
    let whole = {
        let registry = SourceRegistry::new();
        let faulty = FaultyReader::new(data.clone(), bad.clone());
        let mut reader = DeviceReader::new(faulty, total, DeviceOptions::default());
        let set = write_split_set(
            &whole_out,
            &mut reader,
            total,
            options(u64::MAX),
            &[HashAlgorithm::Sha256],
            &registry,
            &mut |_, _| {},
            &Locus::new(&whole_out),
        )
        .unwrap();
        assert_eq!(set.parts.len(), 1);
        (set.digests, reader.unreadable_bytes())
    };

    let split_out = dir.path().join("split.aff4");
    let split = {
        let registry = SourceRegistry::new();
        let faulty = FaultyReader::new(data.clone(), bad.clone());
        let mut reader = DeviceReader::new(faulty, total, DeviceOptions::default());
        let set = write_split_set(
            &split_out,
            &mut reader,
            total,
            options(128 * 1024),
            &[HashAlgorithm::Sha256],
            &registry,
            &mut |_, _| {},
            &Locus::new(&split_out),
        )
        .unwrap();
        assert!(
            set.parts.len() > 1,
            "expected the region to cross a boundary"
        );
        (set.digests, reader.unreadable_bytes())
    };

    assert_eq!(
        whole.0.first().map(aff4tools::Digest::hex),
        split.0.first().map(aff4tools::Digest::hex),
        "placeholder content differed across a part boundary"
    );
    assert_eq!(
        whole.1, split.1,
        "the same region must be recorded as unreadable in both modes"
    );
}

/// A source too large for 999 parts at the given threshold is refused before
/// any part file is created, so the refusal costs nothing.
///
/// Exercised through `preflight` rather than the CLI: `SplitSize` offers no
/// threshold below 1 GiB, so a CLI fixture would need a terabyte of source.
#[test]
fn split_refuses_an_over_long_set_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    // 1000 parts at this threshold: one more than the three-digit limit allows.
    let threshold = 1024u64;
    let source_size = threshold * 1000;

    let result = preflight(source_size, threshold, &Locus::new(&output));
    assert!(result.is_err(), "an over-long set must be refused");
    assert!(
        !part_path(&output, 1).exists(),
        "a refused acquisition must not leave a part behind"
    );
}

/// A set this writer produced is reported as sequential.
///
/// Written through the library rather than the CLI because `--split-file`'s
/// smallest value is 1 GiB, which no test-sized source reaches — a CLI
/// acquisition here would produce one part, and a single part has no layout to
/// report. The verification still goes through the binary, so what is pinned is
/// the line an examiner sees.
#[test]
fn a_generated_set_is_reported_as_sequential() {
    let dir = tempfile::tempdir().unwrap();
    let registry = SourceRegistry::new();
    let set = a_split_set(dir.path(), &registry);
    assert!(set.parts.len() > 2, "need several parts to interleave");

    let mut ver = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    ver.args(["verify", "--split-file", dir.path().to_str().unwrap()]);
    let out = ver.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("sequential (not striped)"),
        "a set this writer produced fills each part before the next \
         (status {:?}):\n{text}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !text.contains("striped (interleaved)"),
        "and must not be called striped:\n{text}"
    );
}

/// Acquiring a device to a split set must verify the parts as one image, the
/// way a single-file acquisition verifies its container.
#[test]
fn split_device_verifies_the_set_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.raw");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&source, incompressible(300 * 1024)).unwrap();
    let output = dir.path().join("evidence.aff4");

    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    let assert = cmd
        .arg("acquire")
        .arg("--device")
        .arg(&source)
        .arg("--split-file")
        .arg("1G")
        .arg("--output")
        .arg(&output)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        stdout.contains("Verifying:"),
        "the set was not verified in place: {stdout}"
    );
    assert!(
        stdout.contains("recomputed digest(s) matched"),
        "no digest comparison was reported: {stdout}"
    );
    assert!(
        !stdout.contains("MISMATCH"),
        "a freshly written set must not mismatch: {stdout}"
    );
}

/// `Acquisition Complete:` marks the end of reading the source, not the end of
/// the run. It must therefore be stamped before verification begins.
///
/// It once sat after the verification hook, so a 14.9 GiB device whose parts
/// were written by 23:46 reported an acquisition completing at 23:48: the
/// re-read of the container was charged to time spent on the medium. An
/// examiner reading that log would misattribute minutes — or, on a large
/// device, hours — to the acquisition.
#[test]
fn acquisition_complete_precedes_verification_in_a_split_set() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.raw");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&source, incompressible(300 * 1024)).unwrap();
    let output = dir.path().join("evidence.aff4");

    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    let assert = cmd
        .arg("acquire")
        .arg("--device")
        .arg(&source)
        .arg("--split-file")
        .arg("1G")
        .arg("--output")
        .arg(&output)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    let acquired = stdout
        .find("Acquisition Complete:")
        .unwrap_or_else(|| panic!("no acquisition timestamp: {stdout}"));
    let verifying = stdout
        .find("Verifying:")
        .unwrap_or_else(|| panic!("the set was not verified: {stdout}"));

    assert!(
        acquired < verifying,
        "`Acquisition Complete:` must be stamped before verification starts, \
         or the verification pass is charged to time spent reading the source: \
         {stdout}"
    );
}

/// A split set must have its per-chunk block hashes recomputed.
///
/// Each part's `ImageStream` records no `aff4:hash` of its own — by design:
/// one digest describes the whole image stream and lives in part 001.
/// `verify_stream` must not return on that emptiness before reaching the
/// per-chunk work, which would leave a split set's leaves unchecked while the
/// identical evidence in one file is checked in full.
#[test]
fn split_set_block_hashes_are_recomputed() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let registry = SourceRegistry::new();
    let data = incompressible(300 * 1024);
    let mut source = std::io::Cursor::new(data.clone());

    let set = write_split_set(
        &output,
        &mut source,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 1, "expected several parts");

    let mut container = aff4tools::Container::open(&set.parts[0].path).unwrap();
    for part in &set.parts[1..] {
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(&part.path).unwrap();
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }

    let report = aff4tools::verify_container(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
    )
    .unwrap();

    let block_checks: Vec<&aff4tools::HashCheck> = report
        .checks
        .iter()
        .filter(|c| c.coverage == aff4tools::Coverage::Block)
        .collect();
    assert!(
        !block_checks.is_empty(),
        "no per-chunk block hash check was produced for a split set"
    );
    assert!(
        block_checks.iter().all(|c| c.outcome.was_checked()),
        "a block hash check was recorded but never compared: {block_checks:?}"
    );
    assert!(
        report.block_hashes_verified,
        "the report must state that block hashes were verified"
    );
}

/// A split set must report the same block-hash assurance a single-file
/// container reports. Same evidence, same claim.
#[test]
fn split_set_reports_block_hashes_recomputed() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.raw");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&source, incompressible(300 * 1024)).unwrap();
    let set_dir = dir.path().join("set");
    std::fs::create_dir(&set_dir).unwrap();
    let output = set_dir.join("evidence.aff4");

    let mut acquire = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    acquire
        .arg("acquire")
        .arg("--device")
        .arg(&source)
        .arg("--split-file")
        .arg("1G")
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    let mut verify = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    let assert = verify
        .arg("verify")
        .arg("--split-file")
        .arg(&set_dir)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        stdout.contains("All per-chunk block hashes were recomputed."),
        "split set did not report full block-hash coverage: {stdout}"
    );
    assert!(
        !stdout.contains("stores no per-chunk block hashes"),
        "a container holding block hashes must not report storing none: {stdout}"
    );
    assert!(
        !stdout.contains("were not recomputed"),
        "the interim message must be gone: {stdout}"
    );
}

/// Verifying an image must read it once, however many digests it records.
///
/// The author's nine-part set records SHA-256 and MD5 on its `DiskImage`, and
/// each digest drove its own full traversal: 14.9 GiB read twice at the image
/// level alone. Decompression is the expensive act; the algorithms riding along
/// are nearly free.
#[test]
fn an_image_is_read_once_regardless_of_digest_count() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let registry = SourceRegistry::new();
    let data = incompressible(300 * 1024);
    let mut source = std::io::Cursor::new(data.clone());

    let set = write_split_set(
        &output,
        &mut source,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 1, "expected several parts");

    let mut container = aff4tools::Container::open(&set.parts[0].path).unwrap();
    for part in &set.parts[1..] {
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(&part.path).unwrap();
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }

    // A traversal restarts `done` at or near zero; a continuing one only grows.
    let image_arn = set.image_arn.clone();
    let mut passes = 0usize;
    let mut last = u64::MAX;
    let mut observe = |event: aff4tools::Progress<'_>| {
        if let aff4tools::Progress::Bytes { arn, done, .. } = event
            && arn.as_str() == image_arn
        {
            if done <= last {
                passes += 1;
            }
            last = done;
        }
    };

    let report = aff4tools::verify_container_with_progress(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
        &mut observe,
    )
    .unwrap();

    assert!(
        passes <= 1,
        "the image was traversed {passes} times; two recorded digests must \
         share one read"
    );

    // Sharing a read must never mean checking less. Both recorded digests are
    // still compared against a value actually computed — which is the claim the
    // traversal count exists to protect.
    let checked: Vec<_> = report
        .checks
        .iter()
        .filter(|c| {
            c.subject.as_str() == image_arn
                && c.coverage == aff4tools::Coverage::WholeImage
                && c.outcome == aff4tools::Outcome::Match
        })
        .collect();
    assert_eq!(
        checked.len(),
        2,
        "both image digests must be compared, got {checked:?}"
    );
}

/// Verifying a split set must read every stored byte once.
///
/// Nine parts and one image digest meant ten traversals: nine to check each
/// part's stream, one more to re-read the same bevies through the map. The
/// bytes are identical; only the consumer differs. Counting decompressed bytes
/// rather than progress bars keeps the assertion on the quantity that costs the
/// user minutes, which no cosmetic change to the display can satisfy.
#[test]
fn a_split_set_reads_every_stored_byte_once() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let registry = SourceRegistry::new();
    let data = incompressible(300 * 1024);
    let mut source = std::io::Cursor::new(data.clone());

    let set = write_split_set(
        &output,
        &mut source,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 1, "expected several parts");

    let mut container = aff4tools::Container::open(&set.parts[0].path).unwrap();
    for part in &set.parts[1..] {
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(&part.path).unwrap();
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }

    // Total decompressed bytes delivered, summed as per-ARN deltas: `done` is
    // cumulative within one traversal, so a drop marks a new subject rather
    // than data re-read.
    let mut total: u64 = 0;
    let mut last: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut observe = |event: aff4tools::Progress<'_>| {
        if let aff4tools::Progress::Bytes { arn, done, .. } = event {
            let previous = last.entry(arn.as_str().to_owned()).or_insert(0);
            if done >= *previous {
                total += done - *previous;
            } else {
                total += done;
            }
            *previous = done;
        }
    };

    aff4tools::verify_container_with_progress(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
        &mut observe,
    )
    .unwrap();

    let stored = data.len() as u64;
    assert_eq!(
        total, stored,
        "verification delivered {total} bytes for {stored} bytes of evidence; \
         every stored byte must be read exactly once"
    );
}

/// One meter, advancing only forwards, across a whole split set.
///
/// Each `Progress::Bytes` counts from its own object's start, so a display
/// painting `done` directly restarted at zero for every object — nine parts and
/// an image meant the bar ran to 100% and reset ten times. What the accumulated
/// figure must guarantee is that it never goes backwards, which is the property
/// that distinguishes a meter from a series of bars.
#[test]
fn progress_across_a_split_set_never_goes_backwards() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let registry = SourceRegistry::new();
    let data = incompressible(300 * 1024);
    let mut source = std::io::Cursor::new(data.clone());

    let set = write_split_set(
        &output,
        &mut source,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 1, "expected several parts");

    let mut container = aff4tools::Container::open(&set.parts[0].path).unwrap();
    for part in &set.parts[1..] {
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(&part.path).unwrap();
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }

    // The same accumulation the CLI's reporter performs, kept here so the
    // property is tested rather than the rendering.
    let mut cumulative: u64 = 0;
    let mut seen: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut lowest_step = i128::MAX;
    let mut observe = |event: aff4tools::Progress<'_>| {
        if let aff4tools::Progress::Bytes { arn, done, .. } = event {
            let previous = seen.entry(arn.as_str().to_owned()).or_insert(0);
            let delta = if done >= *previous {
                done - *previous
            } else {
                done
            };
            *previous = done;
            let next = cumulative.saturating_add(delta);
            lowest_step = lowest_step.min(i128::from(next) - i128::from(cumulative));
            cumulative = next;
        }
    };

    aff4tools::verify_container_with_progress(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
        &mut observe,
    )
    .unwrap();

    assert!(
        lowest_step >= 0,
        "the meter went backwards by {} bytes",
        -lowest_step
    );
    assert_eq!(
        cumulative,
        data.len() as u64,
        "the meter must end at the bytes actually read"
    );
}

/// One accounting entry per image, however the image was verified.
///
/// A verify run states what a matching digest is a digest *of* — "14.9 GiB
/// stored, 0 B described" — and states it once. Listing the same image ARN
/// several times gives an examiner copies with nothing to distinguish them,
/// which is what the split set did before the image's per-algorithm reads were
/// collapsed. Fusing the traversal into the stream passes added a second way to
/// reach the same defect, so the property is held here rather than left to
/// inspection.
#[test]
fn a_split_set_reports_its_image_accounting_once() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let registry = SourceRegistry::new();
    let data = incompressible(300 * 1024);
    let mut source = std::io::Cursor::new(data.clone());

    let set = write_split_set(
        &output,
        &mut source,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 1, "expected several parts");

    let mut container = aff4tools::Container::open(&set.parts[0].path).unwrap();
    for part in &set.parts[1..] {
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(&part.path).unwrap();
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }

    let report = aff4tools::verify_container(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
    )
    .unwrap();

    let entries: Vec<_> = report
        .read_accounting
        .iter()
        .filter(|e| e.image.as_str() == set.image_arn)
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "the image must be accounted for once, got {entries:?}"
    );
    assert!(
        entries[0].traversed,
        "the fused pass read the image, so the figures are measured not derived"
    );
    assert_eq!(
        entries[0].accounting.stored,
        data.len() as u64,
        "every stored byte must be accounted for"
    );
}

/// The work estimate must cover the whole set, not just the first part.
///
/// `estimate_work` walked the primary volume's objects while verification
/// walked every volume's, so a nine-part set was estimated from part 001 alone.
/// The pre-run block understated the run by a factor of nine, and the meter —
/// which measures against that total — read 250% and showed a time remaining of
/// zero while eight parts were still to be read.
#[test]
fn the_estimate_covers_every_part_of_a_split_set() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let registry = SourceRegistry::new();
    let data = incompressible(300 * 1024);
    let mut source = std::io::Cursor::new(data.clone());

    let set = write_split_set(
        &output,
        &mut source,
        data.len() as u64,
        options(128 * 1024),
        &[HashAlgorithm::Sha256],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 2, "need several parts to be wrong by");

    let mut container = aff4tools::Container::open(&set.parts[0].path).unwrap();
    for part in &set.parts[1..] {
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(&part.path).unwrap();
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }

    let estimate = aff4tools::estimate_work(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
    )
    .unwrap();

    assert_eq!(
        estimate.bytes_to_read,
        data.len() as u64,
        "the estimate must name every stored byte the run will read"
    );

    // And the disk figure must come from each part's own volume: asking the
    // primary about a sibling's segments finds nothing and reports zero.
    assert!(
        estimate.bytes_on_disk > 0,
        "stored bytes must be resolved against the volume holding each stream"
    );

    // The estimate is what the meter measures against, so the two must agree.
    let mut delivered: u64 = 0;
    let mut seen: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut observe = |event: aff4tools::Progress<'_>| {
        if let aff4tools::Progress::Bytes { arn, done, .. } = event {
            let previous = seen.entry(arn.as_str().to_owned()).or_insert(0);
            delivered += if done >= *previous {
                done - *previous
            } else {
                done
            };
            *previous = done;
        }
    };
    aff4tools::verify_container_with_progress(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
        &mut observe,
    )
    .unwrap();

    assert_eq!(
        delivered,
        estimate.bytes_to_read,
        "the meter would read {}% at the end",
        delivered * 100 / estimate.bytes_to_read.max(1)
    );
}
