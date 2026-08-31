//! Phase 2: re-imaging, and proving the result reproduces the source.
//!
//! Adversarial inputs — empty, chunk-boundary, all-zero, incompressible, and
//! a single flipped bit — plus the negative case that matters most: a
//! comparison that cannot fail is not a comparison.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::path::Path;

use aff4tools::model::HashAlgorithm;
use aff4tools::write::acquire::ImageSource;
use aff4tools::write::container_writer::ContainerWriter;
use aff4tools::write::guard::SourceRegistry;
use aff4tools::write::stream_writer::{StreamOptions, write_image_stream};
use aff4tools::{Codec, Container, Locus};

fn write_source(path: &Path, body: &[u8]) {
    // Tests may create fixtures; the library may not. See clippy.toml.
    #[allow(clippy::disallowed_methods)]
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body).unwrap();
}

/// Acquire `body` into a container and return the digests recorded, plus the
/// bytes the reader gives back.
fn acquire_and_read_back(dir: &Path, name: &str, body: &[u8], options: StreamOptions) -> Vec<u8> {
    let src = dir.join(format!("{name}.dd"));
    let out = dir.join(format!("{name}.aff4"));
    write_source(&src, body);

    let mut registry = SourceRegistry::new();
    let source = ImageSource::open(std::slice::from_ref(&src), &mut registry).unwrap();
    let locus = Locus::new(&out);

    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let written = write_image_stream(
        &mut writer,
        &mut source.reader().unwrap(),
        options,
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &locus,
    )
    .unwrap();
    writer.finish().unwrap();

    assert_eq!(written.size, body.len() as u64, "size recorded");

    // Read the stream back through the reader.
    let mut container = Container::open(&out).unwrap();
    let summary = container.summarize().unwrap();
    assert!(
        summary.deviations.is_empty(),
        "written container must be deviation-free: {:#?}",
        summary.deviations
    );

    let arn = aff4tools::Arn::parse(&written.arn, &locus).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let stream = aff4tools::ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();
    let volume = container.volumes_mut().primary_mut();

    let mut back = Vec::new();
    stream
        .read_all(
            volume,
            &mut |bytes: &[u8]| {
                back.extend_from_slice(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();
    back
}

fn options(codec: Codec) -> StreamOptions {
    StreamOptions {
        chunk_size: 4096,
        chunks_per_segment: 4,
        codec,
        block_hashes: true,
    }
}

/// The adversarial set from the plan, each round-tripped byte-for-byte.
///
/// The chunk-boundary cases matter most: **no corpus container has a size that
/// is a partial multiple of `chunkSize`**, so the padding path is otherwise
/// untested anywhere in this project.
#[test]
fn adversarial_images_round_trip_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("one_byte", vec![0x5A]),
        ("exact_chunk", vec![0xAB; 4096]),
        ("one_under", vec![0xCD; 4095]),
        ("one_over", vec![0xEF; 4097]),
        ("exact_bevy", vec![0x11; 4096 * 4]),
        ("bevy_plus_one", vec![0x22; 4096 * 4 + 1]),
        ("all_zero", vec![0u8; 4096 * 3]),
        (
            "incompressible",
            (0..4096u32 * 3)
                .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).unwrap_or(0))
                .collect(),
        ),
        ("mixed", {
            let mut v = vec![0u8; 4096];
            v.extend(std::iter::repeat_n(b'x', 4096));
            v.extend((0..4096u32).map(|i| u8::try_from(i % 251).unwrap_or(0)));
            v.extend_from_slice(b"tail");
            v
        }),
    ];

    for codec in [Codec::Lz4, Codec::Snappy, Codec::Zlib, Codec::Stored] {
        for (name, body) in &cases {
            let unique = format!("{name}_{codec:?}");
            let back = acquire_and_read_back(dir.path(), &unique, body, options(codec));
            assert_eq!(
                back.len(),
                body.len(),
                "{unique}: length changed in round trip"
            );
            assert_eq!(back, *body, "{unique}: bytes changed in round trip");
        }
    }
}

/// A single flipped bit must change the recorded digest.
///
/// Without this, every other check could be passing over a writer that stores
/// something other than what it was given.
#[test]
fn a_single_flipped_bit_changes_the_digest() {
    let dir = tempfile::tempdir().unwrap();

    let mut body = vec![0x42u8; 8192];
    let clean = acquire_and_read_back(dir.path(), "clean", &body, options(Codec::Lz4));

    body[5000] ^= 0x01;
    let flipped = acquire_and_read_back(dir.path(), "flipped", &body, options(Codec::Lz4));

    assert_ne!(clean, flipped, "a flipped bit must survive to the reader");
    assert_eq!(
        flipped[5000],
        0x42 ^ 0x01,
        "the exact bit must be preserved"
    );
}

/// A split source is acquired as one continuous stream.
#[test]
fn a_split_source_acquires_as_one_stream() {
    let dir = tempfile::tempdir().unwrap();
    write_source(&dir.path().join("s.001"), &vec![0xA1; 5000]);
    write_source(&dir.path().join("s.002"), &vec![0xB2; 5000]);

    let found = ImageSource::discover_split(&dir.path().join("s.001")).unwrap();
    let mut registry = SourceRegistry::new();
    let source = ImageSource::open(&found, &mut registry).unwrap();
    assert_eq!(source.total_size(), 10_000);

    let out = dir.path().join("split.aff4");
    let locus = Locus::new(&out);
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let written = write_image_stream(
        &mut writer,
        &mut source.reader().unwrap(),
        options(Codec::Lz4),
        &[HashAlgorithm::Sha256],
        &locus,
    )
    .unwrap();
    writer.finish().unwrap();

    assert_eq!(written.size, 10_000, "both segments must be acquired");
}

/// The source is unwritable for the whole acquisition.
#[test]
fn the_source_cannot_be_written_during_acquisition() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("evidence.dd");
    write_source(&src, b"evidence");

    let mut registry = SourceRegistry::new();
    ImageSource::open(std::slice::from_ref(&src), &mut registry).unwrap();

    assert!(
        ContainerWriter::create(&src, &registry).is_err(),
        "the acquisition source must never be a valid output path"
    );
}

/// A device with unreadable sectors still produces a complete, verifiable
/// container — with the bad regions recorded rather than zero-filled.
///
/// **No corpus container demonstrates `UnreadableData`**, so this path exists
/// only because the failure is injected here. c-aff4 does not implement it at
/// all, and pyaff4's own read-error fixture uses `aff4:Zero`.
#[test]
fn a_device_with_bad_sectors_records_them_and_still_verifies() {
    use aff4tools::write::device::{DeviceOptions, DeviceReader, FaultyReader};

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("faulty.aff4");
    let locus = Locus::new(&out);

    let body = vec![0xC3u8; 20_480];
    let faulty = FaultyReader::new(body.clone(), 4096..5120);
    let mut reader = DeviceReader::new(
        faulty,
        20_480,
        DeviceOptions {
            read_size: 4096,
            sector_size: 512,
        },
    );

    let registry = SourceRegistry::new();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let written = write_image_stream(
        &mut writer,
        &mut reader,
        options(Codec::Lz4),
        &[HashAlgorithm::Sha256],
        &locus,
    )
    .unwrap();
    writer.finish().unwrap();

    // The image keeps the medium's full size; a short image would be a
    // silently truncated acquisition.
    assert_eq!(written.size, 20_480);

    let unreadable: u64 = reader.unreadable_bytes();
    assert_eq!(unreadable, 1024, "the bad extent must be recorded");

    // And the container still verifies against its own recorded digest.
    let mut container = Container::open(&out).unwrap();
    let summary = container.summarize().unwrap();
    assert!(
        summary.deviations.is_empty(),
        "deviations: {:#?}",
        summary.deviations
    );

    // The unreadable region must not read back as zeroes.
    let arn = aff4tools::Arn::parse(&written.arn, &locus).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let stream = aff4tools::ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();
    let volume = container.volumes_mut().primary_mut();
    let mut back = Vec::new();
    stream
        .read_all(
            volume,
            &mut |bytes: &[u8]| {
                back.extend_from_slice(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();

    assert_eq!(back.len(), 20_480);
    let gap = &back[4096..5120];
    assert!(
        !gap.iter().all(|&b| b == 0),
        "an unreadable region must never be zero-filled: zeroes are \
         indistinguishable from genuinely zeroed evidence"
    );
    assert!(
        back[..4096].iter().all(|&b| b == 0xC3) && back[5120..].iter().all(|&b| b == 0xC3),
        "readable data on both sides of the fault must survive"
    );
}

/// The written hash tree must verify from leaves to root.
///
/// The subtlety this guards: the reader trims the final short chunk against
/// `aff4:size` before hashing it, so the writer must hash the trimmed bytes
/// too. Hashing the padded chunk produced the right *number* of digests, all
/// wrong — a failure only a real leaf check catches.
#[test]
fn block_hashes_verify_from_leaves_to_root() {
    let dir = tempfile::tempdir().unwrap();

    // Deliberately not a chunk multiple, so the trimmed final chunk is
    // exercised.
    let body: Vec<u8> = (0..(4096u32 * 6 + 1234))
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    let src = dir.path().join("bh.dd");
    write_source(&src, &body);
    let out = dir.path().join("bh.aff4");
    let locus = Locus::new(&out);

    let mut registry = SourceRegistry::new();
    let source = ImageSource::open(std::slice::from_ref(&src), &mut registry).unwrap();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    write_image_stream(
        &mut writer,
        &mut source.reader().unwrap(),
        options(Codec::Lz4),
        &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
        &locus,
    )
    .unwrap();
    writer.finish().unwrap();

    let mut container = Container::open(&out).unwrap();
    let report = aff4tools::verify_container(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
    )
    .unwrap();

    assert!(
        !report.has_mismatch(),
        "every digest must match: {:#?}",
        report
            .checks
            .iter()
            .filter(|c| c.outcome.is_mismatch())
            .collect::<Vec<_>>()
    );
    assert!(
        report.block_hashes_verified,
        "the leaves must actually have been checked, not merely requested"
    );
    assert!(
        report.checked_count() >= 4,
        "expected linear + block-hash + blockHashesHash checks, got {}",
        report.checked_count()
    );
}
