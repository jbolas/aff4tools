//! `disk_image`: finding a set's parts, choosing its image, and reading it.

use std::path::Path;

use aff4tools::disk_image::{self, DiskImageHandle};
use aff4tools::model::HashAlgorithm;
use aff4tools::write::container_writer::ContainerWriter;
use aff4tools::write::guard::SourceRegistry;
use aff4tools::write::map_writer::{MapEntry, write_map, write_map_as};
use aff4tools::write::multi_part_writer::{MultiPartOptions, write_multi_part};
use aff4tools::write::stream_writer::{StreamOptions, WrittenStream, write_image_stream};
use aff4tools::{Arn, Codec, Error, Locus, UnknownKind, UnknownRegions};

fn options() -> StreamOptions {
    StreamOptions {
        chunk_size: 4096,
        chunks_per_segment: 4,
        codec: Codec::Lz4,
        block_hashes: true,
        block_algorithm: None,
    }
}

/// Byte n is n mod 251: recognizable, and never a run.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn write_stream(writer: &mut ContainerWriter, body: &[u8], locus: &Locus) -> WrittenStream {
    let mut src = body;
    write_image_stream(writer, &mut src, options(), &[HashAlgorithm::Sha256], locus).unwrap()
}

/// A single container holding one disk image of `body`. Returns the image ARN.
fn write_single(path: &Path, body: &[u8]) -> String {
    let registry = SourceRegistry::new();
    let locus = Locus::new(path);
    let mut writer = ContainerWriter::create(path, &registry).unwrap();
    let written = write_stream(&mut writer, body, &locus);
    let entries = [MapEntry {
        mapped_offset: 0,
        length: written.size,
        target_offset: 0,
        target_id: 0,
    }];
    let mapped = write_map(
        &mut writer,
        &entries,
        std::slice::from_ref(&written.arn),
        written.size,
        &written.block_hash_digests,
        &locus,
    )
    .unwrap();
    writer.finish().unwrap();
    mapped.image_arn
}

/// A single container holding two disk images over the same stream. Returns
/// both image ARNs, in the order written.
fn write_two_images(path: &Path, body: &[u8]) -> (String, String) {
    let registry = SourceRegistry::new();
    let locus = Locus::new(path);
    let mut writer = ContainerWriter::create(path, &registry).unwrap();
    let written = write_stream(&mut writer, body, &locus);
    let volume = writer.volume_arn().as_str().to_owned();
    let entries = [MapEntry {
        mapped_offset: 0,
        length: written.size,
        target_offset: 0,
        target_id: 0,
    }];
    let mut arns = Vec::new();
    for tag in ["a", "b"] {
        let mapped = write_map_as(
            &mut writer,
            &format!("{volume}/map-{tag}"),
            &format!("{volume}/image-{tag}"),
            &entries,
            std::slice::from_ref(&written.arn),
            written.size,
            &written.block_hash_digests,
            &locus,
        )
        .unwrap();
        arns.push(mapped.image_arn);
    }
    writer.finish().unwrap();
    (arns[0].clone(), arns[1].clone())
}

/// A multi-part set of `body` in `dir`, split every 128 KiB. Returns the parts in order.
fn write_set(dir: &Path, body: &[u8]) -> Vec<std::path::PathBuf> {
    let output = dir.join("ev.aff4");
    let registry = SourceRegistry::new();
    let mut src = body;
    let set = write_multi_part(
        &output,
        &mut src,
        body.len() as u64,
        MultiPartOptions {
            // Stored, not compressed: the split is by bytes on disk, and LZ4
            // would shrink the repeating pattern into a single part.
            stream: StreamOptions {
                codec: Codec::Stored,
                ..options()
            },
            multi_part_after: 128 * 1024,
        },
        &[HashAlgorithm::Sha256],
        &registry,
        &mut |_, _| {},
        &Locus::new(&output),
    )
    .unwrap();
    assert!(set.parts.len() > 2, "the tests need at least three parts");
    set.parts.into_iter().map(|p| p.path).collect()
}

/// Every byte of the image, read through the handle.
fn read_whole(h: &mut DiskImageHandle) -> aff4tools::Result<Vec<u8>> {
    let size = h.image.size();
    let locus = Locus::new(&h.primary);
    let mut out = vec![0u8; usize::try_from(size).unwrap()];
    let mut resident = None;
    let mut done = 0usize;
    while done < out.len() {
        let n = h.image.read_at_in_set_cached(
            h.container.volumes_mut(),
            done as u64,
            &mut out[done..],
            &locus,
            &mut resident,
        )?;
        assert!(n > 0, "a read inside the image returned nothing");
        done += n;
    }
    Ok(out)
}

#[test]
fn opens_a_single_container() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("single.aff4");
    let body = pattern(40_000);
    let arn = write_single(&path, &body);

    let mut h = disk_image::open(&path).unwrap();
    assert_eq!(h.image.arn().as_str(), arn);
    assert_eq!(h.primary, path);
    assert_eq!(read_whole(&mut h).unwrap(), body);
}

#[test]
fn a_set_opens_whole_from_its_unnumbered_first_part() {
    // Under AFF4-L v1.0-ALPHA §8 a set's first part carries no ordinal, so it
    // cannot be told from a lone container by its name.
    let dir = tempfile::tempdir().unwrap();
    let body = pattern(768 * 1024);
    let parts = write_set(dir.path(), &body);

    let mut h = disk_image::open(&parts[0]).unwrap();
    assert_eq!(h.primary, parts[0]);
    assert_eq!(h.image.size(), body.len() as u64);
    assert_eq!(read_whole(&mut h).unwrap(), body);
}

#[test]
fn a_set_opens_whole_from_any_later_part() {
    let dir = tempfile::tempdir().unwrap();
    let body = pattern(768 * 1024);
    let parts = write_set(dir.path(), &body);

    let last = parts.last().unwrap();
    let mut h = disk_image::open(last).unwrap();
    assert_eq!(
        h.primary, parts[0],
        "part 1 is the primary whatever part was named"
    );
    assert_eq!(read_whole(&mut h).unwrap(), body);
}

#[test]
fn a_set_missing_a_part_never_reads_as_complete() {
    let dir = tempfile::tempdir().unwrap();
    let body = pattern(768 * 1024);
    let parts = write_set(dir.path(), &body);
    // The set was written by this test into its own TempDir; no evidence is
    // touched. See clippy.toml.
    #[allow(clippy::disallowed_methods)]
    std::fs::remove_file(&parts[1]).unwrap();

    // The gap may be refused when opening or when reading the bytes that lived
    // in the missing part. Either is correct. What must never happen is a
    // clean, complete-looking image.
    match disk_image::open(&parts[0]) {
        Err(_) => {}
        Ok(mut h) => assert!(
            read_whole(&mut h).is_err(),
            "a set missing a part read back as a complete image"
        ),
    }
}

#[test]
fn two_disk_images_are_ambiguous_unless_one_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two.aff4");
    let (a, b) = write_two_images(&path, &pattern(10_000));

    match disk_image::open(&path) {
        Err(Error::AmbiguousImage { candidates, .. }) => {
            assert_eq!(candidates.len(), 2);
            assert!(candidates.contains(&a) && candidates.contains(&b));
        }
        Err(other) => panic!("expected AmbiguousImage, got {other}"),
        Ok(_) => panic!("expected AmbiguousImage, got an image"),
    }

    let named = Arn::parse(&b, &Locus::new(&path)).unwrap();
    let h = disk_image::open_arn(&path, &named).unwrap();
    assert_eq!(h.image.arn().as_str(), b);

    let first = disk_image::open_first(&path).unwrap();
    assert!(
        [a.as_str(), b.as_str()].contains(&first.image.arn().as_str()),
        "open_first takes one of the two"
    );
}

#[test]
fn ambiguity_and_absence_are_not_integrity_findings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two.aff4");
    write_two_images(&path, &pattern(10_000));
    let err = disk_image::open(&path).err().unwrap();
    assert!(!err.is_integrity_finding(), "{err}");
    assert_eq!(err.exit_code(), 4);
}

const UNREADABLE: &str = "http://aff4.org/Schema#UnreadableData";

/// A container whose image is `body`, except bytes 4096..5120, which the map
/// records as `aff4:UnreadableData`.
fn write_with_unreadable_region(path: &Path, body: &[u8]) {
    let registry = SourceRegistry::new();
    let locus = Locus::new(path);
    let mut writer = ContainerWriter::create(path, &registry).unwrap();
    let written = write_stream(&mut writer, body, &locus);
    let entries = [
        MapEntry {
            mapped_offset: 0,
            length: 4096,
            target_offset: 0,
            target_id: 0,
        },
        MapEntry {
            mapped_offset: 4096,
            length: 1024,
            target_offset: 0,
            target_id: 1,
        },
        MapEntry {
            mapped_offset: 5120,
            length: written.size - 5120,
            target_offset: 5120,
            target_id: 0,
        },
    ];
    write_map(
        &mut writer,
        &entries,
        &[written.arn.clone(), UNREADABLE.to_owned()],
        written.size,
        // No block hashes: the block map digest composes per-entry stream
        // hashes, and a symbolic entry has none.
        &[],
        &locus,
    )
    .unwrap();
    writer.finish().unwrap();
}

#[test]
fn report_mode_refuses_the_unreadable_region_and_fill_mode_serves_its_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unreadable.aff4");
    let body = pattern(20_480);
    write_with_unreadable_region(&path, &body);

    let mut h = disk_image::open(&path).unwrap();
    let locus = Locus::new(&h.primary);
    let mut resident = None;

    // A read that starts before the region stops where it begins.
    let mut buf = vec![0u8; 8192];
    let n = h
        .image
        .read_at_in_set_cached_with(
            h.container.volumes_mut(),
            0,
            &mut buf,
            &locus,
            &mut resident,
            UnknownRegions::Report,
        )
        .unwrap();
    assert_eq!(n, 4096);
    assert_eq!(&buf[..4096], &body[..4096]);

    // A read inside the region names it.
    let err = h
        .image
        .read_at_in_set_cached_with(
            h.container.volumes_mut(),
            4200,
            &mut buf,
            &locus,
            &mut resident,
            UnknownRegions::Report,
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::UnknownRegion {
                offset: 4096,
                length: 1024,
                kind: UnknownKind::Unreadable,
                ..
            }
        ),
        "{err:?}"
    );

    // After the region, stored bytes are served again.
    let n = h
        .image
        .read_at_in_set_cached_with(
            h.container.volumes_mut(),
            5120,
            &mut buf[..100],
            &locus,
            &mut resident,
            UnknownRegions::Report,
        )
        .unwrap();
    assert_eq!(n, 100);
    assert_eq!(&buf[..100], &body[5120..5220]);

    // The existing read, which verify and export use, is unchanged: it serves
    // the placeholder, which is not recovered data.
    let n = h
        .image
        .read_at_in_set_cached(
            h.container.volumes_mut(),
            4096,
            &mut buf[..1024],
            &locus,
            &mut resident,
        )
        .unwrap();
    assert_eq!(n, 1024);
    assert!(buf.starts_with(b"UNREADABLEDATA"));
}
