//! Writing a Map and the `aff4:DiskImage` that names it.
//!
//! An `ImageStream` on its own is a bytestream, not an image. What makes a
//! container an *image* is a `DiskImage` object naming a `dataStream`, which is
//! a `Map` assembling the address space from one or more streams. pyaff4's
//! `vol.images()` looks for `aff4:Image`, so a container holding only a stream
//! reads as holding nothing.
//!
//! # The three segments
//!
//! - `map` — the entries, 28 bytes each (spec §4):
//!   `mappedOffset: u64`, `length: u64`, `targetOffset: u64`, `targetId: u32`
//! - `idx` — the target index: one target ARN per line, `\n` separated, where
//!   line *n* is target ID *n* (spec §4.1)
//! - `mapPath` — documented by v1.0a §6.3 and hashed by `mapPathHash`
//!
//! Every one of these is parsed by `crate::map`, so the layout here is taken
//! from the reading side rather than restated from the specification.

use crate::error::Result;
use crate::write::container_writer::ContainerWriter;
use crate::write::turtle::{TurtleTerm, XSD_LONG};

/// Bytes per map entry.
const MAP_ENTRY_LEN: usize = 28;

/// One contiguous run of the image's address space.
#[derive(Debug, Clone, Copy)]
pub struct MapEntry {
    /// Offset in the image's address space.
    pub mapped_offset: u64,
    /// How many bytes this run covers.
    pub length: u64,
    /// Offset within the target stream.
    pub target_offset: u64,
    /// Index into the target list.
    pub target_id: u32,
}

/// What a written map turned out to be.
#[derive(Debug, Clone)]
pub struct WrittenMap {
    /// The map object's ARN.
    pub arn: String,
    /// The image object's ARN.
    pub image_arn: String,
    /// The address space covered.
    pub size: u64,
}

/// Write a Map and its `DiskImage` under caller-chosen ARNs.
///
/// [`write_map`] derives both names from the volume, which is right when one
/// volume holds the whole image. A split set cannot do that: every part shares
/// **one** `DiskImage`, so its ARN is minted once by the caller and passed here
/// (spec §7.1, the point of commonality).
///
/// `targets` are the ARNs a map entry's `target_id` indexes into. They need not
/// name streams in `writer`'s own volume; in a split set most of them do not.
///
/// # Errors
///
/// [`Error::Malformed`](crate::error::Error::Malformed) if `map_arn` names no
/// member of the writer's volume.
pub fn write_map_as(
    writer: &mut ContainerWriter,
    map_arn: &str,
    image_arn: &str,
    entries: &[MapEntry],
    targets: &[String],
    size: u64,
    locus: &crate::error::Locus,
) -> Result<WrittenMap> {
    let volume = writer.volume_arn().clone();
    let volume_arn = volume.as_str().to_owned();

    let map_arn = map_arn.to_owned();
    let image_arn = image_arn.to_owned();

    let base = crate::arn::Arn::parse(&map_arn, locus)?
        .member_name(&volume)
        .ok_or_else(|| {
            crate::error::Error::malformed(
                locus.clone(),
                format!("map {map_arn} names no member of volume {volume_arn}"),
            )
        })?;

    // The map segment: entries in address order.
    let mut map_bytes = Vec::with_capacity(entries.len() * MAP_ENTRY_LEN);
    for entry in entries {
        map_bytes.extend_from_slice(&entry.mapped_offset.to_le_bytes());
        map_bytes.extend_from_slice(&entry.length.to_le_bytes());
        map_bytes.extend_from_slice(&entry.target_offset.to_le_bytes());
        map_bytes.extend_from_slice(&entry.target_id.to_le_bytes());
    }

    // The idx segment: one target ARN per line, position = target ID.
    let mut idx_bytes = Vec::new();
    for target in targets {
        idx_bytes.extend_from_slice(target.as_bytes());
        idx_bytes.push(b'\n');
    }

    writer.add_stored_segment(&format!("{base}/{}", crate::map::MAP_SEGMENT), &map_bytes)?;
    writer.add_stored_segment(&format!("{base}/{}", crate::map::IDX_SEGMENT), &idx_bytes)?;
    // mapPath is empty for a single-volume acquisition; it exists so
    // `mapPathHash` has a defined input rather than being absent, which is the
    // state `broken-dedupe.aff4` is in.
    writer.add_stored_segment(&format!("{base}/{}", crate::map::MAP_PATH_SEGMENT), &[])?;

    let lexicon = crate::lexicon::STANDARD11;
    let graph = writer.graph_mut();

    graph.add_type(&map_arn, &lexicon.iri(lexicon.map));
    graph.add(
        &map_arn,
        &lexicon.iri(lexicon.size),
        TurtleTerm::typed(size.to_string(), XSD_LONG),
    );
    for target in targets {
        graph.add(
            &map_arn,
            &lexicon.iri(lexicon.dependent_stream),
            TurtleTerm::iri(target),
        );
        // The inverse edge, which spec §2.2 calls a "backwards pointer to the
        // parent of this object" and lists on ImageStream as well as Map.
        // Written here rather than by the stream writer because a stream is
        // written before its map exists, and this is where both ARNs are known.
        //
        // It is what lets a consumer given a stream find the map that assembles
        // it, instead of scanning every `dependentStream` in the graph. pyaff4's
        // `getParentMap` iterates exactly this predicate and raises
        // "Illegal State" without it, so omitting it locks us out of the only
        // external implementation that recomputes AFF4 hashes.
        //
        // Symbolic streams are skipped: they are described by the standard
        // rather than stored in the container, carry no triples of their own,
        // and giving one a parent would invent an object the volume does not
        // hold.
        if !crate::map::is_symbolic_target(target) {
            graph.add(
                target,
                &lexicon.iri(lexicon.target),
                TurtleTerm::iri(&map_arn),
            );
        }
    }
    graph.add(
        &map_arn,
        &lexicon.iri(lexicon.stored),
        TurtleTerm::iri(&volume_arn),
    );
    graph.add(
        &map_arn,
        &lexicon.iri(lexicon.target),
        TurtleTerm::iri(&image_arn),
    );

    // Spec §2.1 requires the full type chain, not only the most specific type.
    graph.add_type(&image_arn, &lexicon.iri(lexicon.disk_image));
    graph.add_type(&image_arn, &lexicon.iri(lexicon.contiguous_image));
    graph.add_type(&image_arn, &lexicon.iri(lexicon.image));
    graph.add(
        &image_arn,
        &lexicon.iri(lexicon.size),
        TurtleTerm::typed(size.to_string(), XSD_LONG),
    );
    graph.add(
        &image_arn,
        &lexicon.iri(lexicon.data_stream),
        TurtleTerm::iri(&map_arn),
    );
    graph.add(
        &image_arn,
        &lexicon.iri(lexicon.stored),
        TurtleTerm::iri(&volume_arn),
    );

    Ok(WrittenMap {
        arn: map_arn,
        image_arn,
        size,
    })
}

/// Write a Map and its `DiskImage`, both stored in `writer`'s volume.
///
/// `targets` are the ARNs a map entry's `target_id` indexes into.
///
/// # Errors
///
/// As [`write_map_as`].
pub fn write_map(
    writer: &mut ContainerWriter,
    entries: &[MapEntry],
    targets: &[String],
    size: u64,
    locus: &crate::error::Locus,
) -> Result<WrittenMap> {
    let volume_arn = writer.volume_arn().as_str().to_owned();
    let map_arn = format!("{volume_arn}/map");
    let image_arn = format!("{volume_arn}/image");
    write_map_as(writer, &map_arn, &image_arn, entries, targets, size, locus)
}

/// Write a deduplicated file's Map, whose targets are Block Hash ARNs (§4).
///
/// `chunk_targets` is one target ID per chunk in file order; `targets` is the
/// acquisition-wide Block Hash ARN list those IDs index into. Those IDs are
/// **global**; what lands in the container is renumbered per file (see below).
///
/// # Why entries, and not one Slice Map per chunk
///
/// The paper's Slice Map syntax puts a *single-entry* map in the RDF, avoiding
/// two ZIP segments — it is used for the Block Hash ARN → stream mapping, which
/// this writer emits in `dedupe.rs`. A file, though, has as many entries as it
/// has chunks, so it gets an ordinary `map`/`idx` pair. That is what
/// `broken-dedupe.aff4` does too: 437 entries in a real `map` segment.
///
/// # The final chunk
///
/// Every pooled chunk is NUL-padded to full length, so the last entry would run
/// past the file's end. Its `length` is trimmed to what remains of `size`,
/// which is what makes the padding invisible on read.
///
/// # The `idx` lists only this file's own chunks
///
/// Target IDs are **renumbered against a per-file list**, not written against
/// the acquisition-wide one. Writing the global list into every file's `idx`
/// costs N files × N targets: measured at 10,000 files it produced 14.1 GB of
/// `idx` for 101 MiB of evidence — a container 129× larger than the same tree
/// stored without deduplication, and ~564 TB extrapolated to 2M files. A file
/// referencing one chunk now gets a one-line `idx`.
///
/// # Errors
///
/// [`Error::Malformed`](crate::error::Error::Malformed) if the ARN names no
/// member of the volume, or if a chunk's target ID is not in `targets`.
pub fn write_slice_map(
    writer: &mut ContainerWriter,
    file_arn: &str,
    chunk_targets: &[u32],
    targets: &[String],
    size: u64,
    chunk_size: u64,
    locus: &crate::error::Locus,
) -> Result<()> {
    let volume = writer.volume_arn().clone();
    let volume_arn = volume.as_str().to_owned();

    let base = crate::arn::Arn::parse(file_arn, locus)?
        .member_name(&volume)
        .ok_or_else(|| {
            crate::error::Error::malformed(
                locus.clone(),
                format!("file {file_arn} names no member of volume {volume_arn}"),
            )
        })?;

    // Global target ID → this file's local ID, assigned in first-use order. A
    // file that repeats a chunk lists it once and points both entries at it.
    let mut local_of: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut local_targets: Vec<&str> = Vec::new();

    let mut map_bytes = Vec::with_capacity(chunk_targets.len() * MAP_ENTRY_LEN);
    for (index, target_id) in chunk_targets.iter().enumerate() {
        let global = *target_id as usize;
        if global >= targets.len() {
            return Err(crate::error::Error::malformed(
                locus.clone(),
                format!(
                    "{file_arn} references chunk target {target_id}, but only \
                     {} unique chunks were stored",
                    targets.len()
                ),
            ));
        }
        let mapped_offset = index as u64 * chunk_size;
        // Trim the padded tail: the map must describe the file, not the pool.
        let length = chunk_size.min(size.saturating_sub(mapped_offset));
        if length == 0 {
            break;
        }

        let local_id = if let Some(id) = local_of.get(target_id) {
            *id
        } else {
            let id = u32::try_from(local_targets.len()).map_err(|_| {
                crate::error::Error::malformed(
                    locus.clone(),
                    format!("{file_arn} references more chunks than a map can index"),
                )
            })?;
            local_of.insert(*target_id, id);
            local_targets.push(&targets[global]);
            id
        };

        map_bytes.extend_from_slice(&mapped_offset.to_le_bytes());
        map_bytes.extend_from_slice(&length.to_le_bytes());
        // Every chunk sits at offset 0 of its own Block Hash ARN: the ARN names
        // the chunk's content, and the slice into the shared stream is recorded
        // against the ARN itself rather than repeated here.
        map_bytes.extend_from_slice(&0u64.to_le_bytes());
        map_bytes.extend_from_slice(&local_id.to_le_bytes());
    }

    let mut idx_bytes = Vec::new();
    for target in &local_targets {
        idx_bytes.extend_from_slice(target.as_bytes());
        idx_bytes.push(b'\n');
    }

    writer.add_stored_segment(&format!("{base}/{}", crate::map::MAP_SEGMENT), &map_bytes)?;
    writer.add_stored_segment(&format!("{base}/{}", crate::map::IDX_SEGMENT), &idx_bytes)?;
    writer.add_stored_segment(&format!("{base}/{}", crate::map::MAP_PATH_SEGMENT), &[])?;

    // The file is now map-backed as well as being a FileImage: exactly the
    // `FileImage, Image, Map` type triple `broken-dedupe.aff4` carries.
    let lexicon = crate::lexicon::STANDARD11;
    let graph = writer.graph_mut();
    graph.add_type(file_arn, &lexicon.iri(lexicon.map));
    graph.add(
        file_arn,
        &lexicon.iri(lexicon.data_stream),
        TurtleTerm::iri(file_arn),
    );

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::error::Locus;
    use crate::model::HashAlgorithm;
    use crate::write::guard::SourceRegistry;
    use crate::write::stream_writer::{StreamOptions, write_image_stream};

    /// A container with a Map and a `DiskImage` must read back as an image, with
    /// the image's bytes reproducing the source.
    #[test]
    fn a_written_image_reads_back_through_its_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.aff4");
        let locus = Locus::new(&path);
        let registry = SourceRegistry::new();

        let data: Vec<u8> = (0..20_000u32)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();

        let mut writer = ContainerWriter::create(&path, &registry).unwrap();
        let options = StreamOptions {
            chunk_size: 4096,
            chunks_per_segment: 2,
            codec: crate::codec::Codec::Lz4,
            block_hashes: true,
        };
        let stream = write_image_stream(
            &mut writer,
            &mut data.as_slice(),
            options,
            &[HashAlgorithm::Sha256],
            &locus,
        )
        .unwrap();

        let entries = [MapEntry {
            mapped_offset: 0,
            length: stream.size,
            target_offset: 0,
            target_id: 0,
        }];
        let written = write_map(
            &mut writer,
            &entries,
            std::slice::from_ref(&stream.arn),
            stream.size,
            &locus,
        )
        .unwrap();
        writer.finish().unwrap();

        let mut container = crate::container::Container::open(&path).unwrap();
        let summary = container.summarize().unwrap();
        assert!(
            summary.deviations.is_empty(),
            "deviations: {:#?}",
            summary.deviations
        );

        // The image must be discoverable as an image, not merely a stream.
        let images = summary.images();
        assert!(
            images.iter().any(|o| o.arn.as_str() == written.image_arn),
            "the DiskImage must be listed among images: {:#?}",
            summary.objects.iter().map(|o| &o.arn).collect::<Vec<_>>()
        );

        // And it must reproduce the source through the map.
        let lexicon = container.lexicon();
        let arn = crate::arn::Arn::parse(&written.image_arn, &locus).unwrap();
        let image =
            crate::image::Image::open_in_set(&arn, container.volumes_mut(), lexicon, &locus)
                .expect("the image must resolve through its map");

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
            .unwrap();
        assert_eq!(back, data, "the image must reproduce the source bytes");
    }

    /// A split set's `DiskImage` is shared across parts, so its ARN cannot be
    /// derived from the volume that happens to hold the map.
    #[test]
    fn the_image_arn_may_come_from_the_caller() {
        let dir = tempfile::tempdir().unwrap();
        let registry = SourceRegistry::new();
        let path = dir.path().join("m.aff4");
        let mut w = ContainerWriter::create(&path, &registry).unwrap();
        let volume = w.volume_arn().as_str().to_owned();

        let shared_image = "aff4://11111111-2222-3333-4444-555555555555".to_owned();
        let map_arn = format!("{volume}/map");
        let targets = vec![format!("{volume}/data"), "aff4://other/data".to_owned()];
        let entries = [
            MapEntry {
                mapped_offset: 0,
                length: 100,
                target_offset: 0,
                target_id: 0,
            },
            MapEntry {
                mapped_offset: 100,
                length: 50,
                target_offset: 0,
                target_id: 1,
            },
        ];

        let written = write_map_as(
            &mut w,
            &map_arn,
            &shared_image,
            &entries,
            &targets,
            150,
            &Locus::new("m"),
        )
        .unwrap();

        assert_eq!(written.image_arn, shared_image);
        assert_eq!(written.arn, map_arn);
        assert_eq!(written.size, 150);
        w.finish().unwrap();

        let mut volume_back = crate::zip::ZipVolume::open(&path).unwrap();
        let turtle = String::from_utf8(
            crate::zip::Volume::read_segment(&mut volume_back, "information.turtle").unwrap(),
        )
        .unwrap();
        assert!(
            turtle.contains(&shared_image),
            "the shared image ARN must appear:\n{turtle}"
        );
        assert!(
            turtle.contains("aff4://other/data"),
            "every target must be a dependentStream:\n{turtle}"
        );
    }

    /// Spec §2.2 lists `target` on `ImageStream` as a "backwards pointer to the
    /// parent of this object", and every corpus container writes one. Without
    /// it a consumer holding a stream ARN cannot find the map that assembles
    /// it without scanning the whole graph — and pyaff4's `getParentMap`
    /// raises "Illegal State".
    #[test]
    fn every_stored_target_points_back_at_its_map() {
        let dir = tempfile::tempdir().unwrap();
        let registry = SourceRegistry::new();
        let path = dir.path().join("t.aff4");
        let mut w = ContainerWriter::create(&path, &registry).unwrap();
        let volume = w.volume_arn().as_str().to_owned();

        let map_arn = format!("{volume}/map");
        let image_arn = format!("{volume}/image");
        let stream_arn = format!("{volume}/data");
        let targets = vec![stream_arn.clone(), "aff4://other/data".to_owned()];
        let entries = [
            MapEntry {
                mapped_offset: 0,
                length: 10,
                target_offset: 0,
                target_id: 0,
            },
            MapEntry {
                mapped_offset: 10,
                length: 10,
                target_offset: 0,
                target_id: 1,
            },
        ];

        write_map_as(
            &mut w,
            &map_arn,
            &image_arn,
            &entries,
            &targets,
            20,
            &Locus::new("t"),
        )
        .unwrap();
        w.finish().unwrap();

        let mut volume_back = crate::zip::ZipVolume::open(&path).unwrap();
        let turtle = String::from_utf8(
            crate::zip::Volume::read_segment(&mut volume_back, "information.turtle").unwrap(),
        )
        .unwrap();

        // Both stored targets carry the back-pointer, including one living in
        // another volume — a split set's normal case.
        //
        // Matched on the subject at the start of a line: the same ARN also
        // appears as an *object* inside the map's `dependentStream`, and a
        // naive substring search would find that instead.
        for target in &targets {
            let subject = format!("\n<{target}>\n");
            let block = turtle
                .split(&subject)
                .nth(1)
                .unwrap_or_else(|| unreachable!("{target} is not a subject:\n{turtle}"));
            let declaration = block.split("\n\n").next().unwrap_or_default();
            assert!(
                declaration.contains("aff4:target") && declaration.contains(&map_arn),
                "{target} must point back at {map_arn}:\n{turtle}"
            );
        }
    }

    /// A symbolic stream is described by the standard, not stored in the
    /// container, so it has no object to carry a back-pointer. Giving one an
    /// `aff4:target` would invent a resource the volume does not hold.
    #[test]
    fn a_symbolic_target_gets_no_back_pointer() {
        let dir = tempfile::tempdir().unwrap();
        let registry = SourceRegistry::new();
        let path = dir.path().join("s.aff4");
        let mut w = ContainerWriter::create(&path, &registry).unwrap();
        let volume = w.volume_arn().as_str().to_owned();

        let map_arn = format!("{volume}/map");
        let image_arn = format!("{volume}/image");
        let zero = "http://aff4.org/Schema#Zero".to_owned();
        let targets = vec![format!("{volume}/data"), zero.clone()];
        let entries = [
            MapEntry {
                mapped_offset: 0,
                length: 10,
                target_offset: 0,
                target_id: 0,
            },
            MapEntry {
                mapped_offset: 10,
                length: 10,
                target_offset: 0,
                target_id: 1,
            },
        ];

        write_map_as(
            &mut w,
            &map_arn,
            &image_arn,
            &entries,
            &targets,
            20,
            &Locus::new("s"),
        )
        .unwrap();
        w.finish().unwrap();

        let mut volume_back = crate::zip::ZipVolume::open(&path).unwrap();
        let turtle = String::from_utf8(
            crate::zip::Volume::read_segment(&mut volume_back, "information.turtle").unwrap(),
        )
        .unwrap();

        assert!(
            !turtle.contains(&format!("<{zero}>\n")),
            "the Zero stream must not become a subject:\n{turtle}"
        );
    }
}
