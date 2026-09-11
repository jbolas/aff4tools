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
//! - `map` — the entries, 28 bytes each (v1.0a §4):
//!   `mappedOffset: u64`, `length: u64`, `targetOffset: u64`, `targetId: u32`
//! - `idx` — the target index: one target ARN per line, `\n` separated, where
//!   line *n* is target ID *n* (v1.0a §4.1)
//! - `mapPath` — documented by v1.0a §6.3 and hashed by `mapPathHash`
//!
//! Every one of these is parsed by `crate::map`, so the layout here is taken
//! from the reading side rather than restated from the specification.

use crate::error::Result;
use crate::write::container_writer::ContainerWriter;
use crate::write::turtle::{TurtleTerm, XSD_LONG};

/// Bytes per map entry.
const MAP_ENTRY_LEN: usize = 28;

/// The digests AFF4 Standard v1.0a §6.2 defines over a map's own segments.
///
/// Returned by [`write_map_segments`] so a caller composing a block map hash
/// has the four values without re-reading the segments it just wrote.
///
/// # What each covers
///
/// | Property | Over |
/// |---|---|
/// | `aff4:mapPointHash` | the `map` segment |
/// | `aff4:mapIdxHash` | the `idx` segment |
/// | `aff4:mapPathHash` | the `mapPath` segment |
/// | `aff4:mapHash` | all three concatenated, in that order |
///
/// The property is named for a `point` segment the clause's table mentions,
/// while the segment every implementation writes is named `map`. Verified
/// against `Base-Linear.aff4`, whose recorded `mapPointHash` is the digest of
/// its `map` segment.
#[derive(Debug, Clone, Default)]
pub struct MapDigests {
    /// Raw digest of the `map` segment, recorded as `aff4:mapPointHash`.
    pub point: Vec<u8>,
    /// Raw digest of the `idx` segment, recorded as `aff4:mapIdxHash`.
    pub idx: Vec<u8>,
    /// Raw digest of the `mapPath` segment, recorded as `aff4:mapPathHash`.
    pub path: Vec<u8>,
}

/// The algorithm AFF4 Standard v1.0a §6.2 requires for these digests.
///
/// The clause says implementations "WILL employ H={ SHA512 or SHA256 }".
/// SHA-512 is chosen: it is what the reference corpus records, and matching the
/// containers implementations were written against is worth more than matching
/// a preference.
///
/// Deliberately **not** following `--hash`. These digests are inputs to a
/// composition the standard defines, not a matter of examiner preference, and a
/// map digested in BLAKE3 would satisfy no reader.
const MAP_DIGEST_ALGORITHM: crate::model::HashAlgorithm = crate::model::HashAlgorithm::Sha512;

/// Write a map's three segments and record the four digests over them.
///
/// **One function, so no path can write the segments without the digests.**
/// They were written separately at three call sites and none of them recorded a
/// digest, which `conformance` could not report because the AFF4 Standard
/// v1.0a §6.2 rules were not in the registry at all.
///
/// `map_path` is empty for a single-volume acquisition. It is still written and
/// still digested: a defined empty input is what lets `mapPathHash` exist,
/// where an absent segment leaves it undefined — the state `broken-dedupe.aff4`
/// is in.
///
/// # Errors
///
/// [`Error::Io`](crate::error::Error::Io) if a segment cannot be written.
fn write_map_segments(
    writer: &mut ContainerWriter,
    base: &str,
    map_arn: &str,
    map_bytes: &[u8],
    idx_bytes: &[u8],
    map_path: &[u8],
) -> Result<(MapDigests, Vec<(&'static str, String)>)> {
    writer.add_stored_segment(&format!("{base}/{}", crate::map::MAP_SEGMENT), map_bytes)?;
    writer.add_stored_segment(&format!("{base}/{}", crate::map::IDX_SEGMENT), idx_bytes)?;
    writer.add_stored_segment(
        &format!("{base}/{}", crate::map::MAP_PATH_SEGMENT),
        map_path,
    )?;

    let digest = |bytes: &[u8]| {
        crate::hash::digest_bytes_of(&MAP_DIGEST_ALGORITHM, bytes).unwrap_or_default()
    };
    let digests = MapDigests {
        point: digest(map_bytes),
        idx: digest(idx_bytes),
        path: digest(map_path),
    };

    // `mapHash` covers the three segments concatenated, in the order the clause
    // lists them: map, then idx, then mapPath. Confirmed against
    // `Base-Linear.aff4`, whose recorded value this construction reproduces.
    let mut whole = Vec::with_capacity(map_bytes.len() + idx_bytes.len() + map_path.len());
    whole.extend_from_slice(map_bytes);
    whole.extend_from_slice(idx_bytes);
    whole.extend_from_slice(map_path);
    let map_hash = digest(&whole);

    let algorithm = MAP_DIGEST_ALGORITHM.name().to_owned();
    let lexicon = crate::lexicon::STANDARD;
    let mut recorded = Vec::with_capacity(4);
    for (property, value) in [
        ("mapPointHash", &digests.point),
        ("mapIdxHash", &digests.idx),
        ("mapPathHash", &digests.path),
        ("mapHash", &map_hash),
    ] {
        let hex = hex_lower(value);
        writer.graph_mut().add(
            map_arn,
            &lexicon.iri(property),
            TurtleTerm::typed(hex.clone(), lexicon.iri(&algorithm)),
        );
        recorded.push((property, hex));
    }

    Ok((digests, recorded))
}

/// Record the block map digest on the image, and on the map.
///
/// AFF4 Standard v1.0a §6.2 puts it in two places with two spellings:
///
/// - **MUST** on the `aff4:Image`, as `aff4:hash` under a datatype naming the
///   algorithm — `aff4:blockMapHashSHA512` or `aff4:blockMapHashSHA256`.
/// - **MAY** on the `aff4:Map`, as `aff4:blockMapHash` typed `aff4:SHA512` or
///   `aff4:SHA256`.
///
/// Both are written, with the same value. `Base-Linear.aff4` does the same, and
/// writing both settles the placement question design decision D7 raised: AFF4-L
/// v1.0-ALPHA §6.3.1 requires the digest on the map, while this clause requires
/// it on the image, and a container carrying both satisfies each document
/// without choosing between them.
///
/// **Nothing is written when the stream records no block hashes.** The digest
/// composes them, so with none to compose there is no digest — and a value
/// computed over an empty concatenation would look like a real one while
/// attesting nothing.
///
/// When the image and the map are the same subject — the AFF4-L v1.0-ALPHA §6.3
/// form a logical file takes — both properties land on it, which is what that
/// clause's first example shows.
fn write_block_map_digest(
    writer: &mut ContainerWriter,
    map_arn: &str,
    image_arn: &str,
    block_hashes: &[crate::write::stream_writer::BlockHashDigest],
    map_digests: &MapDigests,
) -> Option<String> {
    if block_hashes.is_empty() {
        return None;
    }

    // The `blockHashesHash` values, as bytes. These are the per-algorithm
    // digests already recorded on the stream's BlockHashes objects, so this
    // composes what the container states rather than recomputing it.
    let composed: Vec<Vec<u8>> = block_hashes
        .iter()
        .map(|digest| hex_to_bytes(&digest.hex))
        .collect();
    let block_map = compose_block_map_digest(&composed, map_digests);
    if block_map.is_empty() {
        return None;
    }
    let hex = hex_lower(&block_map);

    let lexicon = crate::lexicon::STANDARD;
    let graph = writer.graph_mut();

    // On the image: `aff4:hash`, with the algorithm carried by the datatype.
    graph.add(
        image_arn,
        &lexicon.iri(lexicon.hash),
        TurtleTerm::typed(hex.clone(), lexicon.iri("blockMapHashSHA512")),
    );
    // On the map: its own property, with an ordinary digest datatype.
    graph.add(
        map_arn,
        &lexicon.iri("blockMapHash"),
        TurtleTerm::typed(hex.clone(), lexicon.iri(MAP_DIGEST_ALGORITHM.name())),
    );
    Some(hex)
}

/// Decode lowercase hex into bytes, ignoring anything malformed.
///
/// The input is this crate's own digest output, so it is always well formed. A
/// non-hex character yields a shorter result rather than a panic.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let Ok(text) = std::str::from_utf8(pair) else {
            continue;
        };
        if let Ok(byte) = u8::from_str_radix(text, 16) {
            out.push(byte);
        }
    }
    out
}

/// Render bytes as lowercase hex.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Compose the block map digest AFF4 Standard v1.0a §6.2 defines.
///
/// `block_hashes_digests` are the `blockHashesHash` values already recorded for
/// each of the stream's block-hash objects, as raw bytes. The clause orders them
/// by digest length, smallest first, and by SHA-512 before Blake2b at equal
/// length. This writer records one algorithm per stream, so the ordering is
/// exercised by containers it reads rather than by ones it writes; it is applied
/// anyway, because a single-element ordering that is wrong for two is a defect
/// waiting for the day a second algorithm is written.
///
/// The composition, confirmed against `Base-Linear.aff4`:
///
/// ```text
/// blockMapHash = H( H(BlockHashes...) || mapPointHash || mapIdxHash || mapPathHash )
/// ```
///
/// Note it concatenates the *digests* of the map segments, not the segments.
/// The `mapPathHash` term is bracketed as optional in the clause and is
/// **included**: excluding it does not reproduce the reference container's
/// recorded value.
#[must_use]
pub fn compose_block_map_digest(
    block_hashes_digests: &[Vec<u8>],
    map_digests: &MapDigests,
) -> Vec<u8> {
    let mut ordered: Vec<&Vec<u8>> = block_hashes_digests.iter().collect();
    // Shortest digest first. Equal lengths keep their given order, which for
    // the one pair the clause calls out — SHA-512 before Blake2b — is the order
    // a caller lists them in.
    ordered.sort_by_key(|d| d.len());

    let mut input = Vec::new();
    for digest in ordered {
        input.extend_from_slice(digest);
    }
    input.extend_from_slice(&map_digests.point);
    input.extend_from_slice(&map_digests.idx);
    input.extend_from_slice(&map_digests.path);

    crate::hash::digest_bytes_of(&MAP_DIGEST_ALGORITHM, &input).unwrap_or_default()
}

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
    /// Every digest recorded over the map, as `(property, lowercase hex)`.
    ///
    /// Returned so an acquisition log can account for what the container holds.
    /// A report naming only the stream's digests, while verification counts
    /// every recorded value, reads as a discrepancy and leaves the rest shown
    /// nowhere.
    pub digests: Vec<(&'static str, String)>,
}

/// Write a Map and its `DiskImage` under caller-chosen ARNs.
///
/// [`write_map`] derives both names from the volume, which is right when one
/// volume holds the whole image. A multi-part set cannot do that: every part shares
/// **one** `DiskImage`, so its ARN is minted once by the caller and passed here
/// (v1.0a §7.1, the point of commonality).
///
/// `targets` are the ARNs a map entry's `target_id` indexes into. They need not
/// name streams in `writer`'s own volume; in a multi-part set most of them do not.
///
/// # Errors
///
/// [`Error::Malformed`](crate::error::Error::Malformed) if `map_arn` names no
/// member of the writer's volume.
#[allow(clippy::too_many_arguments)]
pub fn write_map_as(
    writer: &mut ContainerWriter,
    map_arn: &str,
    image_arn: &str,
    entries: &[MapEntry],
    targets: &[String],
    size: u64,
    block_hashes: &[crate::write::stream_writer::BlockHashDigest],
    locus: &crate::error::Locus,
) -> Result<WrittenMap> {
    let volume = writer.volume_arn().clone();
    let volume_arn = volume.as_str().to_owned();

    let map_arn = map_arn.to_owned();
    let image_arn = image_arn.to_owned();

    let mapping = writer.name_mapping();
    let base = crate::arn::Arn::parse(&map_arn, locus)?
        .member_name(&volume, mapping)
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

    // mapPath is empty for a single-volume acquisition; it exists so
    // `mapPathHash` has a defined input rather than being absent, which is the
    // state `broken-dedupe.aff4` is in.
    let (map_digests, mut recorded_digests) =
        write_map_segments(writer, &base, &map_arn, &map_bytes, &idx_bytes, &[])?;

    let lexicon = crate::lexicon::STANDARD;
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
        // The inverse edge, which v1.0a §2.2 calls a "backwards pointer to the
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

    // v1.0a §2.1 requires the full type chain, not only the most specific type.
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

    if let Some(hex) =
        write_block_map_digest(writer, &map_arn, &image_arn, block_hashes, &map_digests)
    {
        recorded_digests.push(("blockMapHash", hex));
    }

    Ok(WrittenMap {
        arn: map_arn,
        image_arn,
        size,
        digests: recorded_digests,
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
    block_hashes: &[crate::write::stream_writer::BlockHashDigest],
    locus: &crate::error::Locus,
) -> Result<WrittenMap> {
    let volume_arn = writer.volume_arn().as_str().to_owned();
    let map_arn = format!("{volume_arn}/map");
    let image_arn = format!("{volume_arn}/image");
    write_map_as(
        writer,
        &map_arn,
        &image_arn,
        entries,
        targets,
        size,
        block_hashes,
        locus,
    )
}

/// Write a deduplicated file's Map, whose targets are Block Hash ARNs
/// (AFF4-L 2019 §4).
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

    let mapping = writer.name_mapping();
    let base = crate::arn::Arn::parse(file_arn, locus)?
        .member_name(&volume, mapping)
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

    let _ = write_map_segments(writer, &base, file_arn, &map_bytes, &idx_bytes, &[])?;

    // The file is now map-backed as well as being a FileImage: exactly the
    // `FileImage, Image, Map` type triple `broken-dedupe.aff4` carries.
    let lexicon = crate::lexicon::STANDARD;
    let graph = writer.graph_mut();
    graph.add_type(file_arn, &lexicon.iri(lexicon.map));
    graph.add(
        file_arn,
        &lexicon.iri(lexicon.data_stream),
        TurtleTerm::iri(file_arn),
    );

    Ok(())
}

/// Map one file onto a contiguous run of a shared `ImageStream`.
///
/// The AFF4-L Standard v1.0-ALPHA §6.3 form, in the first of that clause's two
/// shapes: `aff4:Map` is added to the `FileImage`'s own type list, so one subject
/// is both Image and Map. The second shape, where `aff4l:dataStream` reaches a
/// separate Map subject, is read but never written — see decision D6 in
/// `docs/superpowers/specs/2026-09-08-phase-9-storage-streams-design.md`.
///
/// # One entry, not one per chunk
///
/// A file appended to a shared stream occupies one unbroken byte range, so its
/// whole content is a single map entry. This is what separates the form from
/// AFF4-L 2019 §4 deduplication, where a file is reassembled from scattered
/// chunks and needs an entry each. One entry per file is why the form's
/// metadata cost stays flat as files grow.
///
/// `target_offset` is the file's first byte within the shared stream and is
/// generally not chunk-aligned: files are packed end to end, which is the
/// rounding waste this form exists to avoid paying per file.
///
/// # Errors
///
/// [`Error::Malformed`](crate::error::Error::Malformed) if `file_arn` names no
/// member of the writer's volume.
pub fn write_shared_map(
    writer: &mut ContainerWriter,
    file_arn: &str,
    stream_arn: &str,
    target_offset: u64,
    size: u64,
    locus: &crate::error::Locus,
) -> Result<()> {
    let volume = writer.volume_arn().clone();
    let volume_arn = volume.as_str().to_owned();

    let mapping = writer.name_mapping();
    let base = crate::arn::Arn::parse(file_arn, locus)?
        .member_name(&volume, mapping)
        .ok_or_else(|| {
            crate::error::Error::malformed(
                locus.clone(),
                format!("file {file_arn} names no member of volume {volume_arn}"),
            )
        })?;

    // AFF4 Standard v1.0a §4: mappedOffset, length, targetOffset, targetId.
    // The file's address space starts at 0 and the shared stream is target 0,
    // this map having exactly one target.
    //
    // A zero-length file gets an empty map rather than a zero-length entry: an
    // entry covering no bytes is a run that does not exist, and a reader
    // summing entry lengths would have to special-case it.
    let mut map_bytes = Vec::with_capacity(MAP_ENTRY_LEN);
    if size > 0 {
        map_bytes.extend_from_slice(&0u64.to_le_bytes());
        map_bytes.extend_from_slice(&size.to_le_bytes());
        map_bytes.extend_from_slice(&target_offset.to_le_bytes());
        map_bytes.extend_from_slice(&0u32.to_le_bytes());
    }

    let mut idx_bytes = Vec::with_capacity(stream_arn.len() + 1);
    idx_bytes.extend_from_slice(stream_arn.as_bytes());
    idx_bytes.push(b'\n');

    // mapPath is empty for a single-volume acquisition, and present so
    // `mapPathHash` has a defined input rather than being absent.
    //
    // The four map segment digests are recorded here; **the block map digest is
    // not, and cannot be.** AFF4 Standard v1.0a §6.2 composes it from "all
    // BlockHashes in the ImageStream", and this map's stream is shared with
    // every other file in the band — its `blockHashesHash` is not known until
    // the acquisition ends, long after this file's map is written, and its value
    // describes every file's chunks rather than this file's.
    //
    // A per-file digest composed from the whole shared stream would be
    // identical for every file in the band while appearing to attest each one
    // individually, which is worse than its absence. Each file's own `aff4:hash`
    // covers its bytes, and the shared stream's block hashes cover the storage,
    // so nothing here is unattested.
    let _ = write_map_segments(writer, &base, file_arn, &map_bytes, &idx_bytes, &[])?;

    let lexicon = crate::lexicon::STANDARD;
    let graph = writer.graph_mut();
    graph.add_type(file_arn, &lexicon.iri(lexicon.map));
    graph.add(
        file_arn,
        &lexicon.iri(lexicon.dependent_stream),
        TurtleTerm::iri(stream_arn),
    );
    // The inverse edge AFF4 Standard v1.0a §2.2 puts on a stream, letting a
    // consumer given the stream find a map that assembles it. Many files share
    // this stream, so it accumulates one per file — which is correct: each is a
    // parent of some part of it.
    graph.add(
        stream_arn,
        &lexicon.iri(lexicon.target),
        TurtleTerm::iri(file_arn),
    );

    Ok(())
}

/// Write a Map over an image stream this file alone uses.
///
/// AFF4-L v1.0-ALPHA §6.3's first example: one subject typed both
/// `aff4:FileImage` and `aff4:Map`, naming the stream that holds its bytes.
///
/// # Why this exists beside [`write_shared_map`]
///
/// The two write the same triples and differ in one fact about the stream.
/// AFF4-L v1.0-ALPHA §6.3 lets several files share one `ImageStream`; when they
/// do, AFF4 Standard v1.0a §6.2's block map digest cannot be computed per file,
/// because its first term is over every block hash in the stream and would
/// therefore describe the whole band. When the stream holds one file, that term
/// describes that file, and AFF4-L v1.0-ALPHA §6.3.1's MUST is satisfiable.
///
/// `block_hashes` is the stream's own per-chunk digests, from
/// [`crate::write::stream_writer::write_image_stream_as`]. Empty means the
/// stream recorded none, and no block map digest is written; AFF4-L
/// v1.0-ALPHA §6.3.1 cannot be met without them, which is a caller error rather
/// than something to paper over here.
///
/// # The file ARN is the Map, unless `indirect`
///
/// As in [`write_shared_map`], the direct form makes the file ARN the Map's
/// own subject. AFF4-L v1.0-ALPHA §6.3's second form instead gives the Map a
/// fresh subject and reaches it from the file through `aff4l:dataStream`;
/// `indirect` selects that form. `record_large_file` records what happened
/// when a logical file's stream was given its own ARN joined by
/// `aff4:dataStream`: the subject read as a `DiskImage` naming a Map, and this
/// project's reader looked for `map` and `idx` members a logical file does not
/// have.
///
/// The indirect form also records `aff4:size` on the minted Map subject, which
/// AFF4 Standard v1.0a §4 requires of every Map. The direct form needs no such
/// triple, because the caller already recorded the size on the file subject and
/// that subject is the Map; the indirect form's Map is a subject of its own, and
/// a Map without a size declares no extent and cannot be resolved at all.
///
/// `namespace_https` selects which `aff4l` namespace the indirect form's
/// `dataStream` predicate takes, between AFF4-L v1.0-ALPHA §4.1's two
/// readings; see `LogicalOptions::namespace_https`. Ignored when `indirect`
/// is false, since the direct form writes no such predicate.
///
/// # Errors
///
/// [`Error::Malformed`](crate::error::Error::Malformed) when `file_arn` names
/// no member of the volume being written.
#[allow(clippy::too_many_arguments)]
pub fn write_own_map(
    writer: &mut ContainerWriter,
    file_arn: &str,
    stream_arn: &str,
    size: u64,
    block_hashes: &[crate::write::stream_writer::BlockHashDigest],
    indirect: bool,
    namespace_https: bool,
    locus: &crate::error::Locus,
) -> Result<()> {
    let volume = writer.volume_arn().clone();
    let volume_arn = volume.as_str().to_owned();

    let mapping = writer.name_mapping();
    let base = crate::arn::Arn::parse(file_arn, locus)?
        .member_name(&volume, mapping)
        .ok_or_else(|| {
            crate::error::Error::malformed(
                locus.clone(),
                format!("file {file_arn} names no member of volume {volume_arn}"),
            )
        })?;

    // AFF4 Standard v1.0a §4: one entry covering the whole file, since this
    // stream holds nothing else. A zero-length file gets an empty map, as in
    // `write_shared_map`: an entry covering no bytes is a run that does not
    // exist.
    let mut map_bytes = Vec::with_capacity(MAP_ENTRY_LEN);
    if size > 0 {
        map_bytes.extend_from_slice(&0u64.to_le_bytes());
        map_bytes.extend_from_slice(&size.to_le_bytes());
        map_bytes.extend_from_slice(&0u64.to_le_bytes());
        map_bytes.extend_from_slice(&0u32.to_le_bytes());
    }

    let mut idx_bytes = Vec::with_capacity(stream_arn.len() + 1);
    idx_bytes.extend_from_slice(stream_arn.as_bytes());
    idx_bytes.push(b'\n');

    let lexicon = crate::lexicon::STANDARD;
    // Which subject is the Map. In the direct form the file is the Map, so one
    // subject carries both types. In the indirect form the Map is its own
    // subject and the file points at it.
    let map_arn = if indirect {
        // A fresh GUID ARN, exactly as `arn_for_entry` mints one for a file
        // under `LogicalProfile::V1Alpha`. `new_uuid` renders lower case, which
        // AFF4-L v1.0-ALPHA §2 requires, and returns `Error::Io` rather than
        // falling back if the OS entropy source is unavailable: a predictable
        // or colliding object name is unrecoverable confusion about which
        // evidence is which.
        let minted = format!(
            "aff4://{}",
            crate::write::container_writer::new_uuid(writer.path())?
        );
        let namespace = crate::lexicon::namespace_for(
            crate::lexicon::Generation::Aff4L10,
            "dataStream",
            namespace_https,
        );
        writer.graph_mut().add(
            file_arn,
            &format!("{namespace}dataStream"),
            TurtleTerm::iri(&minted),
        );
        minted
    } else {
        file_arn.to_owned()
    };

    // The **segment base name** stays derived from the file in the direct
    // form, since the file subject and the Map subject are the same object
    // there. In the indirect form the segments belong to the Map's own
    // subject, so the base is derived from it instead.
    let segment_base = if indirect {
        crate::arn::Arn::parse(&map_arn, locus)?
            .member_name(&volume, mapping)
            .ok_or_else(|| {
                crate::error::Error::malformed(
                    locus.clone(),
                    format!("map {map_arn} names no member of volume {volume_arn}"),
                )
            })?
    } else {
        base
    };

    let (map_digests, _recorded) =
        write_map_segments(writer, &segment_base, &map_arn, &map_bytes, &idx_bytes, &[])?;

    // The digest AFF4-L v1.0-ALPHA §6.3.1 requires, which the shared band
    // cannot carry. In the direct form one subject is both the image and the
    // map, so it is named for both roles; in the indirect form the image is
    // still the file and the map is the fresh subject minted above.
    let _ = write_block_map_digest(writer, &map_arn, file_arn, block_hashes, &map_digests);

    let graph = writer.graph_mut();
    graph.add_type(&map_arn, &lexicon.iri(lexicon.map));
    // AFF4 Standard v1.0a §4 requires every Map to declare its own `aff4:size`,
    // which is how a reader decides what the map covers. In the direct form the
    // file subject *is* the Map and the caller already recorded the size there.
    // In the indirect form the Map is a subject of its own, so without this the
    // Map declares no size and cannot be resolved at all — the container would
    // verify as malformed.
    if indirect {
        graph.add(
            &map_arn,
            &lexicon.iri(lexicon.size),
            TurtleTerm::typed(size.to_string(), XSD_LONG),
        );
    }
    graph.add(
        &map_arn,
        &lexicon.iri(lexicon.dependent_stream),
        TurtleTerm::iri(stream_arn),
    );
    // The inverse edge AFF4 Standard v1.0a §2.2 puts on a stream. One file
    // uses this stream, so exactly one `aff4:target` accumulates here, unlike
    // the band's one per file.
    graph.add(
        stream_arn,
        &lexicon.iri(lexicon.target),
        TurtleTerm::iri(&map_arn),
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
            block_algorithm: None,
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
            &[],
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
        let image = crate::image::Image::open_in_set(
            &arn,
            container.volumes_mut(),
            lexicon,
            crate::arn::NameMapping::Escaped,
            &locus,
        )
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

    /// A multi-part set's `DiskImage` is shared across parts, so its ARN cannot be
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
            &[],
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

    /// v1.0a §2.2 lists `target` on `ImageStream` as a "backwards pointer to the
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
            &[],
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
        // another volume — a multi-part set's normal case.
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
            &[],
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
