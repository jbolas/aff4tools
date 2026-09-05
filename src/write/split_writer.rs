//! Writing one image across several `.aff4` parts.
//!
//! A **part** is one file of a split set; a **segment** is a member inside a
//! volume (`docs/glossary.md`). This module writes *split* sets —
//! sequential, non-striped — which are the special case of v1.0a §7.1 where map
//! entries are monotonic and each part holds one stream.
//!
//! # What makes the parts one image
//!
//! Every part declares the same `aff4:DiskImage`, which v1.0a §7.1 calls the
//! point of
//! commonality. Part 001 additionally holds the Map naming every part's stream,
//! so a reader that opens it learns the whole layout. Parts 002..N hold a stub
//! declaring only their own stream, which is the minimum v1.0a §3 requires of a
//! volume containing an Image Stream (lines 142, 152, 154).
//!
//! # Why not replicate the full graph
//!
//! Evimetry writes the whole graph into every volume of a striped set, because
//! its parallel writers each know the acquisition plan in advance. A sequential
//! writer does not, and a 10M-object acquisition has ~7.5 GB of Turtle
//! (`docs/RDF-scalability.md`) — replicated 16 ways, that is 120 GB of metadata
//! for 16 GB of evidence. See the design document for the full comparison.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Error, Locus, Result};
use crate::hash::{Digest, MultiHasher};
use crate::model::HashAlgorithm;
use crate::write::container_writer::ContainerWriter;
use crate::write::guard::SourceRegistry;
use crate::write::map_writer::{MapEntry, write_map_as};
use crate::write::stream_writer::{StreamOptions, write_image_stream_bounded};
use crate::write::turtle::TurtleTerm;

/// The largest part number a three-digit name can express.
pub const MAX_PARTS: u32 = 999;

/// How a split set should be written.
#[derive(Debug, Clone, Copy)]
pub struct SplitOptions {
    /// Chunking and compression, shared by every part.
    pub stream: StreamOptions,
    /// Start a new part once the current one reaches this many bytes on disk.
    pub split_after: u64,
}

/// One written part.
#[derive(Debug, Clone)]
pub struct WrittenPart {
    /// Where it was written.
    pub path: PathBuf,
    /// Its volume ARN.
    pub volume_arn: String,
    /// The ARN of the stream it holds.
    pub stream_arn: String,
    /// Source bytes stored in it.
    pub size: u64,
    /// Bevies written into it.
    pub bevy_count: u64,
}

/// What a whole split set turned out to be.
#[derive(Debug, Clone)]
pub struct WrittenSet {
    /// Every part, in order.
    pub parts: Vec<WrittenPart>,
    /// The shared `aff4:DiskImage` ARN.
    pub image_arn: String,
    /// The Map's ARN, which lives in part 001.
    pub map_arn: String,
    /// Total source bytes across the set.
    pub total_size: u64,
    /// Digests over the whole image, computed once.
    pub digests: Vec<Digest>,
}

/// The path of part `number`, derived from the base output name.
///
/// Three digits, fixed width, so plain lexicographic sort is correct.
#[must_use]
pub fn part_path(output: &Path, number: u32) -> PathBuf {
    let stem = output
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("evidence");
    let ext = output
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("aff4");
    let name = format!("{stem}_{number:03}.{ext}");
    output
        .parent()
        .map_or_else(|| PathBuf::from(&name), |parent| parent.join(&name))
}

/// Refuse a source that could need more than [`MAX_PARTS`] parts.
///
/// The estimate is the worst case — no compression at all — so this never
/// fails partway through an acquisition. It is deliberately conservative: a
/// compressible source that would in fact have fit is refused, and the message
/// names the smallest threshold that is guaranteed to work.
///
/// # Errors
///
/// [`Error::Malformed`] when the worst case exceeds [`MAX_PARTS`].
pub fn preflight(source_size: u64, split_after: u64, locus: &Locus) -> Result<()> {
    if split_after == 0 {
        return Err(Error::malformed(
            locus.clone(),
            "the split threshold must be greater than zero",
        ));
    }
    let worst_case = source_size.div_ceil(split_after);
    if worst_case > u64::from(MAX_PARTS) {
        let needed = source_size.div_ceil(u64::from(MAX_PARTS));
        let suggestion = (needed.next_power_of_two() / (1 << 30)).max(1);
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "this source could need up to {worst_case} parts at the chosen \
                 --split-file size, but part numbering is limited to {MAX_PARTS}. \
                 Use --split-file {suggestion}G or larger."
            ),
        ));
    }
    Ok(())
}

/// Write `source` across as many parts as the threshold requires.
///
/// # Errors
///
/// [`Error::Malformed`] if the pre-flight check refuses the source or a target
/// path is unusable; [`Error::Io`] on a read or write failure.
// Eight parameters, one over clippy's threshold, for the reason
// `write_image_stream_bounded` gives: `source`, `registry`, and `progress` are
// distinct borrows the caller holds separately, and an options struct would
// move the same eight values one level down while hiding that.
#[allow(clippy::too_many_arguments)]
pub fn write_split_set(
    output: &Path,
    source: &mut dyn Read,
    source_size: u64,
    options: SplitOptions,
    algorithms: &[HashAlgorithm],
    registry: &SourceRegistry,
    progress: &mut dyn FnMut(u64, u64),
    locus: &Locus,
) -> Result<WrittenSet> {
    preflight(source_size, options.split_after, locus)?;

    // Minted before anything is written: every part refers to these, and the
    // shared DiskImage is what makes the parts one image (v1.0a §7.1).
    let image_arn = format!(
        "aff4://{}",
        crate::write::container_writer::new_uuid(output)?
    );

    // Part 001 stays open to the end, because its Map cannot be written until
    // every part's length is known. Every other part closes immediately.
    let first_path = part_path(output, 1);
    let mut first = ContainerWriter::create(&first_path, registry)?;
    let map_arn = format!("{}/map", first.volume_arn().as_str());
    // Captured before the loop: every stub needs it to say which volume holds
    // the map, and `first` is mutably borrowed inside.
    let map_volume_arn = first.volume_arn().as_str().to_owned();

    let mut hasher = MultiHasher::for_algorithms(algorithms);
    let mut parts: Vec<WrittenPart> = Vec::new();
    let mut entries: Vec<MapEntry> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    let mut total: u64 = 0;
    let mut number: u32 = 1;

    // Exhaustion is checked BEFORE a part is created, never after. Creating a
    // part and then discovering the source was already spent would leave a
    // truncated ZIP on disk: `WriteSink` wraps a `BufWriter`, which flushes on
    // drop, and neither it nor `ContainerWriter` implements `Drop` to clean up.
    // The result would be a part file with members but no central directory,
    // sitting beside valid evidence.
    let mut pending: Option<Vec<u8>> = None;

    loop {
        // Part 001 is already open; later parts are created here — but only
        // once a peek has proved there are bytes left to put in them.
        if number > 1 {
            let mut probe = [0u8; 1];
            let got = source
                .read(&mut probe)
                .map_err(|e| Error::io(output.to_path_buf(), e))?;
            if got == 0 {
                break;
            }
            pending = Some(probe[..got].to_vec());
        }

        let mut later = if number == 1 {
            None
        } else {
            Some(ContainerWriter::create(
                &part_path(output, number),
                registry,
            )?)
        };
        let writer = later.as_mut().unwrap_or(&mut first);

        let volume_arn = writer.volume_arn().as_str().to_owned();
        let stream_arn = format!("{volume_arn}/data");

        // The peeked byte must lead the part's data, or it would be lost.
        let mut chained;
        let feed: &mut dyn Read = match pending.take() {
            Some(head) => {
                chained = Read::chain(std::io::Cursor::new(head), &mut *source);
                &mut chained
            }
            None => source,
        };

        let outcome = write_image_stream_bounded(
            writer,
            &stream_arn,
            feed,
            options.stream,
            &mut hasher,
            Some(options.split_after),
            // `write_image_stream_bounded` reports bytes within this part, so
            // add the running total or the display resets at every boundary.
            &mut |done, bevies| progress(total + done, bevies),
            locus,
        )?;

        entries.push(MapEntry {
            mapped_offset: total,
            length: outcome.size,
            target_offset: 0,
            target_id: u32::try_from(targets.len()).map_err(|_| {
                Error::malformed(locus.clone(), "too many parts for a map target id")
            })?,
        });
        targets.push(stream_arn.clone());
        total += outcome.size;

        parts.push(WrittenPart {
            path: part_path(output, number),
            volume_arn,
            stream_arn,
            size: outcome.size,
            bevy_count: outcome.bevy_count,
        });

        let exhausted = outcome.source_exhausted;

        // Later parts close as soon as their stub is written; nothing in a stub
        // depends on a part that comes after it.
        if let Some(mut writer) = later {
            write_stub(&mut writer, &image_arn, &map_arn, &map_volume_arn);
            writer.finish()?;
        }

        if exhausted {
            break;
        }

        number = next_part_number(number, locus)?;
    }

    declare_foreign_streams(&mut first, &parts, &map_arn);

    // One finalize, for the whole image.
    let digests = hasher.finish();

    finish_first_part(
        first, &map_arn, &image_arn, &entries, &targets, total, &digests, locus,
    )?;

    Ok(WrittenSet {
        parts,
        image_arn,
        map_arn,
        total_size: total,
        digests,
    })
}

/// Declare, in part 001, every stream that lives in a later part.
///
/// v1.0a §7.1: a reference must be resolvable. Part 001's map depends on streams
/// living in other parts, so it declares each one — type, the volume that holds
/// it, and what it targets. This is the shape Evimetry writes for a foreign
/// stream in `Base-Linear_1.aff4`, and it is what lets a reader follow the
/// reference without every part carrying the whole graph.
///
/// `parts[0]` is part 001 itself, whose stream is already fully described by
/// [`write_image_stream_bounded`], so it is skipped.
fn declare_foreign_streams(first: &mut ContainerWriter, parts: &[WrittenPart], map_arn: &str) {
    let lexicon = crate::lexicon::STANDARD;
    let graph = first.graph_mut();
    for part in parts.iter().skip(1) {
        graph.add_type(&part.stream_arn, &lexicon.iri(lexicon.image_stream));
        graph.add(
            &part.stream_arn,
            &lexicon.iri(lexicon.stored),
            TurtleTerm::iri(&part.volume_arn),
        );
        graph.add(
            &part.stream_arn,
            &lexicon.iri(lexicon.target),
            TurtleTerm::iri(map_arn),
        );
    }
}

/// The number of the part after `number`, refusing anything past [`MAX_PARTS`].
///
/// `preflight` already rejected a source whose worst case exceeds the limit, so
/// reaching here means the source grew or read longer than its declared size.
/// Refusing is still right: a fourth digit would break the fixed-width naming
/// that makes plain lexicographic order correct.
fn next_part_number(number: u32, locus: &Locus) -> Result<u32> {
    let next = number
        .checked_add(1)
        .ok_or_else(|| Error::malformed(locus.clone(), "part number overflowed"))?;
    if next > MAX_PARTS {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "this source needs more than {MAX_PARTS} parts; \
                 use a larger --split-file size"
            ),
        ));
    }
    Ok(next)
}

/// Write part 001's Map and the image digest, then close it.
///
/// Split out of [`write_split_set`] because it can only run once every part's
/// length is known, which is why part 001 stays open to the end.
// Eight parameters, one over clippy's threshold; every one is a distinct fact
// about the finished set that only the caller has.
#[allow(clippy::too_many_arguments)]
fn finish_first_part(
    mut first: ContainerWriter,
    map_arn: &str,
    image_arn: &str,
    entries: &[MapEntry],
    targets: &[String],
    total: u64,
    digests: &[Digest],
    locus: &Locus,
) -> Result<()> {
    // The Map goes in part 001, naming every part's stream.
    write_map_as(
        &mut first, map_arn, image_arn, entries, targets, total, locus,
    )?;

    // The image digest belongs to the DiskImage, not to any one stream.
    let lexicon = crate::lexicon::STANDARD;
    {
        let graph = first.graph_mut();
        for digest in digests {
            graph.add(
                image_arn,
                &lexicon.iri(lexicon.hash),
                // The same construction `write_stream_metadata` uses
                // (`src/write/stream_writer.rs`), so a split set's digests are
                // typed identically to a single-file container's.
                TurtleTerm::typed(digest.hex(), lexicon.iri(&digest.algorithm().to_string())),
            );
        }
        // No `aff4:size` here: `write_map_as` already wrote it on the image
        // from the same `total`. `TurtleWriter::add` appends without
        // deduplicating (`src/write/turtle.rs`), so a second call would emit
        // the triple twice.
    }

    first.finish()
}

/// Write the stub graph for a part after the first.
///
/// The stream's own declaration is already in the graph, written by
/// [`write_image_stream_bounded`]. This adds only what identifies the part as
/// belonging to the set: the shared `DiskImage` (v1.0a §7.1's point of
/// commonality)
/// and the Map the stream targets.
fn write_stub(writer: &mut ContainerWriter, image_arn: &str, map_arn: &str, map_volume_arn: &str) {
    let lexicon = crate::lexicon::STANDARD;
    let stream_arn = format!("{}/data", writer.volume_arn().as_str());
    let graph = writer.graph_mut();

    graph.add_type(image_arn, &lexicon.iri(lexicon.disk_image));
    graph.add(
        &stream_arn,
        &lexicon.iri(lexicon.target),
        TurtleTerm::iri(map_arn),
    );

    // The map lives in part 001. Declaring it here — type and volume, nothing
    // more — is what makes this part's `aff4:target` resolvable. No size, no
    // hashes, no `dependentStream`: a stub must not grow with the set.
    graph.add_type(map_arn, &lexicon.iri(lexicon.map));
    graph.add(
        map_arn,
        &lexicon.iri(lexicon.stored),
        TurtleTerm::iri(map_volume_arn),
    );
}
