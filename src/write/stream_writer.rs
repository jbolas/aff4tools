//! Writing a bytestream into an AFF4 `ImageStream`.
//!
//! Reads a source in `chunk_size` pieces, packs them into bevies, queues each
//! bevy and its index as ZIP members, and records the stream's metadata in the
//! volume graph.
//!
//! # Digests are computed from the bytes written
//!
//! The linear hashes are fed from the same buffers that go into the chunker, in
//! one pass. Nothing is re-read to hash it, and no digest is copied from a
//! source container: a recorded hash must describe what this writer actually
//! stored, or it is worse than no hash at all.

use std::io::Read;

use crate::codec::Codec;
use crate::error::{Locus, Result};
use crate::hash::MultiHasher;
use crate::model::HashAlgorithm;
use crate::write::bevy::{BevyBuilder, bevy_block_hash_name, bevy_index_name, bevy_name};
use crate::write::container_writer::ContainerWriter;
use crate::write::turtle::{TurtleTerm, XSD_INT, XSD_LONG};

/// How a stream should be chunked and compressed.
#[derive(Debug, Clone, Copy)]
pub struct StreamOptions {
    /// Bytes per chunk.
    pub chunk_size: usize,
    /// Chunks per bevy.
    pub chunks_per_segment: usize,
    /// The codec applied to each chunk.
    pub codec: Codec,
    /// Whether to write per-chunk block hashes.
    ///
    /// On by default: without them a container's composite digests establish
    /// that the stream is intact in aggregate but not that any individual
    /// chunk is, which is what `verify`'s "leaves to root" claim rests on.
    pub block_hashes: bool,
}

impl Default for StreamOptions {
    /// pyaff4 and c-aff4's shared defaults, with LZ4 — measured fastest on
    /// real evidence.
    fn default() -> Self {
        Self {
            chunk_size: crate::write::bevy::DEFAULT_CHUNK_SIZE,
            chunks_per_segment: crate::write::bevy::DEFAULT_CHUNKS_PER_SEGMENT,
            codec: Codec::Lz4,
            block_hashes: true,
        }
    }
}

/// What one written stream turned out to be.
#[derive(Debug, Clone)]
pub struct WrittenStream {
    /// The stream's ARN.
    pub arn: String,
    /// Bytes read from the source.
    pub size: u64,
    /// Bevies written.
    pub bevy_count: u64,
    /// Digests computed over the source bytes, in one pass.
    pub digests: Vec<crate::hash::Digest>,
    /// The `blockHashesHash` recorded for each block-hash segment.
    ///
    /// Reported so an acquisition log can show every digest it wrote rather
    /// than only the stream's own: these are recorded in the container and
    /// recomputed by `verify`, so printing two of four made the log look
    /// inconsistent with the verdict.
    pub block_hash_digests: Vec<BlockHashDigest>,
}

/// The SHA-512 recorded over one block-hash segment.
#[derive(Debug, Clone)]
pub struct BlockHashDigest {
    /// The object's ARN, e.g. `<stream>/blockhash.md5`.
    pub arn: String,
    /// The algorithm whose per-chunk digests the segment holds (`md5`, `sha1`).
    pub holds: String,
    /// The recorded digest, lowercase hex.
    pub hex: String,
}

/// Write `source` into `writer` as an `ImageStream`, returning what was stored.
///
/// `algorithms` are computed over the stream's bytes and recorded as
/// `aff4:hash`. AFF4-L 2019 §3.7 uses SHA-1 and MD5; physical acquisition
/// conventionally uses SHA-256 and MD5. The caller chooses.
///
/// The stream is named `<volume>/data`, which is the single-image case. A
/// logical acquisition holds many streams in one volume and must name each
/// distinctly — see [`write_image_stream_as`].
///
/// # Errors
///
/// [`Error::Io`](crate::error::Error::Io) on a read or write failure;
/// [`Error::Unsupported`](crate::error::Error::Unsupported) for a codec this
/// build declines to write.
pub fn write_image_stream(
    writer: &mut ContainerWriter,
    source: &mut dyn Read,
    options: StreamOptions,
    algorithms: &[HashAlgorithm],
    locus: &Locus,
) -> Result<WrittenStream> {
    let stream_arn = format!("{}/data", writer.volume_arn().as_str());
    write_image_stream_as(writer, &stream_arn, source, options, algorithms, locus)
}

/// Write `source` as an `ImageStream` named `stream_arn`.
///
/// The ARN is the caller's because a volume may hold many streams: AFF4-L
/// stores one per file above the AFF4-L 2019 §3.3 threshold, and they would
/// collide on the
/// `<volume>/data` name [`write_image_stream`] uses.
///
/// # Errors
///
/// As [`write_image_stream`], plus [`Error::Malformed`](crate::error::Error::Malformed)
/// if `stream_arn` names no member of the volume.
pub fn write_image_stream_as(
    writer: &mut ContainerWriter,
    stream_arn: &str,
    source: &mut dyn Read,
    options: StreamOptions,
    algorithms: &[HashAlgorithm],
    locus: &Locus,
) -> Result<WrittenStream> {
    write_image_stream_observed(
        writer,
        stream_arn,
        source,
        options,
        algorithms,
        &mut |_, _| {},
        locus,
    )
}

/// Write a stream, reporting progress as bytes are consumed.
///
/// `progress` is called with `(bytes read, bevies written)` after each bevy is
/// flushed. Use this for anything that might take minutes: a device acquisition
/// is silent for hours otherwise, and silence is indistinguishable from a hang.
///
/// The callback fires per bevy — every 32 MiB at the defaults — rather than per
/// chunk, so it costs nothing measurable. Rate limiting is the caller's job;
/// `ProgressReporter` in the binary repaints at most four times a second.
///
/// # Errors
///
/// As [`write_image_stream_as`].
pub fn write_image_stream_observed(
    writer: &mut ContainerWriter,
    stream_arn: &str,
    source: &mut dyn Read,
    options: StreamOptions,
    algorithms: &[HashAlgorithm],
    progress: &mut dyn FnMut(u64, u64),
    locus: &Locus,
) -> Result<WrittenStream> {
    let volume = writer.volume_arn().clone();
    let volume_arn = volume.as_str().to_owned();
    let stream_arn = stream_arn.to_owned();
    // Derive the member path with the *reader's* own mapping, so the names we
    // write are by construction the names it will look for. Re-implementing the
    // escaping here would be a second source of truth, and the two could drift.
    let parsed = crate::arn::Arn::parse(&stream_arn, locus)?;
    let base = parsed.member_name(&volume).ok_or_else(|| {
        crate::error::Error::malformed(
            locus.clone(),
            format!("stream {stream_arn} names no member of volume {volume_arn}"),
        )
    })?;

    let mut hasher = MultiHasher::for_algorithms(algorithms);
    let mut builder = BevyBuilder::new(
        options.codec,
        options.chunk_size,
        options.chunks_per_segment,
    );

    let mut buffer = vec![0u8; options.chunk_size];
    let mut size: u64 = 0;
    let mut bevy_number: u64 = 0;
    // The block-hash segments, kept so their SHA-512 can be recorded as
    // `blockHashesHash` once every bevy is written.
    let mut block_segments = BlockSegments::default();

    loop {
        let filled = read_full(source, &mut buffer, locus)?;
        if filled == 0 {
            break;
        }
        let chunk = &buffer[..filled];
        hasher.update(chunk);
        size += filled as u64;
        builder.push_chunk(chunk, locus)?;

        if builder.is_full() {
            flush_bevy(
                writer,
                &base,
                bevy_number,
                builder.finish(),
                options.block_hashes,
                &mut block_segments,
            )?;
            bevy_number += 1;
            progress(size, bevy_number);
        }

        if filled < options.chunk_size {
            break; // short read means end of stream
        }
    }

    if !builder.is_empty() {
        flush_bevy(
            writer,
            &base,
            bevy_number,
            builder.finish(),
            options.block_hashes,
            &mut block_segments,
        )?;
        bevy_number += 1;
        progress(size, bevy_number);
    }

    let digests = hasher.finish();

    let block_hash_digests = write_stream_metadata(
        writer,
        &stream_arn,
        &volume_arn,
        options,
        size,
        &digests,
        &block_segments,
    );

    Ok(WrittenStream {
        arn: stream_arn,
        size,
        bevy_count: bevy_number,
        digests,
        block_hash_digests,
    })
}

/// What one bounded write produced.
#[derive(Debug, Clone)]
pub struct BoundedOutcome {
    /// Bytes read from the source into this part.
    pub size: u64,
    /// Bevies written into this part.
    pub bevy_count: u64,
    /// The `blockHashesHash` recorded for each block-hash segment.
    pub block_hash_digests: Vec<BlockHashDigest>,
    /// Whether the source ran out, as opposed to the threshold being reached.
    pub source_exhausted: bool,
}

/// Write part of a stream, stopping once `split_after` bytes are on disk.
///
/// Differs from [`write_image_stream_observed`] in two ways, both required for
/// a split set:
///
/// 1. **The hasher is borrowed, never finalized.** One hasher spans every part,
///    so the image digest describes the whole image rather than one part. The
///    caller finalizes it once, after the last part.
/// 2. **It can stop early.** When `split_after` is `Some(n)`, the write ends
///    after the first bevy that leaves the container at or beyond `n` bytes.
///
/// The threshold is measured in **bytes on disk**, via
/// [`ContainerWriter::bytes_written`], not in source bytes. That is what makes
/// parts approximately equal in size regardless of how compressible the source
/// is. It is checked only after a bevy has been flushed whole, so a part never
/// contains a partial bevy.
///
/// No `aff4:hash` is written for the stream: the image's digest belongs to the
/// `DiskImage`, and every byte here is already covered by block hashes.
///
/// # Errors
///
/// As [`write_image_stream_as`].
// Eight parameters, one over clippy's threshold. Grouping them into an options
// struct would only move the same eight values one level down while hiding
// which of them the borrow checker ties together: `writer` and `hasher` are
// distinct mutable borrows the caller must hold across every part of a set.
// `src/verify.rs:752` takes the same view for the same reason.
#[allow(clippy::too_many_arguments)]
pub fn write_image_stream_bounded(
    writer: &mut ContainerWriter,
    stream_arn: &str,
    source: &mut dyn Read,
    options: StreamOptions,
    hasher: &mut MultiHasher,
    split_after: Option<u64>,
    progress: &mut dyn FnMut(u64, u64),
    locus: &Locus,
) -> Result<BoundedOutcome> {
    let volume = writer.volume_arn().clone();
    let volume_arn = volume.as_str().to_owned();
    let stream_arn = stream_arn.to_owned();
    let parsed = crate::arn::Arn::parse(&stream_arn, locus)?;
    let base = parsed.member_name(&volume).ok_or_else(|| {
        crate::error::Error::malformed(
            locus.clone(),
            format!("stream {stream_arn} names no member of volume {volume_arn}"),
        )
    })?;

    let mut builder = BevyBuilder::new(
        options.codec,
        options.chunk_size,
        options.chunks_per_segment,
    );
    let mut buffer = vec![0u8; options.chunk_size];
    let mut size: u64 = 0;
    let mut bevy_number: u64 = 0;
    let mut block_segments = BlockSegments::default();
    let mut source_exhausted = false;
    let mut threshold_reached = false;

    loop {
        let filled = read_full(source, &mut buffer, locus)?;
        if filled == 0 {
            source_exhausted = true;
            break;
        }
        let chunk = &buffer[..filled];
        hasher.update(chunk);
        size += filled as u64;
        builder.push_chunk(chunk, locus)?;

        if builder.is_full() {
            flush_bevy(
                writer,
                &base,
                bevy_number,
                builder.finish(),
                options.block_hashes,
                &mut block_segments,
            )?;
            bevy_number += 1;
            progress(size, bevy_number);

            // The cut point. The bevy, its index, and its block-hash segments
            // have all reached the sink and the builder is empty, so nothing is
            // buffered and the boundary is clean.
            if let Some(target) = split_after
                && writer.bytes_written() >= target
            {
                threshold_reached = true;
            }
        }

        if filled < options.chunk_size {
            source_exhausted = true;
            break;
        }
        if threshold_reached {
            break;
        }
    }

    if !builder.is_empty() {
        flush_bevy(
            writer,
            &base,
            bevy_number,
            builder.finish(),
            options.block_hashes,
            &mut block_segments,
        )?;
        bevy_number += 1;
        progress(size, bevy_number);
    }

    // The stream's own metadata, minus `aff4:hash`: an empty digest slice.
    let block_hash_digests = write_stream_metadata(
        writer,
        &stream_arn,
        &volume_arn,
        options,
        size,
        &[],
        &block_segments,
    );

    Ok(BoundedOutcome {
        size,
        bevy_count: bevy_number,
        block_hash_digests,
        source_exhausted,
    })
}

/// Render bytes as lowercase hex, the form AFF4 records digests in.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Record the stream's metadata and its `BlockHashes` objects.
///
/// Returns the `blockHashesHash` recorded for each block-hash segment, so the
/// caller can report every digest it wrote.
fn write_stream_metadata(
    writer: &mut ContainerWriter,
    stream_arn: &str,
    volume_arn: &str,
    options: StreamOptions,
    size: u64,
    digests: &[crate::hash::Digest],
    block_segments: &BlockSegments,
) -> Vec<BlockHashDigest> {
    let lexicon = crate::lexicon::STANDARD;
    {
        let graph = writer.graph_mut();
        graph.add_type(stream_arn, &lexicon.iri(lexicon.image_stream));
        graph.add(
            stream_arn,
            &lexicon.iri(lexicon.size),
            TurtleTerm::typed(size.to_string(), XSD_LONG),
        );
        // xsd:int for the chunk fields, xsd:long for sizes — exactly Evimetry's
        // split. Both parse identically here; matching removes a gratuitous
        // difference between our containers and the corpus.
        graph.add(
            stream_arn,
            &lexicon.iri(lexicon.chunk_size),
            TurtleTerm::typed(options.chunk_size.to_string(), XSD_INT),
        );
        graph.add(
            stream_arn,
            &lexicon.iri(lexicon.chunks_in_segment),
            TurtleTerm::typed(options.chunks_per_segment.to_string(), XSD_INT),
        );
        graph.add(
            stream_arn,
            &lexicon.iri(lexicon.compression_method),
            TurtleTerm::iri(options.codec.iri()),
        );
        graph.add(
            stream_arn,
            &lexicon.iri(lexicon.stored),
            TurtleTerm::iri(volume_arn),
        );
        for digest in digests {
            graph.add(
                stream_arn,
                &lexicon.iri(lexicon.hash),
                TurtleTerm::typed(digest.hex(), lexicon.iri(&digest.algorithm().to_string())),
            );
        }
    }

    // The BlockHashes objects: one per algorithm, each recording the SHA-512
    // of the concatenation of that algorithm's block-hash segments. This is
    // what `verify` checks to establish the leaves belong to this stream —
    // without it the per-chunk segments are present but unattested.
    let mut recorded = Vec::new();
    if !options.block_hashes {
        return recorded;
    }
    for (algorithm, segments) in [("md5", &block_segments.md5), ("sha1", &block_segments.sha1)] {
        if segments.is_empty() {
            continue;
        }
        let mut hasher = <sha2::Sha512 as sha2::Digest>::new();
        for segment in segments {
            sha2::Digest::update(&mut hasher, segment);
        }
        let digest = hex_lower(&sha2::Digest::finalize(hasher));

        let object_arn = format!("{stream_arn}/blockhash.{algorithm}");
        let graph = writer.graph_mut();
        graph.add_type(&object_arn, &lexicon.iri(lexicon.block_hashes));
        graph.add(
            &object_arn,
            &lexicon.iri(lexicon.hash),
            TurtleTerm::typed(digest.clone(), lexicon.iri("SHA512")),
        );
        recorded.push(BlockHashDigest {
            arn: object_arn,
            holds: algorithm.to_owned(),
            hex: digest,
        });
    }
    recorded
}

/// The block-hash segments written, kept so their SHA-512 can be recorded.
#[derive(Default)]
struct BlockSegments {
    md5: Vec<Vec<u8>>,
    sha1: Vec<Vec<u8>>,
}

/// Queue one finished bevy's members: the body, its index, and — when block
/// hashing is on — its two per-chunk digest segments.
fn flush_bevy(
    writer: &mut ContainerWriter,
    base: &str,
    number: u64,
    bevy: crate::write::bevy::FinishedBevy,
    block_hashes: bool,
    segments: &mut BlockSegments,
) -> Result<()> {
    // The bevy body reaches the file here, not at `finish`. On a multi-gigabyte
    // acquisition that is the difference between bounded memory and holding the
    // whole container in RAM.
    writer.add_stored_segment(&bevy_name(base, number), &bevy.body)?;
    writer.add_stored_segment(&bevy_index_name(base, number), &bevy.index)?;

    if block_hashes {
        writer.add_stored_segment(&bevy_block_hash_name(base, number, "md5"), &bevy.blocks.md5)?;
        writer.add_stored_segment(
            &bevy_block_hash_name(base, number, "sha1"),
            &bevy.blocks.sha1,
        )?;
        // Retained deliberately: `blockHashesHash` is the SHA-512 of every
        // block-hash segment concatenated, so these must outlive the bevy. They
        // are digests — 16 and 20 bytes per chunk — not bulk data.
        segments.md5.push(bevy.blocks.md5);
        segments.sha1.push(bevy.blocks.sha1);
    }
    Ok(())
}

/// Read until `buffer` is full or the source ends.
///
/// `Read::read` may return fewer bytes than asked for without being at the end
/// — a short read from a pipe or a device is normal. Treating one as
/// end-of-stream would silently truncate the evidence, so this loops.
fn read_full(source: &mut dyn Read, buffer: &mut [u8], locus: &Locus) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match source.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(crate::error::Error::io(locus.path.clone(), e)),
        }
    }
    Ok(filled)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::write::guard::SourceRegistry;

    #[test]
    fn read_full_assembles_short_reads() {
        /// A reader that yields one byte at a time, like a slow device.
        struct Dribble(Vec<u8>, usize);
        impl Read for Dribble {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.1 >= self.0.len() {
                    return Ok(0);
                }
                buf[0] = self.0[self.1];
                self.1 += 1;
                Ok(1)
            }
        }

        let mut src = Dribble(vec![7u8; 100], 0);
        let mut buf = vec![0u8; 100];
        let locus = Locus::new("/synthetic");
        assert_eq!(read_full(&mut src, &mut buf, &locus).unwrap(), 100);
        assert!(
            buf.iter().all(|&b| b == 7),
            "a short read must not truncate"
        );
    }

    /// A stream we write must be readable by our own reader, byte-identical.
    #[test]
    fn a_written_stream_reads_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stream.aff4");
        let registry = SourceRegistry::new();
        let locus = Locus::new(&path);

        // Deliberately not a chunk multiple: exercises the padding path that no
        // corpus container covers.
        let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();

        let mut writer = ContainerWriter::create(&path, &registry).unwrap();
        let options = StreamOptions {
            chunk_size: 4096,
            chunks_per_segment: 4,
            codec: Codec::Snappy,
            block_hashes: true,
        };
        let written = write_image_stream(
            &mut writer,
            &mut data.as_slice(),
            options,
            &[HashAlgorithm::Sha256, HashAlgorithm::Md5],
            &locus,
        )
        .unwrap();
        writer.finish().unwrap();

        assert_eq!(written.size, 70_000);
        assert_eq!(written.digests.len(), 2);

        let mut container = crate::container::Container::open(&path).unwrap();
        let summary = container.summarize().unwrap();
        assert!(
            summary.deviations.is_empty(),
            "written stream must be deviation-free: {:#?}",
            summary.deviations
        );
    }

    use crate::hash::MultiHasher;
    use crate::model::HashAlgorithm;

    /// Incompressible bytes, so a threshold in compressed bytes is reached
    /// predictably rather than depending on the codec's ratio.
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

    /// Splitting must not change the digest: one hasher fed across two bounded
    /// calls equals one hasher fed by a single unbounded call.
    #[test]
    fn a_bounded_write_hashes_the_same_bytes_as_an_unbounded_one() {
        let algorithms = [HashAlgorithm::Sha256, HashAlgorithm::Md5];
        let data = incompressible(512 * 1024);
        let options = StreamOptions {
            chunk_size: 32 * 1024,
            chunks_per_segment: 2,
            codec: crate::codec::Codec::Stored,
            block_hashes: true,
        };

        // Whole, in one call.
        let dir_a = tempfile::tempdir().unwrap();
        let registry = SourceRegistry::new();
        let mut w = ContainerWriter::create(&dir_a.path().join("a.aff4"), &registry).unwrap();
        let arn = format!("{}/data", w.volume_arn().as_str());
        let mut whole = MultiHasher::for_algorithms(&algorithms);
        let mut src = &data[..];
        let out = write_image_stream_bounded(
            &mut w,
            &arn,
            &mut src,
            options,
            &mut whole,
            None,
            &mut |_, _| {},
            &Locus::new("a"),
        )
        .unwrap();
        assert!(out.source_exhausted);
        assert_eq!(out.size, data.len() as u64);
        let whole_digests = whole.finish();

        // Split, across two calls, one hasher.
        let dir_b = tempfile::tempdir().unwrap();
        let mut split = MultiHasher::for_algorithms(&algorithms);
        let mut src = &data[..];
        let mut total = 0u64;
        let mut parts = 0;
        loop {
            let path = dir_b.path().join(format!("b_{parts:03}.aff4"));
            let mut w = ContainerWriter::create(&path, &registry).unwrap();
            let arn = format!("{}/data", w.volume_arn().as_str());
            let out = write_image_stream_bounded(
                &mut w,
                &arn,
                &mut src,
                options,
                &mut split,
                Some(64 * 1024),
                &mut |_, _| {},
                &Locus::new("b"),
            )
            .unwrap();
            total += out.size;
            parts += 1;
            w.finish().unwrap();
            if out.source_exhausted {
                break;
            }
            assert!(parts < 100, "threshold never advanced");
        }
        let split_digests = split.finish();

        assert_eq!(total, data.len() as u64);
        assert!(parts > 1, "the threshold must have produced several parts");
        assert_eq!(
            whole_digests
                .iter()
                .map(|d| d.hex().to_owned())
                .collect::<Vec<_>>(),
            split_digests
                .iter()
                .map(|d| d.hex().to_owned())
                .collect::<Vec<_>>(),
            "splitting changed the digest"
        );
    }

    /// The cut lands only after a whole bevy, so a part never holds a partial
    /// bevy and the file always exceeds the threshold rather than falling short.
    #[test]
    fn the_cut_lands_after_a_whole_bevy() {
        let algorithms = [HashAlgorithm::Sha256];
        let data = incompressible(512 * 1024);
        let options = StreamOptions {
            chunk_size: 32 * 1024,
            chunks_per_segment: 2,
            codec: crate::codec::Codec::Stored,
            block_hashes: false,
        };
        let dir = tempfile::tempdir().unwrap();
        let registry = SourceRegistry::new();
        let mut hasher = MultiHasher::for_algorithms(&algorithms);
        let mut src = &data[..];
        let mut w = ContainerWriter::create(&dir.path().join("c.aff4"), &registry).unwrap();
        let arn = format!("{}/data", w.volume_arn().as_str());
        let out = write_image_stream_bounded(
            &mut w,
            &arn,
            &mut src,
            options,
            &mut hasher,
            Some(64 * 1024),
            &mut |_, _| {},
            &Locus::new("c"),
        )
        .unwrap();

        assert!(!out.source_exhausted, "the source should not be exhausted");
        // Whole bevies only: 2 chunks x 32 KiB.
        assert_eq!(out.size % (64 * 1024), 0);
        assert!(w.bytes_written() >= 64 * 1024);
    }
}
