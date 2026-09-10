//! One `ImageStream` shared by many files, each addressed by its own Map.
//!
//! This module cites the AFF4-L Standard v1.0-ALPHA unless it names another
//! document.
//!
//! # Shared, but not deduplicated
//!
//! [`crate::write::dedupe::ChunkPool`] also appends many files into one stream,
//! and the two are not interchangeable. The pool matches each chunk against
//! every chunk it has already stored and writes it once; this appends every
//! chunk unconditionally. Two files with identical content are stored twice
//! here and once there.
//!
//! That difference is what keeps this conformant. Deduplication emits
//! AFF4-L 2019 §4 constructs no standard defines, so a deduplicated container
//! never reaches zero deviations. The AFF4-L v1.0-ALPHA §6.3 shared stream is
//! ordinary AFF4 Standard v1.0a machinery — an `ImageStream` and a `Map` over
//! it — and conforms exactly.
//!
//! **The distinction is deliberately two types rather than one type with a
//! flag.** What a container stores is not a detail to thread a boolean through:
//! a later reader of either type must be able to see which storage policy
//! applies without tracing a parameter back to its caller.
//!
//! # Why sharing a stream is worth anything
//!
//! A file in its own stream pays for a bevy that is mostly empty: at the
//! defaults a bevy spans 32 MiB, so a 20 MiB file wastes most of one and still
//! costs the ZIP members that carry it. Packing consecutive files into one
//! stream spends that rounding waste once for the acquisition instead of once
//! per file.
//!
//! The saving shrinks as files grow, which is what
//! [`COMMONMAP_THRESHOLD`](crate::write::logical::COMMONMAP_THRESHOLD) marks:
//! above it a file's own rounding waste is a rounding error, and its own stream
//! costs less metadata than a map over a shared one. See
//! `docs/working/storage-stream-study.md`.
//!
//! # Memory
//!
//! Bevies are written as they fill, never accumulated. A file's bytes pass
//! through one chunk-sized buffer, so an acquisition of any size holds one
//! bevy's worth of compressed output at a time. `ChunkPool` cannot do this — it
//! must retain every unique chunk to compare against — which is the second
//! reason these are separate types.

use crate::error::{Locus, Result};
use crate::hash::MultiHasher;
use crate::model::HashAlgorithm;
use crate::write::bevy::BevyBuilder;
use crate::write::container_writer::ContainerWriter;
use crate::write::stream_writer::{BlockHashDigest, BlockSegments, StreamOptions};

/// Where one file's bytes landed in the shared stream.
///
/// A file occupies a contiguous byte range, so one of these becomes one map
/// entry rather than one per chunk.
#[derive(Debug, Clone)]
pub struct SharedPlacement {
    /// The file's first byte, as an offset into the shared stream.
    pub offset: u64,
    /// Bytes actually read from the source.
    pub size: u64,
    /// Digests over the file's own bytes, in the caller's chosen algorithms.
    pub digests: Vec<crate::hash::Digest>,
}

/// What the shared stream turned out to be, once every file has been appended.
#[derive(Debug, Clone)]
pub struct SharedSummary {
    /// The stream's ARN.
    pub arn: String,
    /// Total bytes stored.
    pub size: u64,
    /// Bevies written.
    pub bevy_count: u64,
    /// The `blockHashesHash` recorded for each block-hash segment.
    pub block_hash_digests: Vec<BlockHashDigest>,
}

/// One `ImageStream` accumulating the content of many files.
///
/// Created once per acquisition, appended to per file, and finished once. The
/// ARN is fixed at construction because a map entry written during `append`
/// names it, so it cannot be chosen later.
pub struct SharedStream {
    /// The stream's ARN.
    arn: String,
    /// The member-name prefix its bevies are written under.
    base: String,
    /// How the stream is chunked and compressed.
    options: StreamOptions,
    /// The bevy being filled.
    builder: BevyBuilder,
    /// Bevies already written.
    bevy_number: u64,
    /// Bytes appended so far, which is also the next file's offset.
    size: u64,
    /// Bytes of the chunk currently being assembled.
    ///
    /// A file's content generally does not end on a chunk boundary, so the next
    /// file's first bytes complete the chunk this one left partly filled.
    /// `BevyBuilder` takes whole chunks only — it pads anything short, treating
    /// it as a stream's final chunk — so the partial chunk is held here and
    /// pushed once it is complete.
    partial: Vec<u8>,
    /// Per-chunk digest segments, retained so `blockHashesHash` can be
    /// computed over them at `finish`.
    block_segments: BlockSegments,
}

impl SharedStream {
    /// A shared stream named `stream_arn`, stored in `writer`'s volume.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`](crate::error::Error::Malformed) if `stream_arn`
    /// names no member of the volume.
    pub fn new(
        writer: &ContainerWriter,
        stream_arn: &str,
        options: StreamOptions,
        locus: &Locus,
    ) -> Result<Self> {
        let volume = writer.volume_arn().clone();
        // The member path comes from the reader's own mapping, so what is
        // written is by construction what the reader will look for.
        let base = crate::arn::Arn::parse(stream_arn, locus)?
            .member_name(&volume, writer.name_mapping())
            .ok_or_else(|| {
                crate::error::Error::malformed(
                    locus.clone(),
                    format!(
                        "stream {stream_arn} names no member of volume {}",
                        volume.as_str()
                    ),
                )
            })?;

        Ok(Self {
            arn: stream_arn.to_owned(),
            base,
            options,
            builder: BevyBuilder::with_block_algorithm(
                options.codec,
                options.chunk_size,
                options.chunks_per_segment,
                options.resolved_block_algorithm(),
            ),
            bevy_number: 0,
            size: 0,
            partial: Vec::with_capacity(options.chunk_size),
            block_segments: BlockSegments::default(),
        })
    }

    /// The stream's ARN, which a file's map entry targets.
    #[must_use]
    pub fn arn(&self) -> &str {
        &self.arn
    }

    /// Bytes appended so far.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Append `source`'s bytes, returning where they landed.
    ///
    /// Digests in `algorithms` are computed over this file's bytes alone, in
    /// the same pass that stores them. Nothing is re-read to hash it.
    ///
    /// **A file is not chunk-aligned.** Its bytes begin wherever the previous
    /// file ended, so a file's first byte generally sits mid-chunk. That is
    /// correct and is what the map entry's `targetOffset` records. Padding each
    /// file to a chunk boundary would reintroduce the rounding waste this form
    /// exists to avoid.
    ///
    /// # Errors
    ///
    /// [`Error::Io`](crate::error::Error::Io) if `source` cannot be read, or if
    /// a bevy cannot be written.
    pub fn append(
        &mut self,
        source: &mut dyn std::io::Read,
        algorithms: &[HashAlgorithm],
        writer: &mut ContainerWriter,
        locus: &Locus,
    ) -> Result<SharedPlacement> {
        let offset = self.size;
        let mut hasher = MultiHasher::for_algorithms(algorithms);
        let mut file_size: u64 = 0;

        // Read in chunk-sized pieces, but push into the bevy builder in
        // whatever amounts keep the builder's chunks full. The builder owns
        // chunk boundaries; this only supplies bytes.
        let mut buffer = vec![0u8; self.options.chunk_size];
        loop {
            let filled = read_full(source, &mut buffer, locus)?;
            if filled == 0 {
                break;
            }
            let bytes = &buffer[..filled];
            hasher.update(bytes);
            file_size += filled as u64;
            self.push(bytes, writer, locus)?;
            if filled < self.options.chunk_size {
                break; // a short read means the source ended
            }
        }

        self.size += file_size;
        Ok(SharedPlacement {
            offset,
            size: file_size,
            digests: hasher.finish(),
        })
    }

    /// Feed bytes into the current bevy, flushing whenever one fills.
    ///
    /// `bytes` may span a chunk boundary, because a file's content begins
    /// wherever the previous file's ended.
    fn push(
        &mut self,
        mut bytes: &[u8],
        writer: &mut ContainerWriter,
        locus: &Locus,
    ) -> Result<()> {
        while !bytes.is_empty() {
            let room = self.options.chunk_size - self.partial.len();
            let take = room.min(bytes.len());
            self.partial.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];

            // Only a complete chunk goes to the builder. Handing it a short one
            // would have it NUL-pad the chunk as though the stream had ended,
            // putting padding in the middle of the shared stream and displacing
            // every byte after it.
            if self.partial.len() == self.options.chunk_size {
                self.builder.push_chunk(&self.partial, locus)?;
                self.partial.clear();
                if self.builder.is_full() {
                    self.flush(writer)?;
                }
            }
        }
        Ok(())
    }

    /// Write the current bevy and start a new one.
    fn flush(&mut self, writer: &mut ContainerWriter) -> Result<()> {
        crate::write::stream_writer::flush_bevy(
            writer,
            &self.base,
            self.bevy_number,
            self.builder.finish(),
            self.options.block_hashes,
            &mut self.block_segments,
        )?;
        self.bevy_number += 1;
        Ok(())
    }

    /// Write the trailing bevy and the stream's own metadata.
    ///
    /// `algorithms` digest the whole shared stream, which is a different claim
    /// from the per-file digests `append` returned: this attests the storage,
    /// those attest each file's content.
    ///
    /// # Errors
    ///
    /// As [`append`](Self::append).
    pub fn finish(
        mut self,
        writer: &mut ContainerWriter,
        stream_digests: &[crate::hash::Digest],
        locus: &Locus,
    ) -> Result<SharedSummary> {
        // Now, and only now, is a short chunk genuinely the stream's last. The
        // builder pads it per AFF4 Standard v1.0a §3.2, and `aff4:size` below
        // records the true length so a reader trims the padding away.
        if !self.partial.is_empty() {
            let partial = std::mem::take(&mut self.partial);
            self.builder.push_chunk(&partial, locus)?;
        }
        if !self.builder.is_empty() {
            self.flush(writer)?;
        }

        let volume_arn = writer.volume_arn().as_str().to_owned();
        let block_hash_digests = crate::write::stream_writer::write_stream_metadata(
            writer,
            &self.arn,
            &volume_arn,
            self.options,
            self.size,
            stream_digests,
            &self.block_segments,
        );

        Ok(SharedSummary {
            arn: self.arn,
            size: self.size,
            bevy_count: self.bevy_number,
            block_hash_digests,
        })
    }
}

/// Read until `buffer` is full or the source ends.
///
/// A short read from a file is normal and is not end-of-stream; treating one as
/// the end would silently truncate the evidence.
fn read_full(source: &mut dyn std::io::Read, buffer: &mut [u8], locus: &Locus) -> Result<usize> {
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

    /// Small chunks and bevies, so a test exercises several of each without
    /// writing megabytes.
    fn test_options() -> StreamOptions {
        StreamOptions {
            chunk_size: 64,
            chunks_per_segment: 4,
            codec: crate::codec::Codec::Stored,
            block_hashes: true,
            block_algorithm: None,
        }
    }

    /// A writer over a throwaway container, with the ARN of a stream in it.
    fn scratch(dir: &std::path::Path) -> (ContainerWriter, String, Locus) {
        let path = dir.join("shared.aff4l");
        let locus = Locus::new(&path);
        let registry = SourceRegistry::new();
        let writer = ContainerWriter::create(&path, &registry).unwrap();
        let arn = format!("{}/shared", writer.volume_arn().as_str());
        (writer, arn, locus)
    }

    /// Identical content from two files is stored twice.
    ///
    /// This is the whole difference from `ChunkPool`, and it is what keeps the
    /// form conformant: the stream is shared, the storage is not elided.
    #[test]
    fn identical_content_is_stored_once_per_file() {
        let dir = tempfile::tempdir().unwrap();
        let (mut writer, arn, locus) = scratch(dir.path());
        let mut shared = SharedStream::new(&writer, &arn, test_options(), &locus).unwrap();

        let content = b"identical content";
        let a = shared
            .append(&mut &content[..], &[], &mut writer, &locus)
            .unwrap();
        let b = shared
            .append(&mut &content[..], &[], &mut writer, &locus)
            .unwrap();

        assert_eq!(a.offset, 0);
        assert_eq!(
            b.offset,
            content.len() as u64,
            "the second copy must be stored after the first, not deduplicated onto it"
        );
        assert_eq!(shared.size(), 2 * content.len() as u64);
    }

    /// A file occupies one unbroken range, so its map is one entry.
    #[test]
    fn one_file_occupies_a_contiguous_run() {
        let dir = tempfile::tempdir().unwrap();
        let (mut writer, arn, locus) = scratch(dir.path());
        let mut shared = SharedStream::new(&writer, &arn, test_options(), &locus).unwrap();

        shared
            .append(&mut &b"first"[..], &[], &mut writer, &locus)
            .unwrap();
        let data = vec![7u8; 500];
        let placed = shared
            .append(&mut data.as_slice(), &[], &mut writer, &locus)
            .unwrap();

        assert_eq!(placed.offset, 5, "it starts where the previous file ended");
        assert_eq!(placed.size, 500);
    }

    /// Files are packed end to end without padding between them.
    ///
    /// The chunk size here is 64 and the first file is 5 bytes, so the second
    /// file starts mid-chunk. Padding each file to a chunk boundary would
    /// reintroduce exactly the rounding waste this form exists to avoid.
    #[test]
    fn files_are_not_padded_to_chunk_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let (mut writer, arn, locus) = scratch(dir.path());
        let mut shared = SharedStream::new(&writer, &arn, test_options(), &locus).unwrap();

        for _ in 0..10 {
            shared
                .append(&mut &b"12345"[..], &[], &mut writer, &locus)
                .unwrap();
        }

        assert_eq!(
            shared.size(),
            50,
            "ten 5-byte files must occupy 50 bytes, not ten padded chunks"
        );
    }

    /// Digests returned by `append` cover that file's bytes, not the stream's.
    #[test]
    fn per_file_digests_cover_only_that_file() {
        use crate::model::HashAlgorithm;
        let dir = tempfile::tempdir().unwrap();
        let (mut writer, arn, locus) = scratch(dir.path());
        let mut shared = SharedStream::new(&writer, &arn, test_options(), &locus).unwrap();

        shared
            .append(&mut &b"preceding content"[..], &[], &mut writer, &locus)
            .unwrap();
        let placed = shared
            .append(
                &mut &b"the subject"[..],
                &[HashAlgorithm::Sha256],
                &mut writer,
                &locus,
            )
            .unwrap();

        let expected = crate::hash::digests_of(b"the subject", &[HashAlgorithm::Sha256]);
        assert_eq!(
            placed.digests[0].hex(),
            expected[0].hex(),
            "the digest must cover the file alone, not what was appended before it"
        );
    }

    /// A file spanning several bevies is still one contiguous run.
    #[test]
    fn a_file_larger_than_a_bevy_stays_contiguous() {
        let dir = tempfile::tempdir().unwrap();
        let (mut writer, arn, locus) = scratch(dir.path());
        let mut shared = SharedStream::new(&writer, &arn, test_options(), &locus).unwrap();

        // Chunk 64, bevy 4 chunks: 1000 bytes spans four bevies.
        let data = vec![0xABu8; 1000];
        let placed = shared
            .append(&mut data.as_slice(), &[], &mut writer, &locus)
            .unwrap();

        assert_eq!(placed.offset, 0);
        assert_eq!(placed.size, 1000);
        let summary = shared.finish(&mut writer, &[], &locus).unwrap();
        assert!(
            summary.bevy_count >= 3,
            "1000 bytes at 256 per bevy must span several, got {}",
            summary.bevy_count
        );
        assert_eq!(summary.size, 1000);
    }

    /// An empty file takes no space and does not disturb the next file.
    #[test]
    fn an_empty_file_occupies_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut writer, arn, locus) = scratch(dir.path());
        let mut shared = SharedStream::new(&writer, &arn, test_options(), &locus).unwrap();

        let empty = shared
            .append(&mut &b""[..], &[], &mut writer, &locus)
            .unwrap();
        let after = shared
            .append(&mut &b"after"[..], &[], &mut writer, &locus)
            .unwrap();

        assert_eq!(empty.size, 0);
        assert_eq!(after.offset, 0, "an empty file must not advance the stream");
    }
}
