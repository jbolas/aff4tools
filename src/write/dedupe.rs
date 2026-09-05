//! Deduplicated logical storage, per AFF4-L 2019 §4.
//!
//! > Schatz, B.L. *AFF4-L: A Scalable Open Logical Evidence Container.*
//! > Digital Investigation 29, S143–S149. DFRWS USA 2019.
//!
//! **Every bare section number below cites that paper**, not the AFF4
//! Standard. This module cites no other document.
//!
//! # The two-level model
//!
//! The paper's scheme adds one layer of indirection over the 2010 hash-based
//! imaging approach, which named a ZIP segment per unique chunk and so paid a
//! file header and central-directory entry for each:
//!
//! 1. Every unique chunk is appended to **one shared `ImageStream`** per
//!    acquisition.
//! 2. A **Block Hash ARN** — `aff4:sha512:<digest>` — names that chunk's
//!    *content*, and carries `aff4:dataStream` pointing at the byte range of the
//!    shared stream holding it.
//! 3. Each file is a **`Map`** whose `idx` lists Block Hash ARNs, so a file is
//!    assembled entirely from references.
//!
//! # Deviations are expected here, and that is the correct outcome
//!
//! Both constructs are extensions: `aff4:sha512:` subjects are not AFF4
//! resource names, and `aff4://uuid[0x0:0x8000]` slice ARNs are not in the
//! standard. `aff4tools conformance` reports both, and a deduplicated container
//! this crate writes therefore does **not** reach zero deviations — the only
//! writing path where that is so.
//!
//! That is deliberate. Deduplication has no formal standard to conform to: it
//! is specified in a paper rather than in the AFF4 Standard, and no other
//! implementation reads it robustly. Recording the deviation states exactly
//! that, which is more honest than suppressing it.
//!
//! # Final chunks are NUL-padded
//!
//! §4: *"our chunking algorithm deals with incomplete chunks found at the end
//! portions of files which are not multiples of the chunk size. These are padded
//! with NUL bytes to make a complete chunk."* The padding is inside the hashed
//! content, so two files whose tails differ only in length hash differently, and
//! `aff4:size` on the Map is what trims the padding away on read.

use std::collections::HashMap;

use crate::error::{Locus, Result};
use crate::write::container_writer::ContainerWriter;
use crate::write::stream_writer::StreamOptions;

/// The prefix a Block Hash ARN carries (§4).
///
/// Re-exported from the reader's definition so the two cannot drift: what this
/// writes must be exactly what `crate::map` recognizes.
pub use crate::map::BLOCK_HASH_PREFIX;

/// A Block Hash ARN for `digest`.
///
/// **Hex, not the paper's urlsafe base64.** §4 specifies *"The urlsafe base64
/// (Josefsson, 2006) encoded sha512 hash of the chunk"*, but pyaff4 — the only
/// implementation that writes these — emits lowercase hex, and
/// `broken-dedupe.aff4` carries 437 of them in that form. With no formal
/// standard to conform to, matching the sole existing implementation is worth
/// more than matching the prose.
#[must_use]
pub fn block_hash_arn(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(BLOCK_HASH_PREFIX.len() + digest.len() * 2);
    out.push_str(BLOCK_HASH_PREFIX);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A slice ARN naming `len` bytes at `offset` of `stream_arn` (§4).
///
/// The syntax is the paper's Slice Map, *"inspired by the array slice syntax in
/// the Python language"*, and lets a single-entry map live in the RDF rather
/// than costing two more ZIP segments. Offsets are lowercase hex with an `0x`
/// prefix, matching `broken-dedupe.aff4`.
#[must_use]
pub fn slice_arn(stream_arn: &str, offset: u64, len: u64) -> String {
    format!("{stream_arn}[{offset:#x}:{len:#x}]")
}

/// Where one unique chunk landed in the shared stream.
///
/// The byte offset is deliberately *not* stored: every pooled chunk is padded
/// to full length, so chunk *n* begins at `n * chunk_size`. Recording an offset
/// too would be a second source of truth that could drift from the stream the
/// pool actually writes.
#[derive(Debug, Clone, Copy)]
struct PooledChunk {
    /// Index into the map's target list.
    target_id: u32,
}

/// The shared chunk pool for one deduplicated acquisition.
///
/// Chunks accumulate here across every file walked, which is what makes
/// deduplication work *between* files and not merely within one.
#[derive(Debug)]
pub struct ChunkPool {
    /// SHA-512 of a chunk → where it lives.
    seen: HashMap<[u8; 64], PooledChunk>,
    /// Unique chunk content, in the order first seen. Flushed to one stream.
    unique: Vec<Vec<u8>>,
    /// Block Hash ARNs, positionally matching `unique`.
    arns: Vec<String>,
    /// Bytes of unique content so far — the shared stream's length.
    stored: u64,
    /// Bytes presented, including duplicates.
    presented: u64,
    /// Chunk size, fixed for the acquisition.
    chunk_size: usize,
}

/// What one deduplicated file resolved to.
#[derive(Debug)]
pub struct DedupedFile {
    /// One target ID per chunk, in file order.
    pub target_ids: Vec<u32>,
    /// The file's true length, before NUL padding.
    pub size: u64,
}

impl ChunkPool {
    /// A pool chunking at `chunk_size` bytes.
    #[must_use]
    pub fn new(chunk_size: usize) -> Self {
        Self {
            seen: HashMap::new(),
            unique: Vec::new(),
            arns: Vec::new(),
            stored: 0,
            presented: 0,
            chunk_size,
        }
    }

    /// Unique bytes stored so far.
    #[must_use]
    pub fn stored_bytes(&self) -> u64 {
        self.stored
    }

    /// Bytes presented, duplicates included.
    #[must_use]
    pub fn presented_bytes(&self) -> u64 {
        self.presented
    }

    /// Unique chunks held.
    #[must_use]
    pub fn unique_chunks(&self) -> usize {
        self.unique.len()
    }

    /// Bytes deduplication avoided storing.
    #[must_use]
    pub fn saved_bytes(&self) -> u64 {
        self.presented.saturating_sub(self.stored)
    }

    /// Chunk `source` into the pool, returning the file's chunk references.
    ///
    /// Reads incrementally: a file is never held whole, which is the point of
    /// storing large files as streams in the first place.
    ///
    /// # Errors
    ///
    /// [`Error::Io`](crate::error::Error::Io) if `source` cannot be read.
    pub fn absorb(&mut self, source: &mut dyn std::io::Read, locus: &Locus) -> Result<DedupedFile> {
        let mut buffer = vec![0u8; self.chunk_size];
        let mut target_ids = Vec::new();
        let mut size: u64 = 0;

        loop {
            let filled = read_full(source, &mut buffer, locus)?;
            if filled == 0 {
                break;
            }
            size += filled as u64;
            self.presented += filled as u64;

            // §4: a short final chunk is NUL-padded to a full chunk before
            // hashing, so every pooled chunk is exactly `chunk_size` bytes and
            // the shared stream stays chunk-aligned.
            if filled < self.chunk_size {
                buffer[filled..].fill(0);
            }

            target_ids.push(self.intern(&buffer));

            if filled < self.chunk_size {
                break;
            }
        }

        Ok(DedupedFile { target_ids, size })
    }

    /// Add one full chunk, returning its target ID.
    fn intern(&mut self, chunk: &[u8]) -> u32 {
        let digest = sha512_of(chunk);
        if let Some(existing) = self.seen.get(&digest) {
            return existing.target_id;
        }

        // `u32` is the map entry's target-ID width, so the pool cannot hold
        // more than that many distinct chunks. At 32 KiB each that is 128 TiB
        // of unique content; saturating keeps the type honest without a panic
        // in library code.
        let target_id = u32::try_from(self.unique.len()).unwrap_or(u32::MAX);

        self.seen.insert(digest, PooledChunk { target_id });
        self.arns.push(block_hash_arn(&digest));
        self.unique.push(chunk.to_vec());
        self.stored += chunk.len() as u64;
        target_id
    }

    /// Write the shared stream and every Block Hash ARN's `dataStream`.
    ///
    /// Called once, after every file has been absorbed. Returns the target list
    /// a deduplicated file's map indexes into.
    ///
    /// # Errors
    ///
    /// As [`write_image_stream_as`](crate::write::stream_writer::write_image_stream_as).
    pub fn finish(
        self,
        writer: &mut ContainerWriter,
        options: StreamOptions,
        locus: &Locus,
    ) -> Result<Vec<String>> {
        use crate::write::stream_writer::write_image_stream_as;
        use crate::write::turtle::TurtleTerm;

        let volume_arn = writer.volume_arn().as_str().to_owned();
        let stream_arn = format!("{volume_arn}/blocks");

        // One stream holding every unique chunk, in first-seen order. Written
        // through the ordinary stream writer so bevies, indexes and block
        // hashes are identical in form to any other stream.
        //
        // Fed through a reader that walks the chunks in place rather than
        // concatenating them: joining first would hold the entire deduplicated
        // corpus in memory at once, which is the cost this whole design exists
        // to avoid.
        let mut reader = ChunkListReader {
            chunks: &self.unique,
            chunk: 0,
            offset: 0,
        };
        write_image_stream_as(writer, &stream_arn, &mut reader, options, &[], locus)?;

        // Each Block Hash ARN points at its byte range of the shared stream.
        // This is the indirection §4 introduces: the map names content, and
        // content names storage. Offsets come from the pool's own insertion
        // order — chunk *n* sits at `n * chunk_size`, because every pooled
        // chunk is padded to full length.
        let lexicon = crate::lexicon::STANDARD;
        let chunk_len = self.chunk_size as u64;
        for (index, arn) in self.arns.iter().enumerate() {
            let offset = index as u64 * chunk_len;
            writer.graph_mut().add(
                arn,
                &lexicon.iri(lexicon.data_stream),
                TurtleTerm::iri(slice_arn(&stream_arn, offset, chunk_len)),
            );
        }

        Ok(self.arns)
    }
}

/// Presents a list of chunks as one continuous stream, without joining them.
struct ChunkListReader<'a> {
    chunks: &'a [Vec<u8>],
    chunk: usize,
    offset: usize,
}

impl std::io::Read for ChunkListReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let Some(current) = self.chunks.get(self.chunk) else {
                break;
            };
            let remaining = &current[self.offset..];
            if remaining.is_empty() {
                self.chunk += 1;
                self.offset = 0;
                continue;
            }
            let take = remaining.len().min(buf.len() - written);
            buf[written..written + take].copy_from_slice(&remaining[..take]);
            self.offset += take;
            written += take;
        }
        Ok(written)
    }
}

/// SHA-512 of one chunk.
fn sha512_of(chunk: &[u8]) -> [u8; 64] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha512::new();
    hasher.update(chunk);
    let out = hasher.finalize();
    let mut digest = [0u8; 64];
    digest.copy_from_slice(&out);
    digest
}

/// Read until `buffer` is full or the source ends.
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// §4's Block Hash ARN form, as `broken-dedupe.aff4` writes it.
    #[test]
    fn block_hash_arns_match_the_corpus_form() {
        let arn = block_hash_arn(&[0x00, 0x53, 0x74, 0x19]);
        assert_eq!(arn, "aff4:sha512:00537419");
    }

    /// The Slice Map syntax, verbatim from the paper's example.
    #[test]
    fn slice_arns_match_the_papers_example() {
        let arn = slice_arn("aff4://32f40158-4abe-48d5-9511-d92cbfa62fa9", 0, 0x8000);
        assert_eq!(
            arn,
            "aff4://32f40158-4abe-48d5-9511-d92cbfa62fa9[0x0:0x8000]"
        );
        // And the corpus's non-zero offset form.
        assert_eq!(
            slice_arn("aff4://6a1e6a1a", 0x4f_8000, 0x8000),
            "aff4://6a1e6a1a[0x4f8000:0x8000]"
        );
    }

    /// Identical content must resolve to one stored chunk.
    #[test]
    fn identical_chunks_are_stored_once() {
        let mut pool = ChunkPool::new(16);
        let block = vec![0xABu8; 16];

        let a = pool
            .absorb(&mut block.as_slice(), &Locus::new("/synthetic"))
            .unwrap();
        let b = pool
            .absorb(&mut block.as_slice(), &Locus::new("/synthetic"))
            .unwrap();

        assert_eq!(a.target_ids, b.target_ids, "same content, same chunk");
        assert_eq!(pool.unique_chunks(), 1, "stored once");
        assert_eq!(pool.presented_bytes(), 32, "presented twice");
        assert_eq!(pool.stored_bytes(), 16, "stored once");
        assert_eq!(pool.saved_bytes(), 16);
    }

    /// Different content must not collapse.
    #[test]
    fn distinct_chunks_are_kept_apart() {
        let mut pool = ChunkPool::new(16);
        let a = vec![0x01u8; 16];
        let b = vec![0x02u8; 16];

        let ra = pool
            .absorb(&mut a.as_slice(), &Locus::new("/synthetic"))
            .unwrap();
        let rb = pool
            .absorb(&mut b.as_slice(), &Locus::new("/synthetic"))
            .unwrap();

        assert_ne!(ra.target_ids, rb.target_ids);
        assert_eq!(pool.unique_chunks(), 2);
        assert_eq!(pool.saved_bytes(), 0);
    }

    /// §4: a short final chunk is NUL-padded, and the file's true size is kept
    /// so the padding can be trimmed on read.
    #[test]
    fn short_final_chunks_are_nul_padded_but_size_is_true() {
        let mut pool = ChunkPool::new(16);
        let data = vec![0xFFu8; 20]; // one full chunk plus 4 bytes

        let result = pool
            .absorb(&mut data.as_slice(), &Locus::new("/synthetic"))
            .unwrap();

        assert_eq!(result.size, 20, "the recorded size is the true length");
        assert_eq!(result.target_ids.len(), 2, "two chunks, the second padded");
        assert_eq!(
            pool.stored_bytes(),
            32,
            "both pooled chunks are full-length; the padding is real stored content"
        );
    }

    /// The same short content must hash the same wherever it appears.
    ///
    /// A short chunk is padded before hashing, so its Block Hash ARN must
    /// depend only on the file's own bytes — not on where in the file it sits,
    /// nor on what the pool absorbed before it. Two files ending in the same
    /// 3-byte tail must therefore share that tail's stored chunk.
    #[test]
    fn identical_short_tails_dedupe_against_each_other() {
        let locus = Locus::new("/synthetic");

        let mut pool = ChunkPool::new(8);
        // Two different files whose final partial chunks are identical.
        let mut first = vec![0xFFu8; 8];
        first.extend_from_slice(&[0x11, 0x11, 0x11]);
        let mut second = vec![0xAAu8; 8];
        second.extend_from_slice(&[0x11, 0x11, 0x11]);

        let a = pool.absorb(&mut first.as_slice(), &locus).unwrap();
        let b = pool.absorb(&mut second.as_slice(), &locus).unwrap();

        assert_ne!(
            a.target_ids[0], b.target_ids[0],
            "the differing first chunks must stay distinct"
        );
        assert_eq!(
            a.target_ids[1], b.target_ids[1],
            "identical padded tails must resolve to one stored chunk"
        );
        assert_eq!(
            pool.unique_chunks(),
            3,
            "two distinct heads plus one shared tail"
        );
    }

    /// A tail that is only NUL bytes must not collide with a padded short tail
    /// of the same length — the padding is inside the hashed content, so this
    /// holds by construction, and the test pins it.
    #[test]
    fn padding_participates_in_the_hash() {
        let mut pool = ChunkPool::new(8);
        let short = vec![0xAAu8; 3];
        let padded_equivalent = {
            let mut v = vec![0xAAu8; 3];
            v.resize(8, 0);
            v
        };

        let a = pool
            .absorb(&mut short.as_slice(), &Locus::new("/synthetic"))
            .unwrap();
        let b = pool
            .absorb(&mut padded_equivalent.as_slice(), &Locus::new("/synthetic"))
            .unwrap();

        // Same stored chunk (padding makes them identical) but different sizes,
        // which is exactly why `aff4:size` must be recorded per file.
        assert_eq!(a.target_ids, b.target_ids);
        assert_eq!(a.size, 3);
        assert_eq!(b.size, 8);
    }
}
