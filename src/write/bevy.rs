//! Chunking and compressing a bytestream into bevies.
//!
//! A bevy is one ZIP member holding `chunks_per_segment` compressed chunks,
//! plus a sibling `.index` member of `<QI>` entries — an 8-byte offset and a
//! 4-byte length per chunk. `crate::stream` reads exactly this layout; the
//! constants and the entry format are taken from there rather than restated.
//!
//! # The stored-chunk rule
//!
//! A chunk is kept compressed only when `compressedLen < chunk_size - 16`.
//! Otherwise the *uncompressed* bytes are stored and the chunk is padded to
//! `chunk_size`. This is not an optimisation: a compressed form that reached
//! `chunk_size` would be indistinguishable from a stored chunk on read, so the
//! margin is what keeps the two cases decidable. pyaff4 applies the same rule
//! at `aff4_image.py:87`, and the generator in `utilities/` follows it too.

use crate::codec::Codec;
use crate::error::{Error, Locus, Result};

/// Bytes per bevy-index entry: `<QI>`.
const INDEX_ENTRY_SIZE: usize = 12;

/// The margin the stored-chunk rule requires.
const STORED_MARGIN: usize = 16;

/// Default chunk size, matching pyaff4 and c-aff4.
pub const DEFAULT_CHUNK_SIZE: usize = 32 * 1024;

/// Default chunks per bevy, matching pyaff4 and c-aff4.
pub const DEFAULT_CHUNKS_PER_SEGMENT: usize = 1024;

/// Compress one chunk with `codec`.
///
/// Returns the bytes to store. Callers must apply the stored-chunk rule to the
/// result; this function only compresses.
///
/// # Errors
///
/// [`Error::Unsupported`] for a codec this build declines to write.
pub fn compress_chunk(codec: Codec, chunk: &[u8], locus: &Locus) -> Result<Vec<u8>> {
    match codec {
        Codec::Snappy => Ok(snap::raw::Encoder::new()
            .compress_vec(chunk)
            .unwrap_or_else(|_| chunk.to_vec())),
        Codec::Lz4 => Ok(lz4_flex::block::compress(chunk)),
        Codec::Zlib => {
            use std::io::Write as _;
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(chunk)
                .and_then(|()| encoder.finish())
                .map_err(|e| Error::io(locus.path.clone(), e))
        }
        Codec::Stored => Ok(chunk.to_vec()),
        // Raw deflate and the Rekall snappy dialect are declined on read; a
        // writer that emitted either would produce containers this crate
        // refuses to verify.
        other => Err(Error::unsupported(
            crate::error::Feature::Codec {
                iri: other.iri().to_owned(),
            },
            format!(
                "aff4tools declines to write {} — it is not verifiable by this build",
                other.name()
            ),
        )),
    }
}

/// Per-chunk digests accumulated as a bevy is built.
///
/// These are the leaves of the AFF4 hash tree. Written as
/// `<bevy>.blockHash.md5` and `.sha1` segments, they let `verify` check that
/// each chunk is intact individually rather than only in aggregate — which is
/// what "checked from leaves to root" means.
#[derive(Debug, Default)]
pub struct BlockDigests {
    /// Concatenated 16-byte MD5 digests, one per chunk.
    pub md5: Vec<u8>,
    /// Concatenated 20-byte SHA-1 digests, one per chunk.
    pub sha1: Vec<u8>,
}

/// One bevy under construction.
///
/// Chunks are appended until the bevy is full, then [`BevyBuilder::finish`]
/// yields the member body and its index.
#[derive(Debug)]
pub struct BevyBuilder {
    codec: Codec,
    chunk_size: usize,
    chunks_per_segment: usize,
    body: Vec<u8>,
    index: Vec<u8>,
    chunk_count: usize,
    blocks: BlockDigests,
}

/// A completed bevy: the member body and its `.index` sibling.
#[derive(Debug)]
pub struct FinishedBevy {
    /// The bevy member's bytes.
    pub body: Vec<u8>,
    /// The `<QI>` index member's bytes.
    pub index: Vec<u8>,
    /// How many chunks it holds.
    pub chunk_count: usize,
    /// Per-chunk digests over the *uncompressed* chunk bytes.
    pub blocks: BlockDigests,
}

impl BevyBuilder {
    /// Start an empty bevy.
    #[must_use]
    pub fn new(codec: Codec, chunk_size: usize, chunks_per_segment: usize) -> Self {
        Self {
            codec,
            chunk_size,
            chunks_per_segment,
            body: Vec::with_capacity(chunk_size * 8),
            index: Vec::with_capacity(chunks_per_segment * INDEX_ENTRY_SIZE),
            chunk_count: 0,
            blocks: BlockDigests::default(),
        }
    }

    /// Whether the bevy has reached `chunks_per_segment`.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.chunk_count >= self.chunks_per_segment
    }

    /// Whether nothing has been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunk_count == 0
    }

    /// How many chunks are held.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }

    /// Append one chunk.
    ///
    /// `chunk` may be shorter than `chunk_size` only as the final chunk of a
    /// stream. A short chunk is padded with NUL to `chunk_size` before
    /// compression, per v1.0a §3.2 — the reader trims against `aff4:size`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `chunk` is longer than `chunk_size`;
    /// [`Error::Unsupported`] for a declined codec.
    pub fn push_chunk(&mut self, chunk: &[u8], locus: &Locus) -> Result<()> {
        if chunk.len() > self.chunk_size {
            return Err(Error::malformed(
                locus.clone(),
                format!(
                    "chunk of {} bytes exceeds the declared chunk size {}",
                    chunk.len(),
                    self.chunk_size
                ),
            ));
        }

        // Pad a short final chunk before compressing, so every chunk the
        // reader sees decompresses to exactly chunk_size.
        let padded: Vec<u8>;
        let full = if chunk.len() == self.chunk_size {
            chunk
        } else {
            padded = {
                let mut v = Vec::with_capacity(self.chunk_size);
                v.extend_from_slice(chunk);
                v.resize(self.chunk_size, 0);
                v
            };
            &padded
        };

        // Block hashes cover the **uncompressed** chunk as the reader will
        // reconstruct it — which for a short final chunk means the trimmed
        // bytes, not the padded ones.
        //
        // This is not a free choice. `verify` trims the last chunk against
        // `aff4:size` and hashes what remains (`BlockDigests::finish`), so
        // hashing the padded form here produced digests of the right *count*
        // that matched nothing — a mismatch caught only because the leaves are
        // actually checked. The writer follows the reader, since the reader is
        // what an examiner runs.
        {
            use md5::Digest as _;
            self.blocks.md5.extend_from_slice(&md5::Md5::digest(chunk));
            self.blocks
                .sha1
                .extend_from_slice(&sha1::Sha1::digest(chunk));
        }

        let compressed = compress_chunk(self.codec, full, locus)?;
        let stored: &[u8] = if compressed.len() < self.chunk_size - STORED_MARGIN {
            &compressed
        } else {
            full
        };

        let offset = self.body.len() as u64;
        // The `<QI>` index entry's length field is 32-bit, so a chunk of 4 GiB
        // or more cannot be addressed. Far beyond any sane chunk size, but a
        // silent wrap here would corrupt the index rather than fail.
        let length = u32::try_from(stored.len()).map_err(|_| {
            Error::malformed(
                locus.clone(),
                format!(
                    "stored chunk of {} bytes exceeds the 32-bit bevy index \
                     length field",
                    stored.len()
                ),
            )
        })?;
        self.body.extend_from_slice(stored);
        self.index.extend_from_slice(&offset.to_le_bytes());
        self.index.extend_from_slice(&length.to_le_bytes());
        self.chunk_count += 1;

        Ok(())
    }

    /// Take the finished bevy, leaving the builder empty and reusable.
    #[must_use]
    pub fn finish(&mut self) -> FinishedBevy {
        let chunk_count = self.chunk_count;
        self.chunk_count = 0;
        FinishedBevy {
            body: std::mem::take(&mut self.body),
            index: std::mem::take(&mut self.index),
            chunk_count,
            blocks: std::mem::take(&mut self.blocks),
        }
    }
}

/// The member name of bevy `number`: eight ASCII digits, per v1.0a §4.
#[must_use]
pub fn bevy_name(base: &str, number: u64) -> String {
    format!("{base}/{number:08}")
}

/// The member name of bevy `number`'s block-hash segment for `algorithm`.
///
/// `<base>/<bevy>.blockHash.<alg>`, which is the pattern
/// `crate::verify::block_hash_segments` searches for.
#[must_use]
pub fn bevy_block_hash_name(base: &str, number: u64, algorithm: &str) -> String {
    format!(
        "{base}/{number:08}{}{algorithm}",
        crate::verify::BLOCK_HASH_SUFFIX
    )
}

/// The member name of bevy `number`'s index.
#[must_use]
pub fn bevy_index_name(base: &str, number: u64) -> String {
    format!("{base}/{number:08}{}", crate::stream::INDEX_SUFFIX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn locus() -> Locus {
        Locus::new("/synthetic/out.aff4")
    }

    /// Every codec we write must round-trip through the reader's decompressor.
    /// This is the property the whole writer rests on.
    #[test]
    fn every_writable_codec_round_trips_through_the_reader() {
        let chunk: Vec<u8> = (0..DEFAULT_CHUNK_SIZE)
            .map(|i| u8::try_from((i * 7) % 251).unwrap_or(0))
            .collect();

        for codec in [Codec::Snappy, Codec::Lz4, Codec::Zlib] {
            let compressed = compress_chunk(codec, &chunk, &locus()).unwrap();
            let back =
                crate::codec::decompress_chunk(codec, &compressed, DEFAULT_CHUNK_SIZE, &locus())
                    .expect("a codec we write must decompress with our own reader");
            assert_eq!(back, chunk, "{codec:?} round trip");
        }
    }

    /// Declined codecs must be refused on write, not silently substituted.
    #[test]
    fn declined_codecs_are_refused() {
        let chunk = vec![0u8; 64];
        for codec in [Codec::Deflate, Codec::SnappyRekall] {
            assert!(
                compress_chunk(codec, &chunk, &locus()).is_err(),
                "{codec:?} must be refused on write"
            );
        }
    }

    /// The index must be `<QI>` entries the reader's parser accepts, with
    /// offsets that actually locate each chunk in the body.
    #[test]
    fn the_index_locates_every_chunk() {
        let mut b = BevyBuilder::new(Codec::Snappy, 1024, 4);
        for i in 0..4u8 {
            b.push_chunk(&vec![i; 1024], &locus()).unwrap();
        }
        assert!(b.is_full());
        let bevy = b.finish();
        assert_eq!(bevy.chunk_count, 4);

        let locations = crate::stream::parse_index(&bevy.index, &locus()).unwrap();
        assert_eq!(locations.len(), 4);

        for (i, loc) in locations.iter().enumerate() {
            let start = usize::try_from(loc.offset).unwrap();
            let end = start + loc.length as usize;
            let stored = &bevy.body[start..end];
            let back =
                crate::codec::decompress_chunk(Codec::Snappy, stored, 1024, &locus()).unwrap();
            assert_eq!(back, vec![u8::try_from(i).unwrap(); 1024]);
        }
    }

    /// An incompressible chunk falls back to stored, and the reader still
    /// reproduces it — the stored-chunk rule in both directions.
    #[test]
    fn incompressible_chunks_are_stored_verbatim() {
        let chunk: Vec<u8> = (0..1024u32)
            .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).unwrap_or(0))
            .collect();
        let mut b = BevyBuilder::new(Codec::Snappy, 1024, 1);
        b.push_chunk(&chunk, &locus()).unwrap();
        let bevy = b.finish();

        let locations = crate::stream::parse_index(&bevy.index, &locus()).unwrap();
        let loc = &locations[0];
        let start = usize::try_from(loc.offset).unwrap();
        let stored = &bevy.body[start..start + loc.length as usize];
        let back = crate::codec::decompress_chunk(Codec::Snappy, stored, 1024, &locus()).unwrap();
        assert_eq!(back, chunk);
    }

    /// A short final chunk is NUL-padded to `chunk_size` (v1.0a §3.2). The
    /// reader trims against `aff4:size`, so the padding must be exact.
    #[test]
    fn a_short_final_chunk_is_padded() {
        let mut b = BevyBuilder::new(Codec::Snappy, 1024, 4);
        b.push_chunk(&[0xAA; 100], &locus()).unwrap();
        let bevy = b.finish();

        let locations = crate::stream::parse_index(&bevy.index, &locus()).unwrap();
        let loc = &locations[0];
        let start = usize::try_from(loc.offset).unwrap();
        let stored = &bevy.body[start..start + loc.length as usize];
        let back = crate::codec::decompress_chunk(Codec::Snappy, stored, 1024, &locus()).unwrap();

        assert_eq!(back.len(), 1024, "padded to a full chunk");
        assert_eq!(&back[..100], &[0xAA; 100]);
        assert!(back[100..].iter().all(|&b| b == 0), "padding must be NUL");
    }

    /// An oversized chunk is a caller bug and must be refused.
    #[test]
    fn an_oversized_chunk_is_refused() {
        let mut b = BevyBuilder::new(Codec::Snappy, 1024, 4);
        assert!(b.push_chunk(&[0u8; 2048], &locus()).is_err());
    }

    #[test]
    fn bevy_names_are_eight_digits() {
        assert_eq!(
            bevy_name("aff4%3A%2F%2Fx/data", 0),
            "aff4%3A%2F%2Fx/data/00000000"
        );
        assert_eq!(bevy_index_name("x", 42), "x/00000042.index");
    }
}
