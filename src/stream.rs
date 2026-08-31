//! Reading an `ImageStream`: bevies, chunk indices, and assembly.
//!
//! An `ImageStream` stores its data in bevies (numbered segments), each
//! holding `chunksInSegment` chunks and accompanied by an index giving each
//! chunk's offset and compressed length.
//!
//! # Layout
//!
//! For a stream `aff4://c215ba20-…`, the container holds:
//!
//! ```text
//! aff4%3A%2F%2Fc215ba20-…/00000000        the bevy: chunks, back to back
//! aff4%3A%2F%2Fc215ba20-…/00000000.index  12 bytes per chunk: <QI>
//! ```
//!
//! Bevies are numbered `%08d` from zero. `unicode.aff4` has six; most
//! containers have one.
//!
//! Index entries are 8-byte offset plus **4**-byte length — 12 bytes, not 16
//! (finding L). `Base-Linear.aff4`'s index is 1452 bytes: 121 entries exactly.
//!
//! # Streaming, never materialised
//!
//! [`ImageStream::read_all`] pushes chunk-sized slices to a sink rather than
//! returning a buffer. A disk image is routinely gigabytes and real evidence
//! reaches terabytes, so assembling one in memory is not an option. It also
//! means one pass can feed several digests, which is what feature 1's
//! verification needs.
//!
//! # What this module does not do
//!
//! It reads a *stream*, not an *image*. A `DiskImage` points at a `Map`, which
//! assembles an image out of this stream plus described runs of repeated bytes
//! — see `map.rs`. Reading an `ImageStream` directly gives only the stored
//! portion, which for `Base-Linear.aff4` is 3.96 MB of a 268 MB image.

use std::collections::{HashMap, VecDeque};

use crate::arn::Arn;
use crate::codec::{Codec, decompress_chunk};
use crate::error::{Error, Locus, Result};
use crate::lexicon::Lexicon;
use crate::rdf::Graph;
use crate::zip::Volume;

/// Bytes per bevy-index entry: `<QI>`, an 8-byte offset and 4-byte length.
pub const INDEX_ENTRY_LEN: usize = 12;

/// The suffix naming a bevy's chunk index.
pub const INDEX_SUFFIX: &str = ".index";

/// One chunk's location within its bevy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLocation {
    /// Byte offset of the chunk within the bevy.
    pub offset: u64,
    /// The chunk's stored length, compressed unless it equals the chunk size.
    pub length: u32,
}

/// An `ImageStream` open for reading.
///
/// Holds only the stream's parameters; chunk data is read on demand.
#[derive(Debug, Clone)]
pub struct ImageStream {
    arn: Arn,
    size: u64,
    chunk_size: usize,
    chunks_in_segment: usize,
    codec: Codec,
}

impl ImageStream {
    /// Read a stream's parameters out of the metadata graph.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if a required property is missing or unusable —
    /// a stream that cannot state its own chunk size cannot be read, and
    /// guessing one would produce a confidently wrong result.
    /// [`Error::Unsupported`] if the codec IRI is not recognised.
    pub fn open(arn: &Arn, graph: &Graph, lexicon: &Lexicon, locus: &Locus) -> Result<Self> {
        let locus = locus.clone().subject(arn.as_str());

        // Predicates are per-generation local names; the graph is keyed by
        // full IRI. Pre-standard spells these `chunk_size` / `CompressionMethod`.
        let size_iri = lexicon.iri(lexicon.size);
        let chunk_size_iri = lexicon.iri(lexicon.chunk_size);
        let chunks_iri = lexicon.iri(lexicon.chunks_in_segment);
        let codec_predicate = lexicon.iri(lexicon.compression_method);

        let size = required_u64(graph, arn, &size_iri, "size", &locus)?;
        let chunk_size = required_u64(graph, arn, &chunk_size_iri, "chunkSize", &locus)?;
        let chunks_in_segment = required_u64(graph, arn, &chunks_iri, "chunksInSegment", &locus)?;

        let codec_iri = graph
            .object(arn.as_str(), &codec_predicate)
            .and_then(crate::rdf::Value::as_iri)
            .ok_or_else(|| {
                Error::malformed(
                    locus.clone().predicate(&codec_predicate),
                    "the stream declares no compression method; it cannot be \
                     read without knowing how its chunks are encoded"
                        .to_owned(),
                )
            })?;

        let codec = Codec::from_iri(codec_iri)
            .ok_or_else(|| Codec::unsupported(codec_iri, format!("reading stream {arn}")))?;

        let chunk_size = usize::try_from(chunk_size).map_err(|_| {
            Error::malformed(
                locus.clone().predicate(&chunk_size_iri),
                format!("declared chunk size {chunk_size} does not fit in memory"),
            )
        })?;

        if chunk_size == 0 {
            return Err(Error::malformed(
                locus.clone().predicate(&chunk_size_iri),
                "the stream declares a chunk size of zero; no chunk can hold data".to_owned(),
            ));
        }

        let chunks_in_segment = usize::try_from(chunks_in_segment).map_err(|_| {
            Error::malformed(
                locus.clone().predicate(&chunks_iri),
                format!("declared chunksInSegment {chunks_in_segment} is implausible"),
            )
        })?;

        if chunks_in_segment == 0 {
            return Err(Error::malformed(
                locus.predicate(&chunks_iri),
                "the stream declares zero chunks per bevy; no bevy could hold data".to_owned(),
            ));
        }

        Ok(Self {
            arn: arn.clone(),
            size,
            chunk_size,
            chunks_in_segment,
            codec,
        })
    }

    /// The stream's ARN.
    #[must_use]
    pub fn arn(&self) -> &Arn {
        &self.arn
    }

    /// The stream's declared uncompressed length.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The uncompressed length of each chunk.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// How many chunks each bevy holds.
    #[must_use]
    pub fn chunks_in_segment(&self) -> usize {
        self.chunks_in_segment
    }

    /// The codec each chunk is encoded with.
    #[must_use]
    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// How many bevies this stream spans, from its size.
    #[must_use]
    pub fn bevy_count(&self) -> u64 {
        let per_bevy = self.chunk_size as u64 * self.chunks_in_segment as u64;
        self.size.div_ceil(per_bevy.max(1))
    }

    /// The member name of a bevy, e.g. `aff4%3A%2F%2F…/00000000`.
    ///
    /// Returns `None` when the ARN names no member of this volume — a stream
    /// stored in a sibling container, as striped volumes have.
    #[must_use]
    pub fn bevy_name(&self, volume_arn: &Arn, index: u64) -> Option<String> {
        let base = self.arn.member_name(volume_arn)?;
        Some(format!("{base}/{index:08}"))
    }

    /// Feed every byte of the stream to `sink`, in order.
    ///
    /// Slices are at most one chunk long and borrowed, never accumulated: the
    /// stream is never held in memory whole. The final chunk is truncated to
    /// the declared size, so the total delivered equals [`ImageStream::size`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if a bevy or index is absent, malformed, or
    /// inconsistent with the declared size, and whatever `sink` returns.
    pub fn read_all(
        &self,
        volume: &mut dyn Volume,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<()> {
        self.read_all_observed(volume, sink, &mut |_| {}, locus)
    }

    /// Decompress one bevy into its chunks, in chunk order.
    ///
    /// I/O-free: the caller supplies the bevy and index bytes it has already
    /// read. Chunks are returned separately rather than concatenated because
    /// the stream-size truncation and the block-hash cut are both defined on
    /// chunk boundaries — joining them here would force the caller to find
    /// those boundaries again.
    ///
    /// No truncation is applied. That depends on how many bytes precede this
    /// bevy in the stream, which a bevy decoded out of order does not know.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the index is unreadable, a chunk falls outside
    /// the bevy, or a chunk cannot be decompressed.
    pub fn decode_bevy(
        &self,
        bevy: &[u8],
        index: &[u8],
        bevy_locus: &Locus,
        index_locus: &Locus,
    ) -> Result<Vec<Vec<u8>>> {
        let locations = parse_index_bounded(index, self.chunks_in_segment, index_locus)?;
        let mut chunks = Vec::with_capacity(locations.len());
        for (chunk_index, location) in locations.iter().enumerate() {
            let chunk_locus = bevy_locus.clone().byte_offset(location.offset);
            let chunk = slice_chunk(bevy, *location, chunk_index, &chunk_locus)?;
            chunks.push(decompress_chunk(
                self.codec,
                chunk,
                self.chunk_size,
                &chunk_locus,
            )?);
        }
        Ok(chunks)
    }

    /// As [`ImageStream::read_all`], reporting each bevy as it completes.
    ///
    /// `on_bevy` receives the count of bevies fully delivered so far, after the
    /// last chunk of each one reaches `sink`. Kept separate from `sink` so the
    /// sink's contract stays "bytes, in order, and nothing else".
    ///
    /// # Errors
    ///
    /// As [`ImageStream::read_all`].
    pub fn read_all_observed(
        &self,
        volume: &mut dyn Volume,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        on_bevy: &mut dyn FnMut(u64),
        locus: &Locus,
    ) -> Result<()> {
        let volume_arn = volume.arn().clone();
        let locus = locus.clone().subject(self.arn.as_str());
        let mut delivered: u64 = 0;

        for bevy_index in 0..self.bevy_count() {
            if delivered >= self.size {
                break;
            }

            let bevy_name = self.bevy_name(&volume_arn, bevy_index).ok_or_else(|| {
                Error::malformed(
                    locus.clone(),
                    format!(
                        "stream {} names no member of volume {volume_arn}; its data \
                         is stored elsewhere, which this build cannot follow",
                        self.arn
                    ),
                )
            })?;

            let index_name = format!("{bevy_name}{INDEX_SUFFIX}");
            let bevy_locus = locus.clone().segment(&bevy_name);

            let index = volume.read_segment(&index_name)?;
            let bevy = volume.read_segment(&bevy_name)?;
            let locations = parse_index_bounded(
                &index,
                self.chunks_in_segment,
                &locus.clone().segment(&index_name),
            )?;

            for (chunk_index, location) in locations.iter().enumerate() {
                if delivered >= self.size {
                    break;
                }

                let chunk_locus = bevy_locus.clone().byte_offset(location.offset);
                let chunk = slice_chunk(&bevy, *location, chunk_index, &chunk_locus)?;

                let mut plain = decompress_chunk(self.codec, chunk, self.chunk_size, &chunk_locus)?;

                // The last chunk of the stream is truncated to the declared
                // size. Delivering the whole chunk would append padding that
                // was never part of the evidence.
                let remaining = self.size - delivered;
                if (plain.len() as u64) > remaining {
                    plain.truncate(usize::try_from(remaining).unwrap_or(plain.len()));
                }

                delivered += plain.len() as u64;
                sink(&plain)?;
            }

            on_bevy(bevy_index + 1);
        }

        if delivered != self.size {
            return Err(Error::malformed(
                locus,
                format!(
                    "stream {} delivered {delivered} bytes but declares {}; \
                     a short read would produce a digest that does not match \
                     the evidence",
                    self.arn, self.size
                ),
            ));
        }

        Ok(())
    }
}

/// Reads regions out of an [`ImageStream`] on demand.
///
/// [`ImageStream::read_all`] delivers a stream from start to finish, which is
/// what hashing a stream needs. Reading *through a map* needs a region at a
/// time instead: entries name arbitrary `(target_offset, length)` windows.
///
/// # A few bevies at a time
///
/// A bevy is held decompressed-on-demand: the segment bytes and its index stay
/// resident, and chunks are decompressed as they are asked for. Bevies are kept
/// up to [`BEVY_CACHE_BYTES`], least-recently-used evicted first, so a reader
/// that alternates among a working set re-reads none of them. Peak memory is
/// therefore that budget in *stored* bevy bytes plus one decompressed chunk,
/// not one image.
///
/// Reads are expected to run forward — every map in the corpus is contiguous
/// once sorted — but seeking backwards is not an error. It costs a re-read of
/// the bevy, nothing more, so a caller cannot get a wrong answer by moving in
/// an unexpected order.
pub struct ChunkReader<'v> {
    stream: ImageStream,
    volume: &'v mut dyn Volume,
    volume_arn: Arn,
    /// The bevies currently resident, most-recently-used last.
    ///
    /// Holding more than one amortizes a member read across the chunks taken
    /// from it. `mac_apt` walking APFS B-trees issues 4 KiB reads that change
    /// bevy 71% of the time while revisiting only ~60 bevies, so a single slot
    /// evicts a bevy it needs again a read or two later.
    ///
    /// Since range reads exist this is no longer what makes *scattered*
    /// reading affordable -- `decompress_by_range` is. It now serves the case
    /// where the range path cannot: a deflated member, or a volume that does
    /// not implement ranged reads, where `decompress` falls back to reading the
    /// member whole. Holding several then amortizes that read across the chunks
    /// taken from it. See `BEVY_CACHE_BYTES`.
    ///
    /// Note this cache does *not* serve `verify` or `read_all`: those go
    /// through `read_all_observed` and `read_all_parallel`, which read members
    /// with `read_segment` and decode them with `decode_bevy`, never touching
    /// `ChunkReader`.
    resident: Vec<Bevy>,
    /// Decompressed chunks, keyed by global chunk number.
    ///
    /// This is the layer that serves *repeat* reads of one chunk. A `mac_apt`
    /// SAFARI run issues 13,446 reads against 4,271 distinct offsets -- a
    /// 3.15x re-read factor -- because walking a file's extents returns to the
    /// same block repeatedly.
    ///
    /// It is not redundant with the range read in
    /// [`ChunkReader::decompress_by_range`], though it looks as though it
    /// should be: a range read is cheap but not free, and removing this cache
    /// measured **3.8x slower** on that workload (0.35 s to 1.34 s) while
    /// leaving the metadata walk unchanged. The three layers serve different
    /// access patterns -- range reads for sparse access to a bevy, the bevy
    /// cache for the fallback when a range read cannot be served, this for
    /// repeat access to one chunk.
    ///
    /// This is also the granularity pyaff4 caches at, which is why it beat
    /// this library on that pattern before the cache existed.
    ///
    /// A map rather than a list: the cache holds thousands of chunks and a
    /// linear scan per read would cost more than it saves. Eviction is FIFO by
    /// insertion order, which keeps every lookup O(1) and is indistinguishable
    /// from LRU for a walk that revisits within a few reads.
    chunk: HashMap<u64, Vec<u8>>,
    /// Chunk numbers in insertion order, for eviction.
    chunk_order: VecDeque<u64>,
    /// Bytes currently held in `chunk`, maintained rather than recomputed.
    chunk_bytes_held: usize,
    /// Decoded bevy indexes, keyed by bevy number.
    ///
    /// A range read needs only the chunk's location within its bevy, which the
    /// index gives. Holding the index lets a chunk be fetched without the bevy
    /// it belongs to ever being resident -- that is the whole point of the
    /// range path. Indexes are small: one entry per chunk, so ~8 KiB per bevy
    /// against the ~30 MiB of data they describe, and a container's entire set
    /// of indexes costs less than a single bevy.
    index: HashMap<u64, Vec<ChunkLocation>>,
}

/// How much memory a [`ChunkReader`]'s resident bevies may occupy, in bytes.
///
/// A budget rather than a count, because a bevy's cost is the *stored* segment
/// size and that varies by container: 30 MiB apiece in a 500 GB APFS
/// acquisition, a few hundred KiB in the synthetic fixtures. Capping the count
/// would mean gigabytes on the former and near-nothing on the latter, which is
/// backwards -- the big-bevy container is exactly the one that cannot afford
/// many.
///
/// 512 MiB holds ~17 of this image's bevies, enough that a B-tree walk
/// revisiting a working set of metadata bevies mostly hits, while staying well
/// inside what a forensic workstation running one image can spare. At least one
/// bevy is always resident regardless of the budget, so a container whose
/// single bevy exceeds it still reads rather than failing.
const BEVY_CACHE_BYTES: usize = 512 * 1024 * 1024;

/// How much memory a [`ChunkReader`]'s decompressed chunks may occupy, in
/// bytes.
///
/// Chunks are `chunkSize` -- 32 KiB in the corpus containers -- so this budget
/// holds thousands of them. It is the cache that serves scattered reads of file
/// content, where the bevy cache cannot: see the note on
/// [`ChunkReader::chunk`].
const CHUNK_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// A reader's cached bevy, moved between readers over the same stream.
///
/// Carries the stream ARN so a restore into the wrong reader is refused rather
/// than serving one stream's bytes for another's.
pub struct Residency {
    stream: Arn,
    resident: Vec<Bevy>,
    chunk: HashMap<u64, Vec<u8>>,
    chunk_order: VecDeque<u64>,
    chunk_bytes_held: usize,
    index: HashMap<u64, Vec<ChunkLocation>>,
}

/// One bevy's bytes and decoded index, held while it is being read.
struct Bevy {
    index: u64,
    bytes: Vec<u8>,
    locations: Vec<ChunkLocation>,
}

impl<'v> ChunkReader<'v> {
    /// Open a reader over `stream`, drawing segments from `volume`.
    #[must_use]
    pub fn new(stream: &ImageStream, volume: &'v mut dyn Volume) -> Self {
        let volume_arn = volume.arn().clone();
        Self {
            stream: stream.clone(),
            volume,
            volume_arn,
            resident: Vec::new(),
            chunk: HashMap::new(),
            chunk_order: VecDeque::new(),
            chunk_bytes_held: 0,
            index: HashMap::new(),
        }
    }

    /// The stream being read.
    #[must_use]
    pub fn stream(&self) -> &ImageStream {
        &self.stream
    }

    /// Give the volume back, dropping the resident bevy.
    ///
    /// A caller reading several streams in turn uses this to hand the volume to
    /// the next reader, so only one bevy is ever resident.
    #[must_use]
    pub fn into_volume(self) -> &'v mut dyn Volume {
        self.volume
    }

    /// Take the resident bevy out, leaving the volume behind.
    ///
    /// A reader borrows its volume, so one cannot outlive a short `&mut` on the
    /// volume set — which is what reading a striped image across several files
    /// requires. Moving the residency between readers keeps a run of entries
    /// against one stream reading each bevy once, without the reader itself
    /// having to persist.
    #[must_use]
    pub fn into_residency(self) -> Residency {
        Residency {
            stream: self.stream.arn().clone(),
            resident: self.resident,
            chunk: self.chunk,
            chunk_order: self.chunk_order,
            chunk_bytes_held: self.chunk_bytes_held,
            index: self.index,
        }
    }

    /// Restore a residency taken from an earlier reader over the same stream.
    ///
    /// Ignored when it belongs to a different stream: a bevy from one stream
    /// says nothing about another, and serving it would be a wrong read rather
    /// than a slow one.
    pub fn restore(&mut self, residency: Residency) {
        if residency.stream.as_str() != self.stream.arn().as_str() {
            return;
        }
        self.resident = residency.resident;
        self.chunk = residency.chunk;
        self.chunk_order = residency.chunk_order;
        self.chunk_bytes_held = residency.chunk_bytes_held;
        self.index = residency.index;
    }

    /// Feed `length` bytes starting at `offset` to `sink`, in order.
    ///
    /// Slices are borrowed and at most one chunk long: a 100 MB region is
    /// delivered in chunk-sized pieces, never assembled.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the region runs past the stream's declared size,
    /// if a bevy or index is missing or inconsistent, or if a chunk will not
    /// decompress. Whatever `sink` returns is propagated unchanged.
    pub fn read_region(
        &mut self,
        offset: u64,
        length: u64,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<()> {
        let locus = locus.clone().subject(self.stream.arn.as_str());

        let end = offset.checked_add(length).ok_or_else(|| {
            Error::malformed(
                locus.clone(),
                format!(
                    "a region at offset {offset} of length {length} overflows when \
                     added; the map entry naming it cannot be resolved"
                ),
            )
        })?;

        if end > self.stream.size {
            return Err(Error::malformed(
                locus.clone().byte_offset(offset),
                format!(
                    "a region covering bytes {offset}..{end} extends past stream \
                     {}, which declares {} bytes; reading it would either fail or \
                     silently return data from elsewhere",
                    self.stream.arn, self.stream.size
                ),
            ));
        }

        let chunk_size = self.stream.chunk_size as u64;
        let mut position = offset;

        while position < end {
            let chunk_number = position / chunk_size;
            let within = usize::try_from(position % chunk_size).unwrap_or(0);

            let plain = self.chunk_bytes(chunk_number, &locus)?;

            if within >= plain.len() {
                return Err(Error::malformed(
                    locus.clone().byte_offset(position),
                    format!(
                        "chunk {chunk_number} decompressed to {} bytes, which does \
                         not reach offset {within} within the chunk; the stream is \
                         shorter than its metadata claims",
                        plain.len()
                    ),
                ));
            }

            let available = plain.len() - within;
            let wanted = usize::try_from(end - position).unwrap_or(available);
            let take = available.min(wanted);

            sink(&plain[within..within + take])?;
            position += take as u64;
        }

        Ok(())
    }

    /// Borrow one chunk's plaintext, decompressing and caching as needed.
    fn chunk_bytes(&mut self, chunk_number: u64, locus: &Locus) -> Result<&[u8]> {
        if !self.chunk.contains_key(&chunk_number) {
            let plain = self.decompress(chunk_number, locus)?;
            let incoming = plain.len();

            // Evict in insertion order until the newcomer fits. Never evict
            // everything: one chunk stays even if it alone exceeds the budget.
            while self.chunk_order.len() > 1 && self.chunk_bytes_held + incoming > CHUNK_CACHE_BYTES
            {
                if let Some(victim) = self.chunk_order.pop_front()
                    && let Some(gone) = self.chunk.remove(&victim)
                {
                    self.chunk_bytes_held -= gone.len();
                }
            }

            self.chunk_bytes_held += incoming;
            self.chunk_order.push_back(chunk_number);
            self.chunk.insert(chunk_number, plain);
        }

        // Present: either it already was, or it was just inserted.
        self.chunk
            .get(&chunk_number)
            .map_or(Ok(&[][..]), |b| Ok(&b[..]))
    }

    /// Decompress one chunk, reading only that chunk's bytes where possible.
    ///
    /// Two paths. The **range path** reads the chunk's own bytes out of the
    /// bevy member and touches nothing else; it needs the bevy's index, which
    /// is small and cached, and it works only where the storage layer can
    /// address a member's interior. The **whole-bevy path** is the fallback,
    /// used when the storage layer cannot serve a range -- a deflated member,
    /// or a volume that does not implement ranged reads.
    ///
    /// The range path does not verify the member's CRC -- see
    /// [`Volume::read_segment_range`].
    fn decompress(&mut self, chunk_number: u64, locus: &Locus) -> Result<Vec<u8>> {
        let per_bevy = self.stream.chunks_in_segment as u64;
        let bevy_index = chunk_number / per_bevy;
        let within_bevy = usize::try_from(chunk_number % per_bevy).unwrap_or(0);

        // A bevy already resident costs nothing to slice, so the range read is
        // attempted only when it is not.
        //
        // This reader once counted how often each bevy was wanted while absent
        // and read the whole member after 32 such reads, on the theory that a
        // densely-read bevy amortizes the ~30 MiB. Measurement retired that
        // rule: it cost 42x on a scattered whole-file workload while saving
        // 1.07x on sequential reading.
        if !self.resident.iter().any(|b| b.index == bevy_index)
            && let Some(plain) =
                self.decompress_by_range(chunk_number, bevy_index, within_bevy, locus)?
        {
            return Ok(plain);
        }

        self.load_bevy(bevy_index, locus)?;

        // Populated by load_bevy, which errors rather than leaving it absent.
        let Some(bevy) = self.resident.iter().find(|b| b.index == bevy_index) else {
            return Err(Error::malformed(
                locus.clone(),
                format!("bevy {bevy_index} could not be held for reading"),
            ));
        };

        let location = bevy.locations.get(within_bevy).copied().ok_or_else(|| {
            Error::malformed(
                locus.clone(),
                format!(
                    "chunk {chunk_number} is chunk {within_bevy} of bevy \
                     {bevy_index}, whose index lists only {} chunks; the stream's \
                     declared size and its stored chunks disagree",
                    bevy.locations.len()
                ),
            )
        })?;

        let bevy_locus = locus
            .clone()
            .segment(format!("{bevy_index:08}"))
            .byte_offset(location.offset);

        let chunk = slice_chunk(&bevy.bytes, location, within_bevy, &bevy_locus)?;
        let mut plain = decompress_chunk(
            self.stream.codec,
            chunk,
            self.stream.chunk_size,
            &bevy_locus,
        )?;

        // The final chunk of a stream is short. Delivering its padding would
        // append bytes that were never part of the evidence.
        let chunk_start = chunk_number * self.stream.chunk_size as u64;
        let remaining = self.stream.size.saturating_sub(chunk_start);
        if (plain.len() as u64) > remaining {
            plain.truncate(usize::try_from(remaining).unwrap_or(plain.len()));
        }

        Ok(plain)
    }

    /// Read and decode one chunk without materializing its bevy.
    ///
    /// Returns [`None`] when the storage layer cannot address the member's
    /// interior, leaving the caller to fall back to a whole-bevy read. An
    /// inconsistency *within* data successfully read -- an index that points
    /// past the member, a chunk that will not decode -- is an error, not a
    /// [`None`]: falling back there would replace a finding about the evidence
    /// with a slower path to the same bytes.
    fn decompress_by_range(
        &mut self,
        chunk_number: u64,
        bevy_index: u64,
        within_bevy: usize,
        locus: &Locus,
    ) -> Result<Option<Vec<u8>>> {
        let Some(bevy_name) = self.stream.bevy_name(&self.volume_arn, bevy_index) else {
            return Ok(None);
        };

        let Some(location) = self.chunk_location(bevy_index, &bevy_name, within_bevy, locus)?
        else {
            return Ok(None);
        };

        let length = usize::try_from(location.length).unwrap_or(0);
        if length == 0 {
            return Ok(None);
        }

        let Some(stored) = self
            .volume
            .read_segment_range(&bevy_name, location.offset, length)?
        else {
            return Ok(None);
        };

        let bevy_locus = locus
            .clone()
            .segment(format!("{bevy_index:08}"))
            .byte_offset(location.offset);

        let mut plain = decompress_chunk(
            self.stream.codec,
            &stored,
            self.stream.chunk_size,
            &bevy_locus,
        )?;

        // As in the whole-bevy path: the stream's final chunk is short, and
        // delivering its padding would append bytes that were never evidence.
        let chunk_start = chunk_number * self.stream.chunk_size as u64;
        let remaining = self.stream.size.saturating_sub(chunk_start);
        if (plain.len() as u64) > remaining {
            plain.truncate(usize::try_from(remaining).unwrap_or(plain.len()));
        }

        Ok(Some(plain))
    }

    /// Where one chunk sits inside its bevy, reading and caching the index.
    ///
    /// [`None`] means the index segment is absent, which is a container the
    /// whole-bevy path should report rather than this one.
    fn chunk_location(
        &mut self,
        bevy_index: u64,
        bevy_name: &str,
        within_bevy: usize,
        locus: &Locus,
    ) -> Result<Option<ChunkLocation>> {
        if !self.index.contains_key(&bevy_index) {
            let index_name = format!("{bevy_name}{INDEX_SUFFIX}");
            if !self.volume.has_segment(&index_name) {
                return Ok(None);
            }
            let raw = self.volume.read_segment(&index_name)?;
            let locations = parse_index_bounded(
                &raw,
                self.stream.chunks_in_segment,
                &locus.clone().segment(&index_name),
            )?;
            self.index.insert(bevy_index, locations);
        }

        Ok(self
            .index
            .get(&bevy_index)
            .and_then(|l| l.get(within_bevy))
            .copied())
    }

    /// Make `bevy_index` the resident bevy, reading it if it is not already.
    fn load_bevy(&mut self, bevy_index: u64, locus: &Locus) -> Result<()> {
        // A hit moves the bevy to the most-recent end and reads nothing.
        if let Some(pos) = self.resident.iter().position(|b| b.index == bevy_index) {
            let hit = self.resident.remove(pos);
            self.resident.push(hit);
            return Ok(());
        }

        let bevy_name = self
            .stream
            .bevy_name(&self.volume_arn, bevy_index)
            .ok_or_else(|| {
                Error::malformed(
                    locus.clone(),
                    format!(
                        "stream {} names no member of volume {}; its data is stored \
                         elsewhere, which this build cannot follow",
                        self.stream.arn, self.volume_arn
                    ),
                )
            })?;

        let index_name = format!("{bevy_name}{INDEX_SUFFIX}");
        let index = self.volume.read_segment(&index_name)?;
        let locations = parse_index_bounded(
            &index,
            self.stream.chunks_in_segment,
            &locus.clone().segment(&index_name),
        )?;
        let bytes = self.volume.read_segment(&bevy_name)?;

        // The chunk cache is keyed by global chunk number, so it stays valid
        // across bevy changes and is deliberately not cleared here.

        // Evict least-recently-used until the newcomer fits, but never evict
        // everything: one bevy stays resident even if it alone exceeds the
        // budget, so an oversized container reads slowly rather than not at all.
        let incoming = bytes.len();
        while !self.resident.is_empty()
            && self.resident.iter().map(|b| b.bytes.len()).sum::<usize>() + incoming
                > BEVY_CACHE_BYTES
        {
            self.resident.remove(0);
        }

        self.resident.push(Bevy {
            index: bevy_index,
            bytes,
            locations,
        });

        Ok(())
    }
}

impl std::fmt::Debug for ChunkReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkReader")
            .field("stream", &self.stream.arn)
            .field(
                "resident_bevies",
                &self.resident.iter().map(|b| b.index).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Read a required unsigned integer property, or explain what is missing.
fn required_u64(
    graph: &Graph,
    arn: &Arn,
    predicate: &str,
    label: &str,
    locus: &Locus,
) -> Result<u64> {
    let locus = locus.clone().predicate(predicate);

    let value = graph.object(arn.as_str(), predicate).ok_or_else(|| {
        Error::malformed(
            locus.clone(),
            format!("the stream declares no {label}; it cannot be read without one"),
        )
    })?;

    value.lexical().trim().parse::<u64>().map_err(|e| {
        Error::malformed(
            locus,
            format!(
                "{label} is {:?}, which is not a whole number: {e}",
                value.lexical()
            ),
        )
    })
}

/// Decode a bevy index into chunk locations.
///
/// # Errors
///
/// [`Error::Malformed`] if the index is empty or not a whole number of
/// 12-byte entries.
pub fn parse_index(bytes: &[u8], locus: &Locus) -> Result<Vec<ChunkLocation>> {
    if bytes.is_empty() {
        return Err(Error::malformed(
            locus.clone(),
            "the bevy index is empty; the bevy holds no locatable chunks".to_owned(),
        ));
    }

    if !bytes.len().is_multiple_of(INDEX_ENTRY_LEN) {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "the bevy index is {} bytes, not a whole number of {INDEX_ENTRY_LEN}-byte \
                 entries ({} left over)",
                bytes.len(),
                bytes.len() % INDEX_ENTRY_LEN
            ),
        ));
    }

    Ok(bytes
        .as_chunks::<INDEX_ENTRY_LEN>()
        .0
        .iter()
        .map(|entry| {
            // `as_chunks` yields fixed-size arrays, so the widths are guaranteed
            // by the type and these cannot fail.
            let offset = u64::from_le_bytes(entry[..8].try_into().unwrap_or([0; 8]));
            let length = u32::from_le_bytes(entry[8..12].try_into().unwrap_or([0; 4]));
            ChunkLocation { offset, length }
        })
        .collect())
}

/// Decode a bevy index, refusing one that lists more chunks than a bevy holds.
///
/// The stream declares `chunksInSegment`, which fixes exactly how many entries
/// a bevy's index can carry. An index longer than that is inconsistent with the
/// metadata no matter what the extra entries say, and reading it costs 12 bytes
/// of allocation per bogus entry — a 256 MiB index of zeros is a few hundred
/// kilobytes of stored evidence.
///
/// [`parse_index`] is the unbounded form, kept for callers with no stream in
/// hand; prefer this wherever the stream is known.
///
/// # Errors
///
/// As [`parse_index`], plus [`Error::Malformed`] if the index lists more than
/// `chunks_in_segment` entries.
pub fn parse_index_bounded(
    bytes: &[u8],
    chunks_in_segment: usize,
    locus: &Locus,
) -> Result<Vec<ChunkLocation>> {
    let entries = bytes.len() / INDEX_ENTRY_LEN;
    if entries > chunks_in_segment {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "the bevy index lists {entries} chunks but the stream declares \
                 {chunks_in_segment} chunks per bevy; the index and the metadata \
                 disagree, so no chunk in it can be located with confidence"
            ),
        ));
    }

    parse_index(bytes, locus)
}

/// Borrow one chunk out of a bevy, checking it lies within bounds.
fn slice_chunk<'b>(
    bevy: &'b [u8],
    location: ChunkLocation,
    chunk_index: usize,
    locus: &Locus,
) -> Result<&'b [u8]> {
    let start = usize::try_from(location.offset).map_err(|_| {
        Error::malformed(
            locus.clone(),
            format!("chunk {chunk_index} claims offset {} ", location.offset),
        )
    })?;

    let length = location.length as usize;
    let end = start.checked_add(length).ok_or_else(|| {
        Error::malformed(
            locus.clone(),
            format!(
                "chunk {chunk_index} at offset {start} with length {length} overflows \
                 when added"
            ),
        )
    })?;

    if end > bevy.len() {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "chunk {chunk_index} spans bytes {start}..{end} but the bevy is only \
                 {} bytes; the index and the bevy disagree",
                bevy.len()
            ),
        ));
    }

    if length == 0 {
        return Err(Error::malformed(
            locus.clone(),
            format!("chunk {chunk_index} has zero length; a chunk always holds data"),
        ));
    }

    Ok(&bevy[start..end])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn locus() -> Locus {
        Locus::new("/evidence/case.aff4")
    }

    fn entry(offset: u64, length: u32) -> Vec<u8> {
        let mut v = offset.to_le_bytes().to_vec();
        v.extend_from_slice(&length.to_le_bytes());
        v
    }

    /// The width is 12, not 16. Getting this wrong produces offsets that look
    /// plausible enough to chase for a while.
    #[test]
    fn index_entries_are_twelve_bytes() {
        assert_eq!(INDEX_ENTRY_LEN, 12);

        let mut bytes = entry(0, 1974);
        bytes.extend(entry(1974, 24668));
        assert_eq!(bytes.len(), 24);

        let locations = parse_index(&bytes, &locus()).unwrap();
        assert_eq!(locations.len(), 2);
        assert_eq!(
            locations[0],
            ChunkLocation {
                offset: 0,
                length: 1974
            }
        );
        assert_eq!(
            locations[1],
            ChunkLocation {
                offset: 1974,
                length: 24668
            }
        );
    }

    /// Values measured from `Base-Linear.aff4`'s real index.
    #[test]
    fn decodes_the_measured_index_prefix() {
        let mut bytes = entry(0, 1974);
        bytes.extend(entry(1974, 24668));
        bytes.extend(entry(26642, 32751));
        bytes.extend(entry(59393, 32768));

        let locations = parse_index(&bytes, &locus()).unwrap();
        assert_eq!(locations.len(), 4);
        // Chunk 3 is exactly one chunk long: stored verbatim, not compressed.
        assert_eq!(locations[3].length, 32768);
    }

    #[test]
    fn a_ragged_index_is_malformed() {
        let mut bytes = entry(0, 100);
        bytes.push(0xAB);

        let err = parse_index(&bytes, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("13 bytes"), "{err}");
        assert!(err.to_string().contains("1 left over"), "{err}");
    }

    #[test]
    fn an_empty_index_is_malformed() {
        let err = parse_index(&[], &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// An index padded far past `chunksInSegment` is refused.
    ///
    /// The padded form is cheap to write and expensive to read: 256 MiB of
    /// zeros stores as a few hundred kilobytes and previously parsed into
    /// 22 million `ChunkLocation`s, all of them bogus. The stream's own
    /// declared `chunksInSegment` is the bound.
    #[test]
    fn an_index_longer_than_chunks_in_segment_is_malformed() {
        // Four entries against a stream declaring two chunks per bevy.
        let mut bytes = entry(0, 10);
        bytes.extend(entry(10, 10));
        bytes.extend(entry(20, 10));
        bytes.extend(entry(30, 10));

        let err = parse_index_bounded(&bytes, 2, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        let text = err.to_string();
        assert!(text.contains("lists 4 chunks"), "{text}");
        assert!(text.contains("declares 2"), "{text}");

        // Zero-padding is what a bomb actually looks like: entries that decode
        // to nothing but still cost an allocation each.
        let padded = vec![0u8; 4096 * INDEX_ENTRY_LEN];
        assert!(parse_index_bounded(&padded, 2, &locus()).is_err());
    }

    /// An index exactly filling its bevy, and a short final one, both pass.
    #[test]
    fn an_index_within_chunks_in_segment_is_accepted() {
        let mut bytes = entry(0, 10);
        bytes.extend(entry(10, 10));

        assert_eq!(parse_index_bounded(&bytes, 2, &locus()).unwrap().len(), 2);
        // The last bevy of a stream is short, so fewer entries must be fine.
        assert_eq!(
            parse_index_bounded(&bytes, 2048, &locus()).unwrap().len(),
            2
        );
    }

    /// 1452 bytes is the real length of `Base-Linear.aff4`'s index.
    #[test]
    fn the_measured_index_length_yields_the_measured_chunk_count() {
        assert_eq!(1452 % INDEX_ENTRY_LEN, 0);
        assert_eq!(1452 / INDEX_ENTRY_LEN, 121);
    }

    #[test]
    fn a_chunk_past_the_end_of_its_bevy_is_malformed() {
        let bevy = vec![0u8; 100];
        let err = slice_chunk(
            &bevy,
            ChunkLocation {
                offset: 90,
                length: 20,
            },
            7,
            &locus(),
        )
        .unwrap_err();

        assert!(err.is_integrity_finding(), "{err}");
        let text = err.to_string();
        assert!(text.contains("chunk 7"), "{text}");
        assert!(text.contains("90..110"), "{text}");
        assert!(text.contains("100 bytes"), "{text}");
    }

    #[test]
    fn a_zero_length_chunk_is_malformed() {
        let bevy = vec![0u8; 100];
        let err = slice_chunk(
            &bevy,
            ChunkLocation {
                offset: 0,
                length: 0,
            },
            0,
            &locus(),
        )
        .unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    #[test]
    fn an_offset_and_length_that_overflow_are_malformed() {
        let bevy = vec![0u8; 100];
        let err = slice_chunk(
            &bevy,
            ChunkLocation {
                offset: u64::MAX,
                length: u32::MAX,
            },
            0,
            &locus(),
        )
        .unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    #[test]
    fn a_chunk_is_borrowed_within_bounds() {
        let bevy: Vec<u8> = (0..100u8).collect();
        let chunk = slice_chunk(
            &bevy,
            ChunkLocation {
                offset: 10,
                length: 5,
            },
            0,
            &locus(),
        )
        .unwrap();
        assert_eq!(chunk, &[10, 11, 12, 13, 14]);
    }

    /// Bevy names are `%08d`, appended to the stream's escaped member name.
    #[test]
    fn bevy_names_are_eight_digit_zero_padded() {
        let volume = Arn::parse("aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044", &locus()).unwrap();
        let stream = ImageStream {
            arn: Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus()).unwrap(),
            size: 3_964_928,
            chunk_size: 32768,
            chunks_in_segment: 2048,
            codec: Codec::Snappy,
        };

        assert_eq!(
            stream.bevy_name(&volume, 0).unwrap(),
            "aff4%3A%2F%2Fc215ba20-5648-4209-a793-1f918c723610/00000000"
        );
        assert_eq!(
            stream.bevy_name(&volume, 42).unwrap(),
            "aff4%3A%2F%2Fc215ba20-5648-4209-a793-1f918c723610/00000042"
        );
    }

    /// `Base-Linear.aff4`: 3964928 bytes at 32768 per chunk, 2048 per bevy —
    /// 121 chunks, all within one bevy.
    #[test]
    fn bevy_count_follows_from_size() {
        let stream = ImageStream {
            arn: Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus()).unwrap(),
            size: 3_964_928,
            chunk_size: 32768,
            chunks_in_segment: 2048,
            codec: Codec::Snappy,
        };
        assert_eq!(stream.bevy_count(), 1);

        // A stream exactly filling two bevies.
        let two = ImageStream {
            size: 32768 * 2048 * 2,
            ..stream.clone()
        };
        assert_eq!(two.bevy_count(), 2);

        // One byte more needs a third.
        let three = ImageStream {
            size: 32768 * 2048 * 2 + 1,
            ..stream.clone()
        };
        assert_eq!(three.bevy_count(), 3);
    }
}
