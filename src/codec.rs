//! Chunk compression codecs.
//!
//! AFF4 `ImageStream`s store data in fixed-size chunks, each compressed
//! independently and identified by a codec IRI in the metadata. This module
//! resolves those IRIs and decompresses chunks.
//!
//! # Deliberately I/O-free
//!
//! Nothing here opens a file or knows what a ZIP or a bevy is. A caller hands
//! over bytes and the stream's declared chunk size; this module hands back
//! bytes. Bevy indexing and chunk assembly belong to `stream.rs`.
//!
//! # The IRIs
//!
//! Six, across the two reference implementations:
//!
//! | Codec | IRI |
//! |---|---|
//! | Stored | `http://aff4.org/Schema#compression/stored` |
//! | Stored (alias) | `http://aff4.org/Schema#NullCompressor` |
//! | Snappy | `http://code.google.com/p/snappy/` |
//! | Snappy (Rekall) | `https://github.com/google/snappy` |
//! | Zlib | `https://www.ietf.org/rfc/rfc1950.txt` |
//! | Deflate | `https://tools.ietf.org/html/rfc1951` |
//! | LZ4 | `https://code.google.com/p/lz4/` |
//!
//! # Zlib and deflate are not the same codec
//!
//! Deflate is the algorithm zlib uses, but AFF4 assigns the two **separate
//! IRIs** because they are different wire formats:
//!
//! - **RFC 1950** (zlib) wraps the compressed stream in a 2-byte header and an
//!   Adler-32 trailer.
//! - **RFC 1951** (deflate) is the bare stream, no header and no checksum.
//!
//! aff4-cpp-lite implements both and the difference is visible in the calls:
//! `ZlibCompression.cc:37` uses `::uncompress()`, which requires the RFC 1950
//! header, while `DeflateCompression.cc:44` uses `inflateInit2(&zstream, -15)`
//! — the negative windowBits being zlib's documented request for raw inflate.
//! Feeding one format to the other's decoder fails. pyaff4 implements only
//! zlib; raw deflate has no Python counterpart.
//!
//! # Incompressible chunks are stored verbatim
//!
//! A writer that cannot shrink a chunk emits it uncompressed, with **no marker
//! in the data**. The only signal is `input.len() == chunk_size`. That check
//! lives in [`decompress_chunk`] rather than in callers, so it cannot be
//! forgotten — missing it means feeding raw disk sectors to a decompressor and
//! failing on valid evidence.
//!
//! The one exception is [`Codec::SnappyRekall`], where chunks are always
//! compressed; pyaff4 skips the check for that dialect alone
//! (`aff4_image.py:680`).

use crate::error::{Error, Feature, Locus, Result};

/// The IRI for explicitly-stored (uncompressed) chunks.
pub const STORED_IRI: &str = "http://aff4.org/Schema#compression/stored";

/// An alias for [`STORED_IRI`] used by some writers.
pub const NULL_COMPRESSOR_IRI: &str = "http://aff4.org/Schema#NullCompressor";

/// The IRI for Snappy, as written by standard-conforming implementations.
pub const SNAPPY_IRI: &str = "http://code.google.com/p/snappy/";

/// The IRI for Snappy as written by the Rekall/winpmem dialect.
pub const SNAPPY_REKALL_IRI: &str = "https://github.com/google/snappy";

/// The IRI for zlib (RFC 1950): deflate with header and Adler-32 checksum.
pub const ZLIB_IRI: &str = "https://www.ietf.org/rfc/rfc1950.txt";

/// The IRI for raw deflate (RFC 1951): no header, no checksum.
pub const DEFLATE_IRI: &str = "https://tools.ietf.org/html/rfc1951";

/// The IRI for LZ4 block format.
pub const LZ4_IRI: &str = "https://code.google.com/p/lz4/";

/// The largest chunk this module will ever allocate for, in bytes.
///
/// `chunk_size` reaches these functions from `aff4:chunkSize` in container
/// metadata, so it is evidence-derived and cannot be trusted as an allocation
/// size: a damaged or hostile container declaring a huge value would otherwise
/// abort the process on a capacity overflow before a single byte was read.
///
/// Real containers use 32 KiB (every corpus fixture). 64 MiB is far above
/// anything a writer produces while staying trivially allocatable, so a chunk
/// size beyond it is itself the finding.
pub const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// Render a byte count in binary units, for messages an examiner reads.
///
/// Exact values are always shown alongside this, never replaced by it — a
/// rounded size must not be the only figure in a forensic report.
pub(crate) fn human_bytes(bytes: usize) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    // Integer arithmetic throughout: no float conversion, so no precision
    // question to reason about. The tenths are computed, not rounded by a
    // formatter.
    let b = bytes as u64;
    let render = |unit: u64, suffix: &str| {
        let whole = b / unit;
        let tenths = (b % unit) * 10 / unit;
        format!("{whole}.{tenths} {suffix}")
    };

    match b {
        b if b >= GIB => render(GIB, "GiB"),
        b if b >= MIB => render(MIB, "MiB"),
        b if b >= KIB => render(KIB, "KiB"),
        _ => format!("{bytes} bytes"),
    }
}

/// A chunk compression codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    /// No compression; chunks are stored verbatim.
    Stored,
    /// Snappy, raw block format.
    Snappy,
    /// Snappy as written by Rekall/winpmem, where chunks are always
    /// compressed — the stored-chunk shortcut does not apply.
    SnappyRekall,
    /// Zlib (RFC 1950): deflate framed with a header and Adler-32 trailer.
    Zlib,
    /// Raw deflate (RFC 1951): no framing. Not the same as [`Codec::Zlib`].
    Deflate,
    /// LZ4 block format. Needs the uncompressed size supplied by the caller.
    Lz4,
}

impl Codec {
    /// Resolve a codec from its metadata IRI.
    ///
    /// Returns `None` for an unrecognised IRI. Callers turn that into
    /// [`Feature::Codec`] via [`Codec::unsupported`] — an unknown codec is a
    /// gap in this build, never an integrity finding about the container.
    #[must_use]
    pub fn from_iri(iri: &str) -> Option<Self> {
        match iri {
            STORED_IRI | NULL_COMPRESSOR_IRI => Some(Self::Stored),
            SNAPPY_IRI => Some(Self::Snappy),
            SNAPPY_REKALL_IRI => Some(Self::SnappyRekall),
            ZLIB_IRI => Some(Self::Zlib),
            DEFLATE_IRI => Some(Self::Deflate),
            LZ4_IRI => Some(Self::Lz4),
            _ => None,
        }
    }

    /// The canonical IRI for this codec.
    ///
    /// Round-trips through [`Codec::from_iri`]. Note [`Codec::Stored`] has two
    /// spellings in the wild and this returns [`STORED_IRI`], so the round trip
    /// is canonical rather than byte-preserving.
    #[must_use]
    pub fn iri(self) -> &'static str {
        match self {
            Self::Stored => STORED_IRI,
            Self::Snappy => SNAPPY_IRI,
            Self::SnappyRekall => SNAPPY_REKALL_IRI,
            Self::Zlib => ZLIB_IRI,
            Self::Deflate => DEFLATE_IRI,
            Self::Lz4 => LZ4_IRI,
        }
    }

    /// A short name for reports and messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Snappy => "snappy",
            Self::SnappyRekall => "snappy (Rekall dialect)",
            Self::Zlib => "zlib",
            Self::Deflate => "deflate",
            Self::Lz4 => "lz4",
        }
    }

    /// Whether a chunk whose compressed length equals the chunk size should be
    /// taken as stored verbatim.
    ///
    /// True for every codec but [`Codec::SnappyRekall`], which always
    /// compresses. See the module documentation.
    #[must_use]
    pub fn honours_stored_chunks(self) -> bool {
        !matches!(self, Self::SnappyRekall)
    }

    /// Whether this build can decompress the codec.
    ///
    /// True where there is evidence behind the decoder: a corpus fixture
    /// (snappy), nothing to get wrong (stored), or byte vectors generated by
    /// pyaff4's own calls (zlib, LZ4).
    ///
    /// False for codecs with no fixture and no way to obtain one — see
    /// [`Codec::no_fixture_reason`]. Refusing is deliberate: shipping a
    /// decompression path that has never seen real data would mean claiming
    /// untested correctness about evidence.
    #[must_use]
    pub fn is_implemented(self) -> bool {
        matches!(self, Self::Stored | Self::Snappy | Self::Zlib | Self::Lz4)
    }

    /// Why a codec is declined, when the reason is a missing fixture rather
    /// than unfinished work.
    ///
    /// [`Codec::Deflate`] and [`Codec::SnappyRekall`] are recognised but not
    /// decompressed: no container in the reference corpus uses either, and
    /// neither can be generated — pyaff4 implements no raw deflate at all, and
    /// the Rekall dialect has no writer available here. Only aff4-cpp-lite
    /// writes raw deflate, and building it requires libsnappy and autotools.
    #[must_use]
    pub fn no_fixture_reason(self) -> Option<&'static str> {
        match self {
            Self::Deflate => Some(
                "no container in the reference corpus uses raw deflate (RFC 1951), \
                 and pyaff4 cannot write it, so this decoder has never been \
                 tested against real evidence",
            ),
            Self::SnappyRekall => Some(
                "no container in the reference corpus uses the Rekall/winpmem \
                 snappy dialect, and no writer for it is available here, so this \
                 decoder has never been tested against real evidence",
            ),
            _ => None,
        }
    }

    /// Build the [`Error::Unsupported`] for an IRI this build cannot handle.
    #[must_use]
    pub fn unsupported(iri: &str, context: impl Into<String>) -> Error {
        Error::unsupported(
            Feature::Codec {
                iri: iri.to_owned(),
            },
            context,
        )
    }

    /// The full explanation shown when this codec is declined, including how
    /// to get it supported.
    ///
    /// Spelled out rather than terse because encountering one of these means
    /// the examiner holds a container this project has never seen — which is
    /// exactly the container needed to fix it.
    #[must_use]
    pub fn declined_detail(self, locus: &Locus) -> String {
        // Writing into a String is infallible; the discarded Results below
        // cannot carry an error. Nothing is being swallowed.
        use std::fmt::Write as _;

        let mut detail = format!(
            "compression codec {} ({}) is recognised but not decompressed",
            self.name(),
            self.iri()
        );

        if let Some(reason) = self.no_fixture_reason() {
            let _ = write!(detail, "\n  reason:    {reason}");
        }

        let _ = write!(detail, "\n  container: {}", locus.path.display());
        if let Some(segment) = &locus.segment {
            let _ = write!(detail, "\n  segment:   {segment}");
        }
        if let Some(subject) = &locus.subject {
            let _ = write!(detail, "\n  subject:   {subject}");
        }

        detail.push_str(
            "\n  action:    please contact the aff4tools developer with a sample \
             AFF4 container using this compression method, so support can be \
             implemented and tested against real evidence rather than guessed.",
        );

        detail
    }
}

impl std::fmt::Display for Codec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Decompress one chunk.
///
/// `chunk_size` is the stream's declared uncompressed chunk length: LZ4 needs
/// it, and every other codec uses it to recognise a stored chunk.
///
/// # Errors
///
/// [`Error::Unsupported`] for a codec this build declines — a capability gap,
/// never a statement about the evidence. [`Error::Malformed`] for a chunk that
/// will not decompress, or one that decompresses to the wrong length: both are
/// integrity findings.
pub fn decompress_chunk(
    codec: Codec,
    input: &[u8],
    chunk_size: usize,
    locus: &Locus,
) -> Result<Vec<u8>> {
    // `chunk_size` comes from container metadata. Refuse an implausible value
    // before it is ever used as an allocation size — see [`MAX_CHUNK_SIZE`].
    if chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "the container declares a chunk size of {chunk_size} bytes \
                 ({}), which exceeds this build's {MAX_CHUNK_SIZE} byte ({}) ceiling\
                 \n  read from:  aff4:chunkSize in the container metadata\
                 \n  expected:   32768 bytes, the value every known writer uses\
                 \n  refused by: aff4tools, before decompressing, because a chunk \
                 size this large is either damaged metadata or an attempt to \
                 exhaust memory\
                 \n  note:       no data was read; this is a finding about the \
                 metadata, not about the chunk",
                human_bytes(chunk_size),
                human_bytes(MAX_CHUNK_SIZE),
            ),
        ));
    }

    if codec.honours_stored_chunks() && input.len() == chunk_size {
        return Ok(input.to_vec());
    }

    if !codec.is_implemented() {
        return Err(Codec::unsupported(
            codec.iri(),
            codec.declined_detail(locus),
        ));
    }

    let out = match codec {
        // A stored chunk shorter than chunk_size is the stream's last chunk.
        Codec::Stored => input.to_vec(),
        Codec::Snappy | Codec::SnappyRekall => decompress_snappy(input, chunk_size, locus)?,
        Codec::Zlib => decompress_zlib(input, chunk_size, locus)?,
        Codec::Lz4 => decompress_lz4(input, chunk_size, locus)?,
        Codec::Deflate => {
            return Err(Codec::unsupported(
                codec.iri(),
                codec.declined_detail(locus),
            ));
        }
    };

    if out.len() > chunk_size {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "{} chunk decompressed to {} bytes, larger than the declared \
                 chunk size of {chunk_size}",
                codec.name(),
                out.len()
            ),
        ));
    }

    Ok(out)
}

/// Snappy raw block format — not the framed format.
///
/// pyaff4 calls `snappy.compress`/`decompress`, python-snappy's raw block API
/// (`aff4_image.py:683`). Verified against bytes: the first chunk of
/// `Base-Linear.aff4` begins `80 80 02`, a raw-format varint of 32768. A
/// framed decoder would reject it — the frame format opens with a `0xff`
/// stream identifier.
fn decompress_snappy(input: &[u8], chunk_size: usize, locus: &Locus) -> Result<Vec<u8>> {
    // The declared length is read from evidence, so treat it as hostile: cap
    // the allocation at the chunk size rather than trusting the varint.
    let declared = snap::raw::decompress_len(input).map_err(|e| {
        Error::malformed(
            locus.clone(),
            format!("snappy chunk has an unreadable length header: {e}"),
        )
    })?;

    if declared > chunk_size {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "snappy chunk declares {declared} bytes, larger than the \
                 declared chunk size of {chunk_size}"
            ),
        ));
    }

    // A chunk carrying no data is not a real chunk. `snap` accepts a bare
    // 0x00 varint as "decompresses to nothing", which would hand a caller an
    // empty buffer to hash as though it were evidence.
    if declared == 0 {
        return Err(Error::malformed(
            locus.clone(),
            "snappy chunk declares zero bytes; a chunk always carries data".to_owned(),
        ));
    }

    snap::raw::Decoder::new()
        .decompress_vec(input)
        .map_err(|e| {
            Error::malformed(
                locus.clone(),
                format!("snappy chunk will not decompress: {e}"),
            )
        })
}

/// Zlib (RFC 1950): deflate wrapped in a header and Adler-32 trailer.
///
/// pyaff4 calls `zlib.decompress(cbuffer)` (`aff4_image.py:673`), the standard
/// library's RFC 1950 entry point. Not interchangeable with
/// [`Codec::Deflate`]; see the module documentation.
///
/// # Truncation must not pass as success
///
/// `ZlibDecoder` + `read_to_end` returns `Ok` with **partial data** on a
/// truncated stream: the short read looks like a clean EOF, and the Adler-32
/// trailer that would have caught it is never reached. Verified directly —
/// half a valid stream yields `Ok(12664)` of an expected 32768 bytes.
///
/// So this uses [`flate2::Decompress`] instead, which reports
/// `Status::StreamEnd` only when the trailer has been validated. Anything else
/// is an integrity finding.
///
/// The output buffer is capped at `chunk_size + 1`: a stream that expands
/// beyond its declared size fills the extra byte and is rejected, rather than
/// being allowed to exhaust memory.
fn decompress_zlib(input: &[u8], chunk_size: usize, locus: &Locus) -> Result<Vec<u8>> {
    use flate2::{Decompress, FlushDecompress, Status};

    // `decompress_vec` will not grow the buffer past its capacity — it stops
    // and reports BufError, which reads as truncation. So the capacity must
    // hold a full chunk, plus one byte to detect overrun. Safe to allocate
    // because `decompress_chunk` has already bounded chunk_size by
    // MAX_CHUNK_SIZE.
    debug_assert!(chunk_size <= MAX_CHUNK_SIZE);
    let mut out = Vec::with_capacity(chunk_size.min(MAX_CHUNK_SIZE).saturating_add(1));
    let mut decoder = Decompress::new(true);

    let status = decoder
        .decompress_vec(input, &mut out, FlushDecompress::Finish)
        .map_err(|e| {
            Error::malformed(
                locus.clone(),
                format!("zlib chunk will not decompress: {e}"),
            )
        })?;

    if out.len() > chunk_size {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "zlib chunk decompressed past the declared chunk size of \
                 {chunk_size}, which is larger than a chunk can be"
            ),
        ));
    }

    if status != Status::StreamEnd {
        return Err(Error::malformed(
            locus.clone(),
            format!(
                "zlib chunk is truncated or corrupt: the stream ended without \
                 its Adler-32 trailer after {} of {} compressed bytes",
                decoder.total_in(),
                input.len()
            ),
        ));
    }

    if out.is_empty() {
        return Err(Error::malformed(
            locus.clone(),
            "zlib chunk decompressed to zero bytes; a chunk always carries data".to_owned(),
        ));
    }

    Ok(out)
}

/// LZ4 block format, with the uncompressed size supplied by the caller.
///
/// This matches pyaff4's **read** path: `lz4.block.decompress(cbuffer,
/// self.chunk_size)` (`aff4_image.py:678`). Passing an explicit size means the
/// input carries no 4-byte size prefix.
///
/// # pyaff4's write path disagrees with its own read path
///
/// `aff4_image.py:262` calls `lz4.block.compress(chunk)`, which defaults to
/// `store_size=True` and **prepends a 4-byte little-endian size header**.
/// Feeding that output back to line 678 fails: verified directly, a
/// round trip through pyaff4's own two calls raises *"corrupt input or
/// insufficient space in destination buffer"*.
///
/// aff4tools is a reader, so it matches the read path — headerless block
/// format. A container written by pyaff4's LZ4 path would carry the header and
/// fail here, exactly as it fails in pyaff4 itself. No such container exists in
/// the corpus to check against, which is part of why LZ4 has no fixture.
fn decompress_lz4(input: &[u8], chunk_size: usize, locus: &Locus) -> Result<Vec<u8>> {
    let out = lz4_flex::block::decompress(input, chunk_size).map_err(|e| {
        Error::malformed(locus.clone(), format!("lz4 chunk will not decompress: {e}"))
    })?;

    if out.is_empty() {
        return Err(Error::malformed(
            locus.clone(),
            "lz4 chunk decompressed to zero bytes; a chunk always carries data".to_owned(),
        ));
    }

    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Every IRI the two reference implementations write, read back.
    #[test]
    fn resolves_every_known_iri() {
        assert_eq!(Codec::from_iri(STORED_IRI), Some(Codec::Stored));
        assert_eq!(Codec::from_iri(NULL_COMPRESSOR_IRI), Some(Codec::Stored));
        assert_eq!(Codec::from_iri(SNAPPY_IRI), Some(Codec::Snappy));
        assert_eq!(
            Codec::from_iri(SNAPPY_REKALL_IRI),
            Some(Codec::SnappyRekall)
        );
        assert_eq!(Codec::from_iri(ZLIB_IRI), Some(Codec::Zlib));
        assert_eq!(Codec::from_iri(DEFLATE_IRI), Some(Codec::Deflate));
        assert_eq!(Codec::from_iri(LZ4_IRI), Some(Codec::Lz4));
    }

    /// The distinction that would be easy to collapse: zlib and raw deflate
    /// are different codecs with different IRIs and different wire formats.
    #[test]
    fn zlib_and_deflate_are_distinct() {
        assert_ne!(Codec::Zlib, Codec::Deflate);
        assert_ne!(ZLIB_IRI, DEFLATE_IRI);
        assert_eq!(Codec::from_iri(ZLIB_IRI), Some(Codec::Zlib));
        assert_eq!(Codec::from_iri(DEFLATE_IRI), Some(Codec::Deflate));
        assert_ne!(Codec::Zlib.iri(), Codec::Deflate.iri());
    }

    /// Both snappy spellings resolve, but not to the same variant: the Rekall
    /// one suppresses the stored-chunk shortcut.
    #[test]
    fn the_two_snappy_iris_are_not_interchangeable() {
        assert_ne!(Codec::Snappy, Codec::SnappyRekall);
        assert!(Codec::Snappy.honours_stored_chunks());
        assert!(!Codec::SnappyRekall.honours_stored_chunks());
    }

    #[test]
    fn unknown_iris_do_not_resolve() {
        for iri in [
            "",
            "http://example.com/#codec",
            "https://tukaani.org/xz/",
            "http://aff4.org/Schema#compression/Stored",
            "HTTP://CODE.GOOGLE.COM/P/SNAPPY/",
            " http://code.google.com/p/snappy/",
        ] {
            assert_eq!(Codec::from_iri(iri), None, "{iri} must not resolve");
        }
    }

    /// xz is named in the README but does not exist in AFF4.
    #[test]
    fn xz_is_not_a_codec() {
        assert_eq!(Codec::from_iri("https://tukaani.org/xz/"), None);
        assert!(!ALL.iter().any(|c| c.name().contains("xz")));
    }

    const ALL: [Codec; 6] = [
        Codec::Stored,
        Codec::Snappy,
        Codec::SnappyRekall,
        Codec::Zlib,
        Codec::Deflate,
        Codec::Lz4,
    ];

    #[test]
    fn iris_round_trip_through_resolution() {
        for codec in ALL {
            assert_eq!(Codec::from_iri(codec.iri()), Some(codec), "{codec}");
        }
    }

    #[test]
    fn every_codec_has_a_distinct_iri_and_name() {
        for (i, a) in ALL.iter().enumerate() {
            for b in &ALL[i + 1..] {
                assert_ne!(a.iri(), b.iri(), "{a} and {b} share an IRI");
                assert_ne!(a.name(), b.name(), "{a} and {b} share a name");
            }
        }
    }

    /// Stored returns its input unchanged, at any length.
    #[test]
    fn stored_chunks_pass_through() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vec![0xAB; 32768];

        let out = decompress_chunk(Codec::Stored, &data, 32768, &locus).unwrap();
        assert_eq!(out, data);

        // A short final chunk is still stored verbatim.
        let tail = vec![0xCD; 100];
        let out = decompress_chunk(Codec::Stored, &tail, 32768, &locus).unwrap();
        assert_eq!(out, tail);
    }

    /// The rule that keeps valid evidence from failing: an incompressible
    /// chunk in a compressed stream is stored verbatim with no marker.
    #[test]
    fn a_full_length_chunk_is_taken_as_stored() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vec![0x5A; 32768];

        for codec in [Codec::Snappy, Codec::Zlib, Codec::Deflate, Codec::Lz4] {
            let out = decompress_chunk(codec, &data, 32768, &locus).unwrap();
            assert_eq!(out, data, "{codec} must pass a full-length chunk through");
        }
    }

    /// Rekall always compresses, so a full-length chunk is not a stored chunk
    /// — it falls through to the declined path rather than passing through.
    #[test]
    fn rekall_snappy_does_not_take_a_full_chunk_as_stored() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vec![0x5A; 32768];

        let err = decompress_chunk(Codec::SnappyRekall, &data, 32768, &locus).unwrap_err();
        assert!(matches!(err, Error::Unsupported { .. }), "{err}");
    }

    /// A declined codec is a capability gap, never an integrity finding.
    #[test]
    fn declined_codecs_are_unsupported_not_malformed() {
        let locus = Locus::new("/evidence/case.aff4");
        let short = vec![0u8; 100];

        for codec in [Codec::Deflate, Codec::SnappyRekall] {
            let err = decompress_chunk(codec, &short, 32768, &locus).unwrap_err();
            assert!(matches!(err, Error::Unsupported { .. }), "{codec}: {err}");
            assert!(
                !err.is_integrity_finding(),
                "{codec} must not read as evidence damage"
            );
        }
    }

    /// The unsupported error names the IRI, so a report says which codec.
    #[test]
    fn the_unsupported_error_names_the_codec_iri() {
        let err = Codec::unsupported(LZ4_IRI, "reading chunk 3");
        let rendered = err.to_string();

        assert!(rendered.contains(LZ4_IRI), "{rendered}");
        assert!(!err.is_integrity_finding());
    }

    /// Exactly the codecs with a fixture, or with nothing to get wrong, are
    /// implemented. The rest are declined by decision, not by oversight.
    #[test]
    fn only_codecs_with_evidence_behind_them_are_implemented() {
        // Corpus-backed, or nothing to get wrong.
        assert!(Codec::Stored.is_implemented());
        assert!(Codec::Snappy.is_implemented());
        // Vector-backed: bytes generated by pyaff4's own calls.
        assert!(Codec::Zlib.is_implemented());
        assert!(Codec::Lz4.is_implemented());

        // Neither a fixture nor any route to one.
        for codec in [Codec::Deflate, Codec::SnappyRekall] {
            assert!(!codec.is_implemented(), "{codec} must not claim support");
        }
    }

    /// The two codecs that cannot be fixture-backed at all say why, and tell
    /// the user how to get them supported.
    #[test]
    fn codecs_without_any_route_to_a_fixture_explain_themselves() {
        let locus = Locus::new("/evidence/case.aff4").segment("chunk 3");

        for codec in [Codec::Deflate, Codec::SnappyRekall] {
            assert!(
                codec.no_fixture_reason().is_some(),
                "{codec} must state why it is declined"
            );

            let detail = codec.declined_detail(&locus);
            assert!(detail.contains(codec.iri()), "{detail}");
            assert!(detail.contains("/evidence/case.aff4"), "{detail}");
            assert!(detail.contains("chunk 3"), "{detail}");
            assert!(
                detail.contains("contact the aff4tools developer"),
                "{codec} must tell the user how to get support: {detail}"
            );
            assert!(
                detail.contains("sample AFF4 container"),
                "{codec} must ask for a sample: {detail}"
            );
        }

        // Zlib and LZ4 are merely not-yet-implemented, so they carry no
        // missing-fixture reason: a vector can be generated for them.
        assert_eq!(Codec::Zlib.no_fixture_reason(), None);
        assert_eq!(Codec::Lz4.no_fixture_reason(), None);
    }

    /// The declined message reaches the user through the error, not just the
    /// helper — a detail no caller renders is not a message.
    #[test]
    fn the_declined_message_survives_into_the_error() {
        let locus = Locus::new("/evidence/case.aff4");
        let short = vec![0u8; 100];

        let err = decompress_chunk(Codec::Deflate, &short, 32768, &locus).unwrap_err();
        let rendered = err.to_string();

        assert!(
            rendered.contains("contact the aff4tools developer"),
            "{rendered}"
        );
        assert!(rendered.contains(DEFLATE_IRI), "{rendered}");
    }

    // --- Snappy ------------------------------------------------------------

    fn snappy_compress(data: &[u8]) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(data).unwrap()
    }

    /// Round trip through the raw block format.
    #[test]
    fn snappy_round_trips() {
        let locus = Locus::new("/evidence/case.aff4");
        // Compressible: long runs.
        let data: Vec<u8> = (0..32768u32)
            .map(|i| u8::try_from(i / 256 % 256).unwrap())
            .collect();
        let compressed = snappy_compress(&data);

        assert!(
            compressed.len() < data.len(),
            "fixture must actually compress"
        );

        let out = decompress_chunk(Codec::Snappy, &compressed, 32768, &locus).unwrap();
        assert_eq!(out, data);
    }

    /// The last chunk of a stream is shorter than `chunk_size`, and that is
    /// normal — not a length violation.
    #[test]
    fn a_short_final_chunk_is_accepted() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vec![0x11; 5000];
        let compressed = snappy_compress(&data);

        let out = decompress_chunk(Codec::Snappy, &compressed, 32768, &locus).unwrap();
        assert_eq!(out.len(), 5000);
        assert_eq!(out, data);
    }

    /// AFF4 uses the raw block format. A framed stream must be rejected, not
    /// silently misread — the frame format opens with a 0xff identifier.
    #[test]
    fn framed_snappy_is_rejected() {
        let locus = Locus::new("/evidence/case.aff4");
        let framed = b"\xff\x06\x00\x00sNaPpY\x01\x05\x00\x00hello";

        let err = decompress_chunk(Codec::Snappy, framed, 32768, &locus).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// Garbage is a finding about the evidence, not a capability gap.
    ///
    /// `\x00` is the case worth keeping: `snap` reads it as a valid varint
    /// meaning "decompresses to nothing" and returns `Ok([])`. Without an
    /// explicit check a caller would hash an empty buffer as if it were a
    /// chunk of evidence.
    #[test]
    fn corrupt_snappy_is_malformed_not_unsupported() {
        let locus = Locus::new("/evidence/case.aff4");

        for input in [
            &b""[..],
            &b"\x00"[..],
            &b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..],
            &b"not snappy data at all"[..],
        ] {
            let err = decompress_chunk(Codec::Snappy, input, 32768, &locus).unwrap_err();
            assert!(
                matches!(err, Error::Malformed { .. }),
                "input {input:?} must be a finding: {err}"
            );
        }
    }

    /// A truncated chunk must fail, never return a short buffer that a caller
    /// might hash as if it were complete.
    #[test]
    fn truncated_snappy_fails_rather_than_returning_short_data() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vec![0x22; 32768];
        let compressed = snappy_compress(&data);

        let truncated = &compressed[..compressed.len() / 2];
        let err = decompress_chunk(Codec::Snappy, truncated, 32768, &locus).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// The length header comes from evidence, so a chunk claiming more than
    /// the declared chunk size is refused before anything is allocated.
    #[test]
    fn an_oversized_length_header_is_refused() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vec![0x33; 32768];
        let compressed = snappy_compress(&data);

        // Declared chunk size is smaller than what the chunk claims.
        let err = decompress_chunk(Codec::Snappy, &compressed, 1024, &locus).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    // --- Zlib and LZ4 ------------------------------------------------------
    //
    // No corpus container uses either codec, so these vectors were produced by
    // the calls pyaff4 itself makes — `zlib.compress(chunk)` and
    // `lz4.block.compress(chunk, store_size=False)`. That is stronger evidence
    // than a self round trip, and weaker than a real container. See
    // docs/testing.md.

    /// The payload the committed vectors were generated from.
    fn vector_payload() -> Vec<u8> {
        let mut data = b"AFF4 evidence chunk. ".repeat(2000);
        data.truncate(32768);
        data
    }

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..clean.len() / 2)
            .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// `zlib.compress(payload)` — pyaff4 `aff4_image.py:260`.
    const ZLIB_VECTOR: &str = "\
        789cedc8310dc0201000402baf80a9065830423f8190b051fd15c2dd78b5b527f29b6fee\
        9ed1c7d9ab4495524a29a594524a29a594524a29a594524a29a594524a29a594524a29a5\
        94524a29a594524a29a594524a29a594524a29a594524a29a594524a29a594524a29a594\
        524a29a594524a29a594524a29efca1f378d2ce4";

    /// `lz4.block.compress(payload, store_size=False)` — the form pyaff4's
    /// read path at `aff4_image.py:678` expects.
    const LZ4_VECTOR: &str = "\
        ff06414646342065766964656e6365206368756e6b2e201500ffffffffffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffff53503420657669";

    /// `lz4.block.compress(payload)` — pyaff4's *write* path, which prepends a
    /// 4-byte little-endian size (`00800000` = 32768). Its own read path
    /// cannot consume this.
    const LZ4_WITH_SIZE_HEADER: &str = "\
        00800000ff06414646342065766964656e6365206368756e6b2e201500ffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffffffffff53503420657669";

    /// The decisive test for zlib: bytes produced by Python's zlib, decoded
    /// here, must reproduce the payload exactly.
    #[test]
    fn zlib_decodes_a_vector_from_the_reference_implementation() {
        let locus = Locus::new("/evidence/case.aff4");
        let out = decompress_chunk(Codec::Zlib, &unhex(ZLIB_VECTOR), 32768, &locus).unwrap();
        assert_eq!(out, vector_payload());
    }

    /// The same for LZ4, against pyaff4's read-path framing.
    #[test]
    fn lz4_decodes_a_vector_from_the_reference_implementation() {
        let locus = Locus::new("/evidence/case.aff4");
        let out = decompress_chunk(Codec::Lz4, &unhex(LZ4_VECTOR), 32768, &locus).unwrap();
        assert_eq!(out, vector_payload());
    }

    /// pyaff4's LZ4 write path prepends a size header its own read path cannot
    /// consume. aff4tools follows the read path, so the header form fails —
    /// documented behaviour, not an accident. If a container like this ever
    /// turns up, this test is the record of what was decided and why.
    #[test]
    fn lz4_with_a_size_header_is_rejected() {
        let locus = Locus::new("/evidence/case.aff4");
        let with_header = unhex(LZ4_WITH_SIZE_HEADER);

        // The header really is a 32768 little-endian prefix on the same block.
        assert_eq!(&with_header[..4], &[0x00, 0x80, 0x00, 0x00]);
        assert_eq!(&with_header[4..], unhex(LZ4_VECTOR).as_slice());

        let err = decompress_chunk(Codec::Lz4, &with_header, 32768, &locus).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// Zlib and raw deflate are different wire formats. A zlib stream must not
    /// be silently accepted as deflate, nor the reverse — this is the test that
    /// would catch the two being collapsed into one variant.
    #[test]
    fn zlib_and_deflate_do_not_accept_each_others_bytes() {
        let locus = Locus::new("/evidence/case.aff4");
        let zlib_bytes = unhex(ZLIB_VECTOR);

        // The RFC 1950 header is present: 0x78 CMF, then a valid FCHECK byte.
        assert_eq!(zlib_bytes[0], 0x78);

        // Raw deflate is declined outright, so it cannot silently accept them.
        let err = decompress_chunk(Codec::Deflate, &zlib_bytes, 32768, &locus).unwrap_err();
        assert!(matches!(err, Error::Unsupported { .. }), "{err}");

        // And a headerless deflate stream is not valid zlib.
        let headerless = &zlib_bytes[2..];
        let err = decompress_chunk(Codec::Zlib, headerless, 32768, &locus).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// Round trips prove the wiring; the vectors above prove the format.
    #[test]
    fn zlib_and_lz4_round_trip() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vector_payload();

        let zlib_compressed = {
            use std::io::Write as _;
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&data).unwrap();
            e.finish().unwrap()
        };
        let out = decompress_chunk(Codec::Zlib, &zlib_compressed, 32768, &locus).unwrap();
        assert_eq!(out, data);

        let lz4_compressed = lz4_flex::block::compress(&data);
        let out = decompress_chunk(Codec::Lz4, &lz4_compressed, 32768, &locus).unwrap();
        assert_eq!(out, data);
    }

    /// Corrupt input is a finding about the evidence for both codecs.
    #[test]
    fn corrupt_zlib_and_lz4_are_malformed() {
        let locus = Locus::new("/evidence/case.aff4");

        for codec in [Codec::Zlib, Codec::Lz4] {
            for input in [&b""[..], &b"\x00"[..], &b"not compressed data"[..]] {
                let err = decompress_chunk(codec, input, 32768, &locus).unwrap_err();
                assert!(
                    matches!(err, Error::Malformed { .. }),
                    "{codec} on {input:?}: {err}"
                );
            }
        }
    }

    /// A truncated chunk must fail, not yield short data a caller might hash.
    #[test]
    fn truncated_zlib_and_lz4_fail() {
        let locus = Locus::new("/evidence/case.aff4");

        for (codec, vector) in [(Codec::Zlib, ZLIB_VECTOR), (Codec::Lz4, LZ4_VECTOR)] {
            let full = unhex(vector);
            let truncated = &full[..full.len() / 2];
            let err = decompress_chunk(codec, truncated, 32768, &locus).unwrap_err();
            assert!(err.is_integrity_finding(), "{codec}: {err}");
        }
    }

    /// A zlib bomb must not be decompressed past the declared chunk size.
    #[test]
    fn zlib_cannot_expand_past_the_declared_chunk_size() {
        let locus = Locus::new("/evidence/case.aff4");

        // 1 MiB of zeroes compresses tiny, but the stream declares 32 KiB.
        let bomb = {
            use std::io::Write as _;
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
            e.write_all(&vec![0u8; 1024 * 1024]).unwrap();
            e.finish().unwrap()
        };

        let err = decompress_chunk(Codec::Zlib, &bomb, 32768, &locus).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    // --- Hardening ---------------------------------------------------------

    /// Every codec, every hostile input, no panics. Chunk bytes and lengths
    /// both come from evidence, so neither can be trusted.
    #[test]
    fn no_codec_panics_on_hostile_input() {
        let locus = Locus::new("/evidence/case.aff4");

        let inputs: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0x00],
            vec![0xff],
            vec![0xff; 64],
            vec![0x00; 32768],
            b"AFF4 evidence chunk. ".to_vec(),
            unhex(ZLIB_VECTOR),
            unhex(LZ4_VECTOR),
            // A snappy varint claiming a huge length, with no data behind it.
            vec![0xff, 0xff, 0xff, 0xff, 0x7f],
        ];

        for codec in ALL {
            for input in &inputs {
                for chunk_size in [0usize, 1, 512, 32768, usize::MAX] {
                    // Must return, never panic. Either outcome is acceptable
                    // here; the specific taxonomy is asserted elsewhere.
                    let _ = decompress_chunk(codec, input, chunk_size, &locus);
                }
            }
        }
    }

    /// `chunk_size` is read from container metadata, where a damaged or
    /// hostile value is possible. It must not cause an over-allocation.
    #[test]
    fn an_absurd_chunk_size_does_not_allocate() {
        let locus = Locus::new("/evidence/case.aff4");

        // If chunk_size were trusted as a capacity, this would try to reserve
        // 16 EiB and abort the process.
        for codec in [Codec::Zlib, Codec::Lz4, Codec::Snappy] {
            let _ = decompress_chunk(codec, &unhex(ZLIB_VECTOR), usize::MAX, &locus);
            let _ = decompress_chunk(codec, b"short", usize::MAX, &locus);
        }
    }

    /// A zero chunk size is degenerate but must not be special-cased into
    /// success: nothing legitimately decompresses to nothing.
    #[test]
    fn a_zero_chunk_size_never_succeeds() {
        let locus = Locus::new("/evidence/case.aff4");

        for codec in [Codec::Snappy, Codec::Zlib, Codec::Lz4] {
            let result = decompress_chunk(codec, &unhex(ZLIB_VECTOR), 0, &locus);
            assert!(result.is_err(), "{codec} accepted a zero chunk size");
        }
    }

    /// Empty input with a zero chunk size hits the stored-chunk shortcut,
    /// since `0 == 0`. It must still not yield an empty "chunk".
    #[test]
    fn empty_input_is_never_a_valid_chunk() {
        let locus = Locus::new("/evidence/case.aff4");

        for codec in ALL {
            if let Ok(out) = decompress_chunk(codec, b"", 0, &locus) {
                assert!(
                    out.is_empty(),
                    "{codec} invented {} bytes from nothing",
                    out.len()
                );
            }
        }
    }

    /// LZ4 carries no checksum, so a corrupted-but-decodable block can return
    /// the wrong length. The size bound is the only guard, and it must hold.
    #[test]
    fn lz4_output_is_bounded_by_the_declared_chunk_size() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vector_payload();
        let compressed = lz4_flex::block::compress(&data);

        // The block decompresses to 32768; ask for less and it must fail
        // rather than return a truncated buffer.
        let err = decompress_chunk(Codec::Lz4, &compressed, 1024, &locus).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// A chunk larger than the decoder's working buffer must still decompress.
    ///
    /// Reserving a fixed 64 KiB and relying on the buffer to grow does not
    /// work: `Decompress::decompress_vec` stops at its capacity and reports
    /// `BufError`, which this module reads as truncation, failing every
    /// legitimate 1 MiB chunk. No other test covers it, because none uses a
    /// chunk above 64 KiB.
    #[test]
    fn a_chunk_larger_than_the_working_buffer_still_decompresses() {
        use std::io::Write as _;
        let locus = Locus::new("/evidence/case.aff4");

        let size = 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();

        let compressed = {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&data).unwrap();
            e.finish().unwrap()
        };

        let out = decompress_chunk(Codec::Zlib, &compressed, size, &locus).unwrap();
        assert_eq!(out.len(), size);
        assert_eq!(out, data);

        // The size bound must still hold above the working buffer: 2 MiB of
        // data declared as a 1 MiB chunk is a finding, not a success.
        let bomb = {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
            e.write_all(&vec![0u8; 2 * size]).unwrap();
            e.finish().unwrap()
        };
        let err = decompress_chunk(Codec::Zlib, &bomb, size, &locus).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// A chunk size beyond the ceiling is refused before anything is
    /// allocated. Without this, a hostile `aff4:chunkSize` aborts the process
    /// on a capacity overflow.
    #[test]
    fn an_implausible_chunk_size_is_refused() {
        let locus = Locus::new("/evidence/case.aff4");

        for chunk_size in [MAX_CHUNK_SIZE + 1, usize::MAX / 2, usize::MAX] {
            for codec in ALL {
                let err = decompress_chunk(codec, b"anything", chunk_size, &locus).unwrap_err();
                assert!(
                    err.is_integrity_finding(),
                    "{codec} at chunk size {chunk_size}: {err}"
                );
            }
        }

        // The ceiling itself is allowed through to the codec.
        let err = decompress_chunk(Codec::Snappy, b"garbage", MAX_CHUNK_SIZE, &locus).unwrap_err();
        assert!(
            !err.to_string().contains("exceeds"),
            "the ceiling itself must not be refused: {err}"
        );
    }

    /// An oversized chunk size must be *reported*, not merely refused: the
    /// examiner needs the declared value, where it came from, what was
    /// expected, and the fact that no data was read.
    #[test]
    fn an_oversized_chunk_size_is_reported_in_full() {
        let locus = Locus::new("/evidence/case1.aff4")
            .segment("aff4%3A%2F%2Fuuid/00000000")
            .subject("aff4://c215ba20-5648-4209-a793-1f918c723610");

        let declared = 1 << 40; // 1 TiB
        let err = decompress_chunk(Codec::Snappy, b"x", declared, &locus).unwrap_err();
        let rendered = err.to_string();

        // The exact declared value, never only a rounded one.
        assert!(rendered.contains(&declared.to_string()), "{rendered}");
        assert!(
            rendered.contains("1.0 TiB") || rendered.contains("1024.0 GiB"),
            "{rendered}"
        );
        // The ceiling, so the user can see what the limit is.
        assert!(rendered.contains(&MAX_CHUNK_SIZE.to_string()), "{rendered}");
        // Where the bad value came from.
        assert!(rendered.contains("aff4:chunkSize"), "{rendered}");
        // What a real container looks like.
        assert!(rendered.contains("32768"), "{rendered}");
        // That nothing was decompressed.
        assert!(rendered.contains("no data was read"), "{rendered}");
        // And the locus, so the report names the container and segment.
        assert!(rendered.contains("case1.aff4"), "{rendered}");
        assert!(rendered.contains("00000000"), "{rendered}");

        assert!(err.is_integrity_finding(), "{err}");
    }

    #[test]
    fn byte_counts_render_readably() {
        assert_eq!(human_bytes(0), "0 bytes");
        assert_eq!(human_bytes(512), "512 bytes");
        assert_eq!(human_bytes(32768), "32.0 KiB");
        assert_eq!(human_bytes(MAX_CHUNK_SIZE), "64.0 MiB");
        assert_eq!(human_bytes(1 << 30), "1.0 GiB");
    }

    /// Chunk sizes seen in real containers, plus the boundaries around them.
    #[test]
    fn realistic_chunk_sizes_round_trip() {
        let locus = Locus::new("/evidence/case.aff4");

        for chunk_size in [512usize, 4096, 32768, 65536] {
            let data: Vec<u8> = (0..chunk_size)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();

            let compressed = snap::raw::Encoder::new().compress_vec(&data).unwrap();
            let out = decompress_chunk(Codec::Snappy, &compressed, chunk_size, &locus).unwrap();
            assert_eq!(out, data, "snappy at chunk size {chunk_size}");

            let compressed = lz4_flex::block::compress(&data);
            let out = decompress_chunk(Codec::Lz4, &compressed, chunk_size, &locus).unwrap();
            assert_eq!(out, data, "lz4 at chunk size {chunk_size}");
        }
    }

    /// Single-bit corruption in the middle of a chunk must be caught, not
    /// silently returned as evidence.
    #[test]
    fn bit_flips_are_detected() {
        let locus = Locus::new("/evidence/case.aff4");
        let data = vector_payload();

        // Zlib carries an Adler-32, so every flip must be caught.
        let compressed = {
            use std::io::Write as _;
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&data).unwrap();
            e.finish().unwrap()
        };

        let mut caught = 0;
        for byte in 2..compressed.len() {
            let mut corrupt = compressed.clone();
            corrupt[byte] ^= 0x01;
            match decompress_chunk(Codec::Zlib, &corrupt, 32768, &locus) {
                Err(_) => caught += 1,
                Ok(out) => assert_ne!(
                    out, data,
                    "a corrupted zlib chunk decoded to the original at byte {byte}"
                ),
            }
        }
        assert!(
            caught > 0,
            "zlib's checksum must catch corruption somewhere"
        );
    }

    /// Every error out of this module is one of the two intended variants,
    /// with the container path attached. A bare error with no locus would be
    /// useless in a report.
    #[test]
    fn every_failure_is_typed_and_located() {
        let locus = Locus::new("/evidence/case.aff4").segment("chunk 7");

        for codec in ALL {
            for input in [&b""[..], &b"\x00\x01\x02"[..], &b"\xff\xff\xff\xff"[..]] {
                if let Err(e) = decompress_chunk(codec, input, 32768, &locus) {
                    match &e {
                        Error::Malformed { .. } | Error::Unsupported { .. } => {}
                        other => panic!("{codec} produced an unexpected variant: {other}"),
                    }
                    assert!(
                        e.to_string().contains("case.aff4"),
                        "{codec} lost the container path: {e}"
                    );
                }
            }
        }
    }

    /// The error carries the locus, so a report says which chunk failed.
    #[test]
    fn a_failed_chunk_records_where_it_was() {
        let locus = Locus::new("/evidence/case.aff4")
            .segment("aff4%3A%2F%2Fuuid/00000000")
            .subject("aff4://c215ba20-5648-4209-a793-1f918c723610");

        let err = decompress_chunk(Codec::Snappy, b"garbage", 32768, &locus).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("case.aff4"), "{rendered}");
        assert!(rendered.contains("00000000"), "{rendered}");
    }
}
