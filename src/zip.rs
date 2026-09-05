//! Read-only access to the ZIP storage layer (v1.0a §5).
//!
//! An AFF4 container is a ZIP archive whose members are *segments*. This module
//! opens one for reading, enumerates its segments, and resolves the volume ARN.
//!
//! # Read-only
//!
//! [`ZipVolume::open`] is the single place this crate opens a container, and it
//! uses [`std::fs::File::open`], which cannot write. `zip::ZipWriter` and the
//! `std::fs` mutators are denied crate-wide by `clippy.toml`; see the crate
//! documentation. Nothing here creates, truncates, or modifies a file.
//!
//! # Volume ARN resolution
//!
//! v1.0a §5.4 gives two locations for the volume ARN and -recommends- both:
//! the ZIP comment and a `container.description` segment. Readers accept either.
//!
//! Two observed common deviations are handled:
//!
//! - Canonical reference `Base-Linear.aff4`'s comment is
//!   `aff4://685e15cc-…f77044\0`, while pyaff4 writes no padding and
//!   `container.description` is never padded. An untrimmed ARN carries an
//!   invisible `\0` and compares unequal to everything, so the NUL is trimmed
//!   and a [`DeviationKind::NulPaddedComment`] recorded.
//! - **`container.description` is not always first.** v1.0a §5.4 says it MUST
//!   be
//!   the first member when present; all three pyaff4-written containers place
//!   it at index 1, 3, and 4.
//!
//! # zip64
//!
//! v1.0a §5.4 says all ZIP headers MUST be zip64. No canonical reference
//! container has a zip64 end-of-central-directory record, so this is not
//! enforced — enforcing it would reject every real container.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::arn::Arn;
use crate::error::{Deviation, DeviationKind, Error, Locus, NotAff4Reason, Result};
use crate::model::SegmentKind;
use crate::stream::INDEX_SUFFIX;

/// The segment holding the volume ARN, per v1.0a §5.4.
pub const DESCRIPTION_SEGMENT: &str = "container.description";

/// The ZIP compression method meaning "not compressed".
///
/// Only a STORED member has a seekable interior, which is what makes a range
/// read possible. Every member of every AFF4 container examined so far is
/// STORED — bevies hold already-compressed chunks, so deflating them again
/// would gain nothing — but the format permits otherwise and the code checks.
const METHOD_STORED: u16 = 0;

/// Bytes in a ZIP local file header before its variable-length name.
const LOCAL_HEADER_LEN: usize = 30;

/// The local file header signature, `PK\x03\x04`.
const LOCAL_HEADER_SIGNATURE: &[u8] = b"PK\x03\x04";

/// The largest segment this build will read into memory, in bytes.
///
/// A member's declared uncompressed size is read from the container's own ZIP
/// headers, so it is evidence-derived and cannot be trusted as an allocation
/// size. Without a ceiling, a member storing a few compressed kilobytes of
/// zeros can declare gigabytes and be read into a buffer that size: a 12 MB
/// container measured 5.8 GB resident before this bound existed.
///
/// For scale: the largest member in any canonical reference container is
/// 3.0 MB, and segments from a commercial sample are roughly 32 MiB.
///
/// This is the segment-level counterpart to [`crate::codec::MAX_CHUNK_SIZE`],
/// which bounds decompression; the two guard different allocations and neither
/// subsumes the other.
pub const MAX_SEGMENT_SIZE: u64 = 1024 * 1024 * 1024;

/// The largest expansion ratio [`read_member`] will read a segment at.
///
/// [`MAX_SEGMENT_SIZE`] bounds the absolute size; this bounds the *ratio*
/// between what a member declares and what it stores, which is what a
/// compression bomb actually abuses. A 256 MiB segment stored in 300 KB is a
/// ratio near 900; nothing a real writer produces comes close, because AFF4
/// bevies hold already-compressed chunks and its metadata is small.
///
/// 1000 is deliberately generous — `information.turtle` is highly repetitive
/// RDF and deflate does very well on it — while still turning a
/// kilobytes-to-gigabytes claim into a finding.
const MAX_EXPANSION_RATIO: u64 = 1000;

/// [`MAX_SEGMENT_SIZE`] as a `usize`, for rendering alongside it.
///
/// Saturates rather than wrapping on a 32-bit host, where the ceiling exceeds
/// what a `usize` can express — there the allocation would fail regardless.
const MAX_SEGMENT_SIZE_USIZE: usize = if MAX_SEGMENT_SIZE > usize::MAX as u64 {
    usize::MAX
} else {
    // Guarded by the branch above: the value fits.
    #[allow(clippy::cast_possible_truncation)]
    {
        MAX_SEGMENT_SIZE as usize
    }
};

/// The one call site in this crate that opens a container.
///
/// Every handle comes from here: the volume's own, the central-directory scan,
/// and each parallel reader's. [`File::open`] requests read access only, and
/// `tests/read_only_guard.rs` asserts this is the sole occurrence in the
/// module — so a write-capable handle cannot be introduced quietly.
fn open_read_only(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

/// Classify a segment by its name.
///
/// The storage layer knows only names, so this reads layout, not declared
/// type. Two generations write bevies differently and both are recognised: a
/// Standard container names a bevy's index `<bevy>.index`, while pre-standard
/// containers store each bevy as a *folder* holding `index` and `blockHash.*`
/// members. Deciding by suffix alone would misfile every pre-standard bevy.
///
/// Block hashes are checked before the bevy patterns because this project's
/// containers name them `<bevy>.blockHash.<alg>`, which also ends in a bevy
/// number when read carelessly.
#[must_use]
pub fn classify_segment(name: &str) -> SegmentKind {
    // Top-level metadata members are matched on the whole name: they live at
    // the volume root, never under a stream's ARN path.
    match name {
        DESCRIPTION_SEGMENT => return SegmentKind::ContainerDescription,
        crate::container::METADATA_SEGMENT => return SegmentKind::Metadata,
        crate::version::SEGMENT_NAME => return SegmentKind::Version,
        _ => {}
    }

    let tail = name.rsplit('/').next().unwrap_or(name);

    if tail.contains(crate::verify::BLOCK_HASH_SUFFIX) || tail.starts_with("blockHash.") {
        return SegmentKind::BlockHash;
    }

    // `map`, `idx`, and `mapPath` sit directly under a map object's ARN.
    if matches!(
        tail,
        crate::map::MAP_SEGMENT | crate::map::IDX_SEGMENT | crate::map::MAP_PATH_SEGMENT
    ) {
        return SegmentKind::MapStructure;
    }

    // Standard names a bevy index `00000000.index`; pre-standard puts a bare
    // `index` inside the bevy folder.
    if tail == "index" {
        return SegmentKind::BevyIndex;
    }
    if tail.strip_suffix(INDEX_SUFFIX).is_some_and(is_bevy_number) {
        return SegmentKind::BevyIndex;
    }

    if is_bevy_number(tail) {
        return SegmentKind::BevyData;
    }

    // An AFF4-L logical file keeps its original path, so it matches no AFF4
    // naming convention but is still a known kind. A segment under a volume
    // ARN prefix is not one of these; a rooted path like `/test/dream.txt` is.
    if name.starts_with('/') {
        return SegmentKind::LogicalFile;
    }

    SegmentKind::Other
}

/// Whether a name is a bevy number: eight ASCII digits, per v1.0a §4.
pub(crate) fn is_bevy_number(s: &str) -> bool {
    s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit())
}

/// One member's two sizes, as the central directory records them.
///
/// Both are kept because they answer different questions. `compressed` is what
/// the member costs to read off disk; `uncompressed` is what a consumer will
/// actually process. For a deflated `information.turtle` the two diverge by
/// between 1.0x and 6.5x across the reference corpus, so neither substitutes
/// for the other.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MemberSize {
    /// Bytes occupied in the archive.
    pub(crate) compressed: u64,
    /// Bytes after inflation — what a parser is handed.
    pub(crate) uncompressed: u64,
    /// The ZIP compression method: 0 is STORED, anything else is compressed.
    ///
    /// Only a STORED member has a seekable interior, so this decides whether
    /// [`Volume::read_segment_range`] can serve a request.
    pub(crate) method: u16,
    /// Offset of the member's *local file header* in the container.
    ///
    /// Not the offset of its data: the local header is followed by a name and
    /// an extra field whose lengths only that header records, so finding the
    /// data means reading it. See [`ZipVolume::member_data_offset`].
    pub(crate) header_offset: u64,
}

/// Every member's name and both sizes, read from the central directory.
///
/// One bulk read of the directory rather than a seek per member. Returns an
/// empty map on any parse failure: this feeds a *cost estimate*, so a
/// container whose directory this cannot read should still verify, just
/// without a size prediction. Nothing here is used for a correctness claim.
fn central_directory_sizes(path: &Path) -> Option<HashMap<String, MemberSize>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = open_read_only(path).ok()?;
    let total = file.metadata().ok()?.len();

    // The end-of-central-directory record lives in the last 64 KiB plus the
    // maximum comment length.
    let tail_len = total.min(70_000);
    file.seek(SeekFrom::Start(total - tail_len)).ok()?;
    let mut tail = vec![0u8; usize::try_from(tail_len).ok()?];
    file.read_exact(&mut tail).ok()?;

    let u16at = |b: &[u8], o: usize| -> Option<u16> {
        Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]))
    };
    let u32at = |b: &[u8], o: usize| -> Option<u32> {
        Some(u32::from_le_bytes([
            *b.get(o)?,
            *b.get(o + 1)?,
            *b.get(o + 2)?,
            *b.get(o + 3)?,
        ]))
    };
    let u64at = |b: &[u8], o: usize| -> Option<u64> {
        let mut v = [0u8; 8];
        v.copy_from_slice(b.get(o..o + 8)?);
        Some(u64::from_le_bytes(v))
    };

    // Prefer the zip64 record: a 236 GB container's directory offset does not
    // fit the 32-bit field, which then holds the 0xFFFFFFFF sentinel.
    let (cd_offset, cd_size) = if let Some(p) = rfind(&tail, b"PK\x06\x06") {
        (u64at(&tail, p + 48)?, u64at(&tail, p + 40)?)
    } else {
        let p = rfind(&tail, b"PK\x05\x06")?;
        (
            u64::from(u32at(&tail, p + 16)?),
            u64::from(u32at(&tail, p + 12)?),
        )
    };

    file.seek(SeekFrom::Start(cd_offset)).ok()?;
    let mut cd = vec![0u8; usize::try_from(cd_size).ok()?];
    file.read_exact(&mut cd).ok()?;

    let mut sizes = HashMap::new();
    let mut at = 0usize;
    while at + 46 <= cd.len() && cd.get(at..at + 4)? == b"PK\x01\x02" {
        let name_len = usize::from(u16at(&cd, at + 28)?);
        let extra_len = usize::from(u16at(&cd, at + 30)?);
        let comment_len = usize::from(u16at(&cd, at + 32)?);
        let method = u16at(&cd, at + 10)?;
        let mut compressed = u64::from(u32at(&cd, at + 20)?);
        let uncompressed_32 = u32at(&cd, at + 24)?;
        let mut uncompressed = u64::from(uncompressed_32);
        let header_offset_32 = u32at(&cd, at + 42)?;
        let mut header_offset = u64::from(header_offset_32);

        let name = String::from_utf8_lossy(cd.get(at + 46..at + 46 + name_len)?).into_owned();

        // In a zip64 extra field the 8-byte values appear only for the fields
        // whose 32-bit slot held the sentinel, in a fixed order: uncompressed,
        // then compressed. Reading `compressed` at a fixed offset would pick up
        // the wrong number whenever only one of them overflowed.
        if compressed == u64::from(u32::MAX)
            || uncompressed_32 == u32::MAX
            || header_offset_32 == u32::MAX
        {
            let extra = cd.get(at + 46 + name_len..at + 46 + name_len + extra_len)?;
            let mut e = 0usize;
            while e + 4 <= extra.len() {
                let id = u16at(extra, e)?;
                let len = usize::from(u16at(extra, e + 2)?);
                if id == 1 {
                    let body = extra.get(e + 4..e + 4 + len)?;
                    let mut at64 = 0usize;
                    if uncompressed_32 == u32::MAX {
                        if let Some(value) = u64at(body, at64) {
                            uncompressed = value;
                        }
                        at64 += 8;
                    }
                    if compressed == u64::from(u32::MAX) {
                        if let Some(value) = u64at(body, at64) {
                            compressed = value;
                        }
                        at64 += 8;
                    }
                    if header_offset_32 == u32::MAX
                        && let Some(value) = u64at(body, at64)
                    {
                        header_offset = value;
                    }
                    break;
                }
                e += 4 + len;
            }
        }

        sizes.insert(
            name,
            MemberSize {
                compressed,
                uncompressed,
                method,
                header_offset,
            },
        );
        at += 46 + name_len + extra_len + comment_len;
    }

    Some(sizes)
}

/// The last occurrence of `needle` in `haystack`.
fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

/// Where a volume ARN was found.
///
/// `#[serde(tag = "kind", rename_all = "snake_case")]` gives a designed JSON
/// shape (`{"kind": "both", "consistent": true}`) rather than the derive
/// default (`{"Both": {"consistent": true}}`), which leaked the Rust variant
/// name `Both` verbatim into the schema. Matches this
/// crate's convention for a closed enum with per-variant data; see
/// `rdf::Value` and `zip_volume_set::VolumeOrigin`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArnSource {
    /// From the ZIP comment only.
    ZipComment,
    /// From the `container.description` segment only.
    ContainerDescription,
    /// From both locations, as v1.0a §5.4 recommends.
    Both {
        /// Whether the two agree. A mismatch is an integrity signal.
        consistent: bool,
    },
    /// From neither; recovered from the metadata's empty `:` prefix.
    Metadata,
}

/// A read-only source of AFF4 segments.
///
/// Implemented by [`ZipVolume`] today. It exists as a trait because striped
/// containers (README feature 3) need a set of volumes resolving segments
/// across siblings, and v1.0a §5 also defines a Directory storage layer.
///
/// Deliberately not a seekable stream API: `ImageStream` and `Map` decoding
/// layer on top of this rather than inside it.
pub trait Volume {
    /// The volume's ARN.
    fn arn(&self) -> &Arn;

    /// Every segment name in the volume, in central-directory order.
    fn segment_names(&self) -> &[String];

    /// The index of a segment within [`Volume::segment_names`], if present.
    ///
    /// **Implementors must make this better than a linear scan.** It is a
    /// required method precisely so that cannot be inherited by accident: a
    /// real container has tens of thousands of members, and a linear probe in a
    /// loop is quadratic.
    fn segment_index(&self, name: &str) -> Option<usize>;

    /// Whether a segment exists.
    fn has_segment(&self, name: &str) -> bool {
        self.segment_index(name).is_some()
    }

    /// Every segment name starting with `prefix`, in name order.
    ///
    /// The point is to *avoid probing for names that do not exist*. Searching
    /// for a stream's block-hash segments by generating candidate names and
    /// testing each one costs one lookup per bevy per algorithm — tens of
    /// thousands of probes on a large container, nearly all of them misses.
    /// Asking which names are actually present costs one range query.
    ///
    /// The default implementation scans; [`ZipVolume`] overrides it.
    fn segments_with_prefix(&self, prefix: &str) -> Vec<String> {
        let mut found: Vec<String> = self
            .segment_names()
            .iter()
            .filter(|n| n.starts_with(prefix))
            .cloned()
            .collect();
        found.sort();
        found
    }

    /// Read a segment in full.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Zip`] if the segment is absent or cannot be
    /// decompressed, or [`Error::Io`] if reading fails.
    fn read_segment(&mut self, name: &str) -> Result<Vec<u8>>;

    /// Read `length` bytes at `offset` *within* a segment, if that is possible
    /// without reading the whole member.
    ///
    /// Returns [`None`] when this volume cannot serve the request cheaply —
    /// the member is compressed, absent, or its extent unknown — and the
    /// caller must fall back to [`Volume::read_segment`]. `None` means "ask
    /// the other way", never "no data".
    ///
    /// # Why this exists
    ///
    /// A bevy is one ZIP member holding a thousand chunks. Serving a single
    /// 32 KiB chunk through `read_segment` reads and checksums all ~30 MB of
    /// it. Measured on a 500 GB APFS acquisition, that is 7.4 ms against
    /// 0.006 ms for the range read — a factor of ~1300 — and it is why a
    /// scattered-read workload was an order of magnitude slower than pyaff4.
    ///
    /// # CRC
    ///
    /// **A range read does not verify the member's CRC, and cannot.** The
    /// recorded checksum covers the whole member; a caller holding one chunk
    /// has nothing to check it against. That governs how a *detected* checksum
    /// failure is classified, not when one must be sought — but it does mean
    /// bytes obtained this way are unverified. `verify` reads members in full
    /// and is unaffected.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the read itself fails. A member that simply cannot be
    /// served this way is [`None`], not an error.
    fn read_segment_range(
        &mut self,
        _name: &str,
        _offset: u64,
        _length: usize,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// The bytes a set of segments occupies on disk, for the ones that exist.
    ///
    /// Used to predict I/O cost before reading. Implementations must answer
    /// from data already in memory: a per-member lookup that seeks into the
    /// container would cost minutes on a container with thousands of members,
    /// which is exactly the cost this is meant to predict.
    fn stored_bytes(&self, names: &[String]) -> u64;

    /// A segment's size *after* inflation, or [`None`] if it is not recorded.
    ///
    /// The counterpart to [`Volume::stored_bytes`], and subject to the same
    /// rule: answer from data already in memory, never by seeking.
    ///
    /// Separate because the two diverge. `information.turtle` is deflated, at
    /// ratios from 1.0x to 6.5x across the reference corpus, so its stored size
    /// predicts neither how long it takes to parse nor how much memory that
    /// costs. A caller sizing up work before it starts wants this number.
    ///
    /// **Declared by the container, so never an allocation size.** This is the
    /// same evidence-derived figure [`MAX_SEGMENT_SIZE`] exists to bound; it is
    /// fit for a progress message and not for a `Vec::with_capacity`.
    fn uncompressed_bytes(&self, name: &str) -> Option<u64>;
}

/// A volume that can hand out additional independent readers.
///
/// Parallel verification needs several handles seeking independently over one
/// container. A `ZipArchive` holds a single `File` and a single cursor, so
/// concurrent reads through one handle would serialise — and interleave seeks.
/// Each reader therefore gets its own handle onto the same read-only file.
///
/// Separate from [`Volume`] because not every storage layer can do this: a
/// directory-backed volume may have nothing to clone, and a trait method it had
/// to stub out would be worse than not implementing this trait at all.
pub trait ParallelVolume: Volume + Sync {
    /// Open another independent reader over the same container.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the container cannot be opened again, or [`Error::Zip`]
    /// if its central directory cannot be re-read.
    fn open_reader(&self) -> Result<Box<dyn SegmentReader>>;
}

/// One independent cursor over a volume's segments.
///
/// Deliberately narrower than [`Volume`]: a reader only reads members. It has
/// no ARN, no name list, and no index, because those are shared, immutable, and
/// already answered by the volume itself.
pub trait SegmentReader: Send {
    /// Read a segment in full.
    ///
    /// # Errors
    ///
    /// As [`Volume::read_segment`].
    fn read_segment(&mut self, name: &str) -> Result<Vec<u8>>;
}

/// A ZIP-backed AFF4 volume, open for reading.
pub struct ZipVolume {
    path: PathBuf,
    archive: zip::ZipArchive<File>,
    arn: Arn,
    arn_source: ArnSource,
    segment_names: Vec<String>,
    /// Stored size per member, from the central directory. Empty if it could
    /// not be parsed, in which case cost estimates simply go unreported.
    stored_sizes: HashMap<String, MemberSize>,
    /// Name to position in `segment_names`, so lookups are O(1).
    ///
    /// Built once at open. A container with 16,435 members makes a linear
    /// probe cost real time when it happens in a loop — see
    /// [`Volume::segment_index`].
    segment_index: HashMap<String, usize>,
    /// Names in sorted order, so a prefix search is a range query rather than
    /// a scan. See [`Volume::segments_with_prefix`].
    sorted_names: BTreeSet<String>,
    /// Member name to the offset of its *data*, resolved on first use.
    ///
    /// Finding it costs a 30-byte read of the local file header, so it is
    /// remembered: a scattered-read workload asks for the same handful of
    /// bevies thousands of times, and paying a seek per chunk to rediscover a
    /// constant would reintroduce a smaller version of the cost this whole
    /// path exists to remove.
    data_offsets: Mutex<HashMap<String, Option<u64>>>,
    deviations: Vec<Deviation>,
}

/// Hand-written because `zip::ZipArchive` is not [`Debug`].
///
/// Segment names, sizes, and deviation details are summarised as counts: a
/// container can hold thousands of segments, and a `Debug` line that dumps
/// them all is unusable in a test failure.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for ZipVolume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipVolume")
            .field("path", &self.path)
            .field("arn", &self.arn)
            .field("arn_source", &self.arn_source)
            .field("segments", &self.segment_names.len())
            .field("deviations", &self.deviations.len())
            .finish()
    }
}

impl ZipVolume {
    /// Open a container read-only and resolve its volume ARN.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the file cannot be opened.
    /// - [`Error::Zip`] if it is not a readable ZIP archive.
    /// - [`Error::NotAff4`] if the archive is empty or carries no volume ARN.
    /// - [`Error::Malformed`] if a volume ARN is present but unparseable.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Read-only by construction; see `open_read_only`.
        let file = open_read_only(&path).map_err(|e| Error::io(&path, e))?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| Error::zip(&path, e))?;

        if archive.is_empty() {
            return Err(Error::not_aff4(&path, NotAff4Reason::EmptyArchive));
        }

        let segment_names: Vec<String> = archive.file_names().map(String::from).collect();

        // Stored sizes, read straight from the central directory in one pass.
        //
        // The `zip` crate exposes a member's size only through `by_name` /
        // `by_index`, both of which seek to the member's *local* header first.
        // That costs ~7 ms per member on external media — nearly a minute on a
        // 16,000-member container, to answer a question the central directory
        // already holds. Parsing it directly keeps the whole thing to one read.
        let stored_sizes = central_directory_sizes(&path).unwrap_or_default();

        let mut deviations = Vec::new();

        // A ZIP may legally carry two members with the same name. Keep the
        // first — which is what `by_name` resolves to — and report the rest
        // rather than silently letting one shadow the other.
        let mut segment_index: HashMap<String, usize> = HashMap::with_capacity(segment_names.len());
        let mut duplicates = 0usize;
        for (index, name) in segment_names.iter().enumerate() {
            if segment_index.insert(name.clone(), index).is_some() {
                duplicates += 1;
            }
        }
        // `insert` overwrote on collision; rebuild those to the first index.
        if duplicates > 0 {
            segment_index.clear();
            for (index, name) in segment_names.iter().enumerate() {
                segment_index.entry(name.clone()).or_insert(index);
            }
            deviations.push(Deviation::new(
                Locus::new(&path),
                DeviationKind::DuplicateSegmentName,
                format!(
                    "{duplicates} segment name(s) appear more than once; reads                      resolve to the first occurrence, and the later ones are                      unreachable"
                ),
            ));
        }

        let sorted_names: BTreeSet<String> = segment_names.iter().cloned().collect();

        let (arn, arn_source) =
            resolve_volume_arn(&path, &mut archive, &segment_names, &mut deviations)?;

        Ok(Self {
            path,
            archive,
            arn,
            arn_source,
            segment_names,
            stored_sizes,
            segment_index,
            sorted_names,
            data_offsets: Mutex::new(HashMap::new()),
            deviations,
        })
    }

    /// Where a member's data begins, or [`None`] if it cannot be located or
    /// is not stored uncompressed.
    ///
    /// The central directory records where a member's *local file header*
    /// starts, not where its data does; between them sit a name and an extra
    /// field whose lengths only the local header carries. So this reads those
    /// 30 bytes and adds them up. The zip crate's own `data_start()` is not
    /// usable here: it is a `OnceCell` populated when a member is opened for
    /// reading, which is the very thing being avoided.
    ///
    /// A compressed member returns [`None`]. Its interior is not addressable
    /// without inflating everything before the point of interest, so there is
    /// nothing to be gained.
    fn member_data_offset(&self, name: &str) -> Result<Option<u64>> {
        // A poisoned lock means another thread panicked mid-insert. The map is
        // a pure memo of a value re-derivable at any time, so recovering the
        // guard loses nothing: at worst one entry is recomputed.
        if let Some(known) = self
            .data_offsets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
        {
            return Ok(*known);
        }

        let resolved = self.resolve_data_offset(name)?;
        self.data_offsets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_owned(), resolved);
        Ok(resolved)
    }

    /// Read one local file header and compute the data offset it implies.
    fn resolve_data_offset(&self, name: &str) -> Result<Option<u64>> {
        let Some(size) = self.stored_sizes.get(name) else {
            return Ok(None);
        };
        if size.method != METHOD_STORED {
            return Ok(None);
        }

        let mut file = open_read_only(&self.path).map_err(|e| Error::io(&self.path, e))?;
        file.seek(SeekFrom::Start(size.header_offset))
            .map_err(|e| Error::io(&self.path, e))?;
        let mut header = [0u8; LOCAL_HEADER_LEN];
        if file.read_exact(&mut header).is_err() {
            return Ok(None);
        }
        if &header[..4] != LOCAL_HEADER_SIGNATURE {
            // The directory pointed somewhere that is not a member header.
            // Not an error here: the caller falls back to a full read, which
            // reports the inconsistency with its own diagnostics.
            return Ok(None);
        }

        let name_len = u64::from(u16::from_le_bytes([header[26], header[27]]));
        let extra_len = u64::from(u16::from_le_bytes([header[28], header[29]]));
        Ok(Some(
            size.header_offset
                .saturating_add(LOCAL_HEADER_LEN as u64)
                .saturating_add(name_len)
                .saturating_add(extra_len),
        ))
    }

    /// The container's path on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the volume ARN was found.
    #[must_use]
    pub fn arn_source(&self) -> &ArnSource {
        &self.arn_source
    }

    /// Deviations observed while opening the container.
    #[must_use]
    pub fn deviations(&self) -> &[Deviation] {
        &self.deviations
    }

    /// A [`Locus`] pointing at this container, optionally at one segment.
    #[must_use]
    pub fn locus(&self, segment: Option<&str>) -> Locus {
        let locus = Locus::new(&self.path);
        match segment {
            Some(name) => locus.segment(name),
            None => locus,
        }
    }
}

impl Volume for ZipVolume {
    fn arn(&self) -> &Arn {
        &self.arn
    }

    fn segment_names(&self) -> &[String] {
        &self.segment_names
    }

    fn read_segment(&mut self, name: &str) -> Result<Vec<u8>> {
        read_member(&self.path, &mut self.archive, name)
    }

    fn read_segment_range(
        &mut self,
        name: &str,
        offset: u64,
        length: usize,
    ) -> Result<Option<Vec<u8>>> {
        let Some(data_start) = self.member_data_offset(name)? else {
            return Ok(None);
        };

        // Bounds come from the central directory, which is evidence-derived:
        // a request that runs past the member's recorded extent is refused
        // rather than allowed to read a neighbouring member's bytes.
        let Some(size) = self.stored_sizes.get(name) else {
            return Ok(None);
        };
        let end = offset.saturating_add(length as u64);
        if end > size.uncompressed {
            return Ok(None);
        }

        let mut file = open_read_only(&self.path).map_err(|e| Error::io(&self.path, e))?;
        file.seek(SeekFrom::Start(data_start.saturating_add(offset)))
            .map_err(|e| Error::io(&self.path, e))?;
        let mut buf = vec![0u8; length];
        file.read_exact(&mut buf)
            .map_err(|e| Error::io(&self.path, e))?;
        Ok(Some(buf))
    }

    fn stored_bytes(&self, names: &[String]) -> u64 {
        names
            .iter()
            .filter_map(|name| self.stored_sizes.get(name))
            .map(|size| size.compressed)
            .sum()
    }

    fn uncompressed_bytes(&self, name: &str) -> Option<u64> {
        self.stored_sizes.get(name).map(|size| size.uncompressed)
    }

    fn segment_index(&self, name: &str) -> Option<usize> {
        self.segment_index.get(name).copied()
    }

    fn segments_with_prefix(&self, prefix: &str) -> Vec<String> {
        // A range from the prefix to the first name that cannot share it,
        // rather than a scan of every member.
        self.sorted_names
            .range(prefix.to_owned()..)
            .take_while(|n| n.starts_with(prefix))
            .cloned()
            .collect()
    }
}

impl ParallelVolume for ZipVolume {
    fn open_reader(&self) -> Result<Box<dyn SegmentReader>> {
        let file = open_read_only(&self.path).map_err(|e| Error::io(&self.path, e))?;
        let archive = zip::ZipArchive::new(file).map_err(|e| Error::zip(&self.path, e))?;
        Ok(Box::new(ZipReader {
            path: self.path.clone(),
            archive,
        }))
    }
}

/// One extra `ZipArchive` over the same container, for a parallel reader.
///
/// Opening one re-reads the central directory — about 70 ms on a
/// 16,435-member container — so readers are opened once per run, never per
/// bevy.
struct ZipReader {
    path: PathBuf,
    archive: zip::ZipArchive<File>,
}

impl SegmentReader for ZipReader {
    fn read_segment(&mut self, name: &str) -> Result<Vec<u8>> {
        read_member(&self.path, &mut self.archive, name)
    }
}

/// Parallel readers share `&ZipVolume` across threads, so this must hold.
///
/// A compile-time check rather than a comment: if a future field makes the
/// volume unshareable, this fails at build time instead of forcing the
/// pipeline back onto a single reader silently.
const _: fn() = || {
    fn assert_sync<T: Sync>() {}
    assert_sync::<ZipVolume>();
};

/// Read one member in full.
fn read_member(path: &Path, archive: &mut zip::ZipArchive<File>, name: &str) -> Result<Vec<u8>> {
    let mut member = archive.by_name(name).map_err(|e| Error::zip(path, e))?;

    // The declared size is read from ZIP input. Do not trust as an
    // allocation size. Detect and refuse decompression bombs.
    let declared = member.size();
    if declared > MAX_SEGMENT_SIZE {
        return Err(Error::malformed(
            Locus::new(path).segment(name),
            format!(
                "segment {name} declares {declared} bytes ({}), which exceeds this \
                 build's {MAX_SEGMENT_SIZE} byte ({}) ceiling\
                 \n  read from:  the ZIP central directory\
                 \n  refused by: aff4tools, before reading, because a segment this \
                 large is either damaged metadata or an attempt to exhaust memory\
                 \n  note:       no data was read; this is a finding about the \
                 container's headers, not about the segment's contents",
                crate::codec::human_bytes(usize::try_from(declared).unwrap_or(usize::MAX)),
                crate::codec::human_bytes(MAX_SEGMENT_SIZE_USIZE),
            ),
        ));
    }

    let stored = member.compressed_size();
    if stored > 0 && declared / stored.max(1) > MAX_EXPANSION_RATIO {
        return Err(Error::malformed(
            Locus::new(path).segment(name),
            format!(
                "segment {name} declares {declared} bytes ({}) but stores only \
                 {stored} bytes, an expansion of {}x against this build's \
                 {MAX_EXPANSION_RATIO}x limit\
                 \n  read from:  the ZIP central directory\
                 \n  refused by: aff4tools, before reading, because a ratio this \
                 high is the signature of a compression bomb rather than of any \
                 container a writer produces\
                 \n  note:       no data was read; this is a finding about the \
                 container's headers, not about the segment's contents",
                crate::codec::human_bytes(usize::try_from(declared).unwrap_or(usize::MAX)),
                declared / stored.max(1),
            ),
        ));
    }

    // Sized from the declared length only after both bounds above, so the
    // reservation is capped no matter what the headers claim.
    let mut buf = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));

    // A failure here is not necessarily an environment problem. The `zip`
    // crate reports a member whose CRC does not match its data as an
    // `io::Error` ("Invalid checksum"), and that is a finding about the
    // evidence: the archive says these bytes should hash to something they do
    // not. Classifying it as `Io` would tell an examiner the disk was at
    // fault.
    member.read_to_end(&mut buf).map_err(|e| {
        if is_data_integrity_failure(&e) {
            Error::malformed(
                Locus::new(path).segment(name),
                format!("segment {name} does not match its recorded ZIP checksum: {e};"),
            )
        } else {
            Error::io(path, e)
        }
    })?;
    Ok(buf)
}

/// Whether an `io::Error` from a ZIP member read is really a data-integrity
/// failure rather than a filesystem one.
///
/// The `zip` crate signals a CRC mismatch through `io::ErrorKind::Other` with
/// a message, so the message is the only signal available. Matching on it is
/// unfortunate but contained: an unrecognised error still falls through to
/// [`Error::Io`], which is the safe direction — a misclassified environment
/// error is a nuisance, while a misclassified integrity failure is misleading
/// about evidence.
fn is_data_integrity_failure(error: &std::io::Error) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("checksum") || text.contains("crc")
}

/// Resolve the volume ARN from the ZIP comment and/or `container.description`.
fn resolve_volume_arn(
    path: &Path,
    archive: &mut zip::ZipArchive<File>,
    segment_names: &[String],
    deviations: &mut Vec<Deviation>,
) -> Result<(Arn, ArnSource)> {
    let comment = comment_arn(path, archive, deviations);
    let description = description_arn(path, archive, segment_names, deviations)?;

    let (text, source) = match (comment, description) {
        (Some(c), Some(d)) => {
            let consistent = c == d;
            if !consistent {
                deviations.push(Deviation::new(
                    Locus::new(path),
                    DeviationKind::InconsistentVolumeArn,
                    format!(
                        "ZIP comment says {c:?} but {DESCRIPTION_SEGMENT} says {d:?}; \
                         using {DESCRIPTION_SEGMENT}, which spec §5.4 requires to be \
                         the first member and is the more deliberate declaration"
                    ),
                ));
            }
            // Prefer container.description on disagreement: it is a named
            // segment rather than trailing bytes, so it is less likely to have
            // been damaged or rewritten.
            (d, ArnSource::Both { consistent })
        }
        (Some(c), None) => (c, ArnSource::ZipComment),
        (None, Some(d)) => (d, ArnSource::ContainerDescription),
        (None, None) => {
            // v1.0a §5.4 requires one of the two. Recovery from the metadata's
            // empty `:` prefix belongs to the RDF layer, which is not built
            // yet; report precisely rather than guess.
            return Err(Error::not_aff4(path, NotAff4Reason::NoVolumeArn));
        }
    };

    let arn = Arn::parse(&text, &Locus::new(path))?;
    Ok((arn, source))
}

/// The ARN from the ZIP comment, if present and non-empty.
fn comment_arn(
    path: &Path,
    archive: &zip::ZipArchive<File>,
    deviations: &mut Vec<Deviation>,
) -> Option<String> {
    let raw = archive.comment();
    if raw.is_empty() {
        return None;
    }

    let text = String::from_utf8_lossy(raw);
    let trimmed = trim_arn(&text);

    if trimmed.len() < text.trim_end().len() {
        // Evimetry NUL-pads the comment; pyaff4 does not. Trimming is required
        // for the ARN to compare equal to anything, but the padding is a real
        // departure from the spec's "stored starting at offset 0" and is
        // recorded rather than quietly normalised.
        deviations.push(Deviation::new(
            Locus::new(path),
            DeviationKind::NulPaddedComment,
            format!(
                "the ZIP comment carries {} trailing NUL byte(s) after the volume ARN",
                text.trim_end().len() - trimmed.len()
            ),
        ));
    }

    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// The ARN from `container.description`, if the segment exists.
fn description_arn(
    path: &Path,
    archive: &mut zip::ZipArchive<File>,
    segment_names: &[String],
    deviations: &mut Vec<Deviation>,
) -> Result<Option<String>> {
    let Some(index) = segment_names.iter().position(|n| n == DESCRIPTION_SEGMENT) else {
        return Ok(None);
    };

    if index != 0 {
        // v1.0a §5.4: "the file MUST be the first file stored in the Zip
        // volume". pyaff4 writes it at index 1, 3, and 4 in the reference
        // corpus, so this cannot be an acceptance criterion.
        //
        // Counted from 1 in the message, and the member actually holding first
        // position is named. `index` is a 0-based offset, and reporting it raw
        // beside the word "first" read as a contradiction — "member 1, but it
        // is required to be the first member" invites the examiner to conclude
        // the tool is wrong about a container that really does violate
        // v1.0a §5.4.
        // A finding must be checkable against the container without knowing
        // whether this crate counts from zero.
        let position = index + 1;
        let occupant = segment_names
            .first()
            .map_or_else(String::new, |name| format!(" (\"{name}\" is)"));
        deviations.push(Deviation::new(
            Locus::new(path).segment(DESCRIPTION_SEGMENT),
            DeviationKind::InconsistentVolumeArn,
            format!(
                "{DESCRIPTION_SEGMENT} is stored {position} of {} in the volume, \
                 but it is required to be the first member{occupant}",
                segment_names.len()
            ),
        ));
    }

    let bytes = read_member(path, archive, DESCRIPTION_SEGMENT)?;
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = trim_arn(&text);
    Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
}

/// Trim trailing NULs and surrounding whitespace from an ARN.
fn trim_arn(text: &str) -> &str {
    text.trim_end_matches('\0').trim()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a synthetic container in a temp file.
    ///
    /// This is the one place the crate uses a ZIP writer: it creates a fresh
    /// throwaway archive to test the reader against, and never touches
    /// evidence. `zip` is a dev-dependency for exactly this.
    #[allow(clippy::disallowed_types, clippy::disallowed_methods)]
    fn synth(members: &[(&str, &[u8])], comment: Option<&[u8]>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.aff4");
        let file = File::create(&path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        if let Some(c) = comment {
            writer
                .set_raw_comment(c.to_vec().into_boxed_slice())
                .unwrap();
        }
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in members {
            writer.start_file(*name, opts).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
        (dir, path)
    }

    const VOLUME: &str = "aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044";
    const OTHER: &str = "aff4://51725cd9-3769-4be7-a8ab-94e3ea62bf9a";

    #[test]
    fn reads_the_arn_from_the_zip_comment() {
        let (_d, path) = synth(
            &[("version.txt", b"major=1\nminor=0\n")],
            Some(VOLUME.as_bytes()),
        );
        let vol = ZipVolume::open(&path).unwrap();
        assert_eq!(vol.arn().as_str(), VOLUME);
        assert_eq!(*vol.arn_source(), ArnSource::ZipComment);
        assert!(vol.deviations().is_empty());
    }

    /// Finding B: Evimetry NUL-pads the comment. Untrimmed, the ARN carries an
    /// invisible `\0` and compares unequal to everything.
    #[test]
    fn trims_nul_padding_and_records_it() {
        let mut comment = VOLUME.as_bytes().to_vec();
        comment.push(0);
        let (_d, path) = synth(&[("version.txt", b"x=1\n")], Some(&comment));

        let vol = ZipVolume::open(&path).unwrap();
        assert_eq!(vol.arn().as_str(), VOLUME, "the NUL must not survive");
        assert!(!vol.arn().as_str().contains('\0'));
        assert_eq!(
            vol.deviations()
                .iter()
                .filter(|d| d.kind == DeviationKind::NulPaddedComment)
                .count(),
            1,
            "trimming must be reported, not silent"
        );
    }

    #[test]
    fn reads_the_arn_from_container_description() {
        let (_d, path) = synth(&[(DESCRIPTION_SEGMENT, VOLUME.as_bytes())], None);
        let vol = ZipVolume::open(&path).unwrap();
        assert_eq!(vol.arn().as_str(), VOLUME);
        assert_eq!(*vol.arn_source(), ArnSource::ContainerDescription);
    }

    /// The corpus arrangement: both sources present and agreeing.
    #[test]
    fn accepts_both_sources_when_they_agree() {
        let (_d, path) = synth(
            &[(DESCRIPTION_SEGMENT, VOLUME.as_bytes())],
            Some(VOLUME.as_bytes()),
        );
        let vol = ZipVolume::open(&path).unwrap();
        assert_eq!(*vol.arn_source(), ArnSource::Both { consistent: true });
        assert!(vol.deviations().is_empty());
    }

    /// A disagreement is an integrity signal: it must be reported, and
    /// `container.description` wins.
    #[test]
    fn reports_disagreement_between_the_two_sources() {
        let (_d, path) = synth(
            &[(DESCRIPTION_SEGMENT, VOLUME.as_bytes())],
            Some(OTHER.as_bytes()),
        );
        let vol = ZipVolume::open(&path).unwrap();
        assert_eq!(*vol.arn_source(), ArnSource::Both { consistent: false });
        assert_eq!(vol.arn().as_str(), VOLUME, "container.description wins");
        assert!(
            vol.deviations()
                .iter()
                .any(|d| d.kind == DeviationKind::InconsistentVolumeArn),
            "a mismatch must never pass silently"
        );
    }

    /// v1.0a §5.4 requires it first; pyaff4 does not comply. Record, don't
    /// reject.
    ///
    /// The position must be stated so an examiner can check it against the
    /// archive. It is counted **from 1**, and the member actually holding first
    /// place is named. Reporting the raw 0-based index instead would make a
    /// container with `container.description` second read as "member 1, but it
    /// is required to be the first member" — the tool appearing to contradict
    /// itself about a genuine violation.
    #[test]
    fn description_not_first_is_a_deviation_not_an_error() {
        let (_d, path) = synth(
            &[
                ("version.txt", b"major=1\nminor=1\n"),
                (DESCRIPTION_SEGMENT, VOLUME.as_bytes()),
            ],
            None,
        );
        let vol = ZipVolume::open(&path).unwrap();
        assert_eq!(vol.arn().as_str(), VOLUME);

        let detail = vol
            .deviations()
            .iter()
            .find(|d| d.detail.contains("first member"))
            .map(|d| d.detail.clone())
            .expect("position must be reported");

        // Second of two, counted from 1 — never "member 1".
        assert!(
            detail.contains("stored 2 of 2"),
            "position must be 1-based and state the total: {detail}"
        );
        assert!(
            detail.contains("\"version.txt\""),
            "the member actually first must be named: {detail}"
        );
        assert!(
            !detail.contains("is member 1"),
            "a raw 0-based index reads as a contradiction: {detail}"
        );
    }

    #[test]
    fn an_empty_archive_is_not_aff4() {
        let (_d, path) = synth(&[], None);
        let err = ZipVolume::open(&path).unwrap_err();
        assert!(matches!(
            err,
            Error::NotAff4 {
                reason: NotAff4Reason::EmptyArchive,
                ..
            }
        ));
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn no_volume_arn_anywhere_is_not_aff4() {
        let (_d, path) = synth(&[("version.txt", b"major=1\nminor=0\n")], None);
        let err = ZipVolume::open(&path).unwrap_err();
        assert!(matches!(
            err,
            Error::NotAff4 {
                reason: NotAff4Reason::NoVolumeArn,
                ..
            }
        ));
    }

    #[test]
    // Writes a throwaway file into a temp dir to have something non-ZIP to
    // open. Permitted here because it creates a fresh fixture and never
    // touches evidence; the crate-wide ban stays in force everywhere else.
    #[allow(clippy::disallowed_methods)]
    fn a_non_zip_file_reports_zip_not_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notazip.aff4");
        std::fs::write(&path, b"this is not a zip archive").unwrap();
        let err = ZipVolume::open(&path).unwrap_err();
        assert!(matches!(err, Error::Zip { .. }), "{err}");
        assert!(
            !err.is_integrity_finding(),
            "an unreadable ZIP says nothing about evidence integrity"
        );
    }

    #[test]
    fn a_missing_file_reports_io() {
        let err = ZipVolume::open("/nonexistent/nowhere.aff4").unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "{err}");
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn an_unparseable_volume_arn_is_malformed() {
        let (_d, path) = synth(
            &[(DESCRIPTION_SEGMENT, b"http://example.com/not-an-arn")],
            None,
        );
        let err = ZipVolume::open(&path).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// Overwrite the declared uncompressed size of one member.
    ///
    /// A compression-ratio bomb without the gigabytes: the headers claim
    /// `declared` bytes while the archive still holds a handful. Patches the
    /// 32-bit uncompressed-size field in the member's local header
    /// (`PK\x03\x04`, at +22) and its central-directory record
    /// (`PK\x01\x02`, at +24), located by the name that follows each.
    ///
    /// Only the named member is touched: patching every one would trip the
    /// ceiling on `container.description` during `open`, before the read under
    /// test. The result is a deliberately inconsistent archive, which is the
    /// point — the ceiling must refuse it from the headers alone.
    ///
    /// Writes to a throwaway container built by `synth` in a `TempDir`, never
    /// to evidence — the same exemption `synth` itself takes. The read-only
    /// guard denies `std::fs::write` crate-wide, so the allowance is scoped to
    /// this function rather than relaxed anywhere broader.
    #[allow(clippy::disallowed_methods)]
    fn declare_size(path: &Path, member: &str, declared: u32) {
        let mut bytes = std::fs::read(path).unwrap();
        // (signature, size-field offset, name-length-field offset, name offset)
        let shapes: [(&[u8], usize, usize, usize); 2] =
            [(b"PK\x03\x04", 22, 26, 30), (b"PK\x01\x02", 24, 28, 46)];

        let mut patched = 0;
        for (sig, size_at, name_len_at, name_at) in shapes {
            let mut i = 0;
            while i + name_at <= bytes.len() {
                if !bytes[i..].starts_with(sig) {
                    i += 1;
                    continue;
                }
                let name_len = usize::from(u16::from_le_bytes([
                    bytes[i + name_len_at],
                    bytes[i + name_len_at + 1],
                ]));
                let start = i + name_at;
                if bytes.get(start..start + name_len) == Some(member.as_bytes()) {
                    let at = i + size_at;
                    bytes[at..at + 4].copy_from_slice(&declared.to_le_bytes());
                    patched += 1;
                }
                i += 1;
            }
        }
        assert_eq!(patched, 2, "expected a local header and a directory record");
        std::fs::write(path, bytes).unwrap();
    }

    /// A member declaring far more than it stores is refused before reading.
    ///
    /// Without the ceiling, `read_member` sized its buffer straight from this
    /// field: a 12 MB container measured 5.8 GB resident. The refusal must come
    /// from the declared size alone, so no allocation is attempted.
    #[test]
    fn a_segment_declaring_more_than_the_ceiling_is_refused() {
        let (_d, path) = synth(
            &[
                (DESCRIPTION_SEGMENT, VOLUME.as_bytes()),
                ("version.txt", b"major=1\nminor=0\n"),
            ],
            None,
        );
        // Above MAX_SEGMENT_SIZE, and far above what the member really holds.
        declare_size(&path, "version.txt", u32::MAX);

        let mut vol = ZipVolume::open(&path).unwrap();
        let err = vol.read_segment("version.txt").unwrap_err();

        assert!(
            err.is_integrity_finding(),
            "an implausible declared size is a finding about the container: {err}"
        );
        let text = err.to_string();
        assert!(text.contains("version.txt"), "{text}");
        assert!(text.contains("ceiling"), "{text}");
        assert!(
            text.contains("no data was read"),
            "the message must say nothing was read: {text}"
        );
    }

    /// A member that expands far beyond what it stores is refused.
    ///
    /// The absolute ceiling alone lets a member sit just beneath it while
    /// storing almost nothing: a 256 MiB index of zeros deflates to ~300 KB and
    /// cost 771 MB to read, under any plausible ceiling. The stored size is the
    /// figure an attacker must actually pay, so the ratio is the second bound.
    #[allow(clippy::disallowed_types, clippy::disallowed_methods)]
    #[test]
    fn a_range_read_returns_the_same_bytes_as_a_full_read() {
        let body: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let (_dir, path) = synth(
            &[(DESCRIPTION_SEGMENT, VOLUME.as_bytes()), ("data", &body)],
            None,
        );
        let mut volume = ZipVolume::open(&path).unwrap();

        let whole = volume.read_segment("data").unwrap();
        assert_eq!(whole, body);

        for (offset, length) in [(0u64, 16usize), (1000, 300), (4080, 16)] {
            let part = volume
                .read_segment_range("data", offset, length)
                .unwrap()
                .expect("a stored member can be range-read");
            let at = usize::try_from(offset).unwrap();
            assert_eq!(part, &body[at..at + length], "at {offset}+{length}");
        }
    }

    #[test]
    fn a_range_read_past_the_members_extent_is_refused() {
        let body = vec![7u8; 128];
        let (_dir, path) = synth(
            &[(DESCRIPTION_SEGMENT, VOLUME.as_bytes()), ("data", &body)],
            None,
        );
        let mut volume = ZipVolume::open(&path).unwrap();

        // Refused rather than served from whatever follows the member: the
        // next member's bytes are not this segment's content.
        assert!(
            volume
                .read_segment_range("data", 120, 32)
                .unwrap()
                .is_none(),
            "a read running past the recorded extent must not be served"
        );
        assert!(volume.read_segment_range("data", 0, 128).unwrap().is_some());
    }

    #[test]
    fn a_range_read_of_an_absent_member_is_none_not_an_error() {
        let (_dir, path) = synth(
            &[(DESCRIPTION_SEGMENT, VOLUME.as_bytes()), ("data", b"x")],
            None,
        );
        let mut volume = ZipVolume::open(&path).unwrap();
        assert!(volume.read_segment_range("absent", 0, 1).unwrap().is_none());
    }

    /// A deflated member has no seekable interior, so the caller must be told
    /// to read it whole rather than handed bytes from the wrong offset.
    #[test]
    fn a_compressed_member_cannot_be_range_read() {
        #[allow(clippy::disallowed_types, clippy::disallowed_methods)]
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("deflated.aff4");
            let file = File::create(&path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let stored: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file(DESCRIPTION_SEGMENT, stored).unwrap();
            writer.write_all(VOLUME.as_bytes()).unwrap();
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            writer.start_file("data", opts).unwrap();
            writer.write_all(&vec![0u8; 8192]).unwrap();
            writer.finish().unwrap();

            let mut volume = ZipVolume::open(&path).unwrap();
            assert!(
                volume.read_segment_range("data", 0, 16).unwrap().is_none(),
                "a deflated member must fall back to a whole-member read"
            );
            assert_eq!(volume.read_segment("data").unwrap().len(), 8192);
        }
    }

    /// Builds a zip bomb in a `TempDir` — a 16 MiB run of zeros that deflates
    /// to a few kilobytes — so the expansion ceiling has something to refuse.
    /// Writing the fixture needs the writer the library is denied, scoped to
    /// this one test the same way `declare_size` and `synth` scope theirs.
    #[test]
    #[allow(clippy::disallowed_methods, clippy::disallowed_types)]
    fn a_segment_expanding_far_beyond_its_stored_size_is_refused() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ratio.aff4");
        let file = File::create(&path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        writer.start_file(DESCRIPTION_SEGMENT, opts).unwrap();
        writer.write_all(VOLUME.as_bytes()).unwrap();
        // 16 MiB of zeros deflates to a few kilobytes: a ratio in the thousands.
        writer.start_file("bomb", opts).unwrap();
        writer.write_all(&vec![0u8; 16 * 1024 * 1024]).unwrap();
        writer.finish().unwrap();

        let mut vol = ZipVolume::open(&path).unwrap();
        let err = vol.read_segment("bomb").unwrap_err();

        assert!(err.is_integrity_finding(), "{err}");
        let text = err.to_string();
        assert!(text.contains("expansion"), "{text}");
        assert!(
            text.contains("no data was read"),
            "the message must say nothing was read: {text}"
        );
    }

    /// The ratio bound must clear real evidence by a wide margin.
    ///
    /// Measured across every container in the reference corpus, the highest
    /// expansion of any member is 6.5x — `unicode.aff4`'s `information.turtle`,
    /// 6,452 bytes stored in 990. AFF4 bevies hold already-compressed chunks,
    /// so they barely deflate at all; only the RDF metadata compresses well.
    #[test]
    fn the_expansion_bound_clears_real_containers_by_orders_of_magnitude() {
        const CORPUS_WORST_RATIO: u64 = 7;
        const { assert!(MAX_EXPANSION_RATIO > CORPUS_WORST_RATIO * 100) };
    }

    /// The ceiling must not reject anything a real writer produces.
    #[test]
    fn ordinary_segments_are_well_under_the_ceiling() {
        const { assert!(MAX_SEGMENT_SIZE > 64 * 1024 * 1024) };
        assert_eq!(MAX_SEGMENT_SIZE_USIZE as u64, MAX_SEGMENT_SIZE);

        let (_d, path) = synth(
            &[
                (DESCRIPTION_SEGMENT, VOLUME.as_bytes()),
                ("version.txt", b"major=1\nminor=0\n"),
            ],
            None,
        );
        let mut vol = ZipVolume::open(&path).unwrap();
        assert_eq!(
            vol.read_segment("version.txt").unwrap(),
            b"major=1\nminor=0\n"
        );
    }

    #[test]
    fn reads_segments_and_reports_lengths() {
        let (_d, path) = synth(
            &[
                (DESCRIPTION_SEGMENT, VOLUME.as_bytes()),
                ("version.txt", b"major=1\nminor=0\ntool=t\n"),
            ],
            None,
        );
        let mut vol = ZipVolume::open(&path).unwrap();

        assert!(vol.has_segment("version.txt"));
        assert!(!vol.has_segment("absent.txt"));
        assert_eq!(vol.segment_names().len(), 2);

        let body = vol.read_segment("version.txt").unwrap();
        assert_eq!(body, b"major=1\nminor=0\ntool=t\n");
    }

    #[test]
    fn reading_an_absent_segment_is_an_error_not_a_panic() {
        let (_d, path) = synth(&[(DESCRIPTION_SEGMENT, VOLUME.as_bytes())], None);
        let mut vol = ZipVolume::open(&path).unwrap();
        let err = vol.read_segment("no/such/segment").unwrap_err();
        assert!(matches!(err, Error::Zip { .. }), "{err}");
    }

    /// The library must never modify what it reads. Compares the file's length
    /// and modification time across a full open-and-read cycle.
    #[test]
    fn opening_and_reading_never_modifies_the_container() {
        let (_d, path) = synth(
            &[
                (DESCRIPTION_SEGMENT, VOLUME.as_bytes()),
                ("version.txt", b"major=1\nminor=0\n"),
            ],
            Some(VOLUME.as_bytes()),
        );
        let before = std::fs::metadata(&path).unwrap();
        let (len_before, mtime_before) = (before.len(), before.modified().unwrap());

        {
            let mut vol = ZipVolume::open(&path).unwrap();
            for name in vol.segment_names().to_vec() {
                let _ = vol.read_segment(&name).unwrap();
            }
        }

        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(len_before, after.len(), "file length changed");
        assert_eq!(
            mtime_before,
            after.modified().unwrap(),
            "modification time changed"
        );
    }

    #[test]
    fn locus_names_the_container_and_segment() {
        let (_d, path) = synth(&[(DESCRIPTION_SEGMENT, VOLUME.as_bytes())], None);
        let vol = ZipVolume::open(&path).unwrap();
        let locus = vol.locus(Some("information.turtle"));
        assert_eq!(locus.segment.as_deref(), Some("information.turtle"));
        assert_eq!(locus.path, path);
    }

    const STREAM: &str = "aff4%3A%2F%2F1bc40be7-de68-4e77-9e11-eec997aa5304";

    #[test]
    fn the_three_root_members_are_classified_by_whole_name() {
        assert_eq!(
            classify_segment("container.description"),
            SegmentKind::ContainerDescription
        );
        assert_eq!(
            classify_segment("information.turtle"),
            SegmentKind::Metadata
        );
        assert_eq!(classify_segment("version.txt"), SegmentKind::Version);
    }

    /// Standard writes `<bevy>.index`; pre-standard makes the bevy a folder
    /// holding a bare `index`. Both name the same thing.
    #[test]
    fn bevies_are_recognised_in_both_generations() {
        assert_eq!(
            classify_segment(&format!("{STREAM}/data/00008213")),
            SegmentKind::BevyData
        );
        assert_eq!(
            classify_segment(&format!("{STREAM}/data/00008213.index")),
            SegmentKind::BevyIndex
        );
        // Pre-standard: the bevy is a folder, the index a member inside it.
        assert_eq!(
            classify_segment(&format!("{STREAM}/00000000")),
            SegmentKind::BevyData
        );
        assert_eq!(
            classify_segment(&format!("{STREAM}/00000000/index")),
            SegmentKind::BevyIndex
        );
    }

    #[test]
    fn block_hashes_are_recognised_in_both_spellings() {
        assert_eq!(
            classify_segment(&format!("{STREAM}/00000000.blockHash.md5")),
            SegmentKind::BlockHash
        );
        // Pre-standard puts them inside the bevy folder, unprefixed.
        assert_eq!(
            classify_segment(&format!("{STREAM}/00000000/blockHash.sha1")),
            SegmentKind::BlockHash
        );
    }

    #[test]
    fn the_three_map_members_are_map_structure() {
        for tail in ["map", "idx", "mapPath"] {
            assert_eq!(
                classify_segment(&format!("{STREAM}/{tail}")),
                SegmentKind::MapStructure,
                "{tail}"
            );
        }
    }

    /// An AFF4-L logical file keeps its original path, so it matches no AFF4
    /// naming convention. It must not be filed as `Other`.
    #[test]
    fn a_logical_file_is_not_reported_as_unknown() {
        assert_eq!(
            classify_segment("/test_images/AFF4-L/dream.txt"),
            SegmentKind::LogicalFile
        );
    }

    /// A bevy number is exactly eight digits. Anything else under a stream
    /// path is unrecognised, and saying so is the point.
    #[test]
    fn names_matching_no_convention_are_reported_as_other() {
        assert_eq!(
            classify_segment(&format!("{STREAM}/0000")),
            SegmentKind::Other
        );
        assert_eq!(
            classify_segment(&format!("{STREAM}/notabevy")),
            SegmentKind::Other
        );
    }
}
