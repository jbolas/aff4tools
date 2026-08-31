//! Reading a `Map`: the virtual address space that assembles an image.
//!
//! A `DiskImage` is not a stream of chunks. It is a *map* whose entries say
//! where each region of the image comes from — a stored stream, or a run of
//! one repeated byte recorded as a description rather than as bytes.
//!
//! # Segments
//!
//! A map named `aff4://fcbfdce7-…` is stored as up to three segments:
//!
//! ```text
//! aff4%3A%2F%2Ffcbfdce7-…/map      28 bytes per entry: <QQQI>
//! aff4%3A%2F%2Ffcbfdce7-…/idx      newline-separated target ARNs
//! aff4%3A%2F%2Ffcbfdce7-…/mapPath  optional; absent in broken-dedupe.aff4
//! ```
//!
//! # Entries are 28 bytes
//!
//! `<QQQI>`: offset, length, target offset, target id — 8 + 8 + 8 + 4.
//! Verified across all 16 maps in 10 containers, standard and pre-standard.
//!
//! A length check alone does **not** establish this: five of those sixteen
//! maps also divide evenly by 32. Only decoding entries and resolving target
//! ids distinguishes the two widths, so never "confirm" the entry size from a
//! segment length.
//!
//! # Entries are not stored in order
//!
//! # Described regions are acquired evidence
//!
//! A [`Target::RepeatedByte`] region is a run of one byte recorded as a
//! description instead of as bytes. Those bytes were on the source medium and
//! were read from it — unallocated space reads `0x00`, erased flash `0xFF`.
//! Reconstructing them reproduces the acquired image exactly.
//!
//! **Never describe these as fake, synthetic, empty, or missing data.** The
//! distinction is *stored* versus *described*. In `Base-Linear.aff4`, 98.5% of
//! the image is described: 262 MB of `Zero` against 3.96 MB stored.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::arn::Arn;
use crate::error::{Error, Locus, Result};
use crate::rdf::Graph;

/// Bytes per map entry: `<QQQI>`.
pub const MAP_ENTRY_LEN: usize = 28;

/// The segment holding map entries.
pub const MAP_SEGMENT: &str = "map";
/// The segment holding the target ARN list.
pub const IDX_SEGMENT: &str = "idx";
/// The segment holding the map path, absent in some containers.
pub const MAP_PATH_SEGMENT: &str = "mapPath";

/// Whether an ARN names a stream the standard defines rather than the container.
///
/// Symbolic streams (spec §4.4) are resolved by name: a run of repeated bytes is
/// recorded as a description rather than stored, so no triple declares them and
/// an edge to one is not dangling.
///
/// **This is about how the bytes are stored, not about whether they are real.**
/// The bytes were on the source medium and were read from it; only their storage
/// is elided. `UnknownData` and `UnreadableData` are the exceptions — those mark
/// regions whose true content is genuinely unknown, and they carry defined
/// placeholder content for hashing.
#[must_use]
pub fn is_symbolic_target(iri: &str) -> bool {
    let Some(tail) = iri.rsplit('/').next() else {
        return false;
    };
    tail.starts_with("SymbolicStream")
        || matches!(tail, "Zero" | "UnknownData" | "UnreadableData" | "FF")
}

/// The prefix a content-addressed chunk target carries (AFF4-L §4).
///
/// Defined here rather than in the writer because it is a property of the
/// format: the reader must recognize these whoever wrote them, and
/// `broken-dedupe.aff4` predates this crate entirely.
pub const BLOCK_HASH_PREFIX: &str = "aff4:sha512:";

/// Where a region's bytes come from.
///
/// Named for **how the bytes are recorded**, not for how real they are: both
/// `Stored` and `RepeatedByte` reconstruct acquired evidence. The spec calls
/// the latter a "symbolic stream", which is kept in documentation because it
/// is what the schema URIs say, but the variant name avoids implying the data
/// is fabricated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Bytes stored in a stream, named by its ARN.
    Stored(Arn),
    /// A run of one repeated byte, recorded as a description. See the module
    /// documentation.
    RepeatedByte(u8),
    /// A region whose true content is unknown: deliberately not read, or
    /// unreadable. Distinct from [`Target::RepeatedByte`]. See
    /// [`UnknownKind`].
    Unknown(UnknownKind),
    /// A content-addressed chunk, `aff4:sha512:<digest>` (AFF4-L §4).
    ///
    /// Names a chunk by its content rather than by resource. The bytes live in
    /// a shared `ImageStream`, reached through the ARN's own `aff4:dataStream`
    /// — a second level of indirection no other target kind has, and the reason
    /// this variant carries the ARN text rather than a resolved stream.
    BlockHash(String),
    /// A target this build does not recognize, kept verbatim so it can be
    /// named in a report rather than silently dropped.
    Unrecognised(String),
}

/// Which kind of unknown region a target names.
///
/// Spec p8 gives both defined placeholder content — 1 MiB chunks of a
/// repeating ASCII string, truncated at the chunk boundary — so that linear
/// hashes over images containing them stay reproducible.
///
/// **The placeholder is not recovered content.** A report must never present
/// these bytes as data read from the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownKind {
    /// `aff4:UnknownData` — deliberately not acquired. Repeats `"UNKNOWN"`.
    NotAcquired,
    /// `aff4:UnreadableData` — inaccessible, e.g. bad sectors. Repeats
    /// `"UNREADABLEDATA"`.
    Unreadable,
}

impl UnknownKind {
    /// The ASCII string this region's placeholder repeats.
    #[must_use]
    pub fn filler(self) -> &'static [u8] {
        match self {
            Self::NotAcquired => b"UNKNOWN",
            Self::Unreadable => b"UNREADABLEDATA",
        }
    }
}

impl Target {
    /// Resolve a target from its `idx` entry.
    ///
    /// Recognises the standard and pre-standard symbolic vocabularies:
    ///
    /// | Form | Meaning |
    /// |---|---|
    /// | `…#Zero` | `RepeatedByte(0x00)` |
    /// | `…#SymbolicStreamNN` | `RepeatedByte(0xNN)` |
    /// | `…/2009/aff4#FF` | `RepeatedByte(0xFF)` — pre-standard |
    /// | `…/2012/SymbolicStream#NN` | `RepeatedByte(0xNN)` — pre-standard |
    /// | `…#UnknownData` | `Unknown(NotAcquired)` |
    /// | `…#UnreadableData` | `Unknown(Unreadable)` |
    /// | `aff4://…` | `Stored` |
    #[must_use]
    pub fn parse(text: &str, locus: &Locus) -> Self {
        let text = text.trim();

        if text.starts_with("aff4://") {
            return match Arn::parse(text, locus) {
                Ok(arn) => Self::Stored(arn),
                Err(_) => Self::Unrecognised(text.to_owned()),
            };
        }

        // AFF4-L §4's content-addressed chunk. Not an `aff4://` resource name,
        // so it is checked before the symbolic vocabularies below.
        if text.starts_with(BLOCK_HASH_PREFIX) {
            return Self::BlockHash(text.to_owned());
        }

        let local = text.rsplit_once(['#', '/']).map_or(text, |(_, name)| name);

        match local {
            "Zero" => return Self::RepeatedByte(0x00),
            "UnknownData" => return Self::Unknown(UnknownKind::NotAcquired),
            "UnreadableData" => return Self::Unknown(UnknownKind::Unreadable),
            _ => {}
        }

        // `SymbolicStreamNN`, and the pre-standard bare `NN` under the 2009
        // and 2012 namespaces.
        let hex = local.strip_prefix("SymbolicStream").unwrap_or(local);
        if hex.len() == 2
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            return Self::RepeatedByte(byte);
        }

        Self::Unrecognised(text.to_owned())
    }

    /// Whether reading this target requires stored data.
    ///
    /// A block hash does too — its bytes are in the shared stream — but it
    /// cannot name that stream without the graph, so it is resolved separately
    /// and is not `Stored` here.
    #[must_use]
    pub fn is_stored(&self) -> bool {
        matches!(self, Self::Stored(_))
    }

    /// The Block Hash ARN this target names, if it is one.
    #[must_use]
    pub fn block_hash(&self) -> Option<&str> {
        match self {
            Self::BlockHash(arn) => Some(arn),
            _ => None,
        }
    }

    /// A short description for reports.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Stored(arn) => format!("stored stream {arn}"),
            Self::BlockHash(arn) => format!("deduplicated chunk {arn}"),
            Self::RepeatedByte(b) => format!("a described run of 0x{b:02X}"),
            Self::Unknown(UnknownKind::NotAcquired) => "a region not acquired".to_owned(),
            Self::Unknown(UnknownKind::Unreadable) => "a region that could not be read".to_owned(),
            Self::Unrecognised(text) => format!("unrecognised target {text}"),
        }
    }

    /// How to name this target as a gap fill source.
    ///
    /// The ARN form rather than [`Target::describe`]'s prose, because a gap
    /// fill is reported as the thing the container names (or the thing spec §4
    /// names on its behalf), not as a description of what it contains.
    ///
    /// `aff4:Zero` and `aff4:FF` are the two symbolic streams §4 defines by a
    /// repeated byte; any other repeated byte has no standard name, so it is
    /// stated as the byte value rather than given an invented one.
    #[must_use]
    pub fn gap_fill_name(&self) -> String {
        match self {
            Self::RepeatedByte(0x00) => "aff4:Zero".to_owned(),
            Self::RepeatedByte(0xFF) => "aff4:FF".to_owned(),
            Self::RepeatedByte(b) => format!("a run of 0x{b:02X}"),
            Self::Stored(arn) => arn.to_string(),
            Self::BlockHash(arn) => arn.clone(),
            Self::Unknown(UnknownKind::NotAcquired) => "aff4:UnknownData".to_owned(),
            Self::Unknown(UnknownKind::Unreadable) => "aff4:UnreadableData".to_owned(),
            Self::Unrecognised(text) => text.clone(),
        }
    }
}

/// One region of the image's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapEntry {
    /// Where this region starts in the image.
    pub offset: u64,
    /// How many bytes it covers.
    pub length: u64,
    /// Where the region's bytes start within its target.
    pub target_offset: u64,
    /// Index into the map's target list.
    pub target_id: u32,
}

impl MapEntry {
    /// The offset one past this region's last byte.
    ///
    /// Entries whose `offset + length` overflows are refused by
    /// [`Map::parse_with`], so this cannot saturate for an entry reachable
    /// through a parsed [`Map`]. The saturation is a defensive floor for an
    /// entry constructed directly, not a tolerance: a saturated end would make
    /// two different malformed maps compare equal.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }

    /// The offset one past this region's last byte, or `None` on overflow.
    ///
    /// The checked form used during validation. An entry whose extent does not
    /// fit in `u64` describes no region that could exist, so it is a finding
    /// rather than something to clamp.
    #[must_use]
    pub fn checked_end(&self) -> Option<u64> {
        self.offset.checked_add(self.length)
    }
}

/// How a map's holes should be treated.
///
/// Spec §4 permits a **discontiguous** map to leave regions of its address
/// space uncovered, filled on read from `aff4:mapGapDefaultStream` and
/// defaulting to `aff4:Zero` when that is unset. A *contiguous* image with a
/// hole is a different matter entirely — there the gap is a finding, since the
/// image claims to cover everything.
///
/// So the choice is not a tolerance setting. It follows from the image's
/// declared type, and defaults to the strict reading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum GapPolicy {
    /// Any hole is [`Error::Malformed`]. The default, and correct for a
    /// `ContiguousImage` or `DiskImage`.
    #[default]
    Refuse,
    /// Holes are covered by this target, per spec §4. Only for an image typed
    /// `aff4:DiscontiguousImage`.
    ///
    /// The `bool` is whether `aff4:mapGapDefaultStream` was declared, as
    /// against spec §4's `aff4:Zero` default applying. Carried here because it
    /// is known where the policy is built and unrecoverable afterwards, and a
    /// report must not present the default as the container's own statement.
    Fill(Target, bool),
}

impl GapPolicy {
    /// The spec's default gap stream: `aff4:Zero`, a run of `0x00`.
    #[must_use]
    pub fn spec_default() -> Self {
        Self::Fill(Target::RepeatedByte(0x00), false)
    }
}

/// What filling a map's holes required.
///
/// Reported so an examiner can see that a region was never recorded by the
/// acquisition at all. This is a stronger statement than "described": a
/// described run was measured and written down as a run, whereas a gap was
/// simply not preserved.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct GapSummary {
    /// How many separate holes the map left.
    pub count: usize,
    /// How many bytes they cover in total.
    pub bytes: u64,
    /// What the holes were filled from, named as a report should print it.
    ///
    /// [`None`] when no hole was found, so a gapless map carries nothing.
    pub fill: Option<GapFill>,
}

/// What a map's holes were filled from, and whether the container said so.
///
/// The distinction matters in a report. A container that declares
/// `aff4:mapGapDefaultStream` has *stated* what fills its holes; one that omits
/// it has stated nothing, and spec §4's `aff4:Zero` default applies. Printing
/// the same sentence for both would attribute to the container a claim it never
/// made — the failure mode CLAUDE.md's "don't invent format details" names.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GapFill {
    /// How to name the fill source, e.g. `aff4:Zero` or a stream ARN.
    pub name: String,
    /// Whether `aff4:mapGapDefaultStream` was present.
    ///
    /// `false` means this is spec §4's default, inferred rather than declared.
    pub declared: bool,
}

impl GapFill {
    /// How a report should name this fill source.
    ///
    /// A declared stream is named plainly; an undeclared one names the §4
    /// default **and** says it is the standard's rather than the container's.
    /// Attributing the default to the container would be inventing a statement
    /// it never made.
    ///
    /// The single wording, so the accounting line and the note cannot say
    /// different things about the same container.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.declared {
            self.name.clone()
        } else {
            format!(
                "{} (the §4 default; this container declares no \
                 mapGapDefaultStream)",
                self.name
            )
        }
    }
}

/// How a split set's stored streams are laid out across its parts.
///
/// Descriptive rather than normative: the specification defines no property
/// recording this, and both layouts reassemble through the same Map. See
/// [`Map::split_layout`] for how it is inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitLayout {
    /// One stored stream, so nothing is split across parts.
    Single,
    /// Each part is filled before the next begins.
    Sequential,
    /// Stored streams alternate through the image address space (§7.1).
    Striped,
}

impl SplitLayout {
    /// A phrase for a report.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Single => "a single stream",
            Self::Sequential => "sequential (not striped)",
            Self::Striped => "striped (interleaved)",
        }
    }
}

/// A map: an image assembled from stored streams and described runs.
#[derive(Debug, Clone)]
pub struct Map {
    arn: Arn,
    /// Entries sorted by offset. On-disk order is not preserved — nothing
    /// downstream depends on it, and reads resolve through the sorted view.
    entries: Vec<MapEntry>,
    targets: Vec<Target>,
    size: u64,
    /// Holes the map left, which entries now cover. Zero for every canonical
    /// reference container.
    gaps: GapSummary,
    /// The target id appended to cover holes, if any were found. Entries naming
    /// it are gap fills rather than described runs, which is the only way to
    /// tell the two apart once both are `Target::RepeatedByte`.
    gap_target_id: Option<u32>,
}

impl Map {
    /// Parse a map from its three segments.
    ///
    /// `map_path` is optional: `broken-dedupe.aff4` has no `mapPath` segment.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the entries are not a whole number of 28-byte
    /// records, a target id is out of range, a length is zero, the sorted
    /// entries leave a gap or overlap, or their total does not equal
    /// `declared_size`. Each names the offending entry.
    pub fn parse(
        arn: &Arn,
        map_bytes: &[u8],
        idx_bytes: &[u8],
        declared_size: u64,
        locus: &Locus,
    ) -> Result<Self> {
        Self::parse_with(
            arn,
            map_bytes,
            idx_bytes,
            declared_size,
            &GapPolicy::Refuse,
            locus,
        )
    }

    /// Parse a map, deciding what to do about holes in its address space.
    ///
    /// [`Map::parse`] is this with [`GapPolicy::Refuse`], which is right for
    /// every contiguous image. Pass [`GapPolicy::Fill`] only for an image typed
    /// `aff4:DiscontiguousImage`, where spec §4 permits holes.
    ///
    /// Filled holes become ordinary entries, so everything downstream —
    /// traversal, byte accounting, the sorted view — needs no special case and
    /// the entry list is gapless by construction. [`Map::gaps`] reports what
    /// was filled.
    ///
    /// # Errors
    ///
    /// As [`Map::parse`]. **Overlaps remain fatal under every policy**: the
    /// spec gives an overlapping region no defined content, so there is nothing
    /// to fill it with and a guess would be a fabrication.
    pub fn parse_with(
        arn: &Arn,
        map_bytes: &[u8],
        idx_bytes: &[u8],
        declared_size: u64,
        gap_policy: &GapPolicy,
        locus: &Locus,
    ) -> Result<Self> {
        let locus = locus.clone().subject(arn.as_str());

        let mut targets = parse_targets(idx_bytes, &locus);
        if targets.is_empty() {
            return Err(Error::malformed(
                locus.clone().segment(IDX_SEGMENT),
                "the map names no targets; its entries cannot be resolved".to_owned(),
            ));
        }

        let mut entries = parse_entries(map_bytes, &locus)?;
        if entries.is_empty() {
            return Err(Error::malformed(
                locus.clone().segment(MAP_SEGMENT),
                "the map has no entries; it covers no part of the image".to_owned(),
            ));
        }

        // Validate targets and lengths before sorting, so a report can name
        // the entry as it appears in the segment.
        for (index, entry) in entries.iter().enumerate() {
            if entry.length == 0 {
                return Err(Error::malformed(
                    locus.clone().segment(MAP_SEGMENT),
                    format!("map entry {index} has zero length; it covers no bytes"),
                ));
            }
            if entry.target_id as usize >= targets.len() {
                return Err(Error::malformed(
                    locus.clone().segment(MAP_SEGMENT),
                    format!(
                        "map entry {index} names target {} but only {} targets are \
                         listed in the idx segment",
                        entry.target_id,
                        targets.len()
                    ),
                ));
            }
            // An extent that does not fit in u64 describes no region that could
            // exist. Clamping it would let two different malformed maps present
            // the same apparent coverage, and the gap and overlap checks below
            // both reason about `end()`.
            if entry.checked_end().is_none() {
                return Err(Error::malformed(
                    locus.clone().segment(MAP_SEGMENT),
                    format!(
                        "map entry {index} starts at offset {} and claims {} bytes, \
                         which together exceed the largest representable offset; the \
                         entry describes a region that cannot exist",
                        entry.offset, entry.length
                    ),
                ));
            }
        }

        // Entries need not be stored in address order — broken-dedupe.aff4
        // is not. Sort, then check coverage.
        entries.sort_unstable_by_key(|e| e.offset);

        let (covered, gaps, gap_target_id) = resolve_coverage(
            &mut entries,
            &mut targets,
            declared_size,
            gap_policy,
            &locus,
        )?;

        if covered != declared_size {
            return Err(Error::malformed(
                locus.clone().segment(MAP_SEGMENT),
                format!(
                    "the map covers {covered} bytes but the image declares \
                     {declared_size}; a digest over a short image would not match \
                     the evidence"
                ),
            ));
        }

        Ok(Self {
            arn: arn.clone(),
            entries,
            targets,
            size: declared_size,
            gaps,
            gap_target_id,
        })
    }

    /// Read a map's declared size out of the metadata graph, then parse it.
    ///
    /// # Errors
    ///
    /// As [`Map::parse`], plus [`Error::Malformed`] if the subject declares no
    /// usable `aff4:size`.
    pub fn open(
        arn: &Arn,
        map_bytes: &[u8],
        idx_bytes: &[u8],
        graph: &Graph,
        size_predicate: &str,
        locus: &Locus,
    ) -> Result<Self> {
        Self::open_with(
            arn,
            map_bytes,
            idx_bytes,
            graph,
            size_predicate,
            &GapPolicy::Refuse,
            locus,
        )
    }

    /// Read a map's declared size out of the graph and parse it, choosing a
    /// gap policy.
    ///
    /// # Errors
    ///
    /// As [`Map::parse_with`], plus [`Error::Malformed`] if the subject
    /// declares no usable `aff4:size`.
    pub fn open_with(
        arn: &Arn,
        map_bytes: &[u8],
        idx_bytes: &[u8],
        graph: &Graph,
        size_predicate: &str,
        gap_policy: &GapPolicy,
        locus: &Locus,
    ) -> Result<Self> {
        let size = graph
            .object(arn.as_str(), size_predicate)
            .and_then(|value| value.lexical().trim().parse::<u64>().ok())
            .ok_or_else(|| {
                Error::malformed(
                    locus
                        .clone()
                        .subject(arn.as_str())
                        .predicate(size_predicate),
                    "the map declares no usable size; its coverage cannot be checked".to_owned(),
                )
            })?;

        let mut map = Self::parse_with(arn, map_bytes, idx_bytes, size, gap_policy, locus)?;
        map.resolve_block_hashes(graph, locus);
        Ok(map)
    }

    /// Rewrite content-addressed targets into concrete stream reads (AFF4-L §4).
    ///
    /// A `aff4:sha512:<digest>` target names a chunk's *content*; the bytes are
    /// found by following that ARN's own `aff4:dataStream` to a slice of the
    /// shared stream, e.g. `aff4://<uuid>[0x4f8000:0x8000]`. Resolving it here,
    /// where the graph is in hand, means the read path sees an ordinary
    /// [`Target::Stored`] and needs no second level of its own.
    ///
    /// The slice's start is folded into each entry's `target_offset` and the
    /// target becomes the **bare** stream ARN. Leaving the range on the ARN
    /// would be tidier to read but would not resolve: stream lookup matches the
    /// full ARN text, and no stream is named `…[0x0:0x8000]`.
    ///
    /// A target whose `dataStream` is missing or unusable is **left as a block
    /// hash**, so reading it fails loudly rather than resolving to the wrong
    /// bytes. That is the state `broken-dedupe.aff4` is in: it lists 437 such
    /// targets and declares a `dataStream` for none of them.
    fn resolve_block_hashes(&mut self, graph: &Graph, locus: &Locus) {
        if !self.targets.iter().any(|t| t.block_hash().is_some()) {
            return;
        }
        let data_stream = crate::lexicon::STANDARD11.iri(crate::lexicon::STANDARD11.data_stream);

        // Target id → where in the shared stream that chunk begins.
        let mut slice_starts: BTreeMap<u32, u64> = BTreeMap::new();

        for (index, target) in self.targets.iter_mut().enumerate() {
            let Some(block_arn) = target.block_hash() else {
                continue;
            };
            let Some(slice) = graph.object(block_arn, &data_stream) else {
                continue;
            };
            let Ok(arn) = Arn::parse(slice.lexical().trim(), locus) else {
                continue;
            };
            let Some(range) = arn.byte_range() else {
                continue;
            };
            // `without_range`, not `volume`: the chunk lives in a *stream*
            // inside the volume, and dropping the path would name the volume
            // itself, which declares no size and cannot be read.
            let Ok(bare) = Arn::parse(arn.without_range(), locus) else {
                continue;
            };
            let Ok(id) = u32::try_from(index) else {
                continue;
            };
            slice_starts.insert(id, range.start);
            *target = Target::Stored(bare);
        }

        // Shift every entry against a resolved chunk to the chunk's true
        // position in the shared stream.
        for entry in &mut self.entries {
            if let Some(start) = slice_starts.get(&entry.target_id) {
                entry.target_offset = entry.target_offset.saturating_add(*start);
            }
        }
    }

    /// The gap stream a map declares, per spec §4.
    ///
    /// Reads `aff4:mapGapDefaultStream`, **defaulting to `aff4:Zero`** when the
    /// property is absent per Specification.
    #[must_use]
    pub fn declared_gap_target(arn: &Arn, graph: &Graph, predicate: &str, locus: &Locus) -> Target {
        Self::declared_gap_fill(arn, graph, predicate, locus).0
    }

    /// [`Map::declared_gap_target`], also saying whether the property was there.
    ///
    /// A report must not attribute the §4 default to the container as though it
    /// had been declared, so the two cases are distinguishable at the point the
    /// distinction is still known.
    #[must_use]
    pub fn declared_gap_fill(
        arn: &Arn,
        graph: &Graph,
        predicate: &str,
        locus: &Locus,
    ) -> (Target, bool) {
        graph
            .object(arn.as_str(), predicate)
            .and_then(crate::rdf::Value::as_iri)
            .map_or((Target::RepeatedByte(0x00), false), |iri| {
                (Target::parse(iri, locus), true)
            })
    }

    /// The map's ARN.
    #[must_use]
    pub fn arn(&self) -> &Arn {
        &self.arn
    }

    /// The image's total size, as declared and as covered.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// What filling the map's holes required, if anything.
    ///
    /// Zero for every canonical reference container. A non-zero count means
    /// regions of the address space were never recorded by the acquisition and
    /// are reconstructed from the gap stream — see [`GapPolicy`].
    #[must_use]
    pub fn gaps(&self) -> &GapSummary {
        &self.gaps
    }

    /// Entries, sorted by offset.
    #[must_use]
    pub fn entries(&self) -> &[MapEntry] {
        &self.entries
    }

    /// The entry covering `offset`, or `None` if none does.
    ///
    /// Binary search, not a scan: [`Map::entries`] is sorted at parse time, and
    /// a random-access read consults this on every call. `Base-Linear.aff4`'s
    /// map has 4103 entries, so a linear walk would make [`Image::read_at`]
    /// quadratic in the number of reads.
    ///
    /// A parsed map is gapless by construction — [`GapPolicy::Fill`] turns
    /// holes into ordinary entries whose target is the declared filler — so
    /// `None` means the offset is at or past the image's end, not that it fell
    /// into a hole.
    ///
    /// [`Image::read_at`]: crate::image::Image::read_at
    #[must_use]
    pub fn entry_at(&self, offset: u64) -> Option<&MapEntry> {
        let index = self
            .entries
            .binary_search_by(|entry| {
                if entry.end() <= offset {
                    Ordering::Less
                } else if entry.offset > offset {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            })
            .ok()?;
        self.entries.get(index)
    }

    /// Fill `buf` from the map starting at `offset`, returning bytes written.
    ///
    /// The random-access counterpart to [`Map::read_all`], and short **only**
    /// at the end of the image. Works against any [`StreamSource`], so one
    /// implementation serves a single volume, a striped set, and a split set
    /// alike.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if an entry names a target the idx segment does not
    /// list, or a target whose bytes cannot be produced. Whatever reading a
    /// stored region returns is propagated.
    pub fn read_at(
        &self,
        source: &mut dyn StreamSource,
        offset: u64,
        buf: &mut [u8],
        locus: &Locus,
    ) -> Result<usize> {
        read_at_impl(self, source, offset, buf, locus)
    }

    /// The resolved target list, indexed by [`MapEntry::target_id`].
    #[must_use]
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    /// The target an entry refers to.
    #[must_use]
    pub fn target_of(&self, entry: &MapEntry) -> Option<&Target> {
        self.targets.get(entry.target_id as usize)
    }

    /// How many bytes come from each target, keyed by target id.
    ///
    /// The measure of how much of an image is stored against described: for
    /// `Base-Linear.aff4` this is 3,964,928 stored against 264,470,528
    /// described.
    #[must_use]
    pub fn bytes_by_target(&self) -> BTreeMap<u32, u64> {
        let mut totals = BTreeMap::new();
        for entry in &self.entries {
            *totals.entry(entry.target_id).or_insert(0) += entry.length;
        }
        totals
    }

    /// Whether this map allocates its stored streams sequentially or
    /// interleaves them.
    ///
    /// **Inferred, not declared.** No AFF4 property distinguishes the two, so
    /// this reads the map's geometry: walking the entries in image order, a
    /// sequential set fills one stored stream before starting the next, so each
    /// appears in exactly one contiguous run. A stream that reappears after
    /// another took over is interleaving. Both reassemble identically through
    /// the Map, so this is descriptive only.
    ///
    /// **Described runs are skipped, and that is what makes it work.** A map's
    /// targets include symbolic streams — a run of `0x00`, `0xFF`, or any
    /// repeated byte (spec §4.4) — which are storage-free descriptions rather
    /// than parts of a set. They routinely alternate with stored data in a
    /// perfectly sequential image, so counting them would report every set as
    /// striped. Only stored targets are read, since only those live in a part.
    ///
    /// A map with fewer than two stored streams is [`SplitLayout::Single`]:
    /// there is no allocation across parts to describe.
    #[must_use]
    pub fn split_layout(&self) -> SplitLayout {
        let mut runs: Vec<u32> = Vec::new();
        for entry in &self.entries {
            if !self.target_of(entry).is_some_and(Target::is_stored) {
                continue;
            }
            if runs.last() != Some(&entry.target_id) {
                runs.push(entry.target_id);
            }
        }

        let mut distinct = runs.clone();
        distinct.sort_unstable();
        distinct.dedup();

        if distinct.len() < 2 {
            return SplitLayout::Single;
        }
        if runs.len() == distinct.len() {
            SplitLayout::Sequential
        } else {
            SplitLayout::Striped
        }
    }

    /// Total bytes that must be read from stored streams.
    #[must_use]
    pub fn stored_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| self.target_of(e).is_some_and(Target::is_stored))
            .map(|e| e.length)
            .sum()
    }

    /// Total bytes reconstructed from a description rather than read.
    ///
    /// Excludes gap fills, which [`Map::gaps`] reports separately.
    #[must_use]
    pub fn described_bytes(&self) -> u64 {
        self.size
            .saturating_sub(self.stored_bytes())
            .saturating_sub(self.gaps.bytes)
    }

    /// Every distinct stored stream this map depends on.
    #[must_use]
    pub fn dependent_streams(&self) -> Vec<&Arn> {
        let mut seen: Vec<&Arn> = Vec::new();
        for target in &self.targets {
            if let Target::Stored(arn) = target
                && !seen.iter().any(|a| a.as_str() == arn.as_str())
            {
                seen.push(arn);
            }
        }
        seen
    }
}

/// How large a buffer a described run is emitted through.
///
/// A `Zero` run of 262 MB must not become a 262 MB allocation: it is written
/// out in pieces of this size, looped. 64 KiB is two chunks — large enough that
/// the per-call overhead disappears, small enough to stay in cache.
pub const RUN_BUFFER_LEN: usize = 64 * 1024;

/// Supplies the stored streams a map depends on.
///
/// Reading through a map needs the map's own entries plus a way to fetch bytes
/// from each stored target. Keeping that behind a trait is what lets feature 3
/// resolve a target living in a sibling container without changing this module:
/// a striped resolver implements the same call against a different volume set.
pub trait StreamSource {
    /// Feed `length` bytes of `stream`, starting at `offset`, to `sink`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the region cannot be read, and whatever `sink`
    /// returns.
    fn read_region(
        &mut self,
        stream: &Arn,
        offset: u64,
        length: u64,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<()>;
}

/// What a map traversal did with each kind of region.
///
/// Kept so a report can state the composition of what was hashed rather than
/// implying every byte was read from storage. The distinction is load-bearing:
/// 98.5% of `Base-Linear.aff4` is reconstructed, not read.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReadAccounting {
    /// Bytes read from stored streams.
    pub stored: u64,
    /// Bytes reconstructed from a described run of one repeated byte.
    pub described: u64,
    /// Bytes of placeholder content for regions whose true content is unknown.
    ///
    /// Never presented as recovered data — see [`UnknownKind`].
    pub unknown_placeholder: u64,
    /// Bytes covering holes the map left, filled from the gap stream.
    ///
    /// Kept apart from `described` deliberately. A described run was measured
    /// by the imager and written down as a run; a gap was **never recorded at
    /// all**, and these bytes come from the spec's default rather than from the
    /// acquisition. Folding the two together would overstate what the container
    /// witnesses. See [`GapPolicy`].
    pub gap_filled: u64,
    /// What those holes were filled from, when there were any.
    ///
    /// Carried so a report can name the source rather than saying "the gap
    /// stream", and can tell a declared `aff4:mapGapDefaultStream` from spec
    /// §4's default applying.
    pub gap_fill: Option<GapFill>,
}

impl ReadAccounting {
    /// Total bytes delivered.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.stored
            .saturating_add(self.described)
            .saturating_add(self.unknown_placeholder)
            .saturating_add(self.gap_filled)
    }
}

impl Map {
    /// Deliver the whole image to `sink`, in address order.
    ///
    /// For each entry the bytes are either read from a stored stream through
    /// `source` or reconstructed from the entry's description. Nothing is
    /// materialised: described runs are emitted through a fixed
    /// [`RUN_BUFFER_LEN`] buffer, so a 262 MB run of `0x00` costs 64 KiB.
    ///
    /// Returns the composition of what was delivered.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if a stored region cannot be read or a target is
    /// unrecognised — a target this build cannot resolve must not be silently
    /// filled in, since the resulting digest would look authoritative and be
    /// wrong. Whatever `sink` returns is propagated unchanged.
    pub fn read_all(
        &self,
        source: &mut dyn StreamSource,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<ReadAccounting> {
        let locus = locus.clone().subject(self.arn.as_str());
        // Named once from the map's own summary rather than per entry: the fill
        // source is a property of the map, and deriving it here keeps the
        // traversed and map-derived accountings naming the same thing.
        let mut accounting = ReadAccounting {
            gap_fill: self.gaps.fill.clone(),
            ..ReadAccounting::default()
        };

        for (position, entry) in self.entries.iter().enumerate() {
            let entry_locus = locus.clone().byte_offset(entry.offset);

            let Some(target) = self.target_of(entry) else {
                return Err(Error::malformed(
                    entry_locus,
                    format!(
                        "map entry {position} names target {} but the idx segment \
                         lists only {} targets",
                        entry.target_id,
                        self.targets.len()
                    ),
                ));
            };

            match target {
                Target::Stored(arn) => {
                    source.read_region(
                        arn,
                        entry.target_offset,
                        entry.length,
                        sink,
                        &entry_locus,
                    )?;
                    accounting.stored = accounting.stored.saturating_add(entry.length);
                }
                Target::RepeatedByte(byte) => {
                    emit_repeated(*byte, entry.length, sink)?;
                    if self.gap_target_id == Some(entry.target_id) {
                        accounting.gap_filled = accounting.gap_filled.saturating_add(entry.length);
                    } else {
                        accounting.described = accounting.described.saturating_add(entry.length);
                    }
                }
                Target::Unknown(kind) => {
                    emit_unknown(*kind, entry.length, entry.target_offset, sink)?;
                    accounting.unknown_placeholder =
                        accounting.unknown_placeholder.saturating_add(entry.length);
                }
                Target::BlockHash(text) => {
                    // A block hash that survived resolution has no usable
                    // `aff4:dataStream`, so its bytes are genuinely
                    // unreachable. `broken-dedupe.aff4` is exactly this.
                    return Err(Error::malformed(
                        entry_locus,
                        format!(
                            "map entry {position} covering bytes {}..{} names \
                             deduplicated chunk {text:?}, but no aff4:dataStream \
                             says where that chunk is stored; its bytes cannot be \
                             produced, and filling the region in would yield a \
                             digest that looks authoritative and is wrong",
                            entry.offset,
                            entry.end()
                        ),
                    ));
                }
                Target::Unrecognised(text) => {
                    return Err(Error::malformed(
                        entry_locus,
                        format!(
                            "map entry {position} covering bytes {}..{} names target \
                             {text:?}, which this build does not recognise; its bytes \
                             cannot be produced, and filling the region in would yield \
                             a digest that looks authoritative and is wrong",
                            entry.offset,
                            entry.end()
                        ),
                    ));
                }
            }
        }

        if accounting.total() != self.size {
            return Err(Error::malformed(
                locus,
                format!(
                    "reading map {} delivered {} bytes but it declares {}",
                    self.arn,
                    accounting.total(),
                    self.size
                ),
            ));
        }

        Ok(accounting)
    }
}

/// One run of an image's address space, as a fused traversal must handle it.
///
/// A traversal that reads stored streams under their own parallel pipeline
/// cannot call back into [`Map::read_all`], which owns its loop. This exposes
/// the same sequence as data so a driver can interleave the two: read the
/// stored runs itself, and ask the map to reconstruct everything else.
#[derive(Debug, Clone)]
pub enum ImageRun {
    /// Bytes read from a stored stream, at that stream's own offset.
    Stored {
        /// The stream holding these bytes.
        stream: Arn,
        /// Where in that stream the run begins.
        target_offset: u64,
        /// How many bytes the run covers.
        length: u64,
    },
    /// Bytes reconstructed from a description rather than read.
    ///
    /// Acquired evidence, not a gap: a symbolic stream is 98.5% of
    /// `Base-Linear.aff4`.
    Described {
        /// The entry's position, so [`Map::emit_described`] can reproduce it.
        position: usize,
    },
}

impl Map {
    /// The map's runs in image address order.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if an entry names a target the idx segment does not
    /// list, or one whose bytes cannot be produced — the same refusals
    /// [`Map::read_all`] makes, for the same reason: a region this build cannot
    /// resolve must never be filled in, since the resulting digest would look
    /// authoritative and be wrong.
    pub fn runs(&self, locus: &Locus) -> Result<Vec<ImageRun>> {
        let locus = locus.clone().subject(self.arn.as_str());
        let mut runs = Vec::with_capacity(self.entries.len());

        for (position, entry) in self.entries.iter().enumerate() {
            let entry_locus = locus.clone().byte_offset(entry.offset);
            let target = self.target_for(entry, position, &entry_locus)?;

            match target {
                Target::Stored(arn) => runs.push(ImageRun::Stored {
                    stream: arn.clone(),
                    target_offset: entry.target_offset,
                    length: entry.length,
                }),
                Target::RepeatedByte(_) | Target::Unknown(_) => {
                    runs.push(ImageRun::Described { position });
                }
                Target::BlockHash(_) | Target::Unrecognised(_) => {
                    // Same refusal as `read_all`, reached the same way.
                    Self::unreadable_target(entry, position, target, &entry_locus)?;
                }
            }
        }

        Ok(runs)
    }

    /// Reconstruct one described run into `sink`.
    ///
    /// Delegates to the same emitters [`Map::read_all`] uses, so a fused
    /// traversal and the ordinary one cannot drift in what they produce.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `position` is not a described entry. Whatever
    /// `sink` returns is propagated unchanged.
    pub fn emit_described(
        &self,
        position: usize,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<ReadAccounting> {
        let locus = locus.clone().subject(self.arn.as_str());
        let entry = self.entries.get(position).ok_or_else(|| {
            Error::malformed(
                locus.clone(),
                format!("map entry {position} does not exist"),
            )
        })?;
        let entry_locus = locus.byte_offset(entry.offset);
        let target = self.target_for(entry, position, &entry_locus)?;

        let mut accounting = ReadAccounting {
            gap_fill: self.gaps.fill.clone(),
            ..ReadAccounting::default()
        };

        match target {
            Target::RepeatedByte(byte) => {
                emit_repeated(*byte, entry.length, sink)?;
                if self.gap_target_id == Some(entry.target_id) {
                    accounting.gap_filled = entry.length;
                } else {
                    accounting.described = entry.length;
                }
            }
            Target::Unknown(kind) => {
                emit_unknown(*kind, entry.length, entry.target_offset, sink)?;
                accounting.unknown_placeholder = entry.length;
            }
            _ => {
                return Err(Error::malformed(
                    entry_locus,
                    format!("map entry {position} is not a described run"),
                ));
            }
        }

        Ok(accounting)
    }

    /// The target an entry names, or the malformed error `read_all` would give.
    fn target_for(&self, entry: &MapEntry, position: usize, locus: &Locus) -> Result<&Target> {
        self.target_of(entry).ok_or_else(|| {
            Error::malformed(
                locus.clone(),
                format!(
                    "map entry {position} names target {} but the idx segment \
                     lists only {} targets",
                    entry.target_id,
                    self.targets.len()
                ),
            )
        })
    }

    /// The refusal for a target whose bytes cannot be produced.
    fn unreadable_target(
        entry: &MapEntry,
        position: usize,
        target: &Target,
        locus: &Locus,
    ) -> Result<()> {
        let detail = match target {
            Target::BlockHash(text) => format!(
                "names deduplicated chunk {text:?}, but no aff4:dataStream says \
                 where that chunk is stored"
            ),
            Target::Unrecognised(text) => {
                format!("names target {text:?}, which this build does not recognise")
            }
            _ => "cannot be produced".to_owned(),
        };
        Err(Error::malformed(
            locus.clone(),
            format!(
                "map entry {position} covering bytes {}..{} {detail}; its bytes \
                 cannot be produced, and filling the region in would yield a \
                 digest that looks authoritative and is wrong",
                entry.offset,
                entry.end()
            ),
        ))
    }
}

/// Emit `length` copies of one byte, through a fixed buffer.
fn emit_repeated(byte: u8, length: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let buffer_len = usize::try_from(length)
        .unwrap_or(RUN_BUFFER_LEN)
        .min(RUN_BUFFER_LEN);
    let buffer = vec![byte; buffer_len];

    let mut remaining = length;
    while remaining > 0 {
        let take = usize::try_from(remaining)
            .unwrap_or(buffer.len())
            .min(buffer.len());
        sink(&buffer[..take])?;
        remaining -= take as u64;
    }
    Ok(())
}

/// Emit the placeholder content spec p8 defines for an unknown region.
///
/// The pattern is the kind's ASCII string repeated to fill 1 MiB blocks, each
/// truncated at the block boundary — so the byte at image offset `n` depends on
/// `n` modulo the block size, not on where a read happens to start. Passing the
/// entry's `target_offset` is what keeps a partial region in phase.
///
/// **The result is not recovered content.** It exists so that a linear hash
/// over an image containing such a region is reproducible.
fn emit_unknown(
    kind: UnknownKind,
    length: u64,
    target_offset: u64,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    /// Spec p8: the pattern restarts every 1 MiB.
    const BLOCK: u64 = 1024 * 1024;

    let filler = kind.filler();
    let mut buffer = Vec::with_capacity(RUN_BUFFER_LEN);
    let mut produced: u64 = 0;

    while produced < length {
        buffer.clear();
        let position = target_offset.saturating_add(produced);
        let within_block = position % BLOCK;

        // Never cross a block boundary in one piece: the pattern restarts there.
        let to_block_end = BLOCK - within_block;
        let want = (length - produced)
            .min(to_block_end)
            .min(RUN_BUFFER_LEN as u64);

        // The truncation at the block boundary means the repeat is not simply
        // `position % filler.len()` across blocks — it is the offset within the
        // block that decides the phase.
        for i in 0..want {
            let index = usize::try_from((within_block + i) % filler.len() as u64).unwrap_or(0);
            buffer.push(filler.get(index).copied().unwrap_or(b'?'));
        }

        sink(&buffer)?;
        produced += want;
    }

    Ok(())
}

/// Fill `buf` from the map starting at `offset`, returning bytes written.
///
/// Short **only** at the end of the image: a read that stops early anywhere
/// else has silently truncated the caller's data. Entries are walked from the
/// one covering `offset` until the buffer is full, so a read crossing any
/// number of entry boundaries is served completely.
///
/// Described regions are served from their declared filler without I/O, exactly
/// as [`Map::read_all`] does. Those bytes were on the source medium and were
/// read from it; only their storage is elided.
///
/// # Errors
///
/// [`Error::Malformed`] if an entry names a target the idx segment does not
/// list, or names a deduplicated chunk or unrecognized target whose bytes
/// cannot be produced. Whatever reading a stored region returns is propagated.
fn read_at_impl(
    map: &Map,
    source: &mut dyn StreamSource,
    offset: u64,
    buf: &mut [u8],
    locus: &Locus,
) -> Result<usize> {
    let locus = locus.clone().subject(map.arn.as_str());
    let mut written = 0usize;

    while written < buf.len() {
        let position = offset.saturating_add(written as u64);
        let Some(entry) = map.entry_at(position) else {
            // At or past the end of the declared address space. A parsed map is
            // gapless, so this is the only reason a lookup fails.
            break;
        };
        let entry_locus = locus.clone().byte_offset(position);

        let Some(target) = map.target_of(entry) else {
            return Err(Error::malformed(
                entry_locus,
                format!(
                    "the map entry covering byte {position} names target {} but the \
                     idx segment lists only {} targets",
                    entry.target_id,
                    map.targets.len()
                ),
            ));
        };

        // How far into this entry the read starts, and how much of it is left.
        let into_entry = position - entry.offset;
        let remaining_here = entry.length - into_entry;
        let want = remaining_here.min((buf.len() - written) as u64);
        // `want` is bounded by the buffer's remaining space, so it fits usize.
        let take = usize::try_from(want).unwrap_or(buf.len() - written);
        let target_offset = entry.target_offset.saturating_add(into_entry);

        // One shared sink: each helper delivers pieces at most a chunk or a run
        // buffer long, and they are copied into `buf` at the running position.
        let mut cursor = written;
        let dest = &mut *buf;
        let mut sink = |piece: &[u8]| -> Result<()> {
            let end = cursor.saturating_add(piece.len()).min(dest.len());
            let room = end - cursor;
            dest[cursor..end].copy_from_slice(&piece[..room]);
            cursor = end;
            Ok(())
        };

        match target {
            Target::Stored(arn) => {
                source.read_region(arn, target_offset, want, &mut sink, &entry_locus)?;
            }
            Target::RepeatedByte(byte) => emit_repeated(*byte, want, &mut sink)?,
            Target::Unknown(kind) => emit_unknown(*kind, want, target_offset, &mut sink)?,
            Target::BlockHash(text) => {
                return Err(Error::malformed(
                    entry_locus,
                    format!(
                        "the map entry covering byte {position} names deduplicated \
                         chunk {text:?}, but no aff4:dataStream says where that chunk \
                         is stored; its bytes cannot be produced, and filling the \
                         region in would yield data that looks authoritative and is wrong"
                    ),
                ));
            }
            Target::Unrecognised(text) => {
                return Err(Error::malformed(
                    entry_locus,
                    format!(
                        "the map entry covering byte {position} names target {text:?}, \
                         which this build does not recognise; its bytes cannot be \
                         produced, and filling the region in would yield data that \
                         looks authoritative and is wrong"
                    ),
                ));
            }
        }

        if cursor != written + take {
            return Err(Error::malformed(
                entry_locus,
                format!(
                    "reading bytes {position}..{} delivered {} bytes rather than {take}; \
                     a short read here would silently truncate the caller's data",
                    position.saturating_add(want),
                    cursor - written
                ),
            ));
        }
        written = cursor;
    }

    Ok(written)
}

/// Check the sorted entries cover the address space, filling holes if allowed.
///
/// Returns the bytes covered, what filling required, and the id of the target
/// appended to cover holes. `entries` is left gapless and sorted, so nothing
/// downstream needs a special case for a discontiguous map.
///
/// # Errors
///
/// [`Error::Malformed`] on a hole under [`GapPolicy::Refuse`], and on **any**
/// overlap: the spec gives an overlapping region no defined content, so there
/// is nothing to fill it with and picking something would be a fabrication.
fn resolve_coverage(
    entries: &mut Vec<MapEntry>,
    targets: &mut Vec<Target>,
    declared_size: u64,
    gap_policy: &GapPolicy,
    locus: &Locus,
) -> Result<(u64, GapSummary, Option<u32>)> {
    // A gap target is appended to the idx list so filled holes are ordinary
    // entries pointing at an ordinary target. Added only if a hole is actually
    // found, so a gapless map's target list is untouched.
    let mut gap_target_id: Option<u32> = None;
    let mut filled: Vec<MapEntry> = Vec::new();
    let mut gaps = GapSummary::default();

    let mut covered: u64 = 0;
    let mut previous_end: u64 = 0;

    for (position, entry) in entries.iter().enumerate() {
        if entry.offset > previous_end {
            // A hole. Whether that is a finding or a documented feature depends
            // on what the image claims to be.
            let GapPolicy::Fill(gap_target, declared) = gap_policy else {
                return Err(Error::malformed(
                    locus.clone().segment(MAP_SEGMENT).byte_offset(entry.offset),
                    format!(
                        "at sorted entry {position}: the map leaves bytes \
                         {previous_end}..{} uncovered; a gap would be read as \
                         data that was never acquired",
                        entry.offset
                    ),
                ));
            };

            let id = gap_target_of(targets, &mut gap_target_id, gap_target, locus)?;
            if gaps.fill.is_none() {
                gaps.fill = Some(GapFill {
                    name: gap_target.gap_fill_name(),
                    declared: *declared,
                });
            }
            let length = entry.offset - previous_end;
            filled.push(MapEntry {
                offset: previous_end,
                length,
                // A gap has no position within its target: every byte of a
                // repeated-byte run is the same, and the spec names no other
                // kind of gap stream.
                target_offset: 0,
                target_id: id,
            });

            gaps.count += 1;
            gaps.bytes = gaps.bytes.saturating_add(length);
            covered = covered.saturating_add(length);
        } else if entry.offset < previous_end {
            return Err(Error::malformed(
                locus.clone().segment(MAP_SEGMENT).byte_offset(entry.offset),
                format!(
                    "at sorted entry {position}: the map covers bytes {}..{} \
                     twice; overlapping regions have no defined content",
                    entry.offset, previous_end
                ),
            ));
        }

        // Refused by `parse_with` before sorting, so the extent is representable.
        previous_end = entry.checked_end().ok_or_else(|| {
            Error::malformed(
                locus.clone().segment(MAP_SEGMENT).byte_offset(entry.offset),
                format!(
                    "at sorted entry {position}: the region starting at {} and \
                     covering {} bytes exceeds the largest representable offset",
                    entry.offset, entry.length
                ),
            )
        })?;

        // Individually representable entries can still sum past u64. A
        // saturated total would compare equal to a declared size that is
        // itself saturated, turning two impossible numbers into a match.
        covered = covered.checked_add(entry.length).ok_or_else(|| {
            Error::malformed(
                locus.clone().segment(MAP_SEGMENT).byte_offset(entry.offset),
                format!(
                    "at sorted entry {position}: the map's entries total more than \
                     the largest representable size; its coverage cannot be checked"
                ),
            )
        })?;
    }

    // A hole at the end of the address space is still a hole. Without this a
    // short map would fall through to the coverage check and be reported as
    // missing bytes rather than filled.
    if previous_end < declared_size
        && let GapPolicy::Fill(gap_target, declared) = gap_policy
    {
        let id = gap_target_of(targets, &mut gap_target_id, gap_target, locus)?;
        let length = declared_size - previous_end;
        filled.push(MapEntry {
            offset: previous_end,
            length,
            target_offset: 0,
            target_id: id,
        });
        // Also set here: a map whose only hole is a short tail never reaches
        // the loop above, and would otherwise report gaps with no fill named.
        if gaps.fill.is_none() {
            gaps.fill = Some(GapFill {
                name: gap_target.gap_fill_name(),
                declared: *declared,
            });
        }
        gaps.count += 1;
        gaps.bytes = gaps.bytes.saturating_add(length);
        covered = covered.saturating_add(length);
    }

    if !filled.is_empty() {
        entries.extend(filled);
        entries.sort_unstable_by_key(|e| e.offset);
    }

    Ok((covered, gaps, gap_target_id))
}

/// The id of the target covering holes, appending it to `targets` on first use.
///
/// Appended lazily so a gapless map's target list is left exactly as the `idx`
/// segment wrote it — no synthesised entry appears unless a hole is actually
/// found.
fn gap_target_of(
    targets: &mut Vec<Target>,
    gap_target_id: &mut Option<u32>,
    gap_target: &Target,
    locus: &Locus,
) -> Result<u32> {
    if let Some(id) = *gap_target_id {
        return Ok(id);
    }

    let id = u32::try_from(targets.len()).map_err(|_| {
        Error::malformed(
            locus.clone().segment(IDX_SEGMENT),
            "the map lists too many targets to add a gap stream".to_owned(),
        )
    })?;
    targets.push(gap_target.clone());
    *gap_target_id = Some(id);
    Ok(id)
}

/// Decode the `idx` segment into targets, one per line.
fn parse_targets(bytes: &[u8], locus: &Locus) -> Vec<Target> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| Target::parse(line, locus))
        .collect()
}

/// Decode the `map` segment into entries, in stored order.
fn parse_entries(bytes: &[u8], locus: &Locus) -> Result<Vec<MapEntry>> {
    if !bytes.len().is_multiple_of(MAP_ENTRY_LEN) {
        return Err(Error::malformed(
            locus.clone().segment(MAP_SEGMENT),
            format!(
                "the map segment is {} bytes, not a whole number of \
                 {MAP_ENTRY_LEN}-byte entries ({} left over)",
                bytes.len(),
                bytes.len() % MAP_ENTRY_LEN
            ),
        ));
    }

    Ok(bytes
        .as_chunks::<MAP_ENTRY_LEN>()
        .0
        .iter()
        .map(|entry| {
            // `as_chunks` yields fixed-size arrays, so the widths are guaranteed
            // by the type and these conversions cannot fail.
            let offset = u64::from_le_bytes(entry[0..8].try_into().unwrap_or([0; 8]));
            let length = u64::from_le_bytes(entry[8..16].try_into().unwrap_or([0; 8]));
            let target_offset = u64::from_le_bytes(entry[16..24].try_into().unwrap_or([0; 8]));
            let target_id = u32::from_le_bytes(entry[24..28].try_into().unwrap_or([0; 4]));
            MapEntry {
                offset,
                length,
                target_offset,
                target_id,
            }
        })
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn locus() -> Locus {
        Locus::new("/evidence/case.aff4")
    }

    fn arn(text: &str) -> Arn {
        Arn::parse(text, &locus()).unwrap()
    }

    fn entry(offset: u64, length: u64, target_offset: u64, target_id: u32) -> Vec<u8> {
        let mut v = offset.to_le_bytes().to_vec();
        v.extend_from_slice(&length.to_le_bytes());
        v.extend_from_slice(&target_offset.to_le_bytes());
        v.extend_from_slice(&target_id.to_le_bytes());
        v
    }

    const IDX: &str = "aff4://c215ba20-5648-4209-a793-1f918c723610\n\
                       http://aff4.org/Schema#Zero\n\
                       http://aff4.org/Schema#SymbolicStreamFF\n";

    #[test]
    fn entries_are_twenty_eight_bytes() {
        assert_eq!(MAP_ENTRY_LEN, 28);
        assert_eq!(entry(0, 32768, 0, 0).len(), 28);

        // The measured lengths from the corpus divide evenly.
        for length in [114_884usize, 12_320, 12_236, 196, 1904, 672, 728, 6860] {
            assert_eq!(length % MAP_ENTRY_LEN, 0, "{length} is not 28-aligned");
        }
        // And 114884 is 4103 entries, as measured in Base-Linear.aff4.
        assert_eq!(114_884 / MAP_ENTRY_LEN, 4103);
    }

    /// The first three entries of `Base-Linear.aff4`, as measured.
    #[test]
    fn decodes_the_measured_entry_prefix() {
        let mut bytes = entry(0, 32768, 0, 0);
        bytes.extend(entry(32768, 32768, 32768, 1));
        bytes.extend(entry(65536, 65536, 32768, 0));

        let entries = parse_entries(&bytes, &locus()).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            MapEntry {
                offset: 0,
                length: 32768,
                target_offset: 0,
                target_id: 0
            }
        );
        assert_eq!(entries[2].length, 65536);
        assert_eq!(entries[2].target_id, 0);
    }

    /// The regression this module exists to avoid: unsorted entries are valid.
    #[test]
    fn entries_stored_out_of_order_are_accepted() {
        // Deliberately scrambled, as broken-dedupe.aff4 stores them.
        let mut bytes = entry(65536, 32768, 0, 0);
        bytes.extend(entry(0, 32768, 0, 0));
        bytes.extend(entry(32768, 32768, 0, 1));

        let map = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 98304, &locus()).unwrap();

        // Stored order is not preserved; the sorted view is what reads use.
        assert_eq!(map.entries()[0].offset, 0);
        assert_eq!(map.entries()[1].offset, 32768);
        assert_eq!(map.entries()[2].offset, 65536);
        assert_eq!(map.size(), 98304);
    }

    #[test]
    fn a_ragged_map_segment_is_malformed() {
        let mut bytes = entry(0, 100, 0, 0);
        bytes.push(0xAB);

        let err = parse_entries(&bytes, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("29 bytes"), "{err}");
        assert!(err.to_string().contains("1 left over"), "{err}");
    }

    #[test]
    fn a_gap_is_malformed_and_names_the_entry() {
        let mut bytes = entry(0, 32768, 0, 0);
        // Skips 32768..65536.
        bytes.extend(entry(65536, 32768, 0, 0));

        let err =
            Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 98304, &locus()).unwrap_err();
        let text = err.to_string();
        assert!(err.is_integrity_finding(), "{text}");
        assert!(text.contains("32768..65536"), "{text}");
        assert!(text.contains("uncovered"), "{text}");
    }

    #[test]
    fn an_overlap_is_malformed() {
        let mut bytes = entry(0, 32768, 0, 0);
        bytes.extend(entry(16384, 32768, 0, 0));

        let err =
            Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 49152, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    /// Coverage short of the declared size must fail: hashing a short image
    /// yields a digest that looks authoritative and is wrong.
    #[test]
    fn coverage_short_of_the_declared_size_is_malformed() {
        let bytes = entry(0, 32768, 0, 0);
        let err =
            Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 65536, &locus()).unwrap_err();
        let text = err.to_string();
        assert!(err.is_integrity_finding(), "{text}");
        assert!(text.contains("32768"), "{text}");
        assert!(text.contains("65536"), "{text}");
    }

    #[test]
    fn a_target_id_beyond_the_idx_list_is_malformed() {
        let bytes = entry(0, 32768, 0, 99);
        let err =
            Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 32768, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("target 99"), "{err}");
        assert!(err.to_string().contains("3 targets"), "{err}");
    }

    #[test]
    fn a_zero_length_entry_is_malformed() {
        let bytes = entry(0, 0, 0, 0);
        let err = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 0, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("zero length"), "{err}");
    }

    /// A crafted entry whose `offset + length` wraps u64.
    ///
    /// Before this was checked, such a map parsed `Ok` with a saturated size:
    /// `end()` clamped to `u64::MAX`, the gap and overlap checks reasoned about
    /// the clamped value, and the declared size — saturated the same way by the
    /// attacker — compared equal. Two impossible numbers matching is not a
    /// verification.
    #[test]
    fn an_entry_whose_extent_overflows_is_malformed() {
        let mut bytes = entry(0, 10, 0, 0);
        bytes.extend(entry(10, u64::MAX - 5, 0, 0));

        let declared = 10u64.saturating_add(u64::MAX - 5);
        let err =
            Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), declared, &locus()).unwrap_err();

        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("map entry 1"), "{err}");
        assert!(
            err.to_string().contains("cannot exist"),
            "the message must say the region is impossible: {err}"
        );
    }

    /// The single-entry form: one entry covering the whole address space and
    /// then some.
    #[test]
    fn a_single_overflowing_entry_is_malformed() {
        let bytes = entry(u64::MAX - 1, 100, 0, 0);
        let err =
            Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), u64::MAX, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// Entries that are each representable but sum past u64.
    ///
    /// Distinct from the case above: no single entry overflows, so the
    /// per-entry check passes and only the running total catches it.
    #[test]
    fn entries_totalling_past_u64_are_malformed() {
        let half = u64::MAX / 2;
        // Sorted and contiguous, so neither the gap nor the overlap check fires.
        let mut bytes = entry(0, half, 0, 0);
        bytes.extend(entry(half, half, 0, 0));
        bytes.extend(entry(half.saturating_mul(2), half, 0, 0));

        let err =
            Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), u64::MAX, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    /// `checked_end` is the validating form; `end` stays saturating for entries
    /// built directly, which parsing can no longer produce.
    #[test]
    fn checked_end_reports_overflow_where_end_clamps() {
        let overflowing = MapEntry {
            offset: u64::MAX - 1,
            length: 100,
            target_offset: 0,
            target_id: 0,
        };
        assert_eq!(overflowing.checked_end(), None);
        assert_eq!(overflowing.end(), u64::MAX);

        let ordinary = MapEntry {
            offset: 10,
            length: 32,
            target_offset: 0,
            target_id: 0,
        };
        assert_eq!(ordinary.checked_end(), Some(42));
        assert_eq!(ordinary.end(), 42);
    }

    #[test]
    fn an_empty_map_or_idx_is_malformed() {
        let bytes = entry(0, 32768, 0, 0);
        assert!(
            Map::parse(&arn("aff4://m"), &bytes, b"", 32768, &locus()).is_err(),
            "an empty idx must be refused"
        );
        assert!(
            Map::parse(&arn("aff4://m"), b"", IDX.as_bytes(), 0, &locus()).is_err(),
            "an empty map must be refused"
        );
    }

    /// Both vocabularies, standard and pre-standard.
    #[test]
    fn resolves_every_symbolic_form_in_the_corpus() {
        let cases = [
            ("http://aff4.org/Schema#Zero", Target::RepeatedByte(0x00)),
            (
                "http://aff4.org/Schema#SymbolicStreamFF",
                Target::RepeatedByte(0xFF),
            ),
            (
                "http://aff4.org/Schema#SymbolicStream61",
                Target::RepeatedByte(0x61),
            ),
            // Pre-standard spellings, measured in Base-Linear.af4.
            (
                "http://afflib.org/2009/aff4#Zero",
                Target::RepeatedByte(0x00),
            ),
            ("http://afflib.org/2009/aff4#FF", Target::RepeatedByte(0xFF)),
            (
                "http://afflib.org/2012/SymbolicStream#61",
                Target::RepeatedByte(0x61),
            ),
            (
                "http://aff4.org/Schema#UnknownData",
                Target::Unknown(UnknownKind::NotAcquired),
            ),
            (
                "http://aff4.org/Schema#UnreadableData",
                Target::Unknown(UnknownKind::Unreadable),
            ),
        ];

        for (text, expected) in cases {
            assert_eq!(Target::parse(text, &locus()), expected, "{text}");
        }
    }

    #[test]
    fn resolves_stored_stream_targets() {
        let target = Target::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus());
        match &target {
            Target::Stored(arn) => {
                assert_eq!(arn.as_str(), "aff4://c215ba20-5648-4209-a793-1f918c723610");
            }
            other => panic!("expected a stored target, got {other:?}"),
        }
        assert!(target.is_stored());
    }

    /// `broken-dedupe.aff4` names its targets by content, not by resource.
    /// Those are not ARNs and must be kept verbatim rather than guessed at.
    ///
    /// They now parse as [`Target::BlockHash`] rather than `Unrecognised`, so
    /// AFF4-L §4's second level can resolve them — but only when the graph
    /// actually says where the chunk lives. Absent that, the text is still kept
    /// verbatim and still refuses to produce bytes.
    #[test]
    fn content_addressed_targets_are_kept_verbatim() {
        let text = "aff4:sha512:932db9c759288cc7c6c0a3f9baad905cf405691e30fb0c0950f8e31634d33cf7";
        let target = Target::parse(text, &locus());
        assert_eq!(target, Target::BlockHash(text.to_owned()));
        assert_eq!(target.block_hash(), Some(text));
        // Not `Stored`: its bytes are unreachable until a dataStream resolves it.
        assert!(!target.is_stored());
        assert!(target.describe().contains(text));
    }

    #[test]
    fn unrecognised_targets_are_never_guessed() {
        for text in [
            "http://example.com/#Whatever",
            "http://aff4.org/Schema#SymbolicStreamZZ",
            "http://aff4.org/Schema#SymbolicStream123",
            "",
        ] {
            assert!(
                matches!(Target::parse(text, &locus()), Target::Unrecognised(_)),
                "{text} must not resolve"
            );
        }
    }

    /// Unknown regions carry defined placeholder content, but it is not
    /// recovered data — the distinction `describe()` must preserve.
    #[test]
    fn unknown_regions_are_described_as_unknown_not_as_data() {
        let not_acquired = Target::Unknown(UnknownKind::NotAcquired);
        assert_eq!(UnknownKind::NotAcquired.filler(), b"UNKNOWN");
        assert!(not_acquired.describe().contains("not acquired"));

        let unreadable = Target::Unknown(UnknownKind::Unreadable);
        assert_eq!(UnknownKind::Unreadable.filler(), b"UNREADABLEDATA");
        assert!(unreadable.describe().contains("could not be read"));

        // Neither reads as ordinary evidence.
        for target in [not_acquired, unreadable] {
            let text = target.describe();
            assert!(!text.contains("stored"), "{text}");
        }
    }

    /// Described runs must never be called fake, synthetic, empty, or missing.
    #[test]
    fn described_runs_are_not_called_fake_data() {
        let text = Target::RepeatedByte(0x00).describe();
        assert!(text.contains("described"), "{text}");
        for forbidden in ["fake", "synthetic", "empty", "missing"] {
            assert!(!text.contains(forbidden), "{text} must not say {forbidden}");
        }
    }

    /// The stored-versus-described split, in the proportions the corpus has.
    #[test]
    fn accounts_for_stored_against_described_bytes() {
        let mut bytes = entry(0, 32768, 0, 0); // stored
        bytes.extend(entry(32768, 262_144, 0, 1)); // Zero
        bytes.extend(entry(294_912, 32768, 0, 2)); // 0xFF

        let total = 32768 + 262_144 + 32768;
        let map = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), total, &locus()).unwrap();

        assert_eq!(map.stored_bytes(), 32768);
        assert_eq!(map.described_bytes(), 294_912);
        assert_eq!(map.stored_bytes() + map.described_bytes(), map.size());

        let by_target = map.bytes_by_target();
        assert_eq!(by_target.get(&0), Some(&32768));
        assert_eq!(by_target.get(&1), Some(&262_144));
        assert_eq!(by_target.get(&2), Some(&32768));
    }

    #[test]
    fn dependent_streams_are_distinct_and_stored_only() {
        let bytes = entry(0, 32768, 0, 0);
        let map = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 32768, &locus()).unwrap();

        let streams = map.dependent_streams();
        assert_eq!(streams.len(), 1, "only the one stored target counts");
        assert_eq!(
            streams[0].as_str(),
            "aff4://c215ba20-5648-4209-a793-1f918c723610"
        );
    }

    /// A stub source serving one stream from a byte slice.
    struct Fake {
        arn: String,
        data: Vec<u8>,
        /// How many times a region was requested, to catch a traversal that
        /// re-reads.
        calls: usize,
    }

    impl StreamSource for Fake {
        fn read_region(
            &mut self,
            stream: &Arn,
            offset: u64,
            length: u64,
            sink: &mut dyn FnMut(&[u8]) -> Result<()>,
            locus: &Locus,
        ) -> Result<()> {
            self.calls += 1;
            if stream.as_str() != self.arn {
                return Err(Error::malformed(locus.clone(), "unknown stream"));
            }
            let start = usize::try_from(offset).unwrap();
            let end = start + usize::try_from(length).unwrap();
            sink(&self.data[start..end])
        }
    }

    fn fake() -> Fake {
        Fake {
            arn: "aff4://c215ba20-5648-4209-a793-1f918c723610".to_owned(),
            // A recognisable pattern: byte n is n mod 251.
            data: (0..200_000u32).map(|i| (i % 251) as u8).collect(),
            calls: 0,
        }
    }

    /// Stored and described regions must interleave in address order, with the
    /// described bytes carrying the value their target names.
    #[test]
    fn reading_through_a_map_interleaves_stored_and_described_regions() {
        let mut bytes = entry(0, 100, 0, 0); // stored, from offset 0
        bytes.extend(entry(100, 50, 0, 1)); // Zero
        bytes.extend(entry(150, 30, 0, 2)); // 0xFF
        bytes.extend(entry(180, 20, 1000, 0)); // stored, from offset 1000

        let map = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 200, &locus()).unwrap();

        let mut source = fake();
        let mut out = Vec::new();
        let accounting = map
            .read_all(
                &mut source,
                &mut |b| {
                    out.extend_from_slice(b);
                    Ok(())
                },
                &locus(),
            )
            .unwrap();

        assert_eq!(out.len(), 200);
        assert_eq!(accounting.stored, 120);
        assert_eq!(accounting.described, 80);
        assert_eq!(accounting.total(), 200);

        // Region by region, against the fake's known pattern.
        assert_eq!(out[0..100], source.data[0..100]);
        assert!(out[100..150].iter().all(|b| *b == 0x00));
        assert!(out[150..180].iter().all(|b| *b == 0xFF));
        assert_eq!(out[180..200], source.data[1000..1020]);
    }

    /// A 262 MB run must not become a 262 MB allocation. Emitting through a
    /// fixed buffer is the whole reason a 256 MB image costs kilobytes.
    #[test]
    fn a_long_described_run_is_emitted_in_bounded_pieces() {
        let length = 300u64 * 1024 * 1024;
        let bytes = entry(0, length, 0, 1); // Zero
        let map = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), length, &locus()).unwrap();

        let mut largest = 0usize;
        let mut delivered = 0u64;
        let mut source = fake();

        map.read_all(
            &mut source,
            &mut |b| {
                largest = largest.max(b.len());
                delivered += b.len() as u64;
                assert!(b.iter().all(|x| *x == 0), "the run must be all zeroes");
                Ok(())
            },
            &locus(),
        )
        .unwrap();

        assert_eq!(delivered, length);
        assert_eq!(largest, RUN_BUFFER_LEN);
        assert_eq!(source.calls, 0, "a described run reads nothing");
    }

    /// A run shorter than the buffer must not over-deliver.
    #[test]
    fn a_short_described_run_delivers_exactly_its_length() {
        let bytes = entry(0, 7, 0, 2); // seven bytes of 0xFF
        let map = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 7, &locus()).unwrap();

        let mut out = Vec::new();
        map.read_all(
            &mut fake(),
            &mut |b| {
                out.extend_from_slice(b);
                Ok(())
            },
            &locus(),
        )
        .unwrap();

        assert_eq!(out, vec![0xFF; 7]);
    }

    /// An unrecognised target must stop the read. Filling the region in would
    /// produce a digest that looks authoritative and is wrong — the worst
    /// failure this module can have.
    #[test]
    fn an_unrecognised_target_refuses_to_produce_bytes() {
        let idx = "http://example.com/#NotAnythingWeKnow\n";
        let bytes = entry(0, 100, 0, 0);
        let map = Map::parse(&arn("aff4://m"), &bytes, idx.as_bytes(), 100, &locus()).unwrap();

        let mut delivered = 0usize;
        let err = map
            .read_all(
                &mut fake(),
                &mut |b| {
                    delivered += b.len();
                    Ok(())
                },
                &locus(),
            )
            .unwrap_err();

        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("does not recognise"), "{err}");
        assert_eq!(
            delivered, 0,
            "nothing may be delivered for a region we cannot produce"
        );
    }

    /// An **unresolved** block hash must refuse just as firmly.
    ///
    /// This is `broken-dedupe.aff4`'s exact shape: 437 content-addressed
    /// targets, none of which declares an `aff4:dataStream`. Recognising the
    /// syntax must never become a licence to invent the bytes.
    #[test]
    fn an_unresolved_block_hash_refuses_to_produce_bytes() {
        let idx = "aff4:sha512:932db9c759288cc7c6c0a3f9baad905c\n";
        let bytes = entry(0, 100, 0, 0);
        let map = Map::parse(&arn("aff4://m"), &bytes, idx.as_bytes(), 100, &locus()).unwrap();

        let mut delivered = 0usize;
        let err = map
            .read_all(
                &mut fake(),
                &mut |b| {
                    delivered += b.len();
                    Ok(())
                },
                &locus(),
            )
            .unwrap_err();

        assert!(err.is_integrity_finding(), "{err}");
        assert!(
            err.to_string().contains("no aff4:dataStream"),
            "the error must say why the chunk is unreachable: {err}"
        );
        assert_eq!(
            delivered, 0,
            "nothing may be delivered for a chunk we cannot locate"
        );
    }

    /// Spec p8: the placeholder repeats within 1 MiB blocks, truncated at the
    /// block boundary. The phase therefore depends on the offset within the
    /// block, not on where the read starts.
    #[test]
    fn unknown_regions_repeat_their_filler_within_one_mib_blocks() {
        let mut out = Vec::new();
        emit_unknown(UnknownKind::NotAcquired, 20, 0, &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(out, b"UNKNOWNUNKNOWNUNKNOWN"[..20].to_vec());

        // Starting part-way in keeps the phase: offset 3 of "UNKNOWN" is 'N'.
        let mut shifted = Vec::new();
        emit_unknown(UnknownKind::NotAcquired, 4, 3, &mut |b| {
            shifted.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(shifted, b"NOWN".to_vec());

        // The pattern restarts at each 1 MiB boundary. 1 MiB is not a multiple
        // of 7, so a naive `position % 7` would put the wrong byte here.
        let mut across = Vec::new();
        emit_unknown(UnknownKind::Unreadable, 2, 1024 * 1024 - 1, &mut |b| {
            across.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(across.len(), 2);
        assert_eq!(
            across[1], b'U',
            "the byte after a block boundary restarts the pattern"
        );
    }

    /// The placeholder is reproducible content, never recovered data — the
    /// accounting must keep it separate from both stored and described bytes.
    #[test]
    fn unknown_placeholder_bytes_are_accounted_separately() {
        let idx = "aff4://c215ba20-5648-4209-a793-1f918c723610\n\
                   http://aff4.org/Schema#UnreadableData\n";
        let mut bytes = entry(0, 10, 0, 0);
        bytes.extend(entry(10, 90, 0, 1));

        let map = Map::parse(&arn("aff4://m"), &bytes, idx.as_bytes(), 100, &locus()).unwrap();

        let accounting = map
            .read_all(&mut fake(), &mut |_| Ok(()), &locus())
            .unwrap();

        assert_eq!(accounting.stored, 10);
        assert_eq!(
            accounting.described, 0,
            "a placeholder is not a described run"
        );
        assert_eq!(accounting.unknown_placeholder, 90);
        assert_eq!(accounting.total(), 100);
    }

    /// A sink failure must propagate rather than being counted as success.
    #[test]
    fn a_sink_failure_stops_the_read() {
        let bytes = entry(0, 1000, 0, 1);
        let map = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 1000, &locus()).unwrap();

        let err = map
            .read_all(
                &mut fake(),
                &mut |_| Err(Error::malformed(locus(), "the sink refused")),
                &locus(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("the sink refused"), "{err}");
    }

    // --- Discontiguous maps (spec §4) -------------------------------------

    /// The default must stay strict. A contiguous image with a hole is a
    /// finding, and always was.
    #[test]
    fn a_gap_is_still_refused_by_default() {
        let mut bytes = entry(0, 32768, 0, 0);
        bytes.extend(entry(65536, 32768, 0, 0));

        let err =
            Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 98304, &locus()).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("uncovered"), "{err}");
    }

    /// Spec §5: a discontiguous map may leave holes, filled from the gap
    /// stream. The filled region becomes an ordinary entry, so the sorted view
    /// is gapless by construction.
    #[test]
    fn a_gap_is_filled_when_the_policy_allows_it() {
        let mut bytes = entry(0, 32768, 0, 0);
        // Skips 32768..65536.
        bytes.extend(entry(65536, 32768, 0, 0));

        let map = Map::parse_with(
            &arn("aff4://m"),
            &bytes,
            IDX.as_bytes(),
            98304,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap();

        assert_eq!(map.gaps().count, 1);
        assert_eq!(map.gaps().bytes, 32768);
        assert_eq!(map.size(), 98304);

        // Three entries now, contiguous from zero.
        assert_eq!(map.entries().len(), 3);
        let mut previous_end = 0;
        for entry in map.entries() {
            assert_eq!(entry.offset, previous_end, "the filled map must be gapless");
            previous_end = entry.end();
        }
        assert_eq!(previous_end, 98304);
    }

    /// The fill source is recorded, so a report can name it instead of saying
    /// "the gap stream".
    ///
    /// `declared` distinguishes a container that stated
    /// `aff4:mapGapDefaultStream` from one where spec §4's default applied.
    /// Reporting the default as though the container had declared it would
    /// attribute a claim it never made.
    #[test]
    fn a_filled_gap_records_what_filled_it() {
        let mut bytes = entry(0, 32768, 0, 0);
        bytes.extend(entry(65536, 32768, 0, 0));

        let undeclared = Map::parse_with(
            &arn("aff4://m"),
            &bytes,
            IDX.as_bytes(),
            98304,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap();
        let fill = undeclared
            .gaps()
            .fill
            .clone()
            .expect("a hole names its fill");
        assert_eq!(fill.name, "aff4:Zero");
        assert!(
            !fill.declared,
            "the §4 default is not the container's claim"
        );

        let declared = Map::parse_with(
            &arn("aff4://m"),
            &bytes,
            IDX.as_bytes(),
            98304,
            &GapPolicy::Fill(Target::RepeatedByte(0xFF), true),
            &locus(),
        )
        .unwrap();
        let fill = declared.gaps().fill.clone().expect("a hole names its fill");
        assert_eq!(fill.name, "aff4:FF");
        assert!(fill.declared);
    }

    /// A map whose only hole is a short tail still names its fill.
    ///
    /// The trailing gap is filled by a separate branch from the one inside the
    /// entry loop, so a container ending short would otherwise report gap bytes
    /// with nothing naming what covered them.
    #[test]
    fn a_trailing_only_gap_still_records_its_fill() {
        let map = Map::parse_with(
            &arn("aff4://m"),
            &entry(0, 32768, 0, 0),
            IDX.as_bytes(),
            65536,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap();
        assert_eq!(map.gaps().count, 1);
        assert_eq!(map.gaps().bytes, 32768);
        let fill = map
            .gaps()
            .fill
            .clone()
            .expect("a trailing hole names its fill");
        assert_eq!(fill.name, "aff4:Zero");
        assert!(!fill.declared);
    }

    /// A gapless map names no fill, so a report has nothing to print.
    #[test]
    fn a_gapless_map_records_no_fill() {
        let map = Map::parse_with(
            &arn("aff4://m"),
            &entry(0, 32768, 0, 0),
            IDX.as_bytes(),
            32768,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap();
        assert_eq!(map.gaps().count, 0);
        assert!(map.gaps().fill.is_none());
    }

    /// A hole at the end of the address space is still a hole. Without this it
    /// would fall through to the coverage check and be reported as a short map.
    #[test]
    fn a_trailing_gap_is_filled_rather_than_reported_as_short_coverage() {
        let bytes = entry(0, 32768, 0, 0);

        let map = Map::parse_with(
            &arn("aff4://m"),
            &bytes,
            IDX.as_bytes(),
            98304,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap();

        assert_eq!(map.gaps().count, 1);
        assert_eq!(map.gaps().bytes, 65536);
        assert_eq!(map.entries().len(), 2);
        assert_eq!(map.entries()[1].offset, 32768);
        assert_eq!(map.entries()[1].length, 65536);
    }

    /// **Overlaps stay fatal under every policy.** The spec gives an
    /// overlapping region no defined content, so there is nothing to fill it
    /// with and choosing something would be a fabrication.
    #[test]
    fn an_overlap_is_fatal_even_when_gaps_are_allowed() {
        let mut bytes = entry(0, 32768, 0, 0);
        bytes.extend(entry(16384, 32768, 0, 0));

        let err = Map::parse_with(
            &arn("aff4://m"),
            &bytes,
            IDX.as_bytes(),
            49152,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap_err();

        assert!(err.is_integrity_finding(), "{err}");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    /// Gap bytes must never be counted as described bytes. A described run was
    /// measured by the imager; a gap was never recorded at all.
    #[test]
    fn gap_bytes_are_accounted_apart_from_described_bytes() {
        let mut bytes = entry(0, 1000, 0, 0); // stored
        bytes.extend(entry(2000, 1000, 0, 1)); // Zero, a described run
        // Leaves 1000..2000 and 3000..4000 as holes.

        let map = Map::parse_with(
            &arn("aff4://m"),
            &bytes,
            IDX.as_bytes(),
            4000,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap();

        assert_eq!(map.gaps().count, 2);
        assert_eq!(map.gaps().bytes, 2000);
        assert_eq!(map.stored_bytes(), 1000);
        assert_eq!(
            map.described_bytes(),
            1000,
            "only the recorded Zero run is described; gaps are not"
        );

        let accounting = map
            .read_all(&mut fake(), &mut |_| Ok(()), &locus())
            .unwrap();

        assert_eq!(accounting.stored, 1000);
        assert_eq!(accounting.described, 1000);
        assert_eq!(accounting.gap_filled, 2000);
        assert_eq!(accounting.total(), 4000);
    }

    /// The filled bytes must be the gap stream's, and a non-default gap stream
    /// must be honoured rather than assumed to be Zero.
    #[test]
    fn filled_gaps_carry_the_gap_streams_byte() {
        let bytes = entry(0, 10, 0, 0);

        for (target, expected) in [
            (GapPolicy::spec_default(), 0x00u8),
            (GapPolicy::Fill(Target::RepeatedByte(0xFF), true), 0xFF),
        ] {
            let map = Map::parse_with(
                &arn("aff4://m"),
                &bytes,
                IDX.as_bytes(),
                20,
                &target,
                &locus(),
            )
            .unwrap();

            let mut out = Vec::new();
            map.read_all(
                &mut fake(),
                &mut |b| {
                    out.extend_from_slice(b);
                    Ok(())
                },
                &locus(),
            )
            .unwrap();

            assert_eq!(out.len(), 20);
            assert!(
                out[10..].iter().all(|b| *b == expected),
                "the gap must be filled with 0x{expected:02X}, got {:?}",
                &out[10..]
            );
        }
    }

    /// Spec §4's default is `aff4:Zero` when `mapGapDefaultStream` is unset.
    #[test]
    fn the_gap_stream_defaults_to_zero_per_spec() {
        // `false`: this is the standard's default applying, not the container
        // declaring anything. A report must be able to tell those apart.
        assert_eq!(
            GapPolicy::spec_default(),
            GapPolicy::Fill(Target::RepeatedByte(0x00), false)
        );
        assert_eq!(GapPolicy::default(), GapPolicy::Refuse);
    }

    /// A gapless map must be untouched: no synthesised target, no deviation,
    /// and the same entries it had before. Guards every canonical container.
    #[test]
    fn a_gapless_map_is_unchanged_by_an_allowing_policy() {
        let mut bytes = entry(0, 32768, 0, 0);
        bytes.extend(entry(32768, 32768, 0, 1));

        let strict = Map::parse(&arn("aff4://m"), &bytes, IDX.as_bytes(), 65536, &locus()).unwrap();
        let lenient = Map::parse_with(
            &arn("aff4://m"),
            &bytes,
            IDX.as_bytes(),
            65536,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap();

        assert_eq!(lenient.gaps().count, 0);
        assert_eq!(lenient.entries(), strict.entries());
        assert_eq!(
            lenient.targets().len(),
            strict.targets().len(),
            "no gap target may be appended to a map that has no gaps"
        );
    }

    /// `end()` must not panic on a directly-constructed entry.
    ///
    /// Saturation is the floor for an entry built in code, not a tolerance for
    /// parsed input: `Map::parse_with` refuses an overflowing entry outright,
    /// so no such entry reaches `end()` through a parsed map. See
    /// `an_entry_whose_extent_overflows_is_malformed`.
    #[test]
    fn entry_end_saturates_rather_than_overflowing() {
        let entry = MapEntry {
            offset: u64::MAX,
            length: u64::MAX,
            target_offset: 0,
            target_id: 0,
        };
        assert_eq!(entry.end(), u64::MAX);
        assert_eq!(entry.checked_end(), None);
    }
    /// A source for a map that stores nothing, so `read_all` needs no volume.
    struct NoStreams;

    impl StreamSource for NoStreams {
        fn read_region(
            &mut self,
            _stream: &Arn,
            _offset: u64,
            _length: u64,
            _sink: &mut dyn FnMut(&[u8]) -> Result<()>,
            _locus: &Locus,
        ) -> Result<()> {
            panic!("this map stores nothing");
        }
    }

    /// `emit_described` and `read_all` must produce identical bytes.
    ///
    /// The fused verification traversal reconstructs described runs through
    /// `emit_described` while the ordinary traversal reconstructs them inside
    /// `read_all`. Two code paths producing the bytes a digest is computed over
    /// is exactly the arrangement that drifts, so both are held against each
    /// other here: a symbolic run and an unknown-data run, the two forms a
    /// container actually carries.
    #[test]
    fn a_described_run_reconstructs_the_same_bytes_either_way() {
        // Entry 0 is symbolic FF (target 2), entry 1 is the same, so the map is
        // wholly described and `read_all` needs no stream source.
        let mut bytes = entry(0, 4096, 0, 2);
        bytes.extend(entry(4096, 4096, 4096, 2));

        let map = Map::parse_with(
            &arn("aff4://c215ba20-5648-4209-a793-1f918c723610/map"),
            &bytes,
            IDX.as_bytes(),
            8192,
            &GapPolicy::Refuse,
            &locus(),
        )
        .unwrap();

        let runs = map.runs(&locus()).unwrap();
        assert_eq!(runs.len(), 2, "both entries are described");
        assert!(runs.iter().all(|r| matches!(r, ImageRun::Described { .. })));

        // What the fused path produces, run by run.
        let mut fused: Vec<u8> = Vec::new();
        for run in &runs {
            let ImageRun::Described { position } = run else {
                panic!("every run here is described");
            };
            map.emit_described(
                *position,
                &mut |b| {
                    fused.extend_from_slice(b);
                    Ok(())
                },
                &locus(),
            )
            .unwrap();
        }

        // What the ordinary traversal produces.
        let mut ordinary: Vec<u8> = Vec::new();
        map.read_all(
            &mut NoStreams,
            &mut |b| {
                ordinary.extend_from_slice(b);
                Ok(())
            },
            &locus(),
        )
        .unwrap();

        assert_eq!(fused, ordinary, "the two paths must not drift");
        assert_eq!(fused.len(), 8192);
        assert!(fused.iter().all(|b| *b == 0xFF), "SymbolicStreamFF is 0xFF");
    }

    /// The entry covering an offset is found, and boundaries land on the later
    /// entry.
    ///
    /// Entries are sorted at parse time, so this is a binary search rather than
    /// a scan: `Base-Linear.aff4`'s map has 4103 entries, and a random-access
    /// read consults this on every call.
    #[test]
    fn entry_at_finds_the_covering_entry() {
        let mut bytes = entry(0, 32768, 0, 0);
        bytes.extend(entry(32768, 32768, 32768, 1));
        bytes.extend(entry(65536, 65536, 32768, 0));
        let map = Map::parse(
            &arn("aff4://c215ba20-5648-4209-a793-1f918c723610/map"),
            &bytes,
            IDX.as_bytes(),
            131_072,
            &locus(),
        )
        .unwrap();

        assert_eq!(map.entry_at(0).unwrap().offset, 0);
        assert_eq!(map.entry_at(32767).unwrap().offset, 0);
        // The boundary belongs to the entry that starts there, never the one
        // that ends there. Off by one here serves bytes from the wrong region.
        assert_eq!(map.entry_at(32768).unwrap().offset, 32768);
        assert_eq!(map.entry_at(65535).unwrap().offset, 32768);
        assert_eq!(map.entry_at(65536).unwrap().offset, 65536);
        assert_eq!(map.entry_at(131_071).unwrap().offset, 65536);
    }

    /// An offset at or past the declared size has no covering entry.
    #[test]
    fn entry_at_past_the_end_is_none() {
        let mut bytes = entry(0, 32768, 0, 0);
        bytes.extend(entry(32768, 32768, 32768, 1));
        let map = Map::parse(
            &arn("aff4://c215ba20-5648-4209-a793-1f918c723610/map"),
            &bytes,
            IDX.as_bytes(),
            65536,
            &locus(),
        )
        .unwrap();

        assert!(
            map.entry_at(65536).is_none(),
            "one past the end covers nothing"
        );
        assert!(map.entry_at(u64::MAX).is_none());
    }

    /// A filled hole is an ordinary entry, so it is found like any other.
    ///
    /// `GapPolicy::Fill` turns holes into entries at parse time, which is why
    /// `entry_at` needs no gap case: a parsed map is gapless by construction.
    /// The bytes still come from the declared filler rather than from storage.
    #[test]
    fn entry_at_finds_a_filled_hole() {
        let mut bytes = entry(0, 32768, 0, 0);
        // Leave 32768..65536 uncovered; the fill policy closes it.
        bytes.extend(entry(65536, 32768, 0, 1));
        let map = Map::parse_with(
            &arn("aff4://c215ba20-5648-4209-a793-1f918c723610/map"),
            &bytes,
            IDX.as_bytes(),
            98304,
            &GapPolicy::spec_default(),
            &locus(),
        )
        .unwrap();

        let filled = map.entry_at(40000).expect("a filled hole is an entry");
        assert!(filled.offset <= 40000 && 40000 < filled.end());
        assert!(map.gaps().count > 0, "the hole must be reported as a gap");
    }
}
