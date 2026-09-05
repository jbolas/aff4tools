//! The container summary and the domain types it is built from.
//!
//! [`ContainerSummary`] is what `aff4tools info` reports: the volume, its
//! generation, and every object described in `information.turtle`.
//!
//! # Three choices worth knowing
//!
//! **Every `rdf:type` is kept.** v1.0a §2.1 requires multiple types — a disk
//! image is `DiskImage` *and* `ContiguousImage` *and* `Image`. Collapsing to a
//! single "kind" would discard information the standard mandates, so
//! [`Aff4Object::types`] holds all of them and [`Aff4Object::role`] is a derived
//! convenience that never replaces the list.
//!
//! **Unmodelled properties are retained.** Whitelisting would hide exactly the
//! metadata an examiner wants: the pre-standard `ComputeResource` block carries
//! BIOS vendor, chassis serial, and ethernet address, none of which the standard
//! defines. Anything not otherwise modelled lands in [`Aff4Object::properties`].
//!
//! **Timestamps stay as lexical strings.** Parsing and reformatting a timestamp
//! that may be quoted in a report is a lossy conversion. The container's own
//! spelling is what gets reported.
//!
//! # Hashes are not verified
//!
//! Every [`StoredHash`] here was *read from the container*, never recomputed.
//! Feature 2 does no hashing at all. Rendering must make that unmistakable —
//! see [`StoredHash::PROVENANCE`].

use std::path::PathBuf;

use crate::arn::Arn;
use crate::error::Deviation;
use crate::lexicon::Generation;
use crate::rdf::Value;
use crate::version::ContainerVersion;
use crate::zip::ArnSource;

/// A complete summary of one container.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContainerSummary {
    /// The container's path on disk.
    pub source_path: PathBuf,
    /// The volume itself.
    pub volume: VolumeInfo,
    /// Which era of the format wrote it.
    pub generation: Generation,
    /// The declared version, or [`None`] for pre-standard containers.
    ///
    /// Absence is a fact about the container, not a gap to fill in.
    pub version: Option<ContainerVersion>,
    /// Every object described in the metadata, in first-appearance order.
    pub objects: Vec<Aff4Object>,
    /// Storage-layer counts.
    pub segments: SegmentSummary,
    /// Every departure from the standard observed while reading.
    pub deviations: Vec<Deviation>,
    /// `@prefix` bindings from the metadata, in declaration order.
    ///
    /// Carried so a report can render a vendor term as `bbt:APFSContainerImage`
    /// rather than stripping it to a bare local name, which would make an
    /// extension indistinguishable from a standard type.
    pub prefixes: Vec<(String, String)>,
    /// The ARNs the volume declares via `aff4:contains` — its own authoritative
    /// statement of what it holds. Empty when the predicate is absent, as it is
    /// on every pre-standard container observed so far.
    pub manifest: Vec<String>,
    /// Where the manifest disagrees with the objects this crate actually found.
    ///
    /// Empty for every canonical reference container: `aff4:contains` is meant
    /// to be authoritative, so a disagreement is a defect worth surfacing, not
    /// a condition to normalise away.
    pub manifest_disagreements: Vec<ManifestDisagreement>,
    /// How many objects of each role the container describes.
    ///
    /// Counted during the parse rather than derived from `objects`, so it stays
    /// correct when `objects` holds only a subset — which is what
    /// [`Container::summarize_brief`](crate::Container::summarize_brief) does on
    /// a container too large to hold whole.
    pub counts: ObjectCounts,
}

/// How many objects of each role a container describes.
///
/// Accumulated as each object is built, so a caller that discards the object
/// still knows what was there. `total` counts every described resource,
/// including roles with no field of their own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectCounts {
    /// Every object described in the metadata.
    pub total: usize,
    /// Objects whose role [`ObjectRole::is_image`] accepts.
    pub images: usize,
    /// `aff4:Map` objects.
    pub maps: usize,
    /// `aff4:ImageStream` objects.
    pub image_streams: usize,
    /// `aff4:FileImage` objects — an AFF4-L file entry.
    pub files: usize,
    /// `aff4:FolderImage` objects.
    pub folders: usize,
    /// Objects the `Bitstream` section could show: an image-like role or an
    /// `ImageStream`, carrying a `hash` or `blockMapHash`.
    ///
    /// Counted during the parse so `--brief` can say how many it is not
    /// showing, even though it retains only a capped sample of them.
    pub bitstream_candidates: usize,
}

impl ObjectCounts {
    /// Count one object.
    ///
    /// `bitstream_candidate` is whether the `Bitstream` section could show it —
    /// the caller tests for a qualifying hash, which this type does not see.
    pub fn observe(&mut self, role: &ObjectRole, bitstream_candidate: bool) {
        self.total += 1;
        if role.is_image() {
            self.images += 1;
        }
        if bitstream_candidate && (role.is_image() || matches!(role, ObjectRole::ImageStream)) {
            self.bitstream_candidates += 1;
        }
        match role {
            ObjectRole::Map => self.maps += 1,
            ObjectRole::ImageStream => self.image_streams += 1,
            ObjectRole::FileImage => self.files += 1,
            ObjectRole::FolderImage => self.folders += 1,
            _ => {}
        }
    }
}

impl ContainerSummary {
    /// Objects whose role is an image of some kind.
    #[must_use]
    pub fn images(&self) -> Vec<&Aff4Object> {
        self.objects.iter().filter(|o| o.role.is_image()).collect()
    }

    /// Objects with the given role.
    #[must_use]
    pub fn with_role(&self, role: &ObjectRole) -> Vec<&Aff4Object> {
        self.objects.iter().filter(|o| &o.role == role).collect()
    }

    /// Whether anything departed from the standard.
    ///
    /// Every deviation counts, routine or not. For the narrower question
    /// `--strict` asks, use [`ContainerSummary::has_noteworthy_deviation`].
    #[must_use]
    pub fn is_conformant(&self) -> bool {
        self.deviations.is_empty()
    }

    /// Whether any deviation is one the format does not routinely produce.
    ///
    /// This is what `--strict` tests. It is deliberately not the negation of
    /// [`ContainerSummary::is_conformant`]: a lone stripe of a striped set
    /// always carries an `ExternalReference`, so failing on it would make the
    /// exit code fire on well-formed containers and stay silent about nothing.
    /// See [`crate::DeviationKind::is_routine`].
    #[must_use]
    pub fn has_noteworthy_deviation(&self) -> bool {
        has_noteworthy_deviation(&self.deviations)
    }
}

/// Whether any deviation in `deviations` is one `--strict` should fail on.
///
/// Free-standing as well as a method, so `conformance` — which collects
/// deviations without building a summary — asks the identical question rather
/// than a copy of it.
#[must_use]
pub fn has_noteworthy_deviation(deviations: &[Deviation]) -> bool {
    deviations.iter().any(|d| !d.kind.is_routine())
}

/// The volume the summary describes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VolumeInfo {
    /// The volume ARN.
    pub arn: Arn,
    /// Where that ARN was found (v1.0a §5.4 allows two locations).
    pub arn_source: ArnSource,
}

/// One ARN where the volume's `aff4:contains` manifest and the objects this
/// crate found disagree.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ManifestDisagreement {
    /// The ARN involved.
    pub arn: String,
    /// How the manifest and the found objects disagree about it.
    pub kind: ManifestIssue,
}

/// The two ways a manifest can disagree with what was actually found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestIssue {
    /// The volume declares this ARN via `aff4:contains`, but no object in this
    /// volume describes it.
    DeclaredButAbsent,
    /// An object local to this volume is described here, but the volume's
    /// `aff4:contains` never names it.
    PresentButUndeclared,
}

/// Storage-layer counts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SegmentSummary {
    /// Number of ZIP members.
    pub count: usize,
    /// How those members break down by kind, most numerous first.
    ///
    /// Counts of *storage* units, not of evidence: one image stream is spread
    /// across thousands of bevies, so a large `BevyData` count describes how
    /// the container is packed, not how much was acquired.
    pub kinds: Vec<SegmentKindCount>,
}

/// One row of the segment breakdown.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SegmentKindCount {
    /// What the segments in this row are.
    pub kind: SegmentKind,
    /// How many members fall into it.
    pub count: usize,
    /// What the row's members are called, without their ARN path.
    ///
    /// For counted kinds this is the alphanumerically last member — bevies are
    /// numbered from zero, so the last one shows how far the sequence runs.
    /// For [`SegmentKind::MapStructure`] it is every member, comma-separated:
    /// `map`, `idx`, and `mapPath` are three different things.
    pub example: String,
}

/// What role a ZIP member plays in the container.
///
/// Classified from the segment *name*, which is the only thing the storage
/// layer knows. The metadata's view of the same objects is reported separately;
/// a name-based kind is a statement about layout, not about declared type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    /// A bevy: one chunked, compressed run of image-stream data (v1.0a §4).
    BevyData,
    /// A bevy's chunk index, giving each chunk's offset and length.
    ///
    /// Named `<bevy>.index` in Standard containers and `<bevy>/index` in
    /// pre-standard ones, which store each bevy as a folder.
    BevyIndex,
    /// Per-chunk block hashes stored beside a bevy (v1.0a §6, optional).
    BlockHash,
    /// A map's entry table (`map`), target list (`idx`), or path list
    /// (`mapPath`) — the virtual address space over other streams.
    MapStructure,
    /// `information.turtle`, the RDF metadata describing every object.
    Metadata,
    /// `container.description`, carrying the volume ARN (v1.0a §5.4).
    ContainerDescription,
    /// `version.txt`, absent in pre-standard containers.
    Version,
    /// A stored logical file (AFF4-L), named by its original path.
    LogicalFile,
    /// A member whose name matches no known AFF4 convention.
    ///
    /// Reported rather than hidden: an unrecognised member in evidence is
    /// something the examiner should see.
    Other,
}

impl SegmentKind {
    /// A short label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BevyData => "bevy data",
            Self::BevyIndex => "bevy index",
            Self::BlockHash => "block hashes",
            Self::MapStructure => "map structure",
            Self::Metadata => "information.turtle",
            Self::ContainerDescription => "container.description",
            Self::Version => "version.txt",
            Self::LogicalFile => "logical file",
            Self::Other => "other",
        }
    }
}

/// One object described in `information.turtle`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Aff4Object {
    /// The object's ARN.
    pub arn: Arn,
    /// Every `rdf:type`, in the order declared (v1.0a §2.1 requires multiple).
    ///
    /// `Arc<str>` rather than `String`: a container's type IRIs are drawn from
    /// a handful of distinct values — 1,208,001 occurrences across **6**
    /// distinct IRIs on a 404,000-object AFF4-L container — so one shared
    /// allocation per distinct value replaces one per occurrence. See
    /// `container::Interner`.
    pub types: Vec<std::sync::Arc<str>>,
    /// The most specific role implied by `types`.
    pub role: ObjectRole,
    /// `aff4:size`, where declared.
    pub size: Option<u64>,
    /// Digests read from the metadata. **Never computed** — see [`StoredHash`].
    pub hashes: Vec<StoredHash>,
    /// The volume this object is stored in, from `aff4:stored`.
    pub stored_in: Option<String>,
    /// Whether the object lives in this volume or another one.
    pub locality: Locality,
    /// Every property not modelled above, in declaration order.
    pub properties: Vec<Property>,
    /// Graph edges this object asserts, in declaration order.
    ///
    /// One entry per **object value**, not per predicate or per statement
    /// line: `aff4:dependentStream <a> , <b> ;` is a single Turtle statement
    /// naming two values, and a striped map's `dependentStream` genuinely
    /// carries one edge per stripe. Collapsing them would silently drop a
    /// dependency the examiner needs.
    pub edges: Vec<GraphEdge>,
    /// For a [`ObjectRole::BlockHashes`] object, what the per-chunk hashes it
    /// holds are — inferred, never container-stated. [`None`] for every other
    /// role.
    ///
    /// Present in JSON only when meaningful
    /// (`#[serde(skip_serializing_if = "Option::is_none")]`), so a consumer
    /// checking for it does not have to special-case every non-`BlockHashes`
    /// object printing `"block_hashes": null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hashes: Option<BlockHashesInfo>,
}

impl Aff4Object {
    /// The value of a property by its local name, if present.
    #[must_use]
    pub fn property(&self, local_name: &str) -> Option<&Property> {
        self.properties.iter().find(|p| &*p.name == local_name)
    }
}

/// What a [`ObjectRole::BlockHashes`] object's per-chunk digests are, and
/// where that fact came from.
///
/// the segment's own `aff4:hash` (on
/// [`Aff4Object::hashes`]) is a digest *of the segment as a whole*, computed
/// with whatever algorithm `blockHashesHash` names — SHA-512 in every corpus
/// fixture. It says nothing about the algorithm of the per-block hashes
/// *inside* that segment, which no triple in the container states. The only
/// place that algorithm is recorded at all is the segment's own ARN suffix
/// (`blockhash.md5`, `.sha1`, `.sha256`, `.blake2b`, `.sha512`) — this crate's
/// own inference from the *name* of a resource, not a fact the container
/// asserts. [`BlockHashesInfo::content_algorithm_source`] carries that
/// provenance explicitly so JSON can never present an inferred value as a
/// container-stated one — see [`StoredHash::PROVENANCE`] for the parallel
/// rule on digests that *are* container-stated but never verified.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockHashesInfo {
    /// The algorithm the per-block hashes use, read from the ARN suffix.
    /// [`None`] when the suffix is absent or unrecognized — never guessed.
    pub content_algorithm: Option<String>,
    /// Always `"arn_suffix"`: names where [`BlockHashesInfo::content_algorithm`]
    /// came from, so it is never mistaken for something the container itself
    /// declared. A fixed value today, kept as a field rather than a comment so
    /// a future second source (were the container ever to state this
    /// directly) has somewhere to be distinguished.
    pub content_algorithm_source: &'static str,
    /// The ARN of the stream this `BlockHashes` object describes (its ARN
    /// parent), where determinable.
    pub of_stream: Option<String>,
}

impl Aff4Object {
    /// [`BlockHashesInfo`] for this object, if its role is
    /// [`ObjectRole::BlockHashes`]. [`None`] for every other role — this is
    /// not a general ARN-parent lookup.
    #[must_use]
    pub fn block_hashes_info(&self) -> Option<BlockHashesInfo> {
        if self.role != ObjectRole::BlockHashes {
            return None;
        }
        Some(BlockHashesInfo {
            content_algorithm: block_hash_content_algorithm(self.arn.as_str())
                .map(ToOwned::to_owned),
            content_algorithm_source: "arn_suffix",
            of_stream: self
                .arn
                .as_str()
                .rsplit_once('/')
                .map(|(parent, _)| parent.to_owned()),
        })
    }
}

/// The content algorithm a `BlockHashes` ARN's suffix names, e.g.
/// `.../blockhash.md5` → `"MD5"`. Standard names the segment
/// `blockhash.<alg>`; pre-standard's equivalent (`blockHash.<alg>`) is not a
/// described object in that generation, so this only ever fires on
/// Standard-generation fixtures — confirmed against the corpus.
///
/// Shared by [`Aff4Object::block_hashes_info`] (JSON) and `report.rs`'s
/// `write_block_hashes_header` (text), so the two surfaces cannot drift on
/// which suffixes are recognized.
#[must_use]
pub fn block_hash_content_algorithm(arn: &str) -> Option<&'static str> {
    let suffix = arn.rsplit_once('.')?.1;
    Some(match suffix.to_ascii_lowercase().as_str() {
        "md5" => "MD5",
        "sha1" => "SHA-1",
        "sha256" => "SHA-256",
        "sha512" => "SHA-512",
        "blake2b" => "Blake2b",
        _ => return None,
    })
}

/// One edge in the object graph: this object, via [`EdgeKind`], to `to`.
///
/// An edge is a fact about *this* object's own statements — the graph is
/// directed, and an edge is recorded once, on the subject that asserts it. A
/// later rendering pass follows edges to draw both the data path (image →
/// map → stream) and metadata attribution (case notes → disk image) without
/// re-deriving either from the raw predicate list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GraphEdge {
    /// What relationship this edge represents.
    ///
    /// `#[serde(flatten)]`: [`EdgeKind`] already serializes as
    /// `{"kind": ..., "predicate": ...}` (an internally tagged enum, matching
    /// this crate's convention for a closed-with-an-escape-hatch enum — see
    /// `rdf::Value` and `zip_volume_set::VolumeOrigin`). Without `flatten`
    /// that shape would nest under this field's own name, producing
    /// `{"kind": {"kind": "storedIn"}, ...}` — a Rust field name doubling the
    /// enum's own tag key. Flattening puts `kind` and `predicate` directly on
    /// the edge object instead.
    #[serde(flatten)]
    pub kind: EdgeKind,
    /// The ARN this edge points to. May name a symbolic stream
    /// (`aff4://.../SymbolicStreamXX`, `aff4:Zero`, `aff4:UnknownData`,
    /// `aff4:UnreadableData`) described by the standard rather than by any
    /// triple in this container.
    pub to: String,
}

/// What kind of relationship a [`GraphEdge`] represents.
///
/// `target` is not a single kind here: the same predicate asserts two
/// structurally different relationships depending on who asserts it (Task
/// the asserting type). A metadata object (`CaseNotes`,
/// `CaseDetails`, `TimeStamps`, `Tool`) uses `target` to attribute itself to
/// an image — that is [`EdgeKind::Describes`]. A data object — `Map`,
/// `ImageStream`, or pre-standard's `stream` — uses the same predicate as
/// part of the image → map → stream data path; that use is
/// [`EdgeKind::TargetStream`], deliberately **not** folded into `Describes`,
/// since doing so would let a reader following `Describes` edges mistake
/// data-path membership for case/administrative attribution. It is also
/// deliberately **not** folded into [`EdgeKind::Other`]: a data-path `target`
/// is a modelled relationship this crate has a name for, and rendering it as
/// the bare predicate name is exactly the defect reported.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "predicate", rename_all = "camelCase")]
pub enum EdgeKind {
    /// `aff4:target`, asserted by a metadata object (case notes, case
    /// details, timestamps, or acquisition-tool details) about the image it
    /// describes. Not used for the image → map → stream data path — see
    /// [`EdgeKind::TargetStream`] and the type-level documentation.
    Describes,
    /// `aff4:dataStream`, asserted by an image naming the map or stream that
    /// backs it.
    DataStream,
    /// `aff4:dependentStream`, asserted by a map naming a stream it reads
    /// from. Multi-valued: a striped map carries one per stripe.
    DependentStream,
    /// `aff4:target`, asserted by a data object (`Map`, `ImageStream`, or
    /// pre-standard's `stream`) rather than a metadata object. This object's
    /// content is drawn from, or is a view onto, the object it targets — the
    /// same relationship `dataStream`/`dependentStream` express on other
    /// generations, spelled with `target` instead. Not [`EdgeKind::Describes`]:
    /// see the type-level documentation for why the two must stay distinct.
    TargetStream,
    /// `aff4:stored`, asserted by any object naming the volume holding it.
    StoredIn,
    /// A predicate this build does not name specially, kept verbatim so an
    /// edge is recorded rather than dropped — for example
    /// `mapGapDefaultStream`, which the corpus shows on nearly every
    /// Standard-generation map.
    Other(String),
}

impl EdgeKind {
    /// The human phrase a report prints for this edge kind — never the
    /// predicate name, which stays available on [`GraphEdge`] via the
    /// object's `properties` for a reader checking against the turtle.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Describes => "describes",
            Self::DataStream => "assembled by",
            Self::DependentStream => "reads bytes from",
            Self::TargetStream => "draws data from",
            Self::StoredIn => "stored in",
            Self::Other(name) => name,
        }
    }
}

/// A property this crate does not model explicitly.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Property {
    /// The predicate's local name, e.g. `diskSerial`.
    ///
    /// Interned: 4,424,000 occurrences across **11** distinct names on a
    /// 404,000-object container.
    pub name: std::sync::Arc<str>,
    /// The full predicate IRI.
    pub iri: std::sync::Arc<str>,
    /// The value.
    pub value: Value,
    /// The bound prefix for this predicate's namespace, e.g. `bbt`.
    ///
    /// [`None`] for the AFF4 namespace, which needs no qualifying. A value here
    /// means the property is a **vendor extension** — legitimate under RDF, but
    /// something an examiner should see labelled rather than mixed in with
    /// standard terms.
    pub prefix: Option<std::sync::Arc<str>>,
    /// The namespace IRI this predicate belongs to.
    ///
    /// Interned alongside `prefix`: a vendor namespace repeats once per
    /// property that uses it.
    pub namespace: Option<std::sync::Arc<str>>,
}

impl Property {
    /// Whether this property comes from outside the AFF4 vocabulary.
    #[must_use]
    pub fn is_vendor(&self) -> bool {
        self.prefix.is_some()
    }
}

/// Whether an object's data lives in the container being summarised.
///
/// Unit-only, so `rename_all` alone gives a plain lowercase string
/// (`"local"`, `"external"`, `"undeclared"`) with no tag wrapper needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Locality {
    /// Stored in this volume.
    Local,
    /// Stored in another volume — normal for one stripe of a striped container,
    /// where a stream legitimately lives in a sibling file. Not an error.
    External,
    /// No `aff4:stored` property, so the location is not declared.
    ///
    /// Also the state of purely virtual objects such as the `BlockHashes`
    /// concatenation URI (v1.0a §6.2), which names no stored segment by design.
    Undeclared,
}

/// What kind of thing an object is.
///
/// Derived from [`Aff4Object::types`] by most-specific-wins. A convenience for
/// grouping output; the full type list remains authoritative.
///
/// Serializes as a **bare string**, not a wrapper object — see
/// [`ObjectRole::json_token`] for the exact rule and why. Deriving with
/// `#[serde(tag = "kind", content = "name")]` would wrap every payload-free
/// variant in `{"kind": "..."}` to accommodate the one variant (`Other`) that
/// carries data. A hand-written `Serialize` (matching
/// [`HashAlgorithm`]'s approach) gives every variant a plain string instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectRole {
    /// A disk image (v1.0a §2.1).
    DiskImage,
    /// A contiguous image that is not declared a disk image.
    ContiguousImage,
    /// An image whose map may leave holes (v1.0a §4).
    ///
    /// **Not a Standard v1.0 type.** Occurs in aff4-cpp-lite.
    DiscontiguousImage,
    /// An image with no more specific type.
    Image,
    /// A logical file image (AFF4-L, v1.1).
    FileImage,
    /// A logical folder (AFF4-L, v1.1).
    FolderImage,
    /// A chunked data stream.
    ImageStream,
    /// A virtual address space over other streams.
    Map,
    /// The concatenation of per-chunk hashes (v1.0a §6.2).
    BlockHashes,
    /// Case details or notes.
    CaseInfo,
    /// Acquisition timestamps.
    TimeStamps,
    /// The volume itself.
    Volume,
    /// Anything else, keeping the declared type's local name.
    Other(String),
}

impl ObjectRole {
    /// Pick the most specific role from a list of type IRIs.
    ///
    /// Order matters: a disk image declares three types, and the most specific
    /// is the useful one to show.
    #[must_use]
    pub fn from_types<S: AsRef<str>>(types: &[S]) -> Self {
        let local = |iri: &str| {
            iri.rsplit_once(['#', '/'])
                .map_or(iri, |(_, name)| name)
                .to_string()
        };
        let names: Vec<String> = types.iter().map(|t| local(t.as_ref())).collect();
        let has = |name: &str| names.iter().any(|n| n == name);

        // Most specific first.
        if has("DiskImage") {
            Self::DiskImage
        } else if has("FileImage") {
            Self::FileImage
        } else if has("FolderImage") {
            Self::FolderImage
        } else if has("DiscontiguousImage") {
            Self::DiscontiguousImage
        } else if has("ContiguousImage") {
            Self::ContiguousImage
        } else if has("ImageStream") || has("stream") {
            Self::ImageStream
        } else if has("Map") || has("map") || has("QueryMap") {
            Self::Map
        } else if has("BlockHashes") {
            Self::BlockHashes
        } else if has("CaseDetails") || has("CaseNotes") || has("caseNotes") {
            Self::CaseInfo
        } else if has("TimeStamps") {
            Self::TimeStamps
        } else if has("ZipVolume") || has("zip_volume") || has("Volume") {
            Self::Volume
        } else if has("Image") {
            Self::Image
        } else {
            Self::Other(names.first().cloned().unwrap_or_else(|| "unknown".into()))
        }
    }

    /// Whether this role is an image of some kind.
    #[must_use]
    pub fn is_image(&self) -> bool {
        matches!(
            self,
            Self::DiskImage
                | Self::ContiguousImage
                | Self::DiscontiguousImage
                | Self::Image
                | Self::FileImage
                | Self::FolderImage
        )
    }

    /// A short label for output.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::DiskImage => "disk image",
            Self::ContiguousImage => "contiguous image",
            Self::DiscontiguousImage => "discontiguous image",
            Self::Image => "image",
            Self::FileImage => "file image",
            Self::FolderImage => "folder",
            Self::ImageStream => "image stream",
            Self::Map => "map",
            Self::BlockHashes => "block hashes",
            Self::CaseInfo => "case info",
            Self::TimeStamps => "timestamps",
            Self::Volume => "volume",
            Self::Other(name) => name,
        }
    }

    /// The stable machine token this role serializes as — a `snake_case`
    /// string for every named variant (`"disk_image"`, `"image_stream"`,
    /// ...), deliberately distinct from [`ObjectRole::label`]'s prose
    /// (`"disk image"`, spaced, for text output).
    ///
    /// `Other(name)` serializes as `"other:{name}"` rather than `name` bare.
    /// A bare passthrough would let an unrecognized declared type collide
    /// with a known token — nothing stops a vendor extension from being
    /// named literally `Volume` or `DiskImage` in its own namespace, and a
    /// bare string can't tell that collision apart from the real thing. The
    /// `other:` prefix keeps every unrecognized role in its own namespace of
    /// tokens, unambiguously: `"other:SomethingNovel"` can never equal
    /// `"disk_image"` no matter what a container declares.
    #[must_use]
    pub fn json_token(&self) -> std::borrow::Cow<'_, str> {
        let named = match self {
            Self::DiskImage => "disk_image",
            Self::ContiguousImage => "contiguous_image",
            Self::DiscontiguousImage => "discontiguous_image",
            Self::Image => "image",
            Self::FileImage => "file_image",
            Self::FolderImage => "folder_image",
            Self::ImageStream => "image_stream",
            Self::Map => "map",
            Self::BlockHashes => "block_hashes",
            Self::CaseInfo => "case_info",
            Self::TimeStamps => "time_stamps",
            Self::Volume => "volume",
            Self::Other(name) => return std::borrow::Cow::Owned(format!("other:{name}")),
        };
        std::borrow::Cow::Borrowed(named)
    }
}

impl serde::Serialize for ObjectRole {
    /// Serializes as [`ObjectRole::json_token`] — a bare string, not a
    /// wrapper object. See the type's doc comment for why this is a
    /// hand-written impl rather than a derive.
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.json_token())
    }
}

impl std::fmt::Display for ObjectRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A digest read from container metadata.
///
/// **Read, never computed.** aff4tools does no hashing in this feature, so a
/// value here says only what the acquiring tool recorded. Rendering must carry
/// [`StoredHash::PROVENANCE`] so a summary can never be mistaken for
/// verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StoredHash {
    /// Which algorithm the metadata declared.
    pub algorithm: HashAlgorithm,
    /// The digest, exactly as written. Never truncated for display.
    pub hex: String,
    /// The predicate this came from, e.g. `hash` or `blockMapHash`.
    pub predicate: String,
}

impl StoredHash {
    /// The marker every rendered hash must carry.
    ///
    /// These digests were recorded at acquisition time by the imaging tool.
    /// aff4tools has not recomputed them.
    pub const PROVENANCE: &'static str = "[acquisition hash]";

    /// Whether the digest's length matches its declared algorithm.
    ///
    /// A mismatch is worth surfacing: a 32-character value typed `aff4:SHA1`
    /// means the metadata is internally inconsistent.
    #[must_use]
    pub fn length_matches_algorithm(&self) -> bool {
        self.algorithm
            .hex_length()
            .is_none_or(|expected| self.hex.len() == expected)
    }
}

/// A digest algorithm named by an AFF4 datatype IRI.
///
/// Serializes as the plain string [`HashAlgorithm::name`] already renders for
/// text output (`"MD5"`, `"SHA512"`, `"blockMapHashSHA512"`, or the raw
/// `Other` string) rather than a derived `{"Md5": null}`/`{"Other": "SHA3"}`
/// shape — one documented vocabulary, not a second one that has to be kept in
/// sync with the text report by hand. A hand-written `Serialize` impl is used
/// instead of a `#[serde(rename = ...)]` list because the two forms would
/// otherwise drift (e.g. `Md5` renamed to `"MD5"` here but `name()` printing
/// `"MD5"` too — the same string, maintained in two places).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// MD5, 128-bit.
    Md5,
    /// SHA-1, 160-bit.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
    /// Blake2b, 512-bit.
    Blake2b,
    /// The composite block-map hash (v1.0a §6.2), SHA-512 flavour.
    BlockMapSha512,
    /// The composite block-map hash, SHA-256 flavour.
    BlockMapSha256,
    /// A datatype this build does not recognise, kept verbatim.
    Other(String),
}

impl HashAlgorithm {
    /// Identify an algorithm from its datatype IRI.
    #[must_use]
    pub fn from_datatype(iri: &str) -> Self {
        let local = iri.rsplit_once(['#', '/']).map_or(iri, |(_, name)| name);
        match local {
            "MD5" => Self::Md5,
            "SHA1" => Self::Sha1,
            "SHA256" => Self::Sha256,
            "SHA512" => Self::Sha512,
            "blake2b" | "Blake2b" => Self::Blake2b,
            "blockMapHashSHA512" => Self::BlockMapSha512,
            "blockMapHashSHA256" => Self::BlockMapSha256,
            other => Self::Other(other.to_string()),
        }
    }

    /// Expected hex-string length, or [`None`] for an unrecognised algorithm.
    #[must_use]
    pub fn hex_length(&self) -> Option<usize> {
        match self {
            Self::Md5 => Some(32),
            Self::Sha1 => Some(40),
            Self::Sha256 | Self::BlockMapSha256 => Some(64),
            Self::Sha512 | Self::Blake2b | Self::BlockMapSha512 => Some(128),
            Self::Other(_) => None,
        }
    }

    /// A short name for output.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
            Self::Blake2b => "Blake2b",
            Self::BlockMapSha512 => "blockMapHashSHA512",
            Self::BlockMapSha256 => "blockMapHashSHA256",
            Self::Other(name) => name,
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl serde::Serialize for HashAlgorithm {
    /// Serializes as [`HashAlgorithm::name`] — see the type's doc comment for
    /// why this is a hand-written impl rather than a derive.
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.name())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn types(names: &[&str]) -> Vec<String> {
        names
            .iter()
            .map(|n| format!("http://aff4.org/Schema#{n}"))
            .collect()
    }

    /// v1.0a §2.1: a disk image declares three types. The most specific is what
    /// a reader wants to see, but all three are retained elsewhere.
    #[test]
    fn picks_the_most_specific_role() {
        let role = ObjectRole::from_types(&types(&["ContiguousImage", "DiskImage", "Image"]));
        assert_eq!(role, ObjectRole::DiskImage);
        assert!(role.is_image());
    }

    #[test]
    fn recognises_logical_image_roles() {
        assert_eq!(
            ObjectRole::from_types(&types(&["FileImage", "Image", "zip_segment"])),
            ObjectRole::FileImage
        );
        assert_eq!(
            ObjectRole::from_types(&types(&["FolderImage"])),
            ObjectRole::FolderImage
        );
    }

    /// Pre-standard containers lowercase their class names.
    #[test]
    fn recognises_pre_standard_class_names() {
        let legacy = |n: &str| vec![format!("http://afflib.org/2009/aff4#{n}")];
        assert_eq!(
            ObjectRole::from_types(&legacy("stream")),
            ObjectRole::ImageStream
        );
        assert_eq!(ObjectRole::from_types(&legacy("map")), ObjectRole::Map);
        assert_eq!(
            ObjectRole::from_types(&legacy("zip_volume")),
            ObjectRole::Volume
        );
        assert_eq!(
            ObjectRole::from_types(&legacy("caseNotes")),
            ObjectRole::CaseInfo
        );
    }

    #[test]
    fn recognises_a_discontiguous_image() {
        let role = ObjectRole::from_types(&[
            "http://aff4.org/Schema#DiscontiguousImage".to_owned(),
            "http://aff4.org/Schema#Image".to_owned(),
            "https://blackbagtech.com/aff4/Schema#APFSContainerImage".to_owned(),
        ]);

        assert_eq!(role, ObjectRole::DiscontiguousImage);
        assert!(role.is_image());
        assert_eq!(role.label(), "discontiguous image");
        assert_ne!(
            role,
            ObjectRole::Image,
            "the generic Image arm must not swallow it"
        );
    }

    #[test]
    fn keeps_unknown_types_verbatim() {
        let role = ObjectRole::from_types(&types(&["SomethingNovel"]));
        assert_eq!(role, ObjectRole::Other("SomethingNovel".into()));
        assert!(!role.is_image());
        assert_eq!(role.label(), "SomethingNovel");
    }

    #[test]
    fn an_untyped_object_has_a_role() {
        assert_eq!(
            ObjectRole::from_types::<&str>(&[]),
            ObjectRole::Other("unknown".into())
        );
    }

    #[test]
    fn identifies_hash_algorithms_from_datatypes() {
        for (iri, expected, len) in [
            ("http://aff4.org/Schema#MD5", HashAlgorithm::Md5, 32),
            ("http://aff4.org/Schema#SHA1", HashAlgorithm::Sha1, 40),
            ("http://aff4.org/Schema#SHA256", HashAlgorithm::Sha256, 64),
            ("http://aff4.org/Schema#SHA512", HashAlgorithm::Sha512, 128),
            (
                "http://aff4.org/Schema#blockMapHashSHA512",
                HashAlgorithm::BlockMapSha512,
                128,
            ),
        ] {
            let algo = HashAlgorithm::from_datatype(iri);
            assert_eq!(algo, expected);
            assert_eq!(algo.hex_length(), Some(len));
        }
    }

    #[test]
    fn keeps_unknown_hash_datatypes() {
        let algo = HashAlgorithm::from_datatype("http://aff4.org/Schema#SHA3");
        assert_eq!(algo, HashAlgorithm::Other("SHA3".into()));
        assert_eq!(algo.hex_length(), None);
    }

    /// A digest whose length contradicts its declared algorithm means the
    /// metadata is internally inconsistent — worth surfacing.
    #[test]
    fn detects_a_digest_length_mismatch() {
        // The real SHA1 from Base-Linear.aff4: 40 characters.
        let good = StoredHash {
            algorithm: HashAlgorithm::Sha1,
            hex: "fbac22cca549310bc5df03b7560afcf490995fbb".into(),
            predicate: "hash".into(),
        };
        assert_eq!(good.hex.len(), 40);
        assert!(good.length_matches_algorithm());

        // An MD5-length value typed SHA1.
        let bad = StoredHash {
            algorithm: HashAlgorithm::Sha1,
            hex: "d5825dc1152a42958c8219ff11ed01a3".into(),
            predicate: "hash".into(),
        };
        assert!(!bad.length_matches_algorithm());
    }

    /// An unrecognised algorithm has no expected length, so nothing to check.
    #[test]
    fn unknown_algorithms_do_not_report_a_mismatch() {
        let hash = StoredHash {
            algorithm: HashAlgorithm::Other("SHA3".into()),
            hex: "abc".into(),
            predicate: "hash".into(),
        };
        assert!(hash.length_matches_algorithm());
    }

    /// A summary must never read as verification.
    #[test]
    fn hashes_carry_their_provenance() {
        assert_eq!(StoredHash::PROVENANCE, "[acquisition hash]");
        assert!(!StoredHash::PROVENANCE.contains("verified"));
    }

    #[test]
    fn roles_render_readably() {
        assert_eq!(ObjectRole::DiskImage.to_string(), "disk image");
        assert_eq!(ObjectRole::ImageStream.to_string(), "image stream");
        assert_eq!(HashAlgorithm::Sha512.to_string(), "SHA512");
    }
}
