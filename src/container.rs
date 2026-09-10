//! Opening a container and identifying which generation wrote it.
//!
//! This is the crate's top-level entry point. [`Container::open`] resolves the
//! storage layer ([`crate::zip`]), the declared version ([`crate::version`]),
//! and the generation ([`crate::lexicon`]) into one handle the rest of the
//! library reads through.
//!
//! # Detection order (v1.0a §1)
//!
//! 1. An empty archive is not an AFF4 volume.
//! 2. If `version.txt` present → parse it. `1.0` and `1.1` are the two known
//!    Standard generations; anything else is [`crate::Error::Unsupported`],
//!    because a future version is intact rather than damaged.
//! 3. `version.txt` present but unparseable → [`crate::Error::Malformed`].
//! 4. No `version.txt` → a pre-standard dialect, told apart by the `aff4:`
//!    namespace declared in `information.turtle`.
//! 5. No `information.turtle` either → not an AFF4 volume.
//!
//! # Two deliberate divergences from pyaff4
//!
//! pyaff4's `identifyURN` (`container.py`) wraps steps 2–4 in a bare
//! `try/except:`, so a *corrupt* `version.txt` silently falls through to
//! namespace sniffing and the container is misidentified. Here that is
//! [`crate::Error::Malformed`]: a container that misstates its own version is a
//! finding, not a fallback case.
//!
//! pyaff4 also fabricates `Version(0, 1)` for pre-standard containers, which
//! have no version file at all. Here [`Container::version`] stays [`None`] —
//! inventing a version number into a forensic summary is exactly the kind of
//! plausible-looking guess this project forbids.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::arn::Arn;
use crate::error::{Deviation, DeviationKind, Error, Feature, Locus, NotAff4Reason, Result};
use crate::lexicon::{Generation, Lexicon};
use crate::model::{
    Aff4Object, ContainerSummary, EdgeKind, GraphEdge, HashAlgorithm, Locality,
    ManifestDisagreement, ManifestIssue, ObjectCounts, ObjectRole, Property, SegmentKind,
    SegmentKindCount, SegmentSummary, StoredHash, VolumeInfo,
};
use crate::rdf::{self, Graph, Value};
use crate::version::{self, ContainerVersion};
use crate::zip::{ArnSource, Volume, ZipVolume};
use crate::zip_volume_set::{VolumeOrigin, ZipVolumeSet};

/// A pool of shared strings, so a repeated term costs one allocation not N.
///
/// Type IRIs and predicate names repeat once per object: on a 404,000-object
/// AFF4-L container, 1,208,001 type occurrences are drawn from **6** distinct
/// IRIs and 4,424,000 predicate names from **11**. Storing each as its own
/// `String` costs 24 bytes inline plus a heap allocation every time; an
/// `Arc<str>` costs 8 bytes and shares one allocation per distinct value.
///
/// Deliberately **not** applied to literal values. Those are timestamps,
/// digests, and paths — 1,205,680 distinct values out of 2,820,000 on the same
/// container — so a pool would add a hash lookup per term and return little.
#[derive(Debug, Default)]
struct Interner {
    pool: HashMap<Box<str>, Arc<str>>,
}

impl Interner {
    /// The shared copy of `text`, creating it on first sight.
    fn intern(&mut self, text: &str) -> Arc<str> {
        if let Some(existing) = self.pool.get(text) {
            return Arc::clone(existing);
        }
        let shared: Arc<str> = Arc::from(text);
        self.pool.insert(Box::from(text), Arc::clone(&shared));
        shared
    }
}

/// The segment holding RDF metadata, in the container root.
pub const METADATA_SEGMENT: &str = "information.turtle";

/// The companion segment holding the metadata's digests.
///
/// AFF4-L v1.0-ALPHA §10.1 fixes this name: [`METADATA_SEGMENT`] with
/// `.hashes` appended.
pub const METADATA_HASH_SEGMENT: &str = "information.turtle.hashes";

/// An open AFF4 container.
#[derive(Debug)]
pub struct Container {
    volumes: ZipVolumeSet,
    generation: Generation,
    version: Option<ContainerVersion>,
    deviations: Vec<Deviation>,
}

/// What `aff4tools conformance` learned from one container.

#[derive(Debug, Clone)]
pub struct ConformanceScan {
    /// The container the findings came from.
    pub path: PathBuf,
    /// Which era wrote it, and so which document governs it.
    pub generation: Generation,
    /// The parsed `version.txt`, absent only for a container that declares
    /// none. Carries both the declared version and the producing tool, which
    /// the report prints in the same words `info` uses.
    pub version: Option<ContainerVersion>,
    /// Every departure recorded, routine or not.
    pub deviations: Vec<Deviation>,
    /// Which rules in scope for this generation went unevaluated.
    ///
    /// Separate from `deviations` because the two claims differ. A deviation
    /// is an observed departure; an unevaluated rule is an absence of
    /// evidence, and folding either into the other would misstate what the
    /// scan found.
    pub coverage: crate::rules::Coverage,
}

/// The generation a sibling volume declares, where it declares one readably.
///
/// [`None`] when the volume has no `version.txt`, when it cannot be read, or
/// when the version names a generation this build does not know. All three are
/// left to the ordinary open path to report against the volume itself rather
/// than being turned into a silent refusal here.
fn sibling_generation(volume: &mut ZipVolume) -> Option<Generation> {
    if !volume.has_segment(version::SEGMENT_NAME) {
        return None;
    }
    let locus = Locus::new(volume.path()).segment(version::SEGMENT_NAME);
    let bytes = volume.read_segment(version::SEGMENT_NAME).ok()?;
    let declared = ContainerVersion::parse(&bytes, &locus).ok()?;
    Generation::from_version(&declared)
}

/// Why an unsupported generation is being declined.
///
/// Only the pre-standard generation reaches here now that v2.1 reads. The
/// function is kept rather than inlined so a later generation that is
/// recognized and declined has one place to say why.
fn unsupported_generation_detail(generation: Generation, path: &std::path::Path) -> String {
    format!(
        "{} declares no version.txt and uses the {} vocabulary; no \
         specification aff4tools cites describes this container, so it \
         does not claim to read it",
        path.display(),
        generation.name()
    )
}

impl Container {
    /// Open a container read-only and identify its generation.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] / [`Error::Zip`] if the file cannot be read as an archive.
    /// - [`Error::NotAff4`] if it is not an AFF4 volume.
    /// - [`Error::Malformed`] if `version.txt` is present but invalid.
    /// - [`Error::Unsupported`] for a recognised but unimplemented generation
    ///   (a future standard version, or the Rekall/winpmem dialect).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut volume = ZipVolume::open(path)?;
        let mut deviations = volume.deviations().to_vec();

        let (generation, version) = identify(&mut volume, &mut deviations)?;

        if !generation.is_supported() {
            return Err(Error::unsupported(
                Feature::Generation {
                    named: generation.name().to_string(),
                },
                unsupported_generation_detail(generation, volume.path()),
            ));
        }

        // The graph is parsed once here and kept with its volume. Pre-standard
        // containers may lack `information.turtle` entirely; an empty graph
        // preserves the previous behaviour, where `graph()` was called lazily
        // and its failure surfaced at the call site rather than at open.
        let graph = match volume.read_segment(METADATA_SEGMENT) {
            Ok(bytes) => {
                let locus = volume.locus(Some(METADATA_SEGMENT));
                Graph::parse(&bytes, &locus).unwrap_or_default()
            }
            Err(_) => Graph::default(),
        };

        Ok(Self {
            volumes: ZipVolumeSet::single(volume, graph),
            generation,
            version,
            deviations,
        })
    }

    /// Add a stripe to this container's volume set.
    ///
    /// The volume must not already be present; a repeat is ignored rather than
    /// treated as an error, since naming a file twice is harmless.
    ///
    /// # Generations must agree
    ///
    /// A volume declaring a different generation than the container is
    /// refused. The generation decides how a resource name maps to a stored
    /// member (AFF4-L v1.0-ALPHA §1.2 against v1.0a §5.2), and the set
    /// resolves every member by the container's own answer. Admitting a
    /// sibling that disagrees would look up its segments under names it does
    /// not use, and report the data as absent when it is present.
    ///
    /// Refused rather than reported as an error, because that is what this
    /// signature can say and what the caller already handles: a volume the set
    /// does not admit is one the caller is told about by the `false` return.
    pub fn add_volume(
        &mut self,
        mut volume: ZipVolume,
        graph: Graph,
        origin: VolumeOrigin,
    ) -> bool {
        if sibling_generation(&mut volume).is_some_and(|g| g != self.generation) {
            return false;
        }
        self.volumes.push(volume, graph, origin)
    }

    /// Every volume backing this container.
    #[must_use]
    pub fn volumes(&self) -> &ZipVolumeSet {
        &self.volumes
    }

    /// Mutable access to the volume set.
    pub fn volumes_mut(&mut self) -> &mut ZipVolumeSet {
        &mut self.volumes
    }

    /// Every object declared by any volume in the set, merged by ARN.
    ///
    /// [`Container::summarize`] reads the primary's graph alone, which is right
    /// for a report *about that file*. It is wrong for verification of a
    /// striped set: a sibling's stream is a stub in the primary, so its
    /// recorded `aff4:hash` and `imageStreamIndexHash` live only in the volume
    /// that holds the data. Verifying the primary's view would silently skip
    /// them — a container's digests going unchecked while the summary line says
    /// everything matched (decision 35).
    ///
    /// Where two volumes declare the same subject, the declaration carrying
    /// **more recorded hashes** wins: that is the full one, and the stub is the
    /// placeholder. Genuine disagreement about a value is caught separately by
    /// [`crate::zip_volume_set::ZipVolumeSet::stream_conflict`], which declines
    /// rather than choosing.
    ///
    /// # Errors
    ///
    /// [`Error::NotAff4`] if the primary has no metadata segment.
    pub fn objects_across_volumes(&mut self) -> Result<Vec<Aff4Object>> {
        if self.volumes.is_single() {
            return Ok(self.summarize()?.objects);
        }

        let mut merged: Vec<Aff4Object> = Vec::new();
        // ARN → index into `merged`. A linear `merged.iter_mut().find(...)`
        // per object would make merging O(n²) across the whole set: a striped
        // container describing ten million objects would run 10^14
        // comparisons. Insertion order is preserved either way.
        let mut position: HashMap<Arc<str>, usize> = HashMap::new();
        let volume_arns: Vec<Arn> = self.volumes.volume_arns().cloned().collect();

        for volume_arn in &volume_arns {
            let Some(graph) = self.volumes.graph_of(volume_arn) else {
                continue;
            };
            let locus = Locus::new(PathBuf::new()).segment(METADATA_SEGMENT);
            let mut ignored = Vec::new();
            let mut interner = Interner::default();
            let objects = build_objects(
                graph,
                &mut interner,
                volume_arn,
                &volume_arns,
                &locus,
                &mut ignored,
            );

            for object in objects {
                match position.get(object.arn.as_str()) {
                    // The fuller declaration wins; a stub records nothing.
                    Some(&index) if object.hashes.len() > merged[index].hashes.len() => {
                        merged[index] = object;
                    }
                    Some(_) => {}
                    None => {
                        position.insert(Arc::from(object.arn.as_str()), merged.len());
                        merged.push(object);
                    }
                }
            }
        }

        Ok(merged)
    }

    /// Every volume's `aff4:DiskImage` ARNs, paired with the volume's path.
    ///
    /// The check that a `--multi-part` set really is one image: v1.0a §7.1 makes a
    /// commonly-named `DiskImage` "the point of commonality unifying" the
    /// volumes, so sharing none means the files are unrelated.
    ///
    /// This exists rather than calling
    /// [`crate::zip_volume_set::ZipVolumeSet::disk_images_per_volume`] directly
    /// because that reads each volume's *retained* graph, and the primary's is
    /// empty under [`Container::open_without_graph`] — the path `info` and
    /// `conformance` take. Reading it there reported "no `DiskImage`" for the
    /// primary of every striped set, including the reference container, and so
    /// refused every well-formed set those two commands were given. The
    /// primary's turtle is therefore streamed here for the type alone, which
    /// keeps the memory saving `open_without_graph` exists for.
    ///
    /// # Errors
    ///
    /// [`Error::NotAff4`] if the primary has no metadata segment, or the
    /// segment cannot be parsed.
    pub fn disk_images_per_volume(&mut self) -> Result<Vec<(PathBuf, Vec<String>)>> {
        let mut per_volume = self.volumes.disk_images_per_volume();

        // Only the primary can be missing its graph; siblings are always added
        // with one (`open_with_graph`).
        let primary_has_graph = self
            .volumes
            .graph_of(&self.volumes.primary().arn().clone())
            .is_some_and(|g| !g.subjects().is_empty());
        if primary_has_graph {
            return Ok(per_volume);
        }

        let locus = self.volumes.primary().locus(Some(METADATA_SEGMENT));
        let disk_image = self.lexicon().iri(self.lexicon().disk_image);
        let bytes = self.metadata_bytes()?;

        let mut images: Vec<String> = Vec::new();
        Graph::stream_by_subject(&bytes, &locus, |subject_graph| {
            let Some(subject) = subject_graph.subjects().first().cloned() else {
                return Ok(());
            };
            if subject_graph.types(&subject).contains(&&*disk_image) {
                images.push(subject.to_string());
            }
            Ok(())
        })?;
        images.sort();
        images.dedup();

        if let Some(first) = per_volume.first_mut() {
            first.1 = images;
        }
        Ok(per_volume)
    }

    /// Volume ARNs this container references but does not hold.
    ///
    /// A stripe declares its sibling's streams as stubs carrying only
    /// `aff4:stored <sibling-volume-ARN>` — so the container names the volume
    /// it is missing. Discovery is therefore metadata-driven: match ARNs,
    /// never guess from filenames.
    #[must_use]
    pub fn missing_volume_arns(&self) -> Vec<Arn> {
        let stored = self.lexicon().iri(self.lexicon().stored);
        let held: Vec<&str> = self.volumes.volume_arns().map(Arn::as_str).collect();

        let mut missing: Vec<Arn> = Vec::new();
        for graph in self.volumes.graphs() {
            for subject in graph.subjects() {
                let Some(value) = graph.object(subject, &stored) else {
                    continue;
                };
                let Value::Iri { iri } = value else { continue };
                if held.contains(&iri.as_str()) {
                    continue;
                }
                let locus = Locus::new(self.volumes.primary().path().to_path_buf());
                let Ok(arn) = Arn::parse(iri, &locus) else {
                    continue;
                };
                if !missing.iter().any(|m| m.as_str() == arn.as_str()) {
                    missing.push(arn);
                }
            }
        }
        missing
    }

    /// The generation that wrote this container.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// The declared version, or [`None`] for pre-standard containers.
    ///
    /// Absence is a fact about the container, not a gap to be filled in.
    #[must_use]
    pub fn version(&self) -> Option<&ContainerVersion> {
        self.version.as_ref()
    }

    /// The vocabulary this container's generation uses.
    #[must_use]
    pub fn lexicon(&self) -> &'static Lexicon {
        self.generation.lexicon()
    }

    /// Which ARN-to-segment rules this container's generation puts in force.
    ///
    /// The companion to [`Self::lexicon`]: that answers what the container's
    /// terms are called, this answers where its bytes are stored.
    #[must_use]
    pub fn name_mapping(&self) -> crate::arn::NameMapping {
        self.generation.name_mapping()
    }

    /// The primary storage volume — the file this container was opened from.
    ///
    /// A striped container has siblings behind [`Container::volumes`]; this is
    /// the one the caller named.
    #[must_use]
    pub fn volume(&self) -> &ZipVolume {
        self.volumes.primary()
    }

    /// Mutable access to the primary storage volume, for reading segments.
    pub fn volume_mut(&mut self) -> &mut ZipVolume {
        self.volumes.primary_mut()
    }

    /// Where the volume ARN was found.
    #[must_use]
    pub fn arn_source(&self) -> &ArnSource {
        self.volumes.primary().arn_source()
    }

    /// Every deviation observed so far.
    #[must_use]
    pub fn deviations(&self) -> &[Deviation] {
        &self.deviations
    }

    /// The raw `information.turtle` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::NotAff4`] if the container has no metadata segment.
    pub fn metadata_bytes(&mut self) -> Result<Vec<u8>> {
        if !self.volumes.primary().has_segment(METADATA_SEGMENT) {
            return Err(Error::not_aff4(
                self.volumes.primary().path(),
                NotAff4Reason::NoMetadata,
            ));
        }
        self.volumes.primary_mut().read_segment(METADATA_SEGMENT)
    }

    /// The raw `information.turtle.hashes` bytes, if the container carries them.
    ///
    /// [`None`] when the segment is absent, which is the ordinary case for a
    /// container written before AFF4-L v1.0-ALPHA §10.1 existed. Its absence is
    /// a conformance question for a v2.1 container, not an integrity finding,
    /// so this reports rather than errors.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the segment is present but cannot be read.
    pub fn metadata_hash_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.volumes.primary().has_segment(METADATA_HASH_SEGMENT) {
            return Ok(None);
        }
        self.volumes
            .primary_mut()
            .read_segment(METADATA_HASH_SEGMENT)
            .map(Some)
    }

    /// Parse the container's metadata graph.
    ///
    /// # Errors
    ///
    /// [`Error::NotAff4`] if there is no metadata, or [`Error::Malformed`] if it
    /// is not valid Turtle.
    pub fn graph(&mut self) -> Result<Graph> {
        let locus = self.volumes.primary().locus(Some(METADATA_SEGMENT));
        let bytes = self.metadata_bytes()?;
        Graph::parse(&bytes, &locus)
    }

    /// Open a container without parsing its metadata graph.
    ///
    /// [`Container::open`] parses `information.turtle` eagerly and keeps the
    /// result. For `info` — and, via
    /// [`Container::open_for_conformance`], for `conformance` — that copy is
    /// never read —
    /// [`Container::summarize`] parses its own — so on a large container it is
    /// pure cost, and **freeing it afterwards does not help**: peak RSS is a
    /// high-water mark, and by then both graphs have been live at once.
    ///
    /// Measured on a 404,000-object AFF4-L container: releasing after the fact
    /// saved 0.4 GB of 4.94 GB, while never parsing saves the graph's full
    /// footprint.
    ///
    /// The graph is not lost. [`Container::graph`] re-parses from the container
    /// on demand, and `verify` — which needs the retained copy — keeps using
    /// [`Container::open`].
    ///
    /// # Errors
    ///
    /// As [`Container::open`].
    pub fn open_without_graph(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_ungraphed(path, Generation::is_supported)
    }

    /// [`Container::open_without_graph`], for `conformance` alone.
    ///
    /// Differs from every other entry point by exactly one generation: it
    /// admits a container whose governing document aff4tools has declared
    /// rules for but cannot yet check. See [`Generation::is_conformance_readable`].
    ///
    /// **The wider gate belongs to the command, not to the graph-free open.**
    /// `open_without_graph` is a memory optimization that `info` shares, so
    /// widening the gate there would let `info` read a generation it cannot
    /// describe. The split is by what the command claims: `conformance`
    /// produces a coverage report, which says which rules were evaluated and
    /// which were not, and an unevaluated rule asserts nothing about the
    /// evidence. `info` and `verify` describe and check evidence, so a
    /// generation whose storage streams cannot yet be read stays declined for
    /// them — a partial reading of evidence misleads in a way a coverage
    /// report does not. Widen those only when those streams can be read.
    ///
    /// # Errors
    ///
    /// As [`Container::open`], except that a v2.1 container is admitted.
    pub fn open_for_conformance(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_ungraphed(path, Generation::is_conformance_readable)
    }

    /// Open without parsing the graph, admitting the generations `admits`
    /// accepts.
    ///
    /// The gate is a parameter rather than duplicated, so the two callers
    /// above cannot drift apart in anything but the one predicate that is
    /// meant to differ.
    fn open_ungraphed(path: impl AsRef<Path>, admits: fn(Generation) -> bool) -> Result<Self> {
        let mut volume = ZipVolume::open(path)?;
        let mut deviations = volume.deviations().to_vec();

        let (generation, version) = identify(&mut volume, &mut deviations)?;

        if !admits(generation) {
            return Err(Error::unsupported(
                Feature::Generation {
                    named: generation.name().to_string(),
                },
                unsupported_generation_detail(generation, volume.path()),
            ));
        }

        Ok(Self {
            volumes: ZipVolumeSet::single(volume, Graph::default()),
            generation,
            version,
            deviations,
        })
    }

    /// Discard the metadata graphs retained since [`Container::open`].
    ///
    /// **For `info` and `conformance` only.** Both build a
    /// [`ContainerSummary`] and never read the graph again, so holding it is
    /// pure cost — measured at **1.81 GB of 5.08 GB (36%)** on a 400,000-object
    /// AFF4-L container, because two graphs are live at once: this one and the
    /// one [`Container::summarize`] parses for itself.
    ///
    /// **Not safe before verification.** `verify` reads the retained graph
    /// after summarizing — `ImageStream::open`, `Image::open`, and the map
    /// reader all take it, for chunk size, compression method, and map targets
    /// that a summary does not carry. Calling this first would make those
    /// re-parse per stream, or fail on a striped set where a sibling's stream
    /// is described only by the volume holding it.
    ///
    /// Nothing is lost that cannot be recovered: the container is on disk and
    /// read-only, so [`Container::graph`] rebuilds from the same bytes.
    ///
    /// This is why it is an explicit call rather than a drop inside
    /// `summarize()`: the safety depends on what the *caller* does next, which
    /// `summarize` cannot see.
    pub fn release_graphs(&mut self) {
        self.volumes.release_graphs();
    }

    /// Collect only the deviations, streaming the metadata rather than
    /// retaining it.
    ///
    /// `aff4tools conformance` reads [`ContainerSummary::deviations`] and
    /// renders nothing per object, yet [`Container::summarize`] holds a 2.26 GB
    /// [`Graph`] and a million [`Aff4Object`]s to get there. This holds
    /// neither: it parses one subject at a time, runs the identical checks
    /// while that subject is in hand, and keeps only the findings plus the set
    /// of subject ARNs.
    ///
    /// Measured on a 1,010,001-object container: **3.26 GB to 1.07 GB**. See
    /// `docs/RDF-scalability.md`.
    ///
    /// # Why the ARN set has to be kept
    ///
    /// The dangling-reference check asks whether a referenced IRI is described
    /// anywhere in the volume, and a reference may name a subject that has not
    /// been parsed yet. Deciding it in-pass would report a forward reference as
    /// dangling when it is not. So each unresolved reference is deferred and
    /// settled against the completed subject set at the end. The set is
    /// `Arc<str>` shared with the parser, so it costs ~0.08 GB at a million
    /// objects rather than a second copy of every ARN.
    ///
    /// # Errors
    ///
    /// As [`Container::summarize`].
    pub fn deviations_only(&mut self) -> Result<ConformanceScan> {
        let locus = self.volumes.primary().locus(Some(METADATA_SEGMENT));
        let volume_arn = self.volumes.primary().arn().clone();
        // Every volume the examiner opened, not just the primary. A reference
        // into a sibling that is present resolves, so it is not reported; one
        // into a volume nobody opened does not, and is. See `locality_of`.
        let siblings: Vec<Arn> = self.volumes.volume_arns().cloned().collect();
        let contains = self.lexicon().iri(self.lexicon().contains);
        let bytes = self.metadata_bytes()?;

        let volume_context = VolumeContext::new(
            &volume_arn,
            self.volumes.primary(),
            self.generation.name_mapping(),
            &locus,
        );

        let mut deviations = self.deviations.clone();
        let mut interner = Interner::default();

        let mut described: HashSet<Arc<str>> = HashSet::new();
        let mut deferred: Vec<DeferredReference> = Vec::new();
        let mut local: Vec<LocalArn> = Vec::new();
        let mut manifest: Vec<String> = Vec::new();
        let mut manifest_declared = false;
        let mut dedupe_subjects = 0usize;

        let parse_deviations = Graph::stream_by_subject(&bytes, &locus, |subject_graph| {
            let Some(subject) = subject_graph.subjects().first().cloned() else {
                return Ok(());
            };
            described.insert(Arc::clone(&subject));

            // The volume's own subject carries the `aff4:contains` manifest.
            // Captured here because this is the only pass over it.
            if &*subject == volume_arn.as_str() {
                manifest_declared = subject_graph
                    .statements_for(&subject)
                    .iter()
                    .any(|s| *s.predicate == contains);
                manifest.extend(
                    subject_graph
                        .objects(&subject, &contains)
                        .into_iter()
                        .filter_map(|value| value.as_iri().map(ToOwned::to_owned)),
                );
            }

            // pyaff4's deduplicating writer indexes stored blocks by content
            // hash. Deliberate, not damage — but they name content, not
            // resources, so they cannot become objects. Counted, not listed.
            if subject.starts_with("aff4:sha512:") || subject.starts_with("aff4:sha256:") {
                dedupe_subjects += 1;
                return Ok(());
            }

            let Some(object) = build_object(
                subject_graph,
                &mut interner,
                &subject,
                &volume_arn,
                &siblings,
                &locus,
                &mut deviations,
            ) else {
                return Ok(());
            };

            // Deferred rather than decided: the target may be a subject this
            // pass has not reached yet.
            defer_object_references(&object, &mut deferred);

            report_any_generation(&object, &volume_context, &mut deviations);
            report_v21(&object, &volume_context, &mut deviations);

            if matches!(object.locality, Locality::Local) {
                // The ARN string is already held by `described`; share that
                // allocation rather than keeping `Aff4Object`'s owned copy. A
                // million owned `Arn`s cost ~0.16 GB, a million `LocalArn`s
                // ~0.02 GB, and the manifest comparison reads no other field.
                local.push(LocalArn {
                    volume_len: u32::try_from(object.arn.volume().len()).unwrap_or(u32::MAX),
                    arn: Arc::clone(&subject),
                });
            }
            Ok(())
        })?;

        // Metadata deviations follow storage-layer ones, so the order still
        // follows the order of discovery.
        deviations.extend(parse_deviations);

        resolve_deferred_references(deferred, &described, &locus, &mut deviations);
        drop(described);

        if dedupe_subjects > 0 {
            deviations.push(dedupe_subject_deviation(&locus, dedupe_subjects));
        }

        self.report_stream_conflicts(&locus, &mut deviations);

        report_manifest_disagreements(
            &manifest,
            manifest_declared,
            &local,
            &volume_arn,
            &locus,
            &mut deviations,
        );

        self.report_metadata_hash(&locus, &mut deviations);
        self.report_part_naming(&mut deviations);

        Ok(ConformanceScan {
            path: self.volumes.primary().path().to_path_buf(),
            generation: self.generation,
            version: self.version.clone(),
            deviations,
            coverage: crate::rules::Coverage::for_generation(self.generation),
        })
    }

    /// Report AFF4-L v1.0-ALPHA §10.1 departures in the metadata integrity hash.
    ///
    /// Only for v2.1 containers: the clause is that standard's, and an earlier
    /// generation carrying no companion segment conforms to its own document.
    /// aff4tools writes the segment for both profiles, but that is a choice its
    /// output makes, not a requirement it may impose on other writers.
    fn report_metadata_hash(&mut self, locus: &Locus, deviations: &mut Vec<Deviation>) {
        if self.generation != Generation::Aff4L10 {
            return;
        }

        let bytes = match self.metadata_hash_bytes() {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                deviations.push(Deviation::new(
                    locus.clone(),
                    DeviationKind::MissingMetadataHash,
                    format!(
                        "this container stores no {METADATA_HASH_SEGMENT}, so a change to \
its metadata layer would leave no trace"
                    ),
                ));
                return;
            }
            // Unreadable is an I/O condition, not a conformance finding; the
            // reading paths report it in their own terms.
            Err(_) => return,
        };

        let hash_locus = locus.clone().segment(METADATA_HASH_SEGMENT);
        // A segment that will not parse is malformed rather than
        // non-conformant, and the reading paths report it in those terms.
        let Ok(graph) = crate::rdf::Graph::parse(&bytes, &hash_locus) else {
            return;
        };

        // The clause names a strength floor, so a segment carrying only weaker
        // digests satisfies its letter but not its purpose.
        let mut algorithms = Vec::new();
        for subject in graph.subjects() {
            for statement in graph.statements_for(subject) {
                let local = statement
                    .predicate
                    .rsplit_once(['#', '/'])
                    .map_or(&*statement.predicate, |(_, name)| name);
                if local != "hash" {
                    continue;
                }
                if let crate::rdf::Value::Literal {
                    datatype: Some(datatype),
                    ..
                } = &statement.object
                {
                    algorithms.push(HashAlgorithm::from_datatype(datatype));
                }
            }
        }
        if !algorithms.is_empty()
            && !algorithms
                .iter()
                .any(crate::hash_selection::satisfies_integrity_clause)
        {
            let named: Vec<&str> = algorithms.iter().map(HashAlgorithm::name).collect();
            deviations.push(Deviation::new(
                locus.clone(),
                DeviationKind::WeakMetadataHash,
                format!(
                    "the metadata integrity hash records only {}, but AFF4-L \
v1.0-ALPHA §10.1 requires SHA-256 or stronger",
                    named.join(" and ")
                ),
            ));
        }
    }

    /// Report a multi-part set named outside the AFF4-L v1.0-ALPHA §8 scheme.
    ///
    /// Judged from the file names in the container's own directory, which is
    /// the only place the answer lives: the scheme is about telling a set's
    /// membership from names alone, so nothing inside any volume could settle
    /// it.
    ///
    /// Only for v2.1 containers. The clause is that standard's, and a set
    /// written to an earlier generation is named by whatever convention its own
    /// writer used — pyaff4's `Base-Linear_1.aff4` among them, which conforms to
    /// its own document and would be misreported here.
    ///
    /// Reported once for the set rather than once per file, since the departure
    /// is a property of how the names relate to each other.
    fn report_part_naming(&self, deviations: &mut Vec<Deviation>) {
        if self.generation != Generation::Aff4L10 {
            return;
        }
        let path = self.volumes.primary().path();
        let Some(departure) = crate::multi_part::naming_departure(path) else {
            return;
        };
        deviations.push(Deviation::new(
            Locus::new(path),
            DeviationKind::MultiPartNamingScheme,
            format!(
                "this container sits in a set named {}, but AFF4-L v1.0-ALPHA §8 names \
one as {}; membership in the set cannot be told from the names alone",
                departure.names.join(", "),
                departure.expected.join(", "),
            ),
        ));
    }

    /// Build a complete summary of the container.
    ///
    /// This is feature 2's entry point. It reads only; nothing is recomputed,
    /// so every hash reported is what the acquiring tool recorded.
    ///
    /// # Errors
    ///
    /// Propagates any failure from opening, reading, or parsing the metadata.
    pub fn summarize(&mut self) -> Result<ContainerSummary> {
        let locus = self.volumes.primary().locus(Some(METADATA_SEGMENT));
        let volume_arn = self.volumes.primary().arn().clone();
        // Every volume the examiner opened, not just the primary. A reference
        // into a sibling that is present resolves, so it is not reported; one
        // into a volume nobody opened does not, and is. See `locality_of`.
        let siblings: Vec<Arn> = self.volumes.volume_arns().cloned().collect();
        let contains = self.lexicon().iri(self.lexicon().contains);
        let bytes = self.metadata_bytes()?;

        let mapping = self.generation.name_mapping();
        let volume_context =
            VolumeContext::new(&volume_arn, self.volumes.primary(), mapping, &locus);

        // Storage-layer deviations first, then metadata ones, so the order
        // follows the order of discovery.
        let mut deviations = self.deviations.clone();
        let mut interner = Interner::default();

        // Streamed rather than parsed into a retained `Graph`. `info` renders
        // every object, so unlike `conformance` it cannot discard them — but it
        // has no need to hold the 15.1M statements *and* the objects built from
        // them at the same time. That overlap was 2.26 GB of the 4.68 GB peak
        // at a million objects; see `docs/RDF-scalability.md`.
        let mut objects: Vec<Aff4Object> = Vec::new();
        let mut counts = ObjectCounts::default();
        let mut described: HashSet<Arc<str>> = HashSet::new();
        let mut deferred: Vec<DeferredReference> = Vec::new();
        let mut manifest: Vec<String> = Vec::new();
        let mut manifest_declared = false;
        let mut dedupe_subjects = 0usize;
        let mut prefixes: Vec<(String, String)> = Vec::new();

        let parse_deviations = Graph::stream_by_subject(&bytes, &locus, |subject_graph| {
            let Some(subject) = subject_graph.subjects().first().cloned() else {
                return Ok(());
            };
            if prefixes.is_empty() {
                prefixes = subject_graph.prefixes().to_vec();
            }
            described.insert(Arc::clone(&subject));

            // The volume's own subject carries the `aff4:contains` manifest,
            // and this is the only pass over it.
            if &*subject == volume_arn.as_str() {
                manifest_declared = subject_graph
                    .statements_for(&subject)
                    .iter()
                    .any(|s| *s.predicate == contains);
                manifest.extend(
                    subject_graph
                        .objects(&subject, &contains)
                        .into_iter()
                        .filter_map(|value| value.as_iri().map(ToOwned::to_owned)),
                );
            }

            // pyaff4's deduplicating writer indexes stored blocks by content
            // hash. Deliberate, not damage — but they name content, not
            // resources, so they cannot become objects. Counted, not listed.
            if subject.starts_with("aff4:sha512:") || subject.starts_with("aff4:sha256:") {
                dedupe_subjects += 1;
                return Ok(());
            }

            if let Some(object) = build_object(
                subject_graph,
                &mut interner,
                &subject,
                &volume_arn,
                &siblings,
                &locus,
                &mut deviations,
            ) {
                // Deferred rather than decided: the target may name a subject
                // this pass has not reached yet.
                defer_object_references(&object, &mut deferred);
                report_any_generation(&object, &volume_context, &mut deviations);
                report_v21(&object, &volume_context, &mut deviations);
                observe_object(&object, &mut counts);
                objects.push(object);
            }
            Ok(())
        })?;

        deviations.extend(parse_deviations);
        resolve_deferred_references(deferred, &described, &locus, &mut deviations);
        drop(described);

        if dedupe_subjects > 0 {
            deviations.push(dedupe_subject_deviation(&locus, dedupe_subjects));
        }

        self.report_stream_conflicts(&locus, &mut deviations);

        let local: Vec<LocalArn> = objects
            .iter()
            .filter(|o| matches!(o.locality, Locality::Local))
            .map(|o| LocalArn {
                volume_len: u32::try_from(o.arn.volume().len()).unwrap_or(u32::MAX),
                arn: Arc::from(o.arn.as_str()),
            })
            .collect();
        let manifest_disagreements = compare_manifest(
            &manifest,
            manifest_declared,
            &local,
            &volume_arn,
            &locus,
            &mut deviations,
        );
        drop(local);

        let segments = segment_summary(self.volumes.primary());

        Ok(ContainerSummary {
            source_path: self.volumes.primary().path().to_path_buf(),
            volume: VolumeInfo {
                arn: volume_arn,
                arn_source: self.volumes.primary().arn_source().clone(),
            },
            generation: self.generation,
            version: self.version.clone(),
            objects,
            segments,
            deviations,
            prefixes,
            manifest,
            manifest_disagreements,
            counts,
        })
    }

    /// Summarize for `info --brief`, retaining only the objects it renders.
    ///
    /// [`Container::summarize`] keeps every object because the full report
    /// lists every object. `--brief` prints counts, the case block, and at most
    /// a handful of bitstream objects — so on a million-object container it was
    /// paying 2.67 GB to build a list it then reduced to three lines.
    ///
    /// This runs the identical parse and the identical per-object checks, and
    /// keeps an object only if it could appear in the brief report:
    ///
    /// - **image-typed**, which `Content Type:` and the `Bitstream` section read
    /// - **carrying a case field**, which the `Case:` line reads
    ///
    /// Everything else is counted into [`ContainerSummary::counts`] and
    /// dropped. Measured on a 1,010,001-object container: **2.802 GB to
    /// 1.050 GB**, with byte-identical output.
    ///
    /// # This summary is deliberately partial
    ///
    /// [`ContainerSummary::objects`] holds a *subset*, so anything counting it
    /// will undercount. `counts` is the authority on how many objects exist.
    /// Use [`Container::summarize`] for any consumer that needs them all —
    /// which is why `info` without `--brief` still does.
    ///
    /// # Errors
    ///
    /// As [`Container::summarize`].
    pub fn summarize_brief(&mut self) -> Result<ContainerSummary> {
        let locus = self.volumes.primary().locus(Some(METADATA_SEGMENT));
        let volume_arn = self.volumes.primary().arn().clone();
        // Every volume the examiner opened, not just the primary. A reference
        // into a sibling that is present resolves, so it is not reported; one
        // into a volume nobody opened does not, and is. See `locality_of`.
        let siblings: Vec<Arn> = self.volumes.volume_arns().cloned().collect();
        let contains = self.lexicon().iri(self.lexicon().contains);
        let bytes = self.metadata_bytes()?;

        let volume_context = VolumeContext::new(
            &volume_arn,
            self.volumes.primary(),
            self.generation.name_mapping(),
            &locus,
        );

        let mut deviations = self.deviations.clone();
        let mut interner = Interner::default();

        let mut objects: Vec<Aff4Object> = Vec::new();
        let mut counts = ObjectCounts::default();
        let mut candidates_kept = 0usize;
        let mut seen_types: HashSet<Arc<str>> = HashSet::new();
        let mut described: HashSet<Arc<str>> = HashSet::new();
        let mut deferred: Vec<DeferredReference> = Vec::new();
        let mut manifest: Vec<String> = Vec::new();
        let mut manifest_declared = false;
        let mut dedupe_subjects = 0usize;
        let mut prefixes: Vec<(String, String)> = Vec::new();

        let parse_deviations = Graph::stream_by_subject(&bytes, &locus, |subject_graph| {
            let Some(subject) = subject_graph.subjects().first().cloned() else {
                return Ok(());
            };
            if prefixes.is_empty() {
                prefixes = subject_graph.prefixes().to_vec();
            }
            described.insert(Arc::clone(&subject));

            if &*subject == volume_arn.as_str() {
                manifest_declared = subject_graph
                    .statements_for(&subject)
                    .iter()
                    .any(|s| *s.predicate == contains);
                manifest.extend(
                    subject_graph
                        .objects(&subject, &contains)
                        .into_iter()
                        .filter_map(|value| value.as_iri().map(ToOwned::to_owned)),
                );
            }

            if subject.starts_with("aff4:sha512:") || subject.starts_with("aff4:sha256:") {
                dedupe_subjects += 1;
                return Ok(());
            }

            if let Some(object) = build_object(
                subject_graph,
                &mut interner,
                &subject,
                &volume_arn,
                &siblings,
                &locus,
                &mut deviations,
            ) {
                defer_object_references(&object, &mut deferred);
                report_any_generation(&object, &volume_context, &mut deviations);
                report_v21(&object, &volume_context, &mut deviations);
                observe_object(&object, &mut counts);
                if brief_renders(&object, candidates_kept, &mut seen_types) {
                    if has_bitstream_hash(&object) {
                        candidates_kept += 1;
                    }
                    objects.push(object);
                }
            }
            Ok(())
        })?;

        deviations.extend(parse_deviations);
        resolve_deferred_references(deferred, &described, &locus, &mut deviations);
        drop(described);

        if dedupe_subjects > 0 {
            deviations.push(dedupe_subject_deviation(&locus, dedupe_subjects));
        }

        self.report_stream_conflicts(&locus, &mut deviations);

        // The manifest comparison is skipped, not approximated. It needs every
        // local ARN, which is the retention this function exists to avoid, and
        // `--brief` renders no disagreement — it prints only the deviation
        // count and points at `conformance`, which does the full comparison.
        let _ = (&manifest, manifest_declared);

        let segments = segment_summary(self.volumes.primary());

        Ok(ContainerSummary {
            source_path: self.volumes.primary().path().to_path_buf(),
            volume: VolumeInfo {
                arn: volume_arn,
                arn_source: self.volumes.primary().arn_source().clone(),
            },
            generation: self.generation,
            version: self.version.clone(),
            objects,
            segments,
            deviations,
            prefixes,
            manifest,
            manifest_disagreements: Vec::new(),
            counts,
        })
    }

    /// Report predicates the admitted volumes disagree about.
    ///
    /// Only meaningful with more than one volume admitted, via `--multi-part`;
    /// a lone volume has nothing to disagree with and
    /// must never be faulted for it.
    ///
    /// The scope is the four predicates whose disagreement makes the set
    /// unreadable as one image. `verify` already declines on these through
    /// [`crate::zip_volume_set::ZipVolumeSet::stream_conflict`]; before this,
    /// `info` absorbed the same conflict silently.
    fn report_stream_conflicts(&self, locus: &Locus, deviations: &mut Vec<Deviation>) {
        if self.volumes.len() < 2 {
            return;
        }

        let lexicon = self.lexicon();
        let predicates = [
            lexicon.iri(lexicon.size),
            lexicon.iri(lexicon.chunk_size),
            lexicon.iri(lexicon.chunks_in_segment),
            lexicon.iri(lexicon.compression_method),
        ];
        let refs: Vec<&str> = predicates.iter().map(String::as_str).collect();

        for conflict in self.volumes.stream_conflicts(&refs) {
            let name = local_name(&conflict.predicate);
            deviations.push(Deviation::new(
                locus
                    .clone()
                    .subject(conflict.stream.as_str())
                    .predicate(&name),
                DeviationKind::ConflictingStreamValue,
                format!(
                    "volume {} declares {name} {}, but volume {} declares {}; \
                     the set cannot be read as one image and no choice between \
                     them is defensible",
                    conflict.first_volume.as_str(),
                    conflict.first_value,
                    conflict.second_volume.as_str(),
                    conflict.second_value,
                ),
            ));
        }
    }
}

/// Turn every subject in the graph into an [`Aff4Object`].
///
/// The retained-graph path, used only by [`Container::objects_across_volumes`]
/// for striped containers, which needs each volume's graph resolved against the
/// others. `info` and `conformance` both stream instead — see
/// [`Container::summarize`] and [`Container::deviations_only`].
fn build_objects(
    graph: &Graph,
    interner: &mut Interner,
    volume: &Arn,
    siblings: &[Arn],
    locus: &Locus,
    deviations: &mut Vec<Deviation>,
) -> Vec<Aff4Object> {
    let mut objects = Vec::new();

    for subject in graph.subjects() {
        // pyaff4's deduplicating writer indexes stored blocks by content hash,
        // producing `aff4:sha512:` subjects. They are deliberate, not damage —
        // but they name content, not resources, so they cannot become objects.
        if subject.starts_with("aff4:sha512:") || subject.starts_with("aff4:sha256:") {
            continue;
        }
        if let Some(object) = build_object(
            graph, interner, subject, volume, siblings, locus, deviations,
        ) {
            objects.push(object);
        }
    }

    objects
}

/// The predicates whose object is a data-path edge to another resource.
const REFERENCE_PREDICATES: [&str; 3] = ["target", "dataStream", "dependentStream"];

/// Whether an ARN names a stream the standard defines rather than the container.
///
/// One definition, in `crate::map`, because the writer needs the same test: a
/// symbolic target gets no `aff4:target` back-pointer, since there is no object
/// in the volume to carry one.
use crate::map::is_symbolic_target as is_symbolic_stream;

/// Build one object, or skip a subject whose ARN cannot be parsed.
fn build_object(
    graph: &Graph,
    interner: &mut Interner,
    subject: &str,
    volume: &Arn,
    siblings: &[Arn],
    locus: &Locus,
    deviations: &mut Vec<Deviation>,
) -> Option<Aff4Object> {
    let subject_locus = locus.clone().subject(subject);

    // A subject that is not an AFF4 ARN is reported and skipped rather than
    // failing the whole summary: one odd subject should not hide the rest.
    let Ok(arn) = Arn::parse(subject, &subject_locus) else {
        deviations.push(Deviation::new(
            subject_locus,
            DeviationKind::UnexpectedDatatype,
            format!("subject {subject:?} is not an AFF4 resource name; skipped"),
        ));
        return None;
    };

    if arn.is_byte_range() {
        // Already reported in aggregate by the RDF layer; no per-object noise.
    }

    let types: Vec<Arc<str>> = graph
        .types(subject)
        .iter()
        .map(|t| interner.intern(t))
        .collect();
    let role = ObjectRole::from_types(&types);

    let mut size = None;
    let mut hashes = Vec::new();
    let mut stored_in = None;
    let mut properties = Vec::new();
    let mut edges = Vec::new();

    for statement in graph.statements_for(subject) {
        if &*statement.predicate == rdf::RDF_TYPE {
            continue; // Already captured in `types`.
        }

        let name = local_name(&statement.predicate);
        let value_locus = subject_locus.clone().predicate(&name);

        if let Some(edge) = edge_for(&name, &statement.object, &types) {
            edges.push(edge);
        }

        match name.as_str() {
            "size" => {
                size = rdf::as_u64(&statement.object, &value_locus, deviations);
            }
            "stored" => {
                stored_in = statement.object.as_iri().map(ToString::to_string);
            }
            // Modelled separately as `ContainerSummary::manifest`.
            "contains" => {}
            _ => {
                // Any literal whose datatype is a timestamp gets checked, so a
                // nonstandard spelling is reported wherever it appears rather
                // than only on predicates this crate models. `dream.aff4` types
                // four of its five properties `^^xsd:datetime` (lowercase),
                // which XSD does not define.
                if is_timestamp_datatype(statement.object.datatype()) {
                    let _ = rdf::as_timestamp(&statement.object, &value_locus, deviations);
                }
            }
        }

        // Any typed literal whose datatype names a digest algorithm is a hash,
        // whatever the predicate: `hash`, `blockMapHash`, `mapIdxHash`, and the
        // rest all carry digests.
        if let Some(hash) = as_stored_hash(&statement.object, &name) {
            if !hash.length_matches_algorithm() {
                deviations.push(Deviation::new(
                    value_locus.clone(),
                    DeviationKind::DigestLengthMismatch,
                    format!(
                        "{} digest is {} hex characters; {} expects {}",
                        hash.algorithm,
                        hash.hex.len(),
                        hash.algorithm,
                        hash.algorithm
                            .hex_length()
                            .map_or_else(|| "an unknown number".to_string(), |n| n.to_string())
                    ),
                ));
            }
            hashes.push(hash);
            continue;
        }

        if !matches!(name.as_str(), "size" | "stored" | "contains") {
            // A predicate outside the AFF4 namespace is a vendor extension,
            // which is legitimate under RDF. One known vendor extension is `bbt:`.
            let (prefix, namespace) = namespace_of(&statement.predicate, graph);

            properties.push(Property {
                name: interner.intern(&name),
                iri: interner.intern(&statement.predicate),
                value: statement.object.clone(),
                prefix: prefix.map(|p| interner.intern(&p)),
                namespace: namespace.map(|n| interner.intern(&n)),
            });
        }
    }

    let locality = locality_of(
        stored_in.as_ref(),
        &subject_locus,
        volume,
        siblings,
        deviations,
    );

    // Grown by pushing, so each `Vec` sits on a power-of-two capacity: a
    // two-element `edges` or `hashes` list occupies four slots. Harmless on a
    // ten-object container, 0.23 GB at a million. Released before the object
    // joins the summary, where it would be held until the report is rendered.
    properties.shrink_to_fit();
    edges.shrink_to_fit();
    hashes.shrink_to_fit();

    let mut object = Aff4Object {
        arn,
        types,
        role,
        size,
        hashes,
        stored_in,
        locality,
        properties,
        edges,
        block_hashes: None,
    };
    object.block_hashes = object.block_hashes_info();
    Some(object)
}

/// Whether `stored_arn` resolves within the volumes currently open.
///
/// A multi-part set's parts reference each other by design (v1.0a §7.1): that is what
/// makes the set reassemblable, and every part necessarily points outside
/// itself. Noting it is useful when one part is inspected alone, and noise when
/// the whole set is present and the reference resolves. The distinction is
/// which volumes are open, so the check needs the set rather than one ARN.
fn resolves_within(stored_arn: &Arn, volumes: &[Arn]) -> bool {
    volumes.iter().any(|v| stored_arn.is_within(v))
}

/// Whether an object lives in this volume, based on its `aff4:stored` value.
///
/// Extracted from [`build_object`] to keep that function's line count under
/// clippy's pedantic threshold.
///
/// `siblings` is every volume ARN currently open, `volume` included. A
/// cross-volume `aff4:stored` is not a spec violation — line 90 defines
/// `stored` as "the Volume that the Image Stream or Map is stored in" with no
/// requirement that it be the current one, and v1.0a §7.1's discovery mechanism
/// depends on pointing at siblings. So the deviation records an *unresolvable*
/// reference, not a cross-volume one: when the named volume is open, the
/// reference resolves and there is nothing to tell the examiner.
///
/// [`Locality::External`] is unaffected. It states where the object lives,
/// which is still outside this volume, and other code reads it that way.
fn locality_of(
    stored_in: Option<&String>,
    subject_locus: &Locus,
    volume: &Arn,
    siblings: &[Arn],
    deviations: &mut Vec<Deviation>,
) -> Locality {
    match stored_in {
        None => Locality::Undeclared,
        Some(iri) => match Arn::parse(iri, subject_locus) {
            Ok(stored_arn) if stored_arn.is_within(volume) => Locality::Local,
            Ok(stored_arn) => {
                if !resolves_within(&stored_arn, siblings) {
                    // Normal for one stripe of a striped container, or one part
                    // of a multi-part set, read alone: the stream genuinely lives in
                    // a volume this reader does not hold. Not an error, but
                    // worth saying, because the view is incomplete.
                    deviations.push(Deviation::new(
                        subject_locus.clone().predicate("stored"),
                        DeviationKind::ExternalReference,
                        format!(
                            "stored in {iri}, which is not this volume ({}) and \
                             is not among the volumes opened; expected when \
                             inspecting one stripe or part on its own",
                            volume.as_str()
                        ),
                    ));
                }
                Locality::External
            }
            Err(_) => Locality::Undeclared,
        },
    }
}

/// One [`GraphEdge`], if `object` names another resource this predicate
/// should be tracked as an edge.
///
/// One edge per object *value* — a Turtle statement can carry several
/// (`aff4:dependentStream <a> , <b> ;`), and the caller invokes this once per
/// statement, so each becomes a distinct edge. A literal-valued `stored`
/// (pre-standard's volume, which records its own filename as a string) is not
/// an edge: nothing to point at. `contains` is excluded: it is the volume's
/// manifest, modelled separately as `ContainerSummary::manifest`, not a graph
/// edge asserted by an individual object.
fn edge_for(local_name: &str, object: &Value, subject_types: &[Arc<str>]) -> Option<GraphEdge> {
    if local_name == "contains" {
        return None;
    }
    let to = object.as_iri()?.to_string();
    Some(GraphEdge {
        kind: classify_edge(local_name, subject_types),
        to,
    })
}

/// Local type names that make an object's `aff4:target` mean attribution
/// ("this metadata describes that image") rather than data-path membership.
///
/// Verified against the corpus: `Base-Linear.aff4`
/// has `CaseNotes`, `CaseDetails`, and `TimeStamps` all `target` the disk
/// image, while a `Map` and an `ImageStream` use the identical predicate for
/// the data path. `Base-Linear.af4` (pre-standard) adds `caseNotes`
/// (lowercase, no `CaseDetails` type exists there) and `Tool` /
/// `ClientConnectionDetails`. Matched case-insensitively for the same reason
/// `ObjectRole::from_types` is: pre-standard lowercases its class names.
///
/// **Closed list, corpus-derived, no deviation on a miss.** This is every
/// metadata type this crate has observed asserting `target`, not a claim that
/// no other metadata type exists. An object of an unrecognised type that
/// asserts `target` for attribution (rather than the data path) will
/// misclassify silently into [`EdgeKind::TargetStream`] rather than
/// [`EdgeKind::Describes`] — a labelling error, not a crash, and this task
/// deliberately raises no deviation for it (edge modelling is descriptive).
/// A future session extending the reference corpus with a new metadata type
/// should extend this list rather than assume it is exhaustive.
const METADATA_TARGET_TYPES: [&str; 5] = [
    "casenotes",
    "casedetails",
    "timestamps",
    "tool",
    "clientconnectiondetails",
];

/// Classify one predicate/subject-types pair into a [`GraphEdge`]'s kind.
///
/// `local_name` is the predicate's local name (post-namespace-stripping, so
/// generation spelling differences are already gone). `subject_types` are the
/// full `rdf:type` IRIs of the object asserting the edge — needed only to
/// disambiguate `target`, whose meaning depends on who asserts it rather than
/// on the predicate alone.
fn classify_edge(local_name: &str, subject_types: &[Arc<str>]) -> EdgeKind {
    match local_name {
        "dataStream" => EdgeKind::DataStream,
        "dependentStream" => EdgeKind::DependentStream,
        "stored" => EdgeKind::StoredIn,
        "target" => {
            let is_metadata_subject = subject_types.iter().any(|t| {
                let name = crate::container::local_name(t).to_lowercase();
                METADATA_TARGET_TYPES.contains(&name.as_str())
            });
            if is_metadata_subject {
                EdgeKind::Describes
            } else {
                // The image -> map -> stream data path (Map, ImageStream, or
                // pre-standard's `stream` asserting `target`). Deliberately
                // not `Describes` — see `EdgeKind`'s documentation. Also
                // deliberately not `Other`: this is a modelled relationship,
                // not an unrecognised predicate.
                EdgeKind::TargetStream
            }
        }
        other => EdgeKind::Other(other.to_string()),
    }
}

/// The prefix and namespace for a predicate, when it is not an AFF4 term.
///
/// Returns `(None, None)` for the AFF4 vocabulary itself: qualifying every
/// standard predicate would be noise, and the point is to make extensions
/// visible.
fn namespace_of(iri: &str, graph: &Graph) -> (Option<String>, Option<String>) {
    let Some((namespace, _)) = split_namespace(iri) else {
        return (None, None);
    };

    // A term in any AFF4 vocabulary is a standard term, not a vendor
    // extension. AFF4-L v1.0-ALPHA §4.1 introduces a second namespace and
    // permits a reader to honor either, which is what including it here does.
    if crate::lexicon::is_known_namespace(namespace) {
        return (None, None);
    }

    let prefix = graph
        .prefixes()
        .iter()
        .find(|(_, bound)| bound == namespace)
        .map(|(name, _)| name.clone());

    (prefix, Some(namespace.to_owned()))
}

/// Split an IRI into its namespace and local name at the last `#` or `/`.
fn split_namespace(iri: &str) -> Option<(&str, &str)> {
    let cut = iri.rfind(['#', '/'])?;
    Some((&iri[..=cut], &iri[cut + 1..]))
}

/// Read a value as a digest, if its datatype names a hash algorithm.
fn as_stored_hash(value: &Value, predicate: &str) -> Option<StoredHash> {
    let datatype = value.datatype()?;
    let algorithm = HashAlgorithm::from_datatype(datatype);

    // Only treat it as a hash when the datatype is a recognised algorithm;
    // an `Other` datatype is far more likely to be an ordinary literal.
    if matches!(algorithm, HashAlgorithm::Other(_)) {
        return None;
    }

    Some(StoredHash {
        algorithm,
        hex: value.lexical().to_string(),
        predicate: predicate.to_string(),
    })
}

/// Whether a datatype IRI names a timestamp, in either spelling.
///
/// `xsd:dateTime` is the defined type; `xsd:datetime` is the lowercase form
/// pyaff4 writes, which appears 40 times across the corpus.
fn is_timestamp_datatype(datatype: Option<&str>) -> bool {
    matches!(
        datatype.and_then(|d| d.rsplit_once('#')),
        Some((_, "dateTime" | "datetime"))
    )
}

/// The last path component of a segment name.
///
/// Segment names embed the owning object's percent-escaped ARN — ~60
/// characters of GUID before anything that distinguishes one member from
/// another. The tail is the part that identifies the segment; the full name
/// stays available from the volume itself.
fn tail_of(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Tally segment names by kind, most numerous first.
///
/// Ties break by the fixed order of [`SegmentKind`] rather than by name, so
/// the same container always renders the same rows: a report that reorders
/// itself between runs is not something an examiner can cite.
fn segment_kinds(names: &[String]) -> Vec<SegmentKindCount> {
    // Every kind, in declaration order, so the tie-break is stable and adding
    // a variant cannot silently omit it from the tally.
    const ORDER: [SegmentKind; 9] = [
        SegmentKind::BevyData,
        SegmentKind::BevyIndex,
        SegmentKind::BlockHash,
        SegmentKind::MapStructure,
        SegmentKind::Metadata,
        SegmentKind::ContainerDescription,
        SegmentKind::Version,
        SegmentKind::LogicalFile,
        SegmentKind::Other,
    ];

    let mut counts: Vec<(usize, Option<&str>)> = vec![(0, None); ORDER.len()];
    // The map's members are few and individually meaningful — `map`, `idx`,
    // `mapPath` are three different things, not three of a kind — so they are
    // named in full rather than represented by one example.
    let mut map_members: Vec<&str> = Vec::new();

    for name in names {
        let kind = crate::zip::classify_segment(name);
        let slot = ORDER
            .iter()
            .position(|k| *k == kind)
            .unwrap_or(ORDER.len() - 1);
        counts[slot].0 += 1;

        if kind == SegmentKind::MapStructure {
            map_members.push(tail_of(name));
        }

        // Keep the alphanumerically greatest name. Bevies are numbered from
        // zero, so the *last* one shows how far the sequence runs; the first
        // is always `00000000` and understates the container. Compared whole,
        // so a container with several streams reports the last bevy of the
        // last stream rather than mixing names from different ones.
        if counts[slot].1.is_none_or(|seen| name.as_str() > seen) {
            counts[slot].1 = Some(name);
        }
    }

    map_members.sort_unstable();
    map_members.dedup();

    let mut rows: Vec<SegmentKindCount> = ORDER
        .iter()
        .zip(counts)
        .filter(|(_, (count, _))| *count > 0)
        .map(|(kind, (count, example))| SegmentKindCount {
            kind: *kind,
            count,
            example: if *kind == SegmentKind::MapStructure {
                map_members.join(", ")
            } else {
                tail_of(example.unwrap_or_default()).to_string()
            },
        })
        .collect();
    // Stable sort, so equal counts keep their `ORDER` position.
    rows.sort_by_key(|row| std::cmp::Reverse(row.count));
    rows
}

/// The local name of an IRI: the part after the last `#` or `/`.
fn local_name(iri: &str) -> String {
    iri.rsplit_once(['#', '/'])
        .map_or(iri, |(_, name)| name)
        .to_string()
}

/// Identify the generation, and the declared version where there is one.
fn identify(
    volume: &mut ZipVolume,
    deviations: &mut Vec<Deviation>,
) -> Result<(Generation, Option<ContainerVersion>)> {
    let path = volume.path().to_path_buf();

    if volume.has_segment(version::SEGMENT_NAME) {
        let bytes = volume.read_segment(version::SEGMENT_NAME)?;
        let locus = Locus::new(&path).segment(version::SEGMENT_NAME);

        // Propagates rather than falling through to namespace sniffing: a
        // container that misstates its own version is a finding.
        let declared = ContainerVersion::parse(&bytes, &locus)?;

        return match Generation::from_version(&declared) {
            Some(generation) => Ok((generation, Some(declared))),
            None => Err(Error::unsupported(
                Feature::Generation {
                    named: format!("{}.{}", declared.major, declared.minor),
                },
                format!(
                    "{} declares version {}.{}; this build implements \
                     AFF4 Standard v1.0 and v1.1",
                    path.display(),
                    declared.major,
                    declared.minor
                ),
            )),
        };
    }

    // No version.txt: a pre-standard dialect. Which one is decided by the
    // `aff4:` namespace in the metadata.
    if !volume.has_segment(METADATA_SEGMENT) {
        return Err(Error::not_aff4(&path, NotAff4Reason::NoMetadata));
    }

    let bytes = volume.read_segment(METADATA_SEGMENT)?;
    let text = String::from_utf8_lossy(&bytes);
    let locus = Locus::new(&path).segment(METADATA_SEGMENT);

    let Some(namespace) = aff4_namespace(&text) else {
        return Err(Error::malformed(
            locus,
            format!(
                "{METADATA_SEGMENT} declares no aff4: prefix, so the container \
                 generation cannot be determined"
            ),
        ));
    };

    match Generation::from_namespace(&namespace) {
        Some(generation) => {
            let _ = deviations; // Namespace detection produces none today.
            Ok((generation, None))
        }
        None => Err(Error::not_aff4(
            &path,
            NotAff4Reason::UnknownNamespace { found: namespace },
        )),
    }
}

/// Extract the IRI bound to the `aff4:` prefix from Turtle source.
///
/// A deliberately narrow scan rather than a parse: generation detection has to
/// happen *before* the RDF layer runs, since the vocabulary it needs depends on
/// the answer. `@prefix` directives are simple enough to read directly, and a
/// container whose prefix line is malformed is reported rather than guessed at.
fn aff4_namespace(turtle: &str) -> Option<String> {
    for line in turtle.lines() {
        let line = line.trim();
        // Turtle allows both `@prefix` and SPARQL-style `PREFIX`.
        let rest = line
            .strip_prefix("@prefix")
            .or_else(|| line.strip_prefix("@PREFIX"))
            .or_else(|| line.strip_prefix("PREFIX"))
            .or_else(|| line.strip_prefix("prefix"))?
            .trim_start();

        let Some(rest) = rest.strip_prefix("aff4:") else {
            continue;
        };
        let rest = rest.trim_start();

        if let Some(open) = rest.find('<')
            && let Some(close) = rest[open..].find('>')
        {
            return Some(rest[open + 1..open + close].to_string());
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::lexicon::{LEGACY_NAMESPACE, STANDARD_NAMESPACE};
    use std::io::Write;
    use std::path::PathBuf;

    /// The AFF4-L v1.0-ALPHA §6.1 size threshold is the binary gibibyte, and it
    /// is inclusive.
    ///
    /// Tested against the constant rather than a fixture: a container
    /// exercising it would have to declare an actual gibibyte, and the whole
    /// content of the rule is which number the comparison uses and which side
    /// of it a stream of exactly that size falls on. The clause writes "1GiB",
    /// so a decimal gigabyte here would report conforming containers and pass
    /// departing ones between the two values.
    #[test]
    fn the_zip_segment_cap_is_an_inclusive_gibibyte() {
        // The comparison the checker makes, over the sizes either side of it.
        let reported = |size: u64| size >= ZIP_SEGMENT_CAP;

        assert_eq!(ZIP_SEGMENT_CAP, 1_073_741_824, "the binary gibibyte");
        assert!(reported(1_073_741_824), "exactly a gibibyte");
        assert!(reported(2_000_000_000), "beyond it");
        assert!(!reported(1_073_741_823), "one byte short");
        assert!(
            !reported(1_000_000_000),
            "a decimal gigabyte is under the cap"
        );
        assert!(!reported(0), "an empty stream");
    }

    /// The two methods AFF4-L v1.0-ALPHA §6.1 permits, and the ones it does not.
    ///
    /// The values are ZIP's own, so naming them here is what keeps the check
    /// from drifting: 8 is Deflate and 9 is Deflate64, which the clause does not
    /// name and a reader built to it need not support.
    #[test]
    fn only_stored_and_deflate_are_permitted_methods() {
        let permitted =
            |method: u16| method == crate::zip::METHOD_STORED || method == METHOD_DEFLATE;
        assert!(permitted(0), "Stored");
        assert!(permitted(8), "Deflate");
        assert!(!permitted(9), "Deflate64");
        assert!(!permitted(12), "BZIP2");
        assert!(!permitted(14), "LZMA");
        assert!(!permitted(93), "Zstandard");
    }

    /// Build a synthetic container. The one sanctioned use of a ZIP writer:
    /// it creates a throwaway archive and never touches evidence.
    #[allow(clippy::disallowed_types, clippy::disallowed_methods)]
    fn synth(members: &[(&str, &[u8])]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.aff4");
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .set_raw_comment(VOLUME.as_bytes().to_vec().into_boxed_slice())
            .unwrap();
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in members {
            writer.start_file(*name, opts).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
        (dir, path)
    }

    const VOLUME: &str = "aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044";

    fn turtle_with(namespace: &str) -> Vec<u8> {
        format!("@prefix aff4:  <{namespace}> .\n@prefix rdf: <http://x#> .\n").into_bytes()
    }

    #[test]
    fn identifies_standard_v1_0() {
        let (_d, path) = synth(&[("version.txt", b"major=1\nminor=0\ntool=Evimetry 2.2.0\n")]);
        let c = Container::open(&path).unwrap();
        assert_eq!(c.generation(), Generation::Standard10);
        assert_eq!(c.version().unwrap().tool.as_deref(), Some("Evimetry 2.2.0"));
        assert_eq!(c.lexicon().chunk_size, "chunkSize");
    }

    #[test]
    fn identifies_standard_v1_1() {
        let (_d, path) = synth(&[("version.txt", b"major=1\nminor=1\ntool=pyaff4\n")]);
        let c = Container::open(&path).unwrap();
        assert_eq!(c.generation(), Generation::PyAff4Logical);
    }

    /// A pre-standard container is detected accurately, then declined.
    ///
    /// No `version.txt` means the container predates the standard, and no
    /// specification this tool cites describes one. Reading it would be
    /// reverse engineering presented as conformance, so it is named and
    /// refused. The corpus `AFF4PreStd/*.af4` fixtures take this path.
    #[test]
    fn a_pre_standard_container_is_unsupported_not_malformed() {
        for namespace in [LEGACY_NAMESPACE, STANDARD_NAMESPACE] {
            let (_d, path) = synth(&[(METADATA_SEGMENT, &turtle_with(namespace))]);
            let err = Container::open(&path).unwrap_err();

            assert!(matches!(err, Error::Unsupported { .. }), "{err}");
            assert!(
                !err.is_integrity_finding(),
                "an unsupported generation says nothing about evidence integrity"
            );
            assert_eq!(err.exit_code(), 6);
            assert!(
                err.to_string().contains("pre-standard"),
                "the container must be named, not merely refused: {err}"
            );
        }
    }

    /// Either pre-standard namespace resolves to Legacy: neither is supported,
    /// so telling the two dialects apart would give one outcome two names.
    #[test]
    fn either_pre_standard_namespace_is_legacy() {
        for namespace in [LEGACY_NAMESPACE, STANDARD_NAMESPACE] {
            assert_eq!(
                Generation::from_namespace(namespace),
                Some(Generation::Legacy)
            );
        }
        assert!(!Generation::Legacy.is_supported());
    }

    /// Every entry point opens a v2.1 container.
    ///
    /// `conformance` admitted v2.1 first, to report what it could not evaluate
    /// while its identity rules were unimplemented. With those rules in place
    /// a v2.1 container's members resolve and its files are identifiable, so
    /// `info` and `verify` read one too. What is still unevaluated stays a
    /// coverage gap, which is a claim about this build rather than about the
    /// evidence.
    #[test]
    fn every_entry_point_opens_a_v2_1_container() {
        let (_d, path) = synth(&[("version.txt", b"major=2\nminor=1\ntool=aff4tools-test\n")]);

        let container = Container::open_for_conformance(&path)
            .expect("conformance reads v2.1 to report what it could not check");
        assert_eq!(container.generation(), Generation::Aff4L10);

        assert_eq!(
            Container::open_without_graph(&path)
                .expect("verify reads v2.1")
                .generation(),
            Generation::Aff4L10
        );
    }

    /// A pre-standard container is still declined by every entry point, and
    /// declining is not a claim that the evidence is damaged.
    #[test]
    fn a_pre_standard_container_is_declined_everywhere() {
        let (_d, path) = synth(&[(METADATA_SEGMENT, &turtle_with(LEGACY_NAMESPACE))]);

        for opened in [
            Container::open(&path).err(),
            Container::open_without_graph(&path).err(),
            Container::open_for_conformance(&path).err(),
        ] {
            let err = opened.expect("a pre-standard container is declined");
            assert!(matches!(err, Error::Unsupported { .. }), "{err}");
            assert!(!err.is_integrity_finding());
        }
    }

    /// The scan carries coverage alongside deviations, and the two are
    /// separate claims: a deviation is an observed departure, an unevaluated
    /// rule is an absence of evidence. A v2.1 scan finding no deviations does
    /// not mean the container conforms — almost none of its rules were checked.
    #[test]
    fn a_scan_reports_coverage_separately_from_deviations() {
        let (_d, path) = synth(&[
            ("version.txt", b"major=2\nminor=1\ntool=aff4tools-test\n"),
            (METADATA_SEGMENT, &turtle_with(STANDARD_NAMESPACE)),
        ]);
        let mut container = Container::open_for_conformance(&path).unwrap();
        let scan = container.deviations_only().unwrap();

        assert_eq!(scan.generation, Generation::Aff4L10);
        assert!(
            !scan.coverage.is_complete(),
            "a v2.1 scan evaluates almost none of the rules in scope"
        );
        assert!(
            scan.coverage.has_unevaluated_must(),
            "binding rules went unevaluated, so conformance was not shown"
        );
    }

    /// Neither gate admits a pre-standard container. No document aff4tools
    /// cites describes one, so there is no rule set to report coverage against.
    #[test]
    fn no_gate_opens_a_pre_standard_container() {
        let (_d, path) = synth(&[(METADATA_SEGMENT, &turtle_with(LEGACY_NAMESPACE))]);

        for opened in [
            Container::open(&path).err(),
            Container::open_without_graph(&path).err(),
            Container::open_for_conformance(&path).err(),
        ] {
            let err = opened.expect("pre-standard is refused by every entry point");
            assert!(matches!(err, Error::Unsupported { .. }), "{err}");
        }
    }

    /// A future standard version is intact, not damaged.
    #[test]
    fn a_future_version_is_unsupported_not_malformed() {
        let (_d, path) = synth(&[("version.txt", b"major=1\nminor=2\ntool=Future\n")]);
        let err = Container::open(&path).unwrap_err();
        assert!(matches!(err, Error::Unsupported { .. }), "{err}");
        assert!(!err.is_integrity_finding());
        assert!(err.to_string().contains("1.2"), "{err}");
    }

    /// pyaff4 would silently fall through to namespace sniffing here.
    #[test]
    fn a_corrupt_version_file_is_malformed_not_a_fallback() {
        let (_d, path) = synth(&[
            ("version.txt", b"major=NOT_A_NUMBER\nminor=0\n"),
            (METADATA_SEGMENT, &turtle_with(LEGACY_NAMESPACE)),
        ]);
        let err = Container::open(&path).unwrap_err();
        assert!(
            err.is_integrity_finding(),
            "a container misstating its version is a finding, not a fallback: {err}"
        );
        assert!(err.to_string().contains("version.txt"), "{err}");
    }

    #[test]
    fn no_metadata_and_no_version_is_not_aff4() {
        let (_d, path) = synth(&[("random.txt", b"hello")]);
        let err = Container::open(&path).unwrap_err();
        assert!(matches!(
            err,
            Error::NotAff4 {
                reason: NotAff4Reason::NoMetadata,
                ..
            }
        ));
    }

    #[test]
    fn an_unrecognised_namespace_is_not_aff4() {
        let (_d, path) = synth(&[(METADATA_SEGMENT, &turtle_with("http://example.com/other#"))]);
        let err = Container::open(&path).unwrap_err();
        match err {
            Error::NotAff4 {
                reason: NotAff4Reason::UnknownNamespace { found },
                ..
            } => assert_eq!(found, "http://example.com/other#"),
            other => panic!("expected UnknownNamespace, got {other}"),
        }
    }

    #[test]
    fn metadata_without_an_aff4_prefix_is_malformed() {
        let (_d, path) = synth(&[(METADATA_SEGMENT, b"@prefix rdf: <http://x#> .\n")]);
        let err = Container::open(&path).unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    #[test]
    fn reads_the_metadata_segment() {
        // A supported generation: a pre-standard container is declined at
        // open, so it cannot be used to exercise the metadata reader.
        let body = turtle_with(STANDARD_NAMESPACE);
        let (_d, path) = synth(&[
            ("version.txt", b"major=1\nminor=0\ntool=test\n".as_slice()),
            (METADATA_SEGMENT, &body),
        ]);
        let mut c = Container::open(&path).unwrap();
        assert_eq!(c.metadata_bytes().unwrap(), body);
    }

    #[test]
    fn missing_metadata_is_reported_when_requested() {
        let (_d, path) = synth(&[("version.txt", b"major=1\nminor=0\n")]);
        let mut c = Container::open(&path).unwrap();
        let err = c.metadata_bytes().unwrap_err();
        assert!(matches!(
            err,
            Error::NotAff4 {
                reason: NotAff4Reason::NoMetadata,
                ..
            }
        ));
    }

    /// Deviations found by the storage layer must survive into the container.
    #[test]
    fn carries_storage_layer_deviations_forward() {
        // synth() always NUL-pads the comment, as Evimetry does.
        let (_d, path) = synth(&[("version.txt", b"major=1\nminor=0\n")]);
        let c = Container::open(&path).unwrap();
        assert_eq!(c.volume().arn().as_str(), VOLUME);
        // The synthetic comment has no NUL, so no deviation is expected here;
        // the assertion is that the list is wired through at all.
        assert_eq!(c.deviations().len(), c.volume().deviations().len());
    }

    /// Timestamps on unmodelled predicates are read, not skipped.
    ///
    /// This tolerates `xsd:datetime` and `xsd:dateTime`.
    #[test]
    fn timestamps_on_unmodelled_predicates_are_read_and_never_flagged() {
        let turtle = br#"@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044/f> a aff4:FileImage ;
    aff4:birthTime "2018-09-17T13:42:20+10:00"^^xsd:datetime ;
    aff4:lastWritten "2018-09-17T13:42:20+10:00"^^xsd:dateTime ;
    aff4:recordChanged "2016-12-07T03:40:14.127Z"^^xsd:dateTime .
"#;
        let (_d, path) = synth(&[
            ("version.txt", b"major=1\nminor=1\ntool=pyaff4\n"),
            (METADATA_SEGMENT, turtle),
        ]);

        let summary = Container::open(&path).unwrap().summarize().unwrap();
        let object = summary
            .objects
            .iter()
            .find(|o| o.arn.as_str().ends_with("/f"))
            .expect("the file image must be summarised");

        // The lexical form is preserved verbatim, whichever way it was typed.
        for predicate in ["birthTime", "lastWritten", "recordChanged"] {
            let property = object
                .properties
                .iter()
                .find(|p| &*p.name == predicate)
                .unwrap_or_else(|| panic!("{predicate} must be read: {:#?}", object.properties));
            assert!(
                property.value.lexical().starts_with("201"),
                "{predicate} must keep its lexical form: {property:#?}"
            );
        }

        assert!(
            summary.deviations.is_empty(),
            "neither datetime spelling is a finding: {:#?}",
            summary.deviations
        );
    }

    /// `broken-dedupe.aff4`'s `aff4:sha512:<digest>` subjects index
    /// deduplicated blocks by content hash. They are a deliberate pyaff4
    /// extension, not damage, but they name content rather than resources — so
    /// they are counted under their own deviation kind rather than listed as
    /// objects or reported as corruption. That container has 437 of them; one
    /// line each would bury every other finding.
    #[test]
    fn content_addressed_subjects_are_aggregated_not_listed() {
        let turtle = br"@prefix aff4: <http://aff4.org/Schema#> .
<aff4:sha512:0053741970ecb5d8> aff4:size 10 .
<aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044/real> a aff4:ImageStream .
";
        let (_d, path) = synth(&[
            ("version.txt", b"major=1\nminor=1\n"),
            (METADATA_SEGMENT, turtle),
        ]);

        let summary = Container::open(&path).unwrap().summarize().unwrap();
        assert_eq!(summary.objects.len(), 1, "the valid subject must survive");

        let dedupe: Vec<_> = summary
            .deviations
            .iter()
            .filter(|d| d.kind == DeviationKind::ContentAddressedSubject)
            .collect();
        assert_eq!(
            dedupe.len(),
            1,
            "content-addressed subjects must be summarised in one entry: {:#?}",
            summary.deviations
        );
        assert!(
            dedupe[0].detail.contains('1'),
            "the count must be stated: {}",
            dedupe[0].detail
        );
    }

    #[test]
    fn the_segment_tally_counts_every_member_exactly_once() {
        let names: Vec<String> = [
            "container.description",
            "information.turtle",
            "version.txt",
            // Deliberately not in ascending order: taking the first member
            // seen would pass a sorted list by accident.
            "vol/data/00000002",
            "vol/data/00000000",
            "vol/data/00000001",
            "vol/data/00000000.index",
            "vol/map",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let rows = segment_kinds(&names);
        let total: usize = rows.iter().map(|r| r.count).sum();
        assert_eq!(
            total,
            names.len(),
            "every member must be counted: {rows:#?}"
        );

        let bevies = rows
            .iter()
            .find(|r| r.kind == SegmentKind::BevyData)
            .expect("bevy row");
        assert_eq!(bevies.count, 3);
        assert_eq!(
            bevies.example, "00000002",
            "the example must be the alphanumerically last bevy, so the row \
             shows how far the sequence runs"
        );
    }

    /// `map`, `idx`, and `mapPath` are three different things, so the row
    /// names them all rather than showing one as representative.
    #[test]
    fn the_map_row_names_every_member_on_one_line() {
        let names: Vec<String> = ["vol/map", "vol/idx", "vol/mapPath", "information.turtle"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        let rows = segment_kinds(&names);
        let map = rows
            .iter()
            .find(|r| r.kind == SegmentKind::MapStructure)
            .expect("map row");
        assert_eq!(map.count, 3);
        assert_eq!(map.example, "idx, map, mapPath");
    }

    /// The ARN prefix is ~60 characters of GUID and identifies nothing the
    /// row does not already say.
    #[test]
    fn examples_carry_no_arn_path() {
        let stream = "aff4%3A%2F%2F1bc40be7-de68-4e77-9e11-eec997aa5304";
        let names: Vec<String> = [format!("{stream}/data/00008213")].to_vec();

        let rows = segment_kinds(&names);
        assert_eq!(rows[0].example, "00008213");
    }

    /// Equal counts must not reorder between runs: a report an examiner cites
    /// has to render the same way every time.
    #[test]
    fn the_segment_tally_orders_by_count_then_by_kind() {
        let names: Vec<String> = [
            "vol/map",
            "container.description",
            "information.turtle",
            "vol/data/00000000",
            "vol/data/00000000.index",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let first = segment_kinds(&names);
        assert!(
            first.windows(2).all(|w| w[0].count >= w[1].count),
            "counts must descend: {first:#?}"
        );

        // Every row here is a single member, so only the fixed kind order
        // decides the result.
        let kinds: Vec<SegmentKind> = first.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            vec![
                SegmentKind::BevyData,
                SegmentKind::BevyIndex,
                SegmentKind::MapStructure,
                SegmentKind::Metadata,
                SegmentKind::ContainerDescription,
            ]
        );

        let mut shuffled = names.clone();
        shuffled.reverse();
        let second = segment_kinds(&shuffled);
        let second_kinds: Vec<SegmentKind> = second.iter().map(|r| r.kind).collect();
        assert_eq!(kinds, second_kinds, "member order must not change the rows");
    }

    #[test]
    fn extracts_the_aff4_namespace_from_prefix_forms() {
        assert_eq!(
            aff4_namespace("@prefix aff4:  <http://aff4.org/Schema#> .").as_deref(),
            Some(STANDARD_NAMESPACE)
        );
        assert_eq!(
            aff4_namespace("PREFIX aff4: <http://afflib.org/2009/aff4#>").as_deref(),
            Some(LEGACY_NAMESPACE)
        );
        // Other prefixes are skipped until aff4: is found.
        assert_eq!(
            aff4_namespace("@prefix rdf: <http://r#> .\n@prefix aff4: <http://a#> .").as_deref(),
            Some("http://a#")
        );
        assert_eq!(
            aff4_namespace("@prefix rdf: <http://r#> .").as_deref(),
            None
        );
        assert_eq!(aff4_namespace("").as_deref(), None);
    }
}

/// How many bitstream candidates [`Container::summarize_brief`] retains.
///
/// `report::write_brief_bitstream` prints `BRIEF_BITSTREAM_LIMIT` (3) of them
/// and then a count of the remainder, which comes from
/// [`ContainerSummary::counts`] rather than the list. The cap is larger than 3
/// so the report keeps some slack — it filters candidates again by whether they
/// carry a qualifying hash, and it disambiguates identities against the shown
/// set — but it is a constant, so an AFF4-L container of ten million files
/// retains a handful rather than ten million.
///
/// **This is the whole point of `summarize_brief`.** Without a cap, a container
/// whose every object is a `FileImage` retains every object and saves nothing.
const BRIEF_CANDIDATE_CAP: usize = 64;

/// Whether `--brief` could render this object, given how many are already kept.
///
/// Three kinds are retained:
///
/// - **Bitstream candidates** — image-typed objects carrying a *qualifying
///   hash*, capped at [`BRIEF_CANDIDATE_CAP`]. The hash test matters: it
///   mirrors `report::write_brief_bitstream`, which drops any candidate without
///   `hash` or `blockMapHash`. Without it the cap fills with the container's
///   first 64 objects — on an AFF4-L acquisition those are `FolderImage`s,
///   which are never hashed — and the `Bitstream` section renders empty.
/// - **Type carriers** — one object per distinct declared type, uncapped but
///   bounded by the vocabulary. `describe_content`'s fallback branch names the
///   types of image-typed objects, so dropping the last object of some type
///   would silently drop that type from `Content Type:`.
/// - **Case-metadata carriers** — the `Case:` line reads three specific
///   predicates, and a container carries a handful of such objects.
fn brief_renders(
    object: &Aff4Object,
    kept_candidates: usize,
    seen_types: &mut HashSet<Arc<str>>,
) -> bool {
    let is_image_typed = object.role.is_image()
        || matches!(object.role, ObjectRole::Map | ObjectRole::ImageStream)
        || object
            .types
            .iter()
            .any(|t| matches!(local_name(t).as_str(), "Image" | "image"));

    if is_image_typed {
        // A type this container has not shown before must be kept whatever the
        // cap says, or `Content Type:` loses it.
        let novel = object.types.iter().any(|t| !seen_types.contains(t));
        if novel {
            for t in &object.types {
                seen_types.insert(Arc::clone(t));
            }
            return true;
        }
        if has_bitstream_hash(object) {
            return kept_candidates < BRIEF_CANDIDATE_CAP;
        }
        return false;
    }

    object.properties.iter().any(|p| {
        BRIEF_CASE_PREDICATES
            .iter()
            .any(|c| p.name.eq_ignore_ascii_case(c))
    })
}

/// Whether `--brief`'s `Bitstream` section would show this object's digests.
///
/// Record one object in the running counts, by role and by storage form.
///
/// One entry point so a caller cannot add the role count and forget the
/// storage count, matching the pattern `report_any_generation` uses for the
/// checkers.
fn observe_object(object: &Aff4Object, counts: &mut crate::model::ObjectCounts) {
    counts.observe(&object.role, has_bitstream_hash(object));
    count_storage_form(object, counts);
}

/// Count which AFF4-L v1.0-ALPHA §6 form holds one file's bytes.
///
/// Only `FileImage` objects are counted. A folder has no content, and the
/// streams and maps that carry content are not files — counting a shared stream
/// beside the files inside it would report the same bytes twice.
///
/// A file recording no form at all is counted as such rather than skipped. An
/// acquisition that could not read a file still records that it existed, and
/// the count is what lets a report say so instead of leaving the totals not
/// adding up.
fn count_storage_form(object: &Aff4Object, counts: &mut crate::model::ObjectCounts) {
    if !matches!(object.role, crate::model::ObjectRole::FileImage) {
        return;
    }
    // A content-free record: no size and no digest. `storage_form_of` would
    // report it as declaring nothing, which is true and is what `None` says
    // here — the distinction the report needs is between "no bytes stored" and
    // "bytes stored somewhere", not which error describes the first.
    if object.size.is_none() && object.hashes.is_empty() {
        counts.observe_storage(None);
        return;
    }
    let form = crate::storage_form::storage_form_of_with_reference(
        &object.types,
        object.has_resident_stream(),
        object.has_stream_reference(),
        &crate::error::Locus::new(""),
    )
    .ok();
    counts.observe_storage(form);
}

/// Mirrors the filter in `report::write_brief_bitstream`: a linear bitstream
/// hash or a block-map root, not any digest the object happens to carry.
fn has_bitstream_hash(object: &Aff4Object) -> bool {
    object
        .hashes
        .iter()
        .any(|h| h.predicate == "hash" || h.predicate == "blockMapHash")
}

/// The predicates `--brief`'s `Case:` line reads.
///
/// Mirrors `report::brief_case_line`. Kept here rather than shared because the
/// library must not depend on the binary's formatting; a mismatch would drop a
/// case field from brief output, so both lists are asserted equal by
/// `brief_case_predicates_match_the_report` in `tests/cli.rs`.
const BRIEF_CASE_PREDICATES: [&str; 3] = ["caseNumber", "evidenceNumber", "examiner"];

/// Settle every deferred reference against the completed subject set.
///
/// Called once the whole file is parsed, because a reference may name a subject
/// that appears later — deciding in-pass would report a forward reference as
/// dangling when it is not.
///
/// Symbolic streams (v1.0a §4.4) are described by the standard, not by the
/// container: `aff4://.../SymbolicStreamXX` and the zero/FF streams carry no
/// triples anywhere and are resolved by name, so an edge to one is well-formed.
fn resolve_deferred_references(
    deferred: Vec<DeferredReference>,
    described: &HashSet<Arc<str>>,
    locus: &Locus,
    deviations: &mut Vec<Deviation>,
) {
    for reference in deferred {
        if described.contains(&*reference.target) || is_symbolic_stream(&reference.target) {
            continue;
        }
        deviations.push(Deviation::new(
            locus
                .clone()
                .subject(&reference.subject)
                .predicate(&*reference.predicate),
            DeviationKind::DanglingReference,
            format!(
                "{} names {}, which no triple in this volume describes \
                 and which declares no aff4:stored pointing elsewhere; \
                 the reference cannot be resolved",
                reference.predicate, reference.target
            ),
        ));
    }
}

/// The deviation recorded for pyaff4's content-addressed dedupe subjects.
///
/// Counted rather than listed: `broken-dedupe.aff4` has 437, and one line each
/// would bury every other finding.
fn dedupe_subject_deviation(locus: &Locus, count: usize) -> Deviation {
    Deviation::new(
        locus.clone(),
        DeviationKind::ContentAddressedSubject,
        format!(
            "{count} content-addressed subject(s) of the form \
             aff4:sha512:<digest> index deduplicated blocks; they are not \
             AFF4 resource names and are not listed as objects"
        ),
    )
}

/// A local object's ARN, reduced to what the manifest comparison reads.
///
/// [`Container::deviations_only`] must remember every local ARN until the whole
/// file is parsed, because the volume's `aff4:contains` manifest may appear
/// after the objects it declares. Keeping a million [`Arn`]s to do so costs
/// ~0.16 GB in `String`s that duplicate ones the parser already interned.
///
/// This shares the parser's allocation and precomputes the one derived value
/// [`compare_manifest`] needs — the length of the volume prefix, for the
/// sub-resource test. `u32` because an ARN longer than 4 GB is not a thing a
/// container can contain.
#[derive(Debug)]
struct LocalArn {
    arn: Arc<str>,
    volume_len: u32,
}

impl LocalArn {
    fn as_str(&self) -> &str {
        &self.arn
    }

    /// The volume portion, as [`Arn::volume`] would return it.
    fn volume(&self) -> &str {
        let end = (self.volume_len as usize).min(self.arn.len());
        &self.arn[..end]
    }
}

/// A reference whose target may not have been parsed yet.
///
/// [`Container::deviations_only`] streams, so a `target` naming a subject later
/// in the file cannot be resolved when it is read. Holding the three strings
/// needed to report it — rather than the object it came from — lets the whole
/// object be dropped at the end of its iteration.
#[derive(Debug)]
struct DeferredReference {
    subject: String,
    predicate: Arc<str>,
    target: String,
}

/// Queue every reference `object` makes, to be resolved once all subjects are known.
///
/// The in-pass counterpart of [`report_object_dangling_references`]: same
/// predicates, same skip of literal-valued targets. The symbolic-stream and
/// membership tests happen at resolution time instead, because neither can be
/// decided before the subject set is complete.
fn defer_object_references(object: &Aff4Object, deferred: &mut Vec<DeferredReference>) {
    for property in &object.properties {
        if !REFERENCE_PREDICATES.contains(&&*property.name) {
            continue;
        }
        let Some(iri) = property.value.as_iri() else {
            continue; // A literal target is a different fault, not this one.
        };
        deferred.push(DeferredReference {
            subject: object.arn.as_str().to_string(),
            predicate: Arc::clone(&property.name),
            target: iri.to_string(),
        });
    }
}

/// Compare the volume's `aff4:contains` manifest against the local objects found.
///
/// The single implementation behind both [`build_manifest`] and
/// [`Container::deviations_only`]. Extracted rather than written twice: the two
/// commands must report the same disagreements about the same container, and a
/// second copy of these rules would be free to drift from this one.
///
/// `declared` is whether the volume makes an `aff4:contains` statement at all,
/// which is distinct from whether that statement names anything — see
/// [`build_manifest`]'s table. When no declaration exists there is nothing for
/// an object to disagree with, so no disagreement is recorded however many
/// objects were found.
///
/// Both directions use a [`HashSet`] rather than a scan. On a container whose
/// manifest names every object, the pairwise form is quadratic — at a million
/// objects that is 10^12 comparisons, which never finishes.
fn compare_manifest(
    manifest: &[String],
    declared: bool,
    local: &[LocalArn],
    volume: &Arn,
    locus: &Locus,
    deviations: &mut Vec<Deviation>,
) -> Vec<ManifestDisagreement> {
    let mut disagreements = Vec::new();
    if !declared {
        return disagreements;
    }

    let present: HashSet<&str> = local.iter().map(LocalArn::as_str).collect();
    let declared_set: HashSet<&str> = manifest.iter().map(String::as_str).collect();

    for arn in manifest {
        if present.contains(arn.as_str()) {
            continue;
        }
        disagreements.push(ManifestDisagreement {
            arn: arn.clone(),
            kind: ManifestIssue::DeclaredButAbsent,
        });
        deviations.push(Deviation::new(
            locus.clone().subject(volume.as_str()).predicate("contains"),
            DeviationKind::DanglingReference,
            format!(
                "the volume's manifest declares {arn}, which no object in this \
                 volume describes"
            ),
        ));
    }

    for arn in local {
        let text = arn.as_str();
        if text == volume.as_str() {
            continue; // The volume does not list itself.
        }
        if declared_set.contains(text) {
            continue;
        }
        // A sub-resource of a declared ARN (e.g. a BlockHashes object at
        // `<stream>/blockhash.sha1`), not a separate undeclared object.
        if declared_set.contains(arn.volume()) {
            continue;
        }
        disagreements.push(ManifestDisagreement {
            arn: text.to_string(),
            kind: ManifestIssue::PresentButUndeclared,
        });
        deviations.push(Deviation::new(
            locus.clone().subject(text),
            DeviationKind::UndeclaredObject,
            "this object is described here, but the volume's aff4:contains manifest never names it",
        ));
    }

    disagreements
}

/// What `report_missing_zip_segment_type` needs about the volume being read.
///
/// Grouped because all three are invariant across the whole streaming pass:
/// passing them individually made the call longer than the statement it
/// guards.
struct VolumeContext<'a> {
    /// The volume's own ARN, for resolving a member name from an ARN.
    volume_arn: &'a Arn,
    /// Every member name in the volume.
    segment_present: HashSet<&'a str>,
    /// Which ARN-to-segment rules the container's generation puts in force.
    mapping: crate::arn::NameMapping,
    /// Where to anchor a deviation.
    locus: &'a Locus,
    /// The open volume, for the checks that ask how a member is stored rather
    /// than whether it exists.
    ///
    /// AFF4-L v1.0-ALPHA §6.1 constrains the compression method and size of a
    /// ZIP segment storage stream, and neither is visible in the metadata: both
    /// are recorded in the ZIP central directory. Holding the volume keeps
    /// those checks reading the container rather than trusting what it says
    /// about itself.
    volume: &'a crate::zip::ZipVolume,
}

/// Summarize a volume's members by the role each name implies.
fn segment_summary(volume: &crate::zip::ZipVolume) -> SegmentSummary {
    SegmentSummary {
        count: volume.segment_names().len(),
        kinds: segment_kinds(volume.segment_names()),
    }
}

impl<'a> VolumeContext<'a> {
    /// Gather what the check needs from an open volume.
    ///
    /// The member names become a set rather than staying a slice:
    /// `report_missing_zip_segment_type` runs once per described subject, and a
    /// linear probe there would be quadratic on a container with tens of
    /// thousands of members.
    fn new(
        volume_arn: &'a Arn,
        volume: &'a crate::zip::ZipVolume,
        mapping: crate::arn::NameMapping,
        locus: &'a Locus,
    ) -> Self {
        Self {
            volume_arn,
            segment_present: volume.segment_names().iter().map(String::as_str).collect(),
            mapping,
            locus,
            volume,
        }
    }
}

/// A logical file whose bytes are a plain ZIP member but which omits
/// `aff4:zip_segment` (AFF4-L 2019 §3.8).
///
/// AFF4-L 2019 §3.8's recipe ends by adding the type "to indicate that it is
/// stored as a Zip Segment". Without it a reader dispatching on type finds
/// neither a
/// segment nor an `ImageStream`, and has nothing to read: `verify` declined
/// `unicode.aff4`'s `README.txt` for naming no data stream, though its bytes
/// were present and its recorded digests matched.
///
/// Deliberately narrow. It fires only when all of these hold, so that a
/// well-formed container of any other shape stays silent:
///
/// - the object is a `FileImage` — the type AFF4-L 2019 §3.8's recipe is about;
/// - it does not already declare `zip_segment`;
/// - it declares no `ImageStream` either, since a stream-backed file is
///   correctly typed and stores its bytes in bevies, not one member;
/// - a ZIP member sits at exactly the ARN's own path, which is what makes it
///   segment-stored rather than merely undescribed.
fn report_missing_zip_segment_type(
    object: &Aff4Object,
    volume: &VolumeContext,
    deviations: &mut Vec<Deviation>,
) {
    let VolumeContext {
        volume_arn,
        segment_present,
        mapping,
        locus,
        ..
    } = volume;
    if !declares_local_type(object, "FileImage") {
        return;
    }
    // Both spellings. The AFF4-L 2019 paper §3.8 writes `aff4:zip_segment`;
    // AFF4-L v1.0-ALPHA §6.1 writes `aff4:ZipSegment`. A container using the
    // spelling its own document defines is correctly typed, and reporting it
    // as untyped would accuse a conforming writer.
    if declares_local_type(object, "zip_segment")
        || declares_local_type(object, "ZipSegment")
        || declares_local_type(object, "ImageStream")
    {
        return;
    }

    // The bytes must actually be there. An object naming no member is a
    // different problem — an image with nothing to read — and reporting it as a
    // missing type would misdescribe it.
    let Some(member) = object.arn.member_name(volume_arn, *mapping) else {
        return;
    };
    if !segment_present.contains(member.as_str()) {
        return;
    }

    deviations.push(Deviation::new(
        (*locus).clone().subject(object.arn.as_str()),
        DeviationKind::MissingZipSegmentType,
        format!(
            "this file's bytes are stored as the ZIP member {member}, but its \
rdf:type list omits aff4:zip_segment, so a reader dispatching on type cannot \
tell where its content lives"
        ),
    ));
}

/// The four digests AFF4 Standard v1.0a §6.2 defines over a map's own segments.
///
/// `mapHash` covers the three concatenated; the others cover one segment each.
const MAP_SEGMENT_DIGESTS: [&str; 4] = ["mapPointHash", "mapIdxHash", "mapPathHash", "mapHash"];

/// Report a map that records no digest over its own segments.
///
/// AFF4 Standard v1.0a §6.2's map property table. **A map is the instruction
/// sheet for reassembling an image**, so a corrupted map yields a wrong image
/// while every stream digest still matches — the streams were never touched.
/// Without these digests the two cases are indistinguishable.
///
/// # What is not reported
///
/// A map carrying *some* of the four is not reported. The clause defines four
/// properties without saying an implementation must write all of them, and one
/// digest over the `map` segment already makes corruption detectable. Demanding
/// the complete set would report conforming containers.
///
/// A subject that is not a map is not reported, obviously — but neither is one
/// whose map segments are absent. That is a different finding, an image with
/// nothing to read, and reporting it here would misdescribe it.
fn report_map_segment_digests(
    object: &Aff4Object,
    volume: &VolumeContext,
    deviations: &mut Vec<Deviation>,
) {
    if !declares_local_type(object, "Map") {
        return;
    }

    // The map's own segments must actually be present. A Map subject naming no
    // member of this volume describes storage held elsewhere, and this check
    // has nothing to say about it.
    let Some(base) = object.arn.member_name(volume.volume_arn, volume.mapping) else {
        return;
    };
    if !volume
        .segment_present
        .contains(format!("{base}/{}", crate::map::MAP_SEGMENT).as_str())
    {
        return;
    }

    if object
        .hashes
        .iter()
        .any(|hash| MAP_SEGMENT_DIGESTS.contains(&hash.predicate.as_str()))
    {
        return;
    }

    deviations.push(Deviation::new(
        volume.locus.clone().subject(object.arn.as_str()),
        DeviationKind::MissingMapSegmentDigest,
        format!(
            "this map records no digest over its own segments, so a corrupted \
map would reassemble the image wrongly while every stream digest still \
matched; AFF4 Standard v1.0a §6.2 defines {} for this",
            MAP_SEGMENT_DIGESTS
                .iter()
                .map(|p| format!("aff4:{p}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ));
}

/// Every check that applies whatever generation wrote the container.
///
/// Both cite the AFF4 Standard v1.0a, which governs the ZIP structure and map
/// rules of every generation — a 1.1 or 2.1 container layers its logical
/// vocabulary above that base rather than replacing it. One entry point so a
/// caller cannot add one and forget the other, matching [`report_v21`].
fn report_any_generation(
    object: &Aff4Object,
    volume: &VolumeContext,
    deviations: &mut Vec<Deviation>,
) {
    report_missing_zip_segment_type(object, volume, deviations);
    report_map_segment_digests(object, volume, deviations);
}

/// Every AFF4-L v1.0-ALPHA check one described object is subject to.
///
/// The two halves are separate because they answer different questions —
/// what an object is called, and how that name is recorded — but they always
/// run together, so one entry point keeps a caller from adding one and
/// forgetting the other.
fn report_v21(object: &Aff4Object, volume: &VolumeContext, deviations: &mut Vec<Deviation>) {
    report_v21_identity(object, volume, deviations);
    report_v21_names(object, volume, deviations);
    report_v21_namespaces(object, volume, deviations);
    report_v21_storage_form(object, volume, deviations);
}

/// The largest in-metadata storage stream AFF4-L v1.0-ALPHA §6.2 permits.
///
/// Its "1Kb" is read as 1024 bytes, the binary kilobyte the rest of the format
/// uses for chunk and bevy sizes.
const RESIDENT_STREAM_CAP: u64 = 1024;

/// Report a stream whose declared storage form names no bytes, or names two
/// (AFF4-L v1.0-ALPHA §6).
///
/// That section makes the `rdf:type` list the statement of where a stream's
/// content is, so a reader selects its access path from the declared type. Both
/// failures leave such a reader with nothing to act on: no form names no place
/// to look, and two forms name two places with no way to tell which is
/// authoritative.
///
/// **Neither is repaired by searching.** Bytes found somewhere other than where
/// the container said would be some other stream's, and a verification reported
/// over them would be a clean result computed on the wrong data. So the finding
/// is recorded and the file's digests go unverified, which the `verify` report
/// states in full.
///
/// Reported per subject. One self-contradicting object must not suppress the
/// findings about the rest, which is the rule `build_object` already follows
/// for a subject that is not a valid ARN.
fn report_v21_storage_form(
    object: &Aff4Object,
    volume: &VolumeContext,
    deviations: &mut Vec<Deviation>,
) {
    // AFF4-L v1.0-ALPHA §6 governs v2.1 containers, which are the ones whose
    // ARNs map to member names literally. An earlier generation's file image
    // is placed by the AFF4-L 2019 rules and is not measured against this
    // clause.
    if volume.mapping != crate::arn::NameMapping::Literal {
        return;
    }

    // Only a logical file carries a primary stream to place. Folders hold no
    // bytes, and the volume, case metadata, and block-hash objects are not
    // streams at all.
    if !matches!(object.role, crate::model::ObjectRole::FileImage) {
        return;
    }

    // A file recorded without content at all. An acquisition that could not
    // read a file still records that the file existed, with its name, times,
    // and mode, and stores no bytes for it — so there is no storage form to
    // declare and nothing here to check.
    //
    // **This is a completeness finding, not a conformance one, and the
    // acquisition already makes it.** Every such path is listed individually
    // with its reason in the SKIPPED report, which also raises the strict exit
    // code. Reporting it a second time as a self-contradicting container would
    // describe an honest record of an unreadable file as a malformed one.
    //
    // The shape is unambiguous: no `aff4:size` and no digest. A file whose
    // bytes were stored always carries both, whichever form holds them.
    if object.size.is_none() && object.hashes.is_empty() {
        return;
    }

    let types: Vec<&str> = object.types.iter().map(|t| &**t).collect();
    let form = match crate::storage_form::storage_form_of_with_reference(
        &types,
        object.has_resident_stream(),
        object.has_stream_reference(),
        volume.locus,
    ) {
        Ok(form) => form,
        Err(error) => {
            // `storage_form_of` distinguishes the two cases in its message; the
            // kind is chosen from which one it reported.
            let text = error.to_string();
            let kind = if text.contains("ambiguous") {
                DeviationKind::AmbiguousStorageForm
            } else {
                DeviationKind::StorageFormNotFound
            };
            deviations.push(Deviation::new(
                volume.locus.clone().subject(object.arn.as_str()),
                kind,
                text,
            ));
            return;
        }
    };

    // A resident stream whose literal is not valid base64. The form is
    // declared and the bytes are not recoverable from it, which is the same
    // failure as a missing member and is reported as such.
    if form == crate::storage_form::StorageForm::InMetadata
        && object.resident_bytes(volume.locus).is_err()
    {
        deviations.push(Deviation::new(
            volume.locus.clone().subject(object.arn.as_str()),
            DeviationKind::StorageFormNotFound,
            "declared an in-metadata storage stream whose aff4l:dataStream literal is not valid base64, so the bytes AFF4-L v1.0-ALPHA §6.2 says are stored here cannot be recovered".to_owned(),
        ));
        return;
    }

    // A declared ZIP segment whose member is absent. The other three forms are
    // resolved by `verify`, which reads them; this check is the one an
    // inspection of the metadata alone can make.
    // AFF4-L v1.0-ALPHA §6.2 caps the in-metadata form at one kilobyte. The
    // bytes are present and unambiguously this stream's, so the container is
    // read normally and the departure is reported: this says the writer chose
    // a form the standard forbids at that size, not that the evidence is
    // damaged.
    if form == crate::storage_form::StorageForm::InMetadata
        && let Ok(Some(bytes)) = object.resident_bytes(volume.locus)
        && bytes.len() as u64 > RESIDENT_STREAM_CAP
    {
        deviations.push(Deviation::new(
            volume.locus.clone().subject(object.arn.as_str()),
            DeviationKind::OversizedResidentStream,
            format!(
                "an in-metadata storage stream holds {} bytes, above the one-kilobyte cap AFF4-L v1.0-ALPHA §6.2 sets for the form",
                bytes.len()
            ),
        ));
    }

    // Both spellings are tried before concluding the bytes are absent. A v2.1
    // container should store the member under the unescaped ARN, and one that
    // escaped it anyway still holds the bytes — that departure is
    // `EscapedV21MemberName`, reported by its own check. Calling it missing
    // content as well would report one fault twice and misdescribe the second.
    if form == crate::storage_form::StorageForm::ZipSegment
        && let Some(member) = object.arn.member_name(volume.volume_arn, volume.mapping)
        && !volume.segment_present.contains(member.as_str())
        && !object
            .arn
            .member_name(volume.volume_arn, crate::arn::NameMapping::Escaped)
            .is_some_and(|escaped| volume.segment_present.contains(escaped.as_str()))
    {
        deviations.push(Deviation::new(
            volume.locus.clone().subject(object.arn.as_str()),
            DeviationKind::StorageFormNotFound,
            format!(
                "declared a ZIP segment storage stream, but the volume holds no                  member named {member:?}; AFF4-L v1.0-ALPHA §6.1 stores such a                  stream under the instance's own ARN"
            ),
        ));
    }

    if form == crate::storage_form::StorageForm::ZipSegment {
        report_zip_segment_stream(object, volume, deviations);
    }
}

/// The largest stream AFF4-L v1.0-ALPHA §6.1 says a ZIP segment should hold.
///
/// The clause writes "1GiB", so this is the binary gibibyte and not 10^9.
const ZIP_SEGMENT_CAP: u64 = 1 << 30;

/// The ZIP compression method meaning Deflate, the one AFF4-L v1.0-ALPHA §6.1
/// permits besides Stored.
const METHOD_DEFLATE: u16 = 8;

/// Report the AFF4-L v1.0-ALPHA §6.1 departures of one ZIP segment storage
/// stream.
///
/// Three requirements, and each is checked against a different source. The
/// compression method and the stream's size come from the ZIP central
/// directory, which is what the container *did* rather than what its metadata
/// says it did; the digest requirement is met or not by the metadata alone.
///
/// Called only for an object whose declared form is already known to be
/// [`StorageForm::ZipSegment`](crate::storage_form::StorageForm::ZipSegment),
/// so nothing here re-decides which form holds the bytes.
///
/// **Silent when the member cannot be found.** All three requirements are about
/// a stream that is stored, and this one is not: its absence is
/// `StorageFormNotFound`, which the caller already reports. Adding that the
/// missing bytes carry no digest and sit under no compression method would
/// state one fault three times — the same reason the caller declines to call
/// such an object untyped as well.
fn report_zip_segment_stream(
    object: &Aff4Object,
    volume: &VolumeContext,
    deviations: &mut Vec<Deviation>,
) {
    let locus = || volume.locus.clone().subject(object.arn.as_str());

    // Both spellings, matching the caller: a container that escaped the member
    // name still stored the bytes, and its compression and size are as much
    // this clause's business as a conforming one's.
    let stored = object
        .arn
        .member_name(volume.volume_arn, volume.mapping)
        .and_then(|member| volume.volume.member_storage(&member))
        .or_else(|| {
            object
                .arn
                .member_name(volume.volume_arn, crate::arn::NameMapping::Escaped)
                .and_then(|escaped| volume.volume.member_storage(&escaped))
        });
    let Some(stored) = stored else {
        return;
    };

    // The clause requires a linear digest of the stream.
    if object.hashes.is_empty() {
        deviations.push(Deviation::new(
            locus(),
            DeviationKind::MissingZipSegmentHash,
            "this ZIP segment storage stream records no aff4:hash, so its bytes can be read but nothing in the container attests to what they were at acquisition; AFF4-L v1.0-ALPHA §6.1 requires a linear digest of the stream"
                .to_owned(),
        ));
    }

    if stored.method != crate::zip::METHOD_STORED && stored.method != METHOD_DEFLATE {
        deviations.push(Deviation::new(
            locus(),
            DeviationKind::UnsupportedSegmentCompression,
            format!(
                "this ZIP segment storage stream is compressed by method {}, but AFF4-L v1.0-ALPHA §6.1 permits only Stored (0) and Deflate (8); a reader built to the clause cannot decompress it",
                stored.method
            ),
        ));
    }

    if stored.uncompressed >= ZIP_SEGMENT_CAP {
        deviations.push(Deviation::new(
            locus(),
            DeviationKind::OversizedZipSegment,
            format!(
                "this ZIP segment storage stream holds {}, at or above the one-gibibyte size AFF4-L v1.0-ALPHA §6.1 says the form should not be used beyond; a compressed member is not efficiently seekable, so reading near its end means inflating everything before it",
                crate::human_bytes(stored.uncompressed)
            ),
        ));
    }
}

/// Report terms written under a namespace their defining standard does not
/// assign them (AFF4-L v1.0-ALPHA §4.1).
///
/// Checked from the property's full IRI, since that is the only place the
/// namespace survives — `local_name` strips it, which is exactly what lets a
/// reader honor either. So the leniency and the check read the same data and
/// reach opposite conclusions, deliberately: the container is read, and the
/// departure is recorded.
fn report_v21_namespaces(
    object: &Aff4Object,
    volume: &VolumeContext,
    deviations: &mut Vec<Deviation>,
) {
    if volume.mapping != crate::arn::NameMapping::Literal {
        return;
    }

    for property in &object.properties {
        let Some((namespace, local)) = split_namespace(&property.iri) else {
            continue;
        };
        // A vendor extension is outside every AFF4 vocabulary and is nobody's
        // to place. Only terms in one of ours are subject to AFF4-L v1.0-ALPHA §4.1.
        if !crate::lexicon::is_known_namespace(namespace) {
            continue;
        }
        let expected = crate::lexicon::namespace_for(Generation::Aff4L10, local);
        if namespace != expected {
            deviations.push(Deviation::new(
                (*volume.locus).clone().subject(object.arn.as_str()),
                DeviationKind::WrongTermNamespace,
                format!(
                    "{local} is written under {namespace} but AFF4-L v1.0-ALPHA \
§4.1 places it in {expected}; a reader that does not accept both namespaces \
will not recognize the term"
                ),
            ));
        }
    }
}

/// Report the AFF4-L v1.0-ALPHA identity departures.
///
/// Four rules, all of them about what an object is called and where its bytes
/// are therefore stored. They apply only to a v2.1 container: under the
/// earlier documents a resource name legitimately carries a path, and the
/// escaped member spelling is the one v1.0a §5.2 requires.
///
/// The gate is the [`crate::arn::NameMapping`] rather than the generation
/// directly, because the mapping *is* the generation's answer to this
/// question, and reading it from one place keeps the check and the resolution
/// from drifting apart.
fn report_v21_identity(
    object: &Aff4Object,
    volume: &VolumeContext,
    deviations: &mut Vec<Deviation>,
) {
    let VolumeContext {
        volume_arn,
        segment_present,
        mapping,
        locus,
        ..
    } = volume;
    if *mapping != crate::arn::NameMapping::Literal {
        return;
    }
    // The volume itself is named by the same scheme but is not an acquired
    // object, and a v2.1 volume ARN is already a bare GUID.
    if object.arn.as_str() == volume_arn.as_str() {
        return;
    }
    let locus = || (*locus).clone().subject(object.arn.as_str());

    // AFF4-L v1.0-ALPHA §2: the name is the scheme plus a GUID. A path after
    // it is the deprecated AFF4-L v1.0-ALPHA §1.1 scheme rather than an
    // extensible part: the extensible part AFF4-L v1.0-ALPHA §2 permits
    // follows the GUID, so what precedes it must be one.
    let authority = object
        .arn
        .volume()
        .strip_prefix("aff4://")
        .unwrap_or_default();
    match guid_case(authority) {
        GuidCase::NotAGuid => {
            deviations.push(Deviation::new(
                locus(),
                DeviationKind::NonGuidArn,
                format!(
                    "this object is named {authority:?}, which is not a GUID; \
AFF4-L v1.0-ALPHA names objects by GUID and carries the suspect's path in \
properties, so a name encoding a path cannot be told from an identity"
                ),
            ));
        }
        GuidCase::Upper => {
            deviations.push(Deviation::new(
                locus(),
                DeviationKind::UppercaseGuidArn,
                format!(
                    "this object's GUID {authority:?} is not lower case; \
resource names are compared as strings, so two spellings of one GUID are two \
resources to a reader that does not normalize them"
                ),
            ));
        }
        GuidCase::Lower => {}
    }

    if !declares_local_type(object, "FileImage") {
        return;
    }

    // AFF4-L v1.0-ALPHA §1.1: the path lives in properties now that the name
    // does not carry it.
    if object.recorded_path().is_none() {
        deviations.push(Deviation::new(
            locus(),
            DeviationKind::MissingRecordedPath,
            "this file records neither aff4:fileName nor aff4:originalPathName, so \
the container holds its bytes but not what they were called"
                .to_owned(),
        ));
    }

    // AFF4-L v1.0-ALPHA §1.2: the member is stored under the unescaped name.
    // Only reported when the escaped spelling is actually present, so a file
    // whose bytes live in an ImageStream or another volume is not accused of
    // storing them in the wrong place.
    if let Some(member) = object.arn.member_name(volume_arn, *mapping)
        && !segment_present.contains(member.as_str())
    {
        let escaped = object
            .arn
            .member_name(volume_arn, crate::arn::NameMapping::Escaped);
        if let Some(escaped) = escaped
            && segment_present.contains(escaped.as_str())
        {
            deviations.push(Deviation::new(
                locus(),
                DeviationKind::EscapedV21MemberName,
                format!(
                    "this file's bytes are stored as the ZIP member {escaped}, but \
AFF4-L v1.0-ALPHA stores them under {member}; a conforming reader looks only at \
the latter"
                ),
            ));
        }
    }
}

/// Report the AFF4-L v1.0-ALPHA §5 name-normalization departures.
///
/// Five rules, checked as two pairs and a spelling.
///
/// The strongest of them is the last: decoding the raw form and re-encoding it
/// must reproduce the display form. That checks the container's two halves
/// against **each other** rather than either against an assumption, so it
/// catches a writer whose encoder and decoder disagree — which no
/// single-property check could.
fn report_v21_names(object: &Aff4Object, volume: &VolumeContext, deviations: &mut Vec<Deviation>) {
    use crate::naming::{RecordedName, base64_decode, needs_raw_form};

    if volume.mapping != crate::arn::NameMapping::Literal {
        return;
    }
    let locus = || (*volume.locus).clone().subject(object.arn.as_str());

    for (name, raw_name) in [
        ("fileName", "fileNameRaw"),
        ("originalPathName", "originalPathNameRaw"),
    ] {
        let Some(display) = object.property(name).map(|p| p.value.lexical()) else {
            continue;
        };
        let raw = object.property(raw_name).map(|p| p.value.lexical());

        // AFF4-L v1.0-ALPHA §5 rule 2b: escapes are uppercase. Checked on the
        // display form itself, so it applies whether or not a raw form exists.
        if has_lowercase_escape(display) {
            deviations.push(Deviation::new(
                locus(),
                DeviationKind::LowercaseNameEscape,
                format!(
                    "{name} {display:?} carries a lowercase percent escape; \
AFF4-L v1.0-ALPHA §5 specifies uppercase"
                ),
            ));
        }

        let Some(raw) = raw.filter(|r| !r.is_empty()) else {
            // No raw form. Rule 2 requires one when the display form was
            // encoded, and a percent escape is the only evidence of that
            // available from the metadata alone.
            if has_percent_escape(display) {
                deviations.push(Deviation::new(
                    locus(),
                    DeviationKind::MissingRawName,
                    format!(
                        "{name} {display:?} is percent-encoded but no {raw_name} \
records the original bytes, so the name cannot be recovered"
                    ),
                ));
            }
            continue;
        };

        // Rule 3: the raw form must actually decode.
        let Some(bytes) = base64_decode(raw) else {
            deviations.push(Deviation::new(
                locus(),
                DeviationKind::MalformedRawName,
                format!("{raw_name} is not valid base64, so the name it records cannot be read"),
            ));
            continue;
        };

        // Rule 1: a name needing no encoding records no raw form.
        if !needs_raw_form(&bytes) {
            deviations.push(Deviation::new(
                locus(),
                DeviationKind::RedundantRawName,
                format!(
                    "{raw_name} is present, but the name it decodes to needs no \
encoding and AFF4-L v1.0-ALPHA §5 does not use a raw form for one"
                ),
            ));
        }

        // Rule 2 the other way: the two halves must describe one name.
        let expected = RecordedName::of(&bytes);
        if expected.display() != display {
            deviations.push(Deviation::new(
                locus(),
                DeviationKind::ContradictoryRawName,
                format!(
                    "{raw_name} decodes to a name whose display form is \
{:?}, but {name} records {display:?}; the container contradicts itself about \
what this file was called",
                    expected.display()
                ),
            ));
        }
    }
}

/// Whether a display name carries a percent escape.
///
/// Two hex digits after a `%`. A bare `%` is a literal one in a clean name,
/// which AFF4-L v1.0-ALPHA §5 rule 1 allows and which must not be mistaken for
/// evidence of encoding.
fn has_percent_escape(display: &str) -> bool {
    let bytes = display.as_bytes();
    bytes
        .windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}

/// Whether any percent escape uses a lowercase hex letter.
fn has_lowercase_escape(display: &str) -> bool {
    let bytes = display.as_bytes();
    bytes.windows(3).any(|w| {
        w[0] == b'%'
            && w[1].is_ascii_hexdigit()
            && w[2].is_ascii_hexdigit()
            && (w[1].is_ascii_lowercase() || w[2].is_ascii_lowercase())
    })
}

/// How a resource name's authority is spelled.
enum GuidCase {
    /// A GUID, lower case, as AFF4-L v1.0-ALPHA §2 requires.
    Lower,
    /// A GUID whose hex digits are not all lower case.
    Upper,
    /// Not a GUID at all.
    NotAGuid,
}

/// Classify a resource name's authority as a GUID and its case.
///
/// Shape only: eight, four, four, four, then twelve hex digits separated by
/// hyphens. Version and variant bits are not checked, because AFF4-L
/// v1.0-ALPHA §2 asks for a GUID rather than for a particular UUID version,
/// and a conforming producer may mint one any way it likes.
fn guid_case(authority: &str) -> GuidCase {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = authority.split('-').collect();
    if parts.len() != GROUPS.len() {
        return GuidCase::NotAGuid;
    }
    let mut upper = false;
    for (part, want) in parts.iter().zip(GROUPS) {
        if part.len() != want || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return GuidCase::NotAGuid;
        }
        upper |= part.chars().any(|c| c.is_ascii_uppercase());
    }
    if upper {
        GuidCase::Upper
    } else {
        GuidCase::Lower
    }
}

/// Whether an object declares `local`, comparing the IRI's local name.
///
/// Types are full IRIs (`http://aff4.org/Schema#ImageStream`), and the
/// pre-standard generation uses a different namespace, so the fragment is what
/// identifies the class across generations.
fn declares_local_type(object: &Aff4Object, local: &str) -> bool {
    object
        .types
        .iter()
        .any(|t| t.rsplit(['#', '/']).next() == Some(local))
}

/// [`compare_manifest`], discarding the disagreements `conformance` does not render.
fn report_manifest_disagreements(
    manifest: &[String],
    declared: bool,
    local: &[LocalArn],
    volume: &Arn,
    locus: &Locus,
    deviations: &mut Vec<Deviation>,
) {
    let _ = compare_manifest(manifest, declared, local, volume, locus, deviations);
}
