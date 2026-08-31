//! A set of AFF4 ZIP volumes that jointly hold one image.
//!
//! A striped container spreads a single image across several `.aff4` files,
//! each holding one stripe's bevy data (Standard v1.0a §7.1). Reading such an
//! image means resolving a stream to whichever volume actually stores it.
//!
//! # Why `ZipVolumeSet` and not `VolumeSet`
//!
//! "Volume" is overloaded. In ordinary forensic usage it names a filesystem or
//! partition *on the evidence* — the thing an examiner mounts, which in AFF4 is
//! an `Image`. Here it names the ZIP file the evidence is packaged in. The two
//! meanings are near-opposites, so the type says which one it holds. See
//! `docs/glossary.md`.
//!
//! # Why the graphs are not merged
//!
//! Each volume keeps its own [`Graph`]. Merging them would be wrong, not merely
//! wasteful: the volumes of a striped set make **conflicting statements about
//! the same subjects**. In the corpus fixture, stream `3bf0bd14` is declared
//! `aff4:stored :` (itself) in volume 2 and `aff4:stored <51725cd9>` in volume
//! 1, and the shared `DiskImage` names a different `dataStream` in each. A
//! merged graph would answer `dataStream` non-deterministically and could fill
//! a stub's absent `size` from whichever triple happened to win — an
//! unattributable input to a digest.
//!
//! Keeping them separate makes resolution explicit and reportable: "`chunkSize`
//! for `3bf0bd14` came from `Base-Linear_2.aff4`" is a sentence an examiner can
//! check.
//!
//! # Why one volume at a time is enough
//!
//! An [`ImageStream`](crate::stream::ImageStream)'s bevies live **entirely
//! within one volume** — a stream is never split across stripes. So striping is
//! a per-*stream* choice of volume, not a per-segment one, and a reader only
//! ever needs one volume for the whole of a stream's traversal. That is what
//! lets [`Volume`], `ChunkReader`, and the parallel path keep their existing
//! single-volume signatures.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::arn::Arn;
use crate::error::{Locus, Result};
use crate::rdf::Graph;
use crate::zip::{Volume, ZipVolume};

/// Two admitted volumes declaring different values for one stream's predicate.
///
/// Carries both values *and* both volume ARNs, so a report can name the files
/// that disagree rather than only the fact of disagreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamConflict {
    /// The stream both volumes describe.
    pub stream: Arn,
    /// The full predicate IRI they disagree about.
    pub predicate: String,
    /// The value declared by the volume reached first.
    pub first_value: String,
    /// The volume that declared `first_value`.
    pub first_volume: Arn,
    /// The differing value declared by a later volume.
    pub second_value: String,
    /// The volume that declared `second_value`.
    pub second_volume: Arn,
}

/// How a volume came to be in the set.
///
/// Recorded so a report can say which files contributed to a digest. A
/// container the examiner did not name is a fact worth surfacing, never a
/// silent convenience.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum VolumeOrigin {
    /// Named directly by the caller.
    Named,
}

/// The primary volume's index — the file the caller named first.
pub const PRIMARY: usize = 0;

/// One volume in the set, with its metadata graph and provenance.
#[derive(Debug)]
struct Member {
    volume: ZipVolume,
    graph: Graph,
    origin: VolumeOrigin,
}

/// A description of one volume, for reports.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VolumeRecord {
    /// The file this volume was read from.
    pub path: PathBuf,
    /// The volume's own ARN.
    pub arn: Arn,
    /// How it entered the set.
    pub origin: VolumeOrigin,
}

/// One or more ZIP volumes, resolved together.
///
/// A single-volume set is the ordinary case and behaves exactly as a lone
/// [`ZipVolume`] did; [`ZipVolumeSet::primary`] is then the only member.
#[derive(Debug)]
pub struct ZipVolumeSet {
    members: Vec<Member>,
    /// Volume ARN to index in `members`.
    by_arn: HashMap<String, usize>,
    /// Stream ARN to the index in `members` that holds its bevies.
    ///
    /// `holds_stream_data` walks a volume's member names and allocates a
    /// `Vec<String>` to do it, which is far too expensive to repeat per read:
    /// profiling a `mac_apt` APFS walk put 58% of all samples in that one call.
    /// Which volume holds a stream cannot change once the set is built -- volumes
    /// are only ever added, and an added volume cannot take a stream away from
    /// one already present -- so the answer is memoized on first use.
    ///
    /// `None` records a stream no member holds, so a miss is not re-derived
    /// either.
    holder: RefCell<HashMap<String, Option<usize>>>,
}

impl ZipVolumeSet {
    /// Build a set from one already-open volume and its graph.
    #[must_use]
    pub fn single(volume: ZipVolume, graph: Graph) -> Self {
        let mut set = Self {
            members: Vec::new(),
            by_arn: HashMap::new(),
            holder: RefCell::new(HashMap::new()),
        };
        set.push(volume, graph, VolumeOrigin::Named);
        set
    }

    /// Add a volume, keeping the first entry for a repeated ARN.
    ///
    /// Returns whether it was added. A duplicate is not an error: naming the
    /// same file twice, or discovering a sibling already named, is harmless.
    pub fn push(&mut self, volume: ZipVolume, graph: Graph, origin: VolumeOrigin) -> bool {
        let key = volume.arn().as_str().to_owned();
        if self.by_arn.contains_key(&key) {
            return false;
        }
        self.by_arn.insert(key, self.members.len());
        self.members.push(Member {
            volume,
            graph,
            origin,
        });
        // A stream this set previously found nowhere may live in the volume
        // just added, so cached misses -- and cached hits, whose indices stay
        // valid but whose absence answers do not -- are dropped.
        self.holder.borrow_mut().clear();
        true
    }

    /// The first volume named — the one the command line pointed at.
    #[must_use]
    pub fn primary(&self) -> &ZipVolume {
        &self.members[0].volume
    }

    /// Mutable access to the primary volume.
    pub fn primary_mut(&mut self) -> &mut ZipVolume {
        &mut self.members[0].volume
    }

    /// How many volumes are in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the set holds exactly one volume — the ordinary case.
    #[must_use]
    pub fn is_single(&self) -> bool {
        self.members.len() == 1
    }

    /// Never empty: a set is built from at least one volume.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Every volume's ARN, in the order the volumes were added.
    pub fn volume_arns(&self) -> impl Iterator<Item = &Arn> {
        self.members.iter().map(|m| m.volume.arn())
    }

    /// Every volume's metadata graph, in the order the volumes were added.
    pub fn graphs(&self) -> impl Iterator<Item = &Graph> {
        self.members.iter().map(|m| &m.graph)
    }

    /// Replace every retained graph with an empty one.
    ///
    /// The metadata stays on disk in a read-only container, so this discards a
    /// cache rather than data: any caller that needs it again re-parses via
    /// `Container::graph`. See `Container::release_graphs` for when that is
    /// safe and when it is not.
    pub fn release_graphs(&mut self) {
        for member in &mut self.members {
            member.graph = Graph::default();
        }
    }

    /// A record per volume, for reports.
    #[must_use]
    pub fn records(&self) -> Vec<VolumeRecord> {
        self.members
            .iter()
            .map(|m| VolumeRecord {
                path: m.volume.path().to_path_buf(),
                arn: m.volume.arn().clone(),
                origin: m.origin.clone(),
            })
            .collect()
    }

    /// A volume and its own graph together.
    ///
    /// Needed because reading a stream requires both, and a stripe's stream is
    /// described only by the volume that holds it. Returning them as a pair
    /// splits one borrow rather than taking two.
    pub fn volume_and_graph_mut(&mut self, volume_arn: &Arn) -> Option<(&mut ZipVolume, &Graph)> {
        let index = *self.by_arn.get(volume_arn.as_str())?;
        let member = &mut self.members[index];
        Some((&mut member.volume, &member.graph))
    }

    /// Which volume's graph declares `subject` with a `map` segment present.
    ///
    /// A map's `map`/`idx` segments live in the volume that declares it. In a
    /// striped set each volume has its own map, so the primary's is not always
    /// the one being verified.
    #[must_use]
    pub fn declaring_volume(&self, subject: &Arn) -> Option<&Arn> {
        self.members
            .iter()
            .find(|m| {
                subject
                    .member_name(m.volume.arn())
                    .is_some_and(|base| m.volume.has_segment(&format!("{base}/map")))
            })
            .map(|m| m.volume.arn())
    }

    /// Which volume stores the block-hash segments for a `BlockHashes` object.
    ///
    /// The object is named `<stream>/blockhash.<alg>`; the segments sit under
    /// the stream's own prefix. Every stripe usually stores every stream's
    /// block hashes, so this is normally the primary — but a set where it is
    /// not must still find them rather than declining.
    #[must_use]
    pub fn holding_block_hashes(&self, object: &Arn) -> Option<&Arn> {
        let (stream_iri, suffix) = object.as_str().rsplit_once("/blockhash.")?;
        self.members
            .iter()
            .find(|m| {
                let locus = crate::error::Locus::new(m.volume.path().to_path_buf());
                let Ok(stream) = Arn::parse(stream_iri, &locus) else {
                    return false;
                };
                let Some(base) = stream.member_name(m.volume.arn()) else {
                    return false;
                };
                m.volume
                    .segments_with_prefix(&format!("{base}/"))
                    .iter()
                    .any(|n| n.ends_with(&format!(".blockHash.{suffix}")))
            })
            .map(|m| m.volume.arn())
    }

    /// The map this volume stores, as `(map ARN, member base)`.
    ///
    /// Each stripe carries its own near-equivalent map (v1.0a §7.1), and the
    /// striped root digest is built from each stripe's *own* map segments — so
    /// the map wanted here is the local one, not the primary's.
    #[must_use]
    pub fn local_map(&self, volume_arn: &Arn) -> Option<(Arn, String)> {
        let index = *self.by_arn.get(volume_arn.as_str())?;
        let member = &self.members[index];
        let map_type = "http://aff4.org/Schema#Map";

        for subject in member.graph.subjects_of_type(map_type) {
            let locus = crate::error::Locus::new(member.volume.path().to_path_buf());
            let Ok(arn) = Arn::parse(subject, &locus) else {
                continue;
            };
            let Some(base) = arn.member_name(member.volume.arn()) else {
                continue;
            };
            if member.volume.has_segment(&format!("{base}/map")) {
                return Some((arn, base));
            }
        }
        None
    }

    /// Mutable access to the volume with this ARN.
    pub fn get_mut(&mut self, volume_arn: &Arn) -> Option<&mut ZipVolume> {
        self.by_arn
            .get(volume_arn.as_str())
            .map(|&i| &mut self.members[i].volume)
    }

    /// The graph of the volume with this ARN.
    #[must_use]
    pub fn graph_of(&self, volume_arn: &Arn) -> Option<&Graph> {
        self.by_arn
            .get(volume_arn.as_str())
            .map(|&i| &self.members[i].graph)
    }

    /// Which volume holds `stream`'s bevy data, if any in this set does.
    ///
    /// Answered by looking for a **bevy** under the stream's prefix, not by
    /// asking whether the name resolves. A stripe stores its sibling's
    /// `.blockHash.*` and index segments while holding none of its bevies, so
    /// name resolvability would give the wrong volume. See decision 36.
    #[must_use]
    pub fn holding(&self, stream: &Arn) -> Option<&Arn> {
        let index = self.holder_index(stream)?;
        self.members.get(index).map(|m| m.volume.arn())
    }

    /// Mutable access to the volume holding `stream`'s data.
    pub fn holding_mut(&mut self, stream: &Arn) -> Option<&mut ZipVolume> {
        let index = self.holder_index(stream)?;
        self.members.get_mut(index).map(|m| &mut m.volume)
    }

    /// The index in `members` holding `stream`, memoized.
    fn holder_index(&self, stream: &Arn) -> Option<usize> {
        if let Some(known) = self.holder.borrow().get(stream.as_str()) {
            return *known;
        }
        let found = self
            .members
            .iter()
            .position(|m| holds_stream_data(&m.volume, stream));
        self.holder
            .borrow_mut()
            .insert(stream.as_str().to_owned(), found);
        found
    }

    /// The graph that fully describes `stream`, and the volume it came from.
    ///
    /// A stripe declares its sibling's streams as **stubs** — `aff4:stored` and
    /// `aff4:target` only, with no `size`, `chunkSize`, or `compressionMethod`.
    /// A stub cannot be read, so the real declaration must come from the volume
    /// that holds the data.
    ///
    /// Resolution never infers. The parameters are taken from **one** graph,
    /// whole; they are never assembled from several, defaulted, or borrowed
    /// from a same-named local stream. A stream whose declarations disagree
    /// across volumes is a finding, not something to reconcile — see
    /// [`ZipVolumeSet::stream_conflict`].
    ///
    /// Tries the primary first so a locally complete declaration always wins,
    /// then the volume holding the bevies, then any other member.
    #[must_use]
    pub fn describing(&self, stream: &Arn, size_iri: &str, chunk_size_iri: &str) -> Option<usize> {
        let complete = |m: &Member| {
            m.graph.object(stream.as_str(), size_iri).is_some()
                && m.graph.object(stream.as_str(), chunk_size_iri).is_some()
        };
        self.members.iter().position(complete)
    }

    /// The graph at a member index, for a caller that resolved one.
    #[must_use]
    pub fn graph_at(&self, index: usize) -> &Graph {
        &self.members[index].graph
    }

    /// The volume ARN at a member index.
    #[must_use]
    pub fn arn_at(&self, index: usize) -> &Arn {
        self.members[index].volume.arn()
    }

    /// Mutable access to the volume at a member index.
    pub fn volume_at_mut(&mut self, index: usize) -> &mut ZipVolume {
        &mut self.members[index].volume
    }

    /// The file at a member index, for attributing what was read.
    #[must_use]
    pub fn path_at(&self, index: usize) -> &Path {
        self.members[index].volume.path()
    }

    /// Whether two volumes declare different values for the same predicate.
    ///
    /// Returns the two disagreeing lexical forms. A striped set whose volumes
    /// disagree about a stream's `chunkSize` or `size` cannot be trusted to
    /// produce one digest, so the caller declines rather than picking a side.
    #[must_use]
    pub fn stream_conflict(&self, stream: &Arn, predicate: &str) -> Option<(String, String)> {
        self.stream_conflict_attributed(stream, predicate)
            .map(|c| (c.first_value, c.second_value))
    }

    /// As [`ZipVolumeSet::stream_conflict`], naming the volumes that disagreed.
    ///
    /// A report has to say *which* volumes conflict, not merely that two values
    /// exist: with three stripes admitted, "512 and 1024" alone leaves the
    /// examiner unable to tell which file to look at.
    #[must_use]
    pub fn stream_conflict_attributed(
        &self,
        stream: &Arn,
        predicate: &str,
    ) -> Option<StreamConflict> {
        let mut seen: Option<(String, &Arn)> = None;
        for member in &self.members {
            let Some(value) = member.graph.object(stream.as_str(), predicate) else {
                continue;
            };
            let form = value.lexical().to_owned();
            match &seen {
                None => seen = Some((form, member.volume.arn())),
                Some((first, first_volume)) if *first != form => {
                    return Some(StreamConflict {
                        stream: stream.clone(),
                        predicate: predicate.to_owned(),
                        first_value: first.clone(),
                        first_volume: (*first_volume).clone(),
                        second_value: form,
                        second_volume: member.volume.arn().clone(),
                    });
                }
                Some(_) => {}
            }
        }
        None
    }

    /// Every conflict among `predicates`, for every stream any admitted volume
    /// describes.
    ///
    /// Scoped by the caller rather than sweeping all shared predicates: the
    /// predicates that matter are the ones whose disagreement makes the set
    /// unreadable as one image. A flood of low-value conflicts would train an
    /// examiner to skip the section.
    ///
    /// At most one conflict is reported per stream and predicate — the first
    /// disagreeing pair. Listing every pairwise combination across many stripes
    /// would repeat one underlying fault.
    #[must_use]
    pub fn stream_conflicts(&self, predicates: &[&str]) -> Vec<StreamConflict> {
        let mut subjects: Vec<&str> = Vec::new();
        for member in &self.members {
            for subject in member.graph.subjects() {
                let subject: &str = subject;
                if !subjects.contains(&subject) {
                    subjects.push(subject);
                }
            }
        }

        let mut conflicts = Vec::new();
        for subject in subjects {
            // A subject that is not a parseable ARN cannot be a stream; the
            // summary reports that separately and it is not a conflict.
            let Ok(arn) = Arn::parse(subject, &Locus::new(self.primary().path())) else {
                continue;
            };
            for predicate in predicates {
                if let Some(conflict) = self.stream_conflict_attributed(&arn, predicate) {
                    conflicts.push(conflict);
                }
            }
        }
        conflicts
    }

    /// Look `subject` up in every volume's graph, nearest first.
    ///
    /// Returns the graph that declares it along with the volume it came from,
    /// so a caller can attribute what it read. The primary is tried first, so a
    /// locally complete declaration always wins over a sibling's.
    #[must_use]
    pub fn declaring(&self, subject: &Arn, predicate: &str) -> Option<(&Graph, &Arn)> {
        self.members
            .iter()
            .find(|m| m.graph.object(subject.as_str(), predicate).is_some())
            .map(|m| (&m.graph, m.volume.arn()))
    }

    /// The index of the first volume whose graph states `predicate` about
    /// `subject`, primary first.
    ///
    /// An index rather than a borrow, so the caller can go on to borrow the set
    /// mutably — which reading the object it just located requires.
    #[must_use]
    pub fn declaring_index(&self, subject: &Arn, predicate: &str) -> Option<usize> {
        self.members
            .iter()
            .position(|m| m.graph.object(subject.as_str(), predicate).is_some())
    }

    /// Every `aff4:DiskImage` ARN each volume declares, in volume order.
    ///
    /// The join key for a striped set: v1.0a §7.1 makes a commonly-named
    /// `DiskImage` "the point of commonality unifying" the volumes, and the
    /// corpus fixture bears that out — `951b3e29…` appears identically in both
    /// stripes while every other identifier differs per volume.
    #[must_use]
    pub fn disk_images_per_volume(&self) -> Vec<(PathBuf, Vec<String>)> {
        const DISK_IMAGE: &str = "http://aff4.org/Schema#DiskImage";
        self.members
            .iter()
            .map(|m| {
                let mut images: Vec<String> = m
                    .graph
                    .subjects_of_type(DISK_IMAGE)
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                images.sort();
                (m.volume.path().to_path_buf(), images)
            })
            .collect()
    }
}

/// Whether this volume stores `stream`'s bevies.
///
/// Shared with `verify::volume_holds_stream_data`; see decision 36 for why the
/// test is bevy presence rather than name resolvability.
fn holds_stream_data(volume: &ZipVolume, stream: &Arn) -> bool {
    let Some(base) = stream.member_name(volume.arn()) else {
        return false;
    };
    volume
        .segments_with_prefix(&format!("{base}/"))
        .into_iter()
        .any(|name| {
            name.rsplit_once('/')
                .is_some_and(|(_, leaf)| crate::zip::is_bevy_number(leaf))
        })
}

/// Open a container read-only and parse its metadata graph.
///
/// Routed through [`ZipVolume::open`], so the crate's single `File::open`
/// chokepoint still holds.
///
/// # Errors
///
/// [`Error::Zip`] if the file is not a readable archive, or [`Error::Malformed`]
/// if its metadata is not valid Turtle.
pub fn open_with_graph(path: impl AsRef<Path>) -> Result<(ZipVolume, Graph)> {
    let mut volume = ZipVolume::open(path)?;
    let locus = volume.locus(Some(crate::container::METADATA_SEGMENT));
    let bytes = volume.read_segment(crate::container::METADATA_SEGMENT)?;
    let graph = Graph::parse(&bytes, &locus)?;
    Ok((volume, graph))
}
