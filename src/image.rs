//! Reading an image: a map resolved against the streams it depends on.
//!
//! [`crate::stream`] reads one `ImageStream`. [`crate::map`] parses a map and
//! knows how to walk it. This module joins the two: it finds a container's
//! images, opens the map each one points at, and supplies the stored streams
//! that map's entries name.
//!
//! # What an image actually is
//!
//! A `DiskImage` names a `dataStream`, which is a `Map`. The map's entries
//! resolve to either an `ImageStream` stored in the container or a run of one
//! repeated byte recorded as a description. For `Base-Linear.aff4` that is
//! 3.96 MB stored against 264 MB described — reading the `ImageStream` alone
//! yields 1.5% of the image.
//!
//! # Nothing is materialised
//!
//! [`Image::read`] delivers bytes to a sink in address order. A 268 MB image
//! costs one bevy plus one chunk plus a 64 KiB run buffer, and real evidence
//! reaches terabytes, so this is not an optimisation.

use crate::arn::Arn;
use crate::error::{Deviation, DeviationKind, Error, Locus, Result};
use crate::lexicon::Lexicon;
use crate::map::{GapPolicy, IDX_SEGMENT, MAP_SEGMENT, Map, ReadAccounting, StreamSource};
use crate::rdf::Graph;
use crate::stream::{ChunkReader, ImageStream, Residency};
use crate::zip::Volume;
use crate::zip_volume_set::{PRIMARY, ZipVolumeSet};

/// An image, resolved to the map and streams that produce its bytes.
#[derive(Debug, Clone)]
pub struct Image {
    /// The image object's ARN — the `DiskImage`, not its map.
    arn: Arn,
    /// The map that assembles it.
    map: Map,
    /// Every stored stream the map depends on, opened from the metadata.
    streams: Vec<ImageStream>,
}

impl Image {
    /// Open the image named by `arn`, following its `dataStream` to a map.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the image names no data stream, if the map's
    /// segments are missing or inconsistent, or if a dependent stream cannot be
    /// opened. [`Error::Unsupported`] if a dependent stream uses a codec this
    /// build declines.
    pub fn open(
        arn: &Arn,
        volume: &mut dyn Volume,
        graph: &Graph,
        lexicon: &Lexicon,
        locus: &Locus,
    ) -> Result<Self> {
        let locus = locus.clone().subject(arn.as_str());

        let map_arn = data_stream_of(arn, graph, lexicon, &locus)?;

        // v1.0a §4 (p7), verbatim: "The map MAY be discontiguous, in which case a
        // default value of holes MAY be specified by the property of the Map
        // object aff4:mapGapDefaultStream. If the map is discontiguous, and the
        // mapGapDefaultStream property is not set, then aff4:Zero is used to
        // fill the holes."
        //
        // The spec makes discontiguity a property of the **Map** rather than of
        // the image type — `aff4:DiscontiguousImage` appears nowhere in the
        // standard (0 occurrences, against 5 each for `ContiguousImage` and
        // `DiskImage`) and comes from aff4-cpp-lite.
        //
        // Even so, the *image* type is what gates hole-filling. A declared gap
        // stream alone is not enough: `Base-Linear.aff4` is a plain `DiskImage`
        // that still declares `mapGapDefaultStream aff4:Zero`, so treating that
        // as permission would make a truncated map on a contiguous image
        // silently readable instead of a finding. An image that says it is
        // contiguous must cover its whole address space.
        let gap_policy = if declares_discontiguous(arn, graph) {
            {
                let (target, declared) = Map::declared_gap_fill(
                    &map_arn,
                    graph,
                    &lexicon.iri(lexicon.map_gap_default_stream),
                    &locus,
                );
                GapPolicy::Fill(target, declared)
            }
        } else {
            GapPolicy::Refuse
        };

        let map = open_map(&map_arn, volume, graph, lexicon, &gap_policy, &locus)?;

        let mut streams = Vec::new();
        for stream_arn in map.dependent_streams() {
            streams.push(ImageStream::open(stream_arn, graph, lexicon, &locus)?);
        }

        Ok(Self {
            arn: arn.clone(),
            map,
            streams,
        })
    }

    /// Open an image whose streams may live in sibling volumes.
    ///
    /// The single-volume [`Image::open`] fails on a striped container: the
    /// sibling's stream is declared as a **stub** carrying only `aff4:stored`
    /// and `aff4:target`, so it has no `size` to read. Here each dependent
    /// stream is opened against whichever volume's graph fully describes it.
    ///
    /// The map itself is read from the primary. Every volume of a striped set
    /// carries its own near-equivalent map covering the whole address space
    /// (v1.0a §7.1), so the primary's is sufficient and is the one the examiner
    /// pointed at.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the map cannot be read, if a dependent stream is
    /// described by no volume in the set, or if two volumes disagree about a
    /// stream's parameters.
    pub fn open_in_set(
        arn: &Arn,
        volumes: &mut ZipVolumeSet,
        lexicon: &Lexicon,
        locus: &Locus,
    ) -> Result<Self> {
        let locus = locus.clone().subject(arn.as_str());

        // Resolve against the volume that *declares* this image, not the
        // primary. In a striped set every volume declares the shared DiskImage,
        // so the primary is usually right — but a volume may also hold an image
        // of its own, which the primary has never heard of. Reading the
        // primary's graph unconditionally then failed with "names no data
        // stream" on an image that names one perfectly well, downgrading a
        // digest that verifies when the same file is opened alone.
        let data_stream_iri = lexicon.iri(lexicon.data_stream);
        let declaring = volumes
            .declaring_index(arn, &data_stream_iri)
            .unwrap_or(PRIMARY);

        // Everything the graph is needed for happens first, so the borrow ends
        // before the volume set is borrowed mutably. `Graph` is not `Clone`,
        // and cloning one per image would be wasteful even if it were.
        let (map_arn, gap_policy) = {
            let graph = volumes.graph_at(declaring);
            let map_arn = data_stream_of(arn, graph, lexicon, &locus)?;
            let gap_policy = if declares_discontiguous(arn, graph) {
                {
                    let (target, declared) = Map::declared_gap_fill(
                        &map_arn,
                        graph,
                        &lexicon.iri(lexicon.map_gap_default_stream),
                        &locus,
                    );
                    GapPolicy::Fill(target, declared)
                }
            } else {
                GapPolicy::Refuse
            };
            (map_arn, gap_policy)
        };
        let map_size_iri = lexicon.iri(lexicon.size);

        // The map's segments live in the volume that declares the map, which is
        // the volume that declared the image.
        let (map_bytes, idx_bytes) = {
            let volume = volumes.volume_at_mut(declaring);
            let base = map_arn.member_name(volume.arn()).ok_or_else(|| {
                Error::malformed(
                    locus.clone(),
                    format!(
                        "map {map_arn} names no member of volume {}; its segments \
                         are stored elsewhere",
                        volume.arn()
                    ),
                )
            })?;
            let map_bytes = volume.read_segment(&format!("{base}/{MAP_SEGMENT}"))?;
            let idx_bytes = volume.read_segment(&format!("{base}/{IDX_SEGMENT}"))?;
            (map_bytes, idx_bytes)
        };

        let map = Map::open_with(
            &map_arn,
            &map_bytes,
            &idx_bytes,
            volumes.graph_at(declaring),
            &map_size_iri,
            &gap_policy,
            &locus,
        )?;

        let size_iri = lexicon.iri(lexicon.size);
        let chunk_size_iri = lexicon.iri(lexicon.chunk_size);

        let mut streams = Vec::new();
        for stream_arn in map.dependent_streams() {
            // Disagreement is a finding, never something to reconcile: two
            // volumes claiming different chunk sizes for one stream cannot both
            // be right, and picking one would make the resulting digest
            // unattributable.
            for predicate in [&size_iri, &chunk_size_iri] {
                if let Some((a, b)) = volumes.stream_conflict(stream_arn, predicate) {
                    return Err(Error::malformed(
                        locus.clone().subject(stream_arn.as_str()),
                        format!(
                            "volumes disagree about {predicate} for this stream \
                             ({a} and {b}); the set cannot be read as one image"
                        ),
                    ));
                }
            }

            let Some(index) = volumes.describing(stream_arn, &size_iri, &chunk_size_iri) else {
                let stored_iri = lexicon.iri(lexicon.stored);
                let stored = volumes
                    .graph_at(declaring)
                    .object(stream_arn.as_str(), &stored_iri)
                    .and_then(crate::rdf::Value::as_iri)
                    .unwrap_or("an unnamed volume")
                    .to_owned();
                return Err(Error::malformed(
                    locus.clone().subject(stream_arn.as_str()),
                    format!(
                        "this stream is declared only as a stub, with no size or \
                         chunk size; the volume describing it ({stored}) is not \
                         among those given. Pass the containing folder with \
                         --split-file <dir>"
                    ),
                ));
            };

            streams.push(ImageStream::open(
                stream_arn,
                volumes.graph_at(index),
                lexicon,
                &locus,
            )?);
        }

        Ok(Self {
            arn: arn.clone(),
            map,
            streams,
        })
    }

    /// Read the whole image, resolving streams across a volume set.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if a stream's data is in no volume of the set, or
    /// if the map does not cover its declared size.
    pub fn read_from_set(
        &self,
        volumes: &mut ZipVolumeSet,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<ReadAccounting> {
        let mut source = SetStreams::new(&self.streams, volumes);
        self.map.read_all(&mut source, sink, locus)
    }

    /// The image's ARN.
    #[must_use]
    pub fn arn(&self) -> &Arn {
        &self.arn
    }

    /// The map that assembles this image.
    #[must_use]
    pub fn map(&self) -> &Map {
        &self.map
    }

    /// The stored streams the map depends on.
    #[must_use]
    pub fn streams(&self) -> &[ImageStream] {
        &self.streams
    }

    /// The image's size, as the map declares and covers it.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.map.size()
    }

    /// A deviation describing the map's holes, if it left any.
    ///
    /// Legal for a discontiguous image, and still always reported: the filled
    /// bytes were never recorded by the acquisition, so an examiner needs to
    /// know a digest over this image covers content the spec supplied rather
    /// than content the imager measured.
    #[must_use]
    pub fn gap_deviation(&self, locus: &Locus, whole_image_digest: bool) -> Option<Deviation> {
        let gaps = self.map.gaps();
        if gaps.count == 0 {
            return None;
        }

        let fill = gaps.fill.as_ref().map_or_else(
            || "the gap stream".to_owned(),
            crate::map::GapFill::describe,
        );

        // What a recorded digest actually covers, which is the question an
        // examiner has once they know part of the address space was never
        // acquired. Stated either way rather than left to inference: "no digest
        // covers these bytes" and "a digest covers them as the standard defines
        // them" are different findings, and silence would read as the second.
        let coverage = if whole_image_digest {
            "The image digest recorded here covers them as the standard defines \
             them, not as bytes the imager measured."
        } else {
            "No digest recorded in this container covers them: the image stream \
             hashes cover stored bytes, and no whole-image digest is recorded."
        };

        Some(Deviation::new(
            locus.clone().subject(self.arn.as_str()),
            DeviationKind::MapGap,
            format!(
                "This is a discontiguous image. The map leaves {} hole(s) covering \
                 {} bytes, filled with {fill} per Specification §4. These bytes \
                 were not acquired. {coverage}",
                gaps.count, gaps.bytes
            ),
        ))
    }

    /// Deliver every byte of the image to `sink`, in address order.
    ///
    /// Returns the composition of what was delivered — stored against
    /// described — so a report can state it rather than implying every byte
    /// came off the medium at read time.
    ///
    /// # Errors
    ///
    /// As [`Map::read_all`], plus whatever reading a bevy returns.
    pub fn read(
        &self,
        volume: &mut dyn Volume,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<ReadAccounting> {
        let mut source = VolumeStreams::new(&self.streams, volume);
        self.map.read_all(&mut source, sink, locus)
    }

    /// Fill `buf` from the image starting at `offset`, returning bytes written.
    ///
    /// The random-access counterpart to [`Image::read`]. Short **only** at the
    /// end of the image, so a caller that gets fewer bytes than it asked for
    /// has reached the end rather than hit a boundary.
    ///
    /// This is the seam an external consumer needs: TSK, libewf's FUSE mount,
    /// and `mac_apt` all reduce to `read(offset, buffer, length)`.
    ///
    /// # Errors
    ///
    /// As [`Map::read_at`], plus whatever reading a bevy returns.
    pub fn read_at(
        &self,
        volume: &mut dyn Volume,
        offset: u64,
        buf: &mut [u8],
        locus: &Locus,
    ) -> Result<usize> {
        let mut source = VolumeStreams::new(&self.streams, volume);
        self.map.read_at(&mut source, offset, buf, locus)
    }

    /// Fill `buf` from an image whose streams span a volume set.
    ///
    /// The random-access counterpart to [`Image::read_from_set`], for striped
    /// and split containers.
    ///
    /// **One-shot, and that costs a bevy per call.** The source is built and
    /// dropped here, so the resident bevy it caches does not survive to the
    /// next read. A bevy is `chunkSize × chunksInSegment` — 64 MiB for the
    /// corpus containers — so a client issuing many small reads should use
    /// [`Image::reader_in_set`] instead, which keeps the residency. Measured at
    /// 10.5 MiB/s here against 1.5 GiB/s there; see `examples/seek_bench.rs`.
    ///
    /// # Errors
    ///
    /// As [`Map::read_at`], plus whatever reading a bevy returns.
    pub fn read_at_in_set(
        &self,
        volumes: &mut ZipVolumeSet,
        offset: u64,
        buf: &mut [u8],
        locus: &Locus,
    ) -> Result<usize> {
        let mut source = SetStreams::new(&self.streams, volumes);
        self.map.read_at(&mut source, offset, buf, locus)
    }

    /// Fill `buf` from a volume set, carrying the resident bevy across calls.
    ///
    /// The same read as [`Image::read_at_in_set`], but the caller owns the
    /// residency instead of it being discarded when the source drops. Pass the
    /// same `resident` back on the next call and a run of reads inside one bevy
    /// decompresses it once.
    ///
    /// This exists for consumers that cannot hold an [`ImageReader`]: the C ABI
    /// keeps the `Container` and the `Image` in one owned struct, so a reader
    /// borrowing from both fields would make that struct self-referential.
    /// Threading the residency through the call sidesteps the borrow while
    /// keeping the caching that makes small reads affordable -- the difference
    /// `mac_apt` sees between a bevy per 4 KiB read and one per bevy.
    ///
    /// # Errors
    ///
    /// As [`Map::read_at`], plus whatever reading a bevy returns.
    pub fn read_at_in_set_cached(
        &self,
        volumes: &mut ZipVolumeSet,
        offset: u64,
        buf: &mut [u8],
        locus: &Locus,
        resident: &mut Option<(Arn, Residency)>,
    ) -> Result<usize> {
        let mut source = SetStreams::new(&self.streams, volumes);
        source.resident = resident.take();
        let result = self.map.read_at(&mut source, offset, buf, locus);
        *resident = source.resident.take();
        result
    }

    /// A reader that keeps its decompressed bevy resident across reads.
    ///
    /// [`Image::read_at_in_set`] builds and drops its source per call, which
    /// discards the cached bevy and makes every read decompress one afresh.
    /// This holds the source for the reader's lifetime instead, so consecutive
    /// reads inside one bevy cost no decompression at all — the difference
    /// between 10.5 MiB/s and 1.5 GiB/s on the striped corpus fixture.
    ///
    /// This is the shape an external consumer wants: a handle opened once and
    /// read many times, which is exactly how TSK, libewf's FUSE mount, and
    /// `mac_apt` all drive a forensic image.
    #[must_use]
    pub fn reader_in_set<'i, 'v>(&'i self, volumes: &'v mut ZipVolumeSet) -> ImageReader<'i, 'v> {
        ImageReader {
            map: &self.map,
            source: SetStreams::new(&self.streams, volumes),
        }
    }
}

/// A random-access reader over one image, holding its bevy resident.
///
/// Created by [`Image::reader_in_set`]. Reads through this are the fast path;
/// [`Image::read_at_in_set`] is the convenience form that pays a bevy
/// decompression per call.
pub struct ImageReader<'i, 'v> {
    map: &'i Map,
    source: SetStreams<'v>,
}

impl ImageReader<'_, '_> {
    /// Fill `buf` starting at `offset`, returning bytes written.
    ///
    /// Short **only** at the end of the image.
    ///
    /// # Errors
    ///
    /// As [`Map::read_at`], plus whatever reading a bevy returns.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8], locus: &Locus) -> Result<usize> {
        self.map.read_at(&mut self.source, offset, buf, locus)
    }

    /// The image's size, as the map declares and covers it.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.map.size()
    }
}

/// Serves a map's stored targets from one volume.
///
/// Holds one [`ChunkReader`] at a time, rebuilt when the map moves to a
/// different stream. Keeping it across entries is what makes traversal cheap:
/// `Base-Linear.aff4`'s map has 4103 entries against a single stored stream, so
/// a reader per entry would re-read the same 3 MB bevy four thousand times.
///
/// One at a time rather than one per stream, because a reader holds its bevy
/// resident — several readers would mean several resident bevies. Every corpus
/// map has exactly one stored target, so this costs nothing today; a map
/// alternating between two streams would pay a bevy read per switch, which is
/// correct but worth revisiting if such a container appears.
struct VolumeStreams<'v> {
    streams: Vec<ImageStream>,
    volume: Option<&'v mut dyn Volume>,
    reader: Option<ChunkReader<'v>>,
    open: Option<Arn>,
}

impl<'v> VolumeStreams<'v> {
    fn new(streams: &[ImageStream], volume: &'v mut dyn Volume) -> Self {
        Self {
            streams: streams.to_vec(),
            volume: Some(volume),
            reader: None,
            open: None,
        }
    }

    /// Make `stream` the open one, building a reader if it is not already.
    fn open_stream(&mut self, stream: &Arn, locus: &Locus) -> Result<()> {
        if self
            .open
            .as_ref()
            .is_some_and(|a| a.as_str() == stream.as_str())
        {
            return Ok(());
        }

        let found = self
            .streams
            .iter()
            .find(|s| s.arn().as_str() == stream.as_str())
            .ok_or_else(|| {
                Error::malformed(
                    locus.clone(),
                    format!(
                        "the map depends on stream {stream}, which the metadata does \
                         not describe; its regions cannot be read"
                    ),
                )
            })?
            .clone();

        // Reclaim the volume from the previous reader before building the next,
        // so only one reader — and so only one resident bevy — ever exists.
        let volume = match self.reader.take() {
            Some(reader) => reader.into_volume(),
            None => self.volume.take().ok_or_else(|| {
                Error::malformed(
                    locus.clone(),
                    "the volume is no longer available for reading".to_owned(),
                )
            })?,
        };

        self.reader = Some(ChunkReader::new(&found, volume));
        self.open = Some(stream.clone());
        Ok(())
    }
}

impl StreamSource for VolumeStreams<'_> {
    fn read_region(
        &mut self,
        stream: &Arn,
        offset: u64,
        length: u64,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<()> {
        self.open_stream(stream, locus)?;

        let reader = self.reader.as_mut().ok_or_else(|| {
            Error::malformed(
                locus.clone(),
                format!("no reader is open for stream {stream}"),
            )
        })?;

        reader.read_region(offset, length, sink, locus)
    }
}

/// Serves a map's stored targets from a set of volumes.
///
/// The single-volume [`VolumeStreams`] borrows one `&mut dyn Volume` for its
/// whole life and hands it between readers. That cannot work across stripes:
/// consecutive map entries may name streams in different files.
///
/// Instead this holds the set and builds a reader per switch, borrowing only
/// the volume that holds the stream in question. A stream's bevies live
/// entirely in one volume, so a reader still spans a whole run of entries
/// against the same stream — the case that matters, since a map has thousands
/// of entries and only a handful of targets.
///
/// A [`ChunkReader`] cannot outlive the borrow of the volume it reads, and
/// `read_region` only ever gets a short `&mut self`. So the reader is built per
/// call rather than cached, and the **bevy** is cached instead: `ChunkReader`
/// is handed the previous residency and returns it, so a run of entries against
/// one stream still reads each bevy once.
///
/// That keeps peak residency at one bevy, as the single-volume path has, while
/// letting consecutive entries name streams in different files.
struct SetStreams<'v> {
    streams: Vec<ImageStream>,
    volumes: &'v mut ZipVolumeSet,
    /// The stream the cached bevy belongs to, and the bevy itself.
    resident: Option<(Arn, Residency)>,
}

impl<'v> SetStreams<'v> {
    fn new(streams: &[ImageStream], volumes: &'v mut ZipVolumeSet) -> Self {
        Self {
            streams: streams.to_vec(),
            volumes,
            resident: None,
        }
    }
}

impl StreamSource for SetStreams<'_> {
    fn read_region(
        &mut self,
        stream: &Arn,
        offset: u64,
        length: u64,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        locus: &Locus,
    ) -> Result<()> {
        let found = self
            .streams
            .iter()
            .find(|s| s.arn().as_str() == stream.as_str())
            .ok_or_else(|| {
                Error::malformed(
                    locus.clone(),
                    format!(
                        "the map depends on stream {stream}, which the metadata does \
                         not describe; its regions cannot be read"
                    ),
                )
            })?
            .clone();

        // Carry the bevy forward only when it belongs to this stream.
        let carried = match self.resident.take() {
            Some((arn, residency)) if arn.as_str() == stream.as_str() => Some(residency),
            _ => None,
        };

        let volume = self.volumes.holding_mut(stream).ok_or_else(|| {
            Error::malformed(
                locus.clone().subject(stream.as_str()),
                format!(
                    "no volume given holds this stream's data; pass the folder \
                     holding {stream} with --split-file <dir>"
                ),
            )
        })?;

        let mut reader = ChunkReader::new(&found, volume);
        if let Some(residency) = carried {
            reader.restore(residency);
        }
        let result = reader.read_region(offset, length, sink, locus);
        self.resident = Some((stream.clone(), reader.into_residency()));
        result
    }
}

/// Follow an image's `dataStream` (or `dependentStream`) to its map.
fn data_stream_of(arn: &Arn, graph: &Graph, lexicon: &Lexicon, locus: &Locus) -> Result<Arn> {
    let predicate = lexicon.iri(lexicon.data_stream);

    let iri = graph
        .object(arn.as_str(), &predicate)
        .and_then(crate::rdf::Value::as_iri)
        .ok_or_else(|| {
            Error::malformed(
                locus.clone().predicate(&predicate),
                format!(
                    "image {arn} names no data stream; without one there is nothing \
                     to read, and guessing which object holds its bytes would be a \
                     fabrication"
                ),
            )
        })?
        .to_owned();

    Arn::parse(&iri, locus)
}

/// Read a map's three segments out of the volume and parse it.
fn open_map(
    arn: &Arn,
    volume: &mut dyn Volume,
    graph: &Graph,
    lexicon: &Lexicon,
    gap_policy: &GapPolicy,
    locus: &Locus,
) -> Result<Map> {
    let base = arn.member_name(volume.arn()).ok_or_else(|| {
        Error::malformed(
            locus.clone(),
            format!(
                "map {arn} names no member of volume {}; its segments are stored \
                 elsewhere, which this build cannot follow",
                volume.arn()
            ),
        )
    })?;

    let map_bytes = volume.read_segment(&format!("{base}/{MAP_SEGMENT}"))?;
    let idx_bytes = volume.read_segment(&format!("{base}/{IDX_SEGMENT}"))?;

    Map::open_with(
        arn,
        &map_bytes,
        &idx_bytes,
        graph,
        &lexicon.iri(lexicon.size),
        gap_policy,
        locus,
    )
}

/// Whether an image declares itself `aff4:DiscontiguousImage`.
///
/// **This type is not in the AFF4 Standard v1.0**.
/// It occurs in aff4-cpp-lite (`AFF4Lexicon.cc:41`) and is written by
/// at least one commerical tool, whose containers omit `mapGapDefaultStream`
/// while still leaving holes.
fn declares_discontiguous(arn: &Arn, graph: &Graph) -> bool {
    graph.types(arn.as_str()).iter().any(|iri| {
        let local = iri.rsplit_once(['#', '/']).map_or(*iri, |(_, name)| name);
        local == "DiscontiguousImage"
    })
}
