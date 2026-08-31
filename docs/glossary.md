# Glossary

This is a glossary of AFF4 terms as the `aff4tools` project uses them. This has been machine generated and lightly edited by a person. Requested corrections welcome.

See the [AFF4 Standard Specification](https://github.com/aff4/Standard) for more.

---

## The storage layer

### volume

The base or root of an AFF4 storage Container is defined as a Volume. 
In all known AFF4 implementations, it's a ZIP file. It holds ZIP
segments and is identified by its own GUID, an ARN such as
`aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad`.

Note: in an AFF4, "Volume" is **not a unit of evidence being preserved.** In ordinary 
forensic usage, a "volume" is often a logical partition -- the thing an examiner mounts.
But when talking about an .aff4, the file is a ZIP volume.

This naming collision is why the code says `ZipVolume` and `ZipVolumeSet` rather than
`Volume`/`VolumeSet`. When writing for examiners, prefer "container" for the .aff4
file, and reserve "volume" for their accustomed meaning.

### segment

Any member inside a ZIP archive. `information.turtle`,
`version.txt`, `container.description`, a bevy, a bevy index, `map`, `idx`,
`mapPath`, and each `.blockHash.<alg>` are all segments.

A segment is the storage layer's unit and carries no meaning by itself; what a
segment *is* comes from its name and from what `information.turtle` says about
it. A container with 16,435 members has 16,435 segments regardless of how many
streams or images it describes.

**Not a [part](#part).** A segment lives inside a volume; a part *is* a volume,
one file of a [split set](#split-set). This meaning of "segment" is fixed and
must not be reused for a file of a set.

### part

**One file of a split set** — `evidence_001.aff4`, `evidence_002.aff4`, and so
on. A part is a whole [volume](#volume): it has its own ARN, its own ZIP
central directory, and opens on its own.

**Not a [segment](#segment), and the two must never be swapped.** A segment is a
member *inside* a volume; a part *is* a volume. A six-part set of containers
holding 3,000 members each has six parts and 18,000 segments. Avoid "segmented"
as an adjective for a set, which reads as "made of segments" — say "split set".

### split set

Several [parts](#part) holding one image between them, whether allocated
[sequentially](#sequential) or [striped](#stripe). `--split-folder <DIR>` reads
one: parts are ordered by the numbers in their names, so `part_9` precedes
`part_10`, and a gap in the numbering is refused rather than silently skipped.

Every part declares the same [DiskImage](#image) ARN — v1.0a §7.1's point of
commonality — which is what makes them one image rather than several.

### split file

`acquire --split-file <SIZE>`: writing one acquisition across several parts,
starting a new one each time the current reaches the threshold. The threshold
counts bytes **on disk**, so parts stay near the chosen size whatever the
compression ratio, and a part may overshoot by at most one [bevy](#bevy).

### sequential

The parts of [split set](#split-set) may be sequential, in which each [part](#part) is filled before the next
begins, so each part's stream occupies one contiguous run of the image address
space. This is the layout `acquire --split-file` writes. It is familiar to 
forensic examiners accustomed to the .E01 format.

Contrast split sets that are [striped](#stripe), where the streams interleave. Neither is declared
anywhere in a container: both are inferred from map geometry
(`Map::split_layout`), and both reassemble identically through the
[Map](#map).

### stripe

One volume of a set that **jointly** stores a single image, each volume holding
part of the data. Specified in Standard v1.0a §7.1.

Stripes are joined by a commonly-named [DiskImage](#image) ARN appearing
identically in every volume. Each stripe carries its own near-equivalent
[Map](#map) covering the whole address space, and declares every dependent
[image stream](#image-stream) — including those whose data lives in a sibling,
which appear as stubs with no `size` or `chunkSize`.

**Striping is not redundancy.** Losing one stripe loses data permanently. It
exists for acquisition bandwidth, not resilience. Contrast *mirrored* and
*segmented* multi-ZIP containers, also named in §7 and both unimplemented here —
note that §7's "segmented" is its own term for a multi-ZIP arrangement and is
unrelated to a [segment](#segment) inside a volume. This project says
[split set](#split-set) for what it writes, to keep clear of both.

---

## Stored data

### chunk

The fixed-size unit of compression and of block hashing: `aff4:chunkSize` bytes,
32 KiB in every corpus container but a per-stream property, never a constant.

Each chunk is compressed independently, which is what makes random access
possible. If a chunk compresses to no smaller than `chunkSize` it is stored
verbatim. Where a stream's size is not a multiple of `chunkSize`, the final
chunk is **zero-padded** and the reader trims it against `aff4:size`
(v1.0a §3.2).

### bevy

A segment holding a run of consecutive chunks — the unit in which stored image
data is actually written. Named by zero-padded number: `00000000`, `00000001`,
and so on. `aff4:chunksInSegment` gives how many chunks a bevy holds.

Every bevy has a companion [bevy index](#index) segment, `<name>.index`. Bevies
are the unit of parallel work in `src/parallel.rs`, and the unit that
`aff4tools verify` counts in its progress line.

### image stream

A seekable sequence of fixed-size chunks stored as bevies — **the thing that
holds bytes.** Typed `aff4:ImageStream`. Carries `aff4:size`,
`aff4:chunkSize`, `aff4:chunksInSegment`, and `aff4:compressionMethod`.

Contrast with [Map](#map), which stores no bytes at all. An image stream's
`aff4:hash` covers only its **stored** bytes; for example, in the canonical 
reference image `Base-Linear.aff4`, 3,964,928 stored bytes represent the 
image's 268,435,456.

An image stream's bevies live **entirely within one volume**; a stream is never
split across stripes. That is what makes striping a per-stream choice rather
than a per-segment one.

---

## Description

### Map

A **virtual address space**: an ordered list of entries, each saying "image
bytes X through Y come from target T at offset Z". Typed `aff4:Map`, stored as
a `map` segment of 28-byte `<QQQI>` entries — mapped offset, length, target
offset, target id.

**A map stores no data.** This is the mechanism that makes AFF4 cheap: a run of
268 MB of zeroes is one entry pointing at a symbolic stream, not 268 MB in the
container. 98.5% of `Base-Linear.aff4` is described this way.

The accurate distinction is **stored** versus **described** — never "real"
versus "fake". For `aff4:Zero` and `aff4:SymbolicStreamXX` the bytes were
genuinely present on the source medium and genuinely read; only their storage
is elided, and reconstruction reproduces the acquired image exactly.
`aff4:UnknownData` and `aff4:UnreadableData` are the exception: those mark
regions whose true content is *unknown*, so what reconstructs is a defined
placeholder, never to be reported as recovered content.

### Index

**Two unrelated structures share this name.** Always say which.

- **Bevy index** — segment `<bevy>.index`, 12 bytes per chunk: `<QI>`, an
  8-byte offset into the bevy and a 4-byte compressed length. Locates chunks
  within one bevy. (Note the spec's reader algorithm derives length from
  adjacent offsets and ignores the stored length field.)
- **Map target index** — segment `idx`, a newline-separated list of target
  ARNs. Line 0 is target id 0, line 1 is id 1, and so on; map entries reference
  targets by that integer id. Resolves a map entry's target to a stream.

They are different sizes, different formats, and different purposes. Conflating
them is an easy and expensive mistake.

---

## Images

### Image

The **evidence object** — the disk, file, or memory being preserved, as
distinct from the bytes storing it. Typed `aff4:Image` with more specific
subtypes. Holds no data; points via `aff4:dataStream` to a Map or image stream.

Spec §2.1 requires **multiple `rdf:type` semantics**: a disk image carries
`aff4:DiskImage`, `aff4:ContiguousImage`, *and* `aff4:Image` simultaneously,
not just the most specific one.

`aff4:DiskImage` is the type that serves as the join key across
[stripes](#stripe) — it is the one identifier deliberately held constant when
every other (volume, map, stream) differs per volume.

### ContiguousImage

An image whose address space is **fully covered**: every byte in `0..size` has
a source. A gap is a defect to report, not a hole to fill.

### DiscontiguousImage

An image that **may** have holes. Holes are filled by the stream named in
`aff4:mapGapDefaultStream`, defaulting to `aff4:Zero` when unset.

**The image type decides gap policy, not the map** — `image.rs:80` gates on
`declares_discontiguous`, which inspects the image's `rdf:type`. A map with
gaps under a `ContiguousImage` is an error even if the map declares a gap
stream; a `DiscontiguousImage` fills them. Getting this backwards means either
refusing a valid container or silently fabricating bytes for an invalid one.

---

## Metadata

### ARN

**AFF4 Resource Name** — the identifier for every object in the format:
`aff4://<guid>` optionally followed by a path, as in
`aff4://c215ba20-5648-4209-a793-1f918c723610/00000000.index`.

An ARN doubles as a **storage address**: spec §5's URI→path mapping turns it
into a segment path. An ARN within the current volume maps to a relative path;
a foreign one is percent-escaped whole and becomes a directory at the volume
root (`aff4%3A%2F%2F<guid>/…`).

Despite the `://`, an ARN is **not a URL** and need not resolve to anything on
a network. pyaff4 additionally emits byte-range ARNs of the form
`aff4://<guid>[0x4f8000:0x8000]`, an extension no standard text defines.

### RDF

The **Resource Description Framework** — the subject–predicate–object triple
model AFF4 uses for all metadata. `<aff4://…c215ba20> aff4:chunkSize "32768"`
is one triple. See https://www.w3.org/RDF/.

Its value here is extensibility: a vendor adds predicates without breaking
readers that do not know them. That is also why `aff4tools info` reports every
`rdf:type` and retains unrecognized predicates rather than discarding them.

### Turtle

The Terse RDF Triple Language, the **syntax** that RDF is written in.
Every AFF4 container must have an `information.turtle` segment. See https://www.w3.org/TR/turtle/.
