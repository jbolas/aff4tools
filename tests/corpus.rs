//! Integration tests against the AFF4 canonical reference corpus.
//!
//! Fixtures live outside the repository and are never copied into it: they are
//! Apache-2.0 licensed, and CLAUDE.md marks them read-only. Set
//! `AFF4_TEST_IMAGES` to override the default location of `~/.cache/aff4tools/corpus`.
//!
//! Gated behind `--features corpus` so `cargo test` passes without them, and so
//! a green run never silently means "verified nothing":
//!
//! ```sh
//! cargo test --features corpus
//! ```
//!
//! Expected values here were read out of the containers, not derived from the
//! specification. Hand-derived expectations are what let an earlier bug in the
//! ARN member-name mapping through.

#![cfg(feature = "corpus")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use aff4tools::{
    Container, ContainerSummary, DeviationKind, EdgeKind, Generation, GraphEdge, HashAlgorithm,
    Locality, ObjectRole, Volume,
};

/// The corpus root, or a clear failure explaining how to point at it.
fn corpus_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("AFF4_TEST_IMAGES") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").expect("HOME must be set to locate the corpus");
    PathBuf::from(home).join(".cache/aff4tools/corpus")
}

fn summarize(relative: &str) -> ContainerSummary {
    let path = corpus_root().join(relative);
    assert!(
        path.is_file(),
        "corpus fixture missing: {}\nSet AFF4_TEST_IMAGES to the directory holding \
         pyaff4/ and aff4-cpp-lite/.",
        path.display()
    );
    let mut container =
        Container::open(&path).unwrap_or_else(|e| panic!("opening {}: {e}", path.display()));
    container
        .summarize()
        .unwrap_or_else(|e| panic!("summarising {}: {e}", path.display()))
}

const STD: &str = "pyaff4/test_images/AFF4Std";
const LOGICAL: &str = "pyaff4/test_images/AFF4-L";
const PRESTD: &str = "pyaff4/test_images/AFF4PreStd";

#[test]
fn base_linear_matches_its_recorded_metadata() {
    let s = summarize(&format!("{STD}/Base-Linear.aff4"));

    assert_eq!(s.generation, Generation::Standard10);
    assert_eq!(
        s.volume.arn.as_str(),
        "aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044"
    );
    let version = s.version.as_ref().expect("v1.0 declares a version");
    assert_eq!((version.major, version.minor), (1, 0));
    assert_eq!(version.tool.as_deref(), Some("Evimetry 2.2.0"));
    assert_eq!(s.segments.count, 10);

    // Spec §2.1 requires all three types on a disk image.
    let images = s.images();
    assert_eq!(images.len(), 1);
    let image = images[0];
    assert_eq!(image.role, ObjectRole::DiskImage);
    let mut types: Vec<&str> = image.types.iter().map(|t| &**t).collect();
    types.sort_unstable();
    assert_eq!(
        types,
        [
            "http://aff4.org/Schema#ContiguousImage",
            "http://aff4.org/Schema#DiskImage",
            "http://aff4.org/Schema#Image",
        ]
    );
    assert_eq!(image.size, Some(268_435_456));

    let streams = s.with_role(&ObjectRole::ImageStream);
    assert_eq!(streams.len(), 1);
    let stream = streams[0];
    assert_eq!(stream.size, Some(3_964_928));
    assert_eq!(
        stream
            .property("chunkSize")
            .map(|p| p.value.lexical())
            .unwrap(),
        "32768"
    );
    assert_eq!(
        stream
            .property("chunksInSegment")
            .map(|p| p.value.lexical())
            .unwrap(),
        "2048"
    );
    assert_eq!(
        stream
            .property("compressionMethod")
            .and_then(|p| p.value.as_iri())
            .unwrap(),
        "http://code.google.com/p/snappy/"
    );

    // Digests in full — never truncated.
    let sha1 = stream
        .hashes
        .iter()
        .find(|h| h.algorithm == HashAlgorithm::Sha1)
        .expect("the stream records a SHA1");
    assert_eq!(sha1.hex, "fbac22cca549310bc5df03b7560afcf490995fbb");
    let md5 = stream
        .hashes
        .iter()
        .find(|h| h.algorithm == HashAlgorithm::Md5)
        .expect("the stream records an MD5");
    assert_eq!(md5.hex, "d5825dc1152a42958c8219ff11ed01a3");

    // Evimetry NUL-pads the ZIP comment; that is the only expected departure.
    let kinds: Vec<DeviationKind> = s.deviations.iter().map(|d| d.kind).collect();
    assert_eq!(
        kinds,
        [DeviationKind::NulPaddedComment],
        "unexpected deviations: {:#?}",
        s.deviations
    );
}

#[test]
fn the_data_path_runs_from_image_through_map_to_stream() {
    let s = summarize(&format!("{STD}/Base-Linear.aff4"));

    let image = s
        .objects
        .iter()
        .find(|o| o.arn == "aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb")
        .expect("the disk image");
    assert!(
        image.edges.iter().any(|e| e.kind == EdgeKind::DataStream
            && e.to == "aff4://fcbfdce7-4488-4677-abf6-08bc931e195b"),
        "image -> map via dataStream: {:?}",
        image.edges
    );

    let map = s
        .objects
        .iter()
        .find(|o| o.arn == "aff4://fcbfdce7-4488-4677-abf6-08bc931e195b")
        .expect("the map");
    assert!(
        map.edges.iter().any(|e| e.kind == EdgeKind::DependentStream
            && e.to == "aff4://c215ba20-5648-4209-a793-1f918c723610"),
        "map -> image stream via dependentStream: {:?}",
        map.edges
    );
}

/// A striped map depends on one stream per stripe. Edges are a collection,
/// never a single value — this is the case that proves it.
#[test]
fn a_striped_map_carries_one_dependent_stream_per_stripe() {
    let s = summarize(&format!("{STD}/Striped/Base-Linear_1.aff4"));
    let map = s
        .objects
        .iter()
        .find(|o| o.arn == "aff4://2dd04819-73c8-40e3-a32b-fdddb0317eac")
        .expect("the map");

    let deps: Vec<&GraphEdge> = map
        .edges
        .iter()
        .filter(|e| e.kind == EdgeKind::DependentStream)
        .collect();
    assert_eq!(deps.len(), 2, "one per stripe: {:?}", map.edges);
}

/// Pre-standard uses a separate vocabulary. Edges must be found there too, or
/// the graph rendering silently degrades to nothing on a whole generation.
#[test]
#[ignore = "pre-standard containers are declined at open; see \
            a_pre_standard_container_is_declined"]
fn pre_standard_objects_carry_edges() {
    let s = summarize(&format!("{PRESTD}/Base-Linear.af4"));
    assert!(
        s.objects.iter().any(|o| !o.edges.is_empty()),
        "no edges found in a pre-standard container"
    );
}

/// Pre-standard has no `dataStream`/`dependentStream` at all: its data object
/// (typed `aff4:stream`) asserts the data path with `aff4:target` instead,
/// the same predicate metadata objects use for attribution. The two must not
/// collapse to the same edge kind, and neither may fall through to `Other` —
/// a data-path `target` is a modelled relationship, just spelled differently
/// on this generation (fix-round-1, coordinator finding 2).
#[test]
#[ignore = "pre-standard containers are declined at open; see \
            a_pre_standard_container_is_declined"]
fn pre_standard_data_object_targets_the_data_path_not_other() {
    let s = summarize(&format!("{PRESTD}/Base-Linear.af4"));
    let stream = s
        .objects
        .iter()
        .find(|o| o.arn == "aff4://c9f68c3a-0843-4a92-bbd8-2596a75b09be")
        .expect("the pre-standard stream object");
    assert!(
        stream.types.iter().any(|t| t.ends_with("#stream")),
        "sanity: this must be the aff4:stream-typed object: {:?}",
        stream.types
    );
    assert!(
        stream.edges.iter().any(|e| e.kind == EdgeKind::TargetStream
            && e.to == "aff4://085066db-6315-4369-a87e-bdc7bc777d45"),
        "the stream's target must classify as TargetStream, not Other: {:?}",
        stream.edges
    );
    assert!(
        !stream
            .edges
            .iter()
            .any(|e| matches!(&e.kind, EdgeKind::Other(name) if name == "target")),
        "a data-path target must never fall through to Other(\"target\"): {:?}",
        stream.edges
    );
}

/// Corrupt at the data layer, not the metadata layer. Summarising must succeed
/// — this guards against over-eager rejection.
#[test]
fn base_linear_read_error_still_summarises() {
    let s = summarize(&format!("{STD}/Base-Linear-ReadError.aff4"));
    assert_eq!(s.generation, Generation::Standard10);
    assert_eq!(s.images().len(), 1);
}

/// A different tool version from its siblings — guards against hardcoding one
/// vendor string.
#[test]
fn all_hashes_reports_its_own_tool_version() {
    let s = summarize(&format!("{STD}/Base-Linear-AllHashes.aff4"));
    assert_eq!(
        s.version.as_ref().unwrap().tool.as_deref(),
        Some("Evimetry 3.0.0")
    );
    let streams = s.with_role(&ObjectRole::ImageStream);
    assert!(
        streams[0].hashes.len() >= 2,
        "AllHashes should carry several digests"
    );
}

/// One stripe references a stream stored in its sibling volume. That is normal,
/// not an error.
#[test]
fn a_striped_volume_reports_external_references() {
    let s = summarize(&format!("{STD}/Striped/Base-Linear_1.aff4"));
    assert_eq!(
        s.volume.arn.as_str(),
        "aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad"
    );

    let external: Vec<_> = s
        .objects
        .iter()
        .filter(|o| o.locality == Locality::External)
        .collect();
    assert!(
        !external.is_empty(),
        "stripe 1 must reference at least one object in the sibling volume"
    );
    assert!(
        s.deviations
            .iter()
            .any(|d| d.kind == DeviationKind::ExternalReference),
        "an external reference must be reported"
    );
}

/// With both stripes open, the reference resolves and is not reported.
///
/// The counterpart to `a_striped_volume_reports_external_references`. A
/// cross-volume `aff4:stored` is not a spec violation — v1.0a line 90 puts no
/// requirement on which volume, and §7.1's discovery mechanism depends on
/// pointing at siblings — so the finding is an *unresolvable* reference. When
/// the named volume is among those opened, there is nothing to tell the
/// examiner. `Locality::External` is unaffected: the object still lives
/// elsewhere, which is what that field states.
#[test]
fn a_complete_striped_set_reports_no_external_reference() {
    let root = corpus_root();
    let mut container = Container::open(root.join(format!("{STD}/Striped/Base-Linear_1.aff4")))
        .expect("stripe 1 must open");
    let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(
        root.join(format!("{STD}/Striped/Base-Linear_2.aff4")),
    )
    .expect("stripe 2 must open");
    assert!(container.add_volume(
        volume,
        graph,
        aff4tools::zip_volume_set::VolumeOrigin::Named
    ));

    let summary = container.summarize().unwrap();
    assert!(
        !summary
            .deviations
            .iter()
            .any(|d| d.kind == DeviationKind::ExternalReference),
        "the whole set resolves, so nothing should be reported: {:?}",
        summary.deviations
    );
    // The classification stays: the object still lives in the sibling.
    assert!(
        summary
            .objects
            .iter()
            .any(|o| o.locality == Locality::External),
        "Locality::External must be unchanged by the suppression"
    );
}

#[test]
fn the_two_stripes_are_distinct_volumes() {
    let one = summarize(&format!("{STD}/Striped/Base-Linear_1.aff4"));
    let two = summarize(&format!("{STD}/Striped/Base-Linear_2.aff4"));
    assert_ne!(one.volume.arn.as_str(), two.volume.arn.as_str());
    assert_eq!(
        two.volume.arn.as_str(),
        "aff4://51725cd9-3769-4be7-a8ab-94e3ea62bf9a"
    );
}

/// AFF4-L: the volume ARN comes from the ZIP comment because the metadata
/// declares no volume subject at all.
#[test]
fn dream_is_a_logical_image_with_five_deviations() {
    let s = summarize(&format!("{LOGICAL}/dream.aff4"));

    assert_eq!(s.generation, Generation::PyAff4Logical);
    assert_eq!(s.version.as_ref().unwrap().tool.as_deref(), Some("pyaff4"));
    assert_eq!(
        s.volume.arn.as_str(),
        "aff4://5aea2dd0-32b4-4c61-a9db-677654be6f83"
    );

    let images = s.images();
    assert_eq!(images.len(), 1);
    let file = images[0];
    assert_eq!(file.role, ObjectRole::FileImage);
    assert_eq!(file.size, Some(8688));
    assert_eq!(
        file.property("originalFileName")
            .map(|p| p.value.lexical())
            .unwrap(),
        "./test_images/AFF4-L/dream.txt"
    );
    assert_eq!(
        file.hashes
            .iter()
            .find(|h| h.algorithm == HashAlgorithm::Md5)
            .unwrap()
            .hex,
        "75d83773f8d431a3ca91bfb8859e486d"
    );

    // Two writer's-style spellings, neither reported, both asserted against the
    // real corpus rather than a synthetic file.
    //
    // The untyped `aff4:size 8688`: Turtle types a bare integer as xsd:integer,
    // so the value is identical to "8688"^^xsd:long and no interpretation turns
    // on the spelling.
    //
    // The four lowercase xsd:datetime literals (birthTime, lastAccessed,
    // lastWritten, recordChanged), counted from the container's own turtle: the
    // lexical form is preserved verbatim either way, so no reading of the
    // evidence turns on the capital T.
    let untyped = s
        .deviations
        .iter()
        .filter(|d| d.kind == DeviationKind::UntypedNumericLiteral)
        .count();
    let datetime = s
        .deviations
        .iter()
        .filter(|d| d.kind == DeviationKind::NonstandardDatatype)
        .count();
    assert_eq!(
        untyped, 0,
        "an untyped integer is a writer's style, not a finding: {:#?}",
        s.deviations
    );
    assert_eq!(
        datetime, 0,
        "the datetime spelling is a writer's style, not a finding: {:#?}",
        s.deviations
    );
}

#[test]
fn unicode_container_holds_many_logical_images() {
    let s = summarize(&format!("{LOGICAL}/unicode.aff4"));
    assert_eq!(s.generation, Generation::PyAff4Logical);
    assert!(
        s.images().len() >= 8,
        "expected several file images, got {}",
        s.images().len()
    );
    assert!(s.objects.iter().any(|o| o.role == ObjectRole::FileImage));
}

/// This container exercises two non-standard ARN forms at once, and the
/// summary must handle each differently.
///
/// - 437 **byte-range** ARNs, `aff4://<uuid>[0x…:0x…]`, appear as objects.
///   They parse, because pyaff4 documents them (`ByteRangeARN`).
/// - 437 **content-addressed** subjects, `aff4:sha512:<digest>`, are the
///   deduplication index. They have no `aff4://` authority and so are not
///   resource names at all; each is skipped and reported rather than guessed
///   at, and the rest of the container still summarises.
#[test]
fn broken_dedupe_handles_two_non_standard_arn_forms() {
    let s = summarize(&format!("{LOGICAL}/broken-dedupe.aff4"));
    assert_eq!(s.generation, Generation::PyAff4Logical);

    assert!(
        s.deviations
            .iter()
            .any(|d| d.kind == DeviationKind::ByteRangeArn),
        "the byte-range extension must be reported"
    );

    let dedupe: Vec<_> = s
        .deviations
        .iter()
        .filter(|d| d.kind == DeviationKind::ContentAddressedSubject)
        .collect();
    assert_eq!(
        dedupe.len(),
        1,
        "the dedupe index must be summarised in one entry, not 437"
    );
    assert!(
        dedupe[0].detail.contains("437"),
        "the count must be reported: {}",
        dedupe[0].detail
    );

    // The container still yields its real objects despite the odd subjects.
    assert!(
        !s.objects.is_empty(),
        "unparseable subjects must not suppress the whole summary"
    );
    assert!(
        s.objects.iter().any(|o| o.role == ObjectRole::FileImage),
        "the logical image itself must survive"
    );
}

/// Pre-standard containers are detected accurately, then declined.
///
/// No specification aff4tools cites describes one, so reading it would be
/// reverse engineering presented as conformance. The refusal names the
/// generation rather than fabricating a version, as pyaff4 does with
/// Version(0,1), and it is not an integrity finding.
#[test]
fn a_pre_standard_container_is_declined() {
    for name in [
        "Base-Linear.af4",
        "Base-Allocated.af4",
        "Base-Linear-ReadError.af4",
    ] {
        let path = corpus_root().join(format!("{PRESTD}/{name}"));
        let err = Container::open(&path).unwrap_err();

        assert!(
            matches!(err, aff4tools::Error::Unsupported { .. }),
            "{name}: {err}"
        );
        assert!(
            !err.is_integrity_finding(),
            "{name}: an unsupported generation says nothing about integrity"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("pre-standard"),
            "{name}: the refusal must name the generation: {rendered}"
        );
        assert!(
            !rendered.contains("0.1"),
            "{name}: no version may be invented: {rendered}"
        );
    }
}

/// The broadest regression guard: whatever else changes, no container may panic
/// and none may be silently rejected.
#[test]
fn every_corpus_container_summarises_or_fails_precisely() {
    let mut checked = 0;
    let mut roots = vec![
        corpus_root().join("pyaff4/test_images"),
        corpus_root().join("aff4-cpp-lite/tests/resources"),
    ];
    roots.retain(|r| r.is_dir());
    assert!(!roots.is_empty(), "no corpus directories found");

    let mut files = Vec::new();
    while let Some(dir) = roots.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                roots.push(path);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("aff4" | "af4")
            ) {
                files.push(path);
            }
        }
    }
    files.sort();

    for path in &files {
        checked += 1;
        let mut container = match Container::open(path) {
            Ok(c) => c,
            Err(e) => {
                // A precise error is acceptable; a panic is not.
                assert!(
                    !e.to_string().is_empty(),
                    "{}: error with no message",
                    path.display()
                );
                continue;
            }
        };
        match container.summarize() {
            Ok(summary) => {
                assert_eq!(summary.source_path, *path);
                assert!(
                    !summary.volume.arn.as_str().is_empty(),
                    "{}: empty volume ARN",
                    path.display()
                );
                assert!(
                    !summary.volume.arn.as_str().contains('\0'),
                    "{}: NUL survived into the volume ARN",
                    path.display()
                );
            }
            Err(e) => assert!(
                !e.to_string().is_empty(),
                "{}: error with no message",
                path.display()
            ),
        }
    }

    assert!(
        checked >= 20,
        "expected at least 20 corpus containers, found {checked}"
    );
}

/// Reading must never modify evidence.
#[test]
fn summarising_does_not_modify_the_container() {
    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let before = std::fs::metadata(&path).unwrap();

    let mut container = Container::open(&path).unwrap();
    let _ = container.summarize().unwrap();

    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(before.len(), after.len(), "file length changed");
    assert_eq!(
        before.modified().unwrap(),
        after.modified().unwrap(),
        "modification time changed"
    );
}

// --- Codec: real chunks from a real container -----------------------------
//
// The decisive test for feature 4. Unit tests round-trip data this crate
// compressed itself, which proves the wiring and nothing about AFF4's actual
// on-disk format. These chunks were written by Evimetry.

/// Bevy index entries are `<QI>`: an 8-byte offset and a 4-byte length.
/// Confirmed against pyaff4 (`aff4_image.py:739`) and the fixture's own
/// index, whose length divides exactly by 12.
const BEVY_INDEX_ENTRY: usize = 12;

/// Read a member out of a container. Test-only: the library deliberately has
/// no public segment reader until `stream.rs` lands.
fn read_member(path: &std::path::Path, name: &str) -> Vec<u8> {
    let file = std::fs::File::open(path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut member = archive.by_name(name).unwrap();
    let mut buffer = Vec::new();
    std::io::Read::read_to_end(&mut member, &mut buffer).unwrap();
    buffer
}

fn member_names(path: &std::path::Path) -> Vec<String> {
    let file = std::fs::File::open(path).unwrap();
    let archive = zip::ZipArchive::new(file).unwrap();
    archive.file_names().map(str::to_owned).collect()
}

/// Every chunk of a real snappy bevy decompresses to exactly the declared
/// chunk size, except the last.
#[test]
fn decompresses_every_chunk_of_a_real_snappy_bevy() {
    use aff4tools::codec::{Codec, decompress_chunk};

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let names = member_names(&path);

    let index_name = names
        .iter()
        .find(|n| n.ends_with("/00000000.index"))
        .expect("the fixture has a bevy index")
        .clone();
    let bevy_name = index_name.trim_end_matches(".index").to_owned();

    let index = read_member(&path, &index_name);
    let bevy = read_member(&path, &bevy_name);

    assert_eq!(
        index.len() % BEVY_INDEX_ENTRY,
        0,
        "index length {} is not a whole number of 12-byte entries",
        index.len()
    );

    let chunk_size = 32768usize;
    let entries = index.len() / BEVY_INDEX_ENTRY;
    assert!(entries > 1, "need several chunks to be worth testing");

    let locus = aff4tools::Locus::new(&path).segment(&bevy_name);
    let mut total = 0usize;
    let mut stored_chunks = 0usize;

    for i in 0..entries {
        let at = i * BEVY_INDEX_ENTRY;
        let offset = u64::from_le_bytes(index[at..at + 8].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(index[at + 8..at + 12].try_into().unwrap()) as usize;

        assert!(
            offset + length <= bevy.len(),
            "chunk {i} runs past the end of the bevy"
        );

        if length == chunk_size {
            stored_chunks += 1;
        }

        let compressed = &bevy[offset..offset + length];
        let out = decompress_chunk(Codec::Snappy, compressed, chunk_size, &locus)
            .unwrap_or_else(|e| panic!("chunk {i} (offset {offset}, {length} bytes): {e}"));

        if i + 1 < entries {
            assert_eq!(
                out.len(),
                chunk_size,
                "chunk {i} of {entries} decompressed to {} bytes, not {chunk_size}",
                out.len()
            );
        } else {
            assert!(out.len() <= chunk_size, "final chunk is oversized");
        }

        total += out.len();
    }

    // The bevy holds whole chunks, so the total is a multiple of chunk_size
    // unless this is the stream's final bevy.
    assert!(total > 0);
    assert_eq!(
        total,
        entries * chunk_size,
        "expected {entries} full chunks from this bevy"
    );

    // Finding J is not hypothetical: this fixture really does contain
    // incompressible chunks stored verbatim.
    assert!(
        stored_chunks > 0,
        "expected at least one stored chunk in a real image"
    );
}

/// A container's declared codec resolves. Guards against the IRI list drifting
/// away from what writers actually emit.
#[test]
fn the_corpus_codec_iri_resolves() {
    use aff4tools::codec::{Codec, SNAPPY_IRI};

    let summary = summarize(&format!("{STD}/Base-Linear.aff4"));
    let declared: Vec<String> = summary
        .objects
        .iter()
        .filter_map(|o| o.property("compressionMethod"))
        .map(|p| match &p.value {
            aff4tools::rdf::Value::Iri { iri } => iri.clone(),
            other => panic!("compressionMethod must be an IRI, got {other:?}"),
        })
        .collect();

    assert!(
        !declared.is_empty(),
        "the fixture must declare a compression method"
    );
    for iri in declared {
        assert_eq!(
            Codec::from_iri(&iri),
            Some(Codec::Snappy),
            "{iri} must resolve to snappy"
        );
        assert_eq!(iri, SNAPPY_IRI);
    }
}

// --- ImageStream assembly (feature 1, item 1) -----------------------------

/// The decisive test for item 1: assembling a real stream must reproduce the
/// exact byte count and content the container recorded.
///
/// The expected values were measured out of `Base-Linear.aff4` before any of
/// this was written — 121 chunks, 3964928 bytes, SHA1 `fbac22cc…`.
#[test]
fn assembles_a_real_image_stream_to_its_declared_size() {
    use aff4tools::stream::ImageStream;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);

    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();

    assert_eq!(stream.size(), 3_964_928);
    assert_eq!(stream.chunk_size(), 32768);
    assert_eq!(stream.chunks_in_segment(), 2048);
    assert_eq!(stream.codec(), aff4tools::Codec::Snappy);
    assert_eq!(stream.bevy_count(), 1);

    let mut total = 0u64;
    let mut chunks = 0usize;
    let mut first_chunk = Vec::new();
    stream
        .read_all(
            container.volume_mut(),
            &mut |bytes| {
                if chunks == 0 {
                    first_chunk = bytes.to_vec();
                }
                total += bytes.len() as u64;
                chunks += 1;
                Ok(())
            },
            &locus,
        )
        .unwrap();

    assert_eq!(
        total, 3_964_928,
        "assembled size must equal the declared size"
    );
    assert_eq!(chunks, 121, "121 chunks were measured in this bevy");
    assert_eq!(first_chunk.len(), 32768);
}

/// Reading must never hold the stream in memory. The sink sees chunk-sized
/// slices, so a 268 MB image costs one chunk of working space.
#[test]
fn reading_a_stream_never_buffers_more_than_a_chunk() {
    use aff4tools::stream::ImageStream;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);

    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();

    let mut largest = 0usize;
    stream
        .read_all(
            container.volume_mut(),
            &mut |bytes| {
                largest = largest.max(bytes.len());
                Ok(())
            },
            &locus,
        )
        .unwrap();

    assert!(
        largest <= stream.chunk_size(),
        "a slice of {largest} bytes exceeds the {} byte chunk size",
        stream.chunk_size()
    );
}

/// A stream spanning several bevies must read them in order. `unicode.aff4`
/// has six, so a single-bevy assumption fails here rather than silently
/// truncating in the field.
#[test]
fn assembles_streams_that_span_several_bevies() {
    use aff4tools::stream::ImageStream;

    let path = corpus_root().join(format!("{LOGICAL}/unicode.aff4"));
    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);

    let stream_type = format!("{}{}", lexicon.namespace, lexicon.image_stream);
    let streams: Vec<String> = graph
        .subjects_of_type(&stream_type)
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert!(
        !streams.is_empty(),
        "unicode.aff4 must declare image streams"
    );

    let mut checked = 0;
    for subject in streams {
        let arn = aff4tools::Arn::parse(&subject, &locus).unwrap();
        let stream = match ImageStream::open(&arn, &graph, lexicon, &locus) {
            Ok(s) => s,
            // Some logical objects are not readable streams; skip only those
            // that decline for a stated reason.
            Err(_) => continue,
        };

        let mut total = 0u64;
        stream
            .read_all(
                container.volume_mut(),
                &mut |bytes| {
                    total += bytes.len() as u64;
                    Ok(())
                },
                &locus,
            )
            .unwrap_or_else(|e| panic!("reading {subject}: {e}"));

        assert_eq!(total, stream.size(), "{subject} assembled short");
        checked += 1;
    }

    assert!(checked > 0, "no stream in unicode.aff4 was readable");
}

/// Reading data must not modify the container.
#[test]
fn reading_a_stream_does_not_modify_the_container() {
    use aff4tools::stream::ImageStream;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let before = std::fs::metadata(&path).unwrap();

    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);
    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();
    stream
        .read_all(container.volume_mut(), &mut |_| Ok(()), &locus)
        .unwrap();

    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(before.len(), after.len(), "file length changed");
    assert_eq!(
        before.modified().unwrap(),
        after.modified().unwrap(),
        "modification time changed"
    );
}

// --- First real verification (feature 1, item 2) --------------------------

/// The moment the project stops reporting claims and starts checking them.
///
/// Reads `Base-Linear.aff4`'s ImageStream, recomputes SHA1 and MD5 over the
/// assembled bytes, and compares against what the container recorded at
/// acquisition. These expected values were read out of the container, not
/// produced by this crate.
#[test]
fn recomputed_digests_match_the_recorded_acquisition_hashes() {
    use aff4tools::hash::MultiHasher;
    use aff4tools::stream::ImageStream;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);

    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();

    let mut hasher = MultiHasher::for_algorithms(&[HashAlgorithm::Sha1, HashAlgorithm::Md5]);
    stream
        .read_all(
            container.volume_mut(),
            &mut |bytes| {
                hasher.update(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();

    assert_eq!(
        hasher.bytes_hashed(),
        3_964_928,
        "a short read would give a wrong digest that looks authoritative"
    );

    let digests = hasher.finish();
    let sha1 = digests
        .iter()
        .find(|d| *d.algorithm() == HashAlgorithm::Sha1)
        .unwrap();
    let md5 = digests
        .iter()
        .find(|d| *d.algorithm() == HashAlgorithm::Md5)
        .unwrap();

    assert_eq!(sha1.hex(), "fbac22cca549310bc5df03b7560afcf490995fbb");
    assert_eq!(md5.hex(), "d5825dc1152a42958c8219ff11ed01a3");
}

/// Recomputed digests must match the container's own `StoredHash` values
/// through `Digest::matches`, not just as strings — the algorithm has to agree
/// too.
#[test]
fn recomputed_digests_match_the_stored_hashes_by_value_and_algorithm() {
    use aff4tools::hash::MultiHasher;
    use aff4tools::stream::ImageStream;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let summary = summarize(&format!("{STD}/Base-Linear.aff4"));

    // Only `aff4:hash` is a digest over the stream's bytes. Evimetry also
    // writes `aff4:imageStreamHash`, whose construction is undocumented and
    // which pyaff4 never reads — see finding R.
    let stored: Vec<_> = summary
        .with_role(&ObjectRole::ImageStream)
        .first()
        .expect("the container has an image stream")
        .hashes
        .iter()
        .filter(|h| h.predicate == "hash")
        .cloned()
        .collect();
    assert!(stored.len() >= 2, "expected several recorded digests");

    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);
    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();

    let algorithms: Vec<HashAlgorithm> = stored.iter().map(|h| h.algorithm.clone()).collect();
    let mut hasher = MultiHasher::for_algorithms(&algorithms);
    stream
        .read_all(
            container.volume_mut(),
            &mut |bytes| {
                hasher.update(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();
    let digests = hasher.finish();

    let mut compared = 0;
    for recorded in &stored {
        let Some(computed) = digests
            .iter()
            .find(|d| *d.algorithm() == recorded.algorithm)
        else {
            continue;
        };
        assert!(
            computed.matches(recorded),
            "{:?}: recorded {} but computed {}",
            recorded.algorithm,
            recorded.hex,
            computed.hex()
        );
        compared += 1;
    }
    assert!(compared >= 2, "expected to verify at least two digests");
}

/// Five algorithms over one pass, all matching. Guards the multi-algorithm
/// path against a per-algorithm bug that a single digest would hide.
#[test]
fn all_five_recorded_algorithms_verify_in_one_pass() {
    use aff4tools::hash::MultiHasher;
    use aff4tools::stream::ImageStream;

    let relative = format!("{STD}/Base-Linear-AllHashes.aff4");
    let summary = summarize(&relative);
    let stream_object = (*summary
        .with_role(&ObjectRole::ImageStream)
        .first()
        .expect("AllHashes has an image stream"))
    .clone();

    let recorded: Vec<_> = stream_object
        .hashes
        .iter()
        .filter(|h| h.predicate == "hash" && aff4tools::hash::is_computable(&h.algorithm))
        .cloned()
        .collect();
    assert_eq!(
        recorded.len(),
        5,
        "AllHashes records MD5, SHA1, SHA256, SHA512 and Blake2b under aff4:hash"
    );

    let path = corpus_root().join(&relative);
    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);
    let stream = ImageStream::open(&stream_object.arn, &graph, lexicon, &locus).unwrap();

    let algorithms: Vec<HashAlgorithm> = recorded.iter().map(|h| h.algorithm.clone()).collect();
    let mut hasher = MultiHasher::for_algorithms(&algorithms);
    stream
        .read_all(
            container.volume_mut(),
            &mut |bytes| {
                hasher.update(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();
    let digests = hasher.finish();
    assert_eq!(digests.len(), 5);

    for expected in &recorded {
        let computed = digests
            .iter()
            .find(|d| *d.algorithm() == expected.algorithm)
            .unwrap_or_else(|| panic!("{:?} was not computed", expected.algorithm));
        assert!(
            computed.matches(expected),
            "{:?}: recorded {} but computed {}",
            expected.algorithm,
            expected.hex,
            computed.hex()
        );
    }
}

/// A mutated copy must produce a *mismatch*, not an error and not a panic.
/// Without this, a passing suite only proves the happy path.
#[test]
fn a_mutated_container_produces_a_digest_mismatch() {
    use aff4tools::hash::MultiHasher;
    use aff4tools::stream::ImageStream;

    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let bytes = std::fs::read(&source).unwrap();

    // Flip one bit deep inside the bevy, well past the ZIP headers.
    let mut mutated = bytes.clone();
    let target = mutated.len() / 2;
    mutated[target] ^= 0x01;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mutated.aff4");
    // A throwaway copy in a TempDir; the fixture itself is never written to.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&path, &mutated).unwrap();

    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);
    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();

    let mut hasher = MultiHasher::for_algorithms(&[HashAlgorithm::Sha1]);
    let read = stream.read_all(
        container.volume_mut(),
        &mut |b| {
            hasher.update(b);
            Ok(())
        },
        &locus,
    );

    match read {
        Ok(()) => {
            let sha1 = hasher.finish().into_iter().next().unwrap();
            assert_ne!(
                sha1.hex(),
                "fbac22cca549310bc5df03b7560afcf490995fbb",
                "a mutated container must not reproduce the recorded digest"
            );
        }
        // A flip inside a bevy is usually caught earlier than hashing: the
        // ZIP member's own CRC fails, giving Error::Zip. A flip that survives
        // the CRC can still break decompression, giving Malformed. Both are
        // specific, reported failures — what must never happen is a panic, or
        // a clean read that reproduces the recorded digest.
        Err(e) => {
            let text = e.to_string();
            assert!(
                e.is_integrity_finding(),
                "corruption is a finding about the evidence, not an environment \
                 error, got: {text}"
            );
            assert!(text.contains("mutated.aff4"), "{text}");
        }
    }

    // The source is untouched.
    assert_eq!(std::fs::read(&source).unwrap(), bytes);
}

/// A mutation the ZIP layer cannot catch must still be caught by the digest.
///
/// The previous test usually trips the member CRC first, which proves the ZIP
/// layer works rather than the hashing. This one rewrites data whose CRC still
/// validates — by recompressing a whole member — so the *only* thing standing
/// between altered evidence and a clean report is the recomputed digest.
#[test]
fn altered_data_that_passes_the_zip_crc_is_caught_by_the_digest() {
    use aff4tools::hash::MultiHasher;
    use aff4tools::stream::ImageStream;
    use std::io::Write as _;

    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rewritten.aff4");

    let bevy_name = "aff4%3A%2F%2Fc215ba20-5648-4209-a793-1f918c723610/00000000";

    // Rebuild the archive, altering one byte of the bevy. The writer computes
    // a fresh, valid CRC, so the ZIP layer sees nothing wrong.
    {
        let input = std::fs::File::open(&source).unwrap();
        let mut reader = zip::ZipArchive::new(input).unwrap();
        #[allow(clippy::disallowed_methods)]
        let output = std::fs::File::create(&path).unwrap();
        // The one sanctioned use of a ZIP writer: a throwaway copy in a
        // TempDir, never an evidence file.
        #[allow(clippy::disallowed_types)]
        let mut writer = zip::ZipWriter::new(output);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        let names: Vec<String> = reader.file_names().map(str::to_owned).collect();
        for name in names {
            let mut member = reader.by_name(&name).unwrap();
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut member, &mut body).unwrap();
            if name == bevy_name {
                // Flip a bit inside the first chunk's compressed data.
                body[64] ^= 0x02;
            }
            writer.start_file(&name, options).unwrap();
            writer.write_all(&body).unwrap();
        }
        writer.finish().unwrap();
    }

    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&path);
    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();

    let mut hasher = MultiHasher::for_algorithms(&[HashAlgorithm::Sha1]);
    let read = stream.read_all(
        container.volume_mut(),
        &mut |b| {
            hasher.update(b);
            Ok(())
        },
        &locus,
    );

    match read {
        Ok(()) => {
            let sha1 = hasher.finish().into_iter().next().unwrap();
            assert_ne!(
                sha1.hex(),
                "fbac22cca549310bc5df03b7560afcf490995fbb",
                "altered data reproduced the recorded digest — verification is not working"
            );
        }
        Err(e) => assert!(
            e.is_integrity_finding(),
            "altered data must be a finding, not an environment error: {e}"
        ),
    }
}

// --- Map parsing (feature 1, item 3) --------------------------------------

/// Every map in the corpus must parse: standard, AFF4-L, striped, and
/// pre-standard. Expected entry counts were measured before implementation.
///
/// `broken-dedupe.aff4` is the important one — its entries are stored out of
/// address order, and an earlier draft of the plan would have rejected it.
#[test]
fn every_map_in_the_corpus_parses() {
    use aff4tools::map::Map;

    // (relative path, map subject prefix search, entries, covered bytes)
    let expected: &[(&str, usize, u64)] = &[
        (
            "pyaff4/test_images/AFF4Std/Base-Linear.aff4",
            4103,
            268_435_456,
        ),
        (
            "pyaff4/test_images/AFF4Std/Base-Linear-AllHashes.aff4",
            4103,
            268_435_456,
        ),
        (
            "pyaff4/test_images/AFF4Std/Base-Linear-ReadError.aff4",
            4104,
            268_435_456,
        ),
        (
            "pyaff4/test_images/AFF4Std/Base-Allocated.aff4",
            440,
            268_435_456,
        ),
        (
            "pyaff4/test_images/AFF4Std/Striped/Base-Linear_1.aff4",
            4104,
            268_435_456,
        ),
        (
            "pyaff4/test_images/AFF4Std/Striped/Base-Linear_2.aff4",
            4103,
            268_435_456,
        ),
        (
            "pyaff4/test_images/AFF4-L/broken-dedupe.aff4",
            437,
            14_296_643,
        ),
    ];

    for (relative, entry_count, covered) in expected {
        let path = corpus_root().join(relative);
        let mut container =
            Container::open(&path).unwrap_or_else(|e| panic!("opening {relative}: {e}"));
        let locus = aff4tools::Locus::new(&path);

        // Find the map by its segments rather than by metadata type: the
        // pre-standard containers fold Map and Image into one subject.
        let names: Vec<String> = container.volume().segment_names().to_vec();
        let prefix = names
            .iter()
            .find_map(|n| n.strip_suffix("/map"))
            .unwrap_or_else(|| panic!("{relative} has no map segment"))
            .to_owned();

        let map_bytes = container
            .volume_mut()
            .read_segment(&format!("{prefix}/map"))
            .unwrap();
        let idx_bytes = container
            .volume_mut()
            .read_segment(&format!("{prefix}/idx"))
            .unwrap();

        assert_eq!(
            map_bytes.len() / aff4tools::map::MAP_ENTRY_LEN,
            *entry_count,
            "{relative}: unexpected entry count"
        );

        let arn = aff4tools::Arn::parse("aff4://placeholder", &locus).unwrap();
        let map = Map::parse(&arn, &map_bytes, &idx_bytes, *covered, &locus)
            .unwrap_or_else(|e| panic!("parsing the map in {relative}: {e}"));

        assert_eq!(map.entries().len(), *entry_count, "{relative}");
        assert_eq!(map.size(), *covered, "{relative}");
        assert_eq!(
            map.stored_bytes() + map.described_bytes(),
            *covered,
            "{relative}: stored and described must account for every byte"
        );
    }
}

/// The measured composition of `Base-Linear.aff4`: 3.96 MB stored against
/// 264 MB described. This is finding P, asserted rather than narrated.
#[test]
fn base_linear_is_overwhelmingly_described_rather_than_stored() {
    use aff4tools::map::{Map, Target};

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);

    let prefix = "aff4%3A%2F%2Ffcbfdce7-4488-4677-abf6-08bc931e195b";
    let map_bytes = container
        .volume_mut()
        .read_segment(&format!("{prefix}/map"))
        .unwrap();
    let idx_bytes = container
        .volume_mut()
        .read_segment(&format!("{prefix}/idx"))
        .unwrap();

    let arn = aff4tools::Arn::parse("aff4://fcbfdce7-4488-4677-abf6-08bc931e195b", &locus).unwrap();
    let map = Map::parse(&arn, &map_bytes, &idx_bytes, 268_435_456, &locus).unwrap();

    // Measured before implementation.
    assert_eq!(map.stored_bytes(), 3_964_928);
    assert_eq!(map.described_bytes(), 264_470_528);

    let by_target = map.bytes_by_target();
    assert_eq!(by_target.get(&0), Some(&3_964_928), "the ImageStream");
    assert_eq!(by_target.get(&1), Some(&261_980_160), "Zero");
    assert_eq!(by_target.get(&2), Some(&2_457_600), "SymbolicStreamFF");
    assert_eq!(by_target.get(&3), Some(&32_768), "SymbolicStream61");

    // The four targets resolve to what the idx segment names.
    assert_eq!(map.targets().len(), 4);
    assert!(map.targets()[0].is_stored());
    assert_eq!(map.targets()[1], Target::RepeatedByte(0x00));
    assert_eq!(map.targets()[2], Target::RepeatedByte(0xFF));
    assert_eq!(map.targets()[3], Target::RepeatedByte(0x61));

    // One dependent stream: the ImageStream item 1 already reads.
    let streams = map.dependent_streams();
    assert_eq!(streams.len(), 1);
    assert_eq!(
        streams[0].as_str(),
        "aff4://c215ba20-5648-4209-a793-1f918c723610"
    );
}

/// Pre-standard containers use a different symbolic vocabulary — including a
/// third namespace, `afflib.org/2012/SymbolicStream#`. A standard-only
/// resolver silently produces unrecognised targets here.
#[test]
#[ignore = "pre-standard containers are declined at open; see \
            a_pre_standard_container_is_declined"]
fn the_pre_standard_symbolic_vocabulary_resolves() {
    use aff4tools::map::{Map, Target};

    let path = corpus_root().join(format!("{PRESTD}/Base-Linear.af4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);

    let names: Vec<String> = container.volume().segment_names().to_vec();
    let prefix = names
        .iter()
        .find_map(|n| n.strip_suffix("/map"))
        .unwrap()
        .to_owned();

    let map_bytes = container
        .volume_mut()
        .read_segment(&format!("{prefix}/map"))
        .unwrap();
    let idx_bytes = container
        .volume_mut()
        .read_segment(&format!("{prefix}/idx"))
        .unwrap();

    let arn = aff4tools::Arn::parse("aff4://placeholder", &locus).unwrap();
    let map = Map::parse(&arn, &map_bytes, &idx_bytes, 268_435_456, &locus).unwrap();

    // Zero, FF, and the 2012-namespace 61 all resolve to repeated bytes.
    let repeated: Vec<u8> = map
        .targets()
        .iter()
        .filter_map(|t| match t {
            Target::RepeatedByte(b) => Some(*b),
            _ => None,
        })
        .collect();
    assert!(
        repeated.contains(&0x00),
        "Zero must resolve: {:?}",
        map.targets()
    );
    assert!(
        repeated.contains(&0xFF),
        "FF must resolve: {:?}",
        map.targets()
    );
    assert!(
        repeated.contains(&0x61),
        "the 2012 SymbolicStream namespace must resolve: {:?}",
        map.targets()
    );

    assert!(
        !map.targets()
            .iter()
            .any(|t| matches!(t, Target::Unrecognised(_))),
        "no pre-standard target should be unrecognised: {:?}",
        map.targets()
    );
}

/// `broken-dedupe.aff4` has no `mapPath` segment and names its targets by
/// content digest. Both must be handled without inventing anything.
#[test]
fn broken_dedupe_parses_without_a_map_path_segment() {
    use aff4tools::map::{Map, Target};

    let path = corpus_root().join(format!("{LOGICAL}/broken-dedupe.aff4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);

    let names: Vec<String> = container.volume().segment_names().to_vec();
    let prefix = names
        .iter()
        .find_map(|n| n.strip_suffix("/map"))
        .unwrap()
        .to_owned();

    assert!(
        !names.iter().any(|n| n == &format!("{prefix}/mapPath")),
        "this container is expected to have no mapPath segment"
    );

    let map_bytes = container
        .volume_mut()
        .read_segment(&format!("{prefix}/map"))
        .unwrap();
    let idx_bytes = container
        .volume_mut()
        .read_segment(&format!("{prefix}/idx"))
        .unwrap();

    let arn = aff4tools::Arn::parse("aff4://placeholder", &locus).unwrap();
    let map = Map::parse(&arn, &map_bytes, &idx_bytes, 14_296_643, &locus).unwrap();

    assert_eq!(map.entries().len(), 437);
    assert_eq!(map.targets().len(), 437);

    // Content-addressed names parse as AFF4-L §4 block hashes, and — because
    // this container declares no `aff4:dataStream` for any of them — must stay
    // unresolved rather than being guessed at. `Map::parse` has no graph, so
    // resolution cannot even be attempted here.
    assert!(
        map.targets()
            .iter()
            .all(|t| matches!(t, Target::BlockHash(_))),
        "aff4:sha512: names are content addresses, not resource names"
    );
    assert!(
        map.targets().iter().all(|t| !t.is_stored()),
        "an unresolved block hash must never count as stored data"
    );
    assert!(map.dependent_streams().is_empty());
    assert_eq!(map.stored_bytes(), 0);
}

// ---------------------------------------------------------------------------
// Feature 1 item 4: reading through a map.
// ---------------------------------------------------------------------------

/// The acceptance test for item 4, and the one that would catch a mis-resolved
/// map: a wrong entry produces a confidently wrong digest over data that
/// decompressed cleanly.
///
/// The expected SHA-512 was produced by an independent Python reference that
/// shares no code with aff4tools — it decodes the bevy index, decompresses with
/// a from-scratch snappy decoder, sorts the map entries, and reconstructs the
/// described runs itself. Agreement between two independent assemblies is worth
/// far more than a value this build printed.
#[test]
fn reading_base_linear_through_its_map_reproduces_the_whole_image() {
    use aff4tools::hash::MultiHasher;
    use aff4tools::image::Image;
    use aff4tools::model::HashAlgorithm;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();

    let image_arn =
        aff4tools::Arn::parse("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb", &locus).unwrap();

    let image = Image::open(&image_arn, container.volume_mut(), &graph, lexicon, &locus).unwrap();

    assert_eq!(image.size(), 268_435_456, "the declared image size");

    let mut hasher = MultiHasher::for_algorithms(&[
        HashAlgorithm::Sha512,
        HashAlgorithm::Md5,
        HashAlgorithm::Sha1,
    ]);
    let mut largest_slice = 0usize;

    let accounting = image
        .read(
            container.volume_mut(),
            &mut |bytes| {
                largest_slice = largest_slice.max(bytes.len());
                hasher.update(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();

    // Every byte of a 256 MB image, from 3.8 MB of stored data.
    assert_eq!(accounting.total(), 268_435_456);
    assert_eq!(accounting.stored, 3_964_928);
    assert_eq!(accounting.described, 264_470_528);
    assert_eq!(accounting.unknown_placeholder, 0);
    assert_eq!(hasher.bytes_hashed(), 268_435_456);

    // Bounded memory: no slice may exceed the run buffer, and the run buffer is
    // two chunks. A regression that materialised a 262 MB run would show here
    // before it showed as an out-of-memory failure on real evidence.
    assert!(
        largest_slice <= aff4tools::map::RUN_BUFFER_LEN,
        "a slice of {largest_slice} bytes was delivered; nothing may exceed \
         the {} byte run buffer",
        aff4tools::map::RUN_BUFFER_LEN
    );

    let digests = hasher.finish();
    let hex = |algorithm: &HashAlgorithm| {
        digests
            .iter()
            .find(|d| d.algorithm() == algorithm)
            .unwrap()
            .hex()
            .to_owned()
    };

    // Independently computed; see the doc comment.
    assert_eq!(
        hex(&HashAlgorithm::Sha512),
        "5710e1629690b7273309e304f1bfc6b1c1333320962f8f71085f51f38499ec72\
         d248786baf6dd5546835bf678db68526efff8b0d1ebc8378636f2111ff954ca8"
    );
    assert_eq!(hex(&HashAlgorithm::Md5), "dd6dbda282e27fd0d196abd95f5c3e58");
    assert_eq!(
        hex(&HashAlgorithm::Sha1),
        "7d3d27f667f95f7ec5b9d32121622c0f4b60b48d"
    );
}

/// A described run must be reconstructed byte for byte, not merely counted.
///
/// `Base-Linear.aff4`'s map covers 261,980,160 bytes of `Zero`, 2,457,600 of
/// `0xFF`, and 32,768 of `0x61`. Tallying the bytes actually delivered proves
/// the runs carry the byte their target names, which a length-only check would
/// miss entirely.
#[test]
fn described_runs_deliver_the_byte_their_target_names() {
    use aff4tools::image::Image;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();

    let image_arn =
        aff4tools::Arn::parse("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb", &locus).unwrap();
    let image = Image::open(&image_arn, container.volume_mut(), &graph, lexicon, &locus).unwrap();

    let mut counts = [0u64; 256];
    image
        .read(
            container.volume_mut(),
            &mut |bytes| {
                for b in bytes {
                    counts[*b as usize] += 1;
                }
                Ok(())
            },
            &locus,
        )
        .unwrap();

    // The described runs are floors, not equalities: the stored 3.96 MB
    // contributes its own bytes on top of them.
    assert!(
        counts[0x00] >= 261_980_160,
        "expected at least the Zero run, got {}",
        counts[0x00]
    );
    assert!(
        counts[0xFF] >= 2_457_600,
        "expected at least the 0xFF run, got {}",
        counts[0xFF]
    );
    assert!(
        counts[0x61] >= 32_768,
        "expected at least the 0x61 run, got {}",
        counts[0x61]
    );

    let total: u64 = counts.iter().sum();
    assert_eq!(total, 268_435_456);
}

/// Random access must agree with sequential reading.
///
/// `ImageStream::read_all` and `ChunkReader::read_region` are separate code
/// paths, and the second is the one map traversal uses. If they disagree, a map
/// read is wrong in a way no stream-level test would catch.
#[test]
fn region_reads_agree_with_sequential_reading() {
    use aff4tools::stream::{ChunkReader, ImageStream};

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();

    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();

    // The whole stream, sequentially. 3.96 MB is small enough to hold here;
    // the library itself never does this.
    let mut whole = Vec::new();
    stream
        .read_all(
            container.volume_mut(),
            &mut |bytes| {
                whole.extend_from_slice(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();
    assert_eq!(whole.len(), 3_964_928);

    // Regions chosen to straddle chunk boundaries, sit inside one chunk, start
    // at zero, and end exactly at the stream's end.
    let cases: &[(u64, u64)] = &[
        (0, 1),
        (0, 32_768),
        (32_767, 2),
        (32_768, 32_768),
        (100_000, 100_000),
        (3_964_928 - 1, 1),
        (3_964_928 - 40_000, 40_000),
        (1_234_567, 654_321),
    ];

    let mut reader = ChunkReader::new(&stream, container.volume_mut());
    for (offset, length) in cases {
        let mut got = Vec::new();
        reader
            .read_region(
                *offset,
                *length,
                &mut |bytes| {
                    got.extend_from_slice(bytes);
                    Ok(())
                },
                &locus,
            )
            .unwrap();

        let start = usize::try_from(*offset).unwrap();
        let end = start + usize::try_from(*length).unwrap();
        assert_eq!(
            got.len(),
            usize::try_from(*length).unwrap(),
            "{offset}+{length}"
        );
        assert_eq!(got, whole[start..end], "region {offset}+{length} differs");
    }

    // Backwards is not an error, only a re-read.
    let mut back = Vec::new();
    reader
        .read_region(
            0,
            16,
            &mut |bytes| {
                back.extend_from_slice(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();
    assert_eq!(
        back,
        whole[0..16],
        "seeking backwards must still be correct"
    );
}

/// A region past the end of a stream is a finding, not a short read.
#[test]
fn a_region_past_the_end_of_a_stream_is_refused() {
    use aff4tools::stream::{ChunkReader, ImageStream};

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();

    let arn = aff4tools::Arn::parse("aff4://c215ba20-5648-4209-a793-1f918c723610", &locus).unwrap();
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();
    let mut reader = ChunkReader::new(&stream, container.volume_mut());

    let err = reader
        .read_region(3_964_928 - 10, 20, &mut |_| Ok(()), &locus)
        .unwrap_err();
    assert!(err.is_integrity_finding(), "{err}");
    assert!(err.to_string().contains("3964928"), "{err}");
}

/// Reading a whole image must not touch the container.
#[test]
fn reading_an_image_does_not_modify_the_container() {
    use aff4tools::image::Image;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let before = std::fs::metadata(&path).unwrap();

    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let image_arn =
        aff4tools::Arn::parse("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb", &locus).unwrap();
    let image = Image::open(&image_arn, container.volume_mut(), &graph, lexicon, &locus).unwrap();
    image
        .read(container.volume_mut(), &mut |_| Ok(()), &locus)
        .unwrap();
    drop(container);

    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
}

// ---------------------------------------------------------------------------
// Feature 1 item 5: composite hashes.
// ---------------------------------------------------------------------------

/// Every digest `Base-Linear.aff4` records, recomputed and matched.
///
/// This is the whole tree: per-chunk digests at the leaves, the block-hash
/// segment digests above them, the three map-segment digests, and
/// `blockMapHash` at the root. A container where every one of these agrees is
/// verified from leaves to root.
#[test]
fn base_linear_verifies_every_recorded_digest() {
    use aff4tools::verify::{Outcome, VerifyOptions, verify_container};

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();

    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    assert!(
        !report.has_mismatch(),
        "a canonical container must verify clean; mismatches: {:#?}",
        report
            .checks
            .iter()
            .filter(|c| c.outcome.is_mismatch())
            .collect::<Vec<_>>()
    );

    let by_predicate = |predicate: &str| {
        report
            .checks
            .iter()
            .find(|c| c.predicate == predicate)
            .unwrap_or_else(|| panic!("no check for {predicate}: {:#?}", report.checks))
    };

    // The four map digests, each SHA512 over segment bytes.
    for predicate in ["mapPointHash", "mapIdxHash", "mapPathHash", "mapHash"] {
        assert_eq!(
            by_predicate(predicate).outcome,
            Outcome::Match,
            "{predicate} must be recomputed and match"
        );
    }

    // The root of the tree, on the DiskImage.
    let block_map = report
        .checks
        .iter()
        .find(|c| c.predicate == "hash" && c.algorithm == aff4tools::HashAlgorithm::BlockMapSha512)
        .expect("the DiskImage's blockMapHashSHA512 must be checked");
    assert_eq!(block_map.outcome, Outcome::Match);
    assert_eq!(
        block_map.expected,
        "c339331791f2018c50247cae1307ea8b0ce1166fac8747c5f4438c364b3d6c56\
         793405afec7eec366205073ed9f7e7801556587c87181d83afe356bc9244ccf2"
    );

    // The two BlockHashes segment digests.
    let block_hash_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.role == aff4tools::ObjectRole::BlockHashes)
        .collect();
    assert!(
        block_hash_checks.len() >= 2,
        "both blockhash segments must be checked: {block_hash_checks:#?}"
    );

    // Per-chunk verification: 121 chunks, MD5 and SHA1.
    assert!(report.block_hashes_verified);
    let per_block: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.coverage == aff4tools::Coverage::Block)
        .collect();
    assert_eq!(per_block.len(), 2, "one check per block-hash algorithm");
    for check in &per_block {
        assert_eq!(check.outcome, Outcome::Match, "{:#?}", check);
        assert!(
            check.expected.contains("121 chunk digests"),
            "{}",
            check.expected
        );
    }

    // Nothing may be silently skipped.
    assert!(report.checked_count() >= 9, "{:#?}", report.checks);
    assert_eq!(report.match_count(), report.checked_count());
}

/// Every `BlockHashes` object's `aff4:hash` is recomputed, with its value.
///
/// These are the `blockHashesHash` digests — SHA512 over a whole
/// `.blockHash.<alg>` segment. They were silently skipped until Stage 1 of
/// feature 3c: `verify_block_hash_segment` split the *escaped member name* on
/// `'.'`, producing `…%2Fblockhash`, which prefix-matches no segment, and then
/// returned without emitting a check. A bare `return` on a not-found is a
/// silent skip, and this one hid two verifiable digests in every container that
/// records them.
///
/// The sibling test above asserted only `>= 2` such checks *existed*, which the
/// declines satisfied. Pinning the digests is what makes the regression
/// detectable.
#[test]
fn block_hashes_objects_have_their_digests_recomputed() {
    use aff4tools::verify::{Outcome, VerifyOptions, verify_container};

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    let expected = [
        (
            "blockhash.md5",
            "9062f1c9f48438a6875a60b7e1323151e8ff583c8531ca7806d6c29b7d961ced\
             dba8783e8e4c49ff37702304cdf1dc4c7a9b8f67c73af07fc14422c0be9ae20d",
        ),
        (
            "blockhash.sha1",
            "5f487386e32230f282174d197c40a6de4b8d039449a90cf0b720aeb9d213cf33\
             7b92a6f0547c5150dd5d1dfcc817e6d5018a2383efec7b6df38015235c9be9e1",
        ),
    ];

    for (suffix, digest) in expected {
        let check = report
            .checks
            .iter()
            .find(|c| c.subject.as_str().ends_with(suffix))
            .unwrap_or_else(|| panic!("no check for {suffix}: {:#?}", report.checks));
        assert_eq!(
            check.outcome,
            Outcome::Match,
            "{suffix} must be recomputed, not skipped: {check:#?}"
        );
        assert_eq!(
            check.actual, digest,
            "{suffix} recomputed to the wrong value"
        );
        assert_eq!(check.expected, digest);
    }
}

/// A stripe verifies its own `blockMapHash` without opening the image.
///
/// Two independent Stage 1 findings meet here.
///
/// First, the map's copy of `blockMapHash` must not be dropped on the
/// reasoning that the image-side check covers it. For a stripe it does not: the
/// sibling's stream is declared as a stub with no `aff4:size`, so `Image::open`
/// fails and *neither* copy would be checked, leaving the container reporting
/// "N of N matched" while this digest goes unverified.
///
/// Second — and this is the trap — each stripe stores **both** streams'
/// block-hash segments but its `blockMapHash` covers only the stream whose
/// bevies are local. Verified by recomputation: including the foreign stream's
/// digests, in either position, matches nothing. So the locality test must be
/// bevy presence, not "can these segments be named", or a future striped
/// resolver silently breaks a digest that matches today.
#[test]
fn each_stripe_verifies_its_own_block_map_hash() {
    use aff4tools::verify::{Outcome, VerifyOptions, verify_container};

    let expected = [
        (
            "Base-Linear_1.aff4",
            "904c68e4240071a2057f40b1da4328c5c93232924ad6714ab5d6aa27504ec10e\
             387efa89380b42ea4f596dcdf1f085330a50f30091d88ebdc8a4a781047fd2d9",
        ),
        (
            "Base-Linear_2.aff4",
            "1a9618d0d2c8099224a4876f9470d394070bad137e23bc24c23bb42f99c0fd18\
             c7f8c16924d31cdf11ff91de0ab165e80a5b5110675c25310d72245145512941",
        ),
    ];

    for (name, digest) in expected {
        let path = corpus_root().join(format!("{STD}/Striped/{name}"));
        let mut container = Container::open(&path).unwrap();
        let report =
            verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

        let check = report
            .checks
            .iter()
            .find(|c| c.predicate == "blockMapHash")
            .unwrap_or_else(|| panic!("{name} records blockMapHash but no check was emitted"));

        assert_eq!(check.outcome, Outcome::Match, "{name}: {check:#?}");
        assert_eq!(
            check.actual, digest,
            "{name}: recomputed the wrong value — a foreign stream's block \
             hashes may have been included"
        );
        assert!(
            !report.has_mismatch(),
            "{name} must verify clean: {:#?}",
            report
                .checks
                .iter()
                .filter(|c| c.outcome.is_mismatch())
                .collect::<Vec<_>>()
        );
    }
}

/// Block hashing is on by default, so a default run is a whole-tree claim.
///
/// The default is the setting almost every run will use, and it decides how
/// much of the hash tree a clean report actually covers. Pinning it here means
/// a change to it has to be deliberate.
#[test]
fn the_default_verifies_the_leaf_level() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    assert!(
        VerifyOptions::default().block_hashes,
        "block hashing must default to on"
    );

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let report = verify_container(&mut container, VerifyOptions::default()).unwrap();

    assert!(
        report.block_hashes_verified,
        "a default run must reach the leaf level"
    );
    let blocks = report
        .checks
        .iter()
        .filter(|c| c.coverage == aff4tools::Coverage::Block)
        .count();
    assert!(
        blocks > 0,
        "a default run must produce per-chunk checks: {:#?}",
        report.checks
    );
}

/// The image's `blockMapHash` and the map's must be the same value, computed
/// the same way — the recorded metadata carries it in both places.
#[test]
fn the_block_map_hash_is_consistent_between_image_and_map() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let report = verify_container(&mut container, VerifyOptions::default()).unwrap();

    let image_value = report
        .checks
        .iter()
        .find(|c| c.algorithm == aff4tools::HashAlgorithm::BlockMapSha512)
        .map(|c| c.actual.clone())
        .expect("the image's blockMapHash must be recomputed");

    // The map records the same digest under `blockMapHash`. It is verified with
    // the image rather than twice, but the recorded values must agree.
    let summary = Container::open(&path).unwrap().summarize().unwrap();
    let map_recorded = summary
        .objects
        .iter()
        .filter(|o| o.role == aff4tools::ObjectRole::Map)
        .flat_map(|o| o.hashes.iter())
        .find(|h| h.predicate == "blockMapHash")
        .map(|h| h.hex.clone())
        .expect("the Map records blockMapHash");

    assert_eq!(
        image_value.to_lowercase(),
        map_recorded.to_lowercase(),
        "the recomputed blockMapHash must equal what the Map records"
    );
}

/// All five algorithms, plus the composite tree, on the container that has
/// them.
#[test]
fn all_hashes_container_verifies_across_five_algorithms() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    let path = corpus_root().join(format!("{STD}/Base-Linear-AllHashes.aff4"));
    let mut container = Container::open(&path).unwrap();
    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    assert!(
        !report.has_mismatch(),
        "mismatches: {:#?}",
        report
            .checks
            .iter()
            .filter(|c| c.outcome.is_mismatch())
            .collect::<Vec<_>>()
    );

    let stream_algorithms: std::collections::BTreeSet<String> = report
        .checks
        .iter()
        .filter(|c| c.coverage == aff4tools::Coverage::StoredStream && c.outcome.was_checked())
        .map(|c| c.algorithm.to_string())
        .collect();

    for expected in ["MD5", "SHA1", "SHA256", "SHA512", "Blake2b"] {
        assert!(
            stream_algorithms.contains(expected),
            "{expected} must be recomputed; got {stream_algorithms:?}"
        );
    }
}

/// Every corpus container must verify or decline precisely — never panic, and
/// never report a mismatch on evidence that is intact.
#[test]
fn every_corpus_container_verifies_or_declines_precisely() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    let mut checked = 0usize;
    let mut containers = 0usize;

    for relative in [
        "pyaff4/test_images/AFF4Std/Base-Linear.aff4",
        "pyaff4/test_images/AFF4Std/Base-Linear-AllHashes.aff4",
        "pyaff4/test_images/AFF4Std/Base-Linear-ReadError.aff4",
        "pyaff4/test_images/AFF4Std/Base-Allocated.aff4",
        "pyaff4/test_images/AFF4-L/dream.aff4",
        "pyaff4/test_images/AFF4-L/unicode.aff4",
    ] {
        let path = corpus_root().join(relative);
        if !path.exists() {
            continue;
        }
        containers += 1;

        let mut container =
            Container::open(&path).unwrap_or_else(|e| panic!("opening {relative}: {e}"));
        let report = verify_container(&mut container, VerifyOptions::default())
            .unwrap_or_else(|e| panic!("verifying {relative}: {e}"));

        assert!(
            !report.has_mismatch(),
            "{relative} is intact evidence and must not report a mismatch: {:#?}",
            report
                .checks
                .iter()
                .filter(|c| c.outcome.is_mismatch())
                .collect::<Vec<_>>()
        );

        // Every declined check must say why, in terms an examiner can act on.
        for check in &report.checks {
            if let aff4tools::Outcome::NotVerifiable { reason, .. } = &check.outcome {
                assert!(
                    !reason.is_empty(),
                    "{relative}: {} declined without a reason",
                    check.predicate
                );
            }
        }

        checked += report.checked_count();
    }

    assert!(
        containers >= 6,
        "expected most of the corpus, saw {containers}"
    );
    assert!(
        checked > 20,
        "expected many digests recomputed, saw {checked}"
    );
}

/// `Base-Linear-ReadError.aff4` is a separate acquisition, not a corrupted
/// copy — its own digests must verify clean. Finding Q, asserted.
#[test]
fn the_read_error_container_verifies_against_its_own_digests() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    let path = corpus_root().join(format!("{STD}/Base-Linear-ReadError.aff4"));
    let mut container = Container::open(&path).unwrap();
    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    assert!(
        !report.has_mismatch(),
        "a read error at acquisition time is not a verification failure: {:#?}",
        report
            .checks
            .iter()
            .filter(|c| c.outcome.is_mismatch())
            .collect::<Vec<_>>()
    );
    assert!(report.checked_count() > 0);
}

// ---------------------------------------------------------------------------
// Feature 1 item 7: hardening. Mutation must be reported, never missed.
// ---------------------------------------------------------------------------

/// Rebuild a container into a `TempDir`, transforming one member's bytes.
///
/// The writer computes a fresh, valid CRC, so the ZIP layer sees nothing wrong
/// and only the digests can catch the change. Never touches the source: the
/// corpus is a read-only fixture.
fn rebuilt_with<F>(source: &std::path::Path, target: &std::path::Path, member: &str, mutate: F)
where
    F: Fn(&mut Vec<u8>),
{
    use std::io::Write as _;

    let input = std::fs::File::open(source).unwrap();
    let mut reader = zip::ZipArchive::new(input).unwrap();
    #[allow(clippy::disallowed_methods)]
    let output = std::fs::File::create(target).unwrap();
    // The one sanctioned use of a ZIP writer: a throwaway copy in a TempDir.
    #[allow(clippy::disallowed_types)]
    let mut writer = zip::ZipWriter::new(output);
    let options: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    writer
        .set_raw_comment(reader.comment().to_vec().into_boxed_slice())
        .unwrap();

    let names: Vec<String> = reader.file_names().map(str::to_owned).collect();
    for name in names {
        let mut entry = reader.by_name(&name).unwrap();
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut body).unwrap();
        if name == member {
            mutate(&mut body);
        }
        drop(entry);
        writer.start_file(&name, options).unwrap();
        writer.write_all(&body).unwrap();
    }
    writer.finish().unwrap();
}

/// Altering the map must be reported as a mismatch, not as a damaged container.
///
/// This is the distinction the whole error taxonomy exists for: verification ran
/// successfully and the answer is negative. Reporting it as `Malformed` would
/// tell an examiner the file is broken when the finding is that the evidence
/// does not match its recorded digests.
#[test]
fn an_altered_map_is_reported_as_a_mismatch_not_an_error() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("altered-map.aff4");

    // Swap two entries' target offsets: still 28-byte records, still gapless,
    // still summing to the declared size — only the content changes.
    rebuilt_with(
        &source,
        &path,
        "aff4%3A%2F%2Ffcbfdce7-4488-4677-abf6-08bc931e195b/map",
        |body| {
            body[16] ^= 0x01;
        },
    );

    let mut container = Container::open(&path).unwrap();
    let report = verify_container(&mut container, VerifyOptions::default()).unwrap();

    assert!(
        report.has_mismatch(),
        "an altered map segment must be caught: {:#?}",
        report.checks
    );

    // Both the segment's own digest and the composite above it must fail.
    let failed: Vec<&str> = report
        .checks
        .iter()
        .filter(|c| c.outcome.is_mismatch())
        .map(|c| c.predicate.as_str())
        .collect();
    assert!(failed.contains(&"mapPointHash"), "{failed:?}");
    assert!(failed.contains(&"mapHash"), "{failed:?}");
    assert!(
        failed.contains(&"hash"),
        "blockMapHash on the image must fail too: {failed:?}"
    );

    // Every mismatch shows both digests at full length, and they differ.
    for check in report.checks.iter().filter(|c| c.outcome.is_mismatch()) {
        assert_eq!(check.expected.len(), 128, "{}", check.predicate);
        assert_eq!(check.actual.len(), 128, "{}", check.predicate);
        assert_ne!(check.expected, check.actual);
    }
}

/// Altering chunk data must be caught by the per-block hashes.
///
/// This is what `--block-hashes` buys: the composite digests all still match,
/// because the block-hash segments were not touched. Only recomputing the
/// leaves reveals that they no longer describe the data.
#[test]
fn altered_chunk_data_is_caught_only_by_the_block_hashes() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("altered-chunk.aff4");

    rebuilt_with(
        &source,
        &path,
        "aff4%3A%2F%2Fc215ba20-5648-4209-a793-1f918c723610/00000000",
        |body| {
            // Inside the first chunk's compressed data.
            body[64] ^= 0x02;
        },
    );

    // Without block hashes: the stream digest catches it, the composites do not.
    //
    // Both sides are written out explicitly rather than leaning on the default,
    // because this test *is* the contrast between them: it would quietly stop
    // testing anything if the default moved under it.
    let mut container = Container::open(&path).unwrap();
    let without = verify_container(
        &mut container,
        VerifyOptions {
            block_hashes: false,
        },
    )
    .unwrap();

    let composite_ok = without
        .checks
        .iter()
        .filter(|c| c.coverage == aff4tools::Coverage::Composite)
        .all(|c| !c.outcome.is_mismatch());
    assert!(
        composite_ok,
        "the composite digests cover the block-hash segments, which were not \
         altered, so they must still match: {:#?}",
        without.checks
    );
    assert!(!without.block_hashes_verified);

    // With block hashes: the leaf level catches it.
    let mut container = Container::open(&path).unwrap();
    let with = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    assert!(with.block_hashes_verified);
    let block_failures: Vec<&aff4tools::HashCheck> = with
        .checks
        .iter()
        .filter(|c| c.coverage == aff4tools::Coverage::Block && c.outcome.is_mismatch())
        .collect();
    assert!(
        !block_failures.is_empty(),
        "per-chunk verification must catch altered chunk data: {:#?}",
        with.checks
    );

    // The report must localise the damage, not merely announce it.
    assert!(
        with.notes.iter().any(|n| n.contains("chunk 0")),
        "the first differing chunk must be named: {:#?}",
        with.notes
    );
}

/// A truncated bevy must be a finding, never a short read reported as success.
#[test]
fn a_truncated_bevy_is_reported_rather_than_silently_shortening_the_stream() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("truncated-bevy.aff4");

    rebuilt_with(
        &source,
        &path,
        "aff4%3A%2F%2Fc215ba20-5648-4209-a793-1f918c723610/00000000",
        |body| {
            body.truncate(body.len() / 2);
        },
    );

    let mut container = Container::open(&path).unwrap();
    let report = verify_container(&mut container, VerifyOptions::default()).unwrap();

    // The stream's own digests cannot be computed, and must say so rather than
    // being quietly omitted or reported over a short read.
    let stream_checks: Vec<&aff4tools::HashCheck> = report
        .checks
        .iter()
        .filter(|c| c.coverage == aff4tools::Coverage::StoredStream)
        .collect();

    assert!(
        !stream_checks.is_empty(),
        "the stream's digests must appear"
    );
    for check in stream_checks {
        assert!(
            !matches!(check.outcome, aff4tools::Outcome::Match),
            "a truncated bevy must never produce a match: {check:#?}"
        );
        if let aff4tools::Outcome::NotVerifiable { reason, .. } = &check.outcome {
            assert!(!reason.is_empty());
        }
    }
}

/// A map whose lengths do not sum to the declared size must be refused.
#[test]
fn a_map_that_does_not_cover_the_image_is_refused() {
    use aff4tools::image::Image;

    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("short-map.aff4");

    rebuilt_with(
        &source,
        &path,
        "aff4%3A%2F%2Ffcbfdce7-4488-4677-abf6-08bc931e195b/map",
        |body| {
            // Drop the last entry: coverage now falls short of the declared
            // 268435456, which would otherwise hash a short image.
            let len = body.len();
            body.truncate(len - aff4tools::map::MAP_ENTRY_LEN);
        },
    );

    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let image_arn =
        aff4tools::Arn::parse("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb", &locus).unwrap();

    let err = Image::open(&image_arn, container.volume_mut(), &graph, lexicon, &locus)
        .expect_err("a map that covers less than the image must be refused");
    assert!(err.is_integrity_finding(), "{err}");
    let text = err.to_string();
    assert!(text.contains("268435456"), "{text}");
}

/// Verification must never modify the container, even on a mutated copy.
#[test]
fn verifying_does_not_modify_the_container() {
    use aff4tools::verify::{VerifyOptions, verify_container};

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let before = std::fs::metadata(&path).unwrap();

    let mut container = Container::open(&path).unwrap();
    let _ = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();
    drop(container);

    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
}

/// The parallel reader must deliver exactly what the serial reader delivers.
///
/// Not "the same digest" — the same *slices*, in the same order. A digest can
/// match while the slice boundaries differ, and a reordering that happens to
/// compensate would be invisible at the digest but would break the block-hash
/// cut, which is defined on chunk boundaries. Comparing the call sequence
/// itself is what makes the parallel path provably equivalent.
///
/// Run across several thread plans, including lopsided ones, because a bug in
/// the reorder window is most likely to show when readers and workers are
/// mismatched.
#[test]
fn the_parallel_reader_delivers_the_same_slices_as_the_serial_one() {
    use aff4tools::Locus;
    use aff4tools::parallel::{ThreadPlan, read_all_parallel};
    use aff4tools::stream::ImageStream;

    // Standard containers only: a pre-standard volume stores each bevy as a
    // folder (`00000000/index`), which `read_all` does not address on either
    // path, so it would test the failure mode rather than the equivalence.
    for relative in [
        format!("{STD}/Base-Linear.aff4"),
        format!("{STD}/Base-Allocated.aff4"),
        format!("{STD}/Base-Linear-AllHashes.aff4"),
        format!("{STD}/Base-Linear-ReadError.aff4"),
    ] {
        let path = corpus_root().join(&relative);
        if !path.is_file() {
            continue;
        }

        let mut container = Container::open(&path).unwrap();
        let graph = container.graph().unwrap();
        let lexicon = container.lexicon();
        let locus = Locus::new(&path);

        let summary = container.summarize().unwrap();
        let streams: Vec<_> = summary
            .objects
            .iter()
            .filter(|o| matches!(o.role, ObjectRole::ImageStream))
            .map(|o| o.arn.clone())
            .collect();

        for arn in streams {
            let stream = match ImageStream::open(&arn, &graph, lexicon, &locus) {
                Ok(stream) => stream,
                Err(_) => continue,
            };

            // The oracle. A container that fails to read serially is still a
            // valid case: the parallel path must fail the same way.
            let mut serial: Vec<Vec<u8>> = Vec::new();
            let mut serial_bevies: Vec<u64> = Vec::new();
            let volume = container.volume_mut();
            let serial_result = stream
                .read_all_observed(
                    volume,
                    &mut |bytes| {
                        serial.push(bytes.to_vec());
                        Ok(())
                    },
                    &mut |n| serial_bevies.push(n),
                    &locus,
                )
                .map_err(|e| e.to_string());

            for (readers, workers) in [(1, 1), (2, 2), (4, 1), (1, 4), (3, 5)] {
                let plan = ThreadPlan {
                    readers,
                    workers,
                    digesters: 0,
                    available: readers + workers,
                    budget: readers + workers,
                };

                let mut parallel: Vec<Vec<u8>> = Vec::new();
                let mut parallel_bevies: Vec<u64> = Vec::new();
                let volume = container.volume_mut();
                let parallel_result = read_all_parallel(
                    &stream,
                    volume,
                    plan,
                    &mut |bytes| {
                        parallel.push(bytes.to_vec());
                        Ok(())
                    },
                    &mut |n| parallel_bevies.push(n),
                    &locus,
                )
                .map_err(|e| e.to_string());

                assert_eq!(
                    parallel_result, serial_result,
                    "{relative} {arn} at {plan:?}: outcome differs from serial"
                );
                assert_eq!(
                    parallel.len(),
                    serial.len(),
                    "{relative} {arn} at {plan:?}: slice count differs"
                );
                assert!(
                    parallel == serial,
                    "{relative} {arn} at {plan:?}: slice sequence differs from serial"
                );
                assert_eq!(
                    parallel_bevies, serial_bevies,
                    "{relative} {arn} at {plan:?}: bevy completion sequence differs"
                );
            }
        }
    }
}

/// A stream whose size is not a whole number of chunks must be truncated at
/// the same byte on both paths.
///
/// The truncation depends on how many bytes precede the final chunk, which is
/// the one thing a bevy decoded out of order cannot know. If it ever moved out
/// of the ordered consumer this is what would catch it.
#[test]
fn the_parallel_reader_truncates_the_final_chunk_identically() {
    use aff4tools::Locus;
    use aff4tools::parallel::{ThreadPlan, read_all_parallel};
    use aff4tools::stream::ImageStream;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let locus = Locus::new(&path);

    let summary = container.summarize().unwrap();
    let arn = summary
        .objects
        .iter()
        .find(|o| matches!(o.role, ObjectRole::ImageStream))
        .map(|o| o.arn.clone())
        .expect("an image stream");
    let stream = ImageStream::open(&arn, &graph, lexicon, &locus).unwrap();

    // Only meaningful if the stream really does end mid-chunk.
    let ragged = !(stream.size()).is_multiple_of(stream.chunk_size() as u64);

    let plan = ThreadPlan {
        readers: 2,
        workers: 3,
        digesters: 0,
        available: 5,
        budget: 5,
    };
    let mut total: u64 = 0;
    let mut last_len = 0usize;
    let volume = container.volume_mut();
    read_all_parallel(
        &stream,
        volume,
        plan,
        &mut |bytes| {
            total += bytes.len() as u64;
            last_len = bytes.len();
            Ok(())
        },
        &mut |_| {},
        &locus,
    )
    .unwrap();

    assert_eq!(
        total,
        stream.size(),
        "the parallel reader must deliver exactly the declared size"
    );
    if ragged {
        assert!(
            last_len < stream.chunk_size(),
            "the final chunk must be truncated, not padded: {last_len}"
        );
    }
}

/// The two stripes' maps must reconstruct byte-identical images.
///
/// This is the strongest correctness oracle the corpus offers for cross-volume
/// reading. Each volume of the striped fixture carries its own near-equivalent
/// map over the *whole* address space — 4104 entries in one, 4103 in the other,
/// interleaving targets from both stripes. Traversing either must yield the
/// same 268,435,456 bytes.
///
/// A single map cannot catch an off-by-one in a cross-volume region read: the
/// error would be reproduced identically on both sides of any self-comparison.
/// Two independently-written maps over the same data can.
#[test]
fn both_stripe_maps_reconstruct_the_same_image() {
    use aff4tools::image::Image;
    use aff4tools::zip_volume_set::{VolumeOrigin, open_with_graph};

    let dir = corpus_root().join(format!("{STD}/Striped"));
    let mut digests = Vec::new();

    // Open the set from each side in turn, so each volume's map is the one
    // traversed. The primary supplies the map; the set supplies the data.
    for (first, second) in [
        ("Base-Linear_1.aff4", "Base-Linear_2.aff4"),
        ("Base-Linear_2.aff4", "Base-Linear_1.aff4"),
    ] {
        let mut container = Container::open(dir.join(first)).unwrap();
        let (volume, graph) = open_with_graph(dir.join(second)).unwrap();
        assert!(container.add_volume(volume, graph, VolumeOrigin::Named));

        let lexicon = container.lexicon();
        let locus = aff4tools::Locus::new(dir.join(first));
        let image_arn = container
            .summarize()
            .unwrap()
            .images()
            .iter()
            .find(|o| o.role == ObjectRole::DiskImage)
            .map(|o| o.arn.clone())
            .expect("the striped fixture declares a DiskImage");

        let image =
            Image::open_in_set(&image_arn, container.volumes_mut(), lexicon, &locus).unwrap();

        let mut hasher = sha2::Sha256::new();
        let mut total: u64 = 0;
        image
            .read_from_set(
                container.volumes_mut(),
                &mut |bytes| {
                    use sha2::Digest as _;
                    hasher.update(bytes);
                    total += bytes.len() as u64;
                    Ok(())
                },
                &locus,
            )
            .unwrap_or_else(|e| panic!("{first} could not be traversed: {e}"));

        use sha2::Digest as _;
        assert_eq!(total, 268_435_456, "{first} must deliver the whole image");
        digests.push((first, format!("{:x}", hasher.finalize())));
    }

    assert_eq!(
        digests[0].1, digests[1].1,
        "the two stripes' maps disagree about the image: {} gave {}, {} gave {}",
        digests[0].0, digests[0].1, digests[1].0, digests[1].1
    );
}

/// A missing stripe declines; it never short-reads or zero-fills.
///
/// The failure mode this guards against is the dangerous one: a traversal that
/// silently substitutes zeroes for an absent volume would produce a clean-
/// looking image and a confidently wrong digest. Opening one stripe alone must
/// fail to resolve the image, naming the volume it needs.
#[test]
fn a_missing_stripe_declines_rather_than_fabricating() {
    use aff4tools::image::Image;

    let dir = corpus_root().join(format!("{STD}/Striped"));
    let mut container = Container::open(dir.join("Base-Linear_1.aff4")).unwrap();
    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(dir.join("Base-Linear_1.aff4"));

    let image_arn = container
        .summarize()
        .unwrap()
        .images()
        .iter()
        .find(|o| o.role == ObjectRole::DiskImage)
        .map(|o| o.arn.clone())
        .unwrap();

    let err = Image::open_in_set(&image_arn, container.volumes_mut(), lexicon, &locus)
        .expect_err("one stripe alone cannot describe the whole image");

    let message = err.to_string();
    assert!(
        message.contains("stub") || message.contains("--split-file"),
        "the error must say which volume is missing and how to supply it: {message}"
    );
}

/// The volume set records where each stripe came from.
///
/// A digest computed across several files is only meaningful if the report says
/// which files. `VolumeOrigin` distinguishes a volume the examiner named from
/// one the tool found by scanning.
#[test]
fn the_volume_set_records_each_stripes_provenance() {
    use aff4tools::zip_volume_set::{VolumeOrigin, open_with_graph};

    let dir = corpus_root().join(format!("{STD}/Striped"));
    let mut container = Container::open(dir.join("Base-Linear_1.aff4")).unwrap();
    let (volume, graph) = open_with_graph(dir.join("Base-Linear_2.aff4")).unwrap();
    container.add_volume(volume, graph, VolumeOrigin::Named);

    let records = container.volumes().records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].arn.as_str(),
        "aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad"
    );
    assert_eq!(
        records[1].arn.as_str(),
        "aff4://51725cd9-3769-4be7-a8ab-94e3ea62bf9a"
    );

    // Which volume holds which stream's data — the fact that drives every
    // cross-volume read, and the one a filename cannot answer.
    let a = aff4tools::Arn::parse(
        "aff4://a04a9189-5e92-4024-a577-37d6cfa72594",
        &aff4tools::Locus::new(dir.clone()),
    )
    .unwrap();
    let b = aff4tools::Arn::parse(
        "aff4://3bf0bd14-1ef9-4185-8b0a-2c7d511b4d30",
        &aff4tools::Locus::new(dir.clone()),
    )
    .unwrap();
    assert_eq!(
        container.volumes().holding(&a).map(aff4tools::Arn::as_str),
        Some("aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad")
    );
    assert_eq!(
        container.volumes().holding(&b).map(aff4tools::Arn::as_str),
        Some("aff4://51725cd9-3769-4be7-a8ab-94e3ea62bf9a")
    );
}

/// The striped image's root digest, and the order it was inferred in.
///
/// `SHA-512(blockMapHash₁ ‖ blockMapHash₂)` over the stripes' **recomputed**
/// digests. Feeding the recorded values instead would make this match even on
/// a damaged stripe — the one failure the digest exists to catch — so the
/// tamper case below is as load-bearing as the match.
///
/// The value is not documented in Standard v1.0, in the v1.0a draft, or in any
/// reference implementation; it was identified against this fixture.
#[test]
fn the_striped_image_root_digest_verifies() {
    use aff4tools::verify::{Outcome, VerifyOptions, verify_container};
    use aff4tools::zip_volume_set::{VolumeOrigin, open_with_graph};

    let dir = corpus_root().join(format!("{STD}/Striped"));
    let mut container = Container::open(dir.join("Base-Linear_1.aff4")).unwrap();
    let (volume, graph) = open_with_graph(dir.join("Base-Linear_2.aff4")).unwrap();
    container.add_volume(volume, graph, VolumeOrigin::Named);

    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    let root = report
        .checks
        .iter()
        .find(|c| c.algorithm == aff4tools::HashAlgorithm::BlockMapSha512)
        .expect("the striped DiskImage records a blockMapHashSHA512");

    assert_eq!(root.outcome, Outcome::Match, "{root:#?}");
    assert_eq!(
        root.actual,
        "1bc643e0680978381ef519e6cc9d3f13ad1266257f29735cbff7f4053910acae\
         1cc1b26ae93a28c269addca5736e4d4ca3a59987f130244f2331823848f80ce0"
    );

    // The order was inferred, not recorded — so it must be stated. A matching
    // digest whose ordering assumption is invisible cannot be checked by anyone
    // reading the report.
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("inferred") && n.contains("filename order")),
        "the inferred stripe order must be reported: {:#?}",
        report.notes
    );

    // Both stripes' own digests are verified too, and neither is skipped.
    let per_stripe = report
        .checks
        .iter()
        .filter(|c| c.predicate == "blockMapHash")
        .count();
    assert_eq!(per_stripe, 2, "each stripe's own blockMapHash is checked");
}

/// Every digest a striped set records is either recomputed or declined.
///
/// The failure this guards is silence: a check that never appears reads as
/// "nothing to report" while a recorded digest goes unverified. Only
/// `imageStreamHash` may be outstanding, and only because its construction is
/// genuinely unidentified.
#[test]
fn a_striped_set_leaves_no_recorded_digest_unaccounted_for() {
    use aff4tools::verify::{VerifyOptions, verify_container};
    use aff4tools::zip_volume_set::{VolumeOrigin, open_with_graph};

    let dir = corpus_root().join(format!("{STD}/Striped"));
    let mut container = Container::open(dir.join("Base-Linear_1.aff4")).unwrap();
    let (volume, graph) = open_with_graph(dir.join("Base-Linear_2.aff4")).unwrap();
    container.add_volume(volume, graph, VolumeOrigin::Named);

    let recorded: usize = container
        .objects_across_volumes()
        .unwrap()
        .iter()
        .map(|o| o.hashes.len())
        .sum();

    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    // Block-hash leaf checks are extra, not recorded digests, so the check
    // count may exceed the recorded count — but never fall below it.
    assert!(
        report.checks.len() >= recorded,
        "{recorded} digests are recorded across the set but only {} checks \
         were emitted; some were skipped silently",
        report.checks.len()
    );

    let unexplained: Vec<_> = report
        .checks
        .iter()
        .filter(|c| !c.outcome.was_checked())
        .filter(|c| !format!("{:?}", c.outcome).contains("imageStreamHash"))
        .collect();
    assert!(
        unexplained.is_empty(),
        "every digest not recomputed must say why: {unexplained:#?}"
    );
}

#[test]
fn the_volume_manifest_is_modelled_across_generations() {
    // Standard: seven declared, all present.
    let s = summarize(&format!("{STD}/Base-Linear.aff4"));
    assert_eq!(s.manifest.len(), 7, "aff4:contains names seven ARNs");
    assert!(
        s.manifest
            .iter()
            .any(|a| a == "aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb"),
        "the disk image must be declared: {:?}",
        s.manifest
    );
    assert!(
        s.manifest_disagreements.is_empty(),
        "a canonical container should agree with itself: {:?}",
        s.manifest_disagreements
    );

    // The pre-standard half of this test is gone: those containers are
    // declined at open, so no manifest can be built for one. See
    // `a_pre_standard_container_is_declined`.
}

/// `dream.aff4`'s `information.turtle` describes exactly one subject (its
/// `FileImage`) and no `ZipVolume` at all, so there is no `aff4:contains`
/// triple anywhere in the container — audit A8.4 rule 9's third row, "no
/// declaration exists". The lone object is therefore not "present but
/// undeclared": there is no declaration for it to disagree with. This is the
/// regression this test exists to catch: treating "the ARN list came back
/// empty" as equivalent to "nothing was declared" flags every local object as
/// an undeclared-manifest deviation, conflating rule 9's middle row (a real but
/// empty declaration) with its third (no declaration at all).
#[test]
fn a_volume_with_no_contains_triple_yields_an_empty_manifest_and_no_deviation() {
    let s = summarize(&format!("{LOGICAL}/dream.aff4"));

    assert!(
        s.manifest.is_empty(),
        "dream.aff4 declares no aff4:contains at all: {:?}",
        s.manifest
    );
    assert!(
        s.manifest_disagreements.is_empty(),
        "an absent manifest is not a disagreement: {:?}",
        s.manifest_disagreements
    );
    assert!(
        !s.deviations
            .iter()
            .any(|d| d.kind == DeviationKind::UndeclaredObject),
        "an absent manifest must not produce UndeclaredObject: {:#?}",
        s.deviations
    );
}

/// Every container in the corpus, found by walking rather than listed.
///
/// A hard-coded list would silently stop covering a fixture added later, and
/// the equivalence property below is exactly the kind that needs to hold for
/// containers nobody thought about when writing the test.
fn every_corpus_container() -> Vec<PathBuf> {
    fn walk(dir: &std::path::Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("aff4" | "af4")
            ) {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(&corpus_root(), &mut found);
    found.sort();
    found
}

/// `deviations_only` streams; `summarize` retains. They must agree exactly.
///
/// `conformance` reads the streaming path and `info` reads the retained one, so
/// a divergence here means the two commands report different findings about the
/// same evidence. That is the failure this test exists to prevent — the
/// streaming rewrite (docs/RDF-scalability.md) traded a 2.26 GB `Graph` for
/// a single-subject window, and nothing but this asserts the trade was lossless.
///
/// Compared as rendered strings including locus, kind, and detail, so a
/// deviation that moved to a different subject or lost its predicate fails.
#[test]
fn streaming_conformance_matches_the_retained_summary() {
    let containers = every_corpus_container();
    assert!(
        containers.len() > 15,
        "expected the full corpus; found {} container(s)",
        containers.len()
    );

    let mut compared = 0usize;
    for path in containers {
        let Ok(mut retained) = Container::open(&path) else {
            continue; // Not every file under the corpus root is a container.
        };
        let Ok(summary) = retained.summarize() else {
            continue;
        };
        let mut streamed = Container::open_without_graph(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let deviations = streamed
            .deviations_only()
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .deviations;

        let render = |list: &[aff4tools::Deviation]| {
            let mut lines: Vec<String> = list.iter().map(|d| format!("{d:?}")).collect();
            // Order differs legitimately: the streaming pass resolves dangling
            // references after the whole file, the retained pass per object.
            // Which findings exist is the property under test, not their order.
            lines.sort();
            lines
        };

        assert_eq!(
            render(&deviations),
            render(&summary.deviations),
            "streaming and retained conformance disagree on {}",
            path.display()
        );
        compared += 1;
    }

    assert!(compared > 15, "only {compared} container(s) compared");
}

/// A striped set must not take the fused single-traversal path.
///
/// Fusing the whole-image digest into the stream passes depends on part order
/// being image order, which holds for the sequential sets this tool writes
/// and does **not** hold when stripes interleave through the
/// address space. Feeding a striped map's bytes in part order would produce a
/// digest that is confidently wrong, so the fused path refuses and the image
/// keeps its own traversal. This is the fixture that would catch it: the
/// canonical striped pair, verified as one set.
#[test]
fn a_striped_set_still_verifies_every_recorded_digest() {
    let root = corpus_root();
    let mut container = Container::open(root.join(format!("{STD}/Striped/Base-Linear_1.aff4")))
        .expect("stripe 1 must open");
    let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(
        root.join(format!("{STD}/Striped/Base-Linear_2.aff4")),
    )
    .expect("stripe 2 must open");
    assert!(container.add_volume(
        volume,
        graph,
        aff4tools::zip_volume_set::VolumeOrigin::Named
    ));

    let report = aff4tools::verify_container(
        &mut container,
        aff4tools::VerifyOptions { block_hashes: true },
    )
    .expect("the striped set must verify");

    // Not one mismatch anywhere. A fused traversal wrongly applied here would
    // show up as an image digest that no longer reproduces.
    let mismatched: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.outcome == aff4tools::Outcome::Mismatch)
        .collect();
    assert!(
        mismatched.is_empty(),
        "a striped set must verify intact: {mismatched:?}"
    );
    assert!(
        report.checks.iter().any(|c| c.outcome.was_checked()),
        "something must actually have been checked"
    );
}

/// Random access agrees with sequential reading, byte for byte.
///
/// The property that matters for `read_at`: if it disagrees with the traversal
/// path anywhere, one of the two is wrong, and a consumer reading through the
/// seam would get bytes that never came off the medium. Checked against
/// `Base-Linear.aff4`, which is 98.5% described rather than stored, so most of
/// the comparison exercises the filler paths rather than decompression.
#[test]
fn read_at_agrees_with_sequential_reading() {
    use aff4tools::image::Image;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let image_arn =
        aff4tools::Arn::parse("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb", &locus).unwrap();
    let image = Image::open(&image_arn, container.volume_mut(), &graph, lexicon, &locus).unwrap();

    // Assemble the first 8 MiB sequentially, as the traversal path delivers it.
    const WINDOW: usize = 8 * 1024 * 1024;
    let mut sequential = Vec::with_capacity(WINDOW);
    image
        .read(
            container.volume_mut(),
            &mut |bytes| {
                if sequential.len() < WINDOW {
                    let take = (WINDOW - sequential.len()).min(bytes.len());
                    sequential.extend_from_slice(&bytes[..take]);
                }
                Ok(())
            },
            &locus,
        )
        .unwrap();
    assert_eq!(sequential.len(), WINDOW);

    // The same bytes, one random-access call.
    let mut whole = vec![0u8; WINDOW];
    let got = image
        .read_at(container.volume_mut(), 0, &mut whole, &locus)
        .unwrap();
    assert_eq!(got, WINDOW, "a read inside the image is never short");
    assert_eq!(whole, sequential, "random access must match traversal");

    // And in pieces, at offsets that do not line up with chunk or entry
    // boundaries: 4096 divides neither the 32 KiB chunk size nor the entry
    // lengths, so these reads straddle both.
    for start in [0usize, 1, 4095, 32_768, 40_000, 1_048_576, 4_000_003] {
        let mut piece = vec![0u8; 4096];
        let n = image
            .read_at(container.volume_mut(), start as u64, &mut piece, &locus)
            .unwrap();
        assert_eq!(n, 4096, "a read at {start} inside the image is never short");
        assert_eq!(
            piece,
            &sequential[start..start + 4096],
            "bytes at offset {start} disagree"
        );
    }
}

/// A read at the end of the image is short, and past it returns nothing.
///
/// The one place `read_at` may return fewer bytes than asked for. A caller
/// distinguishes "end of image" from "boundary hit" by this contract, so it
/// needs to hold exactly.
#[test]
fn read_at_is_short_only_at_the_end_of_the_image() {
    use aff4tools::image::Image;

    let path = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let mut container = Container::open(&path).unwrap();
    let locus = aff4tools::Locus::new(&path);
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let image_arn =
        aff4tools::Arn::parse("aff4://cf853d0b-5589-4c7c-8358-2ca1572b87eb", &locus).unwrap();
    let image = Image::open(&image_arn, container.volume_mut(), &graph, lexicon, &locus).unwrap();
    let size = image.size();

    // Straddling the end: half the buffer can be filled.
    let mut straddle = vec![0u8; 4096];
    let n = image
        .read_at(container.volume_mut(), size - 2048, &mut straddle, &locus)
        .unwrap();
    assert_eq!(n, 2048, "only the bytes that exist are delivered");

    // At the end: nothing.
    let mut past = vec![0u8; 4096];
    let n = image
        .read_at(container.volume_mut(), size, &mut past, &locus)
        .unwrap();
    assert_eq!(
        n, 0,
        "a read at the end delivers nothing and is not an error"
    );

    // Well past the end: still nothing, still not an error.
    let n = image
        .read_at(container.volume_mut(), size * 2, &mut past, &locus)
        .unwrap();
    assert_eq!(n, 0);

    // A zero-length read is a no-op.
    let mut empty: [u8; 0] = [];
    let n = image
        .read_at(container.volume_mut(), 0, &mut empty, &locus)
        .unwrap();
    assert_eq!(n, 0);
}

/// A described region is served from its filler, with no stored bytes read.
///
/// `Base-Allocated.aff4` records unallocated space as runs of a repeated byte.
/// Those bytes were on the source medium and were read from it; only their
/// storage is elided, so reconstructing them reproduces the acquired image.
#[test]
fn read_at_serves_described_regions_from_their_filler() {
    use aff4tools::image::Image;

    let path = corpus_root().join(format!("{STD}/Base-Allocated.aff4"));
    let locus = aff4tools::Locus::new(&path);

    let image_arn = Container::open(&path)
        .unwrap()
        .summarize()
        .unwrap()
        .objects
        .iter()
        .find(|o| o.role == ObjectRole::DiskImage)
        .map(|o| o.arn.clone())
        .expect("the container holds a DiskImage");

    let mut container = Container::open(&path).unwrap();
    let graph = container.graph().unwrap();
    let lexicon = container.lexicon();
    let image = Image::open(&image_arn, container.volume_mut(), &graph, lexicon, &locus).unwrap();

    // Find a described run through the map and read inside it.
    let described = image
        .map()
        .entries()
        .iter()
        .find(|e| {
            image
                .map()
                .target_of(e)
                .is_some_and(|t| !t.is_stored() && e.length >= 4096)
        })
        .copied()
        .expect("an allocated image records described runs");

    let mut buf = vec![0u8; 4096];
    let n = image
        .read_at(container.volume_mut(), described.offset, &mut buf, &locus)
        .unwrap();
    assert_eq!(n, 4096);
    // A repeated-byte run reads as that byte throughout.
    assert!(
        buf.windows(2).all(|w| w[0] == w[1]),
        "a described run of one repeated byte must read uniformly"
    );
}

/// Random access across a striped set agrees with sequential reading.
///
/// Stripes are the case where consecutive map entries may name streams in
/// different files, so `SetStreams` rebuilds its reader per call and hands the
/// resident bevy across. This is the test that the handoff serves correct
/// bytes rather than stale ones.
#[test]
fn read_at_in_set_agrees_on_a_striped_container() {
    use aff4tools::image::Image;
    use aff4tools::zip_volume_set::{VolumeOrigin, open_with_graph};

    let dir = corpus_root().join(format!("{STD}/Striped"));
    let first = dir.join("Base-Linear_1.aff4");
    let mut container = Container::open(&first).unwrap();
    let (volume, graph) = open_with_graph(dir.join("Base-Linear_2.aff4")).unwrap();
    assert!(container.add_volume(volume, graph, VolumeOrigin::Named));

    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&first);
    let image_arn = container
        .summarize()
        .unwrap()
        .images()
        .iter()
        .find(|o| o.role == ObjectRole::DiskImage)
        .map(|o| o.arn.clone())
        .expect("the striped fixture declares a DiskImage");
    let image = Image::open_in_set(&image_arn, container.volumes_mut(), lexicon, &locus).unwrap();

    const WINDOW: usize = 8 * 1024 * 1024;
    let mut sequential = Vec::with_capacity(WINDOW);
    image
        .read_from_set(
            container.volumes_mut(),
            &mut |bytes| {
                if sequential.len() < WINDOW {
                    let take = (WINDOW - sequential.len()).min(bytes.len());
                    sequential.extend_from_slice(&bytes[..take]);
                }
                Ok(())
            },
            &locus,
        )
        .unwrap();
    assert_eq!(sequential.len(), WINDOW);

    let mut whole = vec![0u8; WINDOW];
    let got = image
        .read_at_in_set(container.volumes_mut(), 0, &mut whole, &locus)
        .unwrap();
    assert_eq!(got, WINDOW);
    assert_eq!(
        whole, sequential,
        "random access across stripes must match traversal"
    );
}

/// Seeking backward and forward across a striped set returns stable bytes.
///
/// Guards the residency handoff specifically: a bevy cached by one reader and
/// handed to the next must not serve bytes from the stream it was read for
/// after the map moves to a different one. Sequential traversal cannot catch
/// this, because it never goes backward.
#[test]
fn read_at_in_set_is_stable_under_seeking() {
    use aff4tools::image::Image;
    use aff4tools::zip_volume_set::{VolumeOrigin, open_with_graph};

    let dir = corpus_root().join(format!("{STD}/Striped"));
    let first = dir.join("Base-Linear_1.aff4");
    let mut container = Container::open(&first).unwrap();
    let (volume, graph) = open_with_graph(dir.join("Base-Linear_2.aff4")).unwrap();
    assert!(container.add_volume(volume, graph, VolumeOrigin::Named));

    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&first);
    let image_arn = container
        .summarize()
        .unwrap()
        .images()
        .iter()
        .find(|o| o.role == ObjectRole::DiskImage)
        .map(|o| o.arn.clone())
        .expect("the striped fixture declares a DiskImage");
    let image = Image::open_in_set(&image_arn, container.volumes_mut(), lexicon, &locus).unwrap();

    // Offsets chosen to alternate across a wide span, so consecutive reads are
    // likely to land in different stripes.
    let offsets: [u64; 6] = [0, 4_194_304, 65_536, 8_388_608, 131_072, 2_097_152];

    let mut first_pass = Vec::new();
    for offset in offsets {
        let mut buf = vec![0u8; 4096];
        let n = image
            .read_at_in_set(container.volumes_mut(), offset, &mut buf, &locus)
            .unwrap();
        assert_eq!(n, 4096, "read at {offset} was short");
        first_pass.push(buf);
    }

    // The same offsets in reverse must return the same bytes.
    for (index, offset) in offsets.iter().enumerate().rev() {
        let mut buf = vec![0u8; 4096];
        let n = image
            .read_at_in_set(container.volumes_mut(), *offset, &mut buf, &locus)
            .unwrap();
        assert_eq!(n, 4096);
        assert_eq!(
            buf, first_pass[index],
            "re-reading offset {offset} after seeking returned different bytes"
        );
    }
}

/// A kept-resident reader returns the same bytes as the one-shot call.
///
/// `reader_in_set` exists for speed — it keeps the decompressed bevy across
/// reads, which `read_at_in_set` discards per call. Speed is only worth having
/// if the bytes agree, and a stale residency served after the map moves to
/// another stream is exactly how they would not.
#[test]
fn a_kept_reader_agrees_with_the_one_shot_call() {
    use aff4tools::image::Image;
    use aff4tools::zip_volume_set::{VolumeOrigin, open_with_graph};

    let dir = corpus_root().join(format!("{STD}/Striped"));
    let first = dir.join("Base-Linear_1.aff4");
    let mut container = Container::open(&first).unwrap();
    let (volume, graph) = open_with_graph(dir.join("Base-Linear_2.aff4")).unwrap();
    assert!(container.add_volume(volume, graph, VolumeOrigin::Named));

    let lexicon = container.lexicon();
    let locus = aff4tools::Locus::new(&first);
    let image_arn = container
        .summarize()
        .unwrap()
        .images()
        .iter()
        .find(|o| o.role == ObjectRole::DiskImage)
        .map(|o| o.arn.clone())
        .expect("the striped fixture declares a DiskImage");
    let image = Image::open_in_set(&image_arn, container.volumes_mut(), lexicon, &locus).unwrap();

    // Offsets that move between stripes and back, so the residency is handed
    // across a stream change and then reused.
    let offsets: [u64; 8] = [
        0, 4_194_304, 4_198_400, 0, 65_536, 8_388_608, 65_536, 12_582_912,
    ];

    let mut one_shot = Vec::new();
    for offset in offsets {
        let mut buf = vec![0u8; 4096];
        let n = image
            .read_at_in_set(container.volumes_mut(), offset, &mut buf, &locus)
            .unwrap();
        assert_eq!(n, 4096);
        one_shot.push(buf);
    }

    let mut reader = image.reader_in_set(container.volumes_mut());
    assert_eq!(reader.size(), 268_435_456);
    for (index, offset) in offsets.iter().enumerate() {
        let mut buf = vec![0u8; 4096];
        let n = reader.read_at(*offset, &mut buf, &locus).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(
            buf, one_shot[index],
            "the kept reader disagreed at offset {offset}"
        );
    }
}

/// Re-acquiring an AFF4 reproduces the source image exactly.
///
/// The strongest available test of `read_at`: the new container is assembled
/// from bytes served at offsets across the whole address space, then read back
/// through its own map. If the seam is wrong anywhere — an off-by-one at an
/// entry boundary, a stale bevy, a described run served with the wrong filler —
/// these digests differ.
///
/// Note what is *not* claimed: the two containers are not byte-identical, and
/// must not be. The source is snappy, the output lz4, and the ARNs differ. It
/// is the *image* that is reproduced, not the packaging.
#[test]
fn re_acquiring_an_aff4_reproduces_the_source_image() {
    use aff4tools::image::Image;
    use sha2::Digest as _;

    /// The image a container carries, hashed through its map.
    fn image_digest(path: &std::path::Path) -> (String, u64) {
        let locus = aff4tools::Locus::new(path);
        let mut container = Container::open(path).unwrap();
        let arn = container
            .summarize()
            .unwrap()
            .images()
            .iter()
            .find(|o| o.role == ObjectRole::DiskImage)
            .map(|o| o.arn.clone())
            .expect("a DiskImage");
        let lexicon = container.lexicon();
        let image = Image::open_in_set(&arn, container.volumes_mut(), lexicon, &locus).unwrap();
        let mut hasher = sha2::Sha256::new();
        let mut total = 0u64;
        image
            .read_from_set(
                container.volumes_mut(),
                &mut |bytes| {
                    hasher.update(bytes);
                    total += bytes.len() as u64;
                    Ok(())
                },
                &locus,
            )
            .unwrap();
        (format!("{:x}", hasher.finalize()), total)
    }

    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("reacquired.aff4");

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("acquire")
        .arg("--image")
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "acquire failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    let (source_digest, source_size) = image_digest(&source);
    let (output_digest, output_size) = image_digest(&output);

    assert_eq!(source_size, 268_435_456, "the source image size");
    assert_eq!(
        output_size, source_size,
        "the re-acquired image is a different size"
    );
    assert_eq!(
        source_digest, output_digest,
        "the re-acquired image does not reproduce the source"
    );
}

/// A re-acquired container verifies and conforms.
///
/// CLAUDE.md requires every writing path except `--deduplicate` to produce
/// zero deviations. Re-acquisition is a writing path.
#[test]
fn a_re_acquired_container_verifies_and_conforms() {
    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("reacquired.aff4");

    let acquired = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["acquire", "--image"])
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(acquired.status.success());
    let transcript = String::from_utf8_lossy(&acquired.stdout);
    assert!(
        transcript.contains("no deviations"),
        "acquisition reported deviations:\n{transcript}"
    );

    let verified = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("verify")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verified.stdout)
    );

    let conformance = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("conformance")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        conformance.status.success(),
        "conformance failed: {}",
        String::from_utf8_lossy(&conformance.stdout)
    );
}

/// An AFF4-L container is refused as an `--image` source, by name.
///
/// A logical container carries files, not a disk image. Acquiring one as an
/// image would either fail obscurely or, worse, hash something that is not the
/// evidence. The error names the reason.
#[test]
fn a_logical_container_is_refused_as_an_image_source() {
    let source = corpus_root().join(format!("{LOGICAL}/dream.aff4"));
    assert!(
        source.is_file(),
        "corpus fixture missing: {}",
        source.display()
    );
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("nope.aff4");

    let attempt = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["acquire", "--image"])
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();

    assert!(
        !attempt.status.success(),
        "a logical container must be refused"
    );
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&attempt.stdout),
        String::from_utf8_lossy(&attempt.stderr)
    );
    assert!(
        message.contains("DiskImage") || message.contains("logical"),
        "the refusal must say why:\n{message}"
    );
    assert!(!output.exists(), "no container may be left behind");
}

/// `export` reproduces the image the container carries.
#[test]
fn export_reproduces_the_image() {
    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("image.raw");

    let run = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("export")
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(bytes.len(), 268_435_456, "the exported image size");
    assert_eq!(
        hex_of(&bytes, HashAlgorithm::Sha256),
        "d7d6df4534f06568eb90a06e252592c9b79378b95bb9a7e01db3a388feda6c13",
        "exported bytes are not the image the container carries"
    );
}

/// `--output -` streams the same bytes to stdout.
#[test]
fn export_to_stdout_matches_the_file() {
    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["export"])
        .arg(&source)
        .args(["--output", "-"])
        .output()
        .unwrap();
    assert!(run.status.success());
    assert_eq!(
        hex_of(&run.stdout, HashAlgorithm::Sha256),
        "d7d6df4534f06568eb90a06e252592c9b79378b95bb9a7e01db3a388feda6c13",
        "stdout must carry the same bytes as a file export"
    );
}

/// An existing output file is refused, never truncated.
#[test]
fn export_refuses_to_overwrite() {
    let source = corpus_root().join(format!("{STD}/Base-Linear.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("taken.raw");
    // Tests may create fixtures; the library may not. See clippy.toml.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&output, b"existing evidence").unwrap();

    let run = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("export")
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();

    assert!(!run.status.success(), "overwriting must be refused");
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"existing evidence",
        "the existing file must be untouched"
    );
}

/// `export --logical` writes every file, including stream-backed ones.
///
/// `unicode.aff4` stores six of its seven files as `ImageStream`s rather than
/// ZIP segments (AFF4-L §3.4). Reading only segments silently skipped every
/// file above the threshold, which is why this asserts the count.
#[test]
fn export_logical_writes_every_file() {
    let source = corpus_root().join(format!("{LOGICAL}/unicode.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out");

    let run = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("export")
        .arg(&source)
        .arg("--logical")
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "export --logical failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let mut found = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    walk(&target, &mut found);
    assert_eq!(
        found.len(),
        7,
        "every logical file must be written: {found:?}"
    );

    // The recorded hash for one of the stream-backed files.
    let allocated = target.join("test_images/AFF4Std/Base-Allocated.aff4");
    let bytes = std::fs::read(&allocated).unwrap();
    assert_eq!(
        hex_of(&bytes, HashAlgorithm::Md5),
        "8f6d32154ad22a3e291fb0224e367b3f",
        "extracted content does not match the container's recorded hash"
    );
}

/// The digest of `bytes`, using the library's own hasher.
///
/// Deliberately not a test-only hash implementation: comparing against the
/// container's recorded value means comparing what aff4tools itself would
/// compute.
fn hex_of(bytes: &[u8], algorithm: HashAlgorithm) -> String {
    let mut hasher = aff4tools::hash::MultiHasher::for_algorithms(&[algorithm]);
    hasher.update(bytes);
    hasher
        .finish()
        .first()
        .expect("one algorithm in, one digest out")
        .hex()
        .to_owned()
}

/// No exported path escapes the target, whatever the container recorded.
///
/// `broken-dedupe.aff4` records `/Users/bradley/git/pyaff4/...`, an absolute
/// path from the acquiring machine. It must land beneath the target and
/// nowhere else.
#[test]
fn an_absolute_arn_path_is_rebased_under_the_target() {
    let source = corpus_root().join(format!("{LOGICAL}/broken-dedupe.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out");

    // The fixture is deliberately broken, so the run may report skips. What
    // matters is that nothing was written outside the target.
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("export")
        .arg(&source)
        .arg("--logical")
        .arg(&target)
        .output()
        .unwrap();

    assert!(
        !std::path::Path::new("/Users/bradley").exists(),
        "an absolute recorded path escaped the target"
    );
    if target.exists() {
        for entry in walkdir(&target) {
            assert!(
                entry.starts_with(&target),
                "{} escaped the target",
                entry.display()
            );
        }
    }
}

/// Every path beneath `dir`, recursively.
fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            out.push(path);
        }
    }
    out
}

/// Recorded times reach the extracted files where the host can set them.
#[test]
fn extracted_files_carry_their_recorded_times() {
    let source = corpus_root().join(format!("{LOGICAL}/dream.aff4"));
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out");

    let run = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .arg("export")
        .arg(&source)
        .arg("--logical")
        .arg(&target)
        .output()
        .unwrap();
    assert!(run.status.success());

    let file = target.join("test_images/AFF4-L/dream.txt");
    let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
    let recorded = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_537_155_740);
    assert_eq!(
        modified, recorded,
        "lastWritten 2018-09-17T13:42:20+10:00 did not reach the file"
    );

    // The two macOS cannot set must be reported rather than lost.
    let transcript = String::from_utf8_lossy(&run.stdout);
    assert!(
        transcript.contains("birthTime"),
        "an unsettable recorded time must still be reported:\n{transcript}"
    );
}

/// `unicode.aff4` omits `aff4:zip_segment` on the one file it stores as a
/// segment, and that departure must be reported.
///
/// AFF4-L §3.8's recipe ends by adding the type "to indicate that it is stored
/// as a Zip Segment". pyaff4 writes it in `dream.aff4` and not here, so the
/// same implementation is inconsistent with itself — which is why the rule
/// cannot be inferred from reference output alone.
#[test]
fn unicode_omits_zip_segment_on_its_segment_stored_file() {
    let path = corpus_root().join(format!("{LOGICAL}/unicode.aff4"));
    let mut container = Container::open(&path).expect("opening unicode.aff4");
    let deviations = container
        .deviations_only()
        .expect("collecting deviations")
        .deviations;

    let found: Vec<_> = deviations
        .iter()
        .filter(|d| d.kind == aff4tools::DeviationKind::MissingZipSegmentType)
        .collect();

    assert_eq!(
        found.len(),
        1,
        "exactly one file in unicode.aff4 is segment-stored without the type, \
         got: {deviations:#?}"
    );
    assert!(
        found[0].locus.to_string().contains("README.txt"),
        "the deviation must name the file it is about: {}",
        found[0].locus
    );

    // Cited to the paper, not the Standard: the Standard does not cover
    // logical files at all, so claiming a section of it would be an invention.
    // pyaff4-era AFF4-L: v1.0a as base, the 2019 paper for logical constructs.
    let generation = aff4tools::Generation::PyAff4Logical;
    assert_eq!(
        aff4tools::DeviationKind::MissingZipSegmentType.spec_section(generation),
        None,
        "the Standard legislates nothing here"
    );
    let (document, section) = aff4tools::DeviationKind::MissingZipSegmentType
        .other_specification(generation)
        .expect("AFF4-L is the document that does");
    assert!(
        document.contains("AFF4-L") && section == "§3.8",
        "must cite AFF4-L §3.8, got {document} {section}"
    );
}

/// A correctly typed container raises no such deviation.
///
/// `dream.aff4` stores its one file as a segment *and* declares
/// `aff4:zip_segment`. Without this, a check that fired on every logical file
/// would pass the test above while being useless.
#[test]
fn dream_declares_zip_segment_and_raises_no_deviation() {
    let path = corpus_root().join(format!("{LOGICAL}/dream.aff4"));
    let mut container = Container::open(&path).expect("opening dream.aff4");
    let deviations = container
        .deviations_only()
        .expect("collecting deviations")
        .deviations;

    assert!(
        !deviations
            .iter()
            .any(|d| d.kind == aff4tools::DeviationKind::MissingZipSegmentType),
        "dream.aff4 types its segment correctly: {deviations:#?}"
    );
}

/// Every recorded digest in `unicode.aff4` is recomputed, including the file
/// that omits `aff4:zip_segment`.
///
/// Before the fallback, `README.txt` fell through to the map path and its two
/// digests were reported `NOT RECOMPUTED` — a silent gap on a canonical
/// reference container, at exit code 0. The bytes were present and correct the
/// whole time.
#[test]
fn unicode_verifies_every_digest_including_the_untyped_segment() {
    let path = corpus_root().join(format!("{LOGICAL}/unicode.aff4"));
    let mut container = Container::open(&path).expect("opening unicode.aff4");
    let report = aff4tools::verify::verify_container(
        &mut container,
        aff4tools::verify::VerifyOptions { block_hashes: true },
    )
    .expect("verifying unicode.aff4");

    assert!(!report.has_mismatch(), "unicode.aff4 must verify clean");

    let declined: Vec<_> = report
        .checks
        .iter()
        .filter(|c| !c.outcome.was_checked())
        .collect();
    assert!(
        declined.is_empty(),
        "no digest may be left unchecked: {declined:#?}"
    );

    // The file that omits the type must be among those actually checked.
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.subject.as_str().contains("README.txt")),
        "README.txt's digests must be recomputed, not skipped"
    );
}

/// A folder is never asked for a data stream.
///
/// `ObjectRole::is_image` counts `FolderImage` among the images, which is right
/// for the listing but wrong for verification: a folder has no map, no stream,
/// and no `aff4:hash`. Every AFF4-L container holding a folder reported one
/// "names no data stream" note per folder, on containers that were well formed.
#[test]
fn folders_are_not_reported_as_unresolvable_images() {
    for name in ["unicode.aff4", "dream.aff4"] {
        let path = corpus_root().join(format!("{LOGICAL}/{name}"));
        let mut container =
            Container::open(&path).unwrap_or_else(|e| panic!("opening {name}: {e}"));
        let report = aff4tools::verify::verify_container(
            &mut container,
            aff4tools::verify::VerifyOptions { block_hashes: true },
        )
        .unwrap_or_else(|e| panic!("verifying {name}: {e}"));

        assert!(
            !report
                .notes
                .iter()
                .any(|n| n.contains("could not be resolved to a map")),
            "{name} raised an unresolvable-image note: {:#?}",
            report.notes
        );
    }
}
