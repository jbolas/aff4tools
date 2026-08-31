//! End-to-end checks that what aff4tools writes, aff4tools reads.
//!
//! Validation by pyaff4 lives in `tests/cross_tool.rs`, because
//! self-consistency cannot catch a writer and reader sharing one
//! misunderstanding.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aff4tools::Container;
use aff4tools::write::container_writer::ContainerWriter;
use aff4tools::write::guard::SourceRegistry;

/// **Members must reach the file as they are written, not at `finish`.**
///
/// Buffering members until the volume closed would hold a 16 GB acquisition's
/// compressed bevies in RAM and leave the output at zero bytes for its whole
/// duration — indistinguishable from a hang, and unbounded memory on
/// evidence-sized input. `zip_writer` names "no member may be buffered whole in
/// memory" as a requirement.
///
/// Asserted by observing the file grow *while members are still being added*.
/// The sink keeps a 1 MiB write buffer, which is why the payload here exceeds
/// it: what must not happen is the *container* being buffered, not every byte
/// reaching the platter individually.
#[test]
fn members_reach_the_file_before_the_volume_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("streamed.aff4");
    let registry = SourceRegistry::new();

    let mut writer = ContainerWriter::create(&path, &registry).unwrap();

    // Well past the sink's 1 MiB buffer, so a streaming writer must have
    // flushed most of it while a buffering one would still hold everything.
    let payload = vec![0xABu8; 8 * 1024 * 1024];
    for i in 0..4 {
        writer
            .add_stored_segment(&format!("aff4://vol/big{i}"), &payload)
            .unwrap();
    }

    let mid_write = std::fs::metadata(&path).unwrap().len();
    assert!(
        mid_write >= 24 * 1024 * 1024,
        "32 MiB of members must be largely on disk before finish, found only \
         {mid_write} bytes — the container is being buffered in memory"
    );

    // `bytes_written` is what a progress display reports, so it must track the
    // real position rather than a queued count.
    assert!(
        writer.bytes_written() >= mid_write,
        "reported position must not lag the file"
    );

    writer.finish().unwrap();

    // And the result is still a valid container.
    let mut container = Container::open(&path).unwrap();
    let summary = container.summarize().unwrap();
    assert!(
        summary.deviations.is_empty(),
        "streaming must not cost conformance: {:#?}",
        summary.deviations
    );
}

/// A container we write must open, and report **zero** deviations — a bar no
/// corpus writer currently meets.
#[test]
fn a_written_container_opens_and_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("written.aff4");
    let registry = SourceRegistry::new();

    let writer = ContainerWriter::create(&path, &registry).unwrap();
    let expected_arn = writer.volume_arn().as_str().to_owned();
    writer.finish().unwrap();

    let mut container = Container::open(&path).expect("our own writer's output must open");
    let summary = container.summarize().unwrap();

    assert_eq!(summary.volume.arn.as_str(), expected_arn);
    assert!(
        summary.deviations.is_empty(),
        "our output must have zero deviations, found: {:#?}",
        summary.deviations
    );
}

/// §5.4: `container.description` must be the first member stored — measured by
/// physical offset, which is what "stored" means.
#[test]
fn container_description_is_written_first() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ordered.aff4");
    let registry = SourceRegistry::new();

    ContainerWriter::create(&path, &registry)
        .unwrap()
        .finish()
        .unwrap();

    let file = std::fs::File::open(&path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut infos: Vec<(String, u64)> = (0..archive.len())
        .map(|i| {
            let f = archive.by_index(i).unwrap();
            (f.name().to_owned(), f.header_start())
        })
        .collect();
    infos.sort_by_key(|(_, offset)| *offset);

    assert_eq!(
        infos[0].0, "container.description",
        "physically first member must be container.description"
    );
    assert_eq!(infos[0].1, 0, "and it must start at offset 0");
}

/// The minor version is a feature marker, and must state which vocabulary the
/// container actually uses.
///
/// Every implementation reads it that way: pyaff4 writes `minor=1` only from
/// `createURN` ("create a new writable *logical* AFF4 container") and `minor=2`
/// for encrypted containers, while Evimetry writes `minor=0` on every physical
/// image. The corpus splits on exactly that line — 12 physical containers at
/// 1.0, 3 logical at 1.1.
///
/// It is not bookkeeping. pyaff4's `Container.identifyURN` selects
/// `lexicon.standard11` when the version is 1.1 and `lexicon.standard`
/// otherwise, and its hash validator handles only the latter, so a physical
/// image declaring 1.1 cannot be checked by the one external implementation
/// that recomputes AFF4 hashes.
#[test]
fn the_minor_version_states_which_vocabulary_is_used() {
    let dir = tempfile::tempdir().unwrap();
    let registry = SourceRegistry::new();

    let physical = dir.path().join("physical.aff4");
    ContainerWriter::create(&physical, &registry)
        .unwrap()
        .finish()
        .unwrap();

    let logical = dir.path().join("logical.aff4");
    ContainerWriter::create_logical(&logical, &registry)
        .unwrap()
        .finish()
        .unwrap();

    let minor_of = |path: &std::path::Path| -> u32 {
        let mut container = Container::open(path).unwrap();
        container
            .summarize()
            .unwrap()
            .version
            .expect("a version must be declared")
            .minor
    };

    assert_eq!(
        minor_of(&physical),
        0,
        "a physical image uses only v1.0 terms"
    );
    assert_eq!(
        minor_of(&logical),
        1,
        "a logical image carries FileImage, originalFileName, and the \
         filesystem timestamps, none of which exist in v1.0"
    );
}

/// The volume names this tool, so a container's provenance is legible without
/// external records.
///
/// The minor version is asserted per profile by
/// `the_minor_version_states_which_vocabulary_is_used`.
#[test]
fn the_version_segment_declares_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("versioned.aff4");
    let registry = SourceRegistry::new();

    ContainerWriter::create(&path, &registry)
        .unwrap()
        .finish()
        .unwrap();

    let mut container = Container::open(&path).unwrap();
    let summary = container.summarize().unwrap();
    let version = summary.version.expect("a version must be declared");
    assert_eq!(version.major, 1);
    // Name *and* version, the convention every corpus writer follows
    // (`Evimetry 2.2.0`). Asserted against `CARGO_PKG_VERSION` rather than a
    // literal, so bumping the release does not fail this — but the version must
    // be there: a bare `aff4tools` cannot say which build produced the evidence.
    assert_eq!(
        version.tool.as_deref(),
        Some(format!("aff4tools {}", env!("CARGO_PKG_VERSION")).as_str())
    );
}

/// Refusing to overwrite is a hard rule, checked end to end.
#[test]
fn writing_over_an_existing_container_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("once.aff4");
    let registry = SourceRegistry::new();

    ContainerWriter::create(&path, &registry)
        .unwrap()
        .finish()
        .unwrap();

    assert!(
        ContainerWriter::create(&path, &registry).is_err(),
        "a second write to the same path must be refused"
    );
}
