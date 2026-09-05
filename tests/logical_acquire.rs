//! Phase 4: AFF4-L logical acquisition, per Schatz (2019).
//!
//! > Schatz, B.L. *AFF4-L: A Scalable Open Logical Evidence Container.*
//! > Digital Investigation 29, S143-S149. DFRWS USA 2019.
//!
//! **Every bare section number below cites that paper**, not the AFF4
//! Standard. This file cites no other document.
//!
//! The tests that matter here are the ones covering what **pyaff4 does not
//! write**: the §3.6 resource-enumeration model. Without it a consumer cannot
//! tell which paths were acquisition roots or walk the acquired tree, and no
//! AFF4-L container in existence today supports that.

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::disallowed_methods)]

use std::io::Write as _;
use std::path::Path;

use aff4tools::verify::{VerifyOptions, verify_container};
use aff4tools::write::container_writer::ContainerWriter;
use aff4tools::write::guard::SourceRegistry;
use aff4tools::write::logical::{LogicalOptions, acquire_logical};

/// The built binary, for the tests that assert on its output and exit code.
fn aff4tools() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("aff4tools").expect("the binary must build")
}
use aff4tools::{Container, Locus};

fn write_file(path: &Path, body: &[u8]) {
    #[allow(clippy::disallowed_methods)]
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body).unwrap();
}

/// Read a container's `information.turtle`.
fn read_turtle(path: &Path) -> String {
    let file = std::fs::File::open(path).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let mut buf = String::new();
    use std::io::Read as _;
    zip.by_name("information.turtle")
        .unwrap()
        .read_to_string(&mut buf)
        .unwrap();
    buf
}

/// Build a small tree and acquire it, returning the container path and turtle.
fn acquire_tree(dir: &Path) -> (std::path::PathBuf, String) {
    let tree = dir.join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    write_file(&tree.join("a.txt"), b"hello world\n");
    write_file(&tree.join("sub").join("c.txt"), b"nested\n");

    let out = dir.join("logical.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();

    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert_eq!(acquired.files, 2, "two files acquired");
    assert_eq!(acquired.folders, 2, "the root and its subfolder");

    let turtle = {
        let file = std::fs::File::open(&out).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        let mut buf = String::new();
        use std::io::Read as _;
        zip.by_name("information.turtle")
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        buf
    };
    (out, turtle)
}

/// The §3.6 enumeration model must be present in full.
///
/// pyaff4 defines all four of these terms and writes none of them, so this is
/// the property that distinguishes a paper-conformant container from the only
/// existing implementation's output.
#[test]
fn the_resource_enumeration_model_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let (_out, turtle) = acquire_tree(dir.path());

    for term in [
        "aff4:LogicalAcquisitionTask",
        "aff4:filesystemRoot",
        "aff4:Folder",
        "aff4:child",
    ] {
        assert!(
            turtle.contains(term),
            "{term} missing — this is exactly what pyaff4 omits:\n{turtle}"
        );
    }
}

/// Table 3's five metadata terms, plus both §3.7 hashes.
#[test]
fn table_3_metadata_and_both_hashes_are_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let (_out, turtle) = acquire_tree(dir.path());

    for term in [
        "aff4:originalFileName",
        "aff4:birthTime",
        "aff4:lastWritten",
        "aff4:lastAccessed",
        "aff4:FileImage",
    ] {
        assert!(turtle.contains(term), "{term} missing:\n{turtle}");
    }
    assert!(turtle.contains("aff4:MD5"), "§3.7 MD5:\n{turtle}");
    assert!(turtle.contains("aff4:SHA1"), "§3.7 SHA1:\n{turtle}");

    // Timestamps must be the correct XSD type, not pyaff4's lowercase form.
    assert!(
        turtle.contains("xsd:dateTime"),
        "correct datatype:\n{turtle}"
    );
    assert!(
        !turtle.contains("xsd:datetime"),
        "must not reproduce pyaff4's non-XSD datatype:\n{turtle}"
    );
}

/// §3.8: `zip_segment` joins the type list only for segment-stored content.
#[test]
fn segment_stored_files_declare_zip_segment() {
    let dir = tempfile::tempdir().unwrap();
    let (_out, turtle) = acquire_tree(dir.path());
    assert!(turtle.contains("aff4:zip_segment"), "{turtle}");
}

/// The container must open and report zero deviations.
#[test]
fn a_logical_container_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let (out, _turtle) = acquire_tree(dir.path());

    let mut container = Container::open(&out).unwrap();
    let summary = container.summarize().unwrap();
    assert!(
        summary.deviations.is_empty(),
        "deviations: {:#?}",
        summary.deviations
    );
}

/// File content must be stored byte-identically and be readable as a segment.
#[test]
fn acquired_file_content_is_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let (out, _turtle) = acquire_tree(dir.path());

    let file = std::fs::File::open(&out).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let name = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_owned())
        .find(|n| n.ends_with("a.txt"))
        .expect("the acquired file must be a member");

    use std::io::Read as _;
    let mut body = Vec::new();
    zip.by_name(&name).unwrap().read_to_end(&mut body).unwrap();
    assert_eq!(body, b"hello world\n", "content must survive verbatim");
}

/// Two acquisitions of one tree must produce identical metadata.
///
/// Directory order is not guaranteed by the filesystem, so the walker sorts.
/// Without that, two containers of the same evidence would differ for no
/// reason an examiner could explain.
#[test]
fn acquisition_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let (_a, first) = acquire_tree(&dir.path().join("one"));
    let (_b, second) = acquire_tree(&dir.path().join("two"));

    // Volume ARNs and the tree's own location differ by design, so compare the
    // *shape*: the sequence of predicates and types, which is what a
    // non-deterministic directory walk would disturb.
    let shape = |t: &str| {
        t.lines()
            .map(str::trim)
            .filter(|l| l.starts_with("aff4:") || l.starts_with("a "))
            .map(|l| l.split_whitespace().next().unwrap_or("").to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shape(&first),
        shape(&second),
        "two acquisitions of one tree must produce the same structure"
    );

    // And the digests, which depend only on content.
    let digests = |t: &str| {
        t.lines()
            .filter(|l| l.contains("aff4:hash"))
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        digests(&first),
        digests(&second),
        "same content, same hashes"
    );
}

/// Content that compresses poorly, so a large file really occupies bevies
/// rather than collapsing to nothing.
fn incompressible(len: usize) -> Vec<u8> {
    // A cheap xorshift: deterministic, so a failure reproduces exactly.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u8::try_from(state & 0xff).unwrap_or(0)
        })
        .collect()
}

/// Acquire one tree with explicit options, returning the container path.
fn acquire_with(dir: &Path, tree: &Path, options: LogicalOptions) -> std::path::PathBuf {
    let out = dir.join("out.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(tree).unwrap();

    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree.to_path_buf()),
        options,
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert!(
        acquired.skipped.is_empty(),
        "nothing should be skipped: {:?}",
        acquired.skipped
    );
    out
}

/// **Q11, the gap this closes.** A file above the §3.3 threshold must be
/// *acquired as an ImageStream*, not skipped.
///
/// Before this, `--logical` silently limited itself to trees of small files:
/// anything over 1 MiB was recorded in `skipped` with a reason. A logical
/// imager that cannot store a 2 MiB file is not a logical imager.
#[test]
fn files_above_the_threshold_are_stored_as_image_streams() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    let big = incompressible(3 * 1024 * 1024);
    write_file(&tree.join("big.bin"), &big);
    write_file(&tree.join("small.txt"), b"small\n");

    let out = acquire_with(dir.path(), &tree, LogicalOptions::default());

    let turtle = read_turtle(&out);
    assert!(
        turtle.contains("aff4:ImageStream"),
        "the large file must be stored as an ImageStream:\n{turtle}"
    );
    // The corpus shape: the file's own ARN carries FileImage, Image and
    // ImageStream together, with no dataStream indirection.
    assert!(
        !turtle.contains("aff4:dataStream"),
        "a logical file IS its stream; a dataStream here would make readers \
         look for a Map that does not exist:\n{turtle}"
    );
    // The bevies must live under the file's own path, per §3.4 — so the
    // container browses readably in an ordinary ZIP tool.
    let file = std::fs::File::open(&out).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_owned())
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with("big.bin/00000000")),
        "expected bevy members under the file's own path, got: {names:?}"
    );
    // The small file stays a plain segment: the threshold must still split.
    assert!(
        names.iter().any(|n| n.ends_with("small.txt")),
        "the small file must remain a zip segment: {names:?}"
    );
}

/// The large file's bytes must survive: read back through the ImageStream and
/// compare against the source, byte for byte.
///
/// This is gate 3 applied to the logical path. Storing a stream that decodes to
/// the wrong bytes would pass every structural check above.
#[test]
fn a_large_logical_file_reads_back_byte_identically() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // Deliberately not a chunk multiple: exercises the trimmed final chunk.
    let big = incompressible(2 * 1024 * 1024 + 1234);
    write_file(&tree.join("big.bin"), &big);

    let out = acquire_with(dir.path(), &tree, LogicalOptions::default());
    let locus = Locus::new(&out);

    let mut container = Container::open(&out).unwrap();
    let summary = container.summarize().unwrap();
    let arn = summary
        .objects
        .iter()
        .find(|o| o.arn.as_str().ends_with("big.bin"))
        .expect("the acquired file must be described")
        .arn
        .clone();

    // A large logical file IS an ImageStream, so it is read as one directly —
    // there is no Map to resolve.
    let lexicon = container.lexicon();
    let stream = {
        let graph = container.graph().unwrap();
        aff4tools::stream::ImageStream::open(&arn, &graph, lexicon, &locus)
            .expect("the acquired file must open as an ImageStream")
    };

    let mut back = Vec::new();
    stream
        .read_all(
            container.volume_mut(),
            &mut |bytes: &[u8]| {
                back.extend_from_slice(bytes);
                Ok(())
            },
            &locus,
        )
        .unwrap();
    assert_eq!(back.len(), big.len(), "length must match");
    assert!(back == big, "the stored bytes must reproduce the source");
}

/// A container holding a large file must still verify and conform.
#[test]
fn a_large_logical_file_verifies_and_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_file(&tree.join("big.bin"), &incompressible(2 * 1024 * 1024));

    let out = acquire_with(dir.path(), &tree, LogicalOptions::default());

    let mut container = Container::open(&out).unwrap();
    let summary = container.summarize().unwrap();
    assert!(
        summary.deviations.is_empty(),
        "deviations: {:#?}",
        summary.deviations
    );

    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();
    assert!(
        !report.has_mismatch(),
        "a logical container with a large file must verify clean: {:#?}",
        report
            .checks
            .iter()
            .filter(|c| c.outcome.is_mismatch())
            .collect::<Vec<_>>()
    );
    assert!(
        report.match_count() > 0,
        "something must actually have been recomputed, or this proves nothing"
    );
}

/// The acquisition transcript must be written to a log beside the container.
///
/// A real acquisition reports thousands of skipped paths; terminal scrollback
/// is not a record. The log defaults to `<output>_log.txt` so it travels with
/// the evidence it describes.
#[test]
fn the_acquisition_transcript_is_logged_beside_the_container() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_file(&tree.join("a.txt"), b"hello\n");

    let out = dir.path().join("evidence.aff4");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["acquire", "--logical"])
        .arg(&tree)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert!(status.status.success(), "acquisition must succeed");

    let log = dir.path().join("evidence_log.txt");
    assert!(
        log.is_file(),
        "the default log must sit beside the container: {}",
        log.display()
    );

    let body = std::fs::read_to_string(&log).unwrap();
    let stdout = String::from_utf8_lossy(&status.stdout);
    for line in ["Acquiring:", "Volume ARN:", "Acquired:", "Conformance:"] {
        assert!(body.contains(line), "the log must carry {line:?}:\n{body}");
        assert!(stdout.contains(line), "and so must stdout:\n{stdout}");
    }
    assert!(
        body.contains("acquisition log") && body.contains("Started:"),
        "the log must identify itself and when it began:\n{body}"
    );
}

/// The log must never overwrite an existing one.
#[test]
fn an_existing_log_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_file(&tree.join("a.txt"), b"hello\n");

    let out = dir.path().join("evidence.aff4");
    let log = dir.path().join("evidence_log.txt");
    write_file(&log, b"a previous acquisition's record\n");

    let result = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["acquire", "--logical"])
        .arg(&tree)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();

    assert!(
        !result.status.success(),
        "it must refuse rather than clobber"
    );
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        "a previous acquisition's record\n",
        "the earlier log must survive untouched"
    );
}

/// A symlink is recorded as skipped, never silently followed.
///
/// Following one can duplicate content or escape the acquisition root, and the
/// paper defines no representation for the link itself.
#[test]
fn symlinks_are_skipped_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_file(&tree.join("real.txt"), b"real\n");
    std::os::unix::fs::symlink(tree.join("real.txt"), tree.join("link.txt")).unwrap();

    let out = dir.path().join("sym.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();

    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert_eq!(acquired.files, 1, "only the real file is acquired");
    assert!(
        acquired
            .skipped
            .iter()
            .any(|(p, r)| p.ends_with("link.txt") && r.contains("symlink")),
        "the symlink must be reported, not silently dropped: {:?}",
        acquired.skipped
    );
}

/// A path that was skipped is named by no triple in the container.
///
/// Symlinks and character devices are refused and the skip reported. The
/// parent folder must not then assert `aff4:child` naming them, and a special
/// file must not have its Table 3 metadata written before the check that
/// refuses it. Either would describe a resource the container does not hold:
/// a consumer walking §3.6's tree would reach an ARN that resolves to nothing.
///
/// The skip is reported to the examiner, which is where an unacquired path
/// belongs. It must not also appear in the graph as a relationship the
/// container cannot honor.
///
/// A folder whose *contents* could not be listed is a different case and is
/// deliberately still recorded: the folder itself was observed, and only its
/// children are missing.
#[cfg(unix)]
#[test]
fn a_skipped_path_is_named_by_no_triple() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    write_file(&tree.join("real.txt"), b"acquired\n");
    std::os::unix::fs::symlink("/etc/hosts", tree.join("link")).unwrap();

    // A FIFO is neither a folder nor a regular file — the case that can leave
    // a subject with timestamps and no rdf:type.
    // `mkfifo(1)` rather than libc, to keep this test dependency-free. If it
    // is unavailable the symlink half of the test still runs.
    let fifo = tree.join("pipe");
    let made = std::process::Command::new("mkfifo")
        .arg(fifo.to_str().unwrap())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let out = dir.path().join("skips.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert_eq!(acquired.files, 1, "only the regular file is acquired");
    let expected_skips = if made { 2 } else { 1 };
    assert_eq!(
        acquired.skipped.len(),
        expected_skips,
        "every refusal must be reported: {:?}",
        acquired.skipped
    );

    let turtle = read_turtle(&out);
    assert!(
        turtle.contains("real.txt"),
        "the acquired file must be described"
    );
    assert!(
        !turtle.contains("/link"),
        "a skipped symlink must not appear in the graph:\n{turtle}"
    );
    if made {
        assert!(
            !turtle.contains("/pipe"),
            "a skipped special file must not appear in the graph:\n{turtle}"
        );
    }
}

/// §3.6 names *roots*, plural: one acquisition task may carry several
/// `aff4:filesystemRoot` edges.
///
/// An examiner collecting from two places on one disk — a user's documents and
/// an attached volume's exports — must get one container recording one
/// acquisition, not two containers to correlate by hand. The per-root loop and
/// the edges it asserts had no coverage: every other test here passes a single
/// root, so a regression collapsing `roots` to `roots[0]` would have gone
/// unnoticed.
#[test]
fn several_roots_each_get_a_filesystem_root_edge() {
    let dir = tempfile::tempdir().unwrap();
    let documents = dir.path().join("documents");
    let exports = dir.path().join("elsewhere").join("exports");
    std::fs::create_dir_all(&documents).unwrap();
    std::fs::create_dir_all(&exports).unwrap();
    write_file(&documents.join("a.txt"), b"from documents\n");
    write_file(&exports.join("b.txt"), b"from exports\n");

    let out = dir.path().join("multi.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&documents).unwrap();
    registry.register(&exports).unwrap();

    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let roots = vec![documents.clone(), exports.clone()];
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        &roots,
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert_eq!(acquired.files, 2, "one file from each root");
    assert_eq!(acquired.folders, 2, "both roots recorded as folders");

    let turtle = read_turtle(&out);

    // Both roots must hang off the acquisition task. Turtle writes a repeated
    // predicate once with a comma-separated object list, so the roots are found
    // in that list rather than by counting `aff4:filesystemRoot` occurrences —
    // a count that reads 1 even when both edges are present.
    let roots_clause = turtle
        .split("aff4:filesystemRoot")
        .nth(1)
        .expect("the acquisition task must declare its roots")
        .split(';')
        .next()
        .expect("the root list ends at the next predicate");
    for root in [&documents, &exports] {
        let fragment = aff4tools::write::logical::arn_path_fragment(&root.to_string_lossy());
        assert!(
            roots_clause.contains(&fragment),
            "{} must be listed as an acquisition root, got:{roots_clause}",
            root.display()
        );
    }

    // One acquisition, not one per root: §3.6's task is the shared subject the
    // roots attach to.
    assert_eq!(
        turtle.matches("aff4:LogicalAcquisitionTask").count(),
        1,
        "several roots are still a single acquisition:\n{turtle}"
    );

    let mut container = Container::open(&out).unwrap();
    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();
    assert!(
        !report.has_mismatch(),
        "a multi-root container must verify clean: {:#?}",
        report
            .checks
            .iter()
            .filter(|c| c.outcome.is_mismatch())
            .collect::<Vec<_>>()
    );
}

/// Two roots sharing a basename must stay distinct.
///
/// ARNs are built from the full path, not the basename, so `caseA/docs` and
/// `caseB/docs` cannot collide. Were that ever reduced to the file name, one
/// root's files would silently overwrite the other's — the failure mode an
/// examiner is least able to detect, since the container would still verify.
#[test]
fn same_named_roots_in_different_places_do_not_collide() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("caseA").join("docs");
    let b = dir.path().join("caseB").join("docs");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    write_file(&a.join("notes.txt"), b"alpha\n");
    write_file(&b.join("notes.txt"), b"beta\n");

    let out = dir.path().join("collide.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&a).unwrap();
    registry.register(&b).unwrap();

    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let roots = vec![a.clone(), b.clone()];
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        &roots,
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert_eq!(
        acquired.files, 2,
        "both same-named files must be acquired, not one overwriting the other"
    );

    // The two files must be stored under distinct, full-path-derived members.
    let file = std::fs::File::open(&out).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let members: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_owned())
        .collect();
    let notes: Vec<&String> = members
        .iter()
        .filter(|n| n.ends_with("notes.txt"))
        .collect();
    assert_eq!(
        notes.len(),
        2,
        "both roots' notes.txt must survive as separate members: {members:#?}"
    );
    assert_ne!(notes[0], notes[1], "and under different names: {notes:#?}");

    let mut container = Container::open(&out).unwrap();
    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();
    assert!(
        !report.has_mismatch(),
        "distinct content under colliding basenames must verify: {:#?}",
        report
            .checks
            .iter()
            .filter(|c| c.outcome.is_mismatch())
            .collect::<Vec<_>>()
    );
}

/// `aff4:stored` is written exactly once per subject.
///
/// A large file's bytes become an `ImageStream`, and that stream's ARN *is* the
/// file's own — there is no `aff4:dataStream` indirection (see
/// `record_large_file`). Both `write_image_stream_as` and Table 3 emitted
/// `aff4:stored`, so a stream-backed file carried the identical triple twice:
/// `aff4:stored : , : ;`. RDF treats a repeated triple as one statement, so
/// neither `verify` nor `conformance` noticed — but this writer's output must
/// conform exactly, and a duplicate makes a byte comparison against another
/// writer differ for no reason.
#[test]
fn stored_is_recorded_once_per_subject() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    // One either side of the segment threshold: the small file takes the ZIP
    // segment path, the large one the ImageStream path that duplicated.
    write_file(&tree.join("small.log"), b"small\n");
    write_file(
        &tree.join("big.bin"),
        &vec![
            b'A';
            usize::try_from(aff4tools::write::logical::MAX_SEGMENT_RESIDENT_SIZE).unwrap() + 1
        ],
    );

    let out = dir.path().join("stored.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    let turtle = read_turtle(&out);

    // Turtle writes a repeated predicate once with a comma-separated object
    // list, so the duplicate shows as `aff4:stored : , :` rather than as two
    // `aff4:stored` tokens. Check each subject's object list.
    for block in turtle.split("\n\n") {
        for line in block.lines() {
            let line = line.trim();
            let Some(objects) = line.strip_prefix("aff4:stored") else {
                continue;
            };
            let objects = objects.trim_end_matches([';', '.', ' ']);
            assert!(
                !objects.contains(','),
                "a subject records aff4:stored more than once — `{}` in:\n{block}",
                line
            );
        }
    }

    // The triple must still be present: dropping it entirely would also pass a
    // duplicate check.
    assert!(
        turtle.contains("aff4:stored"),
        "every subject still needs its aff4:stored edge:\n{turtle}"
    );

    let mut container = Container::open(&out).unwrap();
    let report = verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();
    assert!(!report.has_mismatch(), "the container must still verify");
}

/// Every logical file records its own linear digests, whichever way it is stored.
///
/// §3.7 pairs MD5 and SHA-1 on each file. An examiner expects a per-file hash
/// they can compare against a hash of the original — so it must be the digest
/// of the file's *own bytes*, not something derived from chunking. Storage form
/// must not change it: a file at 1 MiB and the same file at 1 MiB + 1 byte take
/// different paths through the writer and must both record the same kind of
/// hash. Block hashes are a separate, additional record on their own
/// `aff4:BlockHashes` subjects, never a substitute.
#[test]
fn every_logical_file_records_linear_digests_whatever_its_storage() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    let threshold = usize::try_from(aff4tools::write::logical::MAX_SEGMENT_RESIDENT_SIZE).unwrap();
    let small = b"a small file\n".to_vec();
    // One byte over, so it takes the ImageStream path.
    let large = vec![b'Z'; threshold + 1];
    write_file(&tree.join("small.log"), &small);
    write_file(&tree.join("big.bin"), &large);

    let out = dir.path().join("hashes.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    let turtle = read_turtle(&out);

    for (name, body, expected_form) in [
        ("small.log", &small, "aff4:zip_segment"),
        ("big.bin", &large, "aff4:ImageStream"),
    ] {
        let block = turtle
            .split("\n\n")
            .find(|b| {
                b.lines().next().is_some_and(|l| l.contains(name)) && b.contains("aff4:FileImage")
            })
            .unwrap_or_else(|| panic!("no FileImage subject for {name}:\n{turtle}"));

        assert!(
            block.contains(expected_form),
            "{name} must take the {expected_form} path for this test to mean \
             anything:\n{block}"
        );

        // The digests must equal a linear hash of the original bytes.
        let digest = aff4tools::hash::digest_of(&aff4tools::model::HashAlgorithm::Md5, body)
            .expect("MD5 is always available");
        let md5 = digest.hex();
        assert!(
            block.contains(&format!("\"{md5}\"^^aff4:MD5")),
            "{name} must record the linear MD5 of its own bytes ({md5}):\n{block}"
        );
        assert!(
            block.contains("^^aff4:SHA1"),
            "{name} must record a SHA-1 as well (§3.7 pairs them):\n{block}"
        );
    }

    // Block hashes are additional, on their own subjects — never instead of the
    // file's own digest.
    for block in turtle.split("\n\n") {
        if block.contains("aff4:BlockHashes") {
            assert!(
                !block.contains("aff4:FileImage"),
                "block hashes belong on their own subject, not on the file:\n{block}"
            );
        }
    }
}

/// A directory's `aff4:child` edges are written once its contents are done.
///
/// The edge must never name a path that turned out to be skipped, so it can
/// only be written after the child's outcome is known. The recursion used to
/// carry that on the call stack; now the writer collects each directory's
/// acquired children and writes the edges when the directory closes.
#[test]
fn child_edges_survive_the_discovery_split() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    write_file(&tree.join("a.txt"), b"hello world\n");
    write_file(&tree.join("sub").join("c.txt"), b"nested\n");

    let out = dir.path().join("logical.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    let turtle = read_turtle(&out);

    // Two directories, so two subjects carry children: the root and `sub`.
    let edges = turtle.matches("aff4:child").count();
    assert!(
        edges >= 2,
        "the tree's containment edges must survive the split:\n{turtle}"
    );

    // And the enumeration model's root marker is still asserted.
    assert!(
        turtle.contains("filesystemRoot") || turtle.contains("aff4:filesystemRoot"),
        "the acquisition task must still name its root:\n{turtle}"
    );
}

/// A skipped path is never named by a `aff4:child` edge.
#[cfg(unix)]
#[test]
fn a_skipped_path_gets_no_child_edge() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_file(&tree.join("real.txt"), b"content\n");
    std::os::unix::fs::symlink(tree.join("real.txt"), tree.join("link.txt")).unwrap();

    let out = dir.path().join("logical.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert!(
        acquired
            .skipped
            .iter()
            .any(|(p, _)| p.ends_with("link.txt")),
        "the symlink must be reported as skipped"
    );

    let turtle = read_turtle(&out);
    assert!(
        !turtle.contains("link.txt"),
        "a skipped path must not appear in the graph at all:\n{turtle}"
    );
}

/// A file's recorded `aff4:size` is the length actually read, never the length
/// the metadata walk predicted.
///
/// The walk's figure is an estimate by the time the bytes are read — under
/// `--scan-first` the whole tree is inventoried before the container exists,
/// so on a live system a log file can grow in between. The digests and the
/// stored segment come from the read, so a predicted size would contradict
/// them, with nothing in the container saying which to believe.
#[test]
fn a_small_file_records_the_length_actually_read() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_file(&tree.join("a.txt"), b"hello world\n");

    let out = dir.path().join("logical.aff4");
    let locus = Locus::new(&out);
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create_logical(&out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    let acquired = acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &locus,
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert_eq!(
        acquired.bytes, 12,
        "the acquired byte count is the read length"
    );
    assert!(
        acquired.changed.is_empty(),
        "an unchanged file is not reported as changed: {:?}",
        acquired.changed
    );

    let turtle = read_turtle(&out);
    assert!(
        turtle.contains("\"12\"^^xsd:long"),
        "aff4:size must be the read length:\n{turtle}"
    );
}

/// The estimate must cover files stored as plain ZIP members, not only streams.
///
/// `estimate_work` counted `ImageStream` objects and skipped everything else,
/// but an AFF4-L container stores a small file as one ZIP segment, and
/// `verify_zip_segment_image` reads every byte of it. The meter therefore
/// measured a run against a total that omitted them: a 4.4 GiB logical
/// container announced 3.3 GiB and then read past its own total.
///
/// The corpus could not catch this — a container of only streamed files has
/// nothing segment-stored to omit — so the fixture mixes both storage forms
/// deliberately.
#[test]
fn the_estimate_covers_segment_stored_files() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // Incompressible, so stored size is a real cost rather than a rounding
    // artefact, and distinct per file so no dedupe collapses them.
    let mut total: u64 = 0;
    for i in 0..12_u8 {
        let body: Vec<u8> = (0..4096_u32)
            .map(|b| (b.wrapping_mul(2_654_435_761).wrapping_add(u32::from(i)) >> 13) as u8)
            .collect();
        write_file(&tree.join(format!("f{i}.bin")), &body);
        total += body.len() as u64;
    }

    let out = acquire_with(dir.path(), &tree, LogicalOptions::default());

    let mut container = Container::open(&out).unwrap();
    let estimate =
        aff4tools::estimate_work(&mut container, VerifyOptions { block_hashes: true }).unwrap();

    assert_eq!(
        estimate.bytes_to_read, total,
        "every acquired byte must be in the estimate, however it is stored"
    );

    // The estimate is what the meter measures against, so a run must not read
    // past it. This is the symptom the user saw, stated as an assertion.
    let mut delivered: u64 = 0;
    let mut seen: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut observe = |event: aff4tools::Progress<'_>| {
        if let aff4tools::Progress::Bytes { arn, done, .. } = event {
            let previous = seen.entry(arn.as_str().to_owned()).or_insert(0);
            delivered += done.saturating_sub(*previous);
            *previous = done;
        }
    };
    let mut container = Container::open(&out).unwrap();
    aff4tools::verify::verify_container_with_progress(
        &mut container,
        VerifyOptions { block_hashes: true },
        &mut observe,
    )
    .unwrap();

    assert!(
        delivered <= estimate.bytes_to_read,
        "the run read {delivered} bytes against an estimate of {}; a meter cannot \
         exceed its own total",
        estimate.bytes_to_read
    );
}

/// A logical container's verify report states the verdict without listing
/// every match.
///
/// The report this replaces printed one entry per digest: 138,179 files became
/// 1.25 million lines and 92 MB, in which the five actionable notes sat in the
/// last thousandth of the file. The counts must still reconcile — a summary
/// that loses a check is worse than a long report.
#[test]
fn a_logical_verify_collapses_matches_into_counts() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(src.join("b.txt"), vec![b'x'; 100]).unwrap();
    std::fs::write(src.join("sub/c.txt"), b"nested\n").unwrap();
    let container = dir.path().join("logical.aff4");

    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&src)
        .arg("--output")
        .arg(&container)
        .assert()
        .success();

    let assert = aff4tools().arg("verify").arg(&container).assert().success();
    let text = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // Three files, two algorithms each, counted rather than listed.
    assert!(
        text.contains("Matched (6)"),
        "the matches must be totalled:\n{text}"
    );
    assert!(
        text.contains("3  file digests (MD5)") && text.contains("3  file digests (SHA1)"),
        "each algorithm's matches must be counted:\n{text}"
    );

    // The digests themselves are gone from the default report — this is the
    // property the whole change exists for.
    assert!(
        !text.contains("b1946ac92492d2347c6235b4d2611184"),
        "a matching digest must not be printed by default:\n{text}"
    );
    assert!(
        text.contains("--full-listing"),
        "the report must say where the digests went:\n{text}"
    );

    // A report of a few lines, not a few hundred thousand.
    assert!(
        text.lines().count() < 30,
        "the collapsed report must stay short, got {} lines:\n{text}",
        text.lines().count()
    );
}

/// `--verbose` restores the per-check listing the default no longer prints.
#[test]
fn verbose_restores_the_full_listing() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"hello\n").unwrap();
    let container = dir.path().join("logical.aff4");

    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&src)
        .arg("--output")
        .arg(&container)
        .assert()
        .success();

    let assert = aff4tools()
        .args(["verify", "-v"])
        .arg(&container)
        .assert()
        .success();
    let text = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        text.contains("b1946ac92492d2347c6235b4d2611184"),
        "--verbose must print the recorded digest:\n{text}"
    );
    assert!(
        text.contains("computed:"),
        "--verbose must show the comparison was made:\n{text}"
    );
}

/// The TSV carries one row per file, with a column trio per algorithm.
///
/// Folders are excluded because they have no content to hash, and the volume
/// ARN is stated once rather than repeated on every row — on the container
/// that prompted this it was 18 MB of the same 45 bytes.
#[test]
fn the_digest_table_is_one_row_per_file() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(src.join("sub/c.txt"), b"nested\n").unwrap();
    let container = dir.path().join("logical.aff4");
    let table = dir.path().join("digests.tsv");

    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&src)
        .arg("--output")
        .arg(&container)
        .assert()
        .success();

    aff4tools()
        .arg("verify")
        .arg("--full-listing")
        .arg(&table)
        .arg(&container)
        .assert()
        .success();

    let tsv = std::fs::read_to_string(&table).unwrap();
    let lines: Vec<&str> = tsv.lines().collect();

    assert!(
        lines[0].starts_with("# volume\taff4://"),
        "the volume ARN must be stated once, not on every row:\n{tsv}"
    );
    assert_eq!(
        lines[1],
        "path\tsize\toutcome\tMD5_recorded\tMD5_computed\tMD5_outcome\t\
         SHA1_recorded\tSHA1_computed\tSHA1_outcome",
        "columns must be derived from the algorithms in use"
    );

    // Two files, and no row for either folder.
    let rows = &lines[2..];
    assert_eq!(rows.len(), 2, "one row per file, folders excluded:\n{tsv}");
    for row in rows {
        assert_eq!(
            row.split('\t').count(),
            9,
            "every row must have the full column count:\n{row}"
        );
        assert!(
            row.contains("\tMATCH\t"),
            "an intact file must record a match:\n{row}"
        );
    }
}

/// The table is created, never overwritten.
///
/// The same rule `info --full-listing` follows: a previous run's table is a
/// record the examiner may still need, and silently replacing it would destroy
/// evidence.
#[test]
fn the_digest_table_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"hello\n").unwrap();
    let container = dir.path().join("logical.aff4");
    let table = dir.path().join("digests.tsv");
    std::fs::write(&table, b"an earlier run\n").unwrap();

    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&src)
        .arg("--output")
        .arg(&container)
        .assert()
        .success();

    aff4tools()
        .arg("verify")
        .arg("--full-listing")
        .arg(&table)
        .arg(&container)
        .assert()
        .code(3);

    assert_eq!(
        std::fs::read_to_string(&table).unwrap(),
        "an earlier run\n",
        "the existing table must be left untouched"
    );
}
