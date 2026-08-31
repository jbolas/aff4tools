//! The metadata scanner: the queue protocol, the cost model, and degradation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use aff4tools::write::scan::{SCAN_QUEUE_CAPACITY, ScanItem, cost_of, spawn};

fn build_tree(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(root.join("b.txt"), b"world\n").unwrap();
    std::fs::write(root.join("sub").join("c.txt"), b"nested\n").unwrap();
}

/// The scanner reports every file in the tree, with its size.
#[test]
fn the_scanner_finds_every_file() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    build_tree(&tree);

    let scanner = spawn(vec![tree.clone()], SCAN_QUEUE_CAPACITY);
    let mut names = Vec::new();
    for item in scanner.items.iter() {
        if let ScanItem::File { path, size } = item {
            assert!(size > 0, "a fixture file must have a size");
            names.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    scanner.join();

    names.sort();
    assert_eq!(names, vec!["a.txt", "b.txt", "c.txt"]);
}

/// Every directory's items are bracketed by `Dir` and `DirEnd`.
///
/// The writer needs that bracket to know when a directory is finished, which
/// is when its `aff4:child` edges may be written.
#[test]
fn directories_are_bracketed() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    build_tree(&tree);

    let scanner = spawn(vec![tree.clone()], SCAN_QUEUE_CAPACITY);
    let items: Vec<ScanItem> = scanner.items.iter().collect();
    scanner.join();

    let dirs = items
        .iter()
        .filter(|i| matches!(i, ScanItem::Dir { .. }))
        .count();
    let ends = items
        .iter()
        .filter(|i| matches!(i, ScanItem::DirEnd))
        .count();
    assert_eq!(dirs, ends, "every Dir must be closed by a DirEnd");
    assert_eq!(dirs, 2, "the root and `sub` are both directories");

    // Depth never goes negative: a DirEnd never precedes its Dir.
    let mut depth = 0i32;
    for item in &items {
        match item {
            ScanItem::Dir { .. } => depth += 1,
            ScanItem::DirEnd => {
                depth -= 1;
                assert!(depth >= 0, "a DirEnd arrived before its Dir");
            }
            _ => {}
        }
    }
    assert_eq!(depth, 0, "every directory must be closed");
}

/// The totals are marked complete once the walk finishes.
#[test]
fn totals_are_marked_complete_when_the_walk_ends() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    build_tree(&tree);

    let scanner = spawn(vec![tree.clone()], SCAN_QUEUE_CAPACITY);
    let totals = std::sync::Arc::clone(&scanner.totals);
    for _ in scanner.items.iter() {}
    scanner.join();

    let (files, cost, complete) = totals.snapshot();
    assert!(complete, "the scan must be marked complete once it ends");
    assert_eq!(files, 3, "three files in the fixture tree");
    assert!(cost > 0, "cost must accumulate");
}

/// A small file costs more than its bytes: the per-file overhead is real.
///
/// At or below `MAX_SEGMENT_RESIDENT_SIZE` a file is stored as a ZIP segment,
/// so a tree of many tiny files carries a cost its byte count does not show.
#[test]
fn small_files_carry_a_per_file_overhead() {
    let small = cost_of(10);
    assert!(small > 10, "a 10-byte file must cost more than 10: {small}");

    let large = cost_of(64 * 1024 * 1024);
    assert_eq!(
        large,
        64 * 1024 * 1024,
        "a large file costs its bytes, with no segment overhead"
    );
}

/// An unreadable directory is reported, and the walk continues.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_reported_not_fatal() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    build_tree(&tree);
    let locked = tree.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("hidden.txt"), b"secret\n").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let scanner = spawn(vec![tree.clone()], SCAN_QUEUE_CAPACITY);
    let items: Vec<ScanItem> = scanner.items.iter().collect();
    scanner.join();

    // Restore so the tempdir can be cleaned up.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

    let files = items
        .iter()
        .filter(|i| matches!(i, ScanItem::File { .. }))
        .count();
    assert_eq!(files, 3, "the readable files must still be found");
    assert!(
        items.iter().any(|i| matches!(i, ScanItem::Skipped { .. })),
        "the unreadable directory must be reported"
    );
}

/// A consumer that stops reading does not wedge the scanner.
///
/// The channel bound is the only limit on run-ahead; dropping the receiver
/// must let the scanner thread exit rather than block forever.
#[test]
fn dropping_the_receiver_lets_the_scanner_exit() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for i in 0..500 {
        std::fs::write(tree.join(format!("f{i}.txt")), b"x").unwrap();
    }

    // A capacity of 1 guarantees the scanner blocks on send almost at once.
    let scanner = spawn(vec![tree.clone()], 1);
    // Drops the receiver, then joins: the scanner must return from its blocked
    // `send` rather than park forever. A hang here fails the test by timeout.
    scanner.drop_queue_and_join();
}

/// A scanned acquisition and an inline one produce the same container shape.
///
/// The scanner changes when paths are discovered, never what is written.
#[test]
fn scanned_and_inline_acquisitions_agree() {
    use aff4tools::Locus;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::logical::{LogicalOptions, acquire_logical, acquire_logical_scanned};

    fn shape(turtle: &str) -> Vec<String> {
        let mut out: Vec<String> = turtle
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("aff4:") || l.starts_with("a "))
            .map(|l| l.split_whitespace().next().unwrap_or("").to_owned())
            .collect();
        out.sort();
        out
    }

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

    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    build_tree(&tree);

    let inline_out = dir.path().join("inline.aff4");
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create_logical(&inline_out, &registry).unwrap();
    let mut noop = |_: &aff4tools::write::logical::LogicalAcquisition| {};
    acquire_logical(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &Locus::new(&inline_out),
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    let scanned_out = dir.path().join("scanned.aff4");
    let mut registry2 = SourceRegistry::new();
    registry2.register(&tree).unwrap();
    let mut writer2 = ContainerWriter::create_logical(&scanned_out, &registry2).unwrap();
    let mut noop2 =
        |_: &aff4tools::write::logical::LogicalAcquisition, _: Option<(u64, u64, bool)>| {};
    acquire_logical_scanned(
        &mut writer2,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &Locus::new(&scanned_out),
        &mut noop2,
    )
    .unwrap();
    writer2.finish().unwrap();

    assert_eq!(
        shape(&read_turtle(&inline_out)),
        shape(&read_turtle(&scanned_out)),
        "the scanner must not change what is written"
    );
}

/// The progress callback is told the scan completed.
#[test]
fn the_callback_sees_the_scan_complete() {
    use aff4tools::Locus;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::logical::{LogicalOptions, acquire_logical_scanned};

    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    build_tree(&tree);

    let out = dir.path().join("scanned.aff4");
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create_logical(&out, &registry).unwrap();

    let mut saw_estimate = false;
    {
        let mut observe = |_: &aff4tools::write::logical::LogicalAcquisition,
                           totals: Option<(u64, u64, bool)>| {
            if let Some((files, cost, _)) = totals
                && files > 0
                && cost > 0
            {
                saw_estimate = true;
            }
        };
        acquire_logical_scanned(
            &mut writer,
            std::slice::from_ref(&tree),
            LogicalOptions::default(),
            &Locus::new(&out),
            &mut observe,
        )
        .unwrap();
    }
    writer.finish().unwrap();

    assert!(
        saw_estimate,
        "the callback must receive the scanner's running totals"
    );
}

/// A normal, complete scanned acquisition reports nothing as skipped.
///
/// `acquire_from_items` drains any directory left open when the item stream
/// ends and reports each one. That drain exists for a truncated stream; a
/// balanced one must never reach it, or every clean run would report a
/// skipped path and exit non-zero under `--strict`.
#[test]
fn a_complete_scanned_acquisition_skips_nothing() {
    use aff4tools::Locus;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::logical::{LogicalOptions, acquire_logical_scanned};

    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    build_tree(&tree);
    std::fs::create_dir_all(tree.join("sub").join("deeper")).unwrap();
    std::fs::write(tree.join("sub").join("deeper").join("d.txt"), b"deep\n").unwrap();

    let out = dir.path().join("clean.aff4");
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create_logical(&out, &registry).unwrap();
    let mut noop =
        |_: &aff4tools::write::logical::LogicalAcquisition, _: Option<(u64, u64, bool)>| {};
    let acquired = acquire_logical_scanned(
        &mut writer,
        std::slice::from_ref(&tree),
        LogicalOptions::default(),
        &Locus::new(&out),
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert!(
        acquired.skipped.is_empty(),
        "a complete acquisition must skip nothing, got {:?}",
        acquired.skipped
    );
    assert_eq!(acquired.files, 4, "every file in the tree must be acquired");
}

/// Several roots are all acquired, and each is a filesystem root.
///
/// The scanned path counts completed root subtrees so a failed scan can be
/// finished off inline from the right place. That counting must not disturb a
/// sound multi-root run.
#[test]
fn a_scanned_acquisition_handles_several_roots() {
    use aff4tools::Locus;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::logical::{LogicalOptions, acquire_logical_scanned};

    let dir = tempfile::tempdir().unwrap();
    let one = dir.path().join("one");
    let two = dir.path().join("two");
    build_tree(&one);
    build_tree(&two);
    let loose = dir.path().join("loose.txt");
    std::fs::write(&loose, b"loose\n").unwrap();

    let out = dir.path().join("many.aff4");
    let mut registry = SourceRegistry::new();
    registry.register(&one).unwrap();
    registry.register(&two).unwrap();
    registry.register(&loose).unwrap();
    let mut writer = ContainerWriter::create_logical(&out, &registry).unwrap();
    let mut noop =
        |_: &aff4tools::write::logical::LogicalAcquisition, _: Option<(u64, u64, bool)>| {};
    let roots = vec![one, two, loose];
    let acquired = acquire_logical_scanned(
        &mut writer,
        &roots,
        LogicalOptions::default(),
        &Locus::new(&out),
        &mut noop,
    )
    .unwrap();
    writer.finish().unwrap();

    assert!(acquired.skipped.is_empty(), "{:?}", acquired.skipped);
    assert_eq!(
        acquired.files, 7,
        "three files per tree, plus the loose one"
    );
    assert_eq!(acquired.folders, 4, "two roots and two subdirectories");
}

/// Discovery runs ahead of acquisition rather than finishing before it starts.
///
/// The whole point of scanning on a thread is that the two overlap. If the
/// queue were drained into memory before any file was written, the scan would
/// already be complete at the very first progress callback, and the display
/// would never show its liveness form. This asserts the opposite: on a tree
/// large enough to outrun one queue-load, the first callback arrives while the
/// scan is still running.
#[test]
fn discovery_overlaps_acquisition() {
    use aff4tools::Locus;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::logical::{LogicalOptions, acquire_logical_scanned};

    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("wide");
    std::fs::create_dir_all(&tree).unwrap();
    // More entries than the queue holds, so the scanner cannot have finished
    // before the writer has taken anything off the front of it.
    for i in 0..(SCAN_QUEUE_CAPACITY * 2) {
        std::fs::write(tree.join(format!("f{i:06}.txt")), b"x").unwrap();
    }

    let out = dir.path().join("wide.aff4");
    let mut registry = SourceRegistry::new();
    registry.register(&tree).unwrap();
    let mut writer = ContainerWriter::create_logical(&out, &registry).unwrap();

    let mut first: Option<(u64, u64, bool)> = None;
    {
        let mut observe = |_: &aff4tools::write::logical::LogicalAcquisition,
                           totals: Option<(u64, u64, bool)>| {
            if first.is_none() {
                first = totals;
            }
        };
        acquire_logical_scanned(
            &mut writer,
            std::slice::from_ref(&tree),
            LogicalOptions::default(),
            &Locus::new(&out),
            &mut observe,
        )
        .unwrap();
    }
    writer.finish().unwrap();

    let (_, _, complete) = first.expect("the first file must report totals");
    assert!(
        !complete,
        "the scan must still be running when the first file is acquired; a \
         completed scan there means the queue was drained before acquiring"
    );
}
