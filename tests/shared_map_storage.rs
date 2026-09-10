//! The AFF4-L Standard v1.0-ALPHA §6.3 shared map storage band.
//!
//! A file between `ZIPSEGMENT_THRESHOLD` and `COMMONMAP_THRESHOLD` is stored as
//! a range of one `ImageStream` shared across the acquisition, addressed by a
//! map on the file's own subject. These tests cover the writer, and the reader
//! half is covered against independently built fixtures in `tests/coverage.rs`
//! and `tests/storage_forms.rs`.
//!
//! # Why the fixtures are large
//!
//! The band begins at 16 MiB and there is deliberately no flag to move it: the
//! thresholds are measured properties of the format, not knobs, so a test that
//! lowered them would exercise a configuration no container is ever written in.
//! The files here are therefore genuinely over the threshold, and made of
//! repeating bytes so they compress to almost nothing on disk.

// Integration tests build fixture trees in temp dirs, which needs the file
// constructors the library is denied. `tests/read_only_guard.rs` scans `src/`
// only, so this relaxation cannot reach library code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn aff4tools() -> Command {
    Command::cargo_bin("aff4tools").expect("the binary must build")
}

/// Just past `ZIPSEGMENT_THRESHOLD`, which is 16 MiB.
const IN_BAND: usize = 17 * 1024 * 1024;

/// A tree with two files in the map band and two well below it.
///
/// Two in the band, because one file cannot show that a second is packed after
/// it rather than each getting a stream of its own.
fn source_tree() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(&root).expect("the fixture tree");

    // Distinct content, so a test cannot pass by conflating the two files.
    std::fs::write(root.join("big-a.bin"), vec![0xA5u8; IN_BAND]).expect("a file");
    std::fs::write(root.join("big-b.bin"), vec![0x5Au8; IN_BAND]).expect("a file");
    std::fs::write(root.join("small.txt"), b"below the segment threshold\n").expect("a file");
    std::fs::write(root.join("tiny.txt"), b"x").expect("a file");

    (dir, root)
}

/// Acquire `root` into a new v2.1 container, returning its path.
fn acquire(root: &Path) -> (tempfile::TempDir, PathBuf) {
    let out = tempfile::tempdir().expect("a temp dir");
    let container = out.path().join("acquired.aff4l");
    aff4tools()
        .args(["acquire", "--logical"])
        .arg(root)
        .args(["--aff4l-v1.0", "--output"])
        .arg(&container)
        .assert()
        .success();
    (out, container)
}

/// Every member name in the container.
fn members(container: &Path) -> Vec<String> {
    let file = std::fs::File::open(container).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a readable ZIP");
    (0..zip.len())
        .map(|i| zip.by_index(i).expect("a member").name().to_owned())
        .collect()
}

/// One member's bytes.
fn member(container: &Path, name: &str) -> Vec<u8> {
    use std::io::Read as _;
    let file = std::fs::File::open(container).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a readable ZIP");
    let mut entry = zip.by_name(name).expect("the member exists");
    let mut out = Vec::new();
    entry.read_to_end(&mut out).expect("the member reads");
    out
}

// ---------------------------------------------------------------------------
// What the writer produces.
// ---------------------------------------------------------------------------

/// A file in the band gets the AFF4-L v1.0-ALPHA §6.3 type triple, not its own
/// `ImageStream`.
///
/// Design decision D6 chose the first of that clause's two forms: one subject
/// carrying both `aff4:Image` and `aff4:Map`. The alternative, a separate Map
/// subject reached by `aff4l:dataStream`, is read but never written.
#[test]
fn a_band_file_is_typed_both_image_and_map() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);
    let turtle = String::from_utf8(member(&container, "information.turtle")).expect("UTF-8");

    let subjects = turtle
        .matches("aff4:FileImage , aff4:Image , aff4:Map")
        .count();
    assert_eq!(
        subjects, 2,
        "both band files must carry the Map type on their own subject:\n{turtle}"
    );
}

/// Both band files share one stream rather than getting one each.
#[test]
fn band_files_share_a_single_stream() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);
    let names = members(&container);

    // Bevy members are named `<stream>/00000000`; the shared stream is the only
    // stream this acquisition writes, and its member prefix is `shared`.
    let bevies: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("shared/") && !n.contains('.'))
        .collect();
    assert!(
        !bevies.is_empty(),
        "the shared stream must hold bevies, got {names:?}"
    );

    // Each band file contributes a map, an idx, and a mapPath under its own ARN.
    let maps = names.iter().filter(|n| n.ends_with("/map")).count();
    assert_eq!(maps, 2, "one map per band file, got {names:?}");
}

/// Each band file's map is a single entry covering the whole file.
///
/// One entry per file is what separates this form from AFF4-L 2019 §4
/// deduplication, where a file is reassembled from scattered chunks and needs
/// an entry each. It is also why the form's metadata cost stays flat as files
/// grow.
#[test]
fn each_band_file_has_exactly_one_map_entry() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);

    for name in members(&container).iter().filter(|n| n.ends_with("/map")) {
        let bytes = member(&container, name);
        assert_eq!(
            bytes.len(),
            28,
            "AFF4 Standard v1.0a §4 map entries are 28 bytes, and one file is one entry: {name}"
        );
        let length = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
        assert_eq!(
            length, IN_BAND as u64,
            "the entry must cover the whole file: {name}"
        );
    }
}

/// Files are packed end to end, with the second starting where the first ended.
///
/// Padding each file to a chunk or bevy boundary would reintroduce exactly the
/// rounding waste this storage form exists to avoid.
#[test]
fn the_second_band_file_starts_where_the_first_ended() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);

    let mut offsets: Vec<u64> = members(&container)
        .iter()
        .filter(|n| n.ends_with("/map"))
        .map(|n| {
            let bytes = member(&container, n);
            u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes"))
        })
        .collect();
    offsets.sort_unstable();

    assert_eq!(offsets.len(), 2);
    assert_eq!(offsets[0], 0, "the first file starts the stream");
    assert_eq!(
        offsets[1], IN_BAND as u64,
        "the second must follow immediately, with no padding between them"
    );
}

/// Each band file's `idx` names the shared stream, and only it.
#[test]
fn a_band_files_idx_names_only_the_shared_stream() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);

    for name in members(&container).iter().filter(|n| n.ends_with("/idx")) {
        let text = String::from_utf8(member(&container, name)).expect("UTF-8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "one target, got {lines:?} in {name}");
        assert!(
            lines[0].ends_with("/shared"),
            "the target must be the shared stream, got {}",
            lines[0]
        );
    }
}

/// Small files are unaffected: they stay ZIP segments.
///
/// The band is a band, not a new default. A regression that sent every file
/// through the map would still pass every test above.
#[test]
fn files_below_the_threshold_are_still_segments() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);
    let names = members(&container);

    // A ZIP-segment file is one member named by its ARN alone, with no map
    // sibling under it. The ARN itself contains slashes, so what distinguishes
    // a segment is that nothing follows the GUID.
    let segments = names
        .iter()
        .filter(|n| {
            n.strip_prefix("aff4://")
                .is_some_and(|rest| !rest.contains('/'))
        })
        .count();
    assert_eq!(
        segments, 2,
        "the two small files must remain plain segments, got {names:?}"
    );
}

// ---------------------------------------------------------------------------
// What the readers make of it.
// ---------------------------------------------------------------------------

/// The container this writes reports no deviations.
///
/// Every writing path but `--deduplicate` must reach zero, and the map band is
/// no exception: unlike AFF4-L 2019 §4 deduplication it uses only AFF4 Standard
/// v1.0a constructs, so there is nothing for it to depart from.
#[test]
fn a_shared_map_container_conforms() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);

    // Not `--strict`: that also raises the exit code for unevaluated rules,
    // of which this project still has many by design. What is asserted here is
    // that the map band contributes no *deviation*.
    let assert = aff4tools().arg("conformance").arg(&container).assert();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        out.contains("No deviations found"),
        "the map band must conform exactly:\n{out}"
    );
}

/// `verify` recomputes every band file's digest through its map.
#[test]
fn verify_checks_every_band_file() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);

    let assert = aff4tools().arg("verify").arg(&container).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // Every check attempted completed, and none was declined. Asserted as a
    // property rather than as a digest count: how many digests a container
    // carries depends on the `--hash` default and on whether block hashing is
    // on, neither of which this test is about.
    assert!(
        !out.contains("declined"),
        "no digest may be declined:\n{out}"
    );
    assert!(
        !out.contains("could not be resolved"),
        "no map may fail to resolve:\n{out}"
    );

    // Every check attempted completed. A map-backed file whose bytes could not
    // be read through its map would appear as an attempted-but-incomplete
    // check, which is what this pins.
    //
    // Deliberately not a digest count: each band file also carries the four
    // AFF4 Standard v1.0a §6.2 map segment digests, so the total moves with
    // how many files land in the map band rather than with how many files
    // exist.
    let results = out
        .lines()
        .find(|l| l.contains("checks attempted"))
        .unwrap_or_else(|| panic!("verify must report its totals:\n{out}"));
    let numbers: Vec<u32> = results
        .split_whitespace()
        .filter_map(|w| w.trim_end_matches(';').parse().ok())
        .collect();
    assert_eq!(
        numbers.first(),
        numbers.get(1),
        "every attempted check must complete: {results}"
    );
    assert!(
        out.contains("file digests ("),
        "each file's content digests must be reported:\n{out}"
    );
}

/// `export` reproduces every file's bytes exactly, band files included.
///
/// This is the test that matters most, and the one that caught the real defect:
/// `verify` resolved these files through their maps while `export` dispatched
/// only on `ImageStream` and looked for a ZIP member that does not exist. Both
/// readers must agree about where a file's bytes are, or one of them is
/// reporting on content the other cannot extract.
#[test]
fn export_reproduces_every_file_byte_for_byte() {
    let (src, root) = source_tree();
    let (_out, container) = acquire(&root);

    // `export` refuses to write into a directory that already exists, so name
    // one inside the temp dir rather than handing it the temp dir itself.
    let dest = tempfile::tempdir().expect("a temp dir");
    let target = dest.path().join("extracted");
    aff4tools()
        .args(["export"])
        .arg(&container)
        .args(["--logical"])
        .arg(&target)
        .assert()
        .success();

    // Files are written under their original absolute path, rebased onto the
    // destination.
    let rebased = target.join(
        root.strip_prefix("/")
            .expect("the fixture path is absolute"),
    );

    for name in ["big-a.bin", "big-b.bin", "small.txt", "tiny.txt"] {
        let original = std::fs::read(root.join(name)).expect("the source file");
        let extracted = std::fs::read(rebased.join(name))
            .unwrap_or_else(|e| panic!("{name} was not extracted: {e}"));
        assert_eq!(
            original.len(),
            extracted.len(),
            "{name} came back a different length"
        );
        assert!(original == extracted, "{name} did not round-trip");
    }
    drop(src);
}

/// A clean verification carries no star banner and no undigested-stream claim.
///
/// Two false positives, both introduced while making failures louder, and both
/// about the same confusion: whether a *stream* names a digest is not the same
/// question as whether its *bytes* are protected.
///
/// The AFF4-L v1.0-ALPHA §6.3 shared stream deliberately records no
/// `aff4:hash`. Its bytes belong to the files packed into it, each carrying a
/// content digest and the four AFF4 Standard v1.0a §6.2 map digests. A run
/// reported "2.0 GiB of stored data carries no recomputable digest" about a
/// stream whose files were covered by 165 digests, every one matched.
///
/// **The rule**: a star banner appears only when a recorded digest failed, or
/// when recorded data was not covered by a digest that ran. A star on a clean
/// result trains an examiner to ignore stars.
#[test]
fn a_clean_verification_raises_no_alarm() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);

    let assert = aff4tools().arg("verify").arg(&container).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        !out.contains("***"),
        "a fully matched verification must raise no star banner:\n{out}"
    );
    assert!(
        !out.contains("no recomputable digest"),
        "the shared stream's bytes are covered by its files' digests:\n{out}"
    );
    assert!(
        !out.contains("could not be verified"),
        "nothing went unverified:\n{out}"
    );
}

/// Every map-band file's content digest and map digests are recomputed.
///
/// The positive half of the test above: the shared stream is not merely
/// unaccused, it is genuinely covered. Two files in the band, each carrying one
/// content digest plus the four AFF4 Standard v1.0a §6.2 map digests.
#[test]
fn the_shared_streams_bytes_are_covered_by_its_files() {
    let (_src, root) = source_tree();
    let (_out, container) = acquire(&root);

    let assert = aff4tools().arg("verify").arg(&container).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // The SHA-512 line carries two different things, and the count is their
    // sum: four map segment digests for each of the two band files, plus one
    // content digest for each of the four files, since the default `--hash`
    // selection includes SHA-512.
    let line = out
        .lines()
        .find(|l| l.contains("file digests (SHA512)"))
        .unwrap_or_else(|| panic!("the map digests must be reported:\n{out}"));
    let count: usize = line
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert_eq!(
        count,
        2 * 4 + 4,
        "eight map digests over two band files, plus four content digests: {line}"
    );
}
