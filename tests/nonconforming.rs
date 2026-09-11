//! The `nonconforming` feature's capabilities.
//!
//! Built only under `--features nonconforming`, so the default suite never
//! compiles this file. Used for reference image creation, not everyday use.
//!
//! AFF4-L Standard v1.0-ALPHA governs storage forms. **Every bare section number below cites that standard.**

#![cfg(feature = "nonconforming")]
// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn aff4tools() -> Command {
    Command::cargo_bin("aff4tools").expect("the binary must build")
}

/// Three small files, all far below every size threshold.
///
/// Size must not be able to explain the storage form any of them takes, so
/// only the override can be responsible for it.
fn source_tree() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(&root).expect("the fixture tree");
    std::fs::write(root.join("alpha.txt"), b"alpha contents\n").expect("a file");
    std::fs::write(root.join("beta.txt"), b"beta contents\n").expect("a file");
    std::fs::write(root.join("gamma.txt"), b"gamma contents\n").expect("a file");
    (dir, root)
}

/// Acquire `root` as a v2.1 container, with extra arguments appended.
fn acquire(root: &Path, extra: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let out = tempfile::tempdir().expect("a temp dir");
    let container = out.path().join("evidence.aff4l");
    let mut command = aff4tools();
    command
        .args(["acquire", "--logical"])
        .arg(root)
        .arg("--output")
        .arg(&container)
        .arg("--aff4l-v1.0");
    for arg in extra {
        command.arg(arg);
    }
    command.assert().success();
    (out, container)
}

/// Acquire the standard tree under one forced storage form.
fn acquire_forced(form: &str) -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
    let (src, root) = source_tree();
    let (out, container) = acquire(&root, &["--storage-form", form]);
    (src, out, container)
}

/// The container's `information.turtle`, as text.
fn turtle(path: &Path) -> String {
    let file = std::fs::File::open(path).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a ZIP archive");
    let mut body = String::new();
    std::io::Read::read_to_string(
        &mut zip.by_name("information.turtle").expect("the metadata"),
        &mut body,
    )
    .expect("the metadata reads");
    body
}

/// Every member name in the container.
fn members(path: &Path) -> Vec<String> {
    let file = std::fs::File::open(path).expect("the container opens");
    let mut zip = zip::ZipArchive::new(file).expect("a ZIP archive");
    (0..zip.len())
        .map(|i| zip.by_index(i).expect("a member").name().to_owned())
        .collect()
}

#[test]
fn the_override_forces_zip_segments() {
    let (_src, _out, path) = acquire_forced("segment");
    let body = turtle(&path);
    let typed = body.matches("aff4:ZipSegment").count();
    assert_eq!(
        typed, 3,
        "expected three files typed as ZIP segments (§6.1), got {typed} in:\n{body}"
    );
}

#[test]
fn the_override_forces_a_shared_map_on_files_far_below_its_threshold() {
    // §6.3, the band: several files' Maps over one `ImageStream`. Size-based
    // selection would send files this small to §6.1 segments, so the three
    // Map types here can only come from the override.
    let (_src, _out, path) = acquire_forced("shared-map");
    let body = turtle(&path);
    let maps = body.matches("aff4:Map").count();
    assert_eq!(
        maps, 3,
        "expected three files typed as maps, got {maps} in:\n{body}"
    );

    // One stream, shared: the band's defining property. Excludes the bevy's
    // `.index` sibling, which also matches on the bevy number and would
    // otherwise double-count one shared stream as two.
    let bevies = members(&path)
        .into_iter()
        .filter(|m| m.contains("/00000000") && !m.ends_with(".index"))
        .count();
    assert_eq!(
        bevies, 1,
        "expected one shared bevy across three files, got {bevies}"
    );
}

#[test]
fn the_override_forces_an_own_image_stream_on_small_files() {
    // §6.4, a bare `ImageStream` with no Map.
    let (_src, _out, path) = acquire_forced("imagestream");
    let body = turtle(&path);
    let streams = body.matches("aff4:ImageStream").count();
    assert!(
        streams >= 3,
        "expected at least three image streams, got {streams} in:\n{body}"
    );
    assert!(
        !body.contains("aff4:Map"),
        "§6.4 storage wrote a Map:\n{body}"
    );
}

#[test]
fn an_own_map_carries_the_block_map_hash_a_shared_map_cannot() {
    let (_src, _out, path) = acquire_forced("own-map");
    let body = turtle(&path);

    let maps = body.matches("aff4:Map").count();
    assert_eq!(
        maps, 3,
        "expected three files typed as maps, got {maps} in:\n{body}"
    );

    // One stream per file, unlike the band's one for all three. This is the
    // whole difference between the two §6.3 forms. Only the bevy itself is
    // counted: its `.index` and `.blockHash.*` siblings share the bevy number
    // and would otherwise count one stream several times.
    let bevies = members(&path)
        .into_iter()
        .filter(|m| m.ends_with("/00000000"))
        .count();
    assert_eq!(bevies, 3, "expected one bevy per file, got {bevies}");

    // §6.3.1 requires a block map hash on every map, in either of two
    // spellings. This form exists so that requirement can be met: each stream
    // belongs to one file, so its block hashes describe that file's bytes and
    // nobody else's.
    let digests = body.matches("blockMapHashSHA512").count();
    assert_eq!(
        digests, 3,
        "expected one block map digest per file, got {digests} in:\n{body}"
    );
}

#[test]
fn a_shared_map_still_carries_no_block_map_hash() {
    // The companion to the test above, and the reason both forms exist. A map
    // over a shared stream cannot carry the digest: the stream's block hashes
    // describe every file in the band, so a per-file value composed from them
    // would be identical across the band while appearing to attest each file.
    // Whether §6.3.1's MUST reaches such a map is an open question for the
    // standard's author, and this asserts the current answer rather than
    // endorsing it.
    let (_src, _out, path) = acquire_forced("shared-map");
    let body = turtle(&path);
    assert!(
        !body.contains("blockMapHash"),
        "a shared-stream map recorded a block map digest:\n{body}"
    );
}

#[test]
fn an_own_map_container_verifies_and_reports_no_deviation() {
    let (_src, _out, path) = acquire_forced("own-map");

    // Every recorded digest recomputes, including the block map digests this
    // form exists to write.
    aff4tools().arg("verify").arg(&path).assert().success();

    // And the container departs from nothing. `map.aff4l` ships in the
    // permanent reference set, so an unmet requirement here would be an unmet
    // requirement in a proposed reference image.
    //
    // Read from the JSON report's deviation list rather than from `--strict`'s
    // exit code or the report's own `conformant` flag. Both of those also fail
    // on a MUST the rule registry has not yet been taught to evaluate, and this
    // build carries several of those, so every container aff4tools writes fails
    // them whatever it holds. An empty deviation list is the narrower question
    // this form has to answer: nothing observed departs from the standard.
    let report = aff4tools()
        .arg("conformance")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .assert()
        .success();
    let body = String::from_utf8(report.get_output().stdout.clone()).expect("UTF-8 JSON");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("a JSON report");
    let container = &parsed["containers"][0];
    assert_eq!(
        container["deviations"].as_array().map(Vec::len),
        Some(0),
        "the container departed from the standard:\n{body}"
    );
}

#[test]
fn the_indirect_form_puts_the_map_on_a_separate_subject() {
    let (_src, root) = source_tree();
    let (_out, path) = acquire(
        &root,
        &["--storage-form", "own-map", "--datastream-indirect"],
    );
    let body = turtle(&path);

    // The FileImage names a Map rather than being one: `aff4l:dataStream` with
    // an IRI object, which is the second of §6.3's two forms. The turtle
    // writer column-aligns objects (`OBJECT_COLUMN`), so the gap after the
    // predicate is checked loosely rather than as an exact two spaces.
    assert!(
        body.contains("aff4l:dataStream")
            && body
                .lines()
                .any(|line| line.trim_start().starts_with("aff4l:dataStream")
                    && line.contains("<aff4://")),
        "no indirect dataStream reference in:\n{body}"
    );

    // Six subjects rather than three: each file and each Map.
    let maps = body.matches("aff4:Map").count();
    assert_eq!(
        maps, 3,
        "expected three Map subjects, got {maps} in:\n{body}"
    );

    // The writer records the block map digest under both spellings, on two
    // different subjects: `aff4:hash "..."^^aff4:blockMapHashSHA512` on the
    // FileImage (the spelling AFF4 Standard v1.0a §6.2 assigns to the Image),
    // and bare `aff4:blockMapHash "..."^^aff4:SHA512` on the Map (the
    // placement AFF4-L v1.0-ALPHA §6.3.1 requires). Writing both is how the
    // writer avoids choosing between the two documents rather than how it
    // settles their disagreement. This form only makes the two subjects
    // distinct; it does not move which spelling lands where. The count below
    // is of the SHA512-suffixed spelling, so it counts occurrences on the
    // FileImage subject, one per file, not on the Map.
    let digests = body.matches("blockMapHashSHA512").count();
    assert_eq!(
        digests, 3,
        "expected one blockMapHashSHA512-suffixed digest per file, got {digests} in:\n{body}"
    );
}

#[test]
fn the_indirect_form_verifies() {
    // A reference image exists to pose one question. A container that this
    // tool's own `verify` cannot resolve poses a second, unintended one, so the
    // indirect form is held to the same bar as the direct form: every recorded
    // digest recomputes.
    //
    // The Map the indirect form mints is a subject of its own, and a Map
    // declares its extent through `aff4:size` (AFF4 Standard v1.0a §4).
    // Without that triple on the Map itself the map resolves as malformed and
    // its digests go unrecomputed, while `acquire` still exits 0.
    let (_src, root) = source_tree();
    let (_out, path) = acquire(
        &root,
        &["--storage-form", "own-map", "--datastream-indirect"],
    );

    let verified = aff4tools().arg("verify").arg(&path).assert().success();
    let report = String::from_utf8(verified.get_output().stdout.clone()).expect("UTF-8 output");
    assert!(
        !report.contains("were not recomputed") && !report.contains("NOT fully verified"),
        "the indirect form wrote a container verify could not resolve:\n{report}"
    );
}

#[test]
fn the_direct_form_is_still_the_default() {
    // §6.3's first form, and what `map.aff4l` in the permanent set carries.
    // The indirect form must be reachable only when asked for.
    let (_src, _out, path) = acquire_forced("own-map");
    let body = turtle(&path);
    assert!(
        !body
            .lines()
            .any(|line| line.trim_start().starts_with("aff4l:dataStream")
                && line.contains("<aff4://")),
        "the direct form emitted an indirect reference:\n{body}"
    );
}

/// Every `FileImage` subject's turtle block that carries a resident
/// `aff4l:dataStream` literal.
///
/// The turtle writer separates subjects with a blank line and opens each
/// block with the subject's own `a <types> ;` line, so a block is delimited
/// by splitting on `"\n\n"` and its type line is its second line.
///
/// **Scoped to `FileImage` subjects deliberately.** An extended attribute is
/// a substream, and AFF4-L v1.0-ALPHA §6.2's ceiling stores it resident under
/// the same rule a primary stream uses — `write_extended_attributes` gives it
/// the identical `aff4l:dataStream` base64 shape. macOS applies a
/// `com.apple.provenance` extended attribute to every file it creates, so a
/// fixture tree acquired on macOS always carries one `aff4l:FileExtendedAttribute`
/// subject with a resident literal per file, on top of whatever the primary
/// stream did. Counting `^^xsd:base64Binary` across the whole document
/// conflates the two and cannot tell a resident primary stream from a
/// resident attribute; scoping to subjects typed `aff4:FileImage` is what
/// discriminates them. The reference-image generator hits the same xattr on
/// any macOS source tree, so this distinction matters there too, not only in
/// this test.
fn resident_file_image_blocks(body: &str) -> Vec<&str> {
    body.split("\n\n")
        .filter(|block| {
            block.lines().any(|l| l.contains("aff4:FileImage"))
                && block.contains("aff4l:dataStream")
                && block.contains("^^xsd:base64Binary")
        })
        .collect()
}

#[test]
fn a_primary_stream_can_be_forced_resident() {
    // §6.2's second example does exactly this: a `FileImage` carrying
    // `aff4l:dataStream` with a base64 literal. This writer never chooses it,
    // on measured grounds recorded in `choose_storage` — an in-metadata
    // subject costs more turtle than a ZIP segment subject before it holds a
    // byte. The standard permits it, so a reference image must be able to
    // show it.
    let (_src, _out, path) = acquire_forced("resident");
    let body = turtle(&path);

    let resident_files = resident_file_image_blocks(&body).len();
    assert_eq!(
        resident_files, 3,
        "expected one resident FileImage per file, got {resident_files} in:\n{body}"
    );
}

#[test]
fn a_forced_resident_stream_still_refuses_to_exceed_the_ceiling() {
    // §6.2's MUST NOT is a requirement, not a default: a stream above 1 KiB
    // may not be stored in the metadata whatever was asked for. The override
    // moves this writer's *choices*, never a clause's MUST NOT.
    //
    // Asserted on `FileImage` subjects only, not on the document as a whole:
    // this fixture's one file still carries a `com.apple.provenance` extended
    // attribute on macOS, which is legitimately resident at 11 bytes under
    // the same §6.2 ceiling applied to a substream. A document-wide search
    // for `^^xsd:base64Binary` would find that attribute's literal and fail
    // on every macOS host regardless of whether the primary stream — the
    // thing this test is actually about — obeyed the ceiling.
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("evidence");
    std::fs::create_dir_all(&root).expect("the fixture tree");
    std::fs::write(root.join("big.bin"), vec![b'x'; 4096]).expect("a file");

    let (_out, path) = acquire(&root, &["--storage-form", "resident"]);
    let body = turtle(&path);
    let resident_files = resident_file_image_blocks(&body);
    assert!(
        resident_files.is_empty(),
        "a 4 KiB stream was stored in the metadata, above the §6.2 ceiling:\n{resident_files:?}"
    );
}

#[test]
fn the_alternative_namespace_is_written_when_asked() {
    let (_src, root) = source_tree();

    // Not the shared `acquire` helper: that asserts success, but this
    // container is now expected to carry deviations (see below), and
    // `acquire` itself exits non-zero — `EXIT_STRICT_DEVIATION` — whenever
    // the container it just wrote has any, independent of `--strict`.
    let out = tempfile::tempdir().expect("a temp dir");
    let path = out.path().join("evidence.aff4l");
    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&root)
        .arg("--output")
        .arg(&path)
        .arg("--aff4l-v1.0")
        .arg("--namespace-https")
        .assert()
        .code(7);
    let body = turtle(&path);

    assert!(
        body.contains("<https://aff4.org/Schema/2022/#>"),
        "the https namespace was not bound in:\n{body}"
    );
    assert!(
        !body.contains("<http://aff4.org/Schema/2022/#>"),
        "both namespaces appear, which would make the container ambiguous:\n{body}"
    );

    // AFF4-L v1.0-ALPHA §4.1 assigns the `aff4l` vocabulary the `http://`
    // namespace; every term this container writes under `https://` therefore
    // departs from the standard, and `conformance` must say so. Asserting
    // "no deviations" here would assert the false negative this test exists
    // to catch: `is_known_namespace` has to recognize the `https://` spelling
    // as one of ours before `report_v21_namespaces` ever reaches the
    // namespace comparison that raises `WrongTermNamespace` — omitting it
    // from that list makes every `aff4l:` term look like a vendor extension
    // and skips the check entirely, which is exactly what happened before
    // `is_known_namespace` was corrected.
    //
    // Not asserted as an exact count: the xattr-driven deviations scale with
    // how many extended attributes the fixture tree carries, which is
    // platform-dependent (macOS's `com.apple.provenance` versus none
    // elsewhere). What must hold on every platform is that at least one
    // deviation is reported and every deviation reported here is the one
    // kind this input can produce.
    let report = aff4tools()
        .arg("conformance")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .assert()
        .success();
    let report_body = String::from_utf8(report.get_output().stdout.clone()).expect("UTF-8 JSON");
    let parsed: serde_json::Value = serde_json::from_str(&report_body).expect("a JSON report");
    let deviations = parsed["containers"][0]["deviations"]
        .as_array()
        .expect("a deviations array");
    assert!(
        !deviations.is_empty(),
        "the https-namespace container reported no deviations; AFF4-L \
v1.0-ALPHA §4.1's namespace check did not run on it:\n{report_body}"
    );
    assert!(
        deviations
            .iter()
            .all(|d| d["kind"] == "wrong_term_namespace"),
        "an unexpected deviation kind appeared:\n{report_body}"
    );

    // The acquisition task's `pathSeparator` is written on every v2.1
    // acquisition and is not affected by how many xattrs the fixture tree
    // carries, so its deviation message is asserted verbatim.
    let path_separator_detail = deviations
        .iter()
        .find(|d| {
            d["detail"]
                .as_str()
                .is_some_and(|s| s.starts_with("pathSeparator"))
        })
        .unwrap_or_else(|| panic!("no pathSeparator deviation in:\n{report_body}"))["detail"]
        .as_str()
        .expect("a string detail");
    assert_eq!(
        path_separator_detail,
        "pathSeparator is written under https://aff4.org/Schema/2022/# but AFF4-L v1.0-ALPHA \
§4.1 places it in http://aff4.org/Schema/2022/#; a reader that does not accept both namespaces \
will not recognize the term"
    );
}

#[test]
fn the_default_namespace_is_unchanged() {
    // The reading this project takes, and what every other image in the set
    // carries. §4.1's examples use `http://`, and implementations are written
    // against examples.
    let (_src, _out, path) = acquire_forced("segment");
    let body = turtle(&path);
    assert!(
        !body.contains("<https://aff4.org/Schema/2022/#>"),
        "the default acquisition wrote the https namespace:\n{body}"
    );
}

/// `--datastream-indirect` reaches only the own-map writer, so every other
/// combination is refused at argument-parsing time rather than accepted and
/// quietly ignored.
///
/// A reference image built from a command whose flags did not all take effect
/// answers a different question from the one asked for it.
#[test]
fn the_indirect_form_refuses_every_form_but_own_map() {
    let (_src, root) = source_tree();
    let out = tempfile::tempdir().expect("a temp dir");

    for form in [
        None,
        Some("segment"),
        Some("resident"),
        Some("shared-map"),
        Some("imagestream"),
    ] {
        let container = out.path().join(format!("{}.aff4l", form.unwrap_or("none")));
        let mut command = aff4tools();
        command
            .args(["acquire", "--logical"])
            .arg(&root)
            .arg("--output")
            .arg(&container)
            .arg("--aff4l-v1.0")
            .arg("--datastream-indirect");
        if let Some(form) = form {
            command.args(["--storage-form", form]);
        }
        command.assert().failure().code(2);
        assert!(
            !container.exists(),
            "a refused combination still wrote a container for {form:?}"
        );
    }
}

/// `--deduplicate` gives no file its own storage, so there is no form left to
/// force. The combination is refused rather than resolved by a silent
/// precedence.
#[test]
fn deduplication_and_a_forced_storage_form_are_refused_together() {
    let (_src, root) = source_tree();
    let out = tempfile::tempdir().expect("a temp dir");

    for extra in [
        vec!["--storage-form", "own-map", "--deduplicate"],
        vec!["--datastream-indirect", "--deduplicate"],
    ] {
        let container = out
            .path()
            .join(format!("{}.aff4l", extra[0].trim_start_matches('-')));
        let mut command = aff4tools();
        command
            .args(["acquire", "--logical"])
            .arg(&root)
            .arg("--output")
            .arg(&container)
            .arg("--aff4l-v1.0");
        for arg in &extra {
            command.arg(arg);
        }
        command.assert().failure().code(2);
        assert!(
            !container.exists(),
            "a refused combination still wrote a container for {extra:?}"
        );
    }
}
