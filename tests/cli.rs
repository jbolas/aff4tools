//! End-to-end tests of the `aff4tools` binary.
//!
//! Tests that need a real container are gated behind `--features corpus`, like
//! `tests/corpus.rs`. Argument handling and exit codes are exercised without
//! fixtures so they run everywhere.

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::disallowed_methods)]

use assert_cmd::Command;
use predicates::prelude::*;

fn aff4tools() -> Command {
    Command::cargo_bin("aff4tools").expect("the binary must build")
}

/// Expand tabs to spaces the way a terminal does, for column assertions.
///
/// A tab advances to the next multiple of `width`, which is what makes
/// tab-separated output line up (or not). Asserting on raw `\t` counts would
/// not catch a label that overruns its stop and pushes its value a column
/// further right.
#[cfg(feature = "corpus")]
fn expand_tabs(line: &str, width: usize) -> String {
    let mut out = String::new();
    for ch in line.chars() {
        if ch == '\t' {
            let next = (out.len() / width + 1) * width;
            out.extend(std::iter::repeat_n(' ', next - out.len()));
        } else {
            out.push(ch);
        }
    }
    out
}

/// A fixture committed to this repository, under `tests/fixtures/`.
///
/// These are the containers this project made itself, so they ship with the
/// source and need no corpus download. Resolved from `CARGO_MANIFEST_DIR`, so
/// it works from any working directory.
fn fixture_path(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    assert!(path.is_file(), "fixture missing: {}", path.display());
    path.to_string_lossy().into_owned()
}

/// The corpus root, or a clear failure explaining how to point at it.
///
/// Mirrors `corpus_root()` in `tests/corpus.rs`.
#[cfg(feature = "corpus")]
fn corpus_path(relative: &str) -> String {
    let root = std::env::var_os("AFF4_TEST_IMAGES").map_or_else(
        || {
            std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME must be set"))
                .join(".cache/aff4tools/corpus")
        },
        std::path::PathBuf::from,
    );
    let path = root.join(relative);
    assert!(path.is_file(), "corpus fixture missing: {}", path.display());
    path.to_string_lossy().into_owned()
}

/// **Evidence that could not be read must not exit 0.**
///
/// `verify` could give only two answers to a script: 0 for "fine" and 8 for
/// "a digest did not match". A container whose evidence segments would not
/// decompress fell into neither, so it exited 0 while half its recorded
/// digests went unchecked — the tool reported "2 of 2 matched" and a script
/// gating on the exit code passed it. Unverifiable evidence is now 9.
///
/// The line this draws is what the test pins down. Only *evidence* that could
/// not be retrieved counts. A codec this build declines to decompress (raw
/// deflate) must stay at 0: the evidence is perfectly intact and the decline
/// is a limit of the tool. Getting that wrong would make the code fire on
/// healthy containers and train an examiner to ignore it.
///
/// **One part of a split set alone is also 9.** The format legitimately
/// spreads one image across several files, so a lone part looks ordinary — but
/// it references volumes it does not hold, so bytes its recorded digests cover
/// cannot be read back, which is what 9 means. The report names the fix rather
/// than offering a partial view over whichever streams happened to be present.
#[test]
fn unreadable_evidence_exits_nine_and_tool_limits_do_not() {
    // Damaged evidence: a bevy segment that fails its recorded ZIP checksum.
    //
    // Built by `utilities/create_test_aff4.py --bevies 8 --chunk-size 512`,
    // then flipping one bit at two offsets inside the stored bytes of bevy
    // `00000003`. Corrupting the payload rather than the ZIP structure is what
    // makes the CRC fail while the archive still parses, which is the state a
    // real bit-rotted container is in. 15 KB, replacing a 14 MB fixture that
    // exercised exactly the same path.
    let assert = aff4tools()
        .arg("verify")
        .arg(fixture_path("bitrot-test.aff4"))
        .assert()
        .code(9);
    let report = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    // Matched on "unreadable" alone: the sentence around it is reviewed and
    // rewritten, and a test that pins the phrasing turns every language edit
    // into a spurious failure. What must hold is that the finding is named at
    // all, not that it is named in particular words.
    assert!(
        report.to_lowercase().contains("unreadable"),
        "the report must name the finding, not only set the exit code:\n{report}"
    );

    // A declined codec is this build's limit. The container is intact.
    aff4tools()
        .arg("verify")
        .arg(fixture_path("deflate-test.aff4"))
        .assert()
        .code(0);
}

/// The same exit-code line, drawn against real reference containers.
///
/// Split from the fixture-only half so that half runs on a bare clone: these
/// two cases need containers this project does not redistribute.
#[cfg(feature = "corpus")]
#[test]
fn unreadable_evidence_exits_nine_on_reference_containers() {
    // One part of a split set: it names volumes it does not hold, so its
    // digests cover bytes that cannot be read back. Exit 9, and say how to fix
    // it rather than reporting over a partial view.
    let assert = aff4tools()
        .arg("verify")
        .arg(corpus_path(
            "pyaff4/test_images/AFF4Std/Striped/Base-Linear_1.aff4",
        ))
        .assert()
        .code(9);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("--split-file"),
        "the message must name the fix:\n{stderr}"
    );

    // And an ordinary container stays clean even though it carries one digest
    // (`imageStreamHash`) this build cannot recompute.
    aff4tools()
        .arg("verify")
        .arg(corpus_path("pyaff4/test_images/AFF4Std/Base-Linear.aff4"))
        .assert()
        .code(0);
}

// --- the acquisition report's account of what verification checked --------

/// **The verify pass must be announced before it runs, and its scope stated
/// without leading on a negation.**
///
/// Two reported defects, both in text an examiner reads to decide whether the
/// evidence is sound:
///
/// 1. Verification re-reads the entire container. On a 15 GiB device
///    acquisition that ran one to two minutes in total silence, which is
///    indistinguishable from a hang.
/// 2. The closing line began `Bytes: NOT compared`, which reads as a failed
///    check. It is not a check; it is a statement of scope — verification
///    reads the container, never the source.
#[test]
fn the_report_says_verification_read_the_container_not_the_source() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.dd");
    let out = dir.path().join("out.aff4");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&src, vec![0x5Au8; 512 * 1024]).unwrap();

    let assert = aff4tools()
        .args(["acquire", "--image"])
        .arg(&src)
        .arg("--output")
        .arg(&out)
        .assert()
        .success();
    let report = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // The pass is named before its verdict, so a long silence is explained
    // while it happens rather than after.
    let announced = report
        .find("Verifying:")
        .expect("the verify pass must be announced:\n{report}");
    let verdict = report
        .find("Verify:")
        .expect("the verify result must be reported");
    assert!(
        announced < verdict,
        "the announcement must precede the verdict, or it explains nothing:\n{report}"
    );

    // The announcement must name the container as what is being read. The
    // source is never re-read: its digests were taken as it streamed in, so
    // recomputing them from the container is the whole proof.
    let announcement = report
        .lines()
        .find(|l| l.starts_with("Verifying:"))
        .expect("the verify pass must be announced:\n{report}");
    assert!(
        announcement.contains("container"),
        "the announcement must name the container as what is read:\n{announcement}"
    );
    assert!(
        !report.contains("identical to the source"),
        "acquire must not re-read the source to compare against it:\n{report}"
    );
}

/// **Every acquisition mode verifies by default, and every one honors the flag.**
///
/// Each mode grew its own copy of the verification block and they drifted:
/// `--logical` verified nothing at all, and `--device` verified even when
/// `--no-verify` was given. Both are exactly the failure a forensic tool
/// cannot have — one wrote unverified evidence, the other claimed a check the
/// operator had declined.
///
/// `--device` needs a real block device and cannot run here; the shared
/// `verify_after_acquire` is what ties all three together, so covering the two
/// file-backed modes covers the logic the third uses.
#[test]
fn every_acquisition_mode_verifies_by_default_and_honors_no_verify() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.dd");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&src, vec![0x5Au8; 512 * 1024]).unwrap();

    let tree = dir.path().join("tree");
    #[allow(clippy::disallowed_methods)]
    std::fs::create_dir_all(&tree).unwrap();
    #[allow(clippy::disallowed_methods)]
    std::fs::write(tree.join("a.txt"), "hello\n".repeat(500)).unwrap();

    // (flag, extra args) for each mode, run with and without --no-verify.
    let modes: [(&str, &std::path::Path); 2] = [("--image", &src), ("--logical", &tree)];

    for (flag, source) in modes {
        let verified = dir
            .path()
            .join(format!("{}-on.aff4", flag.trim_start_matches('-')));
        let report = String::from_utf8_lossy(
            &aff4tools()
                .arg("acquire")
                .arg(flag)
                .arg(source)
                .arg("--output")
                .arg(&verified)
                .assert()
                .success()
                .get_output()
                .stdout,
        )
        .to_string();
        assert!(
            report.contains("Verifying:") && report.contains("Verify:"),
            "{flag} must verify by default; writing unverified evidence is the \
             failure this tool exists to prevent:\n{report}"
        );

        let skipped = dir
            .path()
            .join(format!("{}-off.aff4", flag.trim_start_matches('-')));
        let report = String::from_utf8_lossy(
            &aff4tools()
                .arg("acquire")
                .arg(flag)
                .arg(source)
                .arg("--no-verify")
                .arg("--output")
                .arg(&skipped)
                .assert()
                .success()
                .get_output()
                .stdout,
        )
        .to_string();
        assert!(
            !report.contains("Verifying:") && !report.contains("Verify:"),
            "{flag} must honor --no-verify; reporting a verdict for a check the \
             operator declined would be a false claim:\n{report}"
        );
        assert!(
            report.contains("Scope:") && report.contains("--no-verify"),
            "{flag} must state that the check was skipped:\n{report}"
        );

        // Skipping must be a deferral, not a loss.
        aff4tools()
            .arg("verify")
            .arg(&skipped)
            .assert()
            // Exit 0 is the claim under test: the container verifies. Matching
            // the verdict's wording would break on every language edit.
            .success();
    }
}

/// **`--no-verify` skips the container re-read, and says so.**
///
/// The flag gates the one check that proves something — recomputing the
/// recorded digests from the written container. It does not gate a
/// byte-for-byte re-read of the source, which proves nothing the digests do not
/// already establish.
#[test]
fn no_verify_skips_the_container_re_read_and_states_the_scope() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.dd");
    let out = dir.path().join("out.aff4");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&src, vec![0x5Au8; 512 * 1024]).unwrap();

    let assert = aff4tools()
        .args(["acquire", "--image"])
        .arg(&src)
        .arg("--output")
        .arg(&out)
        .arg("--no-verify")
        .assert()
        .success();
    let report = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // The check must genuinely not run: reporting a verdict here would claim
    // a proof that was never computed.
    assert!(
        !report.contains("Verifying:") && !report.contains("Verify:"),
        "--no-verify must skip the verify pass entirely:\n{report}"
    );

    // Scope must be stated. `NOT compared` as an opening reads as a failed
    // check; this is not a check at all, but a statement of what was covered.
    assert!(
        !report.contains("NOT compared"),
        "scope must not be phrased as a failed check:\n{report}"
    );
    let scope = report
        .lines()
        .find(|l| l.starts_with("Scope:"))
        .expect("the report must state what verification covered:\n{report}");
    assert!(
        scope.contains("--no-verify"),
        "scope must name the flag that narrowed it:\n{scope}"
    );

    // The container must still verify later, which is what makes skipping
    // the check a deferral rather than a loss.
    aff4tools()
        .arg("verify")
        .arg(&out)
        .assert()
        // As above: the exit code carries the claim, not the phrasing.
        .success();
}

/// **The verify summary separates checks from recorded values.**
///
/// "6 of 6 recomputed digest(s) matched" could not be reconciled against the
/// four digests `info` lists, because the two numbers count different things:
/// a block-hash check compares a whole sequence of per-chunk digests as one
/// check, not one recorded value. Both figures were right and the report gave
/// no way to tell them apart.
///
/// The three counts are now distinct, and this pins the arithmetic that
/// relates them: every check is either one recorded value or one sequence, so
/// the recorded-value count can never exceed the check count.
#[cfg(feature = "corpus")]
#[test]
fn the_verify_summary_distinguishes_checks_from_recorded_values() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.dd");
    let out = dir.path().join("out.aff4");
    // 2 MiB at the default 32 KiB chunk = 64 chunks, hashed MD5 and SHA-1.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&src, vec![0x5Au8; 2 * 1024 * 1024]).unwrap();

    aff4tools()
        .args(["acquire", "--image"])
        .arg(&src)
        .arg("--output")
        .arg(&out)
        .assert()
        .success();

    let assert = aff4tools().arg("verify").arg(&out).assert().success();
    let report = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let start = report
        .find("Verification results:")
        .expect("the report must summarize what was verified");
    let summary: String = report[start..]
        .lines()
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");

    // The per-chunk total is stated, not left to be inferred from a per-check
    // count an examiner would have to add up.
    assert!(
        summary.contains("128 per-chunk digests"),
        "64 chunks over two algorithms is 128 compared digests:\n{summary}"
    );

    // Recorded values are the number `info` shows: two stream digests plus one
    // blockHashesHash per block-hash segment.
    assert!(
        summary.contains("4 recorded digest value(s)"),
        "the container records four digest values:\n{summary}"
    );

    // And the check count stays distinct from both.
    assert!(
        summary.contains("6 completed"),
        "four value checks plus two sequence checks is six:\n{summary}"
    );

    // Attempted is stated, and on a container aff4tools wrote itself nothing is
    // declined, so it equals completed.
    assert!(
        summary.contains("6 checks attempted"),
        "the attempted count must be stated:\n{summary}"
    );

    // A block-hash check says what it did, rather than printing a bare count
    // that could be read as "this many exist" instead of "this many compared".
    assert!(
        report.contains("verified 64 per-chunk digests, all recomputed and compared"),
        "a sequence check must state that every digest was compared:\n{report}"
    );

    // Turning block hashing off removes the sequence checks and the clause
    // that reports them, leaving the recorded values alone.
    let assert = aff4tools()
        .arg("verify")
        .arg("--no-block-hashing")
        .arg(&out)
        .assert()
        .success();
    let plain = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let start = plain
        .find("Verification results:")
        .expect("the report must summarize what was verified");
    let summary: String = plain[start..]
        .lines()
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !summary.contains("per-chunk"),
        "with block hashing off there are no per-chunk digests to report:\n{summary}"
    );
    assert!(
        summary.contains("4 completed") && summary.contains("4 recorded digest value(s)"),
        "the four recorded values are still checked:\n{summary}"
    );
}

/// **The acquisition report accounts for every digest it recorded.**
///
/// The log printed the stream's two digests while verification went on to
/// report six checks, and the four it never showed were the `blockHashesHash`
/// values. Two printed against six checked reads as an inconsistency in the
/// tool's own arithmetic — the sort of thing that has to be explained in a
/// report — when both numbers were correct and simply counted different
/// things.
///
/// Every digest written into the container is now named by the object that
/// carries it, so the log can be reconciled against `info` without arithmetic.
#[cfg(feature = "corpus")]
#[test]
fn the_acquisition_report_names_every_digest_it_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.dd");
    let out = dir.path().join("out.aff4");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&src, vec![0x5Au8; 512 * 1024]).unwrap();

    let assert = aff4tools()
        .args(["acquire", "--image"])
        .arg(&src)
        .arg("--output")
        .arg(&out)
        .assert()
        .success();
    let report = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        report.contains("ImageStream hashes:") && report.contains("BlockHashes:"),
        "the two kinds of digest must be reported under their own headings:\n{report}"
    );

    // Every digest the container records must appear in the report. Read back
    // from the Turtle rather than hardcoded, so this tracks what was written.
    let file = std::fs::File::open(&out).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let turtle = {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut zip.by_name("information.turtle").unwrap(), &mut s)
            .unwrap();
        s
    };
    let recorded: std::collections::BTreeSet<String> = turtle
        .split('"')
        .filter(|t| t.len() >= 32 && t.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_owned)
        .collect();
    assert!(
        recorded.len() >= 4,
        "expected the stream's digests plus a blockHashesHash per algorithm, \
         found {}:\n{turtle}",
        recorded.len()
    );
    for digest in &recorded {
        assert!(
            report.contains(digest.as_str()),
            "digest {digest} is recorded in the container but absent from the \
             report:\n{report}"
        );
    }

    // Named by the object that carries it, so a line can be matched against
    // `info` without counting.
    assert!(
        report.contains("  data ") && report.contains("  blockhash.md5 "),
        "each digest must be named by its ARN suffix:\n{report}"
    );

    // The acquisition and the run as a whole are both stamped.
    assert!(
        report.contains("Acquisition Complete:") && report.contains("Completed:"),
        "the report must timestamp the end of acquisition and of the run:\n{report}"
    );
}

/// **Every acquisition mode writes a log beside its container.**
///
/// Logging was originally wired into `--logical` alone — the mode whose noisy
/// output prompted the feature — so `--image` and `--device` ran with no record
/// at all. It was reported as a missing file after a real device acquisition,
/// which is the worst way to discover it: the run an examiner is least able to
/// repeat was the one left unlogged.
///
/// `--device` cannot be exercised here without a real block device, so this
/// covers `--image`; the shared `setup_log` helper is what ties the three
/// together.
#[test]
fn an_image_acquisition_writes_a_log_beside_the_container() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.dd");
    let out = dir.path().join("evidence.aff4");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&src, vec![0x11u8; 256 * 1024]).unwrap();

    aff4tools()
        .args(["acquire", "--image"])
        .arg(&src)
        .arg("--output")
        .arg(&out)
        .assert()
        .success();

    // Named from the container's stem, so the record travels with the evidence.
    let log = dir.path().join("evidence_log.txt");
    assert!(
        log.exists(),
        "a log must be written beside the container; found: {:?}",
        std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| Some(e.ok()?.file_name()))
            .collect::<Vec<_>>()
    );

    // And it must hold the report, not merely exist.
    let body = std::fs::read_to_string(&log).unwrap();
    assert!(
        body.contains("aff4tools") && body.contains("Started:"),
        "the log must carry a header identifying the run:\n{body}"
    );
    assert!(
        body.contains("Verify:"),
        "the log must record the verification verdict, not just the preamble:\n{body}"
    );
}

// --- argument handling, no fixtures required -----------------------------

#[test]
fn no_arguments_prints_usage() {
    aff4tools()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn help_lists_the_info_command() {
    aff4tools()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("info"));
}

#[test]
fn info_help_lists_every_flag() {
    let assert = aff4tools().args(["info", "--help"]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    for flag in ["--format", "--strict", "--objects", "--brief"] {
        assert!(out.contains(flag), "{flag} missing from help:\n{out}");
    }
}

/// B8: help must describe the report's actual (post-B0-B7) defaults — no
/// verbosity flag, full detail unconditionally, and a `--format json` value
/// that says where the shape is documented.
///
/// Also guards the `--full-listing` threshold: help text is for operators, so
/// it must carry the number itself and never the name of the constant holding
/// it. `large_listing_threshold!` in `src/main.rs` is what keeps the printed
/// figure and the enforced one the same.
#[test]
fn help_describes_the_new_defaults() {
    let assert = aff4tools().args(["info", "--help"]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(!out.contains("--verbose"), "-v was removed:\n{out}");
    for flag in ["--format", "--strict", "--objects"] {
        assert!(out.contains(flag), "{flag} missing from help:\n{out}");
    }
    // An earlier assertion was that `--format json`'s help named the
    // `containers`/`errors` envelope. The help has since been rewritten to
    // point at each command's own `--help` instead of describing the shape
    // inline, because the shape differs by command and one blurb could not be
    // true of all of them. What must stay true is that the value's help says
    // more than "Machine-readable JSON" — the wording the envelope replaced was
    // equally true of the bare array before it.
    assert!(
        out.contains("Shape differs by command"),
        "--format json help must point at the per-command shape:\n{out}"
    );

    // The threshold is an operator-facing number, so `--full-listing` must
    // print its digits rather than the name of the constant that holds them.
    assert!(
        out.contains("Above 2000 objects"),
        "--full-listing help must state the real threshold:\n{out}"
    );
    assert!(
        !out.contains("LARGE_LISTING_THRESHOLD"),
        "help must not leak the constant's name:\n{out}"
    );
}

#[test]
fn verbose_flag_is_rejected() {
    aff4tools()
        .args(["info", "-v", "/nonexistent/nowhere.aff4"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));
}

#[cfg(feature = "corpus")]
#[test]
fn case_metadata_appears_before_the_object_listing() {
    let path = corpus_path("pyaff4/test_images/AFF4Std/Base-Linear.aff4");
    let assert = aff4tools().args(["info", &path]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        out.contains("Case ID: 1SR Canonical"),
        "no case number:\n{out}"
    );
    assert!(out.contains("Administrator"), "no examiner:\n{out}");
    assert!(out.contains("Drive 1"), "no evidence number:\n{out}");

    // Both appended notes, not just the first.
    assert!(
        out.contains("This is an appended case note"),
        "note 1:\n{out}"
    );
    assert!(
        out.contains("This is another appended case note"),
        "note 2:\n{out}"
    );

    let case = out.find("Case ID: 1SR Canonical").expect("case number");
    let objects = out.find("Objects").expect("object listing");
    assert!(case < objects, "case metadata must precede the listing");
}

/// Pre-standard types the same object `caseNotes`, lowercase, in a separate
/// vocabulary. A block keyed on the Standard spelling would silently show
/// nothing for an entire generation.
#[cfg(feature = "corpus")]
#[test]
fn case_metadata_is_found_in_pre_standard_containers_too() {
    let path = corpus_path("pyaff4/test_images/AFF4PreStd/Base-Linear.af4");
    let assert = aff4tools().args(["info", &path]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        out.contains("Case ID: 1SR Canonical"),
        "no case number:\n{out}"
    );
    let case = out.find("Case ID: 1SR Canonical").expect("case number");
    let objects = out.find("Objects").expect("object listing");
    assert!(case < objects, "case metadata must precede the listing");
}

/// AFF4-L containers carry zero case-bearing predicates (measured directly
/// from `information.turtle`). Ruling R1: absence prints no `Case` section at
/// all, never an empty block or a negative sentence.
#[cfg(feature = "corpus")]
#[test]
fn aff4_l_containers_print_no_case_section() {
    for relative in [
        "pyaff4/test_images/AFF4-L/dream.aff4",
        "pyaff4/test_images/AFF4-L/unicode.aff4",
        "pyaff4/test_images/AFF4-L/broken-dedupe.aff4",
    ] {
        let path = corpus_path(relative);
        let assert = aff4tools().args(["info", &path]).assert().success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        assert!(
            !out.contains("Case"),
            "{relative} must print no Case section:\n{out}"
        );
    }
}

#[cfg(feature = "corpus")]
#[test]
fn default_output_shows_every_property() {
    let path = corpus_path("pyaff4/test_images/AFF4Std/Base-Linear.aff4");
    let assert = aff4tools().args(["info", &path]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    // Previously only visible under -v.
    assert!(out.contains("chunkSize"), "missing chunkSize:\n{out}");
    assert!(out.contains("diskSerial"), "missing diskSerial:\n{out}");
}

#[cfg(feature = "corpus")]
#[test]
fn the_report_shows_graph_relationships_not_bare_arns() {
    let path = corpus_path("pyaff4/test_images/AFF4Std/Base-Linear.aff4");
    let assert = aff4tools().args(["info", &path]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // The volume's own manifest is reported.
    assert!(out.contains("contains"), "no manifest shown:\n{out}");

    // Objects are no longer ordered by ARN: the disk image precedes the
    // image stream that backs it, though its UUID sorts later.
    let image = out.find("cf853d0b").expect("disk image");
    let stream = out.find("c215ba20").expect("image stream");
    assert!(image < stream, "graph order, not ARN order:\n{out}");
}

/// A stripe is the hard case: an external stream with no size and no hash,
/// two dependentStream edges, and three different counts in one report.
#[cfg(feature = "corpus")]
#[test]
fn a_stripe_reports_its_external_stream_as_a_reference() {
    let path = corpus_path("pyaff4/test_images/AFF4Std/Striped/Base-Linear_1.aff4");
    let assert = aff4tools().args(["info", &path]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // The stream whose bytes live in the sibling volume must read as an
    // external reference, never as a defective or empty object.
    assert!(
        out.contains("3bf0bd14"),
        "the external stream must appear:\n{out}"
    );
    assert!(
        out.contains("another volume"),
        "its externality must be stated:\n{out}"
    );

    // Both stripes' streams are reachable from the map.
    assert!(out.contains("a04a9189"), "local stream missing:\n{out}");
}

/// property columns must size to the widest label present in each
/// object's own block, not a fixed width that only some names fit. Every
/// non-blank content line in an object block must start with the same
/// left-hand column width — checked on `acquisitionCompletionState`, one of
/// the longest AFF4 property names in the corpus, alongside `role`, one of
/// the shortest.
#[cfg(feature = "corpus")]
#[test]
fn long_property_names_do_not_collapse_the_column() {
    let path = corpus_path("pyaff4/test_images/AFF4Std/Base-Linear.aff4");
    let assert = aff4tools()
        .args(["info", "--objects", "all", &path])
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    let role_line = out
        .lines()
        .find(|l| l.trim_start().starts_with("role "))
        .expect("a role line");
    let long_line = out
        .lines()
        .find(|l| l.contains("acquisitionCompletionState"))
        .expect("acquisitionCompletionState line");

    let column = |line: &str| line.len() - line.trim_start().len();
    // Both lines belong to the same object block (the disk image), so their
    // label columns must line up: the value each label is followed by starts
    // at the same character offset.
    let role_value_at = role_line.find("disk image").expect("role value");
    let long_value_at = long_line.find("Completed Normally").expect("long value");
    assert_eq!(
        role_value_at - column(role_line),
        long_value_at - column(long_line),
        "columns do not align:\nrole line: {role_line:?}\nlong line: {long_line:?}"
    );
}

/// B5's handover item 2: `mapGapDefaultStream` names a symbolic stream
/// (`aff4:Zero`) and must render as a phrase like its neighboring edges, not
/// as the raw AFF4-namespace IRI `http://aff4.org/Schema#Zero`.
#[cfg(feature = "corpus")]
#[test]
fn map_gap_default_stream_renders_as_a_qualified_name() {
    let path = corpus_path("pyaff4/test_images/AFF4Std/Base-Linear.aff4");
    let assert = aff4tools()
        .args(["info", "--objects", "all", &path])
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        out.contains("aff4:Zero"),
        "mapGapDefaultStream must render aff4:Zero:\n{out}"
    );
    assert!(
        !out.contains("http://aff4.org/Schema#Zero"),
        "the raw IRI must not leak into the report:\n{out}"
    );
}

/// B5's handover item 3: the `Case` block's `Recorded by` line must not dump
/// every contributing ARN on one line. It should summarize by type and point
/// at the object listing instead.
#[cfg(feature = "corpus")]
#[test]
fn recorded_by_summarizes_rather_than_listing_every_arn() {
    let path = corpus_path("pyaff4/test_images/AFF4Std/Base-Linear.aff4");
    let assert = aff4tools().args(["info", &path]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    let recorded_by = out
        .lines()
        .find(|l| l.contains("Recorded by"))
        .expect("a Recorded by line");
    assert!(
        recorded_by.contains("CaseNotes") && recorded_by.contains("CaseDetails"),
        "must summarize by type:\n{recorded_by}"
    );
    // Under the default filter, CaseNotes/CaseDetails are not admitted, so
    // this must not falsely claim they are listed below.
    assert!(
        !recorded_by.contains("listed below"),
        "must not claim ARNs are listed when the default filter excludes them:\n{recorded_by}"
    );
    // No full ARN should appear on the line itself.
    assert!(
        !recorded_by.contains("aff4://"),
        "must not spell out ARNs on this line:\n{recorded_by}"
    );
}

/// A missing file is an environment problem, not an evidence finding.
#[test]
fn a_missing_file_exits_three() {
    aff4tools()
        .args(["info", "/nonexistent/nowhere.aff4"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("cannot read"));
}

/// Exit code 2 belongs to clap. Library errors start at 3 so a script can tell
/// a mistyped command line from an unreadable container.
#[test]
fn a_usage_error_exits_two() {
    aff4tools().arg("nosuchcommand").assert().code(2);
    aff4tools().arg("info").assert().code(2); // PATH is required
}

#[test]
fn help_lists_the_verify_command() {
    aff4tools()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("verify"));
}

#[test]
fn verify_help_lists_every_flag() {
    let assert = aff4tools().args(["verify", "--help"]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    for flag in ["--format", "--no-block-hashing", "--strict", "--verbose"] {
        assert!(out.contains(flag), "{flag} missing from help:\n{out}");
    }
}

/// A missing file is an environment problem whichever subcommand asked for it.
#[test]
fn verifying_a_missing_file_exits_three() {
    aff4tools()
        .args(["verify", "/nonexistent/nowhere.aff4"])
        .assert()
        .code(3);
}

// --- behaviour against real containers -----------------------------------

#[cfg(feature = "corpus")]
mod corpus {
    use super::{PredicateBooleanExt, aff4tools, expand_tabs, predicate};
    use std::path::PathBuf;

    fn fixture(relative: &str) -> PathBuf {
        let root = std::env::var_os("AFF4_TEST_IMAGES").map_or_else(
            || {
                PathBuf::from(std::env::var_os("HOME").expect("HOME must be set"))
                    .join(".cache/aff4tools/corpus")
            },
            PathBuf::from,
        );
        let path = root.join(relative);
        assert!(path.is_file(), "corpus fixture missing: {}", path.display());
        path
    }

    const BASE_LINEAR: &str = "pyaff4/test_images/AFF4Std/Base-Linear.aff4";
    const ALL_HASHES: &str = "pyaff4/test_images/AFF4Std/Base-Linear-AllHashes.aff4";
    const READ_ERROR: &str = "pyaff4/test_images/AFF4Std/Base-Linear-ReadError.aff4";
    const DREAM: &str = "pyaff4/test_images/AFF4-L/dream.aff4";
    const BROKEN_DEDUPE: &str = "pyaff4/test_images/AFF4-L/broken-dedupe.aff4";
    const PRESTD: &str = "pyaff4/test_images/AFF4PreStd/Base-Linear.af4";
    const UNICODE: &str = "pyaff4/test_images/AFF4-L/unicode.aff4";

    // --- header layout ----------------------------------------------------

    /// A physical container says so, with the shape as a qualifier.
    ///
    /// The examiner's problem this solves: a `.aff4` extension is identical
    /// whether the container holds a disk image or a logical file collection,
    /// and nothing outside the file distinguishes them.
    ///
    /// Whether `out` holds a header line labeled `label` carrying `value`.
    ///
    /// Matched as "line starts with the label, ends with the value" rather
    /// than as one literal string: the width labels are padded to is a layout
    /// choice, and a test that bakes it in fails on a change that breaks
    /// nothing. `info_header_and_segment_columns_line_up` is what guards the
    /// alignment itself.
    fn header_line_has(out: &str, label: &str, value: &str) -> bool {
        out.lines()
            .any(|l| l.starts_with(label) && l.trim_end().ends_with(value))
    }

    /// `Image` must not appear on its own — every image object declares it, so
    /// it separates nothing — and the line must precede `AFF4 Version:`, since
    /// it exists to be read first.
    #[test]
    fn info_states_the_content_type_of_a_disk_image() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            header_line_has(&out, "Content Type:", "DiskImage (contiguous)"),
            "a disk image must name itself and its shape:\n{out}"
        );

        let content = out.find("Content Type:").expect("content type line");
        let version = out.find("AFF4 Version:").expect("version line");
        assert!(
            content < version,
            "Content Type must come before AFF4 Version:\n{out}"
        );
    }

    /// A logical container counts what it holds rather than naming a root.
    ///
    /// `unicode.aff4` carries two `FolderImage`s and seven `FileImage`s as
    /// siblings — there is no single root folder to name, so the line counts
    /// both kinds and claims no containment between them. The counts are read
    /// from the container's own turtle, not from this crate's expectations.
    #[test]
    fn info_states_the_content_type_of_a_logical_image() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(UNICODE))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            header_line_has(
                &out,
                "Content Type:",
                "AFF4-L logical image containing 7 files and 2 folders"
            ),
            "a logical image must count its files and folders:\n{out}"
        );
        assert!(
            !out.contains("DiskImage"),
            "a logical container must not be described as a disk image:\n{out}"
        );
    }

    /// One file, no folders: the counts read singular, not `1 files`.
    #[test]
    fn a_single_logical_file_is_counted_in_the_singular() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(DREAM))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            header_line_has(
                &out,
                "Content Type:",
                "AFF4-L logical image containing 1 file and 0 folders"
            ),
            "counts must agree in number:\n{out}"
        );
    }

    /// Pre-standard containers use a separate vocabulary with no `DiskImage`
    /// term at all, typing their image `QueryMap, map, Image`.
    ///
    /// Those types are listed as found rather than mapped onto the Standard's
    /// vocabulary, which would assert an equivalence no specification states.
    /// The listing is restricted to objects declaring an image type: an
    /// unrestricted sweep pulls in case notes, timestamps, and the acquisition
    /// tool block, which are provenance rather than content.
    #[test]
    fn info_lists_prestandard_types_rather_than_inventing_a_mapping() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(PRESTD))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            header_line_has(&out, "Content Type:", "QueryMap, map"),
            "pre-standard types must be listed as found:\n{out}"
        );
        for provenance in ["caseNotes", "TimeStamps", "ComputeResource", "QueryAction"] {
            assert!(
                !header_line_has(&out, "Content Type:", provenance)
                    && !out
                        .lines()
                        .any(|l| l.starts_with("Content Type:") && l.contains(provenance)),
                "{provenance} is provenance, not content:\n{out}"
            );
        }
    }

    /// The version header reads as `major.minor` with the tool on its own line.
    ///
    /// Replaces `Version:     major=1 minor=0  tool="..."`, which echoed
    /// `version.txt`'s on-disk key-value syntax rather than the form the
    /// standard and an examiner use.
    #[test]
    fn info_states_the_version_and_tool_on_separate_lines() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            header_line_has(&out, "AFF4 Version:", "1.0"),
            "version must read as major.minor:\n{out}"
        );
        // Matched on the line rather than on an exact run of padding: the
        // width every label is padded to is a layout choice, and a test that
        // hardcodes it fails on a change that breaks nothing.
        assert!(
            out.lines()
                .any(|l| l.starts_with("Tool:") && l.ends_with("Evimetry 2.2.0")),
            "tool must be its own line:\n{out}"
        );
        assert!(
            !out.contains("major=") && !out.contains("minor="),
            "the version.txt key-value echo must be gone:\n{out}"
        );
    }

    /// A container declaring no version says so, and prints no empty `Tool:`.
    #[test]
    fn info_omits_the_tool_line_when_none_is_declared() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(PRESTD))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            out.lines()
                .any(|l| l.starts_with("AFF4 Version:") && l.contains("not declared")),
            "absence must be stated:\n{out}"
        );
        assert!(
            !out.contains("Tool:"),
            "a pre-standard container declares no tool, so no blank line:\n{out}"
        );
    }

    /// Header values and the segment breakdown share one column.
    ///
    /// Every header label is padded with spaces to one width, so every value
    /// starts in the same column whatever the label's length. Spaces rather
    /// than tabs: a tab advances to the next stop, so a label one character
    /// longer than a stop pushed its value a whole stop further right than its
    /// neighbours — which is why "Tool:" once needed a second tab.
    #[test]
    fn info_header_and_segment_columns_line_up() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        // Expand tabs the way a terminal does, then check the value column.
        let expanded: Vec<String> = out.lines().map(|line| expand_tabs(line, 8)).collect();

        // Where the value begins: past the label, past the padding spaces the
        // tabs expanded into.
        let value_column = |prefix: &str| -> usize {
            let line = expanded
                .iter()
                .find(|l| l.starts_with(prefix))
                .unwrap_or_else(|| panic!("no line starting {prefix}:\n{out}"));
            let rest = &line[prefix.len()..];
            prefix.len() + (rest.len() - rest.trim_start_matches(' ').len())
        };

        let container = value_column("Container:");
        for prefix in [
            "Volume ARN:",
            "Content Type:",
            "AFF4 Version:",
            "Tool:",
            "Zip segments:",
        ] {
            assert_eq!(
                value_column(prefix),
                container,
                "{prefix} value must start in the same column as Container:'s\n{out}"
            );
        }

        // Every segment row's example starts in one column.
        let examples: Vec<usize> = expanded
            .iter()
            .filter(|l| l.contains("map structure") || l.contains("bevy data"))
            .map(|l| l.find(|c: char| c != ' ').unwrap_or(0))
            .collect();
        assert!(
            examples.windows(2).all(|w| w[0] == w[1]),
            "segment rows must share a left edge:\n{out}"
        );
    }

    // --- verify's block-hash coverage statement ---------------------------

    /// The closing coverage line must describe work actually done.
    ///
    /// `Base-Linear` stores block-hash segments, so the leaves really are
    /// checked and the strong claim is earned.
    #[test]
    fn verify_claims_leaves_to_root_only_when_block_hashes_exist() {
        aff4tools()
            .args(["verify"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "All per-chunk block hashes were recomputed.",
            ));
    }

    /// A container storing no block-hash segments must not claim the leaves
    /// were checked.
    #[test]
    fn verify_does_not_claim_leaf_coverage_when_no_block_hashes_are_stored() {
        let assert = aff4tools()
            .args(["verify"])
            .arg(fixture(DREAM))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            !out.contains("were recomputed."),
            "must not claim leaf coverage with no block hashes stored:\n{out}"
        );
        assert!(
            out.contains("stores no per-chunk block hashes"),
            "must say why nothing was checked:\n{out}"
        );
        assert!(
            !out.contains("--no-block-hashing"),
            "must not blame a flag the user never passed:\n{out}"
        );
    }

    /// Opting out is still reported as opting out, distinctly from the
    /// nothing-stored case.
    #[test]
    fn verify_names_the_flag_when_block_hashing_was_declined() {
        aff4tools()
            .args(["verify", "--no-block-hashing"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success()
            .stdout(
                predicate::str::contains(
                    "Per-chunk block hashes were not recomputed, per --no-block-hashing.",
                )
                .and(predicate::str::contains("All per-chunk block hashes were recomputed.").not()),
            );
    }

    // --- conformance ------------------------------------------------------

    /// The three parts the report is specified to have, in order: which
    /// container, what it was checked against, and the deviations.
    #[test]
    fn conformance_reports_container_specification_and_deviations() {
        let assert = aff4tools()
            .args(["conformance"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        let container = out.find("Container:").expect("a Container: line");
        let checking = out
            .find("Checking conformance with AFF4 Specification 1.0a")
            .expect("the specification line");
        let deviations = out.find("Deviations (").expect("a Deviations block");

        assert!(
            container < checking && checking < deviations,
            "the three parts must appear in order:\n{out}"
        );
        assert!(
            out.contains("Base-Linear.aff4"),
            "the container must be named:\n{out}"
        );
    }

    /// Every listed deviation cites the section it departs from.
    #[test]
    fn conformance_cites_a_spec_section_per_deviation() {
        aff4tools()
            .args(["conformance"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success()
            .stdout(
                predicate::str::contains("NUL-padded ZIP comment")
                    .and(predicate::str::contains("AFF4 Specification 1.0a §5.4")),
            );
    }

    /// A container with nothing recorded says so, and still refuses to imply
    /// its bytes were checked.
    #[test]
    fn conformance_on_a_clean_container_makes_no_verification_claim() {
        let assert = aff4tools()
            .args(["conformance"])
            .arg(fixture(PRESTD))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        if out.contains("No deviations") {
            assert!(
                out.contains("no digest was recomputed"),
                "a clean conformance report must not read as verification:\n{out}"
            );
        }
    }

    /// The JSON envelope matches `info`'s shape and carries the citation.
    #[test]
    fn conformance_json_has_the_envelope_and_citations() {
        let assert = aff4tools()
            .args(["conformance", "--format", "json"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");

        assert!(value["containers"].is_array(), "{out}");
        assert!(value["errors"].is_array(), "{out}");

        let container = &value["containers"][0];
        assert_eq!(
            container["specification"], "AFF4 Specification 1.0a",
            "{out}"
        );
        assert_eq!(container["conformant"], false, "{out}");

        let deviation = &container["deviations"][0];
        assert_eq!(deviation["kind"], "nul_padded_comment", "{out}");
        assert_eq!(deviation["spec_section"], "§5.4", "{out}");
        assert!(
            deviation["detail"].as_str().is_some_and(|d| !d.is_empty()),
            "{out}"
        );
    }

    /// A failure is reported in the JSON envelope, not lost to stderr.
    #[test]
    fn conformance_json_reports_a_failure_in_the_envelope() {
        let assert = aff4tools()
            .args(["conformance", "--format", "json", "/nonexistent/nope.aff4"])
            .assert()
            .failure();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");

        assert_eq!(
            value["containers"].as_array().map(Vec::len),
            Some(0),
            "{out}"
        );
        assert_eq!(value["errors"].as_array().map(Vec::len), Some(1), "{out}");
    }

    /// Several containers in one invocation each get their own report.
    #[test]
    fn conformance_handles_several_containers() {
        let assert = aff4tools()
            .args(["conformance"])
            .arg(fixture(BASE_LINEAR))
            .arg(fixture(DREAM))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert_eq!(
            out.matches("Checking conformance with").count(),
            2,
            "each container needs its own report:\n{out}"
        );
    }

    #[test]
    fn summarises_a_standard_container() {
        aff4tools()
            .args(["info"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success()
            .stdout(
                predicate::str::contains("aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044")
                    .and(predicate::str::is_match(r"AFF4 Version:\s+1\.0").unwrap())
                    .and(predicate::str::contains("Evimetry 2.2.0")),
            );
    }

    /// Digests must never be shortened: a truncated hash in a forensic report
    /// is worse than none.
    #[test]
    fn digests_are_printed_in_full() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        // The SHA1 and MD5 recorded on the image stream, verbatim.
        assert!(
            out.contains("fbac22cca549310bc5df03b7560afcf490995fbb"),
            "{out}"
        );
        assert!(out.contains("d5825dc1152a42958c8219ff11ed01a3"), "{out}");
        // And a full 128-character SHA512.
        assert!(
            out.contains(
                "c339331791f2018c50247cae1307ea8b0ce1166fac8747c5f4438c364b3d6c56\
                 793405afec7eec366205073ed9f7e7801556587c87181d83afe356bc9244ccf2"
            ),
            "{out}"
        );
        assert!(!out.contains('…'), "no digest may be elided:\n{out}");
    }

    /// A summary reads no data and computes nothing, so every hash must be
    /// marked as recorded at acquisition rather than verified.
    #[test]
    fn every_hash_is_marked_as_an_acquisition_hash() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        let hash_lines = out
            .lines()
            .filter(|l| l.contains("(SHA1)") || l.contains("(MD5)") || l.contains("(SHA512)"));
        let mut seen = 0;
        for line in hash_lines {
            seen += 1;
            assert!(
                line.contains("[acquisition hash]"),
                "hash line without provenance marker: {line}"
            );
        }
        assert!(seen > 0, "expected some hashes:\n{out}");
        assert!(
            !out.to_lowercase().contains("verified"),
            "a summary must never claim verification:\n{out}"
        );
    }

    /// a `BlockHashes` object's content algorithm (from its ARN
    /// suffix, e.g. `.md5`) and its own recorded digest algorithm (always
    /// SHA512 in the corpus, per `aff4:blockHashesHash`) must never share one
    /// label. The digest is never relabelled — `hash (SHA512)` must still be
    /// printed exactly, since that is what the container's typed literal
    /// says — but the content algorithm must appear separately, and the two
    /// must not be conflatable by a reader skimming the block.
    #[test]
    fn block_hashes_state_both_algorithms_separately() {
        let assert = aff4tools()
            .args(["info", "--objects", "all"])
            .arg(fixture(ALL_HASHES))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        for (suffix, content_algorithm) in [
            ("blockhash.md5", "MD5"),
            ("blockhash.sha1", "SHA-1"),
            ("blockhash.sha256", "SHA-256"),
            ("blockhash.blake2b", "Blake2b"),
        ] {
            let start = out
                .find(suffix)
                .unwrap_or_else(|| panic!("{suffix} missing:\n{out}"));
            let block = &out[start..(start + 400).min(out.len())];
            assert!(
                block.contains(content_algorithm),
                "{suffix}'s block must name its content algorithm ({content_algorithm}):\n{block}"
            );
            // The digest itself must still read SHA512, verbatim, never
            // relabelled to the content algorithm.
            assert!(
                block.contains("hash (SHA512)"),
                "{suffix}'s recorded digest must still read hash (SHA512):\n{block}"
            );
        }
    }

    /// the disk image's `hash (blockMapHashSHA512)` and the map's
    /// `blockMapHash (SHA512)` are the identical value, spec-mandated at two
    /// locations (§6.2). The report must say so rather than leaving two
    /// identical 128-character digests unconnected.
    #[test]
    fn block_map_hash_duplication_is_cross_referenced() {
        let assert = aff4tools()
            .args(["info", "--objects", "all"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            out.contains("§6.2"),
            "the disk image's hash must cite spec §6.2:\n{out}"
        );
        assert!(
            out.contains("Same value as hash"),
            "the map's blockMapHash must cross-reference the disk image's hash:\n{out}"
        );
    }

    /// a `DiskImage`/`Map`'s `size` is the full logical extent the map
    /// describes; an `ImageStream`'s `size` is bytes actually stored in this
    /// volume's bevies. Sharpest on `Base-Linear-ReadError.aff4`, where the
    /// two diverge by two orders of magnitude and a reader without the
    /// distinction could mistake the gap for damage.
    #[test]
    fn stored_and_described_sizes_carry_different_labels() {
        let assert = aff4tools()
            .args(["info"])
            .arg(fixture(READ_ERROR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            out.contains("described extent"),
            "the disk image/map must label its size as described:\n{out}"
        );
        assert!(
            out.contains("stored extent"),
            "the image stream must label its size as stored:\n{out}"
        );
        // Neither word may imply damage.
        for bad in ["damaged", "corrupt", "fake", "synthetic", "missing"] {
            assert!(
                !out.to_lowercase().contains(bad),
                "must not describe a described region as {bad}:\n{out}"
            );
        }
    }

    /// A plain AFF4-L
    /// `FileImage` that is its own `ImageStream` (or a bare `zip_segment`,
    /// `dream.aff4`'s case) has no separate map, so stored and described
    /// extents cannot diverge for it. Labelling its `size` line "described
    /// extent" would overclaim a stored/described gap that does not exist.
    /// Only a genuinely `Map`-typed `FileImage` (`broken-dedupe.aff4`) gets
    /// the qualified label.
    #[test]
    fn a_file_image_with_no_map_gets_the_plain_size_label() {
        let assert = aff4tools()
            .args(["info", "--objects", "all"])
            .arg(fixture(DREAM))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            out.lines().any(|l| l.trim_start().starts_with("size ")),
            "a map-free FileImage must use the plain 'size' label:\n{out}"
        );
        assert!(
            !out.contains("described extent") && !out.contains("stored extent"),
            "a map-free FileImage must not claim a stored/described distinction:\n{out}"
        );
    }

    /// The other half of `broken-dedupe.aff4`'s `FileImage` is also
    /// typed `Map` and genuinely has a separate backing `ImageStream` whose
    /// stored bytes differ from the FileImage's described extent — the
    /// qualified labels are correct here, unlike `dream.aff4`.
    #[test]
    fn a_map_backed_file_image_gets_the_qualified_size_label() {
        let assert = aff4tools()
            .args(["info", "--objects", "all"])
            .arg(fixture(BROKEN_DEDUPE))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            out.contains("described extent"),
            "the Map-typed FileImage must use 'described extent':\n{out}"
        );
        assert!(
            out.contains("stored extent"),
            "its backing ImageStream must use 'stored extent':\n{out}"
        );
    }

    #[test]
    fn pre_standard_reports_no_version_rather_than_inventing_one() {
        aff4tools()
            .args(["info"])
            .arg(fixture(PRESTD))
            .assert()
            .success()
            .stdout(
                predicate::str::contains("not declared")
                    .and(predicate::str::contains("pre-standard")),
            );
    }

    /// `info --format json` always emits an envelope object —
    /// `{"containers": [...], "errors": [...]}` — rather than a bare summary
    /// (one input) or a bare array (several), so a script does not have to
    /// branch on argument count to find its own data. See
    /// `json_reports_a_container_error_in_the_envelope_not_as_a_bare_array`
    /// for the failure side.
    #[test]
    fn json_output_is_valid_and_flat() {
        let assert = aff4tools()
            .args(["info", "--format", "json"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        let value: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("invalid JSON: {e}\n{out}"));

        assert!(
            value["errors"].as_array().is_some_and(Vec::is_empty),
            "a clean run must report zero errors: {value}"
        );
        let container = &value["containers"][0];

        // The ARN serialises as a plain string, not an object exposing offsets.
        assert_eq!(
            container["volume"]["arn"].as_str(),
            Some("aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044")
        );
        // A stable snake_case token, not the derive-default
        // PascalCase Rust identifier `Standard10`.
        assert_eq!(container["generation"].as_str(), Some("standard10"));
        assert_eq!(
            container["version"]["tool"].as_str(),
            Some("Evimetry 2.2.0")
        );
        assert!(
            container["objects"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        );
    }

    /// A container that cannot be opened must not make stdout look like "zero
    /// containers matched". A bare `[]` on total failure is indistinguishable
    /// from an intentionally empty result when the real error goes only to
    /// stderr as prose, so the failure is a structured entry in the same JSON
    /// document.
    #[test]
    fn json_reports_a_container_error_in_the_envelope_not_as_a_bare_array() {
        let assert = aff4tools()
            .args(["info", "--format", "json", "/nonexistent/nowhere.aff4"])
            .assert()
            .code(3);
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("invalid JSON: {e}\n{out}"));

        assert!(
            value["containers"].as_array().is_some_and(Vec::is_empty),
            "{value}"
        );
        let errors = value["errors"].as_array().expect("errors is an array");
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0]["path"].as_str(),
            Some("/nonexistent/nowhere.aff4")
        );
        assert_eq!(errors[0]["kind"].as_str(), Some("io"));
        assert_eq!(errors[0]["exit_code"].as_u64(), Some(3));
        assert!(errors[0]["message"].as_str().is_some_and(|m| !m.is_empty()));
    }

    /// Mirrors `a_failure_in_one_container_still_reports_the_others` (text
    /// format) for JSON: one bad path and one good path in the same
    /// invocation must report both in the one document, not lose the failure
    /// to stderr while stdout quietly reports only the success.
    #[test]
    fn json_reports_mixed_success_and_failure_together() {
        let assert = aff4tools()
            .args(["info", "--format", "json", "/nonexistent/nowhere.aff4"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .code(3);
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("invalid JSON: {e}\n{out}"));

        assert_eq!(value["containers"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["errors"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            value["containers"][0]["volume"]["arn"].as_str(),
            Some("aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044")
        );
    }

    /// `--objects` was historically ignored under `--format json`.
    /// It must now filter `objects` the same way it filters the text report.
    #[test]
    fn json_honors_the_objects_filter() {
        let assert = aff4tools()
            .args(["info", "--format", "json", "--objects", "none"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(
            value["containers"][0]["objects"].as_array().map(Vec::len),
            Some(0)
        );
    }

    /// `manifest` sits at the **top level** of the summary, beside
    /// `deviations` and `prefixes` — also volume-scoped facts that live
    /// top-level, not nested under `volume`. This test asserts the shape as it actually
    /// is: `v["manifest"]`.
    ///
    /// Also checks the `arn_source` schema fix (no bare Rust enum variant
    /// name `Both` in the output) and that `deviations` is present.
    #[test]
    fn json_carries_the_manifest_and_a_designed_arn_source() {
        let assert = aff4tools()
            .args(["info", "--format", "json"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let value: serde_json::Value =
            serde_json::from_slice(&assert.get_output().stdout).expect("valid JSON");
        let container = &value["containers"][0];

        assert!(
            container["volume"]["arn_source"].get("Both").is_none(),
            "Rust enum variant leaked into the schema: {}",
            container["volume"]["arn_source"]
        );
        assert_eq!(
            container["volume"]["arn_source"]["kind"].as_str(),
            Some("both"),
            "{}",
            container["volume"]["arn_source"]
        );
        assert_eq!(
            container["manifest"].as_array().map(Vec::len),
            Some(7),
            "JSON must carry the manifest too, at the top level beside \
             deviations and prefixes: {value}"
        );
        assert!(
            container["deviations"].is_array(),
            "deviations must be present in JSON"
        );
    }

    /// B2's edges must not double-nest their own tag under the `kind` field
    /// name (`{"kind": {"kind": "storedIn"}}`) — a `#[serde(flatten)]` bug the
    /// review flagged. Every object's edges (when present) must carry
    /// `kind` as a plain string/tag directly on the edge object.
    #[test]
    fn json_edges_do_not_double_nest_their_kind() {
        let assert = aff4tools()
            .args(["info", "--format", "json", "--objects", "all"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let value: serde_json::Value =
            serde_json::from_slice(&assert.get_output().stdout).expect("valid JSON");
        let containers = value["containers"].as_array().expect("containers array");
        let container = &containers[0];
        let objects = container["objects"].as_array().expect("objects array");

        let mut saw_an_edge = false;
        for object in objects {
            for edge in object["edges"].as_array().expect("edges array") {
                saw_an_edge = true;
                assert!(
                    edge["kind"].is_string(),
                    "edge kind must be a plain string/tag, not a nested object: {edge}"
                );
            }
        }
        assert!(saw_an_edge, "fixture must exercise at least one edge");
    }

    /// Deviations are always reported by `conformance`; `--strict` decides
    /// whether they matter to the exit code, and routine ones deliberately do
    /// not.
    ///
    /// `Base-Linear` has exactly one deviation — the NUL-padded ZIP comment —
    /// which one writer produces for every container it writes. It is reported
    /// either way and fails neither, because an exit code that fires on a
    /// well-formed container carries no information. This test asserted the
    /// opposite previously; see
    /// `DeviationKind::is_routine`.
    #[test]
    fn strict_ignores_routine_deviations_but_still_reports_them() {
        for args in [vec!["conformance"], vec!["conformance", "--strict"]] {
            aff4tools()
                .args(&args)
                .arg(fixture(BASE_LINEAR))
                .assert()
                .success()
                .stdout(predicate::str::contains("NUL-padded ZIP comment"));
        }
    }

    /// `--strict` still sets the exit code on `info` and `verify`, even though
    /// neither lists deviations any more.
    ///
    /// The listing moved to `conformance`; the exit-code contract did not. A
    /// script gating on `info --strict` keeps working, which is why the flag
    /// stayed on both commands.
    #[test]
    fn strict_still_sets_the_exit_code_on_info() {
        aff4tools()
            .args(["info"])
            .arg(fixture(UNICODE))
            .assert()
            .success();

        aff4tools()
            .args(["info", "--strict"])
            .arg(fixture(UNICODE))
            .assert()
            .code(7);
    }

    /// The other half of the contract: a noteworthy deviation does fail.
    ///
    /// `unicode.aff4` carries nonstandard datatype IRIs, which can change how a
    /// value is interpreted and so are never routine.
    #[test]
    fn strict_promotes_noteworthy_deviations_to_a_failure() {
        aff4tools()
            .args(["conformance"])
            .arg(fixture(UNICODE))
            .assert()
            .success();

        aff4tools()
            .args(["conformance", "--strict"])
            .arg(fixture(UNICODE))
            .assert()
            .code(7)
            .stdout(predicate::str::contains("Deviations"));
    }

    #[test]
    fn objects_filter_controls_the_listing() {
        let none = aff4tools()
            .args(["info", "--objects", "none"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let none_out = String::from_utf8_lossy(&none.get_output().stdout).to_string();
        assert!(!none_out.contains("Objects ("), "{none_out}");

        // `--objects all` admits every object, so the count must read as the
        // single figure `Objects (10)` — never `Objects (N of M shown)`, the
        // overloaded numeral filed against: "Segments: N
        // members" and this count must not be readable as the same question.
        let all = aff4tools()
            .args(["info", "--objects", "all"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let all_out = String::from_utf8_lossy(&all.get_output().stdout).to_string();
        assert!(all_out.contains("Objects (10)"), "{all_out}");
        assert!(!all_out.contains("10 of 10"), "{all_out}");

        // The default filter (`images`) narrows the listing, so its header
        // must name both the shown count and the total described — but with
        // wording distinct from `all`'s bare count, and never reusable with
        // "Segments: 10 members" above it.
        let images = aff4tools()
            .args(["info", "--objects", "images"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let images_out = String::from_utf8_lossy(&images.get_output().stdout).to_string();
        assert!(
            images_out.contains("Objects (3 of 10 described"),
            "{images_out}"
        );
    }

    /// The default output includes the unmodelled properties, which is where
    /// vendor-specific acquisition metadata lives.
    #[test]
    fn default_output_shows_unmodelled_properties() {
        let assert = aff4tools()
            .args(["info", "--objects", "all"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        assert!(out.contains("diskSerial"), "{out}");
        assert!(out.contains("SGAT5060001234"), "{out}");
    }

    /// The deviation listing lives in `conformance`, with its spec citation.
    ///
    /// `dream.aff4` stores `container.description` 2nd of 4 where §5.4 requires
    /// it first. Its four lowercase `xsd:datetime` literals are no longer
    /// reported, so this container is down to that one
    /// finding — and the datatype must not reappear in the listing.
    #[test]
    fn reports_deviations_for_a_logical_container() {
        aff4tools()
            .args(["conformance"])
            .arg(fixture(DREAM))
            .assert()
            .success()
            .stdout(
                predicate::str::contains("Deviations")
                    .and(predicate::str::contains("inconsistent volume ARN"))
                    .and(predicate::str::contains("AFF4 Specification 1.0a §5.4"))
                    .and(predicate::str::contains("xsd:datetime").not()),
            );
    }

    /// `info` still states the version, and now points at `conformance`
    /// rather than listing the deviations itself.
    #[test]
    fn info_counts_deviations_and_points_at_conformance() {
        aff4tools()
            .args(["info"])
            .arg(fixture(DREAM))
            .assert()
            .success()
            .stdout(
                predicate::str::is_match(r"AFF4 Version:\s+1\.1")
                    .unwrap()
                    .and(predicate::str::contains("1 deviation"))
                    .and(predicate::str::contains("aff4tools conformance"))
                    // The listing itself must not appear here any more.
                    .and(predicate::str::contains("§5.4").not()),
            );
    }

    /// Several containers in one invocation produce a JSON array.
    #[test]
    fn multiple_paths_produce_a_json_array() {
        let assert = aff4tools()
            .args(["info", "--format", "json"])
            .arg(fixture(BASE_LINEAR))
            .arg(fixture(DREAM))
            .assert()
            .success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        // always the `{"containers": [...], "errors": [...]}`
        // envelope, not a bare array — see `InfoJsonReport` in `main.rs`.
        assert_eq!(
            value["containers"].as_array().map(Vec::len),
            Some(2),
            "{out}"
        );
        assert_eq!(value["errors"].as_array().map(Vec::len), Some(0), "{out}");
    }

    /// One bad path must not suppress the good ones.
    #[test]
    fn a_failure_in_one_container_still_reports_the_others() {
        let assert = aff4tools()
            .args(["info", "/nonexistent/nowhere.aff4"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .code(3);
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        assert!(
            out.contains("aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044"),
            "the readable container must still be summarised:\n{out}"
        );
    }

    // --- verify -----------------------------------------------------------

    /// A canonical container verifies clean and exits zero.
    #[test]
    fn verifying_a_canonical_container_succeeds() {
        let assert = aff4tools()
            .args(["verify"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .code(0);

        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        assert!(out.contains("matched"), "{out}");
        assert!(
            out.contains("All per-chunk block hashes were recomputed."),
            "block hashing is on by default, so a clean run must state that it \
             recomputed them:\n{out}"
        );
        assert!(
            !out.contains("MISMATCH"),
            "a canonical container must not report a mismatch:\n{out}"
        );
    }

    /// Without `--block-hashes` the report must say so, rather than letting a
    /// clean result read as a stronger claim than it is.
    #[test]
    fn a_report_states_when_block_hashes_were_not_recomputed() {
        let assert = aff4tools()
            .args(["verify"])
            .arg(fixture(BASE_LINEAR))
            .arg("--no-block-hashing")
            .assert()
            .code(0);

        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        assert!(
            out.contains("not recomputed"),
            "opting out must disclose what it did not check:\n{out}"
        );
        assert!(out.contains("--no-block-hashing"), "{out}");
    }

    /// Digests are never truncated, in either direction.
    #[test]
    fn verification_output_shows_digests_in_full() {
        let assert = aff4tools()
            .args(["verify", "--verbose"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .code(0);

        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        assert!(
            out.contains(
                "c339331791f2018c50247cae1307ea8b0ce1166fac8747c5f4438c364b3d6c56\
                 793405afec7eec366205073ed9f7e7801556587c87181d83afe356bc9244ccf2"
            ),
            "the blockMapHash must appear at full length:\n{out}"
        );
        assert!(!out.contains('\u{2026}'), "nothing may be elided:\n{out}");
    }

    /// JSON must be valid and carry the outcome of every check.
    #[test]
    fn verification_renders_valid_json() {
        let assert = aff4tools()
            .args(["verify", "--format", "json"])
            .arg(fixture(BASE_LINEAR))
            .assert()
            .code(0);

        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");

        let checks = value["checks"].as_array().expect("checks is an array");
        assert!(!checks.is_empty(), "{out}");

        // Every check names its subject, coverage, and outcome.
        for check in checks {
            assert!(check["subject"].is_string(), "{check}");
            assert!(check["coverage"].is_string(), "{check}");
            assert!(!check["outcome"].is_null(), "{check}");
            assert!(check["expected"].is_string(), "{check}");
        }

        // The coverage statement survives into JSON, so a machine consumer sees
        // the same claim the text report makes. Block hashing is on by
        // default, so a default run reports the whole tree.
        assert_eq!(value["block_hashes_verified"], serde_json::json!(true));
    }

    /// The opt-out must be visible to a machine consumer too, or a reduced
    /// run could be read as a whole-tree claim.
    #[test]
    fn opting_out_of_block_hashing_is_disclosed_in_json() {
        let assert = aff4tools()
            .args(["verify", "--format", "json"])
            .arg(fixture(BASE_LINEAR))
            .arg("--no-block-hashing")
            .assert()
            .code(0);

        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(value["block_hashes_verified"], serde_json::json!(false));
    }

    /// The distinction the exit codes exist for: a mismatch is not a damaged
    /// container. 8 means verification ran and the answer is negative.
    #[test]
    fn a_mismatch_exits_eight_and_not_five() {
        use std::io::Write as _;

        let source = fixture(BASE_LINEAR);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("altered.aff4");

        // Rebuild with one byte of the map changed. The CRC is recomputed, so
        // the ZIP layer is satisfied and only a digest can catch it.
        {
            let input = std::fs::File::open(&source).unwrap();
            let mut reader = zip::ZipArchive::new(input).unwrap();
            #[allow(clippy::disallowed_methods)]
            let output = std::fs::File::create(&path).unwrap();
            #[allow(clippy::disallowed_types)]
            let mut writer = zip::ZipWriter::new(output);
            let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer
                .set_raw_comment(reader.comment().to_vec().into_boxed_slice())
                .unwrap();

            let names: Vec<String> = reader.file_names().map(str::to_owned).collect();
            for name in names {
                let mut entry = reader.by_name(&name).unwrap();
                let mut body = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut body).unwrap();
                if name.ends_with("/map") {
                    body[16] ^= 0x01;
                }
                drop(entry);
                writer.start_file(&name, options).unwrap();
                writer.write_all(&body).unwrap();
            }
            writer.finish().unwrap();
        }

        let assert = aff4tools().args(["verify"]).arg(&path).assert().code(8);

        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        assert!(out.contains("MISMATCH"), "{out}");
        assert!(
            out.contains("digest does not match"),
            "a mismatch must be reported:\n{out}"
        );
        assert!(out.contains("recorded:"), "{out}");
        assert!(out.contains("computed:"), "{out}");
    }

    /// Several containers in one invocation: the most severe result wins, and a
    /// clean container is still reported.
    #[test]
    fn verifying_several_containers_reports_all_of_them() {
        let assert = aff4tools()
            .args(["verify", "--format", "json"])
            .arg(fixture(BASE_LINEAR))
            .arg(fixture(ALL_HASHES))
            .assert()
            .code(0);

        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(value.as_array().map(Vec::len), Some(2), "{out}");
    }

    /// Brief drops detail but must never hide that a deviation was recorded.
    /// `--brief` keeps the content type: it is summary information, and brief
    /// is the summary view.
    ///
    /// Asserted for both container kinds, in the same position as the full
    /// report — before `AFF4 Version:` — so the two headers cannot drift apart
    /// on where the answer appears.
    #[cfg(feature = "corpus")]
    #[test]
    fn brief_states_the_content_type_too() {
        for (path, expected) in [
            (BASE_LINEAR, "DiskImage (contiguous)"),
            (
                UNICODE,
                "AFF4-L logical image containing 7 files and 2 folders",
            ),
        ] {
            let assert = aff4tools()
                .args(["info", "--brief"])
                .arg(fixture(path))
                .assert()
                .success();
            let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

            // Label and value matched separately; see `header_line_has`.
            assert!(
                out.lines()
                    .any(|l| l.starts_with("Content Type:") && l.trim_end().ends_with(expected)),
                "brief must state the content type ({expected}):\n{out}"
            );

            let content = out.find("Content Type:").expect("content type line");
            let version = out.find("AFF4 Version:").expect("version line");
            assert!(
                content < version,
                "Content Type must precede AFF4 Version in brief too:\n{out}"
            );
        }
    }

    /// `--brief` is shorter than the full report but not weaker about findings.
    ///
    /// The listing moved to `conformance`, so what brief has to keep is the
    /// count and the pointer — enough that an examiner cannot read a brief
    /// report as "nothing was recorded" when something was.
    #[cfg(feature = "corpus")]
    #[test]
    fn brief_output_is_shorter_but_keeps_the_deviation_count() {
        let path = fixture(BASE_LINEAR).to_string_lossy().into_owned();

        let full = aff4tools().args(["info", &path]).assert().success();
        let full = String::from_utf8_lossy(&full.get_output().stdout).to_string();

        let brief = aff4tools()
            .args(["info", "--brief", &path])
            .assert()
            .success();
        let brief = String::from_utf8_lossy(&brief.get_output().stdout).to_string();

        assert!(
            brief.lines().count() < full.lines().count(),
            "brief must be shorter: {} vs {}",
            brief.lines().count(),
            full.lines().count()
        );
        assert!(
            brief.contains("1 deviation") && brief.contains("aff4tools conformance"),
            "brief must still surface the deviation count:\n{brief}"
        );
    }

    /// Revised requirement: brief must show the linear bitstream hashes and
    /// the sizes they/the disk image cover, full length, with provenance —
    /// but never the structural `imageStreamHash`/`imageStreamIndexHash`
    /// (the first is unidentified, the second digests container structure,
    /// not the bitstream), and
    /// never a doubled label on a case field whose own recorded text already
    /// reads like one.
    #[cfg(feature = "corpus")]
    #[test]
    fn brief_shows_full_linear_hashes_with_provenance_and_no_structural_hashes() {
        let path = fixture(BASE_LINEAR).to_string_lossy().into_owned();

        let brief = aff4tools()
            .args(["info", "--brief", &path])
            .assert()
            .success();
        let brief = String::from_utf8_lossy(&brief.get_output().stdout).to_string();

        // Full-length linear digests, recorded on the image stream.
        assert!(
            brief.contains("fbac22cca549310bc5df03b7560afcf490995fbb"),
            "brief must show the full linear SHA1:\n{brief}"
        );
        assert!(
            brief.contains("d5825dc1152a42958c8219ff11ed01a3"),
            "brief must show the full linear MD5:\n{brief}"
        );
        // The disk image's block-map tree root, present and labeled as a
        // tree root rather than linear.
        assert!(
            brief.contains(
                "c339331791f2018c50247cae1307ea8b0ce1166fac8747c5f4438c364b3d6c56793405afec7eec366205073ed9f7e7801556587c87181d83afe356bc9244ccf2"
            ),
            "brief must show the full block-map tree root:\n{brief}"
        );
        assert!(
            brief.contains("tree root"),
            "the block-map hash must be labeled as a tree root, not linear:\n{brief}"
        );

        // Provenance on every digest shown.
        let hash_lines = brief
            .lines()
            .filter(|l| {
                l.trim_start().starts_with("hash (") || l.trim_start().starts_with("blockMapHash (")
            })
            .count();
        let provenance_lines = brief.matches("[acquisition hash]").count();
        assert!(
            hash_lines > 0 && hash_lines == provenance_lines,
            "every hash line must carry the provenance marker: {hash_lines} hash lines, {provenance_lines} marked:\n{brief}"
        );

        // Structural hashes never appear, and are never mislabeled linear.
        assert!(
            !brief.contains("imageStreamHash") && !brief.contains("imageStreamIndexHash"),
            "brief must not show structural imageStreamHash/imageStreamIndexHash:\n{brief}"
        );

        // Sizes present with the stored/described vocabulary, not a bare "size".
        assert!(brief.contains("stored extent"), "{brief}");
        assert!(brief.contains("described extent"), "{brief}");
        assert!(brief.contains("268435456"), "{brief}");
        assert!(brief.contains("3964928"), "{brief}");

        // The Case line must not double a label the recorded value already carries.
        assert!(
            !brief.contains("Case ID: Case ID:"),
            "case field must not double its own recorded label:\n{brief}"
        );
    }

    /// A hash without its subject cannot be checked against anything. On a
    /// logical container with several `FileImage` objects, the `Bitstream`
    /// section must say which file each digest belongs to; on a
    /// `Base-Linear.aff4`-shaped container (one disk image, one image
    /// stream) the `[disk image]`/`[image stream]` role labels already
    /// disambiguate, so no extra identity line should appear there.
    #[cfg(feature = "corpus")]
    #[test]
    fn brief_bitstream_entries_carry_object_identity_when_needed() {
        let unicode = fixture(UNICODE).to_string_lossy().into_owned();
        let assert = aff4tools()
            .args(["info", "--brief", &unicode])
            .assert()
            .success();
        let brief = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

        assert!(
            brief.contains("Base-Allocated.aff4") || brief.contains("Base-Linear"),
            "brief must name which file each hash belongs to:\n{brief}"
        );

        let base_linear = fixture(BASE_LINEAR).to_string_lossy().into_owned();
        let assert = aff4tools()
            .args(["info", "--brief", &base_linear])
            .assert()
            .success();
        let brief = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        let bitstream_section = brief
            .split("Bitstream\n")
            .nth(1)
            .and_then(|rest| rest.split("\n\n").next())
            .unwrap_or_default();
        assert!(
            !bitstream_section.contains("aff4://"),
            "single disk-image/image-stream containers must not gain ARN noise in Bitstream:\n{bitstream_section}"
        );
    }
}

/// `--full-listing` writes the same report a small container prints.
///
/// The file must be the *full* report, not a reduced form: a listing written
/// because the terminal one was suppressed is worthless if it is suppressed too.
#[cfg(feature = "corpus")]
#[test]
fn full_listing_writes_the_complete_report() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("listing.txt");
    let container = corpus_path("pyaff4/test_images/AFF4-L/broken-dedupe.aff4");

    let stdout = aff4tools()
        .args(["info", "--full-listing"])
        .arg(&target)
        .arg(&container)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        String::from_utf8_lossy(&stdout).contains("Full listing written to"),
        "the report must say where the listing went"
    );

    let written = std::fs::read_to_string(&target).unwrap();
    let direct = aff4tools()
        .args(["info"])
        .arg(&container)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        written,
        String::from_utf8_lossy(&direct),
        "the file must hold the same report stdout would show"
    );
}

/// `--full-listing` refuses an existing path rather than overwriting it.
///
/// Same rule as the acquisition log: replacing a previous listing would destroy
/// a record the examiner may still need. Exit 3 is the I/O code.
#[cfg(feature = "corpus")]
#[test]
fn full_listing_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("listing.txt");
    // Writes a fixture into a TempDir, not evidence. The deny-list guards the
    // library's read-only posture; a test that must create a file to prove the
    // binary refuses to overwrite one is exactly the exception.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&target, "existing content").unwrap();

    aff4tools()
        .args(["info", "--full-listing"])
        .arg(&target)
        .arg(corpus_path("pyaff4/test_images/AFF4-L/broken-dedupe.aff4"))
        .assert()
        .code(3)
        .stderr(predicate::str::contains("listing.txt"));

    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "existing content",
        "the existing file must be untouched"
    );
}

/// Every reference container stays below the degrade threshold.
///
/// The threshold exists for containers with millions of objects; if a corpus
/// container crossed it, the reference output every other test asserts against
/// would silently become the brief summary. This pins that assumption.
#[cfg(feature = "corpus")]
#[test]
fn no_corpus_container_triggers_the_listing_degrade() {
    for relative in [
        "pyaff4/test_images/AFF4-L/broken-dedupe.aff4",
        "pyaff4/test_images/AFF4Std/Base-Linear.aff4",
        "pyaff4/test_images/AFF4PreStd/Base-Linear.af4",
    ] {
        aff4tools()
            .args(["info"])
            .arg(corpus_path(relative))
            .assert()
            .success()
            .stdout(predicate::str::contains("per-object listing is not shown").not());
    }
}

/// Above the threshold, the per-object listing is replaced by the brief summary
/// and a pointer to `--full-listing`.
///
/// Built by acquiring a directory of 2,100 small files — just over
/// `LARGE_LISTING_THRESHOLD` — rather than with a corpus fixture, because no
/// reference container is large enough to reach the branch. Without this the
/// degrade path is only ever exercised by hand.
#[test]
fn a_large_container_degrades_to_the_brief_listing() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("many");
    std::fs::create_dir(&source).unwrap();
    for i in 0..2_100 {
        // Acquisition source built in a TempDir; see the note above.
        #[allow(clippy::disallowed_methods)]
        std::fs::write(source.join(format!("f{i:05}.txt")), b"x").unwrap();
    }
    let container = dir.path().join("many.aff4");

    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&source)
        .arg("--output")
        .arg(&container)
        .assert()
        .success();

    // Degraded: the notice appears and no per-object property block does.
    aff4tools()
        .args(["info"])
        .arg(&container)
        .assert()
        .success()
        .stdout(predicate::str::contains("per-object listing is not shown"))
        .stdout(predicate::str::contains("--full-listing"));

    // ...and asking for the file gets the full listing, which is far longer.
    let target = dir.path().join("listing.txt");
    aff4tools()
        .args(["info", "--full-listing"])
        .arg(&target)
        .arg(&container)
        .assert()
        .success();

    let written = std::fs::read_to_string(&target).unwrap();
    assert!(
        written.lines().count() > 2_100,
        "the full listing must hold every object; got {} lines",
        written.lines().count()
    );
    assert!(
        !written.contains("per-object listing is not shown"),
        "the file must be the full report, not the degraded one"
    );
}

/// When a check is not recomputed, the summary still reconciles with the list.
///
/// `Base-Linear-ReadError.aff4` records an `imageStreamHash` this build cannot
/// identify, so fourteen checks are rendered and thirteen complete. The summary
/// must not open "13 checks completed; 13 of 13 matched", which reads as a
/// clean sweep of everything present — an examiner counting the entries below
/// could not reach the headline number from them.
///
/// Attempted is stated first, and it is the count that matches the list.
#[cfg(feature = "corpus")]
#[test]
fn the_verify_summary_states_how_many_checks_were_attempted() {
    let assert = aff4tools()
        .arg("verify")
        .arg(corpus_path(
            "pyaff4/test_images/AFF4Std/Base-Linear-ReadError.aff4",
        ))
        .assert()
        .success();
    let report = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        report.contains("14 checks attempted; 13 completed."),
        "attempted must be stated and must exceed completed here:\n{report}"
    );

    // The attempted count is the one that reconciles with what is rendered:
    // every check prints its ARN line, and there are fourteen of them. Counted
    // from the `Checks` heading down, since the read accounting above it opens
    // its block with an ARN line too.
    let checks_from = report
        .find("\nChecks\n")
        .expect("the report must list its checks");
    let rendered = report[checks_from..]
        .lines()
        .filter(|l| l.starts_with("  aff4://"))
        .count();
    assert_eq!(
        rendered, 14,
        "the attempted count must equal the checks actually listed:\n{report}"
    );

    // The declined one is still named separately: "attempted but not completed"
    // and "why" are different facts.
    assert!(
        report.contains("1 recorded digest(s) were not recomputed"),
        "the decline must still be called out:\n{report}"
    );
}

#[test]
fn split_file_rejects_a_size_outside_the_allowed_set() {
    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    cmd.args([
        "acquire",
        "--image",
        "/dev/null",
        "--output",
        "/tmp/x.aff4",
        "--split-file",
        "3G",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("3G"));
}

#[test]
fn split_file_help_lists_the_allowed_sizes() {
    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    cmd.args(["acquire", "--help"]);
    let out = cmd.assert().success().get_output().stdout.clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("--split-file"), "{text}");
    for size in ["1G", "2G", "4G", "8G", "16G", "32G"] {
        assert!(text.contains(size), "help must list {size}: {text}");
    }
}

#[test]
fn verify_split_folder_reports_what_it_found() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.dd");
    // Acquisition source built in a TempDir, not evidence; see the note above.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&src, vec![7u8; 3 * 1024 * 1024]).unwrap();
    let out = dir.path().join("ev.aff4");

    let mut acq = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    acq.args([
        "acquire",
        "--image",
        src.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
        "--split-file",
        "1G",
        "--compression",
        "stored",
        "--chunks-per-bevy",
        "2",
    ]);
    acq.assert().success();

    let mut ver = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    ver.args(["verify", "--split-file", dir.path().to_str().unwrap()]);
    ver.assert()
        .success()
        .stdout(predicates::str::contains("Found "))
        .stdout(predicates::str::contains("split files"));
}

#[test]
fn the_stripe_flag_is_gone() {
    // Every command that reads a split set names it the same way. `--stripe`
    // (info, conformance) and `--split-folder` (verify) were two names for one
    // idea, and a third — acquire's `--split-file` — meant the reader had to
    // remember which command took which. All three are now `--split-file`.
    for command in ["verify", "info", "conformance"] {
        let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
        cmd.args([command, "--help"]);
        let text = String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap();
        assert!(
            !text.contains("--stripe"),
            "{command} still offers --stripe: {text}"
        );
        assert!(
            !text.contains("--split-folder"),
            "{command} still offers --split-folder: {text}"
        );
        assert!(
            text.contains("--split-file"),
            "{command} must offer --split-file: {text}"
        );
    }

    // acquire keeps `--split-file` too, but as a write option taking a size.
    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    cmd.args(["acquire", "--help"]);
    let text = String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap();
    assert!(text.contains("--split-file"), "{text}");
}

#[test]
fn the_discover_siblings_flag_is_gone() {
    for command in ["verify", "info", "conformance"] {
        let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
        cmd.args([command, "--help"]);
        let text = String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap();
        assert!(
            !text.contains("--discover-siblings"),
            "{command} still offers --discover-siblings: {text}"
        );
    }
}

/// A *folder* of AFF4 containers is refused, and says how to proceed.
///
/// A single AFF4 named directly is now re-acquired through its map (see
/// `re_acquiring_an_aff4_reproduces_the_source_image`). A folder is still
/// refused, because nothing in the folder distinguishes a split set from a
/// striped one, and guessing wrong would acquire a partial image while
/// reporting success.
#[test]
fn acquire_refuses_a_folder_of_aff4_containers() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.dd");
    // Acquisition source built in a TempDir, not evidence; see the note above.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&src, vec![3u8; 256 * 1024]).unwrap();
    let container = dir.path().join("ev.aff4");

    let mut acq = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    acq.args([
        "acquire",
        "--image",
        src.to_str().unwrap(),
        "--output",
        container.to_str().unwrap(),
        "--compression",
        "stored",
    ]);
    acq.assert().success();

    // A folder holding only the written container, so discovery sees one kind.
    let only = tempfile::tempdir().unwrap();
    // Copies a container this test just wrote into a second TempDir, so
    // discovery sees a folder of one kind. No corpus fixture is touched.
    #[allow(clippy::disallowed_methods)]
    std::fs::copy(&container, only.path().join("ev.aff4")).unwrap();

    let mut again = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    again.args([
        "acquire",
        "--image",
        only.path().to_str().unwrap(),
        "--output",
        dir.path().join("copy.aff4").to_str().unwrap(),
    ]);
    again
        .assert()
        .failure()
        .stderr(predicates::str::contains("holds a set of AFF4 containers"))
        .stderr(predicates::str::contains("--image <container.aff4>"));
}

/// A folder of raw parts stands for the whole split set.
#[test]
fn acquire_accepts_a_folder_of_raw_parts() {
    let dir = tempfile::tempdir().unwrap();
    let parts = dir.path().join("parts");
    std::fs::create_dir(&parts).unwrap();
    // Raw split-set parts built in a TempDir; see the note above.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(parts.join("img.001"), vec![1u8; 128 * 1024]).unwrap();
    #[allow(clippy::disallowed_methods)]
    std::fs::write(parts.join("img.002"), vec![2u8; 128 * 1024]).unwrap();

    let out = dir.path().join("ev.aff4");
    let mut acq = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    acq.args([
        "acquire",
        "--image",
        parts.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
        "--compression",
        "stored",
    ]);
    acq.assert()
        .success()
        .stdout(predicates::str::contains("Found 2 split files"));
    assert!(out.is_file());
}

/// Naming one part of a split set must not produce a reassuring partial
/// report over whichever streams happened to be present.
///
/// The corpus `Striped/` set is the only real multi-part set available: the
/// smallest `--split-file` size is 1 GiB, so an acquisition small enough for a
/// test never produces a second part.
#[cfg(feature = "corpus")]
#[test]
fn verifying_a_single_part_names_the_fix() {
    let part = corpus_path("pyaff4/test_images/AFF4Std/Striped/Base-Linear_1.aff4");
    let mut ver = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    ver.args(["verify", &part]);
    ver.assert()
        .code(9)
        .stderr(predicates::str::contains("one part of a split set"))
        .stderr(predicates::str::contains("--split-file"));
}

/// The whole striped set verifies once the folder is named.
#[cfg(feature = "corpus")]
#[test]
fn verify_split_folder_reads_a_striped_corpus_set() {
    let part = corpus_path("pyaff4/test_images/AFF4Std/Striped/Base-Linear_1.aff4");
    let dir = std::path::Path::new(&part).parent().unwrap().to_owned();
    let mut ver = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    ver.args(["verify", "--split-file", dir.to_str().unwrap()]);
    ver.assert()
        .success()
        .stdout(predicates::str::contains("Found 2 split files"));
}

/// The reference striped set is reported as striped.
///
/// The counterpart to `a_generated_set_is_reported_as_sequential`
/// (`tests/split_acquire.rs`): that pins the sequential shape this writer
/// produces, this pins the interleaved shape only the corpus has. Neither
/// layout is declared anywhere in the container — both are inferred from map
/// geometry — so having a real example of each is what keeps the inference
/// honest.
#[cfg(feature = "corpus")]
#[test]
fn a_striped_corpus_set_is_reported_as_striped() {
    let part = corpus_path("pyaff4/test_images/AFF4Std/Striped/Base-Linear_1.aff4");
    let dir = std::path::Path::new(&part).parent().unwrap().to_owned();
    let mut ver = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    ver.args(["verify", "--split-file", dir.to_str().unwrap()]);
    ver.assert()
        .success()
        .stdout(predicates::str::contains("striped (interleaved)"))
        .stdout(predicates::str::contains("inferred from the map"));
}

/// `--split-file` with `--device` must reach the acquisition code rather than
/// being refused during argument parsing. The combination was blocked by a clap
/// conflict, which made whole-disk acquisitions — the case that most needs
/// splitting — the one case that could not use it.
#[test]
fn device_accepts_split_file() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("evidence.aff4");
    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    let assert = cmd
        .arg("acquire")
        .arg("--device")
        .arg("/nonexistent/device/node")
        .arg("--split-file")
        .arg("1G")
        .arg("--output")
        .arg(&output)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    // It must fail on the missing device, not on the flag combination.
    assert!(
        !stderr.contains("cannot be used with"),
        "clap refused the flag combination: {stderr}"
    );
    assert!(
        stderr.contains("cannot open device"),
        "expected a device-open error, got: {stderr}"
    );
}

/// `--logical` with `--split-file` must explain why it is refused, not emit
/// clap's generic conflict text. The limit is a design decision with a reason,
/// and the message is where an examiner learns it.
#[test]
fn logical_refuses_split_file_with_a_reason() {
    let dir = tempfile::tempdir().unwrap();
    let roots = dir.path().join("roots");
    std::fs::create_dir(&roots).unwrap();
    #[allow(clippy::disallowed_methods)]
    std::fs::write(roots.join("a.txt"), b"content").unwrap();
    let output = dir.path().join("evidence.aff4");

    let mut cmd = assert_cmd::Command::cargo_bin("aff4tools").unwrap();
    let assert = cmd
        .arg("acquire")
        .arg("--logical")
        .arg(&roots)
        .arg("--split-file")
        .arg("1G")
        .arg("--output")
        .arg(&output)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();

    assert!(
        !stderr.contains("cannot be used with"),
        "expected a worded refusal, got clap's conflict text: {stderr}"
    );
    assert!(
        stderr.contains("not yet supported"),
        "expected an explanation: {stderr}"
    );
    assert!(
        !output.exists(),
        "nothing may be written when the combination is refused"
    );
}

/// `--logical` is repeatable: an examiner may name several roots in one command.
///
/// The flag's own help reads as a single path, so this pins the plural
/// behaviour down at the CLI boundary rather than leaving it to clap's
/// `Vec<PathBuf>` inference.
#[test]
fn logical_accepts_several_roots_in_one_command() {
    let dir = tempfile::tempdir().unwrap();
    let documents = dir.path().join("documents");
    let exports = dir.path().join("elsewhere").join("exports");
    std::fs::create_dir_all(&documents).unwrap();
    std::fs::create_dir_all(&exports).unwrap();
    // Acquisition sources built in a TempDir.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(documents.join("a.txt"), b"from documents\n").unwrap();
    #[allow(clippy::disallowed_methods)]
    std::fs::write(exports.join("b.txt"), b"from exports\n").unwrap();

    let container = dir.path().join("multi.aff4");
    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&documents)
        .arg("--logical")
        .arg(&exports)
        .arg("--output")
        .arg(&container)
        .assert()
        .success()
        // The transcript must account for every root, since it is the record
        // the examiner keeps.
        .stdout(predicate::str::contains("2 root(s)"))
        .stdout(predicate::str::contains("2 file(s)"));

    assert!(container.is_file(), "the container must be written");
}

/// A bad root is refused before anything is created.
///
/// Roots are registered up front, so a typo in the second of three paths must
/// not leave a half-written container behind for an examiner to puzzle over.
#[test]
fn a_missing_root_fails_before_the_container_exists() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good");
    std::fs::create_dir_all(&good).unwrap();
    #[allow(clippy::disallowed_methods)]
    std::fs::write(good.join("a.txt"), b"present\n").unwrap();
    let missing = dir.path().join("no-such-folder");

    let container = dir.path().join("partial.aff4");
    let assert = aff4tools()
        .args(["acquire", "--logical"])
        .arg(&good)
        .arg("--logical")
        .arg(&missing)
        .arg("--output")
        .arg(&container)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("does not exist"),
        "the bad root must be named: {stderr}"
    );
    assert!(
        !container.is_file(),
        "no container may survive a refused acquisition"
    );
}

/// Exporting stream-backed logical files must stay linear in their count.
///
/// `Container::graph` re-parses `information.turtle` in full on every call, so
/// parsing it per file made `export --logical` quadratic: each of *n* files
/// re-read the whole metadata segment. Measured before the fix on 20,000
/// stream-backed files, export ran at roughly one file per second against
/// 4,400 per second for segment-backed ones — a projected six hours for what
/// now takes seconds.
///
/// Growth ratio rather than wall-clock, following
/// `report::tests::ordering_objects_stays_linear`: an absolute timing would be
/// flaky on a loaded machine, but 4x the files taking ~16x the time is the
/// quadratic signature and cannot be explained away.
#[test]
fn exporting_stream_backed_files_stays_linear() {
    // Above the 1 MiB segment threshold, so every file becomes an ImageStream
    // and takes the path that was quadratic.
    fn export_files(count: usize) -> std::time::Duration {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("src");
        std::fs::create_dir_all(&source).unwrap();
        // Compressible content keeps the fixture small on disk while still
        // exceeding the threshold once stored.
        let body = vec![b'A'; 1024 * 1024 + 1];
        for i in 0..count {
            #[allow(clippy::disallowed_methods)]
            std::fs::write(source.join(format!("f{i:04}.bin")), &body).unwrap();
        }

        let container = dir.path().join("streams.aff4");
        aff4tools()
            .args(["acquire", "--logical"])
            .arg(&source)
            .arg("--output")
            .arg(&container)
            .arg("--no-verify")
            .assert()
            .success();

        let target = dir.path().join("out");
        let start = std::time::Instant::now();
        aff4tools()
            .args(["export"])
            .arg(&container)
            .arg("--logical")
            .arg(&target)
            .assert()
            .success();
        let elapsed = start.elapsed();

        assert_eq!(
            std::fs::read_dir(target.join(source.strip_prefix("/").unwrap_or(&source)))
                .unwrap()
                .count(),
            count,
            "every file must be exported"
        );
        elapsed
    }

    // The effect needs enough files that re-parsing the metadata dominates
    // process start-up: measured on the unfixed code, 50 files exported in
    // 0.14 s, 200 in 1.94 s, and 800 in 30.1 s — 4x the files costing ~14x and
    // ~15x the time.
    let _ = export_files(20);

    let small = export_files(200);
    let large = export_files(800);

    // 4x the files: linear costs ~4x, quadratic ~15x as measured. The bound
    // sits between them, generous enough that a loaded machine does not fail a
    // linear export but far below the quadratic form's cost.
    assert!(
        large.as_secs_f64() < small.as_secs_f64() * 8.0,
        "exporting 4x the stream-backed files took {large:?} against {small:?} \
         for the smaller set — that growth is superlinear, so the metadata \
         graph is being re-parsed per file"
    );
}

/// **Every acquisition mode stamps all three timestamps.**
///
/// `Started:` opens the log, `Acquisition Complete:` closes the reading of the
/// source, and `Completed:` closes the run. A mode missing one leaves an
/// examiner unable to say how long the acquisition itself took, which is the
/// question a long run raises.
#[test]
fn every_mode_stamps_all_three_timestamps() {
    let dir = tempfile::tempdir().unwrap();

    // --image, from a small raw source.
    let raw = dir.path().join("source.dd");
    std::fs::write(&raw, vec![0xAB; 4096]).unwrap();
    let out = dir.path().join("image.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--image")
        .arg(&raw)
        .arg("--output")
        .arg(&out)
        .assert()
        .success();

    let body = std::fs::read_to_string(dir.path().join("image_log.txt")).unwrap();
    for stamp in ["Started:", "Acquisition Complete:", "Completed:"] {
        assert!(
            body.contains(stamp),
            "--image log must contain `{stamp}`:\n{body}"
        );
    }
    let acq = body.find("Acquisition Complete:").unwrap();
    let done = body.find("Completed:").unwrap();
    assert!(
        acq < done,
        "`Acquisition Complete:` must precede `Completed:`:\n{body}"
    );

    // --logical, over a small tree.
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(tree.join("sub").join("b.txt"), b"nested\n").unwrap();
    let lout = dir.path().join("logical.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--logical")
        .arg(&tree)
        .arg("--output")
        .arg(&lout)
        .assert()
        .success();

    let lbody = std::fs::read_to_string(dir.path().join("logical_log.txt")).unwrap();
    for stamp in ["Started:", "Acquisition Complete:", "Completed:"] {
        assert!(
            lbody.contains(stamp),
            "--logical log must contain `{stamp}`:\n{lbody}"
        );
    }
    let lacq = lbody.find("Acquisition Complete:").unwrap();
    let ldone = lbody.find("Completed:").unwrap();
    assert!(
        lacq < ldone,
        "`Acquisition Complete:` must precede `Completed:`:\n{lbody}"
    );
}

/// The stamps survive `--no-verify`, where the two land close together.
///
/// The gap between them *is* the verification time, so a near-zero gap
/// truthfully reports that verification did not run. Omitting the lines
/// instead would leave the log unable to say the run finished.
#[test]
fn no_verify_still_stamps_all_three() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"hello\n").unwrap();

    let out = dir.path().join("logical.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--logical")
        .arg(&tree)
        .arg("--no-verify")
        .arg("--output")
        .arg(&out)
        .assert()
        .success();

    let body = std::fs::read_to_string(dir.path().join("logical_log.txt")).unwrap();
    for stamp in ["Started:", "Acquisition Complete:", "Completed:"] {
        assert!(
            body.contains(stamp),
            "--no-verify must still stamp `{stamp}`:\n{body}"
        );
    }
}

/// Exactly one `Completed:` line, however the output is arranged.
///
/// `--device` writes that line from two separate sites: the split-output
/// branch stamps it and returns, and the non-split tail stamps its own. The two
/// branches verify differently and compose their exit codes differently, so
/// they were kept apart rather than merged; what keeps them from drifting is
/// that both call the same helper. A second stamp reintroduced on either side
/// would put two completion times in one log, and an examiner reading it could
/// not say which one ended the run.
///
/// Both branches are driven here. `--device` accepts a regular file, so the
/// split branch is reachable without a block device, and `--split-file` only
/// takes 1G and up — a small source yields a single part, which still takes the
/// split code path.
#[test]
fn the_log_carries_exactly_one_completed_line() {
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join("source.dd");
    std::fs::write(&raw, vec![0xCD; 4096]).unwrap();

    // The non-split path, through `--image`.
    let out = dir.path().join("image.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--image")
        .arg(&raw)
        .arg("--output")
        .arg(&out)
        .assert()
        .success();

    let body = std::fs::read_to_string(dir.path().join("image_log.txt")).unwrap();
    assert_eq!(
        body.matches("Completed:").count(),
        1,
        "exactly one `Completed:` line belongs in the --image log:\n{body}"
    );

    // The device split-output branch: the one that stamps at its own site and
    // returns, rather than falling through to the tail.
    let split = dir.path().join("device_split.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--device")
        .arg(&raw)
        .arg("--split-file")
        .arg("1G")
        .arg("--output")
        .arg(&split)
        .assert()
        .success();

    let sbody = std::fs::read_to_string(dir.path().join("device_split_log.txt")).unwrap();
    assert_eq!(
        sbody.matches("Completed:").count(),
        1,
        "exactly one `Completed:` line belongs in the --device --split-file \
         log:\n{sbody}"
    );
    // The other two stamps must still be there: a single `Completed:` would
    // also be satisfied by a branch that had stopped stamping the rest.
    for stamp in ["Started:", "Acquisition Complete:"] {
        assert!(
            sbody.contains(stamp),
            "the device split branch must still stamp `{stamp}`:\n{sbody}"
        );
    }

    // The non-split device tail, for the same count. Two sites for one concept
    // are only safe while both are exercised.
    let whole = dir.path().join("device_whole.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--device")
        .arg(&raw)
        .arg("--output")
        .arg(&whole)
        .assert()
        .success();

    let wbody = std::fs::read_to_string(dir.path().join("device_whole_log.txt")).unwrap();
    assert_eq!(
        wbody.matches("Completed:").count(),
        1,
        "exactly one `Completed:` line belongs in the --device log:\n{wbody}"
    );
}

/// Progress never reaches a redirected stderr.
///
/// `assert_cmd` captures stderr, so it is not a terminal here, which is
/// exactly the condition the painter checks.
#[test]
fn logical_progress_is_suppressed_when_stderr_is_not_a_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"hello\n").unwrap();

    let out = dir.path().join("logical.aff4");
    let assert = aff4tools()
        .arg("acquire")
        .arg("--logical")
        .arg(&tree)
        .arg("--output")
        .arg(&out)
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        !stderr.contains('\r'),
        "a redirected stderr must carry no carriage returns:\n{stderr}"
    );
}

/// Read one container's volume ARN, from `container.description` (§5.4: the
/// first member stored, and the one place the ARN appears unencoded).
fn read_volume_arn(path: &std::path::Path) -> String {
    let file = std::fs::File::open(path).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut zip.by_name("container.description").unwrap(), &mut buf)
        .unwrap();
    buf
}

/// Blank out every `xsd:dateTime` literal's value, leaving its shape in place.
///
/// `birthTime`, `lastWritten`, `lastAccessed`, and `recordChanged` are read
/// from the filesystem at acquisition time, wall-clock samples rather than
/// content. Two separate acquisitions of the same tree — with or without
/// `--scan-first` — are entitled to disagree on them by a second or two,
/// since each is a fresh `stat` taken at a different moment (and the extra
/// pass `--scan-first` makes over the tree can itself nudge `atime`). None of
/// that bears on whether the two runs wrote the same ARNs, triples, child
/// edges, and order, which is the property under test.
fn mask_datetimes(turtle: &str) -> String {
    let marker = "\"^^xsd:dateTime";
    let mut out = String::with_capacity(turtle.len());
    let mut rest = turtle;
    while let Some(marker_pos) = rest.find(marker) {
        let before_marker = &rest[..marker_pos];
        let quote_start = before_marker
            .rfind('"')
            .expect("dateTime literal opens with '\"'");
        out.push_str(&before_marker[..quote_start]);
        out.push_str("\"TIMESTAMP\"^^xsd:dateTime");
        rest = &rest[marker_pos + marker.len()..];
    }
    out.push_str(rest);
    out
}

/// Read one container's `information.turtle`, with its own volume ARN and
/// every timestamp normalized away.
///
/// Each acquisition mints a fresh random UUID for its volume ARN (see
/// `new_uuid` in `src/write/container_writer.rs`), so two acquisitions of the
/// same tree never produce byte-identical turtle even when every triple they
/// assert is the same. Substituting the ARN out, and masking timestamps per
/// [`mask_datetimes`], is what makes the comparison test the property that
/// actually matters: same ARNs, same triples, same child edges, same order.
fn read_normalized_turtle(path: &std::path::Path) -> String {
    let volume_arn = read_volume_arn(path);
    let file = std::fs::File::open(path).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut zip.by_name("information.turtle").unwrap(), &mut buf)
        .unwrap();
    mask_datetimes(&buf.replace(&volume_arn, "aff4://VOLUME"))
}

/// `--scan-first` produces the same container as the default path: same ARNs,
/// same triples, same child edges, same order. Only *when* discovery happens
/// changes, never *what* is written.
#[test]
fn scan_first_produces_the_same_container() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("a.txt"), b"hello\n").unwrap();
    std::fs::write(tree.join("sub").join("b.txt"), b"nested\n").unwrap();

    let default_out = dir.path().join("default.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--logical")
        .arg(&tree)
        .arg("--output")
        .arg(&default_out)
        .assert()
        .success();

    let scanned_out = dir.path().join("scanned.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--logical")
        .arg(&tree)
        .arg("--scan-first")
        .arg("--output")
        .arg(&scanned_out)
        .assert()
        .success();

    // Both verify clean, which is the property that matters most.
    for container in [&default_out, &scanned_out] {
        aff4tools().arg("verify").arg(container).assert().success();
    }

    // And the turtle itself is identical once each container's own random
    // volume ARN is normalized away: same subjects, same triples, same
    // ordering.
    let default_turtle = read_normalized_turtle(&default_out);
    let scanned_turtle = read_normalized_turtle(&scanned_out);
    assert_eq!(
        default_turtle, scanned_turtle,
        "--scan-first must change only when discovery happens, not what is written"
    );
}

/// `--scan-first` is rejected outside `--logical`.
#[test]
fn scan_first_requires_logical() {
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join("source.dd");
    std::fs::write(&raw, vec![0u8; 1024]).unwrap();

    aff4tools()
        .arg("acquire")
        .arg("--image")
        .arg(&raw)
        .arg("--scan-first")
        .arg("--output")
        .arg(dir.path().join("out.aff4"))
        .assert()
        .failure();
}

/// `--scan-first`'s "Scanned:" line reports a fact — a file count — never an
/// estimated total. The scanner's cost figure (`cost_of` in
/// `src/write/scan.rs`) adds a synthetic per-file overhead for progress
/// display and is not a byte count; rendering it as one would put an
/// estimated total in the acquisition log, which the plan forbids.
///
/// Empty files make the point sharply: any byte figure derived from the
/// synthetic cost is provably wrong here, since the true acquired total is
/// zero.
#[test]
fn scan_first_log_reports_no_estimated_total() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for i in 0..300 {
        std::fs::write(tree.join(format!("f{i}.txt")), b"").unwrap();
    }

    let out = dir.path().join("out.aff4");
    aff4tools()
        .arg("acquire")
        .arg("--logical")
        .arg(&tree)
        .arg("--scan-first")
        .arg("--output")
        .arg(&out)
        .assert()
        .success();

    let log = std::fs::read_to_string(dir.path().join("out_log.txt")).unwrap();
    assert!(
        log.contains("Scanned:     300 file(s)"),
        "the scan's file count is a fact worth recording:\n{log}"
    );
    // A byte figure next to "Scanned:" would be the estimated total the
    // review flagged: the scanner's cost model adds a synthetic per-file
    // overhead, so any such figure here would be provably wrong against the
    // 0 real bytes these empty files hold.
    for line in log.lines() {
        if line.starts_with("Scanned:") {
            assert!(
                !line.contains('B') && !line.contains("iB"),
                "the acquisition log must carry no estimated total, only the \
                 file count:\n{line}"
            );
        }
    }
    assert!(
        log.contains("Acquired:    300 file(s), 1 folder(s), 0 B"),
        "the real acquired total is 0 bytes for 300 empty files:\n{log}"
    );
}

/// A logical acquisition of paths with spaces must verify and export whole.
///
/// The regression, measured on a real 5.3 GiB acquisition of two macOS
/// applications: `Arn::member_name` re-escaped an ARN path fragment that
/// AFF4-L §3.2 had already escaped, so `%20` became `%2520`. Three name
/// spellings resulted for one file — the ARN's, the small-file writer's, and
/// the stream writer's — and they did not agree.
///
/// What it cost: 312 image streams written under names no reader resolved,
/// 614 recorded digests reported as spanning unreadable bytes, and
/// `export --logical` skipping 44,198 of 91,226 files **while exiting 0**.
///
/// Spaces in both a directory and a file name, above and below the 1 MiB
/// segment threshold, so every combination of storage form and escaped
/// component is covered by one fixture.
#[test]
fn files_with_spaces_in_their_paths_verify_and_export_whole() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("src");
    let spaced = source.join("Plug-In Settings").join("Spring Box");
    std::fs::create_dir_all(&spaced).unwrap();

    // Below the threshold: stored as a ZIP segment.
    std::fs::write(spaced.join("Medium Boutique Spring.pst"), b"small body\n").unwrap();
    std::fs::write(source.join("no-spaces.txt"), b"control\n").unwrap();
    // Above the threshold: stored as an ImageStream, the path that broke.
    let big = vec![b'B'; 1024 * 1024 + 1];
    std::fs::write(spaced.join("Sustained Cymbal.aif"), &big).unwrap();
    std::fs::write(source.join("no-spaces-large.bin"), &big).unwrap();

    let container = dir.path().join("spaces.aff4");
    // Acquisition runs verification itself, so a naming disagreement between
    // the writer and the reader fails here rather than being reported later.
    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&source)
        .arg("--output")
        .arg(&container)
        .assert()
        .success();

    aff4tools()
        .args(["verify"])
        .arg(&container)
        .assert()
        .success();

    let target = dir.path().join("out");
    let assert = aff4tools()
        .args(["export"])
        .arg(&container)
        .arg("--logical")
        .arg(&target)
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        !stdout.contains("skipped"),
        "no file may be skipped, got:\n{stdout}"
    );

    let exported = source.strip_prefix("/").unwrap_or(&source);
    let out_spaced = target
        .join(exported)
        .join("Plug-In Settings")
        .join("Spring Box");
    assert_eq!(
        std::fs::read(out_spaced.join("Medium Boutique Spring.pst")).unwrap(),
        b"small body\n",
        "a segment-stored file with spaces must export"
    );
    assert_eq!(
        std::fs::read(out_spaced.join("Sustained Cymbal.aif")).unwrap(),
        big,
        "a stream-stored file with spaces must export"
    );
}

/// Export must not report success when it could not read part of the evidence.
///
/// `export --logical` counted only what it wrote: a run that skipped 44,198 of
/// 91,226 files printed `Written: 47028 file(s)` and exited 0, so a script
/// gating on the exit code accepted a half-exported set as complete. A tool
/// that drops evidence and calls it success is worse than one that fails
/// loudly — `verify` already returns [`EXIT_UNVERIFIABLE`] for the same
/// underlying condition.
#[test]
fn export_reports_a_failure_when_it_skips_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("a.txt"), b"one\n").unwrap();
    std::fs::write(source.join("b.txt"), b"two\n").unwrap();

    let container = dir.path().join("c.aff4");
    aff4tools()
        .args(["acquire", "--logical"])
        .arg(&source)
        .arg("--output")
        .arg(&container)
        .arg("--no-verify")
        .assert()
        .success();

    // Remove one file's stored bytes, leaving its metadata behind: the export
    // must notice the evidence it cannot read rather than counting the rest.
    let damaged = dir.path().join("damaged.aff4");
    corrupt_member_containing(&container, &damaged, "a.txt");

    let target = dir.path().join("out");
    let assert = aff4tools()
        .args(["export"])
        .arg(&damaged)
        .arg("--logical")
        .arg(&target)
        .assert()
        .failure();

    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Skipped") || combined.contains("skipped"),
        "the count of unread files must be stated, got:\n{combined}"
    );
    // The file that was readable must still have been written: a partial
    // export is more useful than none, provided it says so.
    assert_eq!(
        std::fs::read(
            target
                .join(source.strip_prefix("/").unwrap_or(&source))
                .join("b.txt")
        )
        .unwrap(),
        b"two\n"
    );
}

/// Corrupt one stored member's bytes in place, leaving the metadata intact.
///
/// Writing a replacement container would need `zip::ZipWriter`, which
/// `clippy.toml` denies for good reason. Overwriting the member's compressed
/// body byte-for-byte keeps the archive structurally valid while making that
/// one file unreadable — which is the condition under test.
fn corrupt_member_containing(from: &std::path::Path, to: &std::path::Path, needle: &str) {
    let data = std::fs::read(from).unwrap();
    std::fs::write(to, &data).unwrap();

    let reader = std::io::Cursor::new(data.clone());
    let mut archive = zip::ZipArchive::new(reader).unwrap();
    let mut ranges = Vec::new();
    for i in 0..archive.len() {
        let entry = archive.by_index(i).unwrap();
        if entry.name().contains(needle) {
            let start = usize::try_from(entry.data_start().unwrap()).unwrap();
            let len = usize::try_from(entry.compressed_size()).unwrap();
            if len > 0 {
                ranges.push((start, len));
            }
        }
    }
    assert!(!ranges.is_empty(), "no member matched {needle:?}");

    let mut damaged = data;
    for (start, len) in ranges {
        // Not zeroes: a deflate stream of zeroes may still decode. Bytes that
        // cannot begin a valid stream make the read fail rather than succeed
        // with the wrong content.
        for byte in &mut damaged[start..start + len] {
            *byte = 0xFF;
        }
    }
    std::fs::write(to, &damaged).unwrap();
}

/// The usage line must name the source flags. `[OPTIONS] --output <PATH>`
/// alone says an acquisition needs no input, which is the opposite of true.
#[test]
fn acquire_usage_names_the_source_flags() {
    let assert = aff4tools().args(["acquire", "--help"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let usage = stdout
        .lines()
        .find(|l| l.starts_with("Usage:"))
        .expect("acquire --help must print a usage line")
        .to_string();
    for flag in ["--device", "--logical", "--image"] {
        assert!(usage.contains(flag), "usage omits {flag}: {usage}");
    }
    assert!(usage.contains("--output"), "usage omits --output: {usage}");
}

/// Naming no source at all is a usage error, reported by clap against the
/// group rather than by a hand-rolled check after parsing.
#[test]
fn acquire_without_a_source_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let assert = aff4tools()
        .args(["acquire", "--output"])
        .arg(dir.path().join("e.aff4"))
        .assert()
        .code(2);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("--image"),
        "the error must name the source flags: {stderr}"
    );
}

/// The three source flags are mutually exclusive.
#[test]
fn acquire_refuses_two_sources_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("src.dd");
    std::fs::write(&img, vec![0u8; 1024]).unwrap();
    let roots = dir.path().join("roots");
    std::fs::create_dir(&roots).unwrap();

    let assert = aff4tools()
        .args(["acquire", "--image"])
        .arg(&img)
        .arg("--logical")
        .arg(&roots)
        .arg("--output")
        .arg(dir.path().join("e.aff4"))
        .assert()
        .code(2);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("cannot be used with"),
        "expected a conflict error: {stderr}"
    );
}

/// `--logical`-only flags must be refused alongside `--image`, not silently
/// ignored. A bare `requires = "logical"` is satisfied by any member of the
/// conflict set, so each such flag names the conflict directly.
#[test]
fn logical_only_flags_are_refused_with_image() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("src.dd");
    std::fs::write(&img, vec![0u8; 1024]).unwrap();

    for flag in ["--deduplicate", "--scan-first"] {
        let out = dir.path().join(format!("e{}.aff4", flag.len()));
        let assert = aff4tools()
            .args(["acquire", "--image"])
            .arg(&img)
            .arg(flag)
            .arg("--output")
            .arg(&out)
            .assert()
            .code(2);
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
        assert!(
            stderr.contains("cannot be used with"),
            "{flag} was accepted with --image: {stderr}"
        );
        assert!(!out.exists(), "{flag} must not write a container");
    }

    let out = dir.path().join("log.aff4");
    let assert = aff4tools()
        .args(["acquire", "--image"])
        .arg(&img)
        .arg("--log")
        .arg(dir.path().join("acq.txt"))
        .arg("--output")
        .arg(&out)
        .assert()
        .code(2);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("cannot be used with"),
        "--log was accepted with --image: {stderr}"
    );
}

/// Build a split-raw set of `count` segments, each `size` bytes of a distinct
/// filler, and return the directory plus the concatenated expected bytes.
fn split_set(dir: &std::path::Path, stem: &str, count: u32, size: usize) -> Vec<u8> {
    let mut expected = Vec::new();
    for n in 1..=count {
        let filler = vec![u8::try_from(n).unwrap(); size];
        std::fs::write(dir.join(format!("{stem}.{n:03}")), &filler).unwrap();
        expected.extend_from_slice(&filler);
    }
    expected
}

/// Naming the first segment acquires the whole set, with no flag. This is the
/// behavior `--discover-split` used to gate.
#[test]
fn image_discovers_a_split_set_from_its_first_segment() {
    let dir = tempfile::tempdir().unwrap();
    let expected = split_set(dir.path(), "s", 3, 4096);
    let out = dir.path().join("e.aff4");

    aff4tools()
        .args(["acquire", "--image"])
        .arg(dir.path().join("s.001"))
        .arg("--output")
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("3 segment(s)"));

    let raw = dir.path().join("out.raw");
    aff4tools()
        .args(["export"])
        .arg(&out)
        .arg("--output")
        .arg(&raw)
        .assert()
        .success();
    assert_eq!(
        std::fs::read(&raw).unwrap(),
        expected,
        "the exported image must equal every segment concatenated"
    );
}

/// A gap must stop the run. A short set verifies clean, because its digests
/// describe exactly the bytes read, so the omission would never be noticed.
#[test]
fn image_refuses_a_split_set_with_a_gap() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("g.001"), vec![1u8; 1024]).unwrap();
    std::fs::write(dir.path().join("g.003"), vec![3u8; 1024]).unwrap();
    let out = dir.path().join("e.aff4");

    let assert = aff4tools()
        .args(["acquire", "--image"])
        .arg(dir.path().join("g.001"))
        .arg("--output")
        .arg(&out)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(stderr.contains("gap"), "expected a gap error: {stderr}");
    assert!(!out.exists(), "nothing may be written when a gap is found");
}

/// Naming a middle segment must be refused, not read forward from. Discovery
/// reads forward, so it would acquire the tail of the set as the whole image —
/// and that container would verify clean.
#[test]
fn image_refuses_a_segment_that_is_not_the_first() {
    let dir = tempfile::tempdir().unwrap();
    split_set(dir.path(), "s", 3, 1024);
    let out = dir.path().join("e.aff4");

    for segment in ["s.002", "s.003"] {
        let assert = aff4tools()
            .args(["acquire", "--image"])
            .arg(dir.path().join(segment))
            .arg("--output")
            .arg(&out)
            .assert()
            .code(2);
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
        assert!(
            stderr.contains("not the first segment"),
            "{segment} was accepted as a source: {stderr}"
        );
        assert!(!out.exists(), "nothing may be written for {segment}");
    }
}

/// A numeric suffix with no siblings is an ordinary single file, not a set.
#[test]
fn a_lone_numbered_file_is_acquired_as_one_segment() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.001"), vec![0xAB; 2048]).unwrap();

    aff4tools()
        .args(["acquire", "--image"])
        .arg(dir.path().join("x.001"))
        .arg("--output")
        .arg(dir.path().join("e.aff4"))
        .assert()
        .success()
        .stdout(predicate::str::contains("1 segment(s)"));
}

/// The deprecated flag still parses and still acquires, but says it is dead.
/// Breaking a recorded command line would be worse than carrying the flag.
#[test]
fn discover_split_is_deprecated_but_still_works() {
    let dir = tempfile::tempdir().unwrap();
    split_set(dir.path(), "s", 2, 1024);

    let assert = aff4tools()
        .args(["acquire", "--discover-split", "--image"])
        .arg(dir.path().join("s.001"))
        .arg("--output")
        .arg(dir.path().join("e.aff4"))
        .assert()
        .success()
        .stdout(predicate::str::contains("2 segment(s)"));
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("deprecated"),
        "the flag must announce that it does nothing: {stderr}"
    );
}

/// A deprecated flag is hidden from help, so it is not offered to new users.
#[test]
fn discover_split_is_hidden_from_help() {
    let assert = aff4tools().args(["acquire", "--help"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        !stdout.contains("--discover-split"),
        "the deprecated flag must not be advertised"
    );
}
