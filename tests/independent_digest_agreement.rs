//! Gate 5: an independent implementation must compute the *same digests* we do.
//!
//! `tests/cross_tool.rs` is gate 4 — pyaff4 must **accept** what we write. That
//! is weaker than it sounds, because a writer and a reader sharing one
//! misunderstanding pass it, and because it never checks a number.
//!
//! This gate reads containers written by **neither** tool — Evimetry's canonical
//! reference images — and requires aff4tools and pyaff4 to arrive at the same
//! values independently. CLAUDE.md records why that matters: pyaff4 is the only
//! external implementation that recomputes an AFF4 hash at all. Both C++ trees
//! define the hash IRIs and parse recorded digests, but neither recomputes one
//! to compare, so pyaff4 is the sole available oracle.
//!
//! Without this gate, every hash claim rests on aff4tools agreeing with the
//! digest *recorded in the container* plus its own internal consistency. Those
//! are real checks — but if two implementations misread the same field the same
//! way, they both still pass.
//!
//! # The vendored pyaff4 is broken, and the fix is one line
//!
//! All 14 of pyaff4's own hashing tests fail against its own reference images:
//!
//! ```text
//! aff4_image.py:497:  if "AXIOMProcess" in self.version.tool:
//! AttributeError: 'NoneType' object has no attribute 'tool'
//! ```
//!
//! `self.version` is `None` on the validator's path and `.tool` is dereferenced
//! unguarded. Guarding it makes all 14 pass:
//!
//! ```python
//! if self.version is not None and "AXIOMProcess" in self.version.tool:
//! ```
//!
//! That is the **entire** patch, and it must stay that small: a larger one would
//! make the oracle less independent. It changes no digest logic — only whether
//! an unrelated vendor check is reached.
//!
//! # Running these
//!
//! pyaff4's checkout is read-only reference material, so the patch is applied
//! to a copy and named by its own variable:
//!
//! ```sh
//! cp -R "$AFF4_PYAFF4_ROOT" /tmp/pyaff4-patched
//! sed -i '' 's|if "AXIOMProcess" in self.version.tool:|if self.version is not None and "AXIOMProcess" in self.version.tool:|' \
//!     /tmp/pyaff4-patched/pyaff4/aff4_image.py
//!
//! python3 -m venv /tmp/pyaff4env
//! /tmp/pyaff4env/bin/pip install rdflib six future lz4 expiringdict \
//!     intervaltree tzlocal python-dateutil pyyaml pycryptoplus pynacl \
//!     passlib cryptography python-snappy fastchunking pycryptodome
//!
//! AFF4_PYAFF4_PYTHON=/tmp/pyaff4env/bin/python \
//! AFF4_PYAFF4_PATCHED=/tmp/pyaff4-patched \
//!     cargo test --features corpus --test independent_digest_agreement
//! ```
//!
//! **`AFF4_PYAFF4_PATCHED` has no default on purpose.** Pointing it at an
//! unpatched checkout makes every container raise `AttributeError` — a failure
//! that says nothing about aff4tools and would be read as one. Skipping when it
//! is unset follows the corpus-gating rule in `docs/testing.md`: a green run
//! that verified nothing must never pretend otherwise.

#![cfg(feature = "corpus")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use aff4tools::{Container, VerifyOptions};

/// The interpreter that can import pyaff4, or `None` to skip.
fn pyaff4_python() -> Option<PathBuf> {
    let python = PathBuf::from(std::env::var_os("AFF4_PYAFF4_PYTHON")?);
    python.is_file().then_some(python)
}

/// A **patched** pyaff4 checkout, or `None` to skip. No default: see the
/// module docs.
fn pyaff4_patched() -> Option<PathBuf> {
    let root = PathBuf::from(std::env::var_os("AFF4_PYAFF4_PATCHED")?);
    root.join("pyaff4")
        .join("block_hasher.py")
        .is_file()
        .then_some(root)
}

/// Both halves of the harness, or `None` with a loud skip.
fn harness() -> Option<(PathBuf, PathBuf)> {
    match (pyaff4_python(), pyaff4_patched()) {
        (Some(python), Some(root)) => Some((python, root)),
        _ => {
            eprintln!(
                "SKIPPED: set AFF4_PYAFF4_PYTHON and AFF4_PYAFF4_PATCHED (see \
                 module docs). This is the only check that two independent \
                 implementations compute the same digests; a run without it \
                 proves nothing about that."
            );
            None
        }
    }
}

/// The canonical reference images this gate reads.
///
/// `Base-Linear-ReadError.aff4` is included deliberately. It is **not** a
/// corruption fixture: it is a separate acquisition truncated by a read error,
/// carrying its own consistent digests, and it must agree just like the rest.
fn reference_images() -> Vec<PathBuf> {
    // `AFF4_TEST_IMAGES` first, as every other corpus consumer does; the
    // `$HOME` path is only the fallback for an unconfigured working tree.
    // Without the override a clone that keeps its fixtures anywhere else has
    // no way to point this test at them.
    let root = std::env::var_os("AFF4_TEST_IMAGES").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("HOME must be set"))
                .join(".cache/aff4tools/corpus")
        },
        PathBuf::from,
    );
    let base = root.join("pyaff4/test_images/AFF4Std");
    [
        "Base-Linear.aff4",
        "Base-Allocated.aff4",
        "Base-Linear-AllHashes.aff4",
        "Base-Linear-ReadError.aff4",
    ]
    .iter()
    .map(|name| base.join(name))
    .filter(|path| path.is_file())
    .collect()
}

/// Run a pyaff4 snippet against the patched checkout, returning stdout.
fn run_pyaff4(python: &Path, root: &Path, script: &str) -> Result<String, String> {
    let out = std::process::Command::new(python)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", root)
        .output()
        .map_err(|e| format!("could not run {}: {e}", python.display()))?;
    if !out.status.success() {
        return Err(format!(
            "pyaff4 failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// What pyaff4's block validator computed for one container.
struct PyResult {
    /// Per-chunk digests it checked and found valid.
    valid_blocks: usize,
    /// Digests it reported by name, e.g. `BlockMapHash`, `mapIdxHash`.
    named: Vec<(String, String)>,
    /// Digests it found to disagree with the container. Must always be empty.
    invalid: Vec<String>,
}

/// Drive `block_hasher.Validator` over `path`.
fn pyaff4_validate(python: &Path, root: &Path, path: &Path) -> Result<PyResult, String> {
    let script = format!(
        r#"
import sys, warnings
warnings.filterwarnings("ignore")
from pyaff4 import block_hasher, rdfvalue

class Listener(block_hasher.ValidationListener):
    def __init__(self):
        self.valid = 0
        self.named = []
        self.invalid = []
    def onValidBlockHash(self, a):
        self.valid += 1
    def onInvalidBlockHash(self, a, b, uri, offset):
        self.invalid.append("block %s != %s at %s" % (a, b, offset))
    def onValidHash(self, typ, h, uri):
        self.named.append((str(typ), str(h)))
    def onInvalidHash(self, typ, a, b, uri):
        self.invalid.append("%s recorded=%s computed=%s" % (typ, a, b))

listener = Listener()
block_hasher.Validator(listener).validateContainer(
    rdfvalue.URN.FromFileName({path:?}))
print("BLOCKS", listener.valid)
for typ, h in listener.named:
    print("NAMED", typ, h)
for bad in listener.invalid:
    print("INVALID", bad)
"#,
        path = path.to_str().unwrap(),
    );

    let stdout = run_pyaff4(python, root, &script)?;
    let mut result = PyResult {
        valid_blocks: 0,
        named: Vec::new(),
        invalid: Vec::new(),
    };
    for line in stdout.lines() {
        let mut parts = line.splitn(3, ' ');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("BLOCKS"), Some(n), _) => result.valid_blocks = n.parse().unwrap_or(0),
            (Some("NAMED"), Some(typ), Some(value)) => {
                result.named.push((typ.to_owned(), value.to_owned()));
            }
            (Some("INVALID"), Some(rest), tail) => {
                result
                    .invalid
                    .push(format!("{rest} {}", tail.unwrap_or("")));
            }
            _ => {}
        }
    }
    Ok(result)
}

/// pyaff4 and aff4tools must agree, on every canonical reference image.
///
/// Three claims, in increasing strength:
///
/// 1. Neither implementation finds a digest that disagrees with the container.
/// 2. Both check the **same number** of per-chunk block hashes. A disagreement
///    here means the two disagree about chunking or padding, which no
///    single-implementation test can detect.
/// 3. Both compute the same `blockMapHash`. That is a Merkle-style digest over
///    every block-hash segment plus `mapPointHash`, `mapIdxHash`, and
///    `mapPathHash` (v1.0a §6.2), so agreeing on it means agreeing about the
///    whole tree rather than about one number.
#[test]
fn pyaff4_and_aff4tools_compute_the_same_digests() {
    let Some((python, root)) = harness() else {
        return;
    };
    let images = reference_images();
    assert!(!images.is_empty(), "the reference corpus is missing");

    for path in &images {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        // What pyaff4 makes of it.
        let py = pyaff4_validate(&python, &root, path).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            py.invalid.is_empty(),
            "{name}: pyaff4 found a digest that disagrees: {:?}",
            py.invalid
        );
        assert!(
            py.valid_blocks > 0,
            "{name}: pyaff4 validated no block hashes, so nothing was compared"
        );

        // What aff4tools makes of the same bytes.
        let mut container = Container::open(path).unwrap();
        let report =
            aff4tools::verify_container(&mut container, VerifyOptions { block_hashes: true })
                .unwrap();
        assert!(
            !report.has_mismatch(),
            "{name}: aff4tools found a mismatch, which the corpus must never have"
        );

        // 2. The same number of per-chunk digests, for the algorithms both
        //    implementations verify.
        //
        //    aff4tools recomputes per-chunk MD5 and SHA-1 only, which
        //    `--no-block-hashing`'s help text states plainly. pyaff4 recomputes
        //    every algorithm the container carries. On `Base-Linear-AllHashes`
        //    — five algorithms over 121 chunks — that is 242 against 605, and
        //    comparing the raw totals would report a chunking disagreement
        //    where there is none.
        //
        //    So the comparison is scaled to the algorithms in common. Both
        //    tools must agree about how many *chunks* there are, which is the
        //    property worth cross-checking; that aff4tools covers fewer
        //    algorithms is a known limit, pinned by
        //    `aff4tools_verifies_md5_and_sha1_chunks_only` below.
        let shared = shared_block_hash_algorithms(path);
        let ours = report.chunk_digest_count();
        let ours_chunks = ours.checked_div(shared.ours).unwrap_or(0);
        let their_chunks = py.valid_blocks.checked_div(shared.theirs).unwrap_or(0);
        assert_eq!(
            ours_chunks, their_chunks,
            "{name}: chunk counts differ — aff4tools saw {ours_chunks} chunks \
             ({ours} digests over {} algorithm(s)), pyaff4 saw {their_chunks} \
             ({} digests over {} algorithm(s)). The two disagree about chunking.",
            shared.ours, py.valid_blocks, shared.theirs
        );

        // 3. The same blockMapHash.
        let Some((_, py_bmh)) = py
            .named
            .iter()
            .find(|(typ, _)| typ.eq_ignore_ascii_case("BlockMapHash"))
        else {
            panic!("{name}: pyaff4 reported no BlockMapHash");
        };
        let ours_bmh = recomputed_block_map_hash(&report)
            .unwrap_or_else(|| panic!("{name}: aff4tools recomputed no blockMapHash"));
        assert_eq!(
            &ours_bmh, py_bmh,
            "{name}: blockMapHash differs between implementations"
        );

        eprintln!(
            "{name}: {ours} block hashes and blockMapHash {} agree",
            &ours_bmh[..16]
        );
    }
}

/// The `blockMapHash` aff4tools recomputed, lowercase hex.
///
/// Taken from the recomputed side rather than the recorded one: a test that
/// compared pyaff4's computation against the value *written in the file* would
/// pass even if aff4tools computed nothing at all.
fn recomputed_block_map_hash(report: &aff4tools::VerificationReport) -> Option<String> {
    report
        .checks
        .iter()
        .filter(|check| {
            check
                .predicate
                .to_ascii_lowercase()
                .contains("blockmaphash")
                && check.outcome == aff4tools::Outcome::Match
        })
        .map(|check| check.actual.clone())
        .find(|actual| !actual.is_empty())
}

/// A digest neither implementation checks is worth naming, so nobody assumes
/// this gate covers it.
///
/// `imageStreamHash` appears in every Evimetry container and in **no**
/// specification or implementation: not in Standard v1.0a, not in pyaff4, not
/// in c-aff4, not in aff4-cpp-lite. pyaff4's validator silently skips it;
/// aff4tools reports it as unrecomputed rather than pretending. This test pins
/// that asymmetry so a future change cannot quietly claim to verify it.
#[test]
fn image_stream_hash_is_recorded_by_evimetry_and_checked_by_nobody() {
    let Some((python, root)) = harness() else {
        return;
    };
    let path = reference_images()
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == "Base-Linear.aff4"))
        .expect("Base-Linear.aff4 must be present");

    // It is in the container.
    let mut container = Container::open(&path).unwrap();
    let summary = container.summarize().unwrap();
    let recorded = summary
        .objects
        .iter()
        .flat_map(|object| object.hashes.iter())
        .any(|hash| hash.predicate.eq_ignore_ascii_case("imageStreamHash"));
    assert!(recorded, "Base-Linear.aff4 must record an imageStreamHash");

    // pyaff4 does not report it.
    let py = pyaff4_validate(&python, &root, &path).unwrap();
    assert!(
        !py.named
            .iter()
            .any(|(typ, _)| typ.to_ascii_lowercase().contains("imagestreamhash")),
        "pyaff4 now checks imageStreamHash; this gate's scope should be revisited"
    );

    // Nor does the term appear anywhere in pyaff4's source.
    let hits = std::process::Command::new("grep")
        .args(["-rl", "imageStreamHash"])
        .arg(root.join("pyaff4"))
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default();
    assert!(
        hits.is_empty(),
        "pyaff4 now mentions imageStreamHash in {hits}"
    );
}

/// How many block-hash algorithms each implementation recomputes for a
/// container.
struct AlgorithmCoverage {
    /// Algorithms aff4tools recomputes per chunk: MD5 and SHA-1, when present.
    ours: usize,
    /// Algorithms pyaff4 recomputes per chunk: every one the container carries.
    theirs: usize,
}

/// Count the block-hash segments in `path`, split by what each tool covers.
fn shared_block_hash_algorithms(path: &Path) -> AlgorithmCoverage {
    #[allow(clippy::disallowed_methods)]
    let file = std::fs::File::open(path).unwrap();
    let archive = zip::ZipArchive::new(file).unwrap();
    let suffixes: Vec<String> = archive
        .file_names()
        .filter_map(|name| name.rsplit_once(".blockHash.").map(|(_, s)| s.to_owned()))
        .collect();

    let mut distinct: Vec<String> = suffixes;
    distinct.sort();
    distinct.dedup();

    let ours = distinct
        .iter()
        .filter(|s| s.eq_ignore_ascii_case("md5") || s.eq_ignore_ascii_case("sha1"))
        .count();
    AlgorithmCoverage {
        ours,
        theirs: distinct.len(),
    }
}

/// aff4tools recomputes per-chunk digests for MD5 and SHA-1 only, and this
/// pins that limit rather than letting it drift unnoticed.
///
/// `Base-Linear-AllHashes.aff4` carries five block-hash algorithms — md5,
/// sha1, sha256, sha512, blake2b — over 121 chunks. pyaff4 recomputes all 605;
/// aff4tools recomputes 242. `BlockDigests` in `src/verify.rs` has fields for
/// two algorithms and no more.
///
/// **This is a coverage limit, not a correctness bug, and the CLI says so**:
/// `--no-block-hashing`'s help describes "per-chunk MD5 and SHA-1
/// verification". The `blockHashesHash` over each of the other three segments
/// *is* recomputed and compared, so a tampered sha256 segment is still caught —
/// what is not checked is whether each individual sha256 chunk digest describes
/// its chunk.
///
/// If aff4tools ever recomputes all five, this test fails and should be
/// deleted, and the scaling in `pyaff4_and_aff4tools_compute_the_same_digests`
/// becomes unnecessary.
#[test]
fn aff4tools_verifies_md5_and_sha1_chunks_only() {
    let path = reference_images()
        .into_iter()
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n == "Base-Linear-AllHashes.aff4")
        })
        .expect("Base-Linear-AllHashes.aff4 must be present");

    let coverage = shared_block_hash_algorithms(&path);
    assert_eq!(coverage.theirs, 5, "the fixture must carry five algorithms");
    assert_eq!(coverage.ours, 2, "aff4tools covers md5 and sha1");

    let mut container = Container::open(&path).unwrap();
    let report =
        aff4tools::verify_container(&mut container, VerifyOptions { block_hashes: true }).unwrap();
    assert!(!report.has_mismatch());
    assert_eq!(
        report.chunk_digest_count(),
        242,
        "121 chunks x 2 algorithms; if this grew, coverage improved"
    );
}

/// pyaff4 must read back out of *our* container exactly the bytes that went in.
///
/// The tests above read containers Evimetry wrote. This one closes the loop:
/// aff4tools acquires a known source, and pyaff4 — which shares no code with us
/// — traverses the map we wrote, locates the bevies, decompresses the chunks,
/// reassembles the image, and digests it. Agreement with the *source file's*
/// digest is the end-to-end claim, and neither tool computed the value being
/// compared against.
///
/// Uses `LinearHasher`, not `block_hasher.Validator`. The validator needs an
/// `aff4:blockMapHash`, which aff4tools deliberately does not write: our maps
/// hold one entry against one stored stream, so there are no synthetic chunks
/// for it to protect. The linear hasher needs only a readable map and stream.
#[test]
fn pyaff4_reads_back_what_we_acquired() {
    let Some((python, root)) = harness() else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.dd");
    let container = dir.path().join("ours.aff4");

    // Incompressible, so the codec cannot mask a chunking error by producing
    // identical output for different input.
    let data: Vec<u8> = {
        let mut out = Vec::with_capacity(400_000);
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        while out.len() < 400_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(400_000);
        out
    };
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&source, &data).unwrap();

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["acquire", "--image"])
        .arg(&source)
        .arg("--output")
        .arg(&container)
        .status()
        .unwrap();
    assert!(status.success(), "acquisition failed");

    // The map ARN comes from the container, never hardcoded: a wrong ARN would
    // hash the wrong object and the test would pass for the wrong reason.
    let mut volume = aff4tools::zip::ZipVolume::open(&container).unwrap();
    let turtle = String::from_utf8(
        aff4tools::zip::Volume::read_segment(&mut volume, "information.turtle").unwrap(),
    )
    .unwrap();
    let map_arn = turtle
        .split('<')
        .filter_map(|rest| rest.split_once('>').map(|(iri, _)| iri))
        .find(|iri| iri.starts_with("aff4://") && iri.ends_with("/map"))
        .expect("the container must declare a map")
        .to_owned();

    // What the source actually is, computed here rather than taken from the
    // container: comparing pyaff4 against a value aff4tools recorded would only
    // prove the two agree with each other.
    let expected_sha1 = hex(&<sha1::Sha1 as sha1::Digest>::digest(&data));
    let expected_md5 = hex(&<md5::Md5 as md5::Digest>::digest(&data));

    for (algorithm, expected) in [("sha1", &expected_sha1), ("md5", &expected_md5)] {
        let script = format!(
            r#"
import warnings
warnings.filterwarnings("ignore")
from pyaff4 import linear_hasher, lexicon, rdfvalue
alg = {{"sha1": lexicon.HASH_SHA1, "md5": lexicon.HASH_MD5}}[{algorithm:?}]
h = linear_hasher.LinearHasher().hash(
    rdfvalue.URN.FromFileName({path:?}), {map_arn:?}, alg)
print("DIGEST", h.value)
"#,
            algorithm = algorithm,
            path = container.to_str().unwrap(),
            map_arn = map_arn,
        );

        let stdout =
            run_pyaff4(&python, &root, &script).unwrap_or_else(|e| panic!("{algorithm}: {e}"));
        let got = stdout
            .lines()
            .find_map(|line| line.strip_prefix("DIGEST "))
            .unwrap_or_default()
            .trim();

        assert_eq!(
            got, expected,
            "{algorithm}: pyaff4 read different bytes out of our container than \
             we put in.\n  source:  {expected}\n  pyaff4:  {got}"
        );
        eprintln!("pyaff4 {algorithm} over our map: {got} (matches the source)");
    }
}

/// Lowercase hex, the form AFF4 records digests in.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
