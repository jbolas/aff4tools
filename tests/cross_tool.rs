//! Gate 4: an independent implementation must accept what we write.
//!
//! Gates 1-3 (`tests/write_roundtrip.rs`) only prove aff4tools is
//! self-consistent — a writer and reader sharing one misunderstanding pass all
//! three. pyaff4 shares no code with us and is the only external implementation
//! that verifies AFF4 hashes, so it is the authority on whether our output is
//! really AFF4.
//!
//! # Running these
//!
//! pyaff4 is a Python library outside this repo with a long dependency chain
//! (rdflib, six, future, lz4, snappy, expiringdict, pycryptoplus, pynacl,
//! passlib, cryptography, pyyaml). Rather than assume an environment, these
//! tests are **skipped unless `AFF4_PYAFF4_PYTHON` names an interpreter that
//! can import pyaff4**:
//!
//! ```sh
//! python3 -m venv /tmp/pyaff4env
//! /tmp/pyaff4env/bin/pip install rdflib six future lz4 python-snappy \
//!     expiringdict pycryptoplus pynacl passlib cryptography pyyaml \
//!     intervaltree tzlocal python-dateutil fastchunking pycryptodome
//! AFF4_PYAFF4_PYTHON=/tmp/pyaff4env/bin/python cargo test --test cross_tool
//! ```
//!
//! Skipping rather than failing is deliberate, and follows the corpus-gating
//! rule in `docs/testing.md`: a green run without the variable proves nothing
//! about interoperability and must not pretend otherwise. The skip is loud.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use aff4tools::write::container_writer::ContainerWriter;
use aff4tools::write::guard::SourceRegistry;

/// The interpreter that can import pyaff4, or `None` to skip.
fn pyaff4_python() -> Option<PathBuf> {
    let python = PathBuf::from(std::env::var_os("AFF4_PYAFF4_PYTHON")?);
    python.is_file().then_some(python)
}

/// Where pyaff4's source lives, from `AFF4_PYAFF4_ROOT`.
///
/// No default: pyaff4 is a separate project that may be checked out anywhere,
/// and guessing a path would report a confusing missing-file error instead of
/// saying which variable to set.
fn pyaff4_root() -> Option<PathBuf> {
    std::env::var_os("AFF4_PYAFF4_ROOT").map(PathBuf::from)
}

/// Run a pyaff4 snippet, returning stdout on success.
fn run_pyaff4(python: &Path, script: &str) -> Result<String, String> {
    let out = std::process::Command::new(python)
        .arg("-c")
        .arg(script)
        .output()
        .map_err(|e| format!("could not run {}: {e}", python.display()))?;
    if !out.status.success() {
        return Err(format!(
            "pyaff4 rejected our container:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// pyaff4 must open a container we wrote, identify its generation, and agree
/// on its volume ARN.
#[test]
fn pyaff4_opens_a_container_we_wrote() {
    let Some(python) = pyaff4_python() else {
        eprintln!(
            "SKIPPED: set AFF4_PYAFF4_PYTHON to an interpreter that can import \
             pyaff4. This test is the only external check on our output; a run \
             without it proves nothing about interoperability."
        );
        return;
    };
    let Some(root) = pyaff4_root() else {
        eprintln!("SKIPPED: set AFF4_PYAFF4_ROOT to pyaff4's source tree.");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("written.aff4");
    let registry = SourceRegistry::new();

    let writer = ContainerWriter::create(&path, &registry).unwrap();
    let expected_arn = writer.volume_arn().as_str().to_owned();
    writer.finish().unwrap();

    let script = format!(
        "import sys\n\
         sys.path.insert(0, {root:?})\n\
         from pyaff4 import container, rdfvalue\n\
         urn = rdfvalue.URN.FromFileName({path:?})\n\
         version, lex = container.Container.identifyURN(urn)\n\
         print('LEXICON', type(lex).__name__)\n\
         print('MAJOR', version.major)\n\
         print('MINOR', version.minor)\n\
         with container.Container.openURNtoContainer(urn) as vol:\n\
         \x20   print('ARN', vol.urn)\n",
        root = root.to_string_lossy(),
        path = path.to_string_lossy(),
    );

    let stdout = match run_pyaff4(&python, &script) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };

    assert!(
        stdout.contains(&format!("ARN {expected_arn}")),
        "pyaff4 read a different volume ARN than we wrote.\nexpected: \
         {expected_arn}\ngot:\n{stdout}"
    );
    // `ContainerWriter::create` declares a physical image, which is v1.0: the
    // minor version is a feature marker, and a physical container carries no
    // v1.1 vocabulary. A logical acquisition declares v1.1 and would dispatch
    // to `Std11Lexicon` instead — see
    // `write_roundtrip::the_minor_version_states_which_vocabulary_is_used`.
    assert!(
        stdout.contains("MAJOR 1") && stdout.contains("MINOR 0"),
        "pyaff4 must see the v1.0 we declared for a physical image:\n{stdout}"
    );
    // Dispatching to the v1.0 lexicon is what lets pyaff4's hash validator run
    // at all: `block_hasher.Validator` handles `lexicon.standard` and
    // `lexicon.legacy`, and raises `ValueError` on `standard11`.
    assert!(
        stdout.contains("StdLexicon") && !stdout.contains("Std11Lexicon"),
        "pyaff4 must dispatch to the Standard v1.0 lexicon:\n{stdout}"
    );
}

/// pyaff4 must classify a container we wrote as a *physical image* and find
/// the `DiskImage` by ARN.
///
/// This is what the Map and `aff4:Image` object buy: before they were written,
/// pyaff4 opened our containers as logical ones holding zero images. It now
/// behaves exactly as it does with Evimetry's containers.
///
/// Note it still cannot *read* the image bytes — `AFF4FactoryOpen` raises
/// `Unable to create object` — but it raises the identical error on Evimetry's
/// own `Base-Linear.aff4`, so that is a pyaff4 limitation and not a property of
/// our output.
#[test]
fn pyaff4_sees_our_container_as_a_physical_image() {
    let Some(python) = pyaff4_python() else {
        eprintln!("SKIPPED: set AFF4_PYAFF4_PYTHON (see module docs)");
        return;
    };
    let Some(root) = pyaff4_root() else {
        eprintln!("SKIPPED: set AFF4_PYAFF4_ROOT to pyaff4's source tree.");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("image.aff4");
    let locus = aff4tools::Locus::new(&out);
    let registry = SourceRegistry::new();

    let data: Vec<u8> = (0..50_000u32)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();

    let mut writer = ContainerWriter::create(&out, &registry).unwrap();
    let stream = aff4tools::write::stream_writer::write_image_stream(
        &mut writer,
        &mut data.as_slice(),
        aff4tools::write::stream_writer::StreamOptions::default(),
        &[aff4tools::model::HashAlgorithm::Sha256],
        &locus,
    )
    .unwrap();
    let entries = [aff4tools::write::map_writer::MapEntry {
        mapped_offset: 0,
        length: stream.size,
        target_offset: 0,
        target_id: 0,
    }];
    let mapped = aff4tools::write::map_writer::write_map(
        &mut writer,
        &entries,
        std::slice::from_ref(&stream.arn),
        stream.size,
        &locus,
    )
    .unwrap();
    writer.finish().unwrap();

    let script = format!(
        "import sys, os\nsys.path.insert(0, {root:?})\nfrom pyaff4 import container, rdfvalue\nvol = container.Container.openURNtoContainer(rdfvalue.URN.FromFileName({path:?}))\nprint('CLASS', type(vol).__name__)\nprint('IMAGE', vol.image.urn)\nsys.stdout.flush()\nos._exit(0)\n",
        root = root.to_string_lossy(),
        path = out.to_string_lossy(),
    );

    let stdout = match run_pyaff4(&python, &script) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };

    assert!(
        stdout.contains("CLASS PhysicalImageContainer"),
        "pyaff4 must see a physical image, not a logical container:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("IMAGE {}", mapped.image_arn)),
        "pyaff4 must find our DiskImage by ARN.\nexpected {}\ngot:\n{stdout}",
        mapped.image_arn
    );
}
