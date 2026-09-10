//! Extended attributes are detected and acquired.
//!
//! AFF4-L Standard v1.0-ALPHA §4.2 defines `FileExtendedAttribute` and §4.3 the
//! `extendedAttribute` property reaching one. Before Phase 9 a logical
//! acquisition never asked the filesystem whether a file had any, so every
//! attribute was omitted with nothing in the output to say so.
//!
//! Detection is Unix only, by decision: Windows is not a supported platform and
//! NTFS alternate data streams do not exist on the platforms that are.

#![cfg(unix)]
// Fixture trees are built in temp dirs, which needs the file constructors the
// library itself is denied. `tests/read_only_guard.rs` scans `src/` only, so
// this relaxation cannot reach library code.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

/// Set an attribute, or report that this filesystem will not take one.
///
/// A temp directory may sit on a filesystem without attribute support. Skipping
/// is honest there; asserting would test the filesystem rather than the code.
fn set_attr(path: &Path, name: &str, value: &[u8]) -> bool {
    xattr::set(path, name, value).is_ok()
}

#[test]
fn an_extended_attribute_is_read_from_a_file() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("subject.txt");
    std::fs::write(&path, b"content").expect("write the source file");

    if !set_attr(&path, "user.note", b"hello") {
        return;
    }

    let attrs = aff4tools::write::xattr::attributes_of(&path);
    assert!(
        attrs
            .iter()
            .any(|a| a.name.contains("note") && a.value == b"hello"),
        "expected the attribute, got {attrs:?}"
    );
}

/// A file carries only what is actually on it.
///
/// Deliberately not asserted as "empty": macOS attaches `com.apple.provenance`
/// to newly written files, so a test demanding none would fail on the platform
/// this feature exists for. What must hold is that nothing is invented — no
/// attribute this test did not set appears with a name it chose.
#[test]
fn a_file_reports_only_the_attributes_it_carries() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("plain.txt");
    std::fs::write(&path, b"content").expect("write the source file");

    let attrs = aff4tools::write::xattr::attributes_of(&path);
    assert!(
        !attrs.iter().any(|a| a.name.contains("user.")),
        "no user attribute was set, so none may be reported: {attrs:?}"
    );
    // Whatever the platform put there, each entry is well formed.
    for a in &attrs {
        assert!(!a.name.is_empty(), "an attribute name must not be empty");
    }
}

/// Several attributes on one file all come back. The macOS survey found files
/// carrying up to seven.
#[test]
fn every_attribute_on_a_file_is_returned() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("many.txt");
    std::fs::write(&path, b"content").expect("write the source file");

    if !set_attr(&path, "user.one", b"1") {
        return;
    }
    set_attr(&path, "user.two", b"22");
    set_attr(&path, "user.three", b"333");

    let attrs = aff4tools::write::xattr::attributes_of(&path);
    assert!(attrs.len() >= 3, "expected three attributes, got {attrs:?}");
}

/// An attribute holding no bytes is a fact about the file, distinct from one
/// that could not be read, and it is recorded rather than dropped.
#[test]
fn an_empty_attribute_is_recorded_not_dropped() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("empty-attr.txt");
    std::fs::write(&path, b"content").expect("write the source file");

    if !set_attr(&path, "user.empty", b"") {
        return;
    }

    let attrs = aff4tools::write::xattr::attributes_of(&path);
    assert!(
        attrs
            .iter()
            .any(|a| a.name.contains("empty") && a.value.is_empty()),
        "an empty attribute must still appear: {attrs:?}"
    );
}

/// A symlink's own attributes are read, never its target's. The acquisition
/// refuses to follow a link, and reading through one here would attribute the
/// target's metadata to the link.
#[test]
fn a_symlink_is_not_followed() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let target = dir.path().join("target.txt");
    let link = dir.path().join("link.txt");
    std::fs::write(&target, b"content").expect("write the source file");
    std::os::unix::fs::symlink(&target, &link).expect("create the symlink");

    if !set_attr(&target, "user.target", b"on the target") {
        return;
    }

    // Asking the link must not return the target's attribute. The platform may
    // have put attributes of its own on the link, which is why this tests for
    // the specific name rather than for emptiness.
    let attrs = aff4tools::write::xattr::attributes_of(&link);
    assert!(
        !attrs.iter().any(|a| a.name.contains("user.target")),
        "the target's attribute must not be read through the link: {attrs:?}"
    );
}

/// A path that does not exist yields nothing rather than failing. The source is
/// live, and a file removed between the scan and the read is a race, not a
/// finding about the evidence.
#[test]
fn a_missing_path_yields_no_attributes() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("never-created.txt");
    assert!(aff4tools::write::xattr::attributes_of(&path).is_empty());
}
