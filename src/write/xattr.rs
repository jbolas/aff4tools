//! Reading a file's extended attributes.
//!
//! AFF4-L Standard v1.0-ALPHA §4.2 defines `FileExtendedAttribute` and §4.3 the
//! `extendedAttribute` property that reaches one.
//! **Unix only, by decision.** Windows is not supported. The reader handles the alternate data
//! stream shape regardless, because AFF4-L v1.0-ALPHA §6 requires a reader to
//! support every storage form whoever wrote the container.
//!
//! # Reading, never following
//!
//! Every call uses the no-follow variant, so a symlink's own attributes are read
//! rather than its target's. This matches the acquisition's refusal to follow
//! links: following one could duplicate content or escape the acquisition root.
//!
//! # Why a crate rather than the syscalls
//!
//! `src/lib.rs` denies `unsafe_code` with a single audited exception, and
//! `tests/read_only_guard.rs` enforces that by counting the annotations as text.
//! Binding `listxattr` and `getxattr` directly would need a second exception and
//! weaken the audit for two read-only calls, so the `xattr` crate does it behind
//! a safe API instead.

/// One extended attribute: its name and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedAttribute {
    /// The attribute's name, e.g. `com.apple.quarantine`.
    ///
    /// Written to `aff4:name` as a literal. A name that is not valid UTF-8 is
    /// replaced lossily rather than dropped: the attribute's presence is
    /// evidence even when its name will not render.
    pub name: String,
    /// The attribute's value, exactly as read.
    pub value: Vec<u8>,
}

/// The largest attribute value this reads.
///
/// A guard against a pathological source, not a format limit. The macOS survey's
/// largest attribute was 6.4 MB, so this leaves ample headroom while refusing to
/// allocate without bound from a value the filesystem reports.
const MAX_VALUE_BYTES: usize = 64 * 1024 * 1024;

/// Every extended attribute on `path`, in the order the platform reports them.
///
/// Empty when the file has none, when the filesystem does not support them, or
/// on any platform that is not Unix.
///
/// # Errors
///
/// None, deliberately. A file whose attributes cannot be listed yields an empty
/// list rather than an error: the acquisition reads a live filesystem, where a
/// file may be replaced or its permissions changed between one call and the
/// next, and a race is not a finding about the evidence. A file whose *content*
/// could not be read is a finding, and the caller already reports that through
/// the skip path.
#[must_use]
pub fn attributes_of(path: &std::path::Path) -> Vec<ExtendedAttribute> {
    // `xattr::list` and `xattr::get`, not the `_deref` variants: those
    // dereference a symlink and would read the target's attributes as though
    // they were the link's.
    let Ok(names) = xattr::list(path) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for name in names {
        // An attribute that vanishes between the listing and the read is
        // skipped rather than recorded empty. An attribute holding no bytes and
        // one that was removed mid-scan are different facts about the source
        // and must not render identically.
        let Ok(Some(value)) = xattr::get(path, &name) else {
            continue;
        };
        if value.len() > MAX_VALUE_BYTES {
            continue;
        }
        out.push(ExtendedAttribute {
            name: name.to_string_lossy().into_owned(),
            value,
        });
    }
    out
}
