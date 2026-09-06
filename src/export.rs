//! Writing a container's contents back out: raw images, and logical files.
//!
//! The complement of acquisition. Two shapes:
//!
//! - A `DiskImage` is written as the raw (dd) image it carries, which is what
//!   `losetup`, `hdiutil attach`, and `disktype` consume.
//! - An AFF4-L is written as the files and folders it holds.
//!
//! # Placing a logical file is a security boundary
//!
//! An AFF4-L records the acquiring machine's own paths. The corpus proves this
//! is not hypothetical: `broken-dedupe.aff4` carries
//! `/Users/bradley/git/pyaff4/…`, an absolute path from someone else's laptop.
//! Written verbatim that escapes any target directory.
//!
//! [`rebase`] therefore reproduces the recorded hierarchy **beneath** the
//! target — `<target>/Users/bradley/git/…` — which keeps the structure an
//! examiner needs while making escape structurally impossible. Components that
//! cannot be reproduced (a `..`, a drive letter, a control character) are
//! sanitized and **reported**, never silently dropped: an unreported alteration
//! is the same as a lossy conversion.
//!
//! The mapping is pure and lives here so it can be tested without a container,
//! because it is the part that must not be wrong.

use std::path::{Component, Path, PathBuf};

use crate::model::Aff4Object;
use crate::rdf::Value;

/// The four AFF4-L filesystem timestamps, as the container recorded them.
///
/// AFF4-L 2019 §3.5 Table 3 defines all four. Each is `Option` because a
/// container may legitimately carry fewer: `src/write/logical.rs` records that
/// macOS has no `recordChanged` and Linux needs `statx` for `birthTime`, so an
/// absent term means the acquiring platform could not read it — not that the
/// file had no such time.
///
/// Values are kept in their recorded lexical form rather than parsed into an
/// instant. A timestamp's exact spelling is what the container asserts, and
/// reformatting it would be a lossy conversion of evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogicalTimes {
    /// `aff4:birthTime` — when the file was created.
    pub birth_time: Option<String>,
    /// `aff4:lastWritten` — when its content last changed.
    pub last_written: Option<String>,
    /// `aff4:lastAccessed` — when its content was last read.
    pub last_accessed: Option<String>,
    /// `aff4:recordChanged` — when its filesystem metadata last changed.
    pub record_changed: Option<String>,
}

impl LogicalTimes {
    /// Read the four terms off an object's properties.
    ///
    /// Closes the read-side gap `src/container.rs` records: the values are
    /// parsed into the graph but were not reachable by name, so nothing could
    /// act on them.
    #[must_use]
    pub fn of(object: &Aff4Object) -> Self {
        let mut times = Self::default();
        for property in &object.properties {
            // The lexical form as written, not a reparsed instant: a
            // timestamp's spelling is what the container asserts.
            let Value::Literal { lexical, .. } = &property.value else {
                continue;
            };
            let text = lexical.clone();
            match &*property.name {
                "birthTime" => times.birth_time = Some(text),
                "lastWritten" => times.last_written = Some(text),
                "lastAccessed" => times.last_accessed = Some(text),
                "recordChanged" => times.record_changed = Some(text),
                _ => {}
            }
        }
        times
    }

    /// Whether any of the four was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.birth_time.is_none()
            && self.last_written.is_none()
            && self.last_accessed.is_none()
            && self.record_changed.is_none()
    }
}

/// One alteration made to a recorded path so it could be written.
///
/// Reported rather than applied silently. An examiner comparing extracted
/// files against the container's own listing must be able to see why a name
/// differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAlteration {
    /// The path as the container recorded it.
    pub recorded: String,
    /// The relative path actually written, beneath the target.
    pub written: String,
    /// What was changed and why.
    pub reason: String,
}

/// Characters no component may contain.
///
/// The separators are excluded because splitting already consumed them; what
/// remains would corrupt the path or the filesystem. NUL and the control range
/// are refused on every platform, and the Windows-reserved set is refused
/// everywhere so an export is portable rather than reproducible only on the
/// host that made it.
fn is_illegal(c: char) -> bool {
    c == '\0' || c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\\')
}

/// Names Windows refuses regardless of extension.
const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Make one recorded component safe to write, or `None` to drop it.
///
/// Returns the component and, when it differs, why.
fn safe_component(raw: &str) -> (Option<String>, Option<String>) {
    if raw.is_empty() || raw == "." {
        return (None, None);
    }
    if raw == ".." {
        // Resolving it away rather than honoring it: `..` in a recorded path is
        // how an export escapes its target.
        return (
            None,
            Some("a `..` component was removed; it would climb above the target".to_owned()),
        );
    }

    // A Windows drive letter becomes an ordinary directory, so `C:\Users` lands
    // at `<target>/C/Users` and keeps the volume distinction visible.
    let (mut cleaned, mut reason) = if raw.len() == 2 && raw.ends_with(':') {
        let letter = &raw[..1];
        (
            letter.to_owned(),
            Some(format!("drive `{raw}` became directory `{letter}`")),
        )
    } else {
        (raw.to_owned(), None)
    };

    if cleaned.chars().any(is_illegal) {
        cleaned = cleaned
            .chars()
            .map(|c| if is_illegal(c) { '_' } else { c })
            .collect();
        reason = Some(format!(
            "characters illegal in a file name were replaced in {raw:?}"
        ));
    }

    // Trailing dots and spaces are silently stripped by Windows, which would
    // make two distinct recorded names collide there.
    let trimmed = cleaned.trim_end_matches([' ', '.']);
    if trimmed.is_empty() {
        return (
            Some("_".to_owned()),
            Some(format!("{raw:?} reduced to nothing and became `_`")),
        );
    }
    if trimmed != cleaned {
        reason = Some(format!("trailing dots or spaces were removed from {raw:?}"));
        cleaned.truncate(trimmed.len());
    }

    let stem = cleaned
        .split('.')
        .next()
        .unwrap_or(&cleaned)
        .to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        let replaced = format!("{cleaned}_");
        return (
            Some(replaced.clone()),
            Some(format!(
                "{cleaned:?} is reserved on Windows; wrote {replaced:?}"
            )),
        );
    }

    (Some(cleaned), reason)
}

/// Where a recorded path should be written, given the name's raw bytes.
///
/// The byte-level counterpart of [`rebase`], for the names AFF4-L
/// v1.0-ALPHA §5 records raw because they are not valid UTF-8. Preferring the
/// bytes is what reproduces such a name: the display form is lossy by
/// construction, since a literal `%41` and an encoded `A` are the same three
/// characters.
///
/// Valid UTF-8 delegates to [`rebase`], so one sanitizing rule covers both.
///
/// Returns the path to write, plus an alteration when the result differs from
/// what was recorded.
#[must_use]
pub fn rebase_bytes(target: &Path, recorded: &[u8]) -> (PathBuf, Option<PathAlteration>) {
    // Where the bytes are valid UTF-8, the string path handles them and its
    // sanitizing applies unchanged. That is the common case even for a name
    // AFF4-L v1.0-ALPHA §5 encoded, since a control character is valid UTF-8.
    if let Ok(text) = std::str::from_utf8(recorded) {
        return rebase(target, text);
    }

    // Not valid UTF-8. On Unix a filename is a byte string, so the bytes can
    // be written as they are -- the whole reason AFF4-L v1.0-ALPHA §5 records
    // them at all.
    // Sanitizing still applies per component, on the ASCII bytes it knows.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let mut relative = PathBuf::new();
        let mut reasons: Vec<String> = Vec::new();
        for component in recorded.split(|&b| b == b'/' || b == b'\\') {
            let (kept, reason) = safe_component_bytes(component);
            if let Some(reason) = reason {
                reasons.push(reason);
            }
            if let Some(kept) = kept {
                relative.push(std::ffi::OsStr::from_bytes(&kept));
            }
        }
        if relative.as_os_str().is_empty() {
            relative.push("_");
            reasons.push("the recorded bytes named no writable path; wrote `_`".to_owned());
        }
        let written = target.join(&relative);
        let alteration = if reasons.is_empty() {
            None
        } else {
            Some(PathAlteration {
                recorded: String::from_utf8_lossy(recorded).into_owned(),
                written: relative.to_string_lossy().into_owned(),
                reason: reasons.join("; "),
            })
        };
        (written, alteration)
    }

    // Elsewhere a path is not a byte string, so the bytes cannot be written
    // faithfully. The lossy form is used and the substitution reported.
    #[cfg(not(unix))]
    {
        let text = String::from_utf8_lossy(recorded).into_owned();
        let (written, alteration) = rebase(target, &text);
        (
            written,
            Some(alteration.unwrap_or_else(|| {
                PathAlteration {
                    recorded: text.clone(),
                    written: text,
                    reason: "the recorded name is not valid UTF-8 and this platform \
                         cannot write it as bytes"
                        .to_owned(),
                }
            })),
        )
    }
}

/// Sanitize one component given as raw bytes.
///
/// The byte counterpart of [`safe_component`], for a name that is not valid
/// UTF-8. Each byte is judged on its own: the illegal set is ASCII, so a byte
/// above `0x7f` is left alone rather than being mistaken for one.
#[cfg(unix)]
fn safe_component_bytes(raw: &[u8]) -> (Option<Vec<u8>>, Option<String>) {
    if raw.is_empty() || raw == b"." {
        return (None, None);
    }
    if raw == b".." {
        return (
            None,
            Some("a `..` component was removed; it would climb above the target".to_owned()),
        );
    }

    let mut cleaned: Vec<u8> = Vec::with_capacity(raw.len());
    let mut replaced = false;
    for &byte in raw {
        if byte < 0x80 && is_illegal(byte as char) {
            cleaned.push(b'_');
            replaced = true;
        } else {
            cleaned.push(byte);
        }
    }

    // Trailing dots and spaces, as the string path strips them and for the
    // same reason.
    while matches!(cleaned.last(), Some(b'.' | b' ')) {
        cleaned.pop();
        replaced = true;
    }
    if cleaned.is_empty() {
        return (
            Some(b"_".to_vec()),
            Some(format!(
                "{:?} reduced to nothing once made writable; wrote `_`",
                String::from_utf8_lossy(raw)
            )),
        );
    }

    let reason = replaced.then(|| {
        format!(
            "bytes illegal in a file name were replaced in {:?}",
            String::from_utf8_lossy(raw)
        )
    });
    (Some(cleaned), reason)
}

/// Where a recorded path should be written beneath `target`.
///
/// The recorded hierarchy is preserved and rebased: an absolute
/// `/Users/x/notes.txt` becomes `<target>/Users/x/notes.txt`. Nothing can
/// escape `target`, whatever the input says.
///
/// Returns the path to write, plus an alteration when the result differs from
/// what was recorded.
#[must_use]
pub fn rebase(target: &Path, recorded: &str) -> (PathBuf, Option<PathAlteration>) {
    let mut relative = PathBuf::new();
    let mut reasons: Vec<String> = Vec::new();

    // Split on both separators: a container written on Windows records
    // backslashes, and this may be extracting it on a Unix host.
    for raw in recorded.split(['/', '\\']) {
        let (component, reason) = safe_component(raw);
        if let Some(reason) = reason {
            reasons.push(reason);
        }
        if let Some(component) = component {
            relative.push(component);
        }
    }

    if relative.as_os_str().is_empty() {
        relative.push("_");
        reasons.push(format!("{recorded:?} named no writable path; wrote `_`"));
    }

    let written = target.join(&relative);

    // Belt and braces. `safe_component` already refuses every component that
    // could climb, so this asserts the property rather than establishing it —
    // but this is the boundary that must not be wrong, and a future edit to the
    // component logic must not be able to breach it silently.
    debug_assert!(
        !written
            .components()
            .any(|c| matches!(c, Component::ParentDir)),
        "a rebased path must contain no parent-directory component"
    );

    let alteration = if reasons.is_empty() {
        None
    } else {
        Some(PathAlteration {
            recorded: recorded.to_owned(),
            written: relative.to_string_lossy().into_owned(),
            reason: reasons.join("; "),
        })
    };

    (written, alteration)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn target() -> PathBuf {
        PathBuf::from("/out")
    }

    /// A relative path is reproduced unchanged.
    #[test]
    fn an_ordinary_path_is_unchanged() {
        let (path, alteration) = rebase(&target(), "docs/notes.txt");
        assert_eq!(path, PathBuf::from("/out/docs/notes.txt"));
        assert!(alteration.is_none(), "nothing needed changing");
    }

    /// An absolute recorded path is rebased, not written to the root.
    ///
    /// `broken-dedupe.aff4` carries exactly this shape.
    #[test]
    fn an_absolute_path_is_rebased_under_the_target() {
        let (path, alteration) = rebase(&target(), "/Users/bradley/git/pyaff4/x.txt");
        assert_eq!(path, PathBuf::from("/out/Users/bradley/git/pyaff4/x.txt"));
        assert!(
            alteration.is_none(),
            "rebasing preserves the hierarchy and alters nothing"
        );
    }

    /// A `..` component cannot climb out of the target.
    #[test]
    fn a_parent_component_cannot_escape() {
        let (path, alteration) = rebase(&target(), "../../etc/passwd");
        assert_eq!(path, PathBuf::from("/out/etc/passwd"));
        let alteration = alteration.expect("removing `..` must be reported");
        assert!(alteration.reason.contains("climb above the target"));
    }

    /// A path made only of `..` still lands inside the target.
    #[test]
    fn a_path_of_only_parents_is_still_confined() {
        let (path, _) = rebase(&target(), "../../..");
        assert!(path.starts_with("/out"), "{} escaped", path.display());
    }

    /// A Windows drive letter becomes a directory.
    #[test]
    fn a_drive_letter_becomes_a_directory() {
        let (path, alteration) = rebase(&target(), r"C:\Users\jane\notes.txt");
        assert_eq!(path, PathBuf::from("/out/C/Users/jane/notes.txt"));
        assert!(alteration.expect("reported").reason.contains("drive"));
    }

    /// Control characters and separators inside a name are replaced.
    #[test]
    fn illegal_characters_are_replaced_and_reported() {
        let (path, alteration) = rebase(&target(), "bad\nname.txt");
        assert_eq!(path, PathBuf::from("/out/bad_name.txt"));
        assert!(alteration.expect("reported").reason.contains("illegal"));
    }

    /// A Windows-reserved name is suffixed rather than written as-is.
    #[test]
    fn a_reserved_name_is_suffixed() {
        let (path, alteration) = rebase(&target(), "CON.txt");
        assert_eq!(path, PathBuf::from("/out/CON.txt_"));
        assert!(alteration.expect("reported").reason.contains("reserved"));
    }

    /// Unicode names survive unchanged; the corpus has a fixture for this.
    #[test]
    fn unicode_names_are_preserved() {
        let (path, alteration) = rebase(&target(), "документы/файл.txt");
        assert_eq!(path, PathBuf::from("/out/документы/файл.txt"));
        assert!(
            alteration.is_none(),
            "unicode is legal and must not be altered"
        );
    }

    /// No input produces a path outside the target.
    ///
    /// The security property, asserted over the shapes an attacker would try.
    #[test]
    fn no_input_escapes_the_target() {
        for recorded in [
            "../escape",
            "../../../../../../etc/shadow",
            "/etc/passwd",
            r"..\..\windows\system32",
            "a/../../b",
            "",
            ".",
            "..",
            "/",
            "//",
            r"C:\..\..\secret",
            "\0/etc/passwd",
        ] {
            let (path, _) = rebase(&target(), recorded);
            assert!(
                path.starts_with("/out"),
                "{recorded:?} produced {} outside the target",
                path.display()
            );
            assert!(
                !path.components().any(|c| matches!(c, Component::ParentDir)),
                "{recorded:?} produced a climbing path: {}",
                path.display()
            );
        }
    }

    /// An empty recorded path still yields something writable.
    #[test]
    fn an_empty_path_becomes_a_placeholder() {
        let (path, alteration) = rebase(&target(), "");
        assert_eq!(path, PathBuf::from("/out/_"));
        assert!(alteration.is_some(), "inventing a name must be reported");
    }
}
