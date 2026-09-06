//! Finding and ordering the parts of a split AFF4 set.
//!
//! A *part* is one file of a split set; a *segment* is a member inside a volume
//! (see `docs/glossary.md`). This module is read-only and lives outside
//! `src/write/` for that reason.

use std::cmp::Ordering;

/// Compare two file names so that digit runs order numerically.
///
/// Plain lexicographic order puts `part_10` before `part_9`, which silently
/// reassembles an image in the wrong order. Splitting into digit and non-digit
/// runs and comparing digit runs as numbers fixes that, and orders zero-padded
/// names identically either way.
#[must_use]
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut ai, mut bi) = (a.char_indices().peekable(), b.char_indices().peekable());
    loop {
        match (ai.peek().copied(), bi.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some((_, ac)), Some((_, bc))) => {
                if ac.is_ascii_digit() && bc.is_ascii_digit() {
                    let an = take_digits(&mut ai);
                    let bn = take_digits(&mut bi);
                    // Compare by value, then by width, so `01` and `1` are
                    // ordered deterministically rather than reported equal.
                    match an.0.cmp(&bn.0).then(an.1.cmp(&bn.1)) {
                        Ordering::Equal => {}
                        other => return other,
                    }
                } else {
                    match ac.cmp(&bc) {
                        Ordering::Equal => {
                            ai.next();
                            bi.next();
                        }
                        other => return other,
                    }
                }
            }
        }
    }
}

/// Consume a run of digits, returning its value and its width.
///
/// Saturates rather than overflowing: a 30-digit run is not a part number, and
/// a panic on absurd input is not acceptable in this crate.
fn take_digits(iter: &mut std::iter::Peekable<std::str::CharIndices>) -> (u128, usize) {
    let mut value: u128 = 0;
    let mut width = 0usize;
    while let Some((_, c)) = iter.peek().copied() {
        if !c.is_ascii_digit() {
            break;
        }
        value = value
            .saturating_mul(10)
            .saturating_add(u128::from(c.to_digit(10).unwrap_or(0)));
        width += 1;
        iter.next();
    }
    (value, width)
}

/// Container extensions a part of an AFF4 set may carry.
///
/// `af4` is the pre-standard spelling; `aff4l` is the hint AFF4-L
/// v1.0-ALPHA §7 offers for that standard's containers.
const AFF4_EXTENSIONS: [&str; 3] = ["aff4", "af4", "aff4l"];

/// Whether `name` names a part of a multi-part AFF4 set.
///
/// # The ambiguity this resolves
///
/// AFF4-L v1.0-ALPHA §8 names the second file of a set `foo.aff4.1`, whose
/// extension is `1` — digits only. That is also the shape of a raw split image
/// (`image.001`, `image.002`), so extension alone cannot tell them apart.
///
/// **The stem decides.** A digits-only extension whose stem already ends in a
/// container extension is an AFF4 part; otherwise it is a raw one:
///
/// | Name | Stem | Extension | Kind |
/// |---|---|---|---|
/// | `foo.aff4` | `foo` | `aff4` | AFF4, first part |
/// | `foo.aff4.1` | `foo.aff4` | `1` | AFF4, second part |
/// | `image.001` | `image` | `001` | raw |
///
/// The test is total and opens no file: a raw part's stem never carries a
/// container extension.
#[must_use]
pub fn is_aff4_part(name: &str) -> bool {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    if AFF4_EXTENSIONS
        .iter()
        .any(|known| ext.eq_ignore_ascii_case(known))
    {
        return true;
    }
    // A digits-only extension is an AFF4-L v1.0-ALPHA §8 ordinal only when
    // what precedes it is itself a container name.
    if !ext.is_empty() && ext.chars().all(|c| c.is_ascii_digit()) {
        return stem.rsplit_once('.').is_some_and(|(_, inner)| {
            AFF4_EXTENSIONS
                .iter()
                .any(|known| inner.eq_ignore_ascii_case(known))
        });
    }
    false
}

/// The position of a part within its set, counting from zero.
///
/// Three naming conventions reach this, and all three must order correctly
/// because containers in the field carry each:
///
/// | Name | Position | Convention |
/// |---|---|---|
/// | `foo.aff4` | 0 | AFF4-L v1.0-ALPHA §8, first file — no ordinal |
/// | `foo.aff4.1` | 1 | AFF4-L v1.0-ALPHA §8, from the digits-only extension |
/// | `Base-Linear_1.aff4` | 1 | pyaff4's, from a digit run in the stem |
///
/// **Zero for the unnumbered first file** keeps ordering a plain numeric
/// comparison. AFF4-L v1.0-ALPHA §8's ordinal counts files *after* the first, so `foo.aff4.1`
/// and `Base-Linear_1.aff4` both sit at position 1 and mean the same thing —
/// which is what a reader comparing the two names would expect.
///
/// Returns [`None`] when the name carries no position at all, which for a raw
/// split image means its numeric extension is read instead.
///
/// # `evidence_001.aff4`
///
/// The zero-padded form this project wrote before Phase 5.2 is no longer
/// *written*, but it still reads — not by a rule of its own, but because it
/// and pyaff4's `_1` differ only in padding, and one trailing-digit rule
/// covers both. Removing it would have meant adding a rule to reject it,
/// which would strand sets this tool has already produced for no gain.
#[must_use]
pub fn part_number(name: &str) -> Option<u32> {
    if let Some((stem, ext)) = name.rsplit_once('.') {
        // AFF4-L v1.0-ALPHA §8: the ordinal is the whole extension, and the stem is the
        // container name it belongs to.
        if !ext.is_empty()
            && ext.chars().all(|c| c.is_ascii_digit())
            && stem.rsplit_once('.').is_some_and(|(_, inner)| {
                AFF4_EXTENSIONS
                    .iter()
                    .any(|known| inner.eq_ignore_ascii_case(known))
            })
        {
            return ext.parse().ok();
        }
        // AFF4-L v1.0-ALPHA §8: an unsuffixed container name is the first file, position zero.
        if AFF4_EXTENSIONS
            .iter()
            .any(|known| ext.eq_ignore_ascii_case(known))
            && trailing_number(stem).is_none()
        {
            return Some(0);
        }
    }

    // pyaff4's, and a raw split image's: a digit run at the end of the stem.
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    trailing_number(stem)
}

/// The number a trailing digit run spells, when one follows a separator.
///
/// The **last** run, because a case name may itself contain digits:
/// `case_2024_007.aff4` is part 7, not part 2024.
///
/// The run must follow a separator (`_`, `-`, `.`, or a space) or be the whole
/// stem. Without that rule `lz4.aff4` parses as part 4, and every `.aff4`
/// beside it is taken for a sibling part of the same set — which is exactly
/// what happened to the codec fixtures (see
/// `digits_inside_a_word_are_not_a_part_number`).
fn trailing_number(stem: &str) -> Option<u32> {
    let mut end = None;
    for (i, c) in stem.char_indices().rev() {
        if c.is_ascii_digit() {
            end = Some(end.unwrap_or(i + c.len_utf8()));
        } else if end.is_some() {
            // The character before the digit run decides: a separator makes
            // this a numbered suffix, anything else makes it part of a word.
            if !matches!(c, '_' | '-' | '.' | ' ') {
                return None;
            }
            return stem[i + c.len_utf8()..end?].parse().ok();
        }
    }
    end.and_then(|e| stem[..e].parse().ok())
}

use std::path::{Path, PathBuf};

use crate::error::{Error, Locus, Result};

/// What kind of split set a folder holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitKind {
    /// AFF4 volumes: `.aff4` or `.af4`.
    Aff4,
    /// A raw split set: `.001`, `.002`, …
    RawSplit,
}

/// The parts of a split set, in read order.
#[derive(Debug, Clone)]
pub struct SplitSet {
    /// Which kind of files the folder holds.
    pub kind: SplitKind,
    /// Every part, ordered by [`natural_cmp`].
    pub parts: Vec<PathBuf>,
    /// The first part's number, when the names carry one.
    pub first: Option<u32>,
    /// The last part's number, when the names carry one.
    pub last: Option<u32>,
}

impl SplitSet {
    /// The line both `acquire` and `verify` print after ordering.
    ///
    /// Widths come from the file names themselves, so a set named `_001` reads
    /// back as `001` rather than `1`.
    #[must_use]
    pub fn discovery_line(&self) -> String {
        match (self.first, self.last) {
            (Some(first), Some(last)) => {
                let width = self
                    .parts
                    .first()
                    .and_then(|p| numbered(p, self.kind))
                    .map_or(0, |(_, w)| w);
                format!(
                    "Found {} split files, numbered {first:0width$} through {last:0width$}.",
                    self.parts.len(),
                )
            }
            _ => format!("Found {} file(s); no part numbering.", self.parts.len()),
        }
    }
}

/// The part number of a file, and its printed width, given the kind of set it
/// belongs to.
///
/// The two kinds carry the number in different places. An AFF4 part is
/// `evidence_007.aff4`, so the number is the last digit run in the stem. A raw
/// part is `img.001`, where the number *is* the extension — stripping it, as
/// [`part_number`] does, would leave nothing to read.
///
/// Value and width are returned together because they must be read off the
/// same digit run. Deriving them separately is what let `discovery_line` and
/// the gap check disagree about where a raw part's number lives.
fn numbered(path: &Path, kind: SplitKind) -> Option<(u32, usize)> {
    match kind {
        SplitKind::RawSplit => {
            let ext = path.extension().and_then(|e| e.to_str())?;
            if ext.is_empty() || !ext.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            Some((ext.parse().ok()?, ext.len()))
        }
        SplitKind::Aff4 => {
            let name = path.file_name().and_then(|n| n.to_str())?;
            let value = part_number(name)?;
            let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
            let width = stem.chars().rev().take_while(char::is_ascii_digit).count();
            Some((value, width))
        }
    }
}

/// Find the parts of a split set in `dir`.
///
/// # Errors
///
/// [`Error::Malformed`] if the folder holds no split set, holds both an AFF4
/// set and a raw set, or has a gap in its part numbering.
pub fn discover(dir: &Path) -> Result<SplitSet> {
    let locus = Locus::new(dir);
    let entries = std::fs::read_dir(dir).map_err(|e| Error::io(dir.to_path_buf(), e))?;

    let mut aff4: Vec<PathBuf> = Vec::new();
    let mut raw: Vec<PathBuf> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // `is_aff4_part` resolves the one ambiguity here: an AFF4-L
        // v1.0-ALPHA §8 ordinal and a raw split image's extension are both
        // digits, and only the stem tells them apart.
        if is_aff4_part(name) {
            aff4.push(path);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| !ext.is_empty() && ext.chars().all(|c| c.is_ascii_digit()))
        {
            raw.push(path);
        }
    }

    if !aff4.is_empty() && !raw.is_empty() {
        return Err(Error::malformed(
            locus,
            "this folder holds both an AFF4 set and a raw split set; \
             name one file explicitly rather than the folder",
        ));
    }

    let (kind, mut parts) = if aff4.is_empty() {
        if raw.is_empty() {
            return Err(Error::malformed(
                locus,
                "no split set here: expected .aff4 or .aff4l parts, or a raw \
                 set (.001, .002, …)",
            ));
        }
        (SplitKind::RawSplit, raw)
    } else {
        (SplitKind::Aff4, aff4)
    };

    parts.sort_by(|a, b| {
        let an = a.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let bn = b.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        natural_cmp(an, bn)
    });

    let numbers: Vec<Option<u32>> = parts
        .iter()
        .map(|p| numbered(p, kind).map(|(value, _)| value))
        .collect();

    // A single unnumbered file is one container, not a set with a gap.
    if parts.len() > 1 && numbers.iter().all(Option::is_some) {
        for pair in numbers.windows(2) {
            let (Some(a), Some(b)) = (pair[0], pair[1]) else {
                continue;
            };
            if b != a + 1 {
                return Err(Error::malformed(
                    Locus::new(dir),
                    format!(
                        "split set has a gap: part {a} is followed by part {b}; \
                         reassembly would silently omit data"
                    ),
                ));
            }
        }
    }

    let first = numbers.first().copied().flatten();
    let last = numbers.last().copied().flatten();

    Ok(SplitSet {
        kind,
        parts,
        first,
        last,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn unpadded_numbers_order_numerically() {
        let mut names = vec!["e_10.aff4", "e_9.aff4", "e_1.aff4", "e_20.aff4"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            names,
            vec!["e_1.aff4", "e_9.aff4", "e_10.aff4", "e_20.aff4"]
        );
    }

    #[test]
    fn padded_numbers_order_the_same_way() {
        let mut names = vec!["e_010.aff4", "e_009.aff4", "e_001.aff4"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(names, vec!["e_001.aff4", "e_009.aff4", "e_010.aff4"]);
    }

    #[test]
    fn the_last_digit_run_is_the_part_number() {
        assert_eq!(part_number("case_2024_007.aff4"), Some(7));
        assert_eq!(part_number("evidence_001.aff4"), Some(1));
        // An unsuffixed container name is AFF4-L v1.0-ALPHA §8's first file,
        // which is position zero rather than no position at all.
        assert_eq!(part_number("evidence.aff4"), Some(0));
    }

    /// A name whose digits are part of a word is not a part number.
    ///
    /// Without this rule `part_number("lz4.aff4")` answers `Some(4)`, taking
    /// `lz4.aff4` for part 4 of a split set. Sibling discovery then pulls in
    /// unrelated containers, and an error can name a file the caller never
    /// asked about. Content is not at risk, but a diagnostic pointing at the
    /// wrong evidence is its own kind of defect.
    ///
    /// (`lz4.aff4` and the other unread codec fixtures have since been dropped
    /// from that folder, but the parsing rule they exposed still holds.)
    ///
    /// A part number is a numbered suffix, so it must follow a separator.
    /// `lz4` is a codec name; `evidence_004` is a part.
    #[test]
    fn digits_inside_a_word_are_not_a_part_number() {
        // `lz4` is a codec name, not a part number -- so this is a first file
        // (position zero), not part 4.
        assert_eq!(part_number("lz4.aff4"), Some(0));
        assert_eq!(part_number("evidence_004.aff4"), Some(4));
        assert_eq!(part_number("evidence-004.aff4"), Some(4));
        // `evidence.004` is a *raw* split part: the number is the extension,
        // which `numbered(.., SplitKind::RawSplit)` reads. `part_number`
        // strips the extension, so it correctly sees no suffix here.
        assert_eq!(part_number("evidence.004"), None);
        // A bare numeric stem is still a part: `001.aff4`.
        assert_eq!(part_number("001.aff4"), Some(1));
    }

    /// A digit run too long to be a part number must not panic.
    #[test]
    fn an_absurd_digit_run_is_handled() {
        // Too long to parse as a number, so no ordinal is read from the stem
        // and the name falls through to being a first file.
        let huge = format!("e_{}.aff4", "9".repeat(40));
        assert_eq!(part_number(&huge), Some(0));
        let _ = natural_cmp(&huge, "e_1.aff4");
    }

    fn touch(dir: &std::path::Path, name: &str) {
        #[allow(clippy::disallowed_methods)]
        std::fs::File::create(dir.join(name)).unwrap();
    }

    #[test]
    fn a_folder_of_aff4_parts_is_discovered_in_order() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "e_003.aff4");
        touch(dir.path(), "e_001.aff4");
        touch(dir.path(), "e_002.aff4");

        let set = discover(dir.path()).unwrap();
        assert_eq!(set.kind, SplitKind::Aff4);
        assert_eq!(set.parts.len(), 3);
        let names: Vec<_> = set
            .parts
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, vec!["e_001.aff4", "e_002.aff4", "e_003.aff4"]);
        assert_eq!(
            set.discovery_line(),
            "Found 3 split files, numbered 001 through 003."
        );
    }

    #[test]
    fn a_gap_in_part_numbering_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "e_001.aff4");
        touch(dir.path(), "e_003.aff4");

        let err = discover(dir.path()).unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
    }

    #[test]
    fn a_folder_of_raw_parts_is_discovered() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "img.001");
        touch(dir.path(), "img.002");

        let set = discover(dir.path()).unwrap();
        assert_eq!(set.kind, SplitKind::RawSplit);
        assert_eq!(set.parts.len(), 2);
    }

    /// Both kinds in one folder is ambiguous, and guessing could acquire the
    /// wrong evidence. Refuse and make the user name one.
    #[test]
    fn a_folder_holding_both_kinds_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "e_001.aff4");
        touch(dir.path(), "img.001");

        let err = discover(dir.path()).unwrap_err();
        assert!(err.to_string().contains("both"), "{err}");
    }

    #[test]
    fn an_empty_folder_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = discover(dir.path()).unwrap_err();
        assert!(err.to_string().contains("no split set"), "{err}");
    }

    /// One unnumbered container is a single container, not a split set.
    #[test]
    fn a_single_unnumbered_container_needs_no_numbering() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "evidence.aff4");
        let set = discover(dir.path()).unwrap();
        assert_eq!(set.parts.len(), 1);
        // AFF4-L v1.0-ALPHA §8 gives the first file no ordinal, so a lone
        // container is position zero.
        assert_eq!(set.first, Some(0));
    }

    #[test]
    fn a_gap_in_a_raw_split_set_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "img.001");
        touch(dir.path(), "img.003");

        let err = discover(dir.path()).unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
    }

    #[test]
    fn a_contiguous_raw_split_set_is_numbered() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "img.002");
        touch(dir.path(), "img.001");

        let set = discover(dir.path()).unwrap();
        assert_eq!(set.kind, SplitKind::RawSplit);
        assert_eq!(set.first, Some(1));
        assert_eq!(set.last, Some(2));
    }

    /// A raw part's number is its extension, so the width comes from there too.
    #[test]
    fn a_raw_split_set_names_its_range_with_padding() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "img.001");
        touch(dir.path(), "img.002");

        let set = discover(dir.path()).unwrap();
        assert_eq!(
            set.discovery_line(),
            "Found 2 split files, numbered 001 through 002."
        );
    }

    /// An AFF4-L v1.0-ALPHA §8 ordinal and a raw split image's extension are
    /// both digits; only the stem tells them apart.
    ///
    /// This is the ambiguity the AFF4-L v1.0-ALPHA §8 naming introduced, and getting it wrong
    /// means a folder of AFF4 containers is read as a raw image set with its
    /// metadata never consulted.
    #[test]
    fn the_stem_distinguishes_an_aff4_part_from_a_raw_one() {
        // AFF4 parts: a container extension, or an ordinal after one.
        for name in [
            "foo.aff4",
            "foo.aff4.1",
            "foo.aff4.42",
            "foo.aff4l",
            "foo.aff4l.1",
            "foo.af4",
            "Base-Linear_1.aff4",
        ] {
            assert!(is_aff4_part(name), "{name} is an AFF4 part");
        }

        // Raw parts: a digits-only extension whose stem carries no container
        // extension.
        for name in ["image.001", "image.002", "disk.1", "capture.0001"] {
            assert!(!is_aff4_part(name), "{name} is a raw part");
        }

        // Neither.
        for name in ["notes.txt", "README", "image.dd"] {
            assert!(!is_aff4_part(name), "{name} is neither");
        }
    }

    /// Three naming conventions reach `part_number`, and all three order
    /// correctly because containers in the field carry each.
    #[test]
    fn every_convention_yields_a_position() {
        // AFF4-L v1.0-ALPHA §8: the first file has no ordinal, and the
        // ordinal counts files after it.
        assert_eq!(part_number("foo.aff4"), Some(0));
        assert_eq!(part_number("foo.aff4.1"), Some(1));
        assert_eq!(part_number("foo.aff4.10"), Some(10));
        assert_eq!(part_number("foo.aff4l.2"), Some(2));

        // pyaff4's, which the reference corpus uses.
        assert_eq!(part_number("Base-Linear_1.aff4"), Some(1));
        assert_eq!(part_number("Base-Linear_2.aff4"), Some(2));

        // This project's own earlier form still reads: it differs from
        // pyaff4's only in padding, so one rule covers both.
        assert_eq!(part_number("evidence_001.aff4"), Some(1));
        assert_eq!(part_number("evidence_042.aff4"), Some(42));
    }

    /// AFF4-L v1.0-ALPHA §8 names sort into position order, including the unsuffixed first file.
    ///
    /// Plain lexicographic order would put `.10` before `.2`; `natural_cmp`
    /// compares digit runs as numbers, so no padding is needed.
    #[test]
    fn section_8_names_sort_into_order() {
        let mut names = vec!["e.aff4.10", "e.aff4.2", "e.aff4", "e.aff4.1", "e.aff4.9"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            names,
            vec!["e.aff4", "e.aff4.1", "e.aff4.2", "e.aff4.9", "e.aff4.10"]
        );
    }

    /// A folder of AFF4-L v1.0-ALPHA §8 parts is discovered, ordered, and its first part found.
    #[test]
    fn a_folder_of_section_8_parts_is_discovered() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["ev.aff4", "ev.aff4.1", "ev.aff4.2"] {
            touch(dir.path(), name);
        }
        let set = discover(dir.path()).unwrap();
        assert_eq!(set.kind, SplitKind::Aff4);
        assert_eq!(set.parts.len(), 3);
        assert_eq!(set.first, Some(0));
        assert_eq!(set.last, Some(2));
        assert!(set.parts[0].ends_with("ev.aff4"));
        assert!(set.parts[2].ends_with("ev.aff4.2"));
    }

    /// A gap in AFF4-L v1.0-ALPHA §8 numbering is refused, as it is for every other convention.
    ///
    /// Reassembling a set with a part missing would cover less evidence than
    /// the container describes while reporting success.
    #[test]
    fn a_gap_in_section_8_numbering_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["ev.aff4", "ev.aff4.2"] {
            touch(dir.path(), name);
        }
        let err = discover(dir.path()).unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
    }

    /// A raw split set is still recognized beside the new AFF4 shape.
    #[test]
    fn a_raw_set_is_not_mistaken_for_section_8_parts() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["img.001", "img.002"] {
            touch(dir.path(), name);
        }
        let set = discover(dir.path()).unwrap();
        assert_eq!(set.kind, SplitKind::RawSplit);
        assert_eq!(set.parts.len(), 2);
    }
}
