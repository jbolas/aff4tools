//! AFF4 resource names (ARNs) and their mapping to storage-layer paths.
//!
//! An ARN is the `aff4://<uuid>[/path]` URI that names every object in a
//! container. This module owns three things:
//!
//! 1. [`Arn`] — a validated ARN, with the volume/path split.
//! 2. The URI↔path mapping of spec §5.1, which decides whether an object is
//!    stored under a relative path or an escaped absolute one.
//! 3. The escaping rules of spec §5.2.
//!
//! # Escaping: uppercase, per the spec
//!
//! Spec §5.2 rule 2 says escaping MUST use upper case, and the canonical
//! reference containers agree — `Base-Linear.aff4` stores
//! `aff4%3A%2F%2Fc215ba20-…`. pyaff4 emits *lowercase* (`escaping.py`, `"%%%02x"`),
//! so the reference implementation diverges from both the spec and its own
//! corpus. This module emits uppercase and accepts either when decoding, since
//! a reader that rejected lowercase would fail on pyaff4-written containers.
//!
//! # Byte-range ARNs
//!
//! pyaff4 emits `aff4://<uuid>[0x4f8000:0x8000]` to name a byte range of a
//! stream (`aff4_map.py`, `ByteRangeARN`). Square brackets are excluded from
//! Turtle's `IRIREF` production, so these are not legal RDF — but they are
//! deliberate, not corruption, and `broken-dedupe.aff4` contains 437 of them.
//! [`Arn::parse`] accepts them and records the range in [`Arn::byte_range`];
//! callers should raise a [`DeviationKind::ByteRangeArn`] when one appears.

use std::fmt;

use crate::error::{Error, Locus, Result};

/// The URI scheme every ARN uses.
const SCHEME: &str = "aff4://";

/// Characters the spec and pyaff4 both treat as forbidden in a path segment.
///
/// Mirrors the set in pyaff4's `escaping.py`, which in turn tracks the
/// characters excluded from RFC 3987 IRIs.
const FORBIDDEN: &[char] = &['<', '>', '\\', '^', '`', '{', '|', '}', '"', ' '];

/// A byte range attached to an ARN by pyaff4's `ByteRangeARN` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ByteRange {
    /// Offset of the range within the target stream.
    pub start: u64,
    /// Length of the range in bytes.
    pub length: u64,
}

/// A validated AFF4 resource name.
///
/// Construct with [`Arn::parse`]. The lexical form is preserved exactly, so
/// round-tripping an ARN through this type never alters what the container
/// said — important when the value may be quoted in a report.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Arn {
    /// The full lexical form, exactly as it appeared.
    lexical: String,
    /// Byte offset in `lexical` where the path begins (after the UUID), if any.
    path_start: Option<usize>,
    /// Byte offset in `lexical` where a `[start:len]` suffix begins, if any.
    range_start: Option<usize>,
}

impl serde::Serialize for Arn {
    /// Serialises as the plain lexical string.
    ///
    /// The byte offsets are a parsing detail; exposing them would invite
    /// consumers to write `.arn.lexical` and couple to the internals.
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.lexical)
    }
}

impl Arn {
    /// Parse an ARN.
    ///
    /// Accepts the standard `aff4://<uuid>[/path]` form and pyaff4's
    /// `aff4://<uuid>[0xSTART:0xLEN]` byte-range extension.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if `text` lacks the `aff4://` scheme, has an
    /// empty authority, or carries an unparseable byte-range suffix.
    pub fn parse(text: &str, locus: &Locus) -> Result<Self> {
        let Some(rest) = text.strip_prefix(SCHEME) else {
            return Err(Error::malformed(
                locus.clone(),
                format!("{text:?} is not an AFF4 resource name (expected an {SCHEME} prefix)"),
            ));
        };

        if rest.is_empty() {
            return Err(Error::malformed(
                locus.clone(),
                format!("{text:?} has no volume identifier after {SCHEME}"),
            ));
        }

        // A byte-range suffix, if present, is the LAST bracketed group; a path
        // could legitimately contain a bracket in a filename.
        let range_start = match (rest.rfind('['), rest.ends_with(']')) {
            (Some(idx), true) => {
                let inner = &rest[idx + 1..rest.len() - 1];
                parse_byte_range(inner).ok_or_else(|| {
                    Error::malformed(
                        locus.clone(),
                        format!(
                            "{text:?} has a byte-range suffix {:?} that is not \
                             two values separated by ':'",
                            &rest[idx..]
                        ),
                    )
                })?;
                Some(SCHEME.len() + idx)
            }
            _ => None,
        };

        // The authority ends at the first '/' that is not part of a range
        // suffix. Everything from that slash onward is the path.
        let scan_end = range_start.unwrap_or(text.len()) - SCHEME.len();
        let path_start = rest[..scan_end].find('/').map(|i| SCHEME.len() + i);

        if let Some(start) = path_start
            && start == SCHEME.len()
        {
            return Err(Error::malformed(
                locus.clone(),
                format!("{text:?} has no volume identifier before its path"),
            ));
        }

        Ok(Self {
            lexical: text.to_string(),
            path_start,
            range_start,
        })
    }

    /// The full lexical form, exactly as parsed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.lexical
    }

    /// The volume portion: `aff4://<uuid>`, without any path or range suffix.
    #[must_use]
    pub fn volume(&self) -> &str {
        let end = self
            .path_start
            .or(self.range_start)
            .unwrap_or(self.lexical.len());
        &self.lexical[..end]
    }

    /// The path portion including the separator `/`, exactly as it appeared.
    ///
    /// For `aff4://uuid//test/x.txt` this is `//test/x.txt`. The first slash is
    /// the URI separator; the remainder is the stored path. Use
    /// [`Arn::stored_path`] for the latter — this accessor preserves the
    /// lexical form for reporting.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        let start = self.path_start?;
        let end = self.range_start.unwrap_or(self.lexical.len());
        Some(&self.lexical[start..end])
    }

    /// The path as stored, with the URI separator removed.
    ///
    /// The separator after the volume identifier is URI syntax, not part of the
    /// name. AFF4-L records absolute filesystem paths, so the ARN
    /// `aff4://f95de329-…//test_images/AFF4Std/README.txt` carries a doubled
    /// slash and the container stores it as `/test_images/AFF4Std/README.txt`
    /// — verified against `AFF4-L/unicode.aff4`. Dropping only the separator
    /// keeps that leading slash intact.
    #[must_use]
    pub fn stored_path(&self) -> Option<&str> {
        self.path().and_then(|p| p.strip_prefix('/'))
    }

    /// The byte range from a `[start:len]` suffix, if present.
    #[must_use]
    pub fn byte_range(&self) -> Option<ByteRange> {
        let start = self.range_start?;
        let inner = self.lexical[start + 1..self.lexical.len() - 1].as_ref();
        parse_byte_range(inner)
    }

    /// The ARN with any byte-range suffix removed, path intact.
    ///
    /// `aff4://uuid/blocks[0x0:0x8000]` becomes `aff4://uuid/blocks`. Distinct
    /// from [`Arn::volume`], which also drops the path and would turn a slice of
    /// a stream into the volume that holds it.
    #[must_use]
    pub fn without_range(&self) -> &str {
        &self.lexical[..self.range_start.unwrap_or(self.lexical.len())]
    }

    /// Whether this ARN carries pyaff4's byte-range extension.
    ///
    /// Callers should record a [`DeviationKind::ByteRangeArn`] when this is
    /// true, since the syntax is not part of the standard.
    #[must_use]
    pub fn is_byte_range(&self) -> bool {
        self.range_start.is_some()
    }

    /// Whether this ARN names an object inside `volume`.
    #[must_use]
    pub fn is_within(&self, volume: &Arn) -> bool {
        self.volume() == volume.volume()
    }

    /// The ZIP member name this ARN maps to within `volume`.
    ///
    /// Two cases, both present in the reference corpus:
    ///
    /// - **Relative** — the ARN belongs to `volume`, so only the portion after
    ///   the volume identifier is used, with `%20` decoded back to a space:
    ///   `aff4://f95de329-…//test/x.txt` → `/test/x.txt`
    /// - **Absolute** — the ARN belongs to another volume, so the whole scheme
    ///   and identifier are escaped into a single directory name (spec §5.2
    ///   rule 1): `aff4://c215ba20-…/00000000` →
    ///   `aff4%3A%2F%2Fc215ba20-…/00000000`
    ///
    /// # Why the relative case does not escape
    ///
    /// The path is **already escaped**. AFF4-L §3.2 percent-encodes the suspect
    /// path when the ARN is built — space to `%20`, `%` to `%25` — and §3.4
    /// then defines the segment name as that tail with the volume removed and
    /// "any percent encoded spaces converted back to spaces". Nothing is
    /// re-encoded. The paper states this as a deliberate replacement of the
    /// older rule, "in order to enhance human viewability … when browsing with
    /// standard Zip file browsers", and pyaff4 implements exactly this for a
    /// container declaring version 1.1.
    ///
    /// Escaping here a second time turned `%20` into `%2520`: a 5 GiB logical
    /// acquisition wrote 312 image streams under names nothing could read back,
    /// and `export` skipped 44,198 of 91,226 files while reporting success.
    ///
    /// The two rules are a lossless pair, not an ambiguity. Because §3.2 escapes
    /// `%` itself, a `%2520` in an ARN means a file literally named `%20`, and
    /// decoding only `%20` here preserves that distinction.
    ///
    /// The absolute case still escapes: its `aff4://` prefix is URI syntax
    /// rather than a suspect path, and §5.2 rule 1 requires it be encoded into
    /// one directory name.
    ///
    /// A byte-range suffix names a slice of a stream rather than a stored
    /// segment, so it never maps to a member; this returns [`None`] for one.
    #[must_use]
    pub fn member_name(&self, volume: &Arn) -> Option<String> {
        if self.is_byte_range() {
            return None;
        }

        if self.is_within(volume) {
            // Relative: drop the volume and the URI separator, then apply the
            // one §3.4 transformation. An ARN equal to the volume itself names
            // no member.
            return self.stored_path().map(decode_escaped_spaces);
        }

        // Absolute: escape the volume into one directory name, then append the
        // stored path separated by a single '/'.
        let mut name = escape_component(self.volume());
        if let Some(path) = self.stored_path() {
            name.push('/');
            name.push_str(&decode_escaped_spaces(path));
        }
        Some(name)
    }
}

impl fmt::Display for Arn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lexical)
    }
}

impl AsRef<str> for Arn {
    fn as_ref(&self) -> &str {
        &self.lexical
    }
}

impl PartialEq<str> for Arn {
    fn eq(&self, other: &str) -> bool {
        self.lexical == other
    }
}

impl PartialEq<&str> for Arn {
    fn eq(&self, other: &&str) -> bool {
        self.lexical == *other
    }
}

/// Parse `0xSTART:0xLEN` or `START:LEN` from a byte-range suffix.
///
/// Returns [`None`] if the shape is wrong, so callers can report a precise
/// error rather than guessing at intent.
fn parse_byte_range(inner: &str) -> Option<ByteRange> {
    let (start, length) = inner.split_once(':')?;
    Some(ByteRange {
        start: parse_offset(start)?,
        length: parse_offset(length)?,
    })
}

/// Parse a hex (`0x`-prefixed) or decimal offset.
fn parse_offset(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Percent-escape a whole string, including `/` (spec §5.2 rule 1).
///
/// Used for the scheme+identifier prefix, which becomes a single directory
/// name: `aff4://uuid` → `aff4%3A%2F%2Fuuid`.
fn escape_component(text: &str) -> String {
    text.chars().map(escape_char).collect()
}

/// Escape one character per spec §5.2, using **uppercase** hex (rule 2).
fn escape_char(c: char) -> String {
    // Control codes, the forbidden set, ':' and '/' (which would otherwise be
    // read as URI syntax), and '%' itself (so escaping round-trips).
    use std::fmt::Write as _;

    if c.is_control() || FORBIDDEN.contains(&c) || c == ':' || c == '/' || c == '%' {
        let mut out = String::new();
        let mut buf = [0u8; 4];
        for byte in c.encode_utf8(&mut buf).as_bytes() {
            // Writing to a String is infallible; the Result is discarded
            // deliberately rather than unwrapped (the crate denies unwrap).
            let _ = write!(out, "%{byte:02X}");
        }
        out
    } else {
        c.to_string()
    }
}

/// Turn percent-encoded spaces back into spaces — AFF4-L §3.4, and nothing more.
///
/// The inverse of [`encode_spaces`], and the only transformation §3.4 applies
/// to an ARN tail that §3.2 has already escaped. `%20` carries no hex letter,
/// so the uppercase §5.2 rule 2 spelling and pyaff4's lowercase output are the
/// same three characters and one form matches both.
fn decode_escaped_spaces(path: &str) -> String {
    path.replace("%20", " ")
}

/// Percent-encode literal spaces — the inverse of [`decode_escaped_spaces`].
///
/// Recovers the ARN path fragment from a segment name, which is what turns a
/// member found in the archive back into the subject that describes it.
#[must_use]
pub fn encode_spaces(name: &str) -> String {
    name.replace(' ', "%20")
}

/// Restore only a percent-escaped byte-range suffix, leaving the path alone.
///
/// The inverse of `rdf::escape_byte_ranges`, which encodes a pyaff4
/// `[0x0:0x400]` suffix so a conformant Turtle parser will accept the IRI.
/// Only that suffix may be decoded: the rest of an ARN carries escapes that
/// AFF4-L §3.2 put there deliberately, and the ZIP member keeps them.
///
/// Decoding the whole IRI instead turned a legitimate `%3E` — the forbidden
/// `>` in a suspect filename — back into a literal, so the parsed subject and
/// the stored member disagreed and the file was reported as having no data
/// stream. Scoped to a suffix that begins `%5B` and ends `%5D`, which is the
/// only thing the escaping pass ever writes.
#[must_use]
pub fn unescape_byte_range(text: &str) -> String {
    // Uppercase is what the escaping pass emits; a lowercase spelling never
    // reaches here, so one form is enough.
    let Some(open) = text.rfind("%5B") else {
        return text.to_owned();
    };
    if !text.ends_with("%5D") {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..open]);
    out.push_str(&unescape(&text[open..]));
    out
}

/// Decode percent-escapes, accepting upper or lower case hex.
/// The spec mandates uppercase, but pyaff4 writes lowercase, so accept both.
#[must_use]
pub fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &text[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::error::DeviationKind;

    fn locus() -> Locus {
        Locus::new("/evidence/test.aff4")
    }

    /// The volume ARN from `AFF4Std/Base-Linear.aff4`'s ZIP comment.
    const STD_VOLUME: &str = "aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044";
    /// The `ImageStream` ARN from the same container's `information.turtle`.
    const STD_STREAM: &str = "aff4://c215ba20-5648-4209-a793-1f918c723610";
    /// The volume ARN from `AFF4-L/unicode.aff4`.
    const LOGICAL_VOLUME: &str = "aff4://f95de329-6616-440b-bd89-b840e6ba6ab5";

    #[test]
    fn parses_a_bare_volume_arn() {
        let arn = Arn::parse(STD_VOLUME, &locus()).unwrap();
        assert_eq!(arn.as_str(), STD_VOLUME);
        assert_eq!(arn.volume(), STD_VOLUME);
        assert_eq!(arn.path(), None);
        assert!(!arn.is_byte_range());
    }

    #[test]
    fn parses_an_arn_with_a_path() {
        let text = format!("{STD_STREAM}/00000000");
        let arn = Arn::parse(&text, &locus()).unwrap();
        assert_eq!(arn.volume(), STD_STREAM);
        assert_eq!(arn.path(), Some("/00000000"));
    }

    /// AFF4-L records absolute filesystem paths, so the ARN carries a doubled
    /// slash: one URI separator plus the path's own leading slash. `path()`
    /// keeps the lexical form; `stored_path()` drops only the separator.
    #[test]
    fn separates_the_uri_slash_from_the_stored_path() {
        let text = format!("{LOGICAL_VOLUME}//test_images/AFF4Std/Base-Linear.aff4");
        let arn = Arn::parse(&text, &locus()).unwrap();
        assert_eq!(arn.volume(), LOGICAL_VOLUME);
        assert_eq!(arn.path(), Some("//test_images/AFF4Std/Base-Linear.aff4"));
        assert_eq!(
            arn.stored_path(),
            Some("/test_images/AFF4Std/Base-Linear.aff4")
        );
    }

    #[test]
    fn rejects_a_non_aff4_uri() {
        let err = Arn::parse("http://example.com/x", &locus()).unwrap_err();
        assert!(err.is_integrity_finding());
        assert!(err.to_string().contains("aff4://"), "{err}");
    }

    #[test]
    fn rejects_an_empty_authority() {
        assert!(Arn::parse("aff4://", &locus()).is_err());
        assert!(Arn::parse("aff4:///path", &locus()).is_err());
    }

    /// Round-trips the exact member name stored in `Base-Linear.aff4`.
    #[test]
    fn maps_a_foreign_volume_arn_to_an_escaped_member_name() {
        let volume = Arn::parse(STD_VOLUME, &locus()).unwrap();
        let stream = Arn::parse(&format!("{STD_STREAM}/00000000"), &locus()).unwrap();
        assert_eq!(
            stream.member_name(&volume).unwrap(),
            "aff4%3A%2F%2Fc215ba20-5648-4209-a793-1f918c723610/00000000"
        );
    }

    /// Spec §5.2 rule 2: escaping MUST use upper case. pyaff4 emits lowercase;
    /// the canonical containers use uppercase, and so do we.
    #[test]
    fn escapes_with_uppercase_hex() {
        let escaped = escape_component("aff4://x");
        assert_eq!(escaped, "aff4%3A%2F%2Fx");
        assert!(
            !escaped.contains("%3a") && !escaped.contains("%2f"),
            "escaping must be uppercase, got {escaped}"
        );
    }

    /// An ARN inside the volume drops the volume prefix and the URI separator.
    ///
    /// The expected value is the member name literally present in
    /// `AFF4-L/unicode.aff4` — one leading slash, not two.
    #[test]
    fn maps_a_local_arn_to_a_relative_member_name() {
        let volume = Arn::parse(LOGICAL_VOLUME, &locus()).unwrap();
        let file = Arn::parse(
            &format!("{LOGICAL_VOLUME}//test_images/AFF4Std/Base-Linear.aff4/00000000"),
            &locus(),
        )
        .unwrap();
        assert_eq!(
            file.member_name(&volume).unwrap(),
            "/test_images/AFF4Std/Base-Linear.aff4/00000000"
        );
    }

    /// Every member name in this list was read out of a real container. These
    /// are the strings the mapping must produce; hand-derived expectations are
    /// what let the doubled-slash bug through in the first place.
    #[test]
    fn reproduces_member_names_from_the_reference_corpus() {
        // AFF4Std/Base-Linear.aff4 — a foreign volume, escaped absolute form.
        let std_volume = Arn::parse(STD_VOLUME, &locus()).unwrap();
        for (arn, expected) in [
            (
                format!("{STD_STREAM}/00000000"),
                "aff4%3A%2F%2Fc215ba20-5648-4209-a793-1f918c723610/00000000",
            ),
            (
                format!("{STD_STREAM}/00000000.index"),
                "aff4%3A%2F%2Fc215ba20-5648-4209-a793-1f918c723610/00000000.index",
            ),
            (
                "aff4://fcbfdce7-4488-4677-abf6-08bc931e195b/map".to_string(),
                "aff4%3A%2F%2Ffcbfdce7-4488-4677-abf6-08bc931e195b/map",
            ),
        ] {
            let parsed = Arn::parse(&arn, &locus()).unwrap();
            assert_eq!(parsed.member_name(&std_volume).as_deref(), Some(expected));
        }

        // AFF4-L/unicode.aff4 — the local volume, relative form.
        let logical_volume = Arn::parse(LOGICAL_VOLUME, &locus()).unwrap();
        for (arn, expected) in [
            (
                format!("{LOGICAL_VOLUME}//test_images/AFF4Std/README.txt"),
                "/test_images/AFF4Std/README.txt",
            ),
            (
                format!(
                    "{LOGICAL_VOLUME}//test_images/AFF4Std/Striped/Base-Linear_1.aff4/00000000"
                ),
                "/test_images/AFF4Std/Striped/Base-Linear_1.aff4/00000000",
            ),
        ] {
            let parsed = Arn::parse(&arn, &locus()).unwrap();
            assert_eq!(
                parsed.member_name(&logical_volume).as_deref(),
                Some(expected)
            );
        }
    }

    /// AFF4-L §3.4: a relative member name decodes `%20`, and nothing else.
    ///
    /// These vectors are pyaff4's own `escaping_test.py::testARNtoZipSegment`,
    /// which is the reference implementation of the rule for a container
    /// declaring version 1.1. The paper states the mapping as three steps —
    /// drop the volume, drop the separator, turn percent-encoded spaces back
    /// into spaces — and explicitly replaces the older §5.2 rule that
    /// re-encoded the whole tail.
    ///
    /// The regression: re-escaping an ARN whose path fragment §3.2 had already
    /// escaped turned `%20` into `%2520`, so a 5 GiB logical acquisition wrote
    /// 312 image streams under double-escaped names that nothing could read
    /// back — and `export` skipped 44,198 of 91,226 files while exiting 0.
    #[test]
    fn a_relative_member_name_decodes_only_encoded_spaces() {
        let volume = Arn::parse(LOGICAL_VOLUME, &locus()).unwrap();
        for (tail, expected) in [
            ("//foo/some%20file", "/foo/some file"),
            ("//foo/some%20%20file", "/foo/some  file"),
            ("//foo/bar", "/foo/bar"),
            (
                "/bar/c$/foo/\u{30cd}\u{30b3}.txt",
                "bar/c$/foo/\u{30cd}\u{30b3}.txt",
            ),
            (
                "/laptop/My%20Documents/FileSchemeURIs.doc",
                "laptop/My Documents/FileSchemeURIs.doc",
            ),
            ("//C:/example\u{3113}.txt", "/C:/example\u{3113}.txt"),
        ] {
            let arn = Arn::parse(&format!("{LOGICAL_VOLUME}{tail}"), &locus()).unwrap();
            assert_eq!(
                arn.member_name(&volume).as_deref(),
                Some(expected),
                "pyaff4 vector failed for {tail:?}"
            );
        }
    }

    /// A colon in a suspect path is not re-escaped either.
    ///
    /// `%3A` is what §3.2 writes for a `:` inside a *filename*; §3.4 decodes
    /// only `%20`, so the segment keeps the escape. What must never happen is
    /// the `%` itself being escaped again into `%253A`, which is the same
    /// double-escape that lost `Bumper:Opener` from a real acquisition.
    #[test]
    fn a_colon_escape_is_carried_through_not_re_escaped() {
        let volume = Arn::parse(LOGICAL_VOLUME, &locus()).unwrap();
        let arn = Arn::parse(
            &format!("{LOGICAL_VOLUME}//Titles/Bumper%3AOpener/Media/Disc.png"),
            &locus(),
        )
        .unwrap();
        let name = arn.member_name(&volume).unwrap();
        assert!(
            !name.contains("%25"),
            "an already-escaped ARN must not be escaped again, got {name}"
        );
        assert_eq!(name, "/Titles/Bumper%3AOpener/Media/Disc.png");
    }

    /// A literal percent in a suspect filename survives the round trip.
    ///
    /// §3.2 escapes `%` to `%25` when the ARN is built, so `%2520` in an ARN
    /// means a file literally named `%20` — not a space. `%2520` contains no
    /// `%20` to decode, so it survives whole and stays distinguishable from
    /// the space that `%20` alone encodes. That is what makes the two rules a
    /// lossless pair rather than an ambiguity, and it is the behaviour
    /// pyaff4's 1.1 branch produces for the same input.
    #[test]
    fn a_literal_percent_twenty_in_a_filename_stays_distinct_from_a_space() {
        let volume = Arn::parse(LOGICAL_VOLUME, &locus()).unwrap();

        let literal =
            Arn::parse(&format!("{LOGICAL_VOLUME}//foo/some%2520file"), &locus()).unwrap();
        let spaced = Arn::parse(&format!("{LOGICAL_VOLUME}//foo/some%20file"), &locus()).unwrap();

        assert_eq!(
            literal.member_name(&volume).as_deref(),
            Some("/foo/some%2520file"),
            "a file named `some%20file` keeps its escape"
        );
        assert_eq!(
            spaced.member_name(&volume).as_deref(),
            Some("/foo/some file")
        );
        assert_ne!(
            literal.member_name(&volume),
            spaced.member_name(&volume),
            "the two must never collide on one member name"
        );
    }

    #[test]
    fn a_volume_arn_names_no_member_of_itself() {
        let volume = Arn::parse(STD_VOLUME, &locus()).unwrap();
        assert_eq!(volume.member_name(&volume), None);
    }

    #[test]
    fn recognises_locality() {
        let volume = Arn::parse(STD_VOLUME, &locus()).unwrap();
        let local = Arn::parse(&format!("{STD_VOLUME}/x"), &locus()).unwrap();
        let foreign = Arn::parse(&format!("{STD_STREAM}/x"), &locus()).unwrap();
        assert!(local.is_within(&volume));
        assert!(!foreign.is_within(&volume));
    }

    /// pyaff4's byte-range extension, as it appears 437 times in
    /// `broken-dedupe.aff4`.
    #[test]
    fn parses_pyaff4_byte_range_arns() {
        let text = "aff4://6a1e6a1a-8d78-43c7-bd5a-b5d800e4d552[0x4f8000:0x8000]";
        let arn = Arn::parse(text, &locus()).unwrap();
        assert!(arn.is_byte_range());
        assert_eq!(arn.volume(), "aff4://6a1e6a1a-8d78-43c7-bd5a-b5d800e4d552");
        assert_eq!(
            arn.byte_range(),
            Some(ByteRange {
                start: 0x004f_8000,
                length: 0x8000
            })
        );
        // The lexical form is preserved verbatim for reporting.
        assert_eq!(arn.as_str(), text);
    }

    #[test]
    fn accepts_decimal_byte_ranges() {
        let arn = Arn::parse("aff4://abc[1024:512]", &locus()).unwrap();
        assert_eq!(
            arn.byte_range(),
            Some(ByteRange {
                start: 1024,
                length: 512
            })
        );
    }

    /// A byte range names a slice of a stream, not a stored segment.
    #[test]
    fn byte_range_arns_map_to_no_member() {
        let volume = Arn::parse(STD_VOLUME, &locus()).unwrap();
        let ranged = Arn::parse("aff4://6a1e6a1a-8d78-43c7-bd5a[0x0:0x8000]", &locus()).unwrap();
        assert_eq!(ranged.member_name(&volume), None);
    }

    /// A malformed range must be reported, not silently treated as a path.
    #[test]
    fn rejects_an_unparseable_byte_range() {
        let err = Arn::parse("aff4://abc[notarange]", &locus()).unwrap_err();
        assert!(err.to_string().contains("byte-range"), "{err}");
    }

    /// The volume prefix of a foreign ARN is escaped whole — §5.2 rule 1.
    ///
    /// This is the one place escaping still belongs. A relative member name is
    /// governed by AFF4-L §3.4 instead and is not re-encoded; see
    /// [`Arn::member_name`].
    #[test]
    fn escapes_forbidden_and_control_characters() {
        assert_eq!(escape_component("a b"), "a%20b");
        assert_eq!(escape_component("a\"b"), "a%22b");
        assert_eq!(escape_component("a%b"), "a%25b");
        assert_eq!(escape_component("a\u{1}b"), "a%01b");
        // A component is escaped whole, separators included.
        assert_eq!(escape_component("a/b"), "a%2Fb");
    }

    #[test]
    fn unescape_accepts_either_case() {
        assert_eq!(unescape("aff4%3A%2F%2Fx"), "aff4://x");
        assert_eq!(unescape("aff4%3a%2f%2fx"), "aff4://x");
    }

    #[test]
    fn unescape_round_trips_escaped_components() {
        let original = "aff4://c215ba20-5648-4209-a793-1f918c723610";
        assert_eq!(unescape(&escape_component(original)), original);
    }

    /// An escape we cannot decode is left verbatim rather than dropped, so the
    /// oddity stays visible instead of silently changing a name.
    #[test]
    fn unescape_leaves_invalid_escapes_alone() {
        assert_eq!(unescape("a%zzb"), "a%zzb");
        assert_eq!(unescape("trailing%"), "trailing%");
    }

    /// §3.2 rule 3: Unicode outside ASCII is carried, never escaped.
    ///
    /// Keeping `ネコ.txt` readable in an ordinary ZIP browser is the stated
    /// reason AFF4-L refined the mapping at all, so it is asserted against the
    /// member name rather than against an escaping helper.
    #[test]
    fn non_ascii_paths_survive_escaping() {
        // From the AFF4-L corpus: ネコ.txt
        let volume = Arn::parse(LOGICAL_VOLUME, &locus()).unwrap();
        let arn = Arn::parse(
            &format!("{LOGICAL_VOLUME}//tmp/\u{30cd}\u{30b3}.txt"),
            &locus(),
        )
        .unwrap();
        assert_eq!(
            arn.member_name(&volume).as_deref(),
            Some("/tmp/\u{30cd}\u{30b3}.txt")
        );
    }

    #[test]
    fn display_and_as_ref_preserve_the_lexical_form() {
        let arn = Arn::parse(STD_VOLUME, &locus()).unwrap();
        assert_eq!(arn.to_string(), STD_VOLUME);
        assert_eq!(arn.as_ref(), STD_VOLUME);
    }

    /// The deviation kind callers raise for a byte-range ARN must exist.
    #[test]
    fn byte_range_deviation_kind_is_available() {
        assert_eq!(
            DeviationKind::ByteRangeArn.to_string(),
            "byte-range ARN extension"
        );
    }
}
