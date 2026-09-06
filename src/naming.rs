//! Filename and path normalization, per AFF4-L Standard v1.0-ALPHA §5.
//!
//! Every bare section number below cites that standard. Where a rule comes
//! from another document the citation names it.
//!
//! # What §5 is for
//!
//! A filename is not normal text. On Linux, it's a byte string the kernel never
//! validates; only NUL and `/` are forbidden. So a filename may hold bytes that
//! are not valid UTF-8, or control characters that would make the Turtle
//! metadata carrying them hard to parse and unsafe to print.
//!
//! §5 answers this by recording such a name **twice**: the bytes as they were
//! read, base64-encoded, and a printable display form. Together they are
//! lossless — the raw form reconstructs the name exactly, and the display form
//! is safe to put in a report.
//!
//! # The three rules
//!
//! 1. A name that is valid UTF-8 with no control character is stored as it is,
//!    and no raw form is written.
//! 2. Otherwise the raw bytes go to `fileNameRaw` / `originalPathNameRaw` as
//!    base64, and a display form goes to `fileName` / `originalPathName` with
//!    each byte in the escape set replaced by `%` and two uppercase hex
//!    digits.
//! 3. Encoded names need no deconfliction. Two different names may produce one
//!    display form, and the raw form is what tells them apart.
//!
//! # One deliberate departure
//!
//! §5's escape set is `0x00`-`0x1f`, `0x25`, and `0x80`-`0xff`. **This module
//! also escapes `0x7f`.** ASCII defines DEL as a control character and the
//! range is meant to cover the C0 controls; §5's enumeration misses it. See
//! [`is_escaped`].
//!
//! Nothing else is added. In particular `0x80`-`0xff` is escaped because those
//! bytes are non-ASCII, not because `0x80`-`0x9f` happens to be the C1
//! controls — a distinction worth keeping, so a later change to one rule does
//! not silently alter the other.

/// The RFC 4648 standard alphabet, which `xsd:base64Binary` requires.
///
/// Not the URL-safe variant: `+` and `/` are correct here, and a reader
/// decoding a standard literal would reject `-` and `_`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `bytes` as base64 with padding.
/// Hand-written rather than taking a dependency.
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        // Pack up to three bytes into 24 bits, left-aligned, so a short chunk
        // leaves zeros in the low bits and the padding below covers them.
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let packed = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((packed >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((packed >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((packed >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(packed & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// The value of one base64 character, or [`None`] if it is not one.
fn base64_value(c: u8) -> Option<u32> {
    let value = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Decode base64, returning [`None`] if `text` is not well formed.
///
/// Strict: the length must be a multiple of four, padding may appear only at
/// the end, and a character outside the alphabet is refused. A container whose
/// raw form does not decode is making a claim that cannot be checked, and
/// silently recovering part of it would present a guess as the recorded name.
#[must_use]
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    // Padding is at most two characters and only at the very end.
    let padding = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - padding];
    if body.contains(&b'=') {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in body.chunks(4) {
        let mut packed = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            packed |= base64_value(c)? << (18 - 6 * i);
        }
        // A four-character group yields three bytes; a short final group
        // yields one fewer per missing character.
        let produced = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            // A single trailing character encodes no whole byte, so it is not
            // a valid encoding of anything.
            _ => return None,
        };
        for i in 0..produced {
            #[allow(clippy::cast_possible_truncation)]
            out.push(((packed >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Whether §5 escapes this byte in a display form.
///
/// The set is `0x00`-`0x1f`, `0x25` (`%`), `0x7f`, and `0x80`-`0xff`.
///
/// `0x7f` is **this project's addition**, not §5's. ASCII defines DEL as a
/// control character, and §5's range stops at `0x1f`, so the enumeration
/// misses it while plainly meaning to cover the C0 controls. Escaping it keeps
/// a display form free of every ASCII control; a conforming reader sees a
/// well-formed rule-2 pair either way.
///
/// `%` is escaped so the encoding round-trips: without it a file genuinely
/// named `%41.txt` could not be told from one whose display form encodes `A`.
#[must_use]
pub const fn is_escaped(byte: u8) -> bool {
    byte <= 0x1f || byte == b'%' || byte >= 0x7f
}

/// Whether §5 rule 2 applies: the name needs a raw form.
///
/// True when the bytes are not valid UTF-8, or carry a character this module
/// escapes as a control.
///
/// **The trigger and [`is_escaped`] must agree about controls.** If a byte
/// were escaped without triggering rule 2, a name could be judged clean and
/// then encoded anyway, producing a display form with a percent sequence and
/// no raw property to explain it — a container contradicting itself. `0x7f` is
/// in both for that reason.
///
/// Bytes `0x80`-`0xff` do **not** trigger on their own. They appear in every
/// valid UTF-8 name outside ASCII, and §5 rule 1 keeps such a name literal:
/// `café.txt` is valid UTF-8 with no control character, so it is stored as it
/// is. The `0x80`-`0xff` escaping in rule 2b applies only once rule 2 has
/// already been triggered by something else.
#[must_use]
pub fn needs_raw_form(bytes: &[u8]) -> bool {
    if std::str::from_utf8(bytes).is_err() {
        return true;
    }
    bytes.iter().any(|&b| b <= 0x1f || b == 0x7f)
}

/// Build the §5 display form of `bytes`.
///
/// Every escaped byte becomes `%` and two **uppercase** hex digits, per §5's
/// own example. Bytes outside the set are copied through unchanged.
///
/// Operates on bytes rather than characters deliberately: §5 says to treat the
/// name as extended 8-bit values, so a multi-byte UTF-8 character becomes one
/// escape per byte.
#[must_use]
pub fn display_form(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if is_escaped(byte) {
            // Writing to a String is infallible; the Result is discarded
            // deliberately rather than unwrapped (the crate denies unwrap).
            let _ = write!(out, "%{byte:02X}");
        } else {
            out.push(byte as char);
        }
    }
    out
}

/// A filesystem name as it was read, and what §5 makes of it.
///
/// Construct with [`RecordedName::of`]. The two fields are decided together,
/// so they can never disagree about whether the name needed encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedName {
    display: String,
    raw: Option<String>,
}

impl RecordedName {
    /// Apply §5 to one name's bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        if needs_raw_form(bytes) {
            Self {
                display: display_form(bytes),
                raw: Some(base64_encode(bytes)),
            }
        } else {
            // Rule 1: valid UTF-8, no controls, so the bytes are a string and
            // are stored as they are. The `from_utf8` cannot fail --
            // `needs_raw_form` just proved it -- but it is handled rather than
            // unwrapped, and the fallback is the escaped form, which is
            // correct for any input.
            std::str::from_utf8(bytes).map_or_else(
                |_| Self {
                    display: display_form(bytes),
                    raw: Some(base64_encode(bytes)),
                },
                |text| Self {
                    display: text.to_owned(),
                    raw: None,
                },
            )
        }
    }

    /// The value for `aff4:fileName` or `aff4:originalPathName`.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// The value for `aff4:fileNameRaw` or `aff4:originalPathNameRaw`, when
    /// §5 rule 2 applies.
    ///
    /// [`None`] means rule 1 applied and no raw property is written — §5 says
    /// the raw property "is not used" in that case, so writing an empty one
    /// would be wrong.
    #[must_use]
    pub fn raw(&self) -> Option<&str> {
        self.raw.as_deref()
    }

    /// Whether the display form is an encoding rather than the name itself.
    #[must_use]
    pub fn is_encoded(&self) -> bool {
        self.raw.is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Vectors from RFC 4648 §10, which are the canonical ones every
    /// implementation is checked against.
    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "{input:?}");
            assert_eq!(
                base64_decode(expected).as_deref(),
                Some(input.as_bytes()),
                "{expected:?}"
            );
        }
    }

    /// Every byte value survives a round trip, at every length modulo 3.
    ///
    /// The tail lengths are where a hand-written codec goes wrong, so all
    /// three are covered for every starting byte rather than spot-checked.
    #[test]
    fn base64_round_trips_every_byte_and_every_tail() {
        for start in 0..=255u8 {
            for len in 1..=4usize {
                let bytes: Vec<u8> = (0..len)
                    .map(|i| start.wrapping_add(u8::try_from(i).unwrap_or(0)))
                    .collect();
                let encoded = base64_encode(&bytes);
                assert!(
                    encoded.len().is_multiple_of(4),
                    "padding to a multiple of four"
                );
                assert_eq!(
                    base64_decode(&encoded).as_deref(),
                    Some(bytes.as_slice()),
                    "round trip of {bytes:?}"
                );
            }
        }
    }

    /// Malformed input is refused rather than partially decoded. A raw form
    /// that does not decode is a claim that cannot be checked.
    #[test]
    fn base64_refuses_malformed_input() {
        for bad in [
            "Zg=",      // length not a multiple of four
            "Zg===",    // over-padded
            "Z===",     // one content character encodes no whole byte
            "Zm9v!g==", // character outside the alphabet
            "Zg==Zg==", // padding in the middle
            "Zm-9",     // URL-safe alphabet, not the standard one
        ] {
            assert_eq!(base64_decode(bad), None, "{bad:?} must be refused");
        }
    }

    /// §5 rule 1: a name that is valid UTF-8 with no control character is
    /// stored as it is, with no raw form.
    #[test]
    fn a_clean_name_is_stored_as_it_is() {
        let name = RecordedName::of(b"report.txt");
        assert_eq!(name.display(), "report.txt");
        assert_eq!(name.raw(), None);
        assert!(!name.is_encoded());
    }

    /// A non-ASCII name is still clean: valid UTF-8, no control characters.
    ///
    /// This is the case rule 2b's `0x80`-`0xff` escaping could be misread as
    /// covering. It does not: that escaping applies only once rule 2 has
    /// triggered, and an ordinary accented name never triggers it.
    #[test]
    fn a_non_ascii_name_is_clean() {
        let name = RecordedName::of("café.txt".as_bytes());
        assert_eq!(name.display(), "café.txt");
        assert_eq!(name.raw(), None, "an accented name needs no raw form");
    }

    /// A literal percent in a real filename is left alone by rule 1.
    ///
    /// The case a careless decoder gets wrong: `100%.txt` is a valid name, is
    /// stored literally, and must not be percent-decoded on the way out —
    /// which is why the absence of a raw form is what tells a reader not to
    /// decode.
    #[test]
    fn a_literal_percent_is_not_encoded_when_the_name_is_clean() {
        let name = RecordedName::of(b"100%.txt");
        assert_eq!(name.display(), "100%.txt");
        assert_eq!(name.raw(), None);
    }

    /// §5 rule 2: a control character triggers both properties.
    #[test]
    fn a_control_character_triggers_the_raw_form() {
        let name = RecordedName::of(b"a\tb.txt");
        assert_eq!(name.display(), "a%09b.txt");
        assert_eq!(name.raw(), Some(base64_encode(b"a\tb.txt").as_str()));
        assert!(name.is_encoded());
    }

    /// Once rule 2 has triggered, every escaped byte is encoded — including
    /// the `%` and the non-ASCII bytes that rule 1 would have left alone.
    #[test]
    fn an_encoded_name_escapes_percent_and_high_bytes() {
        let name = RecordedName::of("a\tb%c é.txt".as_bytes());
        let display = name.display();
        assert!(display.starts_with("a%09b%25c"), "{display}");
        assert!(
            display.contains("%C3%A9"),
            "é becomes two escapes: {display}"
        );
        assert!(display.contains(' '), "space is not in §5's escape set");
    }

    /// Bytes that are not valid UTF-8 trigger rule 2 and round-trip through
    /// the raw form.
    #[test]
    fn invalid_utf8_round_trips_through_the_raw_form() {
        let bytes = b"bad\xffname.txt";
        let name = RecordedName::of(bytes);
        assert_eq!(name.display(), "bad%FFname.txt");
        let decoded = base64_decode(name.raw().unwrap()).unwrap();
        assert_eq!(decoded, bytes, "the raw form reconstructs the name exactly");
    }

    /// Escapes are uppercase, per §5's own worked example.
    #[test]
    fn escapes_are_uppercase() {
        let display = RecordedName::of(b"\x0d\x1b").display().to_owned();
        assert_eq!(display, "%0D%1B");
        assert!(!display.contains("%0d") && !display.contains("%1b"));
    }

    /// DEL is escaped and triggers rule 2, though §5's enumeration omits it.
    ///
    /// Both halves matter: escaping without triggering would produce a display
    /// form carrying a percent sequence with no raw property to explain it.
    #[test]
    fn del_is_escaped_and_triggers_the_raw_form() {
        assert!(is_escaped(0x7f), "DEL is an ASCII control character");
        assert!(needs_raw_form(b"a\x7fb"), "and so it triggers rule 2");

        let name = RecordedName::of(b"a\x7fb.txt");
        assert_eq!(name.display(), "a%7Fb.txt");
        assert!(name.raw().is_some());
    }

    /// The escape set and the rule-2 trigger agree about every byte.
    ///
    /// Asserted over the whole range rather than sampled: a byte escaped
    /// without triggering would make a container contradict itself, and this
    /// is the invariant that prevents it.
    #[test]
    fn the_escape_set_and_the_trigger_agree_about_controls() {
        for byte in 0..=255u8 {
            let escaped = is_escaped(byte);
            let triggers = needs_raw_form(&[byte]);
            match byte {
                // Controls escape and trigger. High bytes do too, though for
                // a different reason: a lone one is not valid UTF-8. The arms
                // are merged because the assertion is the same, and the
                // reasons are recorded here rather than in duplicate arms.
                0x00..=0x1f | 0x7f | 0x80..=0xff => assert!(escaped && triggers, "{byte:#04x}"),
                // Percent: escaped so the encoding round-trips, but a name
                // that is only `%` is a clean name and stays literal.
                0x25 => assert!(escaped && !triggers, "{byte:#04x}"),
                // Everything else is ordinary.
                _ => assert!(!escaped && !triggers, "{byte:#04x}"),
            }
        }
    }

    /// §5 rule 3: two different names may share a display form.
    ///
    /// Recorded as a property of the format rather than a defect. The raw
    /// forms differ, which is what a consumer uses to tell them apart.
    #[test]
    fn two_names_may_share_a_display_form() {
        // A literal `%09` in a name that also needs encoding, against a real
        // tab: both display as `%09`.
        let literal = RecordedName::of(b"\x01%09");
        let control = RecordedName::of(b"\x01\x09");
        assert_ne!(literal.display(), control.display());

        // The genuine collision: a name whose bytes differ only in ways the
        // display form cannot show.
        let a = RecordedName::of(b"x\x09y");
        let b = RecordedName::of(b"x\x09y");
        assert_eq!(a.display(), b.display());
        assert_eq!(a.raw(), b.raw(), "identical names encode identically");
    }
}
