//! The `version.txt` container version file (spec §1).
//!
//! Every AFF4 Standard container carries a `version.txt` segment in its root:
//!
//! ```text
//! major=1
//! minor=0
//! tool=Evimetry 2.2.0
//! ```
//!
//! Name/value pairs separated by `=`, in arbitrary order, with CRLF, CR, or LF
//! line endings (spec §1). `major`/`minor` give the standard version; `tool` is
//! vendor-specific and identifies the producing tool.
//!
//! Pre-standard containers have no `version.txt` at all — the file was
//! introduced by Standard v1.0. Absence is therefore a normal condition to be
//! reported as such, never a fabricated version number.
//!
//! # Divergences from pyaff4
//!
//! pyaff4's `parseProperties` (`container.py`) splits each line on *every* `=`
//! inside a bare `try/except: pass`, so a `tool` value containing `=` is
//! silently dropped, and a malformed file yields partial data with no
//! indication. It also splits only on `\n`, leaving a stray `\r` in every value
//! of a CRLF file. This parser splits on the first `=` only, accepts all three
//! line endings, and reports [`Error::Malformed`] rather than degrading
//! quietly — a container that misstates its own version is a finding.

use std::collections::BTreeMap;
use std::fmt;

use crate::error::{Error, Locus, Result};

/// The segment name this file always has, in the container root.
pub const SEGMENT_NAME: &str = "version.txt";

/// A parsed `version.txt`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContainerVersion {
    /// Major version. `1` for AFF4 Standard v1.0a and for pyaff4-era AFF4-L;
    /// `2` for the AFF4-L Standard v1.0-ALPHA.
    pub major: u32,
    /// Minor version. `0` for v1.0a, `1` for pyaff4-era AFF4-L and for the
    /// AFF4-L Standard v1.0-ALPHA (which pairs it with major `2`).
    pub minor: u32,
    /// The producing tool, verbatim, e.g. `Evimetry 2.2.0` or `pyaff4`.
    ///
    /// Optional: spec §1 shows it in every example but does not require it, and
    /// treating its absence as fatal would reject a container over a field that
    /// carries no format semantics.
    pub tool: Option<String>,
    /// Any other name/value pairs, preserved in full.
    ///
    /// Spec §1 says vendors should only record information here that signals a
    /// deviation from the standard — so an unrecognised key is exactly the kind
    /// of thing an examiner should see, not something to discard.
    pub extra: BTreeMap<String, String>,
}

impl ContainerVersion {
    /// Parse the contents of a `version.txt` segment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if `major` or `minor` is missing or is not
    /// a non-negative integer. A container that cannot state its own version is
    /// an integrity finding, not something to guess past.
    pub fn parse(bytes: &[u8], locus: &Locus) -> Result<Self> {
        // Values are vendor strings and may be any encoding; decode lossily so
        // a stray byte cannot make the whole container unreadable. Any
        // replacement character stays visible in the reported value.
        let text = String::from_utf8_lossy(bytes);

        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        for line in split_lines(&text) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Split on the FIRST '=' only: `tool=x=y` is a tool named `x=y`.
            let Some((key, value)) = line.split_once('=') else {
                return Err(Error::malformed(
                    locus.clone(),
                    format!(
                        "{SEGMENT_NAME} line {line:?} is not a name=value pair \
                         (spec §1 requires '=' separated pairs)"
                    ),
                ));
            };
            fields.insert(key.trim().to_string(), value.trim().to_string());
        }

        if fields.is_empty() {
            return Err(Error::malformed(
                locus.clone(),
                format!("{SEGMENT_NAME} is empty; spec §1 requires major and minor"),
            ));
        }

        let major = take_number(&mut fields, "major", locus)?;
        let minor = take_number(&mut fields, "minor", locus)?;
        let tool = fields.remove("tool").filter(|t| !t.is_empty());

        Ok(Self {
            major,
            minor,
            tool,
            extra: fields,
        })
    }

    /// Whether this is AFF4 Standard v1.0a (spec §1: major 1, minor 0).
    #[must_use]
    pub fn is_v1_0(&self) -> bool {
        self.major == 1 && self.minor == 0
    }

    /// Whether this is pyaff4-era AFF4-L, which declares `major=1 minor=1`.
    ///
    /// **No specification defines version 1.1.** v1.0a states only that AFF4
    /// Standard v1.0 is major 1, minor 0; the AFF4-L Standard v1.0-ALPHA
    /// assigns AFF4-L major 2, minor 1. Version 1.1 is what pyaff4 wrote when
    /// it added logical imaging, and it is carried by every AFF4-L container
    /// in the reference corpus. Recognised because the evidence exists, not
    /// because a document sanctions the number.
    #[must_use]
    pub fn is_v1_1(&self) -> bool {
        self.major == 1 && self.minor == 1
    }

    /// Whether this is the AFF4-L Standard v1.0-ALPHA.
    ///
    /// Its §3 fixes the pair: "For AFF4-L Standard v1.0, the Major is 2, Minor
    /// is 1."
    #[must_use]
    pub fn is_v2_1(&self) -> bool {
        self.major == 2 && self.minor == 1
    }

    /// Whether this build recognises the declared version.
    ///
    /// Recognising a version is not the same as being able to check it:
    /// `2.1` is known here but declined by
    /// [`crate::lexicon::Generation::is_supported`], because naming a
    /// container accurately and measuring its conformance are separate
    /// questions. A container declaring anything else is intact but beyond
    /// this build — the caller should raise [`Error::Unsupported`], never
    /// [`Error::Malformed`].
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.is_v1_0() || self.is_v1_1() || self.is_v2_1()
    }
}

impl fmt::Display for ContainerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if let Some(tool) = &self.tool {
            write!(f, " ({tool})")?;
        }
        Ok(())
    }
}

/// Split on CRLF, CR, or LF (spec §1 permits all three).
fn split_lines(text: &str) -> impl Iterator<Item = &str> {
    // Normalising CRLF to LF first keeps a CRLF pair from yielding an empty
    // line between records.
    text.split("\r\n")
        .flat_map(|chunk| chunk.split(['\r', '\n']))
}

/// Remove `key` and parse it as a non-negative integer.
fn take_number(fields: &mut BTreeMap<String, String>, key: &str, locus: &Locus) -> Result<u32> {
    let Some(raw) = fields.remove(key) else {
        return Err(Error::malformed(
            locus.clone(),
            format!("{SEGMENT_NAME} has no {key} field (spec §1 requires it)"),
        ));
    };
    raw.parse().map_err(|_| {
        Error::malformed(
            locus.clone(),
            format!("{SEGMENT_NAME} {key}={raw:?} is not a non-negative integer"),
        )
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn locus() -> Locus {
        Locus::new("/evidence/test.aff4").segment(SEGMENT_NAME)
    }

    fn parse(bytes: &[u8]) -> Result<ContainerVersion> {
        ContainerVersion::parse(bytes, &locus())
    }

    /// The exact bytes from `AFF4Std/Base-Linear.aff4`, read out of the
    /// container rather than transcribed from the spec.
    #[test]
    fn parses_the_evimetry_v1_0_container() {
        let v = parse(b"major=1\nminor=0\ntool=Evimetry 2.2.0\n").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.tool.as_deref(), Some("Evimetry 2.2.0"));
        assert!(v.is_v1_0());
        assert!(!v.is_v1_1());
        assert!(v.is_known());
        assert!(v.extra.is_empty());
    }

    /// The exact bytes from `AFF4-L/dream.aff4`.
    #[test]
    fn parses_the_pyaff4_v1_1_container() {
        let v = parse(b"major=1\nminor=1\ntool=pyaff4\n").unwrap();
        assert!(v.is_v1_1());
        assert!(!v.is_v1_0());
        assert!(!v.is_v2_1());
        assert_eq!(v.tool.as_deref(), Some("pyaff4"));
    }

    /// AFF4-L Standard v1.0-ALPHA §3's example: major 2, minor 1.
    #[test]
    fn parses_an_aff4l_v2_1_container() {
        let v = parse(b"major=2\nminor=1\ntool=pyaff4 0.9\n").unwrap();
        assert!(v.is_v2_1());
        assert!(!v.is_v1_0() && !v.is_v1_1());
        assert!(
            v.is_known(),
            "2.1 is recognised here; refusal to check it is a separate decision"
        );
    }

    /// `Base-Linear-AllHashes.aff4` reports a different tool version from its
    /// siblings — a guard against hardcoding one vendor string.
    #[test]
    fn parses_the_evimetry_3_container() {
        let v = parse(b"major=1\nminor=0\ntool=Evimetry 3.0.0\n").unwrap();
        assert_eq!(v.tool.as_deref(), Some("Evimetry 3.0.0"));
    }

    /// Spec §1 permits CRLF, CR, or LF.
    #[test]
    fn accepts_all_three_line_endings() {
        let expected = parse(b"major=1\nminor=0\ntool=t\n").unwrap();
        assert_eq!(
            parse(b"major=1\r\nminor=0\r\ntool=t\r\n").unwrap(),
            expected
        );
        assert_eq!(parse(b"major=1\rminor=0\rtool=t\r").unwrap(), expected);
        // A file with no trailing terminator is still well-formed.
        assert_eq!(parse(b"major=1\nminor=0\ntool=t").unwrap(), expected);
    }

    /// Spec §1: ordering of name/value pairs is arbitrary.
    #[test]
    fn accepts_arbitrary_field_order() {
        let v = parse(b"tool=Evimetry 2.2.0\nminor=0\nmajor=1\n").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.tool.as_deref(), Some("Evimetry 2.2.0"));
    }

    /// pyaff4 splits on every `=` inside a bare `except: pass`, so this line is
    /// silently discarded there. Splitting on the first `=` keeps the value.
    #[test]
    fn splits_on_the_first_equals_only() {
        let v = parse(b"major=1\nminor=0\ntool=weird=tool=name\n").unwrap();
        assert_eq!(v.tool.as_deref(), Some("weird=tool=name"));
    }

    /// Spec §1 says vendors record deviations from the standard here, so an
    /// unrecognised key is worth surfacing rather than dropping.
    #[test]
    fn preserves_unrecognised_fields() {
        let v = parse(b"major=1\nminor=0\ntool=X\nvendorQuirk=sector-aligned\n").unwrap();
        assert_eq!(
            v.extra.get("vendorQuirk").map(String::as_str),
            Some("sector-aligned")
        );
    }

    #[test]
    fn tolerates_blank_lines_and_surrounding_space() {
        let v = parse(b"\nmajor = 1 \n\n  minor=0\n\n").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
    }

    /// `tool` carries no format semantics, so its absence must not reject a
    /// container that is otherwise valid.
    #[test]
    fn tool_is_optional() {
        let v = parse(b"major=1\nminor=0\n").unwrap();
        assert_eq!(v.tool, None);
        assert!(v.is_known());

        let empty_tool = parse(b"major=1\nminor=0\ntool=\n").unwrap();
        assert_eq!(
            empty_tool.tool, None,
            "an empty tool= is the same as absent"
        );
    }

    /// A container that cannot state its own version is a finding, not
    /// something to guess past. pyaff4 would raise `KeyError` here and fall
    /// through to namespace sniffing.
    #[test]
    fn missing_major_or_minor_is_malformed() {
        for bytes in [
            b"minor=0\ntool=X\n".as_slice(),
            b"major=1\ntool=X\n".as_slice(),
        ] {
            let err = parse(bytes).unwrap_err();
            assert!(err.is_integrity_finding(), "{err}");
        }
    }

    #[test]
    fn non_numeric_version_is_malformed() {
        let err = parse(b"major=one\nminor=0\n").unwrap_err();
        assert!(err.is_integrity_finding());
        assert!(err.to_string().contains("major"), "{err}");
        assert!(err.to_string().contains("one"), "{err}");
    }

    #[test]
    fn negative_version_is_malformed() {
        let err = parse(b"major=-1\nminor=0\n").unwrap_err();
        assert!(err.is_integrity_finding(), "{err}");
    }

    #[test]
    fn empty_file_is_malformed() {
        let err = parse(b"").unwrap_err();
        assert!(err.is_integrity_finding());
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn a_line_without_an_equals_is_malformed() {
        let err = parse(b"major=1\nminor=0\ngarbage\n").unwrap_err();
        assert!(err.to_string().contains("garbage"), "{err}");
    }

    /// Errors must say which file and segment they came from, so a report can
    /// point at the evidence rather than at "a container".
    #[test]
    fn errors_record_the_segment() {
        let err = parse(b"major=x\nminor=0\n").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains(SEGMENT_NAME), "{rendered}");
        assert!(rendered.contains("/evidence/test.aff4"), "{rendered}");
    }

    /// A future v1.2 container is intact, not damaged: parsing must succeed and
    /// let the caller raise Unsupported rather than Malformed.
    #[test]
    fn an_unknown_version_parses_but_is_not_known() {
        let v = parse(b"major=1\nminor=2\ntool=Future 1.0\n").unwrap();
        assert_eq!((v.major, v.minor), (1, 2));
        assert!(!v.is_known());
        assert!(!v.is_v1_0() && !v.is_v1_1() && !v.is_v2_1());

        // 2.0 is not 2.1: the AFF4-L standard fixes both numbers.
        let two_oh = parse(b"major=2\nminor=0\n").unwrap();
        assert!(!two_oh.is_known());
        assert!(!two_oh.is_v2_1());
    }

    /// A stray byte in a vendor string must not make the container unreadable;
    /// the replacement character stays visible in the value.
    #[test]
    fn invalid_utf8_degrades_without_failing() {
        let v = parse(b"major=1\nminor=0\ntool=Bad\xffTool\n").unwrap();
        assert!(v.is_v1_0());
        assert!(v.tool.unwrap().contains('\u{fffd}'));
    }

    #[test]
    fn display_is_readable() {
        let v = parse(b"major=1\nminor=0\ntool=Evimetry 2.2.0\n").unwrap();
        assert_eq!(v.to_string(), "1.0 (Evimetry 2.2.0)");

        let no_tool = parse(b"major=1\nminor=1\n").unwrap();
        assert_eq!(no_tool.to_string(), "1.1");
    }
}
