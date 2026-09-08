//! AFF4-L logical acquisition, per Schatz (2019).
//!
//! > Schatz, B.L. *AFF4-L: A Scalable Open Logical Evidence Container.*
//! > Digital Investigation 29, S143–S149. DFRWS USA 2019.
//!
//! **Two documents govern this module now.** The 2019 paper specifies what
//! `--aff4l-legacy` writes; the AFF4-L Standard v1.0-ALPHA specifies what
//! `--aff4l-v1.0` writes. Every citation below therefore names its document,
//! and no bare section number appears.
//!
//! **The paper is the specification here, not pyaff4.** The two disagree: the
//! paper's Table 3 defines nine lexicon items and pyaff4 writes only five,
//! omitting the whole AFF4-L 2019 §3.6 resource-enumeration model
//! (`LogicalAcquisitionTask`, `filesystemRoot`, `Folder`, `child`). A consumer
//! of a pyaff4 logical container therefore cannot tell which paths were the
//! acquisition roots, or walk the acquired tree. This module implements the
//! paper in full for `--aff4l-legacy`.
//!
//! `--aff4l-v1.0` writes three of those four. AFF4-L v1.0-ALPHA §4.3 does not
//! define `child`, so v2.1 output omits it and a consumer walks the tree from
//! `originalPathName` instead — see [`LogicalProfile::writes_child_edges`].
//!
//! # The three encodings
//!
//! - **AFF4-L 2019 §3.2** suspect path → ARN. Table 1's rows are test vectors below.
//! - **AFF4-L 2019 §3.4** ARN → ZIP segment name, which converts percent-encoded spaces
//!   *back* to spaces so containers browse readably in ordinary ZIP tools.
//!   The segment name is therefore not simply the escaped ARN tail.
//! - **AFF4-L 2019 §3.3** the size split: a file at or under the threshold is stored as a
//!   ZIP segment, a larger one as an `ImageStream`. The section argues for the
//!   hybrid; the specific threshold is the prototype's choice, not a
//!   requirement — see [`MAX_SEGMENT_RESIDENT_SIZE`].

use std::path::Path;

use crate::naming::RecordedName;

/// Table 3 of the paper: the AFF4-L lexicon.
///
/// Local names only; the namespace is `aff4:`. **Four of these nine are never
/// written by pyaff4** — `Folder`, `child`, `LogicalAcquisitionTask`, and
/// `filesystemRoot`, which together are AFF4-L 2019 §3.6's resource-enumeration model.
/// They are what lets a consumer identify acquisition roots and walk the
/// acquired tree; without them a logical container is a flat bag of files.
pub mod terms {
    /// The original unencoded file path and name.
    pub const ORIGINAL_FILE_NAME: &str = "originalFileName";
    /// Birth time of a file's content and metadata.
    pub const BIRTH_TIME: &str = "birthTime";
    /// Last modified time of a file's content.
    pub const LAST_WRITTEN: &str = "lastWritten";
    /// Last modified time of a file's filesystem metadata.
    pub const RECORD_CHANGED: &str = "recordChanged";
    /// Last access time of a file's content.
    pub const LAST_ACCESSED: &str = "lastAccessed";
    /// Class: a suspect file.
    pub const FILE_IMAGE: &str = "FileImage";
    /// Class: a suspect folder.
    pub const FOLDER: &str = "Folder";
    /// Class: a suspect folder, as every existing container spells it.
    ///
    /// Not in Table 3 — the paper says `Folder`. `unicode.aff4` and every other
    /// AFF4-L container in the corpus write `FolderImage`, and pyaff4's lexicon
    /// defines only that. Written alongside `Folder` so a container satisfies
    /// the specification and existing readers at once.
    pub const FOLDER_IMAGE: &str = "FolderImage";
    /// The `FileImages` contained in a Folder.
    ///
    /// AFF4-L 2019 §3.6 only. Not defined by AFF4-L v1.0-ALPHA §4.3, so it is
    /// written for `--aff4l-legacy` and withheld for `--aff4l-v1.0`.
    pub const CHILD: &str = "child";
    /// Class: a logical acquisition activity.
    pub const LOGICAL_ACQUISITION_TASK: &str = "LogicalAcquisitionTask";
    /// Points to a Folder or `FileImage` forming an acquisition root.
    pub const FILESYSTEM_ROOT: &str = "filesystemRoot";
    /// The Unix file mode: file type and permission bits, as an integer.
    ///
    /// AFF4-L v1.0-ALPHA §4.3 only, so it is written for `--aff4l-v1.0` and
    /// withheld for `--aff4l-legacy`: the AFF4-L 2019 paper does not define
    /// it.
    pub const FILE_MODE: &str = "fileMode";
    /// The separator the recorded paths of this acquisition use.
    ///
    /// AFF4-L v1.0-ALPHA §4.3 only, on the acquisition task, so it is written
    /// for `--aff4l-v1.0` and withheld for `--aff4l-legacy`: the AFF4-L 2019
    /// paper does not define it.
    ///
    /// It describes the paths this acquisition recorded rather than the
    /// container format, so the value is the acquiring platform's separator.
    /// That standard defines no `child` edge, which makes this the property a
    /// consumer splits `originalPathName` on to recover the acquired tree.
    pub const PATH_SEPARATOR: &str = "pathSeparator";
    /// Marks content stored directly as a ZIP segment (AFF4-L 2019 §3.8).
    pub const ZIP_SEGMENT: &str = "zip_segment";

    /// The entry's own name, under AFF4-L v1.0-ALPHA §1.1.
    ///
    /// That clause writes both this and [`ORIGINAL_PATH_NAME`] with the
    /// `aff4:` prefix in the requirement itself, so neither takes the second
    /// namespace AFF4-L v1.0-ALPHA §4.1 introduces.
    pub const FILE_NAME: &str = "fileName";
    /// The entry's full path, under AFF4-L v1.0-ALPHA §1.1.
    pub const ORIGINAL_PATH_NAME: &str = "originalPathName";
    /// The entry's own name as read, base64-encoded (AFF4-L v1.0-ALPHA §5).
    pub const FILE_NAME_RAW: &str = "fileNameRaw";
    /// The entry's full path as read, base64-encoded (AFF4-L v1.0-ALPHA §5).
    pub const ORIGINAL_PATH_NAME_RAW: &str = "originalPathNameRaw";
    /// Marks content stored as one ZIP segment, as AFF4-L v1.0-ALPHA §6.1
    /// spells it.
    pub const ZIP_SEGMENT_V21: &str = "ZipSegment";
}

/// Characters AFF4-L 2019 §3.1 forbids in an ARN, which must be percent-encoded.
const FORBIDDEN: &[char] = &['<', '>', '\\', '^', '`', '{', '|', '}'];

/// Characters AFF4-L 2019 §3.2 omits that RDF's `IRIREF` production still rejects.
///
/// The paper's forbidden list omits them — it names only angle brackets,
/// backslash, caret, backquote, brace and pipe — but
/// RDF 1.1 excludes `[` and `]` from the `IRIREF` production, so an ARN
/// carrying one raw makes `information.turtle` unparseable by any conformant
/// reader. AFF4-L 2019 §3.7 then spends brackets on its own Slice Map syntax
/// (`aff4://uuid[0x0:0x8000]`) without saying what a filename containing one
/// should do.
///
/// Encoding them resolves both problems at once: the metadata stays valid, and
/// a bracket that reaches the parser is unambiguously a Slice Map's rather
/// than a suspect filename's.
///
/// The double quote is here for the same reason and was found the same way:
/// `IRIREF` excludes it, AFF4-L 2019 §3.2 does not name it, and `/Library` holds
/// `About "Convert" Scripts.scpt`. Together with AFF4-L 2019 §3.2's own list, the control
/// codes, space and `%`, this closes the set — every character RDF 1.1
/// forbids in an IRI is now escaped on the way in.
///
/// `/Library` supplied both cases: `man1/[.1`, the man page for the `[`
/// builtin, and the quoted script name above. A 13.3 GiB acquisition of it
/// wrote metadata no reader could parse.
const ALSO_ILLEGAL_IN_IRI: &[char] = &['[', ']', '"'];

/// The threshold: at or below this a file is stored as a ZIP segment.
///
/// **The paper chooses this value; it does not require it.** AFF4-L 2019 §3.3 reads: "In
/// our prototype implementation we choose to store any bytestreams greater than
/// 1M in size as Image Streams, and smaller as Zip Segments." There is no MUST
/// or SHOULD, and the Standard does not cover logical files at all. pyaff4
/// treats it as policy too — `container.py:341` sets the same 1 MiB beside a
/// commented-out debugging value, and `writeLogicalStream` takes an
/// `allow_large_zipsegments` override that stores a large file as a segment
/// anyway.
///
/// What AFF4-L 2019 §3.3 *does* justify is the hybrid itself, and that reasoning holds: an
/// Image Stream "requires at least two Zip Segments and an extra layer of
/// indirection", which a large file repays and a small one does not.
///
/// Measured on 20,000 small text files, storing everything as `ImageStream`s
/// instead produced a container 2.9x larger with 4x the ZIP members and 3x the
/// RDF subjects: a tiny file becomes a single chunk with no neighbors to
/// compress against, so per-member deflate beats chunked compression outright.
/// Changing the value breaks no conformance rule — readers dispatch on declared
/// `rdf:type`, not on size — provided AFF4-L 2019 §3.8's rule still holds, that
/// `aff4:zip_segment` joins the type list only when the file really is stored
/// that way.
pub const MAX_SEGMENT_RESIDENT_SIZE: u64 = 1024 * 1024;

/// Percent-encode one character.
fn percent_encode(out: &mut String, ch: char) {
    use std::fmt::Write as _;
    let mut buffer = [0u8; 4];
    for byte in ch.encode_utf8(&mut buffer).as_bytes() {
        let _ = write!(out, "%{byte:02X}");
    }
}

/// Encode a suspect path as an ARN path fragment, per AFF4-L 2019 §3.2.
///
/// Rules, verbatim from the paper:
///
/// 1. Forward slashes delimit paths.
/// 2. Control, space, percent, and forbidden characters are percent-encoded.
/// 3. Unicode printables outside ASCII are UTF-8 and **case-sensitive** — they
///    are *not* escaped, which is what keeps `ネコ.txt` readable.
/// 4. The host part of a UNC path is a regular path component.
#[must_use]
pub fn arn_path_fragment(path: &str) -> String {
    // A UNC path `\\host\share` maps to `/host/share`: the host becomes an
    // ordinary component, so it does not get the empty-host `//` marker.
    let (is_unc, rest) = if let Some(rest) = path.strip_prefix(r"\\") {
        (true, rest.replace('\\', "/"))
    } else {
        (false, path.replace('\\', "/"))
    };

    let mut out = String::with_capacity(rest.len() + 8);
    out.push('/');
    if !is_unc && !rest.starts_with('/') {
        // Table 1: a non-UNC path carries a double slash, marking the absence
        // of a host. `c:` becomes `//c:`, not `/c:`.
        out.push('/');
    }

    for ch in rest.chars() {
        match ch {
            '/' => out.push('/'),
            c if c.is_control()
                || c == ' '
                || c == '%'
                || FORBIDDEN.contains(&c)
                || ALSO_ILLEGAL_IN_IRI.contains(&c) =>
            {
                percent_encode(&mut out, c);
            }
            c => out.push(c),
        }
    }
    out
}

/// The full ARN for `path` within `volume_arn`.
#[must_use]
pub fn arn_for_path(volume_arn: &str, path: &str) -> String {
    format!("{volume_arn}{}", arn_path_fragment(path))
}

/// The ARN naming one acquired entry.
///
/// The two profiles disagree about what an object is called, and this is where
/// that choice is made once. [`LogicalProfile::Legacy`] encodes the suspect
/// path per AFF4-L 2019 §3.2; [`LogicalProfile::V1Alpha`] mints a fresh GUID per AFF4-L
/// v1.0-ALPHA §2, and the path is recorded in properties instead.
///
/// # Errors
///
/// [`crate::Error::Io`] if the OS entropy source is unavailable while minting
/// a GUID. That is returned rather than fallen back on: the reasoning on
/// `container_writer::new_uuid` for a volume ARN applies per object too, since
/// a predictable or colliding name is unrecoverable confusion about which
/// evidence is which.
pub fn arn_for_entry(
    volume_arn: &str,
    path: &str,
    profile: LogicalProfile,
    output: &Path,
) -> crate::error::Result<String> {
    match profile {
        LogicalProfile::Legacy => Ok(arn_for_path(volume_arn, path)),
        // `new_uuid` renders lower case, which AFF4-L v1.0-ALPHA §2 requires.
        LogicalProfile::V1Alpha => Ok(format!(
            "aff4://{}",
            crate::write::container_writer::new_uuid(output)?
        )),
    }
}

/// Map an ARN to its ZIP segment name, per AFF4-L 2019 §3.4.
///
/// Strips the volume identifier and the separator that follows it, then
/// converts percent-encoded spaces back to literal spaces. That last step is
/// the reason a segment name is not simply the escaped ARN tail: the paper
/// wants containers to browse readably in `WinRAR` or 7-Zip.
#[must_use]
pub fn segment_name_for_arn(volume_arn: &str, arn: &str, profile: LogicalProfile) -> String {
    if profile.is_v1_alpha() {
        // AFF4-L v1.0-ALPHA §1.2 replaces this mapping rather than amending
        // it: the member is the ARN itself, colon and slashes intact, as that
        // AFF4-L v1.0-ALPHA §6.1 example shows. The `%20` decode below is skipped
        // deliberately rather than relied on to do nothing on a GUID, so a
        // later extensible part is never silently rewritten.
        return arn.to_owned();
    }
    let tail = arn.strip_prefix(volume_arn).unwrap_or(arn);
    // One leading separator is removed; a non-UNC path's second slash is part
    // of the name and stays, which is what makes `/C:/foo` in Table 2.
    let tail = tail.strip_prefix('/').unwrap_or(tail);
    // The same AFF4-L 2019 §3.4 decode `Arn::member_name` applies, so a file written here
    // and a stream written through the ARN land on one spelling. They drifted
    // once — this one decoding `%20`, that one re-escaping it to `%2520` — and
    // a container was written whose streams nothing could read back.
    tail.replace("%20", " ")
}

/// Whether a file of `size` bytes is stored as a ZIP segment (AFF4-L 2019 §3.3).
#[must_use]
pub fn is_segment_resident(size: u64) -> bool {
    size <= MAX_SEGMENT_RESIDENT_SIZE
}

/// The paths AFF4 reserves at the volume root, which a logical file must not
/// collide with (AFF4-L 2019 §3.8 via pyaff4's `isAFF4Collision`).
#[must_use]
pub fn is_reserved_name(name: &str) -> bool {
    matches!(
        name,
        "information.turtle" | "version.txt" | "container.description"
    )
}

/// Normalize a filesystem path for recording as `aff4:originalFileName`.
///
/// The paper preserves the original unencoded path; this keeps it verbatim
/// rather than canonicalizing, because the path as the examiner supplied it is
/// what the acquisition observed.
///
/// **Serves the AFF4-L 2019 path, and is lossy by inheritance.** The value it
/// returns feeds two consumers: [`arn_for_entry`], which under
/// [`LogicalProfile::Legacy`] hands it to [`arn_path_fragment`] to build the
/// ARN and from it the ZIP member name, and the `aff4:originalFileName`
/// property. A name that is not valid UTF-8 becomes U+FFFD here, before either
/// sees it. That has always been this writer's behavior for the 2019 format
/// and stays so, because the escaping pair built on top of it is lossless and
/// correct for that document.
///
/// AFF4-L v1.0-ALPHA §5 requires the bytes instead, and
/// [`recorded_path_bytes`] supplies them. The two coexist because the two
/// documents disagree about what a name is.
#[must_use]
pub fn original_file_name(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// A path's bytes, for AFF4-L v1.0-ALPHA §5 normalization.
///
/// # Platforms
///
/// On Unix a path *is* a byte string, and this returns it with no conversion —
/// which is what lets AFF4-L v1.0-ALPHA §5 record a name the kernel accepted but UTF-8 cannot
/// represent.
///
/// On Windows a path is a sequence of 16-bit UTF-16 code units, not bytes, and
/// may contain an unpaired surrogate that no UTF-8 encoding can represent.
/// Which byte encoding AFF4-L v1.0-ALPHA §5 intends there is a question the standard has not
/// answered, so this returns [`None`] rather than choosing one: writing a raw
/// property in an encoding the standard does not name would assert a faithful
/// record that a reader cannot interpret. The caller falls back to the lossy
/// conversion and records no raw form.
#[must_use]
pub fn recorded_path_bytes(path: &Path) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        Some(path.as_os_str().as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        // Valid UTF-16 with no lone surrogate is representable as UTF-8, and
        // for such a name the bytes are unambiguous. Anything else is the
        // open question above.
        let _ = path;
        path.to_str().map(|text| text.as_bytes().to_vec())
    }
}

/// What one acquired entry is called, in both documents' terms.
///
/// The lossy string serves the AFF4-L 2019 path and the ARN built from it; the
/// pair serves AFF4-L v1.0-ALPHA §5. They travel together because every
/// consumer that needs one needs the other, and because keeping them in one
/// value is what stops a caller supplying a display string from one entry and
/// names from another.
pub struct EntryNames<'a> {
    /// The path as [`original_file_name`] renders it.
    pub display: &'a str,
    /// The AFF4-L v1.0-ALPHA §5 forms, where the platform supplies bytes.
    pub names: Option<&'a (RecordedName, RecordedName)>,
}

/// The AFF4-L v1.0-ALPHA §5 pair for a path and for its own last component.
///
/// Both are derived from the **same** bytes, splitting on the separator before
/// normalizing. That order is the only one that works: after encoding, a
/// literal `/` in a display form is indistinguishable from a separator, and
/// reading the filesystem twice would let the two disagree about one entry.
///
/// Returns [`None`] where the platform cannot supply bytes, which is
/// [`recorded_path_bytes`]'s Windows case.
#[must_use]
pub fn recorded_names(path: &Path) -> Option<(RecordedName, RecordedName)> {
    let bytes = recorded_path_bytes(path)?;
    // A trailing separator would make the last component empty, so it is
    // dropped first -- a folder names itself, not the empty string.
    let trimmed = match bytes.iter().rposition(|&b| b != b'/' && b != b'\\') {
        Some(end) => &bytes[..=end],
        None => &bytes[..],
    };
    let tail = trimmed
        .iter()
        .rposition(|&b| b == b'/' || b == b'\\')
        .map_or(trimmed, |i| &trimmed[i + 1..]);
    Some((RecordedName::of(&bytes), RecordedName::of(tail)))
}

/// What one `stat` of a filesystem entry yielded.
///
/// Every field is optional because platforms differ: Windows has no
/// `recordChanged` or file mode, and Linux needs `statx` for `birthTime`. An
/// absent value is recorded as absent rather than substituted — pyaff4 fills
/// Windows `birthTime` from `st_ctime`, which is creation time only by
/// accident of the CRT.
///
/// The mode travels with the timestamps because it comes from the same call,
/// and passing them separately would let a caller pair one entry's mode with
/// another's times.
#[derive(Debug, Default, Clone)]
pub struct FsMetadata {
    /// `aff4:birthTime`.
    pub birth: Option<String>,
    /// `aff4:lastWritten`.
    pub written: Option<String>,
    /// `aff4:lastAccessed`.
    pub accessed: Option<String>,
    /// `aff4:recordChanged`.
    pub changed: Option<String>,
    /// `aff4:fileMode` — the Unix file mode, absent off Unix.
    pub mode: Option<u32>,
}

/// The Unix file mode, where the platform has one.
///
/// AFF4-L v1.0-ALPHA §4.3 defines `fileMode` as the Unix file mode as an
/// integer. That is the whole mode, type bits included, not the permission
/// bits alone: narrowing it would silently change what the property records.
///
/// [`None`] off Unix. A mode is a Unix concept, and synthesizing one from
/// Windows attributes would assert something the filesystem never said — the
/// same reasoning that keeps `birthTime` absent rather than guessed.
#[must_use]
pub fn file_mode_of(metadata: &std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some(metadata.mode())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Read what a platform can supply from one `stat`.
///
/// Rendered as RFC 3339 in **UTC**, unlike pyaff4's host-local rendering: the
/// same file acquired in two timezones must yield the same literal, or two
/// containers of one file disagree for no reason.
#[must_use]
pub fn metadata_of(metadata: &std::fs::Metadata) -> FsMetadata {
    use std::time::SystemTime;

    fn render(time: std::io::Result<SystemTime>) -> Option<String> {
        let time = time.ok()?;
        let secs = time.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
        Some(format_rfc3339_utc(secs))
    }

    let mut stamps = FsMetadata {
        birth: render(metadata.created()),
        written: render(metadata.modified()),
        accessed: render(metadata.accessed()),
        changed: None,
        mode: file_mode_of(metadata),
    };

    // `recordChanged` is POSIX ctime, which `std` does not expose. On Unix the
    // raw stat field is available.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let ctime = metadata.ctime();
        if ctime > 0 {
            stamps.changed = u64::try_from(ctime).ok().map(format_rfc3339_utc);
        }
    }

    stamps
}

/// Render a Unix timestamp as RFC 3339 in UTC.
///
/// Hand-rolled rather than pulling in `chrono` for one call site; the project
/// deliberately keeps it out of the dependency tree.
#[must_use]
pub fn format_rfc3339_utc(secs: u64) -> String {
    // Days from the civil epoch, via Howard Hinnant's algorithm.
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// How a logical acquisition stores what it acquires.
///
/// Not `Copy`: `algorithms` is a `Vec`, since `--hash` takes an arbitrary
/// selection rather than one of a fixed few.
#[derive(Debug, Clone, Default)]
pub struct LogicalOptions {
    /// Chunking and compression for files stored as `ImageStream`s (AFF4-L 2019 §3.3).
    pub stream: crate::write::stream_writer::StreamOptions,
    /// Whether to deduplicate file content per AFF4-L 2019 §4.
    ///
    /// **Off by default, deliberately.** Dedupe replaces each file's own stored
    /// bytes with references into a shared pool, so a single damaged chunk
    /// harms every file that shares it, and the container no longer holds one
    /// contiguous copy of any file. That is a trade an examiner should opt into
    /// knowingly rather than inherit from a default.
    pub deduplicate: bool,
    /// Which AFF4-L format to write.
    pub profile: LogicalProfile,
    /// Which digests to record for each acquired file.
    ///
    /// Every algorithm here is computed in one pass over the file's bytes, on
    /// its own thread, so the cost of adding one is the slower of the two
    /// rather than their sum — see [`crate::hash::MultiHasher`].
    ///
    /// Empty means [`crate::hash_selection::DEFAULT`]. Stored rather than
    /// defaulted at construction so `LogicalOptions::default()` stays cheap and
    /// the CLI remains the single place the default is applied.
    pub algorithms: Vec<crate::model::HashAlgorithm>,
}

/// Which AFF4-L format an acquisition writes.
///
/// The two are separate code paths from the ARN outward, because the standards
/// disagree about what an object is called: [`Self::Legacy`] names a file by
/// its suspect path, [`Self::V1Alpha`] by a GUID. Everything downstream — the
/// segment name, where the path is recorded, the declared version — follows
/// from that one choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogicalProfile {
    /// The AFF4-L 2019 paper, declaring version 1.1. What this tool has always
    /// written, and what pyaff4 writes.
    ///
    /// The default, and the reason is the standard rather than the code: the
    /// AFF4-L Standard v1.0-ALPHA is a pre-release whose Canonical Reference
    /// Images, which it says take precedence over its own text, are not
    /// published. Until they are, the format with containers in the world is
    /// the safer thing to write by default.
    #[default]
    Legacy,
    /// The AFF4-L Standard v1.0-ALPHA, declaring version 2.1.
    V1Alpha,
}

impl LogicalOptions {
    /// The algorithms to record, resolving an empty selection to the default.
    ///
    /// [`LogicalOptions::default()`] leaves the list empty rather than cloning
    /// a constant, so an empty list means "unspecified", never "record no
    /// digests". A container with no digests could not be verified at all,
    /// which is not something a default should silently produce.
    #[must_use]
    pub fn algorithms(&self) -> &[crate::model::HashAlgorithm] {
        if self.algorithms.is_empty() {
            &crate::hash_selection::DEFAULT
        } else {
            &self.algorithms
        }
    }
}

impl LogicalProfile {
    /// Whether this profile writes AFF4-L Standard v1.0-ALPHA constructs.
    #[must_use]
    pub fn is_v1_alpha(self) -> bool {
        matches!(self, Self::V1Alpha)
    }

    /// Whether this profile writes `aff4:child` containment edges.
    ///
    /// True for [`Self::Legacy`] only. AFF4-L 2019 §3.6 defines `child` as part
    /// of its resource-enumeration model, and the 2019 paper governs what
    /// `--aff4l-legacy` writes.
    ///
    /// The AFF4-L v1.0-ALPHA §4.3 property table does not define `child`. It
    /// keeps `LogicalAcquisitionTask`, `filesystemRoot` and `Folder`, and adds
    /// `pathSeparator`, from which the acquired tree is recoverable:
    /// `originalPathName` carries each entry's full path, and `pathSeparator`
    /// says how to split it. So a v2.1 consumer reconstructs containment from
    /// the paths rather than from an explicit edge.
    ///
    /// Emitting `child` in v2.1 output would put a term in the container that
    /// its governing document does not define, which is the writer-side
    /// leniency this project does not permit: aff4tools' own output conforms
    /// exactly, whatever it accepts on read.
    #[must_use]
    pub fn writes_child_edges(self) -> bool {
        matches!(self, Self::Legacy)
    }

    /// The version this profile's container declares.
    #[must_use]
    pub fn version_profile(self) -> crate::write::container_writer::VersionProfile {
        use crate::write::container_writer::VersionProfile;
        match self {
            Self::Legacy => VersionProfile::Logical,
            Self::V1Alpha => VersionProfile::LogicalV21,
        }
    }
}

/// The separator the acquiring platform's paths use.
///
/// Written as AFF4-L v1.0-ALPHA §4.3's `pathSeparator`. It describes the paths
/// this acquisition recorded, not the container format, so it is the *host's*
/// separator rather than a constant of the standard.
const fn host_path_separator() -> &'static str {
    if cfg!(windows) { "\\" } else { "/" }
}

/// Open the acquisition-task subject and write the properties that do not
/// depend on what was acquired.
///
/// # Why this is a function
///
/// Three entry points build this subject — [`acquire_logical`],
/// [`acquire_logical_scanned`] and [`acquire_logical_prescanned`] — and each
/// previously wrote its type inline. A property added to one and forgotten in
/// the others would mean two acquisition modes producing containers the third
/// does not match, with nothing to catch it: the modes differ in how they
/// *discover* files, which is no reason for their metadata to differ.
///
/// `filesystemRoot` stays at the call sites, because it names what that
/// acquisition actually reached and is only knowable once the walk is done.
fn open_acquisition_task(
    writer: &mut crate::write::container_writer::ContainerWriter,
    task_arn: &str,
    profile: LogicalProfile,
) {
    use crate::write::turtle::{TurtleTerm, XSD_STRING};

    let lexicon = crate::lexicon::STANDARD;
    writer
        .graph_mut()
        .add_type(task_arn, &lexicon.iri(terms::LOGICAL_ACQUISITION_TASK));

    // AFF4-L v1.0-ALPHA §4.3 defines this; the AFF4-L 2019 paper does not, so
    // legacy output must not gain it.
    if profile.is_v1_alpha() {
        writer.graph_mut().add(
            task_arn,
            &v1_alpha_iri(terms::PATH_SEPARATOR),
            TurtleTerm::typed(host_path_separator(), XSD_STRING),
        );
    }
}

/// The IRI of a term as AFF4-L v1.0-ALPHA assigns it.
///
/// A term this standard introduces belongs to its own namespace; one it
/// restates from an earlier document keeps the namespace that document gave
/// it. [`crate::lexicon::namespace_for`] holds that table, and this is the
/// writer's way in.
///
/// **The leniency runs one way only.** A reader may honor either namespace
/// (AFF4-L v1.0-ALPHA §4.1), and `is_known_namespace` implements that. A
/// writer may not choose, which is why this consults the table rather than
/// formatting a fixed prefix the way `Lexicon::iri` does.
fn v1_alpha_iri(local_name: &str) -> String {
    let namespace = crate::lexicon::namespace_for(crate::lexicon::Generation::Aff4L10, local_name);
    format!("{namespace}{local_name}")
}

/// What deduplication achieved over one acquisition.
#[derive(Debug, Clone, Copy)]
pub struct DedupeSummary {
    /// Distinct chunks stored.
    pub unique_chunks: usize,
    /// Bytes actually stored.
    pub stored: u64,
    /// Bytes presented, duplicates included.
    pub presented: u64,
}

impl DedupeSummary {
    /// Bytes deduplication avoided storing.
    #[must_use]
    pub fn saved(&self) -> u64 {
        self.presented.saturating_sub(self.stored)
    }
}

/// One file awaiting its map, held until the shared stream is written.
#[derive(Debug)]
pub(crate) struct PendingDedupe {
    /// The file's ARN.
    pub arn: String,
    /// One target ID per chunk, in file order.
    pub target_ids: Vec<u32>,
    /// The file's true length, before NUL padding.
    pub size: u64,
}

/// What one logical acquisition produced.
#[derive(Debug, Default)]
pub struct LogicalAcquisition {
    /// Files acquired.
    pub files: u64,
    /// Folders recorded.
    pub folders: u64,
    /// Bytes of file content stored.
    pub bytes: u64,
    /// Paths that could not be read, with the reason.
    pub skipped: Vec<(std::path::PathBuf, String)>,
    /// Files whose length on disk differed from the length the walk recorded,
    /// as (path, expected, actual).
    ///
    /// These files **were** acquired, at their actual length — this is not a
    /// completeness finding, and it must never be reported as one. The walk's
    /// figure is an estimate by the time the bytes are read, and under
    /// `--scan-first` the entire tree is inventoried before the container
    /// exists, so a file on a live system has minutes in which to change.
    pub changed: Vec<(std::path::PathBuf, u64, u64)>,
    /// What deduplication saved, when it was used.
    pub dedupe: Option<DedupeSummary>,
    /// Files whose maps are written once the shared stream exists.
    pub(crate) deduped: Vec<PendingDedupe>,
}

/// Acquire `roots` into `writer` as an AFF4-L logical image.
///
/// Implements AFF4-L 2019 §3.8's ordered recipe and §3.6's enumeration model in full.
///
/// # Errors
///
/// [`Error::Io`](crate::error::Error::Io) if a container write fails. A source
/// path that cannot be read is **recorded and skipped**, not fatal: a
/// permission error partway through a tree should not discard the acquisition.
pub fn acquire_logical(
    writer: &mut crate::write::container_writer::ContainerWriter,
    roots: &[std::path::PathBuf],
    options: &LogicalOptions,
    locus: &crate::error::Locus,
    on_progress: &mut dyn FnMut(&LogicalAcquisition),
) -> crate::error::Result<LogicalAcquisition> {
    use crate::write::turtle::{TurtleTerm, XSD_DATE_TIME, XSD_LONG, XSD_STRING};

    let volume_arn = writer.volume_arn().as_str().to_owned();
    let lexicon = crate::lexicon::STANDARD;
    let mut result = LogicalAcquisition::default();
    // The pool spans the whole acquisition, so identical content is stored once
    // *across* files rather than merely within one.
    let mut pool = options
        .deduplicate
        .then(|| crate::write::dedupe::ChunkPool::new(options.stream.chunk_size));

    // AFF4-L 2019 §3.6: one acquisition task, naming each root. A named ARN rather than
    // the paper's blank node `_:1` — a blank node cannot be referenced across
    // containers or survive a graph merge, and an acquisition task is exactly
    // the provenance an examiner may need to cite.
    let task_arn = format!("{volume_arn}/acquisition");
    open_acquisition_task(writer, &task_arn, options.profile);

    for root in roots {
        // Discovery first, writing second. The item list is the same protocol
        // the scanner thread produces, so acquisition is driven by a flat
        // stream either way.
        let mut items = Vec::new();
        collect_items(root, &mut items);
        let acquired = acquire_from_items(
            writer,
            items.into_iter(),
            &volume_arn,
            options,
            pool.as_mut(),
            &mut result,
            on_progress,
        )?;
        // As with `aff4:child`: the edge is asserted only for a root that was
        // actually acquired. A named root that is a symlink or a special file
        // is reported as skipped, and `filesystemRoot` must not point at a
        // subject the container describes with no triples.
        for root_arn in acquired {
            writer.graph_mut().add(
                &task_arn,
                &lexicon.iri(terms::FILESYSTEM_ROOT),
                TurtleTerm::iri(&root_arn),
            );
        }
    }

    writer.graph_mut().add(
        &task_arn,
        &lexicon.iri(lexicon.stored),
        TurtleTerm::iri(&volume_arn),
    );

    finish_dedupe(writer, &mut result, pool, options, locus)?;

    let _ = (XSD_DATE_TIME, XSD_LONG, XSD_STRING);
    Ok(result)
}

/// Write the shared chunk stream and every deduplicated file's map.
///
/// The shared stream and the Block Hash ARNs are written last, once every file
/// has contributed its chunks; each file's map is then written against the
/// final target list. Shared by both entry points so the two cannot drift.
///
/// A no-op when deduplication is off.
///
/// # Errors
///
/// [`Error::Io`](crate::error::Error::Io) if a container write fails.
fn finish_dedupe(
    writer: &mut crate::write::container_writer::ContainerWriter,
    result: &mut LogicalAcquisition,
    pool: Option<crate::write::dedupe::ChunkPool>,
    options: &LogicalOptions,
    locus: &crate::error::Locus,
) -> crate::error::Result<()> {
    let Some(pool) = pool else {
        return Ok(());
    };
    result.dedupe = Some(DedupeSummary {
        unique_chunks: pool.unique_chunks(),
        stored: pool.stored_bytes(),
        presented: pool.presented_bytes(),
    });
    let targets = pool.finish(writer, options.stream, locus)?;
    for file in std::mem::take(&mut result.deduped) {
        crate::write::map_writer::write_slice_map(
            writer,
            &file.arn,
            &file.target_ids,
            &targets,
            file.size,
            options.stream.chunk_size as u64,
            locus,
        )?;
    }
    Ok(())
}

/// What a scanned acquisition tells its caller as it runs.
///
/// The acquisition state, and the scanner's running totals as
/// `(files_found, cost_found, scan_complete)`. The totals are optional so a
/// caller that has no denominator to report can drop its display to liveness.
pub type ScannedProgress<'a> = dyn FnMut(&LogicalAcquisition, Option<(u64, u64, bool)>) + 'a;

/// As [`acquire_logical`], with a scanner thread inventorying ahead.
///
/// The callback receives the acquisition state and the scanner's running
/// totals as `(files_found, cost_found, complete)`.
///
/// Discovery and acquisition genuinely overlap: the queue is consumed lazily,
/// one item at a time, so the scanner runs ahead of the writer by up to
/// [`SCAN_QUEUE_CAPACITY`](crate::write::scan::SCAN_QUEUE_CAPACITY) entries.
/// That bound is the only limit on how far ahead it may run.
///
/// The item stream can still end early: the scanner stops walking when the
/// consumer hangs up. `acquire_from_items` reports that truncation, and the
/// acquisition is not failed by it.
///
/// # Errors
///
/// As [`acquire_logical`].
pub fn acquire_logical_scanned(
    writer: &mut crate::write::container_writer::ContainerWriter,
    roots: &[std::path::PathBuf],
    options: &LogicalOptions,
    locus: &crate::error::Locus,
    on_progress: &mut ScannedProgress<'_>,
) -> crate::error::Result<LogicalAcquisition> {
    use crate::write::turtle::TurtleTerm;

    let volume_arn = writer.volume_arn().as_str().to_owned();
    let lexicon = crate::lexicon::STANDARD;
    let mut result = LogicalAcquisition::default();
    let mut pool = options
        .deduplicate
        .then(|| crate::write::dedupe::ChunkPool::new(options.stream.chunk_size));

    let task_arn = format!("{volume_arn}/acquisition");
    open_acquisition_task(writer, &task_arn, options.profile);

    let scanner =
        crate::write::scan::spawn(roots.to_vec(), crate::write::scan::SCAN_QUEUE_CAPACITY);
    let (items, run) = scanner.split();
    let totals = run.totals();

    let acquired_roots = {
        let totals = std::sync::Arc::clone(&totals);
        // The totals are readable throughout, so the display is live while the
        // scan runs.
        let mut report = |acq: &LogicalAcquisition| {
            let snapshot = totals.snapshot();
            on_progress(acq, Some(snapshot));
        };
        acquire_from_items(
            writer,
            items.into_iter(),
            &volume_arn,
            options,
            pool.as_mut(),
            &mut result,
            &mut report,
        )
    };

    // The queue is exhausted, so the thread is finished or about to be. Joining
    // it before the acquisition returns keeps the scanner's lifetime inside
    // this call rather than leaving a detached thread behind.
    run.join();

    // Unwrapped after the join, deliberately. A minting failure must not
    // leave the scanner thread detached, so the acquisition's own error is
    // raised only once the thread's lifetime has ended inside this call.
    let acquired_roots = acquired_roots?;

    // As in `acquire_logical`: the edge is asserted only for a root that was
    // actually acquired.
    for root_arn in acquired_roots {
        writer.graph_mut().add(
            &task_arn,
            &lexicon.iri(terms::FILESYSTEM_ROOT),
            TurtleTerm::iri(&root_arn),
        );
    }

    writer.graph_mut().add(
        &task_arn,
        &lexicon.iri(lexicon.stored),
        TurtleTerm::iri(&volume_arn),
    );

    finish_dedupe(writer, &mut result, pool, options, locus)?;
    Ok(result)
}

/// As [`acquire_logical`], driven by an item stream the caller already
/// collected to completion, rather than one this call discovers itself.
///
/// For `--scan-first`: the caller has already run [`crate::write::scan::spawn`]
/// to completion and drained its queue, so the total is exact before the first
/// byte is written. This drives that finished stream through the same
/// `acquire_from_items` the concurrent and inline paths use, so the container
/// it produces — ARNs, triples, child edges, order — is identical to theirs.
///
/// Because `items` already spans every root in one balanced stream, this
/// closes every directory it opens; nothing is left on the stack to drain into
/// `result.skipped`.
///
/// # Errors
///
/// As [`acquire_logical`].
pub fn acquire_logical_prescanned(
    writer: &mut crate::write::container_writer::ContainerWriter,
    items: Vec<crate::write::scan::ScanItem>,
    options: &LogicalOptions,
    locus: &crate::error::Locus,
    on_progress: &mut dyn FnMut(&LogicalAcquisition),
) -> crate::error::Result<LogicalAcquisition> {
    use crate::write::turtle::TurtleTerm;

    let volume_arn = writer.volume_arn().as_str().to_owned();
    let lexicon = crate::lexicon::STANDARD;
    let mut result = LogicalAcquisition::default();
    let mut pool = options
        .deduplicate
        .then(|| crate::write::dedupe::ChunkPool::new(options.stream.chunk_size));

    let task_arn = format!("{volume_arn}/acquisition");
    open_acquisition_task(writer, &task_arn, options.profile);

    let acquired_roots = acquire_from_items(
        writer,
        items.into_iter(),
        &volume_arn,
        options,
        pool.as_mut(),
        &mut result,
        on_progress,
    )?;

    for root_arn in acquired_roots {
        writer.graph_mut().add(
            &task_arn,
            &lexicon.iri(terms::FILESYSTEM_ROOT),
            TurtleTerm::iri(&root_arn),
        );
    }

    writer.graph_mut().add(
        &task_arn,
        &lexicon.iri(lexicon.stored),
        TurtleTerm::iri(&volume_arn),
    );

    finish_dedupe(writer, &mut result, pool, options, locus)?;
    Ok(result)
}

/// Walk `path` into a flat item list, writing nothing.
///
/// The inline counterpart to the scanner thread: same item protocol, same
/// order, no concurrency. Used when no scanner thread is running, so an
/// acquisition still has an item stream to be driven by.
///
/// The skip reasons are the acquisition's own, not the scanner's: a symlink
/// says so, a special file says so, and an unreadable path is explained by
/// [`explain_io_error`].
fn collect_items(path: &std::path::Path, out: &mut Vec<crate::write::scan::ScanItem>) {
    use crate::write::scan::ScanItem;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            out.push(ScanItem::Skipped {
                path: path.to_path_buf(),
                reason: explain_io_error(&e),
            });
            return;
        }
    };

    // Symlinks are recorded as skipped rather than followed. Following one can
    // duplicate content or escape the acquisition root entirely, and the paper
    // does not define a representation for the link itself.
    if metadata.is_symlink() {
        out.push(ScanItem::Skipped {
            path: path.to_path_buf(),
            reason: "symlink; not followed".to_owned(),
        });
        return;
    }

    // A FIFO, socket, or device node is neither a folder nor a regular file, so
    // it gets no type and nothing is written for it. Refused before any triple
    // exists, so no subject is left carrying timestamps and no `rdf:type`.
    if !metadata.is_dir() && !metadata.is_file() {
        out.push(ScanItem::Skipped {
            path: path.to_path_buf(),
            reason: "not a regular file".to_owned(),
        });
        return;
    }

    if metadata.is_file() {
        out.push(ScanItem::File {
            path: path.to_path_buf(),
            size: metadata.len(),
        });
        return;
    }

    out.push(ScanItem::Dir {
        path: path.to_path_buf(),
    });
    match std::fs::read_dir(path) {
        Ok(entries) => {
            // Sorted, matching both the scanner and the recursion this
            // replaces, so a degraded run produces the same container as a
            // scanned one. The order reaches the container's turtle. The same
            // helper the scanner uses, so the two walks cannot drift.
            let mut failures = Vec::new();
            let children = crate::write::scan::children_from_entries(
                path,
                entries.map(|e| e.map(|e| e.path())),
                &mut failures,
            );
            // Emitted before recursing, exactly where the scanner sends them.
            for (failed, reason) in failures {
                out.push(ScanItem::Skipped {
                    path: failed,
                    reason,
                });
            }
            for child in children {
                collect_items(&child, out);
            }
        }
        Err(e) => {
            // The folder itself is still recorded, but its contents could not
            // be listed. Reported as skipped, and it asserts no children: the
            // container must not claim a tree it never read.
            out.push(ScanItem::Skipped {
                path: path.to_path_buf(),
                reason: explain_io_error(&e),
            });
        }
    }
    out.push(ScanItem::DirEnd);
}

/// Write a directory's `aff4:child` edges, if its profile defines the term.
///
/// AFF4-L 2019 §3.6 is the containment edge pyaff4 never writes, and what lets
/// a consumer reconstruct the tree. Called only with children that were
/// actually acquired, so no edge names a skipped path.
///
/// Writes nothing under [`LogicalProfile::V1Alpha`]: AFF4-L v1.0-ALPHA §4.3
/// defines no `child` property. See [`LogicalProfile::writes_child_edges`].
fn write_child_edges(
    writer: &mut crate::write::container_writer::ContainerWriter,
    parent: &str,
    children: &[String],
    profile: LogicalProfile,
) {
    use crate::write::turtle::TurtleTerm;

    if !profile.writes_child_edges() {
        return;
    }
    let lexicon = crate::lexicon::STANDARD;
    for child in children {
        writer
            .graph_mut()
            .add(parent, &lexicon.iri(terms::CHILD), TurtleTerm::iri(child));
    }
}

/// One open directory: its ARN, and the children acquired inside it.
struct OpenDir {
    /// Where the directory is, kept so a truncated stream can report it as a
    /// filesystem path, like every other entry in `skipped`.
    path: std::path::PathBuf,
    arn: String,
    children: Vec<String>,
}

/// Acquire an item stream into `writer`, returning the ARNs of acquired roots.
///
/// Items arrive in walk order, each directory bracketed by
/// [`ScanItem::Dir`](crate::write::scan::ScanItem::Dir) and
/// [`ScanItem::DirEnd`](crate::write::scan::ScanItem::DirEnd).
///
/// A directory's `aff4:child` edges are written when it closes, because an edge
/// must never name a path that turned out to be skipped: a consumer following
/// one would reach an ARN that resolves to nothing. The recursion this replaced
/// carried that outcome on the call stack; the directory stack carries it now.
///
/// The edges are written only under [`LogicalProfile::Legacy`]; the children
/// are tracked either way, since the stack is also what promotes an acquired
/// directory to an `aff4:filesystemRoot`.
#[allow(clippy::too_many_arguments)]
fn acquire_from_items(
    writer: &mut crate::write::container_writer::ContainerWriter,
    items: impl Iterator<Item = crate::write::scan::ScanItem>,
    volume_arn: &str,
    options: &LogicalOptions,
    mut pool: Option<&mut crate::write::dedupe::ChunkPool>,
    result: &mut LogicalAcquisition,
    on_progress: &mut dyn FnMut(&LogicalAcquisition),
) -> crate::error::Result<Vec<String>> {
    use crate::write::scan::ScanItem;

    let lexicon = crate::lexicon::STANDARD;
    let mut stack: Vec<OpenDir> = Vec::new();
    let mut roots: Vec<String> = Vec::new();

    for item in items {
        match item {
            ScanItem::Skipped { path, reason } => {
                result.skipped.push((path, reason));
            }
            ScanItem::Dir { path } => {
                let display = original_file_name(&path);
                // AFF4-L v1.0-ALPHA §5 works from the name's bytes; the lossy
                // string above serves the AFF4-L 2019 path and the ARN.
                let names = recorded_names(&path);
                let arn = arn_for_entry(volume_arn, &display, options.profile, writer.path())?;
                let stamps = match std::fs::symlink_metadata(&path) {
                    Ok(m) => metadata_of(&m),
                    // The directory was enumerated a moment ago; if its
                    // metadata has since become unreadable the entry is still
                    // recorded, without timestamps rather than not at all.
                    Err(_) => FsMetadata::default(),
                };
                write_table_3(
                    writer,
                    &arn,
                    &EntryNames {
                        display: &display,
                        names: names.as_ref(),
                    },
                    &stamps,
                    volume_arn,
                    options.profile,
                    true,
                );
                // Both names, deliberately. The paper's Table 3 defines
                // `aff4:Folder`; every corpus container writes
                // `aff4:FolderImage` instead. Writing one would either depart
                // from the specification or be unrecognizable to the tools that
                // exist, so this writes both.
                //
                // Deliberately NOT `aff4:Image`. A folder holds no bytes, and
                // typing it as an image makes every reader — ours included —
                // try to resolve a data stream it does not have. pyaff4 does
                // type folders `aff4:Image`; this is a considered departure.
                writer
                    .graph_mut()
                    .add_type(&arn, &lexicon.iri(terms::FOLDER));
                writer
                    .graph_mut()
                    .add_type(&arn, &lexicon.iri(terms::FOLDER_IMAGE));
                result.folders += 1;
                stack.push(OpenDir {
                    path,
                    arn,
                    children: Vec::new(),
                });
            }
            ScanItem::DirEnd => {
                if let Some(done) = stack.pop() {
                    write_child_edges(writer, &done.arn, &done.children, options.profile);
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(done.arn);
                    } else {
                        roots.push(done.arn);
                    }
                }
            }
            ScanItem::File { path, size } => {
                let display = original_file_name(&path);
                let names = recorded_names(&path);
                let arn = arn_for_entry(volume_arn, &display, options.profile, writer.path())?;
                record_file(
                    writer,
                    &path,
                    &arn,
                    &display,
                    names.as_ref(),
                    size,
                    volume_arn,
                    options,
                    pool.as_deref_mut(),
                    result,
                );
                // A regular file that reached the writer is a child, whether or
                // not its bytes could be stored: it was named, typed, and its
                // Table 3 metadata written, so the edge reaches a subject the
                // container does describe. Only paths refused before any triple
                // was written — the `Skipped` arm above — get no edge.
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(arn);
                } else {
                    roots.push(arn);
                }
                on_progress(result);
            }
        }
    }

    // A stream that ends mid-tree leaves directories open. Their `Dir` items
    // already wrote Table 3 metadata and the folder types, so the graph now
    // describes folders whose contents were never finished — and without this
    // drain the loop would simply fall out, discarding the stack and reporting
    // a clean success for an incomplete container. That is the silent partial
    // this project refuses: a truncated stream must be reported, not dropped.
    //
    // This cannot happen for a balanced stream, so a well-formed acquisition is
    // unaffected. It becomes reachable when the producer is the scanner thread,
    // whose channel closes on a send failure or a panic during unwind, ending
    // the loop indistinguishably from normal completion.
    while let Some(open) = stack.pop() {
        // The edges are still written, for the children acquired before the
        // truncation. Those children were genuinely acquired and the graph
        // describes them, so each edge names a real subject; dropping them
        // would discard true information about what the container does hold.
        write_child_edges(writer, &open.arn, &open.children, options.profile);
        result.skipped.push((
            open.path,
            "directory not closed; the item stream ended before its contents \
             were finished"
                .to_owned(),
        ));
        // Deliberately not promoted to a root or to a parent's child list. The
        // directory is incomplete, so `aff4:filesystemRoot` must not present it
        // as a fully acquired tree.
    }

    Ok(roots)
}

/// Record one regular file: metadata, types, content, and AFF4-L 2019 §3.7 hashes, in
/// AFF4-L 2019 §3.8's order.
///
/// `size` is the size the item stream reported. It is what decides the AFF4-L 2019 §3.3
/// storage form; the size actually recorded is what the read produced, so a
/// file that changed underneath the walk is stored at its true length.
#[allow(clippy::too_many_arguments)]
fn record_file(
    writer: &mut crate::write::container_writer::ContainerWriter,
    path: &std::path::Path,
    arn: &str,
    display: &str,
    names: Option<&(RecordedName, RecordedName)>,
    size: u64,
    volume_arn: &str,
    options: &LogicalOptions,
    pool: Option<&mut crate::write::dedupe::ChunkPool>,
    result: &mut LogicalAcquisition,
) {
    use crate::write::turtle::{TurtleTerm, XSD_LONG};

    let lexicon = crate::lexicon::STANDARD;

    let stamps = match std::fs::symlink_metadata(path) {
        Ok(m) => metadata_of(&m),
        // The file was enumerated a moment ago. If its metadata has since
        // become unreadable it is still recorded, without timestamps rather
        // than not at all; the content read below reports its own failure.
        Err(_) => FsMetadata::default(),
    };

    // A large file's bytes go through `write_image_stream_as`, which emits
    // `aff4:stored` for the stream it writes. That stream's ARN *is* the file's
    // own (see `record_large_file`), so letting Table 3 emit it too put the
    // same triple on the same subject twice.
    let stream_will_record_stored = !is_segment_resident(size);
    write_table_3(
        writer,
        arn,
        &EntryNames { display, names },
        &stamps,
        volume_arn,
        options.profile,
        !stream_will_record_stored,
    );

    writer
        .graph_mut()
        .add_type(arn, &lexicon.iri(terms::FILE_IMAGE));
    writer
        .graph_mut()
        .add_type(arn, &lexicon.iri(lexicon.image));

    // AFF4-L 2019 §4: with deduplication on, every file becomes a Map over the shared chunk
    // pool regardless of size — the AFF4-L 2019 §3.3 threshold does not apply, because no
    // file has its own storage to choose a form for.
    if let Some(pool) = pool {
        record_deduplicated_file(writer, path, arn, size, pool, options, result);
        return;
    }

    // AFF4-L 2019 §3.3: small files are ZIP segments, large ones ImageStreams. The large
    // path streams — a file above the threshold must never be read whole into
    // memory, which is the whole reason the threshold exists.
    if !is_segment_resident(size) {
        record_large_file(
            writer,
            path,
            arn,
            size,
            options.stream,
            options.algorithms(),
            result,
        );
        return;
    }

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            result
                .skipped
                .push((path.to_path_buf(), explain_io_error(&e)));
            return;
        }
    };

    // The length recorded is what was actually read. The digests just computed
    // and the segment written below both come from `bytes`, so recording the
    // walk's figure would put a size in the container that its own hashes and
    // its own stored bytes contradict — with nothing saying which to believe.
    let actual = bytes.len() as u64;
    if actual != size {
        result.changed.push((path.to_path_buf(), size, actual));
    }

    // AFF4-L 2019 §3.7 requires linear bitstream hashes; which algorithms
    // compute them is the examiner's choice, via `--hash`.
    {
        let graph = writer.graph_mut();
        for digest in crate::hash::digests_of(&bytes, options.algorithms()) {
            graph.add(
                arn,
                &lexicon.iri(lexicon.hash),
                TurtleTerm::typed(digest.hex(), lexicon.iri(digest.algorithm().name())),
            );
        }
        graph.add(
            arn,
            &lexicon.iri(lexicon.size),
            TurtleTerm::typed(actual.to_string(), XSD_LONG),
        );
    }

    let segment = segment_name_for_arn(volume_arn, arn, options.profile);
    if is_reserved_name(&segment) {
        result.skipped.push((
            path.to_path_buf(),
            format!("{segment} collides with an AFF4 reserved name"),
        ));
        return;
    }

    // AFF4-L 2019 §3.8, and AFF4-L v1.0-ALPHA §6.1: the type joins the list only when the
    // file really is stored that way. The two documents spell it differently,
    // and each container gets the spelling its own document defines.
    let zip_segment_term = if options.profile.is_v1_alpha() {
        terms::ZIP_SEGMENT_V21
    } else {
        terms::ZIP_SEGMENT
    };
    writer
        .graph_mut()
        .add_type(arn, &lexicon.iri(zip_segment_term));
    if let Err(e) = writer.add_deflated_segment(&segment, &bytes) {
        result.skipped.push((path.to_path_buf(), e.to_string()));
        return;
    }
    result.files += 1;
    result.bytes += actual;
}

/// Record one file as a deduplicated `Map` over the shared chunk pool (AFF4-L 2019 §4).
///
/// The file's chunks go into `pool`; its map is written later, once every file
/// has contributed and the shared stream's target list is final. The AFF4-L 2019 §3.7
/// digests are computed here over the file's **true** bytes — not the NUL-padded
/// chunks — so a deduplicated container's recorded hashes are the same values a
/// non-deduplicated one would record, and match what `sha1sum` says of the
/// original file.
fn record_deduplicated_file(
    writer: &mut crate::write::container_writer::ContainerWriter,
    path: &std::path::Path,
    arn: &str,
    size: u64,
    pool: &mut crate::write::dedupe::ChunkPool,
    options: &LogicalOptions,
    result: &mut LogicalAcquisition,
) {
    use crate::write::turtle::{TurtleTerm, XSD_LONG};

    let lexicon = crate::lexicon::STANDARD;
    let locus = crate::error::Locus::new(path);

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            result
                .skipped
                .push((path.to_path_buf(), explain_io_error(&e)));
            return;
        }
    };

    // Hash the true bytes as they stream past on their way into the pool.
    let mut hashing = HashingReader {
        inner: file,
        hasher: crate::hash::MultiHasher::for_algorithms(options.algorithms()),
    };
    let deduped = match pool.absorb(&mut hashing, &locus) {
        Ok(d) => d,
        Err(e) => {
            result.skipped.push((path.to_path_buf(), e.to_string()));
            return;
        }
    };
    let digests = hashing.hasher.finish();

    // The size recorded is what was actually read, not what `stat` predicted.
    // The file was acquired in full, at its true length, so the change is
    // reported as a changed file, not as a skipped (unacquired) path.
    if deduped.size != size {
        result
            .changed
            .push((path.to_path_buf(), size, deduped.size));
    }

    {
        let graph = writer.graph_mut();
        for digest in &digests {
            graph.add(
                arn,
                &lexicon.iri(lexicon.hash),
                TurtleTerm::typed(digest.hex(), lexicon.iri(digest.algorithm().name())),
            );
        }
        graph.add(
            arn,
            &lexicon.iri(lexicon.size),
            TurtleTerm::typed(deduped.size.to_string(), XSD_LONG),
        );
    }

    result.deduped.push(PendingDedupe {
        arn: arn.to_owned(),
        target_ids: deduped.target_ids,
        size: deduped.size,
    });
    result.files += 1;
    result.bytes += deduped.size;
}

/// Feeds bytes onward while digesting them, so nothing is read twice.
struct HashingReader<R> {
    inner: R,
    /// The selected algorithms, each on its own thread.
    hasher: crate::hash::MultiHasher,
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Record a file above the AFF4-L 2019 §3.3 threshold as an `ImageStream`.
///
/// **Streamed, never buffered.** The file is read in chunks straight into the
/// bevy builder, which is the point of the threshold: a multi-gigabyte file must
/// not need multi-gigabyte memory. `write_image_stream_as` computes the AFF4-L 2019 §3.7
/// digests in that same pass, so nothing is re-read to hash it.
///
/// # The file ARN *is* the stream
///
/// One subject is typed `FileImage, Image, ImageStream`, and the bevies are
/// stored under the file's own path: `/path/to/big.bin/00000000`. There is no
/// separate stream ARN and no `aff4:dataStream` indirection.
///
/// This is taken from `AFF4-L/unicode.aff4`, where every file above the
/// threshold has exactly this shape. An earlier attempt here gave the stream its
/// own ARN joined by `dataStream`; that reads as a `DiskImage` naming a Map, so
/// our own reader looked for `map` and `idx` members that a logical file does
/// not have, and failed with "specified file not found in archive". The corpus
/// form also keeps AFF4-L 2019 §3.4's promise that the container browses readably: the
/// bevies sit exactly where the file does.
fn record_large_file(
    writer: &mut crate::write::container_writer::ContainerWriter,
    path: &std::path::Path,
    arn: &str,
    size: u64,
    stream: crate::write::stream_writer::StreamOptions,
    algorithms: &[crate::model::HashAlgorithm],
    result: &mut LogicalAcquisition,
) {
    use crate::write::stream_writer::write_image_stream_as;
    use crate::write::turtle::{TurtleTerm, XSD_LONG};

    let lexicon = crate::lexicon::STANDARD;
    let locus = crate::error::Locus::new(path);

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            result
                .skipped
                .push((path.to_path_buf(), explain_io_error(&e)));
            return;
        }
    };

    // AFF4-L 2019 §3.7 requires linear digests over the bytes stored; which
    // algorithms compute them is the examiner's choice, via `--hash`.
    let written = match write_image_stream_as(writer, arn, &mut file, stream, algorithms, &locus) {
        Ok(w) => w,
        Err(e) => {
            result.skipped.push((path.to_path_buf(), e.to_string()));
            return;
        }
    };

    // The size recorded is what was actually read, not what `stat` predicted.
    // A file that grew or shrank mid-read would otherwise get a size its own
    // stored bytes contradict. The file was acquired in full, at its true
    // length, so the change is reported as a changed file, not as a skipped
    // (unacquired) path.
    if written.size != size {
        result
            .changed
            .push((path.to_path_buf(), size, written.size));
        let graph = writer.graph_mut();
        graph.add(
            arn,
            &lexicon.iri(lexicon.size),
            TurtleTerm::typed(written.size.to_string(), XSD_LONG),
        );
    }

    result.files += 1;
    result.bytes += written.size;
}

/// The last component of a recorded path — the entry's own name.
///
/// AFF4-L v1.0-ALPHA §1.1 records the full path and the name separately, and
/// this derives the second from the first rather than taking it from the
/// filesystem again, so the two can never disagree about one entry.
///
/// Both separators are split on: a path recorded on Windows carries
/// backslashes, and the acquiring host is not necessarily the one that
/// recorded it. A trailing separator yields the component before it, so a
/// folder path names the folder rather than the empty string.
fn entry_name(path: &str) -> &str {
    path.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
}

/// Write Table 3's common metadata for one entry.
///
/// `record_stored` is false for a file whose bytes become an `ImageStream`:
/// `write_image_stream_as` already emits `aff4:stored` for the stream, and a
/// large logical file's stream ARN is the file's own, so emitting it here as
/// well wrote the identical triple twice on one subject. Harmless to an RDF
/// reader — a repeated triple is the same statement — but this writer's output
/// must conform exactly, and a duplicate makes a byte comparison against
/// another writer differ for no reason.
fn write_table_3(
    writer: &mut crate::write::container_writer::ContainerWriter,
    arn: &str,
    entry: &EntryNames<'_>,
    stamps: &FsMetadata,
    volume_arn: &str,
    profile: LogicalProfile,
    record_stored: bool,
) {
    use crate::write::turtle::{
        TurtleTerm, XSD_BASE64_BINARY, XSD_DATE_TIME, XSD_LONG, XSD_STRING,
    };

    let EntryNames { display, names } = entry;
    let display = *display;

    let lexicon = crate::lexicon::STANDARD;
    let graph = writer.graph_mut();
    if profile.is_v1_alpha() {
        // AFF4-L v1.0-ALPHA §1.1: the name is a GUID, so the path is carried
        // here or nowhere. Both properties are written, because the full path
        // and the entry's own name answer different questions and
        // AFF4-L v1.0-ALPHA §1.1 names both.
        //
        // AFF4-L v1.0-ALPHA §5 decides their form. Where the platform supplies
        // the name's bytes, a name needing encoding carries a raw form beside
        // the display form; where it does not, the lossy conversion is
        // recorded alone rather than asserting a raw form that is not faithful.
        let (path_name, file_name) = match names {
            Some((path_name, file_name)) => (path_name.clone(), file_name.clone()),
            None => (
                RecordedName::of(display.as_bytes()),
                RecordedName::of(entry_name(display).as_bytes()),
            ),
        };

        for (term, raw_term, name) in [
            (
                terms::ORIGINAL_PATH_NAME,
                terms::ORIGINAL_PATH_NAME_RAW,
                &path_name,
            ),
            (terms::FILE_NAME, terms::FILE_NAME_RAW, &file_name),
        ] {
            graph.add(
                arn,
                &lexicon.iri(term),
                TurtleTerm::typed(name.display(), XSD_STRING),
            );
            // AFF4-L v1.0-ALPHA §5 rule 1: the raw property "is not used" for
            // a clean name, so an absent raw form writes no triple rather than
            // an empty one.
            if let Some(raw) = name.raw() {
                graph.add(
                    arn,
                    &lexicon.iri(raw_term),
                    TurtleTerm::typed(raw, XSD_BASE64_BINARY),
                );
            }
        }
    } else {
        graph.add(
            arn,
            &lexicon.iri(terms::ORIGINAL_FILE_NAME),
            TurtleTerm::typed(display, XSD_STRING),
        );
    }
    for (term, value) in [
        (terms::BIRTH_TIME, &stamps.birth),
        (terms::LAST_WRITTEN, &stamps.written),
        (terms::LAST_ACCESSED, &stamps.accessed),
        (terms::RECORD_CHANGED, &stamps.changed),
    ] {
        if let Some(value) = value {
            graph.add(
                arn,
                &lexicon.iri(term),
                TurtleTerm::typed(value, XSD_DATE_TIME),
            );
        }
    }
    // AFF4-L v1.0-ALPHA §4.3's file mode. That standard supplies the term and
    // the AFF4-L 2019 paper does not, so legacy output must not gain it.
    // Absent off Unix, where there is no mode to record.
    if profile.is_v1_alpha()
        && let Some(mode) = stamps.mode
    {
        graph.add(
            arn,
            &lexicon.iri(terms::FILE_MODE),
            TurtleTerm::typed(mode.to_string(), XSD_LONG),
        );
    }
    if record_stored {
        graph.add(
            arn,
            &lexicon.iri(lexicon.stored),
            TurtleTerm::iri(volume_arn),
        );
    }
}

/// Explain an OS error in terms the examiner can act on.
///
/// A raw `Operation not permitted (os error 1)` is accurate and useless: it does
/// not say *why*, and the reflex — rerun under `sudo` — does not work.
///
/// On macOS, `EPERM` on a readable path almost always means **TCC**
/// (Transparency, Consent and Control), which gates access on the *calling
/// application* rather than the user. `/private/var/db/CoreDuet` is mode
/// `drwxr-xr-x` and still refuses `root`, because the terminal running the tool
/// has not been granted Full Disk Access. `EACCES`, by contrast, is ordinary
/// file permissions, where elevating genuinely does help.
///
/// The distinction matters for the acquisition record: a path missing because
/// the operator lacked a macOS privacy grant is a different finding from a path
/// missing because it was unreadable.
#[must_use]
pub fn explain_io_error(error: &std::io::Error) -> String {
    #[cfg(target_os = "macos")]
    if error.raw_os_error() == Some(1) {
        return format!(
            "{error} — macOS denied access to this path regardless of user. \
             This is TCC (privacy protection), not file permissions, so `sudo` \
             does not help: grant Full Disk Access to the terminal or tool \
             running the acquisition (System Settings > Privacy & Security > \
             Full Disk Access), then acquire again"
        );
    }
    error.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const VOLUME: &str = "aff4://e6bae91b-14d231833e18";

    /// **Table 1 of the paper.** These are the specification's own worked
    /// examples, so they are the closest thing to an external oracle this
    /// encoding has.
    #[test]
    fn table_1_path_to_arn_vectors() {
        let cases = [
            ("c:", "aff4://e6bae91b-14d231833e18//c:"),
            ("c:\\", "aff4://e6bae91b-14d231833e18//c:/"),
            ("c:\\foo", "aff4://e6bae91b-14d231833e18//c:/foo"),
            (r"\\bar\c$", "aff4://e6bae91b-14d231833e18/bar/c$"),
            (
                "\\\\bar\\c$\\foo\\ネコ.txt",
                "aff4://e6bae91b-14d231833e18/bar/c$/foo/ネコ.txt",
            ),
            ("/foo/bar", "aff4://e6bae91b-14d231833e18//foo/bar"),
            (
                "/foo/some file",
                "aff4://e6bae91b-14d231833e18//foo/some%20file",
            ),
        ];

        for (path, expected) in cases {
            assert_eq!(
                arn_for_path(VOLUME, path),
                expected,
                "Table 1 vector failed for {path:?}"
            );
        }
    }

    /// **Table 2 of the paper, verbatim**: ARN to ZIP segment name.
    ///
    /// Note row 4: the paper prints `bar/c$/foo` for `…/bar/c$`, which is a
    /// typo in the published table — the other six rows are self-consistent and
    /// the rule (strip volume, strip one separator, decode `%20`) yields
    /// `bar/c$`. Asserted as the rule dictates, with the discrepancy recorded
    /// rather than silently matched.
    #[test]
    fn table_2_arn_to_segment_name_vectors() {
        let cases = [
            ("aff4://e6bae91b-14d231833e18//c:", "/c:"),
            ("aff4://e6bae91b-14d231833e18//c:/", "/c:/"),
            ("aff4://e6bae91b-14d231833e18//c:/foo", "/c:/foo"),
            ("aff4://e6bae91b-14d231833e18/bar/c$", "bar/c$"),
            (
                "aff4://e6bae91b-14d231833e18/bar/c$/foo/ネコ.txt",
                "bar/c$/foo/ネコ.txt",
            ),
            ("aff4://e6bae91b-14d231833e18//foo/bar", "/foo/bar"),
            (
                "aff4://e6bae91b-14d231833e18//foo/some%20file",
                "/foo/some file",
            ),
        ];

        for (arn, expected) in cases {
            assert_eq!(
                segment_name_for_arn(VOLUME, arn, LogicalProfile::Legacy),
                expected,
                "Table 2 vector failed for {arn:?}"
            );
        }
    }

    /// The two naming paths must agree, on every vector, forever.
    ///
    /// A small file is named by `segment_name_for_arn` and a large one by
    /// `Arn::member_name`, and for a while they disagreed: this one decoded
    /// `%20` to a space, that one re-escaped it to `%2520`. A 5 GiB
    /// acquisition then wrote 312 streams under names no reader could resolve,
    /// and `export` dropped 44,198 of 91,226 files while exiting 0. Nothing
    /// caught it because no test compared the two.
    #[test]
    fn both_naming_paths_agree_on_every_table_2_vector() {
        let locus = crate::error::Locus::new("x");
        let volume = crate::arn::Arn::parse(VOLUME, &locus).unwrap();

        for tail in [
            "//c:",
            "//c:/",
            "//c:/foo",
            "/bar/c$",
            "/bar/c$/foo/\u{30cd}\u{30b3}.txt",
            "//foo/bar",
            "//foo/some%20file",
            "//foo/some%20%20file",
            "//foo/some%2520file",
            "//Titles/Bumper%3AOpener/Disc.png",
            "/laptop/My%20Documents/FileSchemeURIs.doc",
        ] {
            let arn = format!("{VOLUME}{tail}");
            let parsed = crate::arn::Arn::parse(&arn, &locus).unwrap();
            assert_eq!(
                parsed
                    .member_name(&volume, crate::arn::NameMapping::Escaped)
                    .as_deref(),
                Some(segment_name_for_arn(VOLUME, &arn, LogicalProfile::Legacy).as_str()),
                "the two naming paths disagree for {tail:?}"
            );
        }
    }

    /// A bracket in a suspect filename must be percent-encoded.
    ///
    /// `[` and `]` are not in AFF4-L 2019 §3.2's forbidden list — which names only angle
    /// brackets, backslash, caret, backquote, brace and pipe — but they are
    /// excluded from Turtle's `IRIREF` production,
    /// so an ARN carrying one raw makes `information.turtle` unparseable. The
    /// paper never reconciles this: AFF4-L 2019 §3.7's Slice Map syntax
    /// (`aff4://uuid[0x0:0x8000]`) puts brackets inside an IRI without saying
    /// how a *filename* containing one should be written.
    ///
    /// Real files hit it. `/Library` holds `man1/[.1`, the man page for the
    /// `[` builtin, and a crash-log folder named `[2026-08-25_…]=Auth Timeout`.
    /// A 13.3 GiB acquisition of it wrote metadata no reader could parse.
    ///
    /// Encoding them keeps the two uses distinct: a bracket that survives into
    /// the parser is a Slice Map's, never a filename's.
    #[test]
    fn a_bracket_in_a_filename_is_escaped() {
        assert_eq!(arn_path_fragment("/usr/man/[.1"), "//usr/man/%5B.1");
        assert_eq!(
            arn_path_fragment("/logs/[2026]=x/f"),
            "//logs/%5B2026%5D=x/f"
        );
        // The closing bracket alone is escaped too: a name may carry either.
        assert_eq!(arn_path_fragment("/a]b"), "//a%5Db");
    }

    /// Every character RDF 1.1 forbids in an IRI must be escaped.
    ///
    /// Asserted as a set rather than one case at a time: AFF4-L 2019 §3.2's list predates
    /// the containers this tool writes, and each character missing from it
    /// surfaced only when a real acquisition hit it — `[` from `man1/[.1`,
    /// then `"` from `About "Convert" Scripts.scpt`, one after the other, each
    /// costing a 13 GiB re-acquisition to find. The whole `IRIREF` exclusion
    /// set is checked here so the next one is caught by this test instead.
    #[test]
    fn no_character_illegal_in_an_iri_survives_into_an_arn() {
        // RDF 1.1 IRIREF excludes these, plus everything below 0x21.
        let illegal: Vec<char> = "<>\"{}|^`\\"
            .chars()
            .chain((0..=0x20u8).map(char::from))
            .collect();

        for c in illegal {
            let fragment = arn_path_fragment(&format!("/a{c}b"));
            assert!(
                !fragment.contains(c),
                "{c:?} (U+{:04X}) is illegal in an IRI but survived into {fragment:?}",
                c as u32
            );
        }
    }

    /// The escape must round-trip to the original name.
    ///
    /// The member keeps the escape — AFF4-L 2019 §3.4 decodes only `%20` — so what proves
    /// the acquisition faithful is that the recorded path still names the file.
    #[test]
    fn a_bracketed_name_round_trips_through_its_arn() {
        for original in ["/usr/man/[.1", "/logs/[2026-08-25]=Auth Timeout/x.xml"] {
            let fragment = arn_path_fragment(original);
            assert!(
                !fragment.contains('['),
                "no raw bracket may reach the metadata: {fragment}"
            );
            assert_eq!(
                crate::arn::unescape(&fragment).trim_start_matches('/'),
                original.trim_start_matches('/'),
                "the escaped fragment must decode back to the suspect path"
            );
        }
    }

    /// Unicode is preserved, not escaped — AFF4-L 2019 §3.2 rule 3, and what makes a
    /// container readable in an ordinary ZIP browser.
    #[test]
    fn unicode_survives_unescaped() {
        let arn = arn_for_path(VOLUME, "/tmp/ネコ.txt");
        assert!(arn.ends_with("/tmp/ネコ.txt"), "{arn}");
        assert!(
            !arn.contains('%'),
            "unicode must not be percent-encoded: {arn}"
        );
    }

    /// Forbidden characters and controls are encoded; the set is AFF4-L 2019 §3.1's.
    #[test]
    fn forbidden_characters_are_encoded() {
        let arn = arn_for_path(VOLUME, "/tmp/a<b>c|d");
        assert!(
            arn.contains("%3C") && arn.contains("%3E") && arn.contains("%7C"),
            "{arn}"
        );
    }

    /// `EPERM` is explained as TCC, with the remedy that actually works.
    ///
    /// The raw text is `Operation not permitted (os error 1)`, which sends an
    /// examiner to `sudo` — and `sudo` does not help, because TCC gates on the
    /// calling application rather than the user. Verified against
    /// `/private/var/db/CoreDuet`, which is mode `drwxr-xr-x` and still refuses
    /// root without Full Disk Access.
    #[test]
    #[cfg(target_os = "macos")]
    fn permission_denied_explains_tcc_and_names_the_remedy() {
        let eperm = std::io::Error::from_raw_os_error(1);
        let text = explain_io_error(&eperm);

        assert!(
            text.contains("Full Disk Access"),
            "the remedy must be named: {text}"
        );
        assert!(
            text.contains("sudo` does not help"),
            "the reflex that does not work must be ruled out: {text}"
        );
        assert!(
            text.contains("Operation not permitted"),
            "the original OS text must survive: {text}"
        );
    }

    /// An ordinary permissions error is left alone.
    ///
    /// `EACCES` really is file permissions, where elevating does help, so it
    /// must not be relabelled as a privacy grant.
    #[test]
    #[cfg(target_os = "macos")]
    fn ordinary_permission_errors_are_not_relabelled_as_tcc() {
        let eacces = std::io::Error::from_raw_os_error(13);
        let text = explain_io_error(&eacces);
        assert!(
            !text.contains("Full Disk Access"),
            "EACCES is not a TCC denial: {text}"
        );
    }

    /// The AFF4-L 2019 §3.3 split threshold.
    #[test]
    fn the_segment_threshold_is_one_mebibyte() {
        assert!(is_segment_resident(0));
        assert!(is_segment_resident(MAX_SEGMENT_RESIDENT_SIZE));
        assert!(!is_segment_resident(MAX_SEGMENT_RESIDENT_SIZE + 1));
    }

    /// Timestamps render as RFC 3339 UTC, checked against known epochs.
    #[test]
    fn timestamps_render_as_rfc3339_utc() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(format_rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap day, which a naive day-count gets wrong.
        assert_eq!(format_rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    /// Round trip: a path encodes to an ARN whose segment name decodes back to
    /// something a reader can locate.
    #[test]
    fn paths_with_spaces_round_trip() {
        let arn = arn_for_path(VOLUME, "/foo/some file");
        assert!(arn.contains("%20"), "the ARN escapes the space: {arn}");
        let segment = segment_name_for_arn(VOLUME, &arn, LogicalProfile::Legacy);
        assert_eq!(segment, "/foo/some file", "the segment name restores it");
    }

    /// Read a written container's `information.turtle`.
    fn read_container_turtle(path: &std::path::Path) -> String {
        use std::io::Read as _;
        let file = std::fs::File::open(path).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        let mut buf = String::new();
        zip.by_name("information.turtle")
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        buf
    }

    /// An item stream that ends mid-tree is reported, never silently dropped.
    ///
    /// `collect_items` always emits balanced brackets, but the scanner thread
    /// does not: its channel closes on a send failure or on a panic during
    /// unwind, and the consuming loop then ends exactly as it would on a
    /// finished tree. A directory left open has already been written to the
    /// graph as a folder, so falling out of the loop would leave the container
    /// asserting folders nothing links to while the acquisition reported a
    /// clean success.
    ///
    /// # Synthetic paths, on purpose
    ///
    /// The stream is built by hand over paths that do not exist. The library
    /// may not create files — `clippy.toml` denies the write APIs to enforce
    /// the read-only rule — and this test does not need them: every arm the
    /// drain depends on runs without touching a disk. The `Dir` arm falls back
    /// to default timestamps when its metadata read fails, and the `File` arm
    /// writes Table 3 metadata and the type triples *before* it attempts to
    /// read content, then reports the failed read in `skipped`. The file's ARN
    /// still joins its parent's child list, which is the deliberate choice this
    /// test pins: a file the graph describes keeps its edge even when its bytes
    /// could not be stored.
    #[test]
    fn a_truncated_item_stream_is_reported_as_skipped() {
        use crate::write::scan::ScanItem;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("truncated.aff4");
        let registry = crate::write::guard::SourceRegistry::new();
        let mut writer =
            crate::write::container_writer::ContainerWriter::create(&out, &registry).unwrap();
        let volume_arn = writer.volume_arn().as_str().to_owned();

        // Dir(A), File(A/f), Dir(A/s), File(A/s/g) — and no `DirEnd` at all:
        // the shape a scanner that stopped partway through leaves behind.
        let tree = std::path::PathBuf::from("/tree");
        let items = vec![
            ScanItem::Dir { path: tree.clone() },
            ScanItem::File {
                path: tree.join("f.txt"),
                size: 2,
            },
            ScanItem::Dir {
                path: tree.join("s"),
            },
            ScanItem::File {
                path: tree.join("s").join("g.txt"),
                size: 2,
            },
        ];

        let mut result = LogicalAcquisition::default();
        let mut noop = |_: &LogicalAcquisition| {};
        let roots = acquire_from_items(
            &mut writer,
            items.into_iter(),
            &volume_arn,
            &LogicalOptions::default(),
            None,
            &mut result,
            &mut noop,
        )
        .expect("minting cannot fail with a working entropy source");

        // 1. Both unclosed directories are reported, so the acquisition is
        //    known to be incomplete instead of passing for a clean run.
        let unclosed: Vec<_> = result
            .skipped
            .iter()
            .filter(|(_, reason)| reason.contains("not closed"))
            .collect();
        assert_eq!(
            unclosed.len(),
            2,
            "both unclosed directories must be reported: {:?}",
            result.skipped
        );
        for expected in [tree.clone(), tree.join("s")] {
            assert!(
                unclosed.iter().any(|(p, _)| *p == expected),
                "{} must be named as unclosed: {:?}",
                expected.display(),
                result.skipped
            );
        }

        // An unclosed directory is not a fully acquired root.
        assert!(
            roots.is_empty(),
            "an unclosed directory is not a fully acquired root: {roots:?}"
        );

        // 2. The child edges for items seen before the truncation are still
        //    written, one per directory. Each names a subject the graph really
        //    describes: the `File` arm wrote Table 3 metadata and the types for
        //    both paths before their contents failed to read.
        writer.finish().unwrap();
        let turtle = read_container_turtle(&out);
        assert_eq!(
            turtle.matches("aff4:child").count(),
            2,
            "each directory keeps the edge to the child it did acquire:\n{turtle}"
        );
        for child in ["f.txt", "s/g.txt"] {
            let arn = arn_for_path(&volume_arn, &original_file_name(&tree.join(child)));
            assert!(
                turtle.contains(&format!("<{arn}>")),
                "the edge to {child} must survive the truncation:\n{turtle}"
            );
        }
    }

    /// A balanced stream is unaffected by the truncation drain.
    ///
    /// The guard on the fix above: the drain must be unreachable for a
    /// well-formed stream, so an ordinary acquisition reports nothing skipped
    /// and still names its root.
    #[test]
    fn a_balanced_item_stream_reports_nothing_skipped() {
        use crate::write::scan::ScanItem;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("balanced.aff4");
        let registry = crate::write::guard::SourceRegistry::new();
        let mut writer =
            crate::write::container_writer::ContainerWriter::create(&out, &registry).unwrap();
        let volume_arn = writer.volume_arn().as_str().to_owned();

        let items = vec![
            ScanItem::Dir {
                path: std::path::PathBuf::from("/tree"),
            },
            ScanItem::DirEnd,
        ];

        let mut result = LogicalAcquisition::default();
        let mut noop = |_: &LogicalAcquisition| {};
        let roots = acquire_from_items(
            &mut writer,
            items.into_iter(),
            &volume_arn,
            &LogicalOptions::default(),
            None,
            &mut result,
            &mut noop,
        )
        .expect("minting cannot fail with a working entropy source");

        assert!(
            result.skipped.is_empty(),
            "a balanced stream skips nothing: {:?}",
            result.skipped
        );
        assert_eq!(roots.len(), 1, "the closed directory is a root: {roots:?}");
    }

    /// A file that changed between the walk and the read is reported as
    /// CHANGED, not as skipped.
    ///
    /// It was acquired — completely, at its true length. `skipped` is headed
    /// "were NOT acquired", so listing it there states the opposite of what
    /// happened.
    #[test]
    fn a_changed_file_is_reported_as_changed_not_skipped() {
        use crate::write::scan::ScanItem;

        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        // This test's tree is a scratch tempdir, never an evidence source, so
        // creating it here does not touch anything the read-only guard exists
        // to protect.
        #[allow(clippy::disallowed_methods)]
        {
            std::fs::create_dir_all(&tree).unwrap();
        }
        // On disk the file is 12 bytes; the item claims 4, as a stale walk
        // would.
        #[allow(clippy::disallowed_methods)]
        std::fs::write(tree.join("a.txt"), b"hello world\n").unwrap();

        let out = dir.path().join("logical.aff4");
        let registry = crate::write::guard::SourceRegistry::new();
        let mut writer =
            crate::write::container_writer::ContainerWriter::create_logical(&out, &registry)
                .unwrap();
        let volume_arn = writer.volume_arn().as_str().to_owned();

        let items = vec![
            ScanItem::Dir { path: tree.clone() },
            ScanItem::File {
                path: tree.join("a.txt"),
                size: 4,
            },
            ScanItem::DirEnd,
        ];

        let mut result = LogicalAcquisition::default();
        let mut noop = |_: &LogicalAcquisition| {};
        acquire_from_items(
            &mut writer,
            items.into_iter(),
            &volume_arn,
            &LogicalOptions::default(),
            None,
            &mut result,
            &mut noop,
        )
        .expect("minting cannot fail with a working entropy source");
        writer.finish().unwrap();

        assert_eq!(
            result.changed.len(),
            1,
            "the size change must be reported: {:?}",
            result.changed
        );
        let (path, expected, actual) = &result.changed[0];
        assert!(path.ends_with("a.txt"));
        assert_eq!((*expected, *actual), (4, 12));

        assert!(
            result.skipped.is_empty(),
            "a file that WAS acquired must not appear under skipped: {:?}",
            result.skipped
        );
        assert_eq!(result.files, 1, "the file was acquired");
        assert_eq!(result.bytes, 12, "the read length is what counts");

        let turtle = read_container_turtle(&out);
        assert!(
            turtle.contains("\"12\"^^xsd:long") && !turtle.contains("\"4\"^^xsd:long"),
            "aff4:size must record 12, not the stale 4:\n{turtle}"
        );
    }
}
