//! AFF4-L logical acquisition, per Schatz (2019).
//!
//! > Schatz, B.L. *AFF4-L: A Scalable Open Logical Evidence Container.*
//! > Digital Investigation 29, S143–S149. DFRWS USA 2019.
//!
//! **The paper is the specification here, not pyaff4.** The two disagree: the
//! paper's Table 3 defines nine lexicon items and pyaff4 writes only five,
//! omitting the whole §3.6 resource-enumeration model
//! (`LogicalAcquisitionTask`, `filesystemRoot`, `Folder`, `child`). A consumer
//! of a pyaff4 logical container therefore cannot tell which paths were the
//! acquisition roots, or walk the acquired tree. This module implements the
//! paper in full.
//!
//! # The three encodings
//!
//! - **§3.2** suspect path → ARN. Table 1's rows are test vectors below.
//! - **§3.4** ARN → ZIP segment name, which converts percent-encoded spaces
//!   *back* to spaces so containers browse readably in ordinary ZIP tools.
//!   The segment name is therefore not simply the escaped ARN tail.
//! - **§3.3** the size split: a file at or under the threshold is stored as a
//!   ZIP segment, a larger one as an `ImageStream`. The section argues for the
//!   hybrid; the specific threshold is the prototype's choice, not a
//!   requirement — see [`MAX_SEGMENT_RESIDENT_SIZE`].

use std::path::Path;

/// Table 3 of the paper: the AFF4-L lexicon.
///
/// Local names only; the namespace is `aff4:`. **Four of these nine are never
/// written by pyaff4** — `Folder`, `child`, `LogicalAcquisitionTask`, and
/// `filesystemRoot`, which together are §3.6's resource-enumeration model.
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
    pub const CHILD: &str = "child";
    /// Class: a logical acquisition activity.
    pub const LOGICAL_ACQUISITION_TASK: &str = "LogicalAcquisitionTask";
    /// Points to a Folder or `FileImage` forming an acquisition root.
    pub const FILESYSTEM_ROOT: &str = "filesystemRoot";
    /// Marks content stored directly as a ZIP segment (§3.8).
    pub const ZIP_SEGMENT: &str = "zip_segment";
}

/// Characters §3.1 forbids in an ARN, which must be percent-encoded.
const FORBIDDEN: &[char] = &['<', '>', '\\', '^', '`', '{', '|', '}'];

/// Characters §3.2 omits that RDF's `IRIREF` production still rejects.
///
/// The paper's forbidden list omits them — it names only angle brackets,
/// backslash, caret, backquote, brace and pipe — but
/// RDF 1.1 excludes `[` and `]` from the `IRIREF` production, so an ARN
/// carrying one raw makes `information.turtle` unparseable by any conformant
/// reader. §3.7 then spends brackets on its own Slice Map syntax
/// (`aff4://uuid[0x0:0x8000]`) without saying what a filename containing one
/// should do.
///
/// Encoding them resolves both problems at once: the metadata stays valid, and
/// a bracket that reaches the parser is unambiguously a Slice Map's rather
/// than a suspect filename's.
///
/// The double quote is here for the same reason and was found the same way:
/// `IRIREF` excludes it, §3.2 does not name it, and `/Library` holds
/// `About "Convert" Scripts.scpt`. Together with §3.2's own list, the control
/// codes, space and `%`, this closes the set — every character RDF 1.1
/// forbids in an IRI is now escaped on the way in.
///
/// `/Library` supplied both cases: `man1/[.1`, the man page for the `[`
/// builtin, and the quoted script name above. A 13.3 GiB acquisition of it
/// wrote metadata no reader could parse.
const ALSO_ILLEGAL_IN_IRI: &[char] = &['[', ']', '"'];

/// The threshold: at or below this a file is stored as a ZIP segment.
///
/// **The paper chooses this value; it does not require it.** §3.3 reads: "In
/// our prototype implementation we choose to store any bytestreams greater than
/// 1M in size as Image Streams, and smaller as Zip Segments." There is no MUST
/// or SHOULD, and the Standard does not cover logical files at all. pyaff4
/// treats it as policy too — `container.py:341` sets the same 1 MiB beside a
/// commented-out debugging value, and `writeLogicalStream` takes an
/// `allow_large_zipsegments` override that stores a large file as a segment
/// anyway.
///
/// What §3.3 *does* justify is the hybrid itself, and that reasoning holds: an
/// Image Stream "requires at least two Zip Segments and an extra layer of
/// indirection", which a large file repays and a small one does not.
///
/// Measured on 20,000 small text files, storing everything as `ImageStream`s
/// instead produced a container 2.9x larger with 4x the ZIP members and 3x the
/// RDF subjects: a tiny file becomes a single chunk with no neighbors to
/// compress against, so per-member deflate beats chunked compression outright.
/// Changing the value breaks no conformance rule — readers dispatch on declared
/// `rdf:type`, not on size — provided §3.8's rule still holds, that
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

/// Encode a suspect path as an ARN path fragment, per §3.2.
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

/// Map an ARN to its ZIP segment name, per §3.4.
///
/// Strips the volume identifier and the separator that follows it, then
/// converts percent-encoded spaces back to literal spaces. That last step is
/// the reason a segment name is not simply the escaped ARN tail: the paper
/// wants containers to browse readably in `WinRAR` or 7-Zip.
#[must_use]
pub fn segment_name_for_arn(volume_arn: &str, arn: &str) -> String {
    let tail = arn.strip_prefix(volume_arn).unwrap_or(arn);
    // One leading separator is removed; a non-UNC path's second slash is part
    // of the name and stays, which is what makes `/C:/foo` in Table 2.
    let tail = tail.strip_prefix('/').unwrap_or(tail);
    // The same §3.4 decode `Arn::member_name` applies, so a file written here
    // and a stream written through the ARN land on one spelling. They drifted
    // once — this one decoding `%20`, that one re-escaping it to `%2520` — and
    // a container was written whose streams nothing could read back.
    tail.replace("%20", " ")
}

/// Whether a file of `size` bytes is stored as a ZIP segment (§3.3).
#[must_use]
pub fn is_segment_resident(size: u64) -> bool {
    size <= MAX_SEGMENT_RESIDENT_SIZE
}

/// The paths AFF4 reserves at the volume root, which a logical file must not
/// collide with (§3.8 via pyaff4's `isAFF4Collision`).
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
#[must_use]
pub fn original_file_name(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Timestamps captured for one filesystem entry (Table 3).
///
/// Every field is optional because platforms differ: Windows has no
/// `recordChanged`, and Linux needs `statx` for `birthTime`. An absent
/// timestamp is recorded as absent rather than substituted — pyaff4 fills
/// Windows `birthTime` from `st_ctime`, which is creation time only by
/// accident of the CRT.
#[derive(Debug, Default, Clone)]
pub struct FsTimestamps {
    /// `aff4:birthTime`.
    pub birth: Option<String>,
    /// `aff4:lastWritten`.
    pub written: Option<String>,
    /// `aff4:lastAccessed`.
    pub accessed: Option<String>,
    /// `aff4:recordChanged`.
    pub changed: Option<String>,
}

/// Read the timestamps a platform can supply for `metadata`.
///
/// Rendered as RFC 3339 in **UTC**, unlike pyaff4's host-local rendering: the
/// same file acquired in two timezones must yield the same literal, or two
/// containers of one file disagree for no reason.
#[must_use]
pub fn timestamps_of(metadata: &std::fs::Metadata) -> FsTimestamps {
    use std::time::SystemTime;

    fn render(time: std::io::Result<SystemTime>) -> Option<String> {
        let time = time.ok()?;
        let secs = time.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
        Some(format_rfc3339_utc(secs))
    }

    let mut stamps = FsTimestamps {
        birth: render(metadata.created()),
        written: render(metadata.modified()),
        accessed: render(metadata.accessed()),
        changed: None,
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
#[derive(Debug, Clone, Copy, Default)]
pub struct LogicalOptions {
    /// Chunking and compression for files stored as `ImageStream`s (§3.3).
    pub stream: crate::write::stream_writer::StreamOptions,
    /// Whether to deduplicate file content per §4.
    ///
    /// **Off by default, deliberately.** Dedupe replaces each file's own stored
    /// bytes with references into a shared pool, so a single damaged chunk
    /// harms every file that shares it, and the container no longer holds one
    /// contiguous copy of any file. That is a trade an examiner should opt into
    /// knowingly rather than inherit from a default.
    pub deduplicate: bool,
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
/// Implements §3.8's ordered recipe and §3.6's enumeration model in full.
///
/// # Errors
///
/// [`Error::Io`](crate::error::Error::Io) if a container write fails. A source
/// path that cannot be read is **recorded and skipped**, not fatal: a
/// permission error partway through a tree should not discard the acquisition.
pub fn acquire_logical(
    writer: &mut crate::write::container_writer::ContainerWriter,
    roots: &[std::path::PathBuf],
    options: LogicalOptions,
    locus: &crate::error::Locus,
    on_progress: &mut dyn FnMut(&LogicalAcquisition),
) -> crate::error::Result<LogicalAcquisition> {
    use crate::write::turtle::{TurtleTerm, XSD_DATE_TIME, XSD_LONG, XSD_STRING};

    let volume_arn = writer.volume_arn().as_str().to_owned();
    let lexicon = crate::lexicon::STANDARD11;
    let mut result = LogicalAcquisition::default();
    // The pool spans the whole acquisition, so identical content is stored once
    // *across* files rather than merely within one.
    let mut pool = options
        .deduplicate
        .then(|| crate::write::dedupe::ChunkPool::new(options.stream.chunk_size));

    // §3.6: one acquisition task, naming each root. A named ARN rather than
    // the paper's blank node `_:1` — a blank node cannot be referenced across
    // containers or survive a graph merge, and an acquisition task is exactly
    // the provenance an examiner may need to cite.
    let task_arn = format!("{volume_arn}/acquisition");
    writer
        .graph_mut()
        .add_type(&task_arn, &lexicon.iri(terms::LOGICAL_ACQUISITION_TASK));

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
        );
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
    options: LogicalOptions,
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
    options: LogicalOptions,
    locus: &crate::error::Locus,
    on_progress: &mut ScannedProgress<'_>,
) -> crate::error::Result<LogicalAcquisition> {
    use crate::write::turtle::TurtleTerm;

    let volume_arn = writer.volume_arn().as_str().to_owned();
    let lexicon = crate::lexicon::STANDARD11;
    let mut result = LogicalAcquisition::default();
    let mut pool = options
        .deduplicate
        .then(|| crate::write::dedupe::ChunkPool::new(options.stream.chunk_size));

    let task_arn = format!("{volume_arn}/acquisition");
    writer
        .graph_mut()
        .add_type(&task_arn, &lexicon.iri(terms::LOGICAL_ACQUISITION_TASK));

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
    options: LogicalOptions,
    locus: &crate::error::Locus,
    on_progress: &mut dyn FnMut(&LogicalAcquisition),
) -> crate::error::Result<LogicalAcquisition> {
    use crate::write::turtle::TurtleTerm;

    let volume_arn = writer.volume_arn().as_str().to_owned();
    let lexicon = crate::lexicon::STANDARD11;
    let mut result = LogicalAcquisition::default();
    let mut pool = options
        .deduplicate
        .then(|| crate::write::dedupe::ChunkPool::new(options.stream.chunk_size));

    let task_arn = format!("{volume_arn}/acquisition");
    writer
        .graph_mut()
        .add_type(&task_arn, &lexicon.iri(terms::LOGICAL_ACQUISITION_TASK));

    let acquired_roots = acquire_from_items(
        writer,
        items.into_iter(),
        &volume_arn,
        options,
        pool.as_mut(),
        &mut result,
        on_progress,
    );

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
#[allow(clippy::too_many_arguments)]
fn acquire_from_items(
    writer: &mut crate::write::container_writer::ContainerWriter,
    items: impl Iterator<Item = crate::write::scan::ScanItem>,
    volume_arn: &str,
    options: LogicalOptions,
    mut pool: Option<&mut crate::write::dedupe::ChunkPool>,
    result: &mut LogicalAcquisition,
    on_progress: &mut dyn FnMut(&LogicalAcquisition),
) -> Vec<String> {
    use crate::write::scan::ScanItem;
    use crate::write::turtle::TurtleTerm;

    let lexicon = crate::lexicon::STANDARD11;
    let mut stack: Vec<OpenDir> = Vec::new();
    let mut roots: Vec<String> = Vec::new();

    for item in items {
        match item {
            ScanItem::Skipped { path, reason } => {
                result.skipped.push((path, reason));
            }
            ScanItem::Dir { path } => {
                let display = original_file_name(&path);
                let arn = arn_for_path(volume_arn, &display);
                let stamps = match std::fs::symlink_metadata(&path) {
                    Ok(m) => timestamps_of(&m),
                    // The directory was enumerated a moment ago; if its
                    // metadata has since become unreadable the entry is still
                    // recorded, without timestamps rather than not at all.
                    Err(_) => FsTimestamps::default(),
                };
                write_table_3(writer, &arn, &display, &stamps, volume_arn, true);
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
                    // §3.6: the containment edge pyaff4 never writes, and what
                    // lets a consumer reconstruct the tree. Written now, and
                    // only for children that were actually acquired.
                    for child in &done.children {
                        writer.graph_mut().add(
                            &done.arn,
                            &lexicon.iri(terms::CHILD),
                            TurtleTerm::iri(child),
                        );
                    }
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(done.arn);
                    } else {
                        roots.push(done.arn);
                    }
                }
            }
            ScanItem::File { path, size } => {
                let display = original_file_name(&path);
                let arn = arn_for_path(volume_arn, &display);
                record_file(
                    writer,
                    &path,
                    &arn,
                    &display,
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
        for child in &open.children {
            writer.graph_mut().add(
                &open.arn,
                &lexicon.iri(terms::CHILD),
                TurtleTerm::iri(child),
            );
        }
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

    roots
}

/// Record one regular file: metadata, types, content, and §3.7 hashes, in
/// §3.8's order.
///
/// `size` is the size the item stream reported. It is what decides the §3.3
/// storage form; the size actually recorded is what the read produced, so a
/// file that changed underneath the walk is stored at its true length.
#[allow(clippy::too_many_arguments)]
fn record_file(
    writer: &mut crate::write::container_writer::ContainerWriter,
    path: &std::path::Path,
    arn: &str,
    display: &str,
    size: u64,
    volume_arn: &str,
    options: LogicalOptions,
    pool: Option<&mut crate::write::dedupe::ChunkPool>,
    result: &mut LogicalAcquisition,
) {
    use crate::write::turtle::{TurtleTerm, XSD_LONG};

    let lexicon = crate::lexicon::STANDARD11;

    let stamps = match std::fs::symlink_metadata(path) {
        Ok(m) => timestamps_of(&m),
        // The file was enumerated a moment ago. If its metadata has since
        // become unreadable it is still recorded, without timestamps rather
        // than not at all; the content read below reports its own failure.
        Err(_) => FsTimestamps::default(),
    };

    // A large file's bytes go through `write_image_stream_as`, which emits
    // `aff4:stored` for the stream it writes. That stream's ARN *is* the file's
    // own (see `record_large_file`), so letting Table 3 emit it too put the
    // same triple on the same subject twice.
    let stream_will_record_stored = !is_segment_resident(size);
    write_table_3(
        writer,
        arn,
        display,
        &stamps,
        volume_arn,
        !stream_will_record_stored,
    );

    writer
        .graph_mut()
        .add_type(arn, &lexicon.iri(terms::FILE_IMAGE));
    writer
        .graph_mut()
        .add_type(arn, &lexicon.iri(lexicon.image));

    // §4: with deduplication on, every file becomes a Map over the shared chunk
    // pool regardless of size — the §3.3 threshold does not apply, because no
    // file has its own storage to choose a form for.
    if let Some(pool) = pool {
        record_deduplicated_file(writer, path, arn, size, pool, result);
        return;
    }

    // §3.3: small files are ZIP segments, large ones ImageStreams. The large
    // path streams — a file above the threshold must never be read whole into
    // memory, which is the whole reason the threshold exists.
    if !is_segment_resident(size) {
        record_large_file(writer, path, arn, size, options.stream, result);
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

    // §3.7: SHA-1 and MD5 linear bitstream hashes, both.
    {
        use md5::Digest as _;
        let md5 = hex_lower(&md5::Md5::digest(&bytes));
        let sha1 = hex_lower(&sha1::Sha1::digest(&bytes));
        let graph = writer.graph_mut();
        graph.add(
            arn,
            &lexicon.iri(lexicon.hash),
            TurtleTerm::typed(md5, lexicon.iri("MD5")),
        );
        graph.add(
            arn,
            &lexicon.iri(lexicon.hash),
            TurtleTerm::typed(sha1, lexicon.iri("SHA1")),
        );
        graph.add(
            arn,
            &lexicon.iri(lexicon.size),
            TurtleTerm::typed(actual.to_string(), XSD_LONG),
        );
    }

    let segment = segment_name_for_arn(volume_arn, arn);
    if is_reserved_name(&segment) {
        result.skipped.push((
            path.to_path_buf(),
            format!("{segment} collides with an AFF4 reserved name"),
        ));
        return;
    }

    // §3.8: zip_segment joins the type list only when so stored.
    writer
        .graph_mut()
        .add_type(arn, &lexicon.iri(terms::ZIP_SEGMENT));
    if let Err(e) = writer.add_deflated_segment(&segment, &bytes) {
        result.skipped.push((path.to_path_buf(), e.to_string()));
        return;
    }
    result.files += 1;
    result.bytes += actual;
}

/// Record one file as a deduplicated `Map` over the shared chunk pool (§4).
///
/// The file's chunks go into `pool`; its map is written later, once every file
/// has contributed and the shared stream's target list is final. The §3.7
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
    result: &mut LogicalAcquisition,
) {
    use crate::write::turtle::{TurtleTerm, XSD_LONG};

    let lexicon = crate::lexicon::STANDARD11;
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
        md5: <md5::Md5 as md5::Digest>::new(),
        sha1: <sha1::Sha1 as sha1::Digest>::new(),
    };
    let deduped = match pool.absorb(&mut hashing, &locus) {
        Ok(d) => d,
        Err(e) => {
            result.skipped.push((path.to_path_buf(), e.to_string()));
            return;
        }
    };
    let md5 = hex_lower(&md5::Digest::finalize(hashing.md5));
    let sha1 = hex_lower(&sha1::Digest::finalize(hashing.sha1));

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
        graph.add(
            arn,
            &lexicon.iri(lexicon.hash),
            TurtleTerm::typed(md5, lexicon.iri("MD5")),
        );
        graph.add(
            arn,
            &lexicon.iri(lexicon.hash),
            TurtleTerm::typed(sha1, lexicon.iri("SHA1")),
        );
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
    md5: md5::Md5,
    sha1: sha1::Sha1,
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        md5::Digest::update(&mut self.md5, &buf[..n]);
        sha1::Digest::update(&mut self.sha1, &buf[..n]);
        Ok(n)
    }
}

/// Record a file above the §3.3 threshold as an `ImageStream`.
///
/// **Streamed, never buffered.** The file is read in chunks straight into the
/// bevy builder, which is the point of the threshold: a multi-gigabyte file must
/// not need multi-gigabyte memory. `write_image_stream_as` computes the §3.7
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
/// form also keeps §3.4's promise that the container browses readably: the
/// bevies sit exactly where the file does.
fn record_large_file(
    writer: &mut crate::write::container_writer::ContainerWriter,
    path: &std::path::Path,
    arn: &str,
    size: u64,
    options: crate::write::stream_writer::StreamOptions,
    result: &mut LogicalAcquisition,
) {
    use crate::model::HashAlgorithm;
    use crate::write::stream_writer::write_image_stream_as;
    use crate::write::turtle::{TurtleTerm, XSD_LONG};

    let lexicon = crate::lexicon::STANDARD11;
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

    // §3.7: SHA-1 and MD5, the paper's pair, computed over the bytes stored.
    let algorithms = [HashAlgorithm::Sha1, HashAlgorithm::Md5];
    let written = match write_image_stream_as(writer, arn, &mut file, options, &algorithms, &locus)
    {
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
    display: &str,
    stamps: &FsTimestamps,
    volume_arn: &str,
    record_stored: bool,
) {
    use crate::write::turtle::{TurtleTerm, XSD_DATE_TIME, XSD_STRING};

    let lexicon = crate::lexicon::STANDARD11;
    let graph = writer.graph_mut();
    graph.add(
        arn,
        &lexicon.iri(terms::ORIGINAL_FILE_NAME),
        TurtleTerm::typed(display, XSD_STRING),
    );
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

/// Render bytes as lowercase hex.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const VOLUME: &str = "aff4://e6bae91b-14d231833e18";

    /// **Table 1 of the paper, verbatim.** These are the specification's own
    /// worked examples, so they are the closest thing to an external oracle
    /// this encoding has — gate 5 of the plan's §6.
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
                segment_name_for_arn(VOLUME, arn),
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
                parsed.member_name(&volume).as_deref(),
                Some(segment_name_for_arn(VOLUME, &arn).as_str()),
                "the two naming paths disagree for {tail:?}"
            );
        }
    }

    /// A bracket in a suspect filename must be percent-encoded.
    ///
    /// `[` and `]` are not in §3.2's forbidden list — which names only angle
    /// brackets, backslash, caret, backquote, brace and pipe — but they are
    /// excluded from Turtle's `IRIREF` production,
    /// so an ARN carrying one raw makes `information.turtle` unparseable. The
    /// paper never reconciles this: §3.7's Slice Map syntax
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
    /// Asserted as a set rather than one case at a time: §3.2's list predates
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
    /// The member keeps the escape — §3.4 decodes only `%20` — so what proves
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

    /// Unicode is preserved, not escaped — §3.2 rule 3, and what makes a
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

    /// Forbidden characters and controls are encoded; the set is §3.1's.
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

    /// The §3.3 split threshold.
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
        let segment = segment_name_for_arn(VOLUME, &arn);
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
            LogicalOptions::default(),
            None,
            &mut result,
            &mut noop,
        );

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
            LogicalOptions::default(),
            None,
            &mut result,
            &mut noop,
        );

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
            LogicalOptions::default(),
            None,
            &mut result,
            &mut noop,
        );
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
