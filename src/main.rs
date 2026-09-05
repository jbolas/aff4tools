//! Command-line front end for `aff4tools`.
//!
//! This layer does only argument parsing, calling into the `aff4tools`
//! library, and formatting results.
//!
//! It is also the only place that decides what a user sees. The library returns
//! errors and deviations as values; this module renders them and picks the
//! exit code.

use std::io::{StdoutLock, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aff4tools::zip::Volume as _;
use aff4tools::zip_volume_set::VolumeOrigin;
use aff4tools::{
    Aff4Object, Container, ContainerSummary, Coverage, Deviation, DeviationKind, Error, HashCheck,
    Image, Locus, ObjectRole, Outcome, Progress, SplitLayout, VerificationReport, VerifyOptions,
    WorkEstimate, estimate_work, verify_container_with_progress,
};
// Re-exported at `pub(crate)` visibility so `report.rs` can keep referring to
// it as `crate::human_bytes`, unchanged from when the function lived here.
pub(crate) use aff4tools::human_bytes;
use clap::{ArgGroup, Parser, Subcommand, ValueEnum};

/// `info`'s human-readable report: object ordering, the manifest
/// reconciliation, and per-object rendering. Kept out of this module because
/// `write_text` alone grew past the point a single file should carry
/// alongside argument parsing and the `verify` report — see the module doc
/// comment in `report.rs`.
mod report;

/// Repaints the acquisition progress line on stderr. Binary-only: it prints,
/// and the library never does — see `painter.rs`'s module doc comment.
mod painter;

/// Exit code clap emits for a usage error, following the Unix convention.
///
/// Library errors start at 3 (see [`Error::exit_code`]) so no failure can be
/// mistaken for a mistyped command line.
const EXIT_USAGE: u8 = 2;

/// Exit code when `--full-listing` cannot be written.
///
/// The same code [`Error::exit_code`] gives an `Io` failure, because that is
/// what this is: the container was read, and writing the requested file failed.
/// The report on stdout is still correct and complete for what it shows, so
/// this marks the file as missing rather than the reading as unsound.
const EXIT_LISTING_IO: u8 = 3;

/// Exit code when `--strict` promotes a deviation to a failure.
///
/// Above every [`Error::exit_code`] value: a strict-mode failure means the
/// container was read successfully but does not conform.
const EXIT_STRICT_DEVIATION: u8 = 7;

/// Exit code when a recomputed digest does not match what the container
/// recorded.
///
/// Deliberately distinct from 5 (`Malformed`): a script must be able to tell
/// "the evidence does not match its recorded digests" from "the container could
/// not be read". Both are serious; they are not the same finding.
const EXIT_MISMATCH: u8 = 8;

/// Exit code when a recorded digest covers bytes that could not be read.
///
/// The third distinct answer verification can give. "Every digest I could
/// check matched" is not "the evidence is sound": a container whose evidence
/// segments will not decompress would otherwise exit clean while half its
/// recorded digests went unchecked, and a script gating on `verify` would pass
/// it.
///
/// Below [`EXIT_MISMATCH`] because a mismatch is the stronger finding.
/// Above the strict-deviation code because unverifiable evidence
/// outranks a metadata departure.
const EXIT_UNVERIFIABLE: u8 = 9;

#[derive(Parser)]
#[command(
    name = "aff4tools",
    version,
    about = "An AFF4 and AFF4-L implementation in Rust",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Get an .aff4 container's metadata.
    Info {
        /// Container to summarize.
        #[arg(
            required_unless_present = "split_file",
            value_name = "PATH",
            conflicts_with = "split_file"
        )]
        paths: Vec<PathBuf>,

        /// Folder containing a split-file .aff4.
        #[arg(long, value_name = "DIR", conflicts_with = "paths")]
        split_file: Option<PathBuf>,

        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Treat departures from the standard as failure.
        #[arg(long)]
        strict: bool,

        /// Which objects to list.
        #[arg(long, value_enum, default_value_t = ObjectFilter::Images)]
        objects: ObjectFilter,

        /// Omit per-object properties.
        #[arg(long)]
        brief: bool,

        /// Write the full per-object listing to a file.
        ///
        /// The threshold is spelled out rather than named: help text is read by
        /// operators, to whom an internal constant's name means nothing. Both
        /// this string and `LARGE_LISTING_THRESHOLD` come from
        /// `large_listing_threshold!`, so the number here cannot drift from the
        /// number enforced.
        #[arg(
            long,
            value_name = "PATH",
            long_help = concat!(
                "Write the full per-object listing to a file.\n\n",
                "Above ", large_listing_threshold!(), " objects the text report ",
                "degrades to the `--brief` summary. This flag writes the full ",
                "listing to file."
            )
        )]
        full_listing: Option<PathBuf>,
    },

    /// Check a container against the AFF4 specification.
    Conformance {
        /// Container to check.
        #[arg(
            required_unless_present = "split_file",
            value_name = "PATH",
            conflicts_with = "split_file"
        )]
        paths: Vec<PathBuf>,

        /// Folder containing a split-file .aff4.
        #[arg(long, value_name = "DIR", conflicts_with = "paths")]
        split_file: Option<PathBuf>,

        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Treat departures from the standard as failure.
        #[arg(long)]
        strict: bool,
    },

    /// Write source data into a new AFF4 container.
    //
    // The three source flags form a required, mutually exclusive group, so
    // clap both renders them in the usage line and rejects "none of them"
    // itself. Without the group the usage line reads `[OPTIONS] --output
    // <PATH>`, which says an acquisition needs no input.
    #[command(group(ArgGroup::new("source").required(true).multiple(false)
        .args(["device", "logical", "images"])))]
    Acquire {
        /// A block device to acquire, e.g. `/dev/rdisk2`.
        #[arg(long, value_name = "PATH", group = "source")]
        device: Option<PathBuf>,

        /// Files or folders to acquire to an AFF4-L logical image. Use multiple `--logical` flags to acquire more than one top-level folder or file.
        #[arg(long = "logical", value_name = "PATH", group = "source")]
        logical: Vec<PathBuf>,

        /// Set source to an existing .dd or .aff4 image. <PATH> to single-file image or folder containing split-file image.
        ///
        /// If given a folder containing a split-file image, files (`ev_001.aff4`, `ev_002.aff4`) are ordered by numeric suffixes in filenames.
        ///
        /// Given the first segment of a split set (`name.001`), the remaining
        /// segments are discovered automatically.
        #[arg(long = "image", value_name = "PATH", group = "source")]
        images: Vec<PathBuf>,

        /// Deprecated; has no effect. `--image name.001` now discovers the
        /// rest of the set on its own, as `--image <folder>` always has.
        #[arg(long, hide = true)]
        discover_split: bool,

        /// Filepath to destination .aff4 file. May not exist already.
        #[arg(long, required = true, value_name = "PATH")]
        output: PathBuf,

        /// Chunk compression codec. Default=`lz4`.
        #[arg(long, value_enum, default_value_t = Compression::Lz4)]
        compression: Compression,

        /// Default=32,768 bytes.
        #[arg(long, default_value_t = 32 * 1024)]
        chunk_size: usize,

        /// Default=1,024 chunks.
        #[arg(long, default_value_t = 1024)]
        chunks_per_bevy: usize,

        /// Write the image across several .aff4 files instead of one.
        ///
        /// Parts are named from --output: `evidence.aff4` becomes
        /// `evidence_001.aff4`, `evidence_002.aff4`, and so on. Numbering is
        /// limited to 999 parts.
        #[arg(long, value_enum, value_name = "SIZE")]
        split_file: Option<SplitSize>,

        /// Skip verification of hash digests in .aff4 after acquisition completes.
        #[arg(long)]
        no_verify: bool,

        // The three `--logical` only flags below each carry
        // `conflicts_with_all` alongside `requires`, not in place of it:
        // `logical`, `images`, and `device` mutually conflict, and clap treats
        // a `requires` on one member of a conflict set as satisfied once any
        // conflicting member is present — so `requires = "logical"` alone
        // silently admits `--scan-first --image PATH` with no `--logical` at
        // all. Naming the conflict directly is what actually rejects it.
        /// Filepath to acquisition log. `--logical` only. Defaults to `<output>_log.txt` beside the container.
        #[arg(long, value_name = "PATH", requires = "logical", conflicts_with_all = ["images", "device"])]
        log: Option<PathBuf>,

        /// Inventory the tree before acquiring, for an exact progress total.
        /// `--logical` only.
        ///
        /// Costs a full metadata traversal before the first byte is written,
        /// in exchange for a true percentage and time remaining from the
        /// start. Without it, acquisition begins at once and the total firms
        /// up while it runs.
        #[arg(long, requires = "logical", conflicts_with_all = ["images", "device"])]
        scan_first: bool,

        /// Deduplicate logical file content (AFF4-L 2019 §4). `--logical` only.
        /// Experimental only!
        ///
        /// Stores each distinct chunk once in a shared `ImageStream` and builds
        /// every file from references to it, which can shrink a container
        /// holding many near-identical files dramatically.
        ///
        /// **Off by default.** Deduplication means no file has its own
        /// contiguous copy any more: one damaged chunk harms every file sharing
        /// it, and the container's structure no longer mirrors the evidence
        /// one-to-one. That is a trade worth making knowingly, not by default.
        #[arg(long, requires = "logical", conflicts_with_all = ["images", "device"])]
        deduplicate: bool,
    },

    /// Write a disk image out as raw dd; or, export logical files to a directory.
    Export {
        /// The container to export. Any part of a split set will do.
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Write the logical files an AFF4-L holds into this directory.
        #[arg(long, value_name = "DIR", conflicts_with = "output")]
        logical: Option<PathBuf>,

        /// Where to write the raw image. `-` writes to stdout.
        #[arg(long, value_name = "PATH", conflicts_with = "logical")]
        output: Option<PathBuf>,
    },

    /// Recompute a container's hash digests and compare them.
    Verify {
        /// Containers to verify.
        #[arg(
            required_unless_present = "split_file",
            value_name = "PATH",
            conflicts_with = "split_file"
        )]
        paths: Vec<PathBuf>,

        /// Folder containing a split-file .aff4.
        #[arg(long, value_name = "DIR", conflicts_with = "paths")]
        split_file: Option<PathBuf>,

        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Skip per-chunk MD5 and SHA-1 verification against the block-hash
        /// segments.
        ///
        /// Block hashing is the leaf level of the AFF4 hash tree and is on by default: without it the composite digests establish that the block-hash segments are intact but not that they describe the data.
        #[arg(long)]
        no_block_hashing: bool,

        /// Treat departures from the standard as failure.
        #[arg(long)]
        strict: bool,

        /// Print every check in full rather than only the failures.
        #[arg(short, long)]
        verbose: bool,

        /// Write the per-file digest table to a tab-separated (TSV) file.
        #[arg(long, value_name = "PATH")]
        full_listing: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable report.
    Text,
    /// Machine-readable JSON. Shape differs by command — see that command's
    /// own `--help`.
    Json,
}

/// Chunk compression for a written container.
///
/// Ordering here is the order of preference, and it is measured rather than
/// asserted.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Compression {
    /// Fastest, with ratio equal or better than snappy. The default.
    Lz4,
    /// Slower than LZ4 and no smaller; kept for interoperability.
    Snappy,
    /// ~5% smaller on incompressible data, roughly 30x slower.
    Zlib,
    /// No compression. Useful when the source is already compressed.
    Stored,
}

impl From<Compression> for aff4tools::Codec {
    fn from(value: Compression) -> Self {
        match value {
            Compression::Lz4 => Self::Lz4,
            Compression::Snappy => Self::Snappy,
            Compression::Zlib => Self::Zlib,
            Compression::Stored => Self::Stored,
        }
    }
}

/// How large each part of a split set may grow before the next one starts.
///
/// A fixed set rather than a free-form size: these are the values examiners
/// actually choose, and constraining them lets clap reject a typo with the
/// valid list rather than accepting `3G` and producing an odd set.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum SplitSize {
    /// 1 GiB per part.
    #[value(name = "1G")]
    One,
    /// 2 GiB per part.
    #[value(name = "2G")]
    Two,
    /// 4 GiB per part.
    #[value(name = "4G")]
    Four,
    /// 8 GiB per part.
    #[value(name = "8G")]
    Eight,
    /// 16 GiB per part.
    #[value(name = "16G")]
    Sixteen,
    /// 32 GiB per part.
    #[value(name = "32G")]
    ThirtyTwo,
}

impl SplitSize {
    /// The threshold in bytes.
    fn bytes(self) -> u64 {
        let gib = 1u64 << 30;
        match self {
            Self::One => gib,
            Self::Two => 2 * gib,
            Self::Four => 4 * gib,
            Self::Eight => 8 * gib,
            Self::Sixteen => 16 * gib,
            Self::ThirtyTwo => 32 * gib,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ObjectFilter {
    /// Every object in the metadata.
    All,
    /// Images, image streams, and maps.
    Images,
    /// No object listing; volume and deviations only.
    None,
}

impl ObjectFilter {
    /// Whether an object passes this filter.
    fn admits(self, object: &Aff4Object) -> bool {
        match self {
            Self::All => true,
            Self::None => false,
            Self::Images => {
                object.role.is_image()
                    || matches!(object.role, ObjectRole::ImageStream | ObjectRole::Map)
            }
        }
    }
}

/// A global allocator that records the high-water mark of live bytes.
///
/// Enabled only when `AFF4TOOLS_ALLOC_STATS` is set.
struct CountingAlloc;

static LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract; this
        // forwards to the system allocator unchanged and only adds counters.
        let ptr = unsafe { std::alloc::System.alloc(layout) };
        if !ptr.is_null() {
            use std::sync::atomic::Ordering::Relaxed;
            let live = LIVE.fetch_add(layout.size(), Relaxed) + layout.size();
            PEAK.fetch_max(live, Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        LIVE.fetch_sub(layout.size(), std::sync::atomic::Ordering::Relaxed);
        // SAFETY: as above; `ptr` came from `alloc` with this same `layout`.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Report the allocation high-water mark, when asked for.
fn report_alloc_stats() {
    if std::env::var_os("AFF4TOOLS_ALLOC_STATS").is_none() {
        return;
    }
    let peak = PEAK.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!(
        "alloc-peak: {peak} bytes ({:.3} GB)",
        peak as f64 / 1_073_741_824.0
    );
}

fn main() -> ExitCode {
    let code = run();
    report_alloc_stats();
    code
}

fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Info {
            paths,
            split_file,
            format,
            strict,
            objects,
            brief,
            full_listing,
        } => match into_sets(paths, split_file) {
            Ok((sets, line)) => {
                if let Some(line) = line {
                    println!("{line}");
                }
                run_info(
                    &sets,
                    format,
                    strict,
                    objects,
                    brief,
                    full_listing.as_deref(),
                )
            }
            Err(e) => ExitCode::from(report_error(&e)),
        },
        Command::Conformance {
            paths,
            split_file,
            format,
            strict,
        } => match into_sets(paths, split_file) {
            Ok((sets, line)) => {
                if let Some(line) = line {
                    println!("{line}");
                }
                run_conformance(&sets, format, strict)
            }
            Err(e) => ExitCode::from(report_error(&e)),
        },
        Command::Acquire {
            images,
            logical,
            device,
            discover_split,
            output,
            compression,
            chunk_size,
            chunks_per_bevy,
            split_file,
            no_verify,
            deduplicate,
            log,
            scan_first,
        } => run_acquire(
            &images,
            &logical,
            device.as_deref(),
            discover_split,
            &output,
            log.as_deref(),
            AcquireOptions {
                compression,
                chunk_size,
                chunks_per_bevy,
                verify_written_container: !no_verify,
                deduplicate,
                split_after: split_file.map(SplitSize::bytes),
                scan_first,
            },
        ),
        Command::Export {
            path,
            logical,
            output,
        } => run_export(&path, logical.as_deref(), output.as_deref()),

        Command::Verify {
            paths,
            split_file,
            format,
            no_block_hashing,
            strict,
            verbose,
            full_listing,
        } => match into_sets(paths, split_file) {
            Ok((sets, line)) => {
                if let Some(line) = line {
                    println!("{line}");
                }
                run_verify(
                    &sets,
                    format,
                    !no_block_hashing,
                    strict,
                    verbose,
                    full_listing.as_deref(),
                )
            }
            Err(e) => ExitCode::from(report_error(&e)),
        },
    }
}

/// Group the command line into the sets of volumes to open.
///
/// Positional paths are independent containers, one set each. A
/// `--split-file` is a single set: every part of one image, in part order.
/// The returned string, when present, is the discovery line to print before
/// reading begins.
///
/// # Errors
///
/// [`Error::Malformed`](aff4tools::Error::Malformed) if the folder holds no
/// split set, holds two kinds at once, or has a gap in its part numbering.
fn into_sets(
    paths: Vec<PathBuf>,
    split_file: Option<PathBuf>,
) -> aff4tools::Result<(Vec<Vec<PathBuf>>, Option<String>)> {
    match split_file {
        None => Ok((paths.into_iter().map(|p| vec![p]).collect(), None)),
        Some(dir) => {
            let set = aff4tools::split_set::discover(&dir)?;
            let line = set.discovery_line();
            Ok((vec![set.parts], Some(line)))
        }
    }
}

/// Verify each path, returning the most severe exit code encountered.
/// Export a container: a raw image, or an AFF4-L's files.
///
/// Any part of a
/// split set may be named — siblings are discovered and the whole image is
/// written — so the container's shape is invisible here exactly as it is
/// through the C ABI.
fn run_export(
    path: &std::path::Path,
    logical: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> ExitCode {
    if let Some(dir) = logical {
        return run_export_logical(path, dir);
    }
    let Some(output) = output else {
        eprintln!("error: one of --output <PATH> or --logical <DIR> is required.");
        eprintln!("       --output writes the raw image; --logical writes an AFF4-L's files.");
        return ExitCode::from(EXIT_USAGE);
    };
    run_export_image(path, output)
}

/// Every part of the split set `path` belongs to, or just `path`.
///
/// Mirrors `aff4tools-ffi`'s `parts_of`: naming any part opens the whole set.
fn split_parts_of(path: &std::path::Path) -> Vec<PathBuf> {
    let alone = || vec![path.to_path_buf()];
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return alone();
    };
    if aff4tools::split_set::part_number(name).is_none() {
        return alone();
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    match aff4tools::split_set::discover(dir) {
        Ok(set)
            if set.kind == aff4tools::split_set::SplitKind::Aff4
                && set.parts.iter().any(|p| p == path) =>
        {
            set.parts
        }
        _ => alone(),
    }
}

/// Open a container and the disk image it holds, following split parts.
///
/// The first part is the primary whatever part was named: in a split set only
/// part 001 carries the Map, so opening the named part as primary fails for
/// every other part.
fn open_disk_image(
    path: &std::path::Path,
) -> Result<(aff4tools::Container, aff4tools::image::Image, PathBuf), String> {
    let parts = split_parts_of(path);
    let primary = parts.first().cloned().unwrap_or_else(|| path.to_path_buf());
    let locus = aff4tools::Locus::new(&primary);

    let mut container = aff4tools::Container::open(&primary)
        .map_err(|e| format!("opening {}: {e}", primary.display()))?;
    for sibling in parts.iter().skip(1) {
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(sibling)
            .map_err(|e| format!("opening part {}: {e}", sibling.display()))?;
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }

    let summary = container
        .summarize()
        .map_err(|e| format!("reading metadata: {e}"))?;
    let disk = summary
        .images()
        .iter()
        .find(|o| o.role == aff4tools::ObjectRole::DiskImage)
        .map(|o| o.arn.clone());

    let Some(arn) = disk else {
        let is_logical = summary.objects.iter().any(|o| {
            matches!(
                o.role,
                aff4tools::ObjectRole::FileImage | aff4tools::ObjectRole::FolderImage
            )
        });
        return Err(if is_logical {
            format!(
                "{} stores no disk image; this appears to be an AFF4-L logical image.\n       \
                 Use `aff4tools export {} --logical <DIR>` to write its files.",
                path.display(),
                path.display()
            )
        } else {
            format!("{} stores no disk image", path.display())
        });
    };

    let lexicon = container.lexicon();
    let image =
        aff4tools::image::Image::open_in_set(&arn, container.volumes_mut(), lexicon, &locus)
            .map_err(|e| format!("opening image {arn}: {e}"))?;
    Ok((container, image, primary))
}

/// Write a `DiskImage` out as raw bytes.
fn run_export_image(path: &std::path::Path, output: &std::path::Path) -> ExitCode {
    let to_stdout = output.as_os_str() == "-";

    if !to_stdout && output.exists() {
        eprintln!("error: {} already exists.", output.display());
        eprintln!("       export refuses to overwrite; name a path that does not exist.");
        return ExitCode::from(EXIT_USAGE);
    }

    let (mut container, image, primary) = match open_disk_image(path) {
        Ok(triple) => triple,
        Err(text) => {
            eprintln!("error: {text}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let locus = aff4tools::Locus::new(&primary);
    let size = image.size();

    // Progress and headers go to stderr: stdout may be the image itself.
    if !to_stdout {
        eprintln!("Source:      {}", primary.display());
        eprintln!("Image:       {}", image.arn());
        eprintln!("Size:        {}", human_bytes(size));
        eprintln!("Output:      {}", output.display());
    }

    let sink: Result<Box<dyn Write>, String> = if to_stdout {
        Ok(Box::new(std::io::stdout().lock()))
    } else {
        // The one file this command creates. `create_new` so an existing file
        // is never truncated, matching `acquire`.
        #[allow(clippy::disallowed_methods)]
        std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(output)
            .map(|f| Box::new(std::io::BufWriter::new(f)) as Box<dyn Write>)
            .map_err(|e| format!("creating {}: {e}", output.display()))
    };
    let mut sink = match sink {
        Ok(s) => s,
        Err(text) => {
            eprintln!("error: {text}");
            return ExitCode::from(EXIT_LISTING_IO);
        }
    };

    let mut written = 0u64;
    let result = image.read_from_set(
        container.volumes_mut(),
        &mut |bytes| {
            written += bytes.len() as u64;
            sink.write_all(bytes)
                .map_err(|e| aff4tools::Error::io(output.to_path_buf(), e))
        },
        &locus,
    );

    if let Err(e) = result {
        return ExitCode::from(report_error(&e));
    }
    if let Err(e) = sink.flush() {
        eprintln!("error: writing {}: {e}", output.display());
        return ExitCode::from(EXIT_LISTING_IO);
    }

    if !to_stdout {
        eprintln!("Written:     {} ({written} bytes)", human_bytes(written));
    }
    if written != size {
        eprintln!(
            "error: wrote {written} bytes but the image declares {size}; the output is short."
        );
        return ExitCode::from(EXIT_LISTING_IO);
    }
    ExitCode::SUCCESS
}

/// Write an AFF4-L's files and folders into `target`.
///
/// Recorded paths are reproduced beneath the target, so an absolute source path
/// lands at `<target>/Users/...` rather than at the filesystem root. See
/// `aff4tools::export::rebase`, which is where that property is enforced and
/// tested.
fn run_export_logical(path: &std::path::Path, target: &std::path::Path) -> ExitCode {
    use aff4tools::export::{LogicalTimes, PathAlteration, rebase};

    let mut container = match aff4tools::Container::open(path) {
        Ok(c) => c,
        Err(e) => return ExitCode::from(report_error(&e)),
    };
    let summary = match container.summarize() {
        Ok(s) => s,
        Err(e) => return ExitCode::from(report_error(&e)),
    };

    let files: Vec<_> = summary
        .objects
        .iter()
        .filter(|o| o.role == aff4tools::ObjectRole::FileImage)
        .cloned()
        .collect();

    if files.is_empty() {
        let has_image = summary
            .images()
            .iter()
            .any(|o| o.role == aff4tools::ObjectRole::DiskImage);
        eprintln!("error: {} holds no logical files.", path.display());
        if has_image {
            eprintln!(
                "       It stores a disk image; use `aff4tools export {} --output <PATH>`.",
                path.display()
            );
        }
        return ExitCode::from(EXIT_USAGE);
    }

    // Created, never reused: writing into a directory that already holds files
    // would mingle this evidence with whatever was there.
    if target.exists() {
        eprintln!("error: {} already exists.", target.display());
        eprintln!("       export refuses to write into an existing directory.");
        return ExitCode::from(EXIT_USAGE);
    }
    #[allow(clippy::disallowed_methods)]
    if let Err(e) = std::fs::create_dir_all(target) {
        eprintln!("error: creating {}: {e}", target.display());
        return ExitCode::from(EXIT_LISTING_IO);
    }

    println!("Source:      {}", path.display());
    println!("Target:      {}", target.display());
    println!("Files:       {}", files.len());
    println!();

    let volume_arn = container.volume().arn().clone();
    let mut written = 0u64;
    let mut bytes_out = 0u64;
    // Every file the export could not write, with why. Counted rather than
    // only printed: a run that skips evidence must not report success, and the
    // total is what the closing line and the exit code are decided from.
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut alterations: Vec<PathAlteration> = Vec::new();
    let mut unset_times: Vec<(String, LogicalTimes)> = Vec::new();
    // The metadata graph, parsed at most once for the whole export.
    let mut graph: Option<aff4tools::rdf::Graph> = None;

    for object in &files {
        // The ARN's path portion is the file's recorded location. Everything
        // after the volume's authority is that path.
        let recorded = object
            .arn
            .as_str()
            .strip_prefix(volume_arn.as_str())
            .unwrap_or(object.arn.as_str())
            .trim_start_matches('/');
        let recorded = percent_decode(recorded);

        let (destination, alteration) = rebase(target, &recorded);
        if let Some(alteration) = alteration {
            alterations.push(alteration);
        }

        // AFF4-L 2019 §3.4 stores a small file as a ZIP segment and a larger
        // one as
        // an ImageStream whose ARN is the file's own. Both are FileImage
        // objects, so the type list is what distinguishes them — reading only
        // segments silently skipped every file above 1 MiB.
        // Types are full IRIs, so compare the local name after the fragment
        // separator: `http://aff4.org/Schema#ImageStream`.
        let is_stream = object
            .types
            .iter()
            .any(|t| t.rsplit(['#', '/']).next() == Some("ImageStream"));

        let bytes = if is_stream {
            // Parsed once, on the first stream-backed file, and reused for
            // every later one. Lazy rather than eager so a container holding
            // only ZIP segments never parses the graph at all.
            let graph = match &graph {
                Some(graph) => graph,
                None => match container.graph() {
                    Ok(parsed) => graph.insert(parsed),
                    Err(e) => {
                        eprintln!("  skipped {recorded}: {e}");
                        skipped.push((recorded.clone(), e.to_string()));
                        continue;
                    }
                },
            };
            match read_logical_stream(&mut container, graph, object, &locus_for(path)) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("  skipped {recorded}: {e}");
                    skipped.push((recorded.clone(), e.to_string()));
                    continue;
                }
            }
        } else {
            let Some(segment) = object.arn.member_name(&volume_arn) else {
                eprintln!("  skipped {recorded}: names no member of this volume");
                skipped.push((
                    recorded.clone(),
                    "names no member of this volume".to_owned(),
                ));
                continue;
            };
            match container.volume_mut().read_segment(&segment) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("  skipped {recorded}: {e}");
                    skipped.push((recorded.clone(), e.to_string()));
                    continue;
                }
            }
        };

        if let Some(parent) = destination.parent() {
            #[allow(clippy::disallowed_methods)]
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("  skipped {recorded}: creating {}: {e}", parent.display());
                skipped.push((
                    recorded.clone(),
                    format!("creating {}: {e}", parent.display()),
                ));
                continue;
            }
        }

        // `create_new`: an export never overwrites, so two recorded paths that
        // collide after sanitizing are reported rather than silently merged.
        #[allow(clippy::disallowed_methods)]
        let created = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&destination);
        let mut file = match created {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  skipped {recorded}: {} — {e}", destination.display());
                skipped.push((recorded.clone(), format!("{} — {e}", destination.display())));
                continue;
            }
        };
        if let Err(e) = file.write_all(&bytes) {
            eprintln!("  failed {recorded}: {e}");
            skipped.push((recorded.clone(), e.to_string()));
            continue;
        }
        drop(file);

        let times = LogicalTimes::of(object);
        if !times.is_empty() {
            let applied = apply_times(&destination, &times);
            if !applied {
                unset_times.push((recorded.clone(), times));
            }
        }

        bytes_out += bytes.len() as u64;
        written += 1;
        println!(
            "  {}",
            destination
                .strip_prefix(target)
                .unwrap_or(&destination)
                .display()
        );
    }

    println!();
    println!("Written:     {written} file(s), {}", human_bytes(bytes_out));

    if !alterations.is_empty() {
        println!();
        println!("Paths altered to be writable ({}):", alterations.len());
        for alteration in &alterations {
            println!("  recorded {}", alteration.recorded);
            println!("    wrote  {}", alteration.written);
            println!("    why    {}", alteration.reason);
        }
    }

    if !unset_times.is_empty() {
        println!();
        println!(
            "Recorded times this host cannot set ({}):",
            unset_times.len()
        );
        for (name, times) in &unset_times {
            println!("  {name}");
            if let Some(t) = &times.birth_time {
                println!("    birthTime      {t}");
            }
            if let Some(t) = &times.record_changed {
                println!("    recordChanged  {t}");
            }
        }
    }

    if !skipped.is_empty() {
        println!();
        println!(
            "Skipped:     {} file(s) whose bytes could not be read",
            skipped.len()
        );
        // The first few by name, so the reason is visible without re-running
        // and scraping stderr; the count above is the whole story.
        for (name, why) in skipped.iter().take(EXPORT_SKIPS_LISTED) {
            println!("  {name}");
            println!("    {why}");
        }
        if skipped.len() > EXPORT_SKIPS_LISTED {
            println!("  … and {} more", skipped.len() - EXPORT_SKIPS_LISTED);
        }
    }

    if written == 0 {
        return ExitCode::from(EXIT_LISTING_IO);
    }
    // A partial export is still written — it is more useful than none — but it
    // is not a success. `verify` answers the same condition with the same code:
    // evidence was recorded that could not be read back.
    if !skipped.is_empty() {
        return ExitCode::from(EXIT_UNVERIFIABLE);
    }
    ExitCode::SUCCESS
}

/// How many skipped files `export` names before summarising the rest.
///
/// Enough to show the shape of the problem, few enough that a run dropping
/// tens of thousands of files does not bury its own closing line.
const EXPORT_SKIPS_LISTED: usize = 10;

/// A locus naming the container being exported.
fn locus_for(path: &std::path::Path) -> aff4tools::Locus {
    aff4tools::Locus::new(path)
}

/// Read a logical file stored as an `ImageStream` rather than a ZIP segment.
///
/// AFF4-L 2019 §3.4: a file above the segment threshold is written as a chunked,
/// compressed stream whose ARN is the file's own. `unicode.aff4` stores six of
/// its seven files this way, so this is the common case rather than the
/// exception.
fn read_logical_stream(
    container: &mut aff4tools::Container,
    graph: &aff4tools::rdf::Graph,
    object: &aff4tools::model::Aff4Object,
    locus: &aff4tools::Locus,
) -> Result<Vec<u8>, aff4tools::Error> {
    let lexicon = container.lexicon();
    let stream = aff4tools::stream::ImageStream::open(&object.arn, graph, lexicon, locus)?;
    let mut out = Vec::with_capacity(usize::try_from(stream.size()).unwrap_or_default());
    stream.read_all(
        container.volume_mut(),
        &mut |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        },
        locus,
    )?;
    Ok(out)
}

/// Decode the percent-escaping an ARN's path carries.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
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

/// Set the two times a POSIX host can set, returning whether all four were.
///
/// macOS and Linux expose mtime and atime through `utimensat`, which is the
/// syscall `touch` itself uses.
fn apply_times(path: &std::path::Path, times: &aff4tools::export::LogicalTimes) -> bool {
    let mtime = times.last_written.as_deref().and_then(parse_rfc3339);
    let atime = times.last_accessed.as_deref().and_then(parse_rfc3339);

    if let (Some(mtime), Some(atime)) = (mtime, atime) {
        let file = std::fs::File::open(path);
        if let Ok(file) = file {
            let times = std::fs::FileTimes::new()
                .set_accessed(atime)
                .set_modified(mtime);
            if file.set_times(times).is_err() {
                return false;
            }
        }
    }

    // The other two are never settable here, so a container recording them
    // always has something to report.
    times.birth_time.is_none() && times.record_changed.is_none()
}

/// Parse an RFC 3339 timestamp into a `SystemTime`.
///
/// Deliberately minimal: only the forms AFF4-L containers actually carry, and
/// `None` for anything else rather than a guess. A wrong timestamp on extracted
/// evidence is worse than an unset one.
fn parse_rfc3339(text: &str) -> Option<std::time::SystemTime> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let num = |a: usize, b: usize| text.get(a..b)?.parse::<i64>().ok();
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);

    // Days since the Unix epoch, by the civil-from-days algorithm (Howard
    // Hinnant's, public domain). Avoids a date dependency for four fields.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    let mut seconds = days * 86400 + hour * 3600 + minute * 60 + second;

    // Offsets: `Z`, or ±HH:MM after the seconds field.
    let rest = &text[19..];
    let offset_at = rest.find(['+', '-']);
    if let Some(at) = offset_at {
        let sign = if rest.as_bytes()[at] == b'+' { 1 } else { -1 };
        let offset = &rest[at + 1..];
        if offset.len() >= 5 {
            let oh = offset.get(0..2)?.parse::<i64>().ok()?;
            let om = offset.get(3..5)?.parse::<i64>().ok()?;
            seconds -= sign * (oh * 3600 + om * 60);
        }
    }

    let epoch = std::time::UNIX_EPOCH;
    if seconds >= 0 {
        u64::try_from(seconds)
            .ok()
            .map(|s| epoch + std::time::Duration::from_secs(s))
    } else {
        u64::try_from(-seconds)
            .ok()
            .map(|s| epoch - std::time::Duration::from_secs(s))
    }
}

fn run_verify(
    sets: &[Vec<PathBuf>],
    format: Format,
    block_hashes: bool,
    strict: bool,
    verbose: bool,
    full_listing: Option<&Path>,
) -> ExitCode {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut worst = 0u8;
    let mut reports = Vec::new();

    let options = VerifyOptions { block_hashes };

    for (index, set) in sets.iter().enumerate() {
        // The header goes out before reading begins, but only for text: JSON
        // serializes the report as one document, and a header printed ahead of
        // it would not be part of that document.
        if index > 0 && format == Format::Text {
            let _ = writeln!(out);
        }
        // JSON serializes the report as one document, so a header printed
        // ahead of it would not be part of that document.
        let header = match format {
            Format::Text => Some(&mut out),
            Format::Json => None,
        };
        match verify(set, options, header) {
            Ok((report, summary)) => {
                // A mismatch is a successful verification with a negative
                // result, so it gets its own code rather than being reported as
                // a damaged container.
                if report.has_mismatch() {
                    worst = worst.max(EXIT_MISMATCH);
                }
                // Evidence that could not be read is a third answer, distinct
                // from both "matched" and "did not match". Reporting it as
                // success would let a container whose evidence will not
                // decompress pass a scripted check.
                if report.has_unreadable() {
                    worst = worst.max(EXIT_UNVERIFIABLE);
                }
                if strict && !summary.is_conformant() {
                    worst = worst.max(EXIT_STRICT_DEVIATION);
                }
                match format {
                    Format::Text => {
                        // The table is written before the report, so the
                        // report's closing pointer names a file that already
                        // exists — and so a failure to write it is reported
                        // where the operator is still reading.
                        let listing = full_listing.map(|path| {
                            let outcome = write_digest_table(path, &report);
                            if let Err(e) = &outcome {
                                eprintln!("error: cannot write {}: {e}", path.display());
                            }
                            (path, outcome.is_ok())
                        });
                        if listing.as_ref().is_some_and(|(_, ok)| !ok) {
                            worst = worst.max(EXIT_LISTING_IO);
                        }
                        let _ = write_verification(
                            &mut out,
                            &report,
                            verbose,
                            block_hashes,
                            listing.and_then(|(path, ok)| ok.then_some(path)),
                        );
                    }
                    Format::Json => reports.push(report),
                }
            }
            Err(error) => worst = worst.max(error.report()),
        }
    }

    if format == Format::Json {
        let rendered = if reports.len() == 1 {
            serde_json::to_string_pretty(&reports[0])
        } else {
            serde_json::to_string_pretty(&reports)
        };
        match rendered {
            Ok(text) => {
                let _ = writeln!(out, "{text}");
            }
            Err(e) => {
                eprintln!("error: cannot render JSON: {e}");
                worst = worst.max(EXIT_USAGE);
            }
        }
    }

    ExitCode::from(worst)
}

/// Verify one container, also reporting whether it conformed.
fn verify(
    paths: &[PathBuf],
    options: VerifyOptions,
    header: Option<&mut StdoutLock>,
) -> std::result::Result<(VerificationReport, ContainerSummary), OpenError> {
    let mut container = open_striped(paths)?;

    // A missing volume means missing data, so say so and name the fix rather
    // than succeeding against a partial view.
    if paths.len() == 1 {
        let missing = container.missing_volume_arns();
        if !missing.is_empty() {
            return Err(OpenError::PartOfSplitSet {
                path: paths[0].clone(),
                missing: missing.len(),
            });
        }
    }

    // Built for the conformance check, and kept: the report's header states
    // what container this is, from the same summary `info` renders.
    let summary = container.summarize()?;

    if let Some(out) = header {
        let _ = report::write_identity_block(out, &summary);
        if paths.len() > 1
            && let Some(line) = describe_split_layout(&mut container, &summary)
        {
            let _ = writeln!(out, "{line}");
        }
        let _ = out.flush();
    }

    let estimate = estimate_work(&mut container, options).unwrap_or_default();
    let show_progress = std::io::IsTerminal::is_terminal(&std::io::stderr());
    if show_progress && estimate.is_substantial() {
        // Trimmed: the description's last line ends in a newline of its own,
        // and the progress line repaints in place directly beneath it.
        // Whether this container holds logical file images. The rollup below
        // is for AFF4-L only, where there is one stream per file; a physical
        // image keeps its per-stream description however many streams it has.
        let logical = summary.counts.files > 0;
        eprintln!("{}", describe_estimate(&estimate, logical).trim_end());
    }

    // The meter measures the whole run, so it is given the run's total rather
    // than deriving one from whichever object is being read.
    let mut reporter = ProgressReporter::new(show_progress)
        .expecting(estimate.bytes_to_read)
        .across_parts(paths.len());
    let report = verify_container_with_progress(&mut container, options, &mut reporter)?;
    reporter.finish();

    Ok((report, summary))
}

/// How a multi-part set allocates its data, as a line for the report.
///
/// [`None`] when the set holds a single stored stream, or when no image's map
/// can be resolved: nothing is claimed that was not read. The layout is
/// inferred from map geometry rather than declared — see
/// [`aff4tools::Map::split_layout`] — so the line says so, and both layouts
/// reassemble identically.
fn describe_split_layout(container: &mut Container, summary: &ContainerSummary) -> Option<String> {
    let lexicon = container.lexicon();
    let images: Vec<Aff4Object> = summary
        .objects
        .iter()
        .filter(|o| o.role.is_image())
        .cloned()
        .collect();

    for object in images {
        let locus = Locus::new(container.volume().path());
        let Ok(image) = Image::open_in_set(&object.arn, container.volumes_mut(), lexicon, &locus)
        else {
            continue;
        };
        let layout = image.map().split_layout();
        if layout == SplitLayout::Single {
            continue;
        }
        return Some(format!(
            "Layout:\t{} across {} parts, inferred from the map.",
            layout.describe(),
            container.volumes().len()
        ));
    }
    None
}

/// Describe what verification is about to read.
///
/// Scope, not duration: which bytes will be read, which digests will be
/// recomputed, and how the host will be used.
fn describe_estimate(estimate: &WorkEstimate, logical: bool) -> String {
    let codecs = if estimate.codecs.is_empty() {
        String::new()
    } else {
        format!(" ({})", estimate.codecs.join(", "))
    };

    let mut out = format!(
        "Reading {} across {} bevies{codecs}",
        human_bytes(estimate.bytes_to_read),
        estimate.bevies,
    );
    if estimate.bytes_on_disk > 0 && estimate.bytes_on_disk != estimate.bytes_to_read {
        out.push_str(&format!(
            ", from {} compressed on disk",
            human_bytes(estimate.bytes_on_disk)
        ));
    }
    out.push_str(".\n");

    // What will actually be recomputed, named before the run rather than
    // discovered in the report afterwards.
    //
    // A logical container has one stream per file, where the same two lines
    // repeat for every one of them — hundreds of lines that say the same
    // thing, scrolled past before the progress bar even starts. Above the
    // threshold the same facts are stated once, as totals.
    //
    // Gated on the container being logical rather than on the stream count
    // alone. A physical image today has one stream, so a count-only test would
    // never fire on one — but that is a property of the evidence, not a
    // guarantee about the code, and this report is the one an examiner reads
    // about a device. The rollup is for AFF4-L, so it asks whether this is
    // AFF4-L.
    if logical && estimate.streams.len() > VERBOSE_STREAM_LIMIT {
        out.push_str(&describe_streams_in_bulk(estimate));
        return finish_estimate(out, estimate);
    }

    for stream in &estimate.streams {
        let linear = if stream.linear.is_empty() {
            "no recomputable acquisition hash".to_owned()
        } else {
            let names: Vec<String> = stream.linear.iter().map(ToString::to_string).collect();
            format!("acquisition hash {}", names.join(" + "))
        };
        out.push_str(&format!(
            "  {} ({}): {linear}\n",
            human_bytes(stream.size),
            stream.codec,
        ));

        if !stream.block_hashes.is_empty() {
            let names: Vec<String> = stream
                .block_hashes
                .iter()
                .map(ToString::to_string)
                .collect();
            out.push_str(&format!(
                "    per-chunk block hashes: {}\n",
                names.join(" + ")
            ));
        } else if estimate.block_hashes {
            out.push_str("    per-chunk block hashes: none stored\n");
        }

        for (predicate, reason) in &stream.not_recomputed {
            out.push_str(&format!("    not recomputed: {predicate} — {reason}\n"));
        }
    }

    finish_estimate(out, estimate)
}

/// How many logical streams may be described one by one.
///
/// Applies only to AFF4-L, where there is one stream per file. The line is
/// drawn where a list stops being readable at a glance rather than at any
/// property of the format.
const VERBOSE_STREAM_LIMIT: usize = 12;

/// State what will be recomputed as totals rather than per stream.
///
/// Every distinct combination is named, so nothing is hidden by the rollup: if
/// some files carry block hashes and others do not, both are stated.
fn describe_streams_in_bulk(estimate: &WorkEstimate) -> String {
    let mut linear: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut blocks: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut with_blocks = 0usize;
    let mut not_recomputed = 0usize;

    for stream in &estimate.streams {
        for algorithm in &stream.linear {
            linear.insert(algorithm.to_string());
        }
        if stream.block_hashes.is_empty() {
            continue;
        }
        with_blocks += 1;
        for algorithm in &stream.block_hashes {
            blocks.insert(algorithm.to_string());
        }
    }
    not_recomputed += estimate
        .streams
        .iter()
        .filter(|s| !s.not_recomputed.is_empty())
        .count();

    let mut out = format!("  {} streams", thousands(estimate.streams.len()));
    if linear.is_empty() {
        out.push_str(", no recomputable acquisition hash");
    } else {
        out.push_str(&format!(
            ": acquisition hash {}",
            linear.into_iter().collect::<Vec<_>>().join(" + ")
        ));
    }
    out.push('\n');

    if with_blocks > 0 {
        out.push_str(&format!(
            "    per-chunk block hashes: {} for {} of them\n",
            blocks.into_iter().collect::<Vec<_>>().join(" + "),
            thousands(with_blocks),
        ));
    } else if estimate.block_hashes {
        out.push_str("    per-chunk block hashes: none stored\n");
    }

    if not_recomputed > 0 {
        out.push_str(&format!(
            "    {} stream(s) hold a digest that will not be recomputed; \
             the report names each one\n",
            thousands(not_recomputed),
        ));
    }
    out
}

/// Append the parts that do not depend on how the streams were described.
fn finish_estimate(mut out: String, estimate: &WorkEstimate) -> String {
    let plan = estimate.threads;
    if plan.is_parallel() {
        let range = |low: usize, high: usize| {
            if low == high {
                format!("{low}")
            } else {
                format!("{low}-{high}")
            }
        };
        let digesting = if plan.digesters > 0 {
            format!(", {} digesting", plan.digesters)
        } else {
            String::new()
        };
        out.push_str(&format!(
            "Threads: {} reading, {} hashing{digesting}.\n",
            range(plan.readers, plan.reader_ceiling()),
            plan.workers,
        ));
    } else {
        out.push_str("Threads: 1 (this host reports no spare parallelism).\n");
    }

    // No time estimate here. The progress line that follows immediately carries
    // a measured rate and a remaining time, both of which beat a prediction
    // made from a fixed throughput constant — and it repaints, so it corrects
    // itself as the run proceeds. Announcing "progress follows on stderr" just
    // above the progress itself said nothing the next line did not show.
    //
    // What stays above is what progress cannot show: which bytes will be read,
    // which digests will be recomputed, and how the host will be used.

    if cfg!(debug_assertions) {
        out.push_str(
            "**********\nThis is an unoptimized debug build. Hashing runs roughly \
             10x slower than a release build. Use a release build to verify evidence.",
        );
    }

    out
}

/// Renders verification progress to stderr at a readable rate.
///
/// The library emits an event per chunk and holds no clock — rate is a
/// presentation decision, so the throttle lives here. Output goes to stderr so
/// `--format json` on stdout stays machine-parseable.
struct ProgressReporter {
    enabled: bool,
    last_paint: std::time::Instant,
    started: std::time::Instant,
    painted: bool,
    /// Bevies delivered, and how many the stream declares.
    ///
    /// Held rather than painted on arrival: a bevy completes far more often
    /// than the repaint interval, and the count is shown alongside the byte
    /// figure rather than as a line of its own.
    bevies: Option<(u64, u64)>,
    /// Bytes delivered across the whole verification, not one object's share.
    ///
    /// Each `Progress::Bytes` carries `done` counted from that object's own
    /// start, so painting it directly restarted the bar at zero for every
    /// object — a nine-part set showed eleven bars and no sense of how much of
    /// the run remained. Accumulating deltas here turns them into one meter.
    cumulative: u64,
    /// The last `done` seen per subject, so deltas can be taken.
    seen: std::collections::HashMap<String, u64>,
    /// What `estimate_work` said the whole run would read.
    ///
    /// `None` when no estimate was available, which drops the percentage and
    /// the time remaining rather than inventing either.
    expected: Option<u64>,
    /// Which part of a set is being read, and how many there are.
    ///
    /// Only the bevy figure is per-part; the byte figure spans the whole run.
    /// Naming the part is what keeps the two legible side by side.
    part: Option<(usize, usize)>,
    /// Stream ARNs seen so far, in first-seen order, so a part can be numbered.
    ///
    /// A set's parts are verified in order, so the position at which a stream
    /// first appears is its part number. Held rather than derived from the ARN,
    /// which carries no ordinal.
    streams: Vec<String>,
    /// How many parts the set has, from the caller.
    parts: usize,
}

impl ProgressReporter {
    /// How often the progress line may repaint.
    const INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

    fn new(enabled: bool) -> Self {
        let now = std::time::Instant::now();
        Self {
            enabled,
            last_paint: now,
            started: now,
            painted: false,
            bevies: None,
            cumulative: 0,
            seen: std::collections::HashMap::new(),
            expected: None,
            part: None,
            streams: Vec::new(),
            parts: 0,
        }
    }

    /// Tell the meter how many parts the run covers, for the bevy label.
    fn across_parts(mut self, parts: usize) -> Self {
        self.parts = parts;
        self
    }

    /// Give the meter the total it is measuring against.
    fn expecting(mut self, bytes: u64) -> Self {
        self.expected = (bytes > 0).then_some(bytes);
        self
    }

    /// Fold one object's cumulative `done` into the run-wide total.
    ///
    /// Returns the run-wide figure. `done` counts from its own object's start,
    /// so the delta is what this event added; a `done` below what that subject
    /// last reported means a new traversal of it, and the whole figure is the
    /// delta.
    fn advance(&mut self, arn: &str, done: u64) -> u64 {
        let previous = self.seen.entry(arn.to_owned()).or_insert(0);
        let delta = if done >= *previous {
            done - *previous
        } else {
            done
        };
        *previous = done;
        self.cumulative = self.cumulative.saturating_add(delta);
        self.cumulative
    }

    /// Clear the progress line, so it does not collide with the report.
    fn finish(&mut self) {
        if self.painted {
            eprint!("\r\x1b[2K");
            self.painted = false;
        }
    }
}

impl aff4tools::ProgressObserver for ProgressReporter {
    fn on(&mut self, event: Progress<'_>) {
        if !self.enabled {
            return;
        }

        match event {
            Progress::Bytes { arn, done, total } => {
                let done = self.advance(arn.as_str(), done);
                let now = std::time::Instant::now();
                if now.duration_since(self.last_paint) < Self::INTERVAL {
                    return;
                }
                self.last_paint = now;
                self.painted = true;

                // The whole run's total where one is known, so the bar measures
                // the run rather than the current object. An object's own
                // `total` is the fallback, which is what a container with no
                // usable estimate gets.
                let total = self.expected.or(total);

                let elapsed = now.duration_since(self.started).as_secs_f64().max(0.001);
                #[allow(clippy::cast_precision_loss)]
                let rate = done as f64 / elapsed;
                // Both figures in GiB, so the unit is stated once and the two
                // numbers can be compared at a glance. A unit that changes as
                // the run proceeds — KiB, then MiB, then GiB — also changes
                // the field width, which shifts everything after it.
                const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
                #[allow(clippy::cast_precision_loss)]
                let done_gib = done as f64 / GIB;
                let share = total.map_or_else(String::new, |total| {
                    #[allow(clippy::cast_precision_loss)]
                    let total = total as f64;
                    let percent = if total == 0.0 {
                        0.0
                    } else {
                        (done as f64 / total) * 100.0
                    };
                    format!("/{:.1} GiB | {percent:.0}%", total / GIB)
                });

                // Explicitly scoped. `BevyCompleted` counts one stream's
                // bevies, so beside a meter spanning nine parts a bare
                // "5/32 bevies" reads as the whole set and is off by an order
                // of magnitude. Naming the part makes the smaller number right
                // rather than misleading.
                let bevies =
                    self.bevies
                        .map_or_else(String::new, |(done, total)| match self.part {
                            Some((part, parts)) => {
                                format!("{done}/{total} bevies in part {part}/{parts}")
                            }
                            None => format!("{done}/{total} bevies"),
                        });

                // Time remaining
                let remaining = total.map_or_else(String::new, |total| {
                    #[allow(clippy::cast_precision_loss)]
                    let left = (total.saturating_sub(done)) as f64;
                    if rate <= 0.0 {
                        return String::new();
                    }
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let seconds = (left / rate).min(359_999.0) as u64;
                    format!(
                        "{:01}:{:02}:{:02}",
                        seconds / 3600,
                        (seconds % 3600) / 60,
                        seconds % 60
                    )
                });

                // Single-spaced, and 73 columns at its widest. Staying inside
                // 80 is what makes the repaint work at all: a wrapped line
                // cannot be overwritten by the carriage return.
                let mut line = format!("{done_gib:.1}{share} | {}/s", human_bytes(rate as u64));
                if !bevies.is_empty() {
                    line.push_str(" | ");
                    line.push_str(&bevies);
                }
                if !remaining.is_empty() {
                    line.push_str(" | ");
                    line.push_str(&remaining);
                }
                eprint!("\r\x1b[2K{line}");
            }
            Progress::BevyCompleted { done, total, .. } => {
                self.bevies = Some((done, total));
            }
            Progress::CheckCompleted { check } => {
                // Only a mismatch is worth interrupting the progress line for.
                // A match is reported twice by the report that follows — once
                // in the `Verified: N of N` tally and again in full by
                // `write_check` — so echoing it here as it lands was pure
                // duplication. A mismatch is different: it is the finding the
                // examiner is waiting for, and on a long run it should appear
                // when it happens rather than minutes later at the end.
                if check.outcome.is_mismatch() {
                    self.finish();
                    eprintln!("  MISMATCH {} ({})", check.predicate, check.algorithm);
                }
            }
            Progress::ObjectStarted { arn, role, .. } => {
                // Cleared with the subject. The count belongs to the stream
                // that reported it, so carrying it into the next object would
                // show a finished stream's total beside the new one's bytes.
                self.bevies = None;

                // Only streams are parts. An image spans them, so it must not
                // claim a part number of its own.
                if matches!(role, aff4tools::ObjectRole::ImageStream) && self.parts > 1 {
                    let arn = arn.as_str();
                    let position = self
                        .streams
                        .iter()
                        .position(|seen| seen == arn)
                        .unwrap_or_else(|| {
                            self.streams.push(arn.to_owned());
                            self.streams.len() - 1
                        });
                    self.part = Some((position + 1, self.parts));
                } else {
                    self.part = None;
                }
            }
            Progress::ObjectFinished { .. } => {}
            // `Progress` is non-exhaustive; a new event must not break the
            // build, and silently ignoring one is the right default for a
            // display.
            _ => {}
        }
    }
}

/// Write the human-readable verification report.
///
/// Two rules this rendering must follow: the word "verified" appears only
/// against a digest that was actually recomputed, and every digest is shown at
/// full length.
/// Name what a map's holes were filled from.
///
/// Delegates to [`aff4tools::GapFill::describe`] so the accounting line and the
/// discontiguous note cannot word the same fact differently; this only supplies
/// the fallback for a map that recorded gaps without one, which a parsed map
/// never does.
fn describe_gap_fill(fill: Option<&aff4tools::GapFill>) -> String {
    fill.map_or_else(
        || "the gap stream (spec §4)".to_owned(),
        aff4tools::GapFill::describe,
    )
}

fn write_verification(
    out: &mut impl Write,
    report: &VerificationReport,
    verbose: bool,
    block_hashes_requested: bool,
    listing: Option<&Path>,
) -> std::io::Result<()> {
    let checked = report.checked_count();
    let matched = report.match_count();
    let declined = report.not_verifiable_count();
    let unreadable = report.unreadable_count();

    // Which images are logical files, taken from the checks' own roles rather
    // than from the container's type: a container may hold both, and the
    // accounting entries do not carry a role of their own.
    let logical = logical_images(report);

    for entry in &report.read_accounting {
        // A logical file's accounting can only ever say "all of it was
        // stored": AFF4-L has no described runs, no map, and no gaps, so the
        // line states a constant. On a disk image the same figures are the
        // real composition of the address space — holes, described runs — and
        // are printed exactly as before.
        if logical.contains(entry.image.as_str()) {
            continue;
        }
        writeln!(out)?;
        writeln!(out, "  {}", entry.image)?;
        // `map` against `read`: where these figures came from. `map` means they
        // were derived from the map's entries without producing a byte; `read`
        // means they were measured while streaming the image. Naming the source
        // is the honest form — the earlier label said "content", which invited
        // reading a hole's size as content that had been examined.
        //
        // "Described" bytes are acquired evidence recorded as a run rather than
        // stored. Never call them empty, synthetic, or missing.
        writeln!(
            out,
            "    {}    {} stored, {} described",
            if entry.traversed { "read" } else { "map " },
            human_bytes(entry.accounting.stored),
            human_bytes(entry.accounting.described)
        )?;
        if entry.accounting.gap_filled > 0 {
            // Never folded in with "described": a described run was measured by
            // the imager, whereas a gap was never recorded at all.
            writeln!(
                out,
                "            {} holes from data not acquired, filled with {}",
                human_bytes(entry.accounting.gap_filled),
                describe_gap_fill(entry.accounting.gap_fill.as_ref())
            )?;
        }
        if entry.accounting.unknown_placeholder > 0 {
            writeln!(
                out,
                "    {} of placeholder content for regions whose true \
                 content is unknown; not recovered data",
                human_bytes(entry.accounting.unknown_placeholder)
            )?;
        }
    }

    // Four numbers, because there are four: checks attempted, checks that
    // completed, recorded values compared, and per-chunk digests compared.
    //
    // **Attempted is stated first, and it is the count that reconciles with the
    // list below.**
    //
    // The recorded-value and per-chunk counts stay, for the reason they were
    // added: a block-hash check compares a whole sequence rather than one
    // value, so "6 of 6" otherwise looked inconsistent with the four digests
    // `info` lists.
    let attempted = report.checks.len();
    let values = report.recorded_value_count();
    let chunks = report.chunk_digest_count();

    writeln!(out)?;
    // Stated before the results, not after them: how deep the verification
    // went qualifies every number that follows, and an examiner who reads only
    // the top of the report still needs it. It used to sit below the whole
    // per-check listing, which on a large container put it a million lines
    // away from the figures it qualifies.
    if report.block_hashes_verified && !logical.is_empty() {
        let files = block_hash_subject_count(report);
        writeln!(
            out,
            "Block hashes: per-chunk digests recomputed for {} of {} file(s) \
             ({} digests)",
            thousands(files),
            thousands(file_check_subjects(report, &logical)),
            thousands(chunks)
        )?;
    }
    writeln!(out, "Verification results:")?;
    writeln!(out, "{attempted} checks attempted; {checked} completed.")?;
    if chunks > 0 {
        writeln!(
            out,
            "{matched} of {checked} matched ({values} recorded digest value(s), \
             {} per-chunk digests)",
            thousands(chunks)
        )?;
    } else {
        writeln!(
            out,
            "{matched} of {checked} matched ({values} recorded digest value(s))"
        )?;
    }
    if declined > 0 {
        writeln!(
            out,
            " *********** {declined} recorded digest(s) were not recomputed ***********"
        )?;
    }
    // Named separately from the count above, because the two are different
    // findings: one is this build's limits, the other is the container's.
    if unreadable > 0 {
        writeln!(
            out,
            "             {unreadable} of those span unreadable bytes"
        )?;
    }

    // Mismatches first
    let mismatches: Vec<&HashCheck> = report
        .checks
        .iter()
        .filter(|c| c.outcome.is_mismatch())
        .collect();

    if !mismatches.is_empty() {
        writeln!(out)?;
        writeln!(out, "MISMATCH ({})", mismatches.len())?;
        for check in mismatches {
            write_check(out, check, verbose)?;
        }
    }

    // Collapsing applies to the per-file digests of a logical image, which is
    // where the volume comes from: a disk image records a handful of digests
    // over its map and streams, and listing them in full is what makes that
    // report readable. So a container with no logical images prints exactly as
    // it always has.
    let collapse = !verbose && !logical.is_empty();

    // Every remaining check, matches included, in the order the report holds
    // them — unchanged for a disk image and under `--verbose`.
    if !collapse {
        let shown: Vec<&HashCheck> = report
            .checks
            .iter()
            .filter(|c| !c.outcome.is_mismatch())
            .collect();

        if !shown.is_empty() {
            writeln!(out)?;
            writeln!(out, "Checks")?;
            for check in shown {
                write_check(out, check, verbose)?;
            }
        }
    }

    // A check that could not be performed is a finding, so it is always listed
    // in full: there are never so many that they bury anything.
    let declined_checks: Vec<&HashCheck> = report
        .checks
        .iter()
        .filter(|c| matches!(c.outcome, Outcome::NotVerifiable { .. }))
        .collect();

    if collapse && !declined_checks.is_empty() {
        writeln!(out)?;
        writeln!(out, "NOT RECOMPUTED ({})", declined_checks.len())?;
        for check in declined_checks {
            write_check(out, check, verbose)?;
        }
    }

    // Matches are the expected case, and one entry each is what made this
    // report unreadable: 138,179 files produced 1.25 million lines to say that
    // nothing was wrong. Counted and grouped by what was checked; the digests
    // themselves go to `--full-listing`.
    let matches = report.checks.iter().filter(|c| c.outcome == Outcome::Match);
    let matches: Vec<&HashCheck> = matches.collect();

    if collapse && !matches.is_empty() {
        writeln!(out)?;
        writeln!(out, "Matched ({})", matches.len())?;
        for (label, count) in group_matches(&matches) {
            writeln!(out, "  {count:>9}  {label}")?;
        }
    }

    if !report.notes.is_empty() {
        writeln!(out)?;
        writeln!(out, "Notes")?;
        // A note names its subject and then repeats the ARN inside its error
        // chain, three times in all — which is unreadable once a logical image
        // produces hundreds of them. Where several notes share one complaint,
        // it is stated once and the subjects listed under it.
        //
        // Only where the report was collapsed: a disk image's notes are
        // prose an examiner reads whole, and rewording them would lose the
        // reasoning they carry.
        if collapse {
            for (shape, subjects) in group_notes(&report.notes) {
                match subjects.len() {
                    0 => {}
                    1 => writeln!(out, "  {shape}")?,
                    _ => {
                        writeln!(out, "  {} images {shape}", subjects.len())?;
                        for subject in subjects {
                            writeln!(out, "    {subject}")?;
                        }
                    }
                }
            }
        } else {
            for note in &report.notes {
                writeln!(out, "  {note}")?;
            }
        }
    }

    writeln!(out)?;
    // Describe what was done with block hashes. The header already stated the
    // coverage, so this is the closing confirmation rather than the only
    // mention.
    if report.block_hashes_verified {
        writeln!(out, "All per-chunk block hashes were recomputed.")?;
    } else if block_hashes_requested {
        writeln!(out, "This container stores no per-chunk block hashes.")?;
    } else {
        writeln!(
            out,
            "Per-chunk block hashes were not recomputed, per --no-block-hashing."
        )?;
    }

    if report.has_mismatch() {
        writeln!(
            out,
            "\n******** At least one recomputed digest does not match the value the \
             container recorded. ********"
        )?;
    } else if checked == 0 {
        writeln!(out, "\nNo hash digest was recomputed.")?;
    }

    // Named last, where an examiner who has read the verdict looks for the
    // detail behind it.
    if let Some(path) = listing {
        writeln!(out, "Per-file digests: {}", path.display())?;
    } else if collapse && !matches.is_empty() {
        writeln!(
            out,
            "Every digest is listed with --verbose, or written as TSV with \
             --full-listing <PATH>."
        )?;
    }

    Ok(())
}

/// Group notes that say the same thing about different subjects.
///
/// Returns each distinct shape with the subjects it covers. A note that does
/// not match the recognised shape is returned alone, with its full text as the
/// shape and no subject list, so nothing is ever dropped or reworded.
fn group_notes(notes: &[String]) -> Vec<(String, Vec<String>)> {
    let mut order: Vec<String> = Vec::new();
    let mut grouped: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for note in notes {
        let (shape, subject) = match note_shape(note) {
            Some(split) => split,
            None => (note.clone(), None),
        };
        if !grouped.contains_key(&shape) {
            order.push(shape.clone());
        }
        let entry = grouped.entry(shape).or_default();
        if let Some(subject) = subject {
            entry.push(subject);
        }
    }

    order
        .into_iter()
        .map(|shape| {
            let subjects = grouped[&shape].clone();
            (shape, subjects)
        })
        .collect()
}

/// Split `image <ARN> <complaint>` into the complaint and the ARN.
///
/// Only the leading `image <ARN>` is treated as the subject; the rest is the
/// shape. Two notes about different files then share a shape exactly when the
/// complaint is the same, which is what makes them safe to count together.
fn note_shape(note: &str) -> Option<(String, Option<String>)> {
    let rest = note.strip_prefix("image ")?;
    let (arn, complaint) = rest.split_once(' ')?;
    if !arn.starts_with("aff4://") {
        return None;
    }
    // The complaint repeats the ARN in its error chain. Take the leading
    // sentence, and the trailing explanation after the last occurrence of the
    // ARN — the part that says *why*, which is what distinguishes "nothing was
    // recorded to read" from a failed comparison. The middle is the chain,
    // which only restates the subject.
    let head = complaint.split(':').next().unwrap_or(complaint).trim();
    let tail = complaint
        .rfind(arn)
        .map(|at| {
            complaint[at + arn.len()..]
                .trim_start_matches([' ', ':'])
                .trim()
        })
        .filter(|tail| !tail.is_empty());
    let shape = match tail {
        Some(tail) => format!("{head} — {tail}"),
        None => head.to_string(),
    };
    Some((shape, Some(arn.to_string())))
}

/// The ARNs of images that are logical files or folders.
///
/// Taken from the checks, which carry a role, because [`ImageAccounting`] does
/// not — and building it from the roles rather than from the container's
/// declared type keeps a mixed container correct.
fn logical_images(report: &VerificationReport) -> std::collections::HashSet<&str> {
    report
        .checks
        .iter()
        .filter(|c| matches!(c.role, ObjectRole::FileImage | ObjectRole::FolderImage))
        .map(|c| c.subject.as_str())
        .collect()
}

/// How many distinct files had their per-chunk digests recomputed.
///
/// A per-chunk check carries the stream's own ARN and covers a whole sequence,
/// with one check per algorithm — so the file count is the number of distinct
/// subjects, not the number of checks.
fn block_hash_subject_count(report: &VerificationReport) -> usize {
    report
        .checks
        .iter()
        .filter(|c| c.outcome.was_checked() && c.digests_covered.is_some())
        .map(|c| c.subject.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

/// How many distinct files carry a per-file digest.
fn file_check_subjects(
    report: &VerificationReport,
    logical: &std::collections::HashSet<&str>,
) -> usize {
    report
        .checks
        .iter()
        .filter(|c| logical.contains(c.subject.as_str()))
        .map(|c| c.subject.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

/// Group matching checks into one counted line each.
///
/// The grouping is what the check was over, not the algorithm alone: "138,179
/// files, MD5 + SHA1" is the fact an examiner wants, and splitting it per
/// algorithm would restate the same population twice.
fn group_matches(matches: &[&HashCheck]) -> Vec<(String, usize)> {
    let mut order: Vec<String> = Vec::new();
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for check in matches {
        let label = match_group_label(check);
        if !counts.contains_key(&label) {
            order.push(label.clone());
        }
        *counts.entry(label).or_default() += 1;
    }
    order
        .into_iter()
        .map(|label| {
            let count = counts[&label];
            (label, count)
        })
        .collect()
}

/// The line a matching check is counted under.
fn match_group_label(check: &HashCheck) -> String {
    let algorithm = check.algorithm.to_string();
    match check.role {
        ObjectRole::FileImage => format!("file digests ({algorithm})"),
        ObjectRole::FolderImage => format!("folder digests ({algorithm})"),
        // A block-hash check is either the per-chunk sequence itself (which
        // covers many digests) or the SHA-512 over the stored segment. They
        // are different claims and must not be counted under one label.
        ObjectRole::BlockHashes if check.digests_covered.is_some() => {
            format!("per-chunk digest sequences ({algorithm})")
        }
        ObjectRole::BlockHashes => {
            format!("block-hash segment digests ({algorithm})")
        }
        _ => {
            // Outside the logical case the role is the useful discriminator,
            // and there are few enough of these that one line each is right.
            format!("{} ({algorithm}, {})", check.role, check.predicate)
        }
    }
}

/// Write the per-file digest table to `path` as TSV.
///
/// Folders are excluded: a folder has no content, so it has nothing to hash
/// and would contribute a row of empty digest columns.
fn write_digest_table(path: &Path, report: &VerificationReport) -> std::io::Result<()> {
    #[allow(clippy::disallowed_methods)] // Creates a new file; never truncates.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut out = std::io::BufWriter::new(file);

    // Gather the per-file checks, keyed by subject, preserving first-seen
    // order so the table follows the report rather than a hash order.
    let mut order: Vec<&str> = Vec::new();
    let mut rows: std::collections::HashMap<&str, Vec<&HashCheck>> =
        std::collections::HashMap::new();
    let mut algorithms: Vec<String> = Vec::new();

    for check in &report.checks {
        if !is_file_digest(check) {
            continue;
        }
        let subject = check.subject.as_str();
        if !rows.contains_key(subject) {
            order.push(subject);
        }
        rows.entry(subject).or_default().push(check);
        let algorithm = check.algorithm.to_string();
        if !algorithms.contains(&algorithm) {
            algorithms.push(algorithm);
        }
    }

    // The volume ARN is the prefix every path shares. Stated once here so the
    // rows can carry the part that distinguishes them.
    let prefix = common_volume_prefix(&order);
    if let Some(prefix) = prefix.as_deref() {
        writeln!(out, "# volume\t{prefix}")?;
    }

    write!(out, "path\tsize\toutcome")?;
    for algorithm in &algorithms {
        write!(
            out,
            "\t{algorithm}_recorded\t{algorithm}_computed\t{algorithm}_outcome"
        )?;
    }
    writeln!(out)?;

    let sizes = image_sizes(report);

    for subject in order {
        let checks = &rows[subject];
        let path_text = prefix
            .as_deref()
            .and_then(|p| subject.strip_prefix(p))
            .unwrap_or(subject);
        write!(out, "{}\t", tsv_field(path_text))?;
        match sizes.get(subject) {
            Some(size) => write!(out, "{size}")?,
            None => write!(out, "")?,
        }
        write!(out, "\t{}", row_outcome(checks))?;

        for algorithm in &algorithms {
            let found = checks
                .iter()
                .find(|c| &c.algorithm.to_string() == algorithm);
            match found {
                Some(check) => write!(
                    out,
                    "\t{}\t{}\t{}",
                    check.expected,
                    check.actual,
                    outcome_word(&check.outcome)
                )?,
                // The container records no digest of this algorithm for this
                // file. Empty, not "MISSING": nothing was expected, so nothing
                // failed.
                None => write!(out, "\t\t\t")?,
            }
        }
        writeln!(out)?;
    }

    out.flush()
}

/// Whether a check is a digest over a file's own content.
///
/// Excludes folders, which have nothing to hash, and every digest that covers
/// a segment or a construction rather than the file's bytes.
fn is_file_digest(check: &HashCheck) -> bool {
    matches!(check.role, ObjectRole::FileImage)
        && matches!(
            check.coverage,
            Coverage::StoredStream | Coverage::WholeImage
        )
}

/// The row's single verdict, worst case first.
///
/// A row whose algorithms disagree is a mismatch, so that sorting or grepping
/// the column cannot hide a failure behind a sibling that matched.
fn row_outcome(checks: &[&HashCheck]) -> &'static str {
    if checks.iter().any(|c| c.outcome.is_mismatch()) {
        "MISMATCH"
    } else if checks
        .iter()
        .any(|c| matches!(c.outcome, Outcome::NotVerifiable { .. }))
    {
        "NOT_RECOMPUTED"
    } else {
        "MATCH"
    }
}

/// One outcome as a single stable token for a machine-read column.
fn outcome_word(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Match => "MATCH",
        Outcome::Mismatch => "MISMATCH",
        Outcome::NotVerifiable { .. } => "NOT_RECOMPUTED",
    }
}

/// The `aff4://<uuid>//` prefix shared by every subject, when there is one.
fn common_volume_prefix(subjects: &[&str]) -> Option<String> {
    let first = subjects.first()?;
    // The volume ARN ends at the `//` that separates it from the path.
    let end = first.find("//").and_then(|scheme| {
        first[scheme + 2..]
            .find("//")
            .map(|rest| scheme + 2 + rest + 2)
    })?;
    let prefix = &first[..end];
    subjects
        .iter()
        .all(|s| s.starts_with(prefix))
        .then(|| prefix.to_string())
}

/// Each image's size in bytes, from the read accounting.
fn image_sizes(report: &VerificationReport) -> std::collections::HashMap<&str, u64> {
    report
        .read_accounting
        .iter()
        .map(|entry| {
            (
                entry.image.as_str(),
                entry.accounting.stored + entry.accounting.described,
            )
        })
        .collect()
}

/// Escape a value for a TSV cell.
///
/// A path may legitimately contain a tab or a newline; either would otherwise
/// break the row into columns or rows that were never intended. Escaped rather
/// than quoted, so the column count is fixed whatever a filename contains.
fn tsv_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// Write one check, with every digest at full length.
///
/// `verbose` prints a match as both values rather than one. They are equal by
/// definition, so the second line adds no information — but it shows the
/// comparison was made against a value that was actually computed, which is
/// the claim a match is making.
fn write_check(out: &mut impl Write, check: &HashCheck, verbose: bool) -> std::io::Result<()> {
    /// Column the outcome starts in, wide enough for the longest algorithm
    /// name so every outcome in a run lines up.
    const ALGORITHM_WIDTH: usize = 8;

    writeln!(out)?;
    writeln!(out, "  {} ({})", check.subject, check.role)?;

    // What the digest covers, kept only where it is not the obvious thing: a
    // predicate other than the plain `hash`, or a coverage other than the
    // object's own bytes, is what an examiner needs told. Repeating it for
    // every ordinary file hash pushed the digest itself onto a third line.
    let detail = check.coverage.describe();
    if check.predicate != "hash" {
        writeln!(out, "    {} over {detail}", check.predicate)?;
    }

    let algorithm = check.algorithm.to_string();
    match &check.outcome {
        Outcome::Match if verbose && check.digests_covered.is_some() => {
            writeln!(out, "  {algorithm:<ALGORITHM_WIDTH$}MATCH")?;
            writeln!(
                out,
                "      verified {} per-chunk digests, all recomputed and compared",
                thousands(check.digests_covered.unwrap_or(0))
            )?;
            writeln!(out, "      recorded: {}", check.expected)?;
            writeln!(out, "      computed: {}", check.actual)?;
        }
        Outcome::Match if verbose => {
            writeln!(out, "  {algorithm:<ALGORITHM_WIDTH$}MATCH")?;
            writeln!(out, "      recorded: {}", check.expected)?;
            writeln!(out, "      computed: {}", check.actual)?;
        }
        // A check covering many digests states what was done to them. Printing
        // the bare count ("489440 chunk digests") left it ambiguous whether
        // every one was compared or the number was merely read from the
        // segment; every one is compared.
        Outcome::Match if check.digests_covered.is_some() => {
            writeln!(out, "  {algorithm:<ALGORITHM_WIDTH$}MATCH")?;
            writeln!(
                out,
                "      verified {} per-chunk digests, all recomputed and compared",
                thousands(check.digests_covered.unwrap_or(0))
            )?;
        }
        Outcome::Match => {
            writeln!(
                out,
                "  {algorithm:<ALGORITHM_WIDTH$}MATCH: {}",
                check.expected
            )?;
        }
        Outcome::Mismatch => {
            writeln!(out, "  {algorithm:<ALGORITHM_WIDTH$}MISMATCH")?;
            writeln!(out, "      recorded: {}", check.expected)?;
            writeln!(out, "      computed: {}", check.actual)?;
        }
        // Both causes print the same way: the reason already says which it is,
        // and the examiner needs the reason, not a taxonomy label.
        Outcome::NotVerifiable { reason, .. } => {
            writeln!(
                out,
                "  {algorithm:<ALGORITHM_WIDTH$}NOT RECOMPUTED: {reason}"
            )?;
            writeln!(out, "      recorded: {}", check.expected)?;
        }
    }

    Ok(())
}

/// summarize each path, returning the most severe exit code encountered.
/// Objects above which the text report degrades to the brief summary.
///
/// A per-object listing of a million-object AFF4-L container is neither
/// readable on a terminal nor cheap: holding every object costs ~2.8 GB at a
/// million and ~28 GB at ten million, against ~1.0 GB for the brief summary,
/// which retains only what it prints.
///
/// 2,000 is set well above every reference container — the largest describes
/// 439 objects — so no canonical container's output changes, and well below
/// the point where a listing stops being readable.
///
/// `--full-listing <PATH>` writes the complete listing to a file regardless.
/// The one place the threshold's digits are written.
///
/// `--full-listing`'s help text has to embed the number as a literal, because
/// clap's derive takes a `&'static str` and `concat!` cannot stringify a
/// `usize` constant. Expanding the same macro in both places keeps the figure
/// the help promises identical to the figure the code enforces;
/// `the_help_states_the_real_threshold` in `tests/cli.rs` asserts it.
macro_rules! large_listing_threshold {
    () => {
        "2000"
    };
}
use large_listing_threshold;

const LARGE_LISTING_THRESHOLD: usize = {
    // Parse the macro's own digits, so the constant cannot disagree with the
    // help text even if someone edits only one of them.
    let digits = large_listing_threshold!().as_bytes();
    let mut value = 0usize;
    let mut i = 0;
    while i < digits.len() {
        value = value * 10 + (digits[i] - b'0') as usize;
        i += 1;
    }
    value
};

// The digits the operator reads and the number the code enforces are the same
// value, checked when the crate compiles rather than only when tests run.
const _: () = assert!(LARGE_LISTING_THRESHOLD == 2_000);

/// Write the complete per-object listing to `path`.
///
/// Created, never overwritten. An existing path is an error for the same reason
/// the acquisition log uses `create_new`: silently replacing a previous
/// listing would destroy a record the examiner may still need, and this is the
/// only file `info` writes.
///
/// The listing is the same text report the terminal would show below the
/// threshold — not a reduced form — so the file and a small container's stdout
/// are the same artifact.
/// Summarize, choosing between the full and brief object lists by size.
///
/// Returns the summary the report will render from. Three cases decide it:
///
/// - **`--format json` or `--full-listing`** — the full list is serialized or
///   written, so it must be built whatever the size.
/// - **`--brief`** — only the brief subset is ever rendered.
/// - **plain text** — the listing degrades above [`LARGE_LISTING_THRESHOLD`],
///   so the brief pass runs first and the full summary is built only if the
///   container turns out to be small.
///
/// The size probe is the brief pass itself rather than a separate count, so a
/// small container is parsed twice and a large one exactly once. Parsing twice
/// costs ~0.1 s on the reference corpus; building a million objects nobody
/// renders costs ~1.75 GB.
fn summarize_sized(
    paths: &[PathBuf],
    brief: bool,
    format: Format,
    full_listing: bool,
) -> std::result::Result<ContainerSummary, OpenError> {
    if matches!(format, Format::Json) || full_listing {
        return summarize_for(paths, false);
    }
    let probe = summarize_for(paths, true)?;
    if brief || probe.counts.total > LARGE_LISTING_THRESHOLD {
        return Ok(probe);
    }
    drop(probe);
    summarize_for(paths, false)
}

fn write_full_listing(
    path: &Path,
    summary: &ContainerSummary,
    filter: ObjectFilter,
) -> std::io::Result<()> {
    #[allow(clippy::disallowed_methods)] // Creates a new file; never truncates.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut out = std::io::BufWriter::new(file);
    report::write_text(&mut out, summary, filter, false)?;
    out.flush()
}

fn run_info(
    sets: &[Vec<PathBuf>],
    format: Format,
    strict: bool,
    filter: ObjectFilter,
    brief: bool,
    full_listing: Option<&Path>,
) -> ExitCode {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut worst = 0u8;
    let mut summaries = Vec::new();
    let mut errors = Vec::new();

    for (index, set) in sets.iter().enumerate() {
        // Whether the full object list is needed at all. `--format json`
        // serializes it, `--full-listing` writes it, and the text listing needs
        // it below the threshold — but above the threshold nothing renders it,
        // so building it would cost ~2.8 GB at a million objects to produce a
        // list that is then discarded.
        //
        // The count is not known before parsing, so `summarize_probe` streams
        // once retaining only the brief subset, and the full summary is built
        // only if that count turns out to be small. The re-parse costs a second
        // pass on containers under the threshold, where a pass is ~0.1 s.
        match summarize_sized(set, brief, format, full_listing.is_some()) {
            Ok(mut summary) => {
                if strict && summary.has_noteworthy_deviation() {
                    // Deviations are always reported; --strict makes them count.
                    // Routine ones are excluded: a lone stripe always carries an
                    // ExternalReference, and failing on that made the exit code
                    // fire on well-formed containers while staying silent about
                    // real faults. See DeviationKind::is_routine.
                    worst = worst.max(EXIT_STRICT_DEVIATION);
                }
                match format {
                    Format::Text => {
                        if index > 0 {
                            let _ = writeln!(out);
                        }
                        // Above the threshold the listing is not printed to the
                        // terminal. `--full-listing` is the way to get it, and
                        // the notice names the flag rather than leaving the
                        // reader to discover that objects were omitted.
                        let degraded = !brief && summary.counts.total > LARGE_LISTING_THRESHOLD;
                        let _ = report::write_text(&mut out, &summary, filter, brief || degraded);
                        if degraded {
                            let _ = writeln!(out);
                            let _ = writeln!(
                                out,
                                "This container describes {} objects, so the \
                                 per-object listing is not shown here.",
                                summary.counts.total
                            );
                            let _ = writeln!(
                                out,
                                "Run with --full-listing <PATH> to write it to a file."
                            );
                        }
                        if let Some(path) = full_listing {
                            match write_full_listing(path, &summary, filter) {
                                Ok(()) => {
                                    let _ = writeln!(out);
                                    let _ =
                                        writeln!(out, "Full listing written to {}", path.display());
                                }
                                Err(e) => {
                                    let _ = writeln!(
                                        std::io::stderr(),
                                        "aff4tools: writing {}: {e}",
                                        path.display()
                                    );
                                    worst = worst.max(EXIT_LISTING_IO);
                                }
                            }
                        }
                    }
                    Format::Json => {
                        // `--objects` is honored under `--format
                        // json` too, filtering `objects` the same way text
                        // does. The rest of the summary (segments,
                        // deviations, manifest, ...) is untouched.
                        summary.objects.retain(|o| filter.admits(o));
                        summaries.push(summary);
                    }
                }
            }
            Err(error) => match format {
                Format::Text => worst = worst.max(error.report()),
                Format::Json => {
                    let (entry, code) = error.as_json_entry(&set[0]);
                    worst = worst.max(code);
                    errors.push(entry);
                }
            },
        }
    }

    if format == Format::Json {
        // Always an envelope object, for one input or several: a bare array
        // cannot distinguish "no containers matched" from "every container
        // failed", and collapsing to a single bare object for exactly one
        // input meant a script had to branch on argument count to find its
        // own data. `containers` and `errors` are each always present, so
        // `jq '.errors | length'` is the same query whether nothing, one
        // thing, or many things failed.
        let report = InfoJsonReport {
            containers: summaries,
            errors,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                let _ = writeln!(out, "{text}");
            }
            Err(e) => {
                eprintln!("error: cannot render JSON: {e}");
                worst = worst.max(EXIT_USAGE);
            }
        }
    }

    ExitCode::from(worst)
}

/// How an acquisition should chunk, compress, and check itself.
#[derive(Debug, Clone, Copy)]
struct AcquireOptions {
    compression: Compression,
    chunk_size: usize,
    chunks_per_bevy: usize,
    /// Whether to recompute the recorded digests from the written container.
    verify_written_container: bool,
    /// Whether a logical acquisition deduplicates content (AFF4-L 2019 §4).
    deduplicate: bool,
    /// When set, write the image across several parts, starting a new one once
    /// the current part reaches this many bytes on disk. Applies to the
    /// byte-stream sources, `--image` and `--device`; `--logical` is refused.
    split_after: Option<u64>,
    /// Whether a logical acquisition inventories the tree to completion before
    /// acquiring, so the progress total is exact from the start.
    scan_first: bool,
}

/// Whether a path names the first segment of a split-raw set, e.g. `img.001`.
///
/// Deliberately narrow: an existing regular file whose extension is entirely
/// digits. A file with no extension, a non-numeric one, or a folder is not a
/// segment, and neither is a path that does not exist — those fall through to
/// the ordinary single-file source path so their own errors are reported.
///
/// Any numeric suffix qualifies, not only `001`, so that naming a middle
/// segment is recognized as a split set and refused by `preceding_segment`
/// rather than quietly acquired as a lone file.
fn is_split_first_segment(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| !e.is_empty() && e.chars().all(|c| c.is_ascii_digit()))
}

/// The segment immediately before `path` in its split set, if it exists.
///
/// Used to reject a source that is not the set's first segment. Only the
/// immediate predecessor is checked: with it absent, `path` is the start of a
/// contiguous run, and any earlier segment beyond that hole is a gap, which
/// `discover_split` reports from the other side.
///
/// The suffix width is preserved, so `img.010` looks for `img.009` and never
/// `img.9`.
fn preceding_segment(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let (stem, suffix) = name.rsplit_once('.')?;
    let width = suffix.len();
    let number: u32 = suffix.parse().ok()?;
    let previous = number.checked_sub(1)?;
    let candidate = path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{stem}.{previous:0width$}"));
    candidate.is_file().then_some(candidate)
}

/// Re-image a source into a new AFF4 container, then prove it.
///
/// The proof is the point. Writing a container is easy; establishing that it
/// holds the source's bytes is what makes it evidence. Two checks run here:
/// unless declined, the digests recorded during acquisition are recomputed
/// from the written container, and the container is checked for conformance.
///
/// The source is never re-read. Its digests were taken from the bytes as they
/// streamed in, so recomputing them from the container is what proves the
/// container holds those bytes; reading a multi-terabyte source a second time
/// would add cost without adding proof.
fn run_acquire(
    images: &[PathBuf],
    logical: &[PathBuf],
    device: Option<&std::path::Path>,
    discover_split: bool,
    output: &std::path::Path,
    log_path: Option<&std::path::Path>,
    settings: AcquireOptions,
) -> ExitCode {
    let AcquireOptions {
        compression,
        chunk_size,
        chunks_per_bevy,
        verify_written_container,
        split_after,
        ..
    } = settings;
    use aff4tools::write::acquire::ImageSource;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::stream_writer::StreamOptions;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // Accepted so existing command lines keep working, but announced, because
    // a flag that silently does nothing is worse than one that says so.
    if discover_split {
        eprintln!(
            "warning: --discover-split is deprecated and has no effect; \
             --image <first segment> discovers the set on its own."
        );
    }

    if let Some(device) = device {
        return run_acquire_device(&mut out, device, output, log_path, settings);
    }

    if !logical.is_empty() {
        // An AFF4-L container is a set of files, not a byte stream, so parts
        // would divide at file boundaries rather than byte thresholds — a
        // different mechanism from the one `--image` and `--device` share. With
        // `--deduplicate` a pool spanning parts would let one part's files
        // depend on chunks stored in another, so no part would be independently
        // readable. Neither is specified.
        if settings.split_after.is_some() {
            eprintln!("error: --split-file is not yet supported for --logical acquisitions.");
            eprintln!(
                "       An AFF4-L container is a set of files rather than a byte stream, so \
                 parts would be divided at file boundaries. That division, and what a \
                 deduplication pool spanning parts would mean, are not specified."
            );
            return ExitCode::from(EXIT_USAGE);
        }
        return run_acquire_logical(&mut out, logical, output, log_path, settings);
    }

    if images.is_empty() {
        eprintln!("error: one of --image, --logical or --device is required");
        return ExitCode::from(EXIT_USAGE);
    }

    // Resolve the source set first, so a split-set gap fails before anything
    // is created.
    let paths: Vec<PathBuf> = if images.len() == 1 && is_split_first_segment(&images[0]) {
        // A first segment stands for its whole set, the same way a folder
        // does. Discovery runs unconditionally because a gap must be an error
        // even when the examiner did not know the source was split: acquiring
        // `name.001` alone, silently, is the data-loss this guards against.
        //
        // `discover_split` reads forward from the segment it is given, so a
        // segment with predecessors would acquire the tail of the set as if it
        // were the whole image — data loss that verifies clean, since the
        // digests would describe exactly the bytes that were read. Refuse.
        if let Some(earlier) = preceding_segment(&images[0]) {
            eprintln!(
                "error: {} is not the first segment of its split set; {} exists.",
                images[0].display(),
                earlier.display()
            );
            eprintln!(
                "       Acquiring from here would silently omit every earlier \
                 segment. Name the first segment, or its folder, instead."
            );
            return ExitCode::from(EXIT_USAGE);
        }
        match ImageSource::discover_split(&images[0]) {
            Ok(found) => {
                if found.len() > 1 {
                    let _ = writeln!(out, "Found {} split files.", found.len());
                }
                found
            }
            Err(e) => return ExitCode::from(report_error(&e)),
        }
    } else if images.len() == 1 && images[0].is_dir() {
        // One folder may stand for a whole split set, so an examiner need not
        // name every part. Ambiguous folders are refused rather than guessed at.
        match aff4tools::split_set::discover(&images[0]) {
            Ok(set) => {
                // Re-imaging an existing AFF4 set would hash the container
                // bytes rather than the image they carry, producing a digest
                // that does not describe the evidence. Refuse instead.
                if set.kind == aff4tools::split_set::SplitKind::Aff4 {
                    eprintln!(
                        "error: {} holds a set of AFF4 containers, and --image cannot \
                         tell a split set apart from a striped one by looking at the \
                         folder.",
                        images[0].display()
                    );
                    eprintln!(
                        "       Name the primary container directly to re-acquire it: \
                         --image <container.aff4>."
                    );
                    return ExitCode::from(EXIT_USAGE);
                }
                let _ = writeln!(out, "{}", set.discovery_line());
                set.parts
            }
            Err(e) => return ExitCode::from(report_error(&e)),
        }
    } else {
        images.to_vec()
    };

    let mut registry = SourceRegistry::new();

    // An AFF4 source is re-imaged through its map rather than read as a flat
    // file: reading the container's bytes would hash the ZIP, not the evidence
    // it carries. Detected by opening it, not by extension — a `.aff4` suffix
    // is a claim, and the ZIP signature is the fact.
    if paths.len() == 1 && aff4tools::write::aff4_source::looks_like_aff4(&paths[0]) {
        return run_acquire_from_aff4(
            &mut out,
            &paths[0],
            output,
            log_path,
            settings,
            &mut registry,
        );
    }

    let source = match ImageSource::open(&paths, &mut registry) {
        Ok(s) => s,
        Err(e) => return ExitCode::from(report_error(&e)),
    };

    // Re-imaging gets the same record as the other two modes. A split-raw set
    // can report per-segment problems, and the run is long enough that its
    // output scrolls away.
    let (log_path, log) = match setup_log(output, log_path) {
        Ok(pair) => pair,
        Err(code) => return ExitCode::from(code),
    };
    let mut out = Tee {
        out: &mut out,
        log: Some(log),
    };
    let out = &mut out;

    let _ = writeln!(out, "Source:      {} segment(s)", source.segments().len());
    for segment in source.segments() {
        let _ = writeln!(out, "             {}", segment.display());
    }
    let _ = writeln!(out, "Size:        {}", human_bytes(source.total_size()));
    let _ = writeln!(out, "Output:      {}", output.display());
    let _ = writeln!(out, "Log:         {}", log_path.display());

    let options = StreamOptions {
        chunk_size,
        chunks_per_segment: chunks_per_bevy,
        codec: compression.into(),
        block_hashes: true,
    };
    let _ = writeln!(
        out,
        "Compression: {} ({} byte chunks, {} per bevy)",
        options.codec.name(),
        chunk_size,
        chunks_per_bevy
    );
    let _ = writeln!(out);

    let locus = aff4tools::Locus::new(output);

    let mut reader = match source.reader() {
        Ok(r) => r,
        Err(e) => return ExitCode::from(report_error(&e)),
    };

    // SHA-256 and MD5: two default hash algorithms.
    let algorithms = [
        aff4tools::HashAlgorithm::Sha256,
        aff4tools::HashAlgorithm::Md5,
    ];

    if let Some(split_after) = split_after {
        // `--image` behavior is unchanged: a write failure and a verification
        // floor both become the same exit code, exactly as before this
        // function distinguished them for `--device`.
        let code = match run_acquire_split(
            out,
            output,
            &mut reader,
            source.total_size(),
            aff4tools::write::split_writer::SplitOptions {
                stream: options,
                split_after,
            },
            &algorithms,
            &registry,
            None,
        ) {
            // `run_acquire_split` has already stamped `Acquisition Complete:`;
            // this closes the run.
            Ok(code) => {
                stamp_completed(out);
                code
            }
            // A write failure means the evidence is incomplete, so no
            // completion line is written: `report_error` has said what failed.
            Err(code) => code,
        };
        return ExitCode::from(code);
    }

    let mut writer = match ContainerWriter::create(output, &registry) {
        Ok(w) => w,
        Err(e) => return ExitCode::from(report_error(&e)),
    };
    let volume_arn = writer.volume_arn().as_str().to_owned();
    // Re-imaging a multi-terabyte source is as long a wait as a device, so it
    // gets the same progress line.
    let mut painter =
        painter::ProgressPainter::new(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    let mut reporter = aff4tools::progress::BlockProgress::new(source.total_size());
    let stream_arn = format!("{volume_arn}/data");
    let written = match aff4tools::write::stream_writer::write_image_stream_observed(
        &mut writer,
        &stream_arn,
        &mut reader,
        options,
        &algorithms,
        &mut |done, bevies| {
            reporter.update(done, bevies);
            if painter.would_paint() {
                let line =
                    aff4tools::progress::AcquisitionProgress::line(&reporter, painter.elapsed());
                painter.paint(&line);
            }
        },
        &locus,
    ) {
        Ok(w) => w,
        Err(e) => {
            painter.finish();
            return ExitCode::from(report_error(&e));
        }
    };
    painter.finish();
    // A stream alone is a bytestream; what makes the container an image is a
    // Map plus a DiskImage naming it. Without these, pyaff4's `images()` finds
    // nothing in our containers.
    let entries = [aff4tools::write::map_writer::MapEntry {
        mapped_offset: 0,
        length: written.size,
        target_offset: 0,
        target_id: 0,
    }];
    let mapped = match aff4tools::write::map_writer::write_map(
        &mut writer,
        &entries,
        std::slice::from_ref(&written.arn),
        written.size,
        &locus,
    ) {
        Ok(m) => m,
        Err(e) => return ExitCode::from(report_error(&e)),
    };

    if let Err(e) = writer.finish() {
        return ExitCode::from(report_error(&e));
    }

    let _ = writeln!(out, "Volume ARN:  {volume_arn}");
    let _ = writeln!(out, "Image:       {}", mapped.image_arn);
    let _ = writeln!(out, "Stream:      {}", written.arn);
    let _ = writeln!(
        out,
        "Written:     {} in {} bevies",
        human_bytes(written.size),
        written.bevy_count
    );
    write_acquired_digests(out, &written);

    // The same split the device log draws: reading the source is done, and
    // what follows is checking what was written.
    stamp_acquisition_complete(out);

    // Check 1: recompute from the container we just wrote.
    let _ = writeln!(out);
    let mut worst = verify_after_acquire(out, output, written.size, verify_written_container);

    // Check 2: conformance.
    match summarize(std::slice::from_ref(&output.to_path_buf())) {
        Ok(summary) => {
            if summary.deviations.is_empty() {
                // Named from the container's own generation, not a constant:
                // what aff4tools wrote decides which document governs it.
                let (spec, _) = summary.generation.governing_spec();
                let _ = writeln!(out, "Conformance: no deviations from {spec}");
            } else {
                let _ = writeln!(
                    out,
                    "Conformance: {} deviation(s) — run `aff4tools conformance`",
                    summary.deviations.len()
                );
                worst = worst.max(EXIT_STRICT_DEVIATION);
            }
        }
        Err(e) => {
            let _ = writeln!(out, "Conformance: could not summarize the container");
            let _ = e;
        }
    }

    stamp_completed(out);

    ExitCode::from(worst)
}

/// The caller's reporting hook, run after a split set is written.
///
/// See `run_acquire_split` for what it receives and what its return value means.
type AcquireReporter<'a> = &'a mut dyn FnMut(&mut dyn Write, &[PathBuf]) -> u8;

/// Write an acquisition across several `.aff4` parts, then let the caller
/// append its own reporting.
///
/// The single-file path writes `--output` itself; this one never does. `output`
/// is a base name from which part names are derived — `evidence.aff4` yields
/// `evidence_001.aff4`, `evidence_002.aff4`, and so on — so an existing
/// `evidence.aff4` is not a collision, while an existing `evidence_001.aff4`
/// is, and `WriteSink::create` refuses it naming the part rather than the base.
///
/// `after` runs once the set is written and its summary printed. It returns an
/// exit-code floor, which is how a device acquisition reports unreadable
/// Re-acquire an existing AFF4 container into a new one.
///
/// The source is read
/// through its Map with `Image::read_at`, not as a flat file, so the bytes fed
/// to the writer are the *image* the container carries rather than the ZIP that
/// carries it. Everything downstream — stream writer, map, digests,
/// verification, conformance — is the same path `--image` already uses.
///
/// A striped source is not yet accepted here: naming the siblings needs a flag,
/// and picking them up implicitly would risk acquiring a partial image while
/// reporting success.
// Mirrors run_acquire's own argument list; each is used independently.
#[allow(clippy::too_many_arguments)]
fn run_acquire_from_aff4(
    out: &mut impl Write,
    source_path: &std::path::Path,
    output: &std::path::Path,
    log_path: Option<&std::path::Path>,
    settings: AcquireOptions,
    registry: &mut aff4tools::write::guard::SourceRegistry,
) -> ExitCode {
    use aff4tools::write::aff4_source::Aff4Source;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::stream_writer::StreamOptions;

    let AcquireOptions {
        compression,
        chunk_size,
        chunks_per_bevy,
        verify_written_container,
        split_after,
        ..
    } = settings;

    let mut source = match Aff4Source::open(source_path, &[], registry) {
        Ok(s) => s,
        // A container holding no DiskImage is not damaged evidence — an AFF4-L
        // is perfectly well-formed, it simply is not a disk image. Reporting it
        // as malformed would tell an examiner their evidence is broken when the
        // command was merely the wrong one, so this is a usage error.
        Err(aff4tools::Error::Malformed { detail, .. }) if detail.contains("aff4:DiskImage") => {
            eprintln!("error: {} stores no disk image.", source_path.display());
            eprintln!("       {detail}");
            return ExitCode::from(EXIT_USAGE);
        }
        Err(e) => return ExitCode::from(report_error(&e)),
    };
    let total_size = source.total_size();
    let source_arn = source.arn().as_str().to_owned();

    let (log_path, log) = match setup_log(output, log_path) {
        Ok(pair) => pair,
        Err(code) => return ExitCode::from(code),
    };
    let mut out = Tee {
        out,
        log: Some(log),
    };
    let out = &mut out;

    let _ = writeln!(out, "Source:      {}", source_path.display());
    let _ = writeln!(out, "Source image: {source_arn}");
    let _ = writeln!(out, "Size:        {}", human_bytes(total_size));
    let _ = writeln!(out, "Output:      {}", output.display());
    let _ = writeln!(out, "Log:         {}", log_path.display());

    let options = StreamOptions {
        chunk_size,
        chunks_per_segment: chunks_per_bevy,
        codec: compression.into(),
        block_hashes: true,
    };
    let _ = writeln!(
        out,
        "Compression: {} ({} byte chunks, {} per bevy)",
        options.codec.name(),
        chunk_size,
        chunks_per_bevy
    );
    let _ = writeln!(out);

    let locus = aff4tools::Locus::new(output);
    let algorithms = [
        aff4tools::HashAlgorithm::Sha256,
        aff4tools::HashAlgorithm::Md5,
    ];

    let mut reader = source.reader();

    if let Some(split_after) = split_after {
        let code = match run_acquire_split(
            out,
            output,
            &mut reader,
            total_size,
            aff4tools::write::split_writer::SplitOptions {
                stream: options,
                split_after,
            },
            &algorithms,
            registry,
            None,
        ) {
            // `run_acquire_split` has already stamped `Acquisition Complete:`;
            // this closes the run. A write failure gets no completion line.
            Ok(code) => {
                stamp_completed(out);
                code
            }
            Err(code) => code,
        };
        return ExitCode::from(code);
    }

    let mut writer = match ContainerWriter::create(output, registry) {
        Ok(w) => w,
        Err(e) => return ExitCode::from(report_error(&e)),
    };
    let volume_arn = writer.volume_arn().as_str().to_owned();
    let mut painter =
        painter::ProgressPainter::new(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    let mut reporter = aff4tools::progress::BlockProgress::new(total_size);
    let stream_arn = format!("{volume_arn}/data");
    let written = match aff4tools::write::stream_writer::write_image_stream_observed(
        &mut writer,
        &stream_arn,
        &mut reader,
        options,
        &algorithms,
        &mut |done, bevies| {
            reporter.update(done, bevies);
            if painter.would_paint() {
                let line =
                    aff4tools::progress::AcquisitionProgress::line(&reporter, painter.elapsed());
                painter.paint(&line);
            }
        },
        &locus,
    ) {
        Ok(w) => w,
        Err(e) => {
            painter.finish();
            return ExitCode::from(report_error(&e));
        }
    };
    painter.finish();
    drop(reader);

    let entries = [aff4tools::write::map_writer::MapEntry {
        mapped_offset: 0,
        length: written.size,
        target_offset: 0,
        target_id: 0,
    }];
    let mapped = match aff4tools::write::map_writer::write_map(
        &mut writer,
        &entries,
        std::slice::from_ref(&written.arn),
        written.size,
        &locus,
    ) {
        Ok(m) => m,
        Err(e) => return ExitCode::from(report_error(&e)),
    };

    if let Err(e) = writer.finish() {
        return ExitCode::from(report_error(&e));
    }

    let _ = writeln!(out, "Volume ARN:  {volume_arn}");
    let _ = writeln!(out, "Image:       {}", mapped.image_arn);
    let _ = writeln!(out, "Stream:      {}", written.arn);
    let _ = writeln!(
        out,
        "Written:     {} in {} bevies",
        human_bytes(written.size),
        written.bevy_count
    );
    write_acquired_digests(out, &written);
    stamp_acquisition_complete(out);

    let _ = writeln!(out);
    let mut worst = verify_after_acquire(out, output, written.size, verify_written_container);

    match summarize(std::slice::from_ref(&output.to_path_buf())) {
        Ok(summary) => {
            if summary.deviations.is_empty() {
                // Named from the container's own generation, not a constant:
                // what aff4tools wrote decides which document governs it.
                let (spec, _) = summary.generation.governing_spec();
                let _ = writeln!(out, "Conformance: no deviations from {spec}");
            } else {
                let _ = writeln!(
                    out,
                    "Conformance: {} deviation(s) — run `aff4tools conformance`",
                    summary.deviations.len()
                );
                worst = worst.max(EXIT_STRICT_DEVIATION);
            }
        }
        Err(e) => {
            let _ = writeln!(out, "Conformance: could not summarize the container");
            let _ = e;
        }
    }

    stamp_completed(out);

    ExitCode::from(worst)
}

/// sectors: `run_acquire_split` cannot know about them, and returning a bare 0
/// would discard the finding.
///
/// The `Result` distinguishes a write failure from a verification finding:
/// `Err(code)` means the write itself failed (`code` is the library error,
/// 3..=6) and nothing after it — including the completion transcript — should
/// print. `Ok(floor)` means the set was written and `floor` is any exit-code
/// floor contributed by the `after` verification hook.
// The argument list mirrors what `write_split_set` itself needs (output,
// reader, size, options, algorithms, registry) plus the caller's `after`
// reporting hook; each is used independently and splitting them into a
// struct would not make a call site clearer.
#[allow(clippy::too_many_arguments)]
fn run_acquire_split(
    out: &mut impl Write,
    output: &std::path::Path,
    reader: &mut dyn std::io::Read,
    source_size: u64,
    options: aff4tools::write::split_writer::SplitOptions,
    algorithms: &[aff4tools::HashAlgorithm],
    registry: &aff4tools::write::guard::SourceRegistry,
    after: Option<AcquireReporter<'_>>,
) -> Result<u8, u8> {
    let locus = aff4tools::Locus::new(output);

    // Fail before a single part is created if the source cannot fit within the
    // part-number limit, so the refusal costs nothing.
    if let Err(e) =
        aff4tools::write::split_writer::preflight(source_size, options.split_after, &locus)
    {
        return Err(report_error(&e));
    }

    let mut painter =
        painter::ProgressPainter::new(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    let mut reporter = aff4tools::progress::BlockProgress::new(source_size);
    // Progress from `write_split_set` is already cumulative across parts, so it
    // passes straight through.
    let set = match aff4tools::write::split_writer::write_split_set(
        output,
        reader,
        source_size,
        options,
        algorithms,
        registry,
        &mut |done, bevies| {
            reporter.update(done, bevies);
            if painter.would_paint() {
                let line =
                    aff4tools::progress::AcquisitionProgress::line(&reporter, painter.elapsed());
                painter.paint(&line);
            }
        },
        &locus,
    ) {
        Ok(set) => set,
        Err(e) => {
            painter.finish();
            return Err(report_error(&e));
        }
    };
    painter.finish();

    // The range end is the LAST part's number, read back from the name that was
    // actually written rather than assumed equal to the count.
    let last = set
        .parts
        .last()
        .and_then(|p| p.path.file_name())
        .and_then(|n| n.to_str())
        .and_then(aff4tools::split_set::part_number);
    match last {
        Some(last) => {
            let _ = writeln!(
                out,
                "Wrote {} split file(s), numbered 001 through {last:03}.",
                set.parts.len()
            );
        }
        None => {
            let _ = writeln!(out, "Wrote {} split file(s).", set.parts.len());
        }
    }
    let _ = writeln!(out, "Image:       {}", set.image_arn);
    let _ = writeln!(out, "Map:         {}", set.map_arn);
    for part in &set.parts {
        let _ = writeln!(
            out,
            "  {}  {} in {} bevies",
            part.path.display(),
            human_bytes(part.size),
            part.bevy_count
        );
    }
    let _ = writeln!(out, "Written:     {} total", human_bytes(set.total_size));
    for digest in &set.digests {
        let _ = writeln!(out, "  {}: {}", digest.algorithm(), digest.hex());
    }

    // Stamped before the `after` hook runs, because that hook verifies the
    // container and verification is not acquisition. Reading the source is
    // finished at this point: every part has been written and closed. Stamping
    // it afterward folded the verification pass into the acquisition, so a
    // 14.9 GiB device whose parts were written by 23:46 reported an
    // "Acquisition Complete" of 23:48 — the re-read time charged to the medium.
    stamp_acquisition_complete(out);

    let mut worst = 0u8;
    if let Some(after) = after {
        let paths: Vec<PathBuf> = set.parts.iter().map(|p| p.path.clone()).collect();
        worst = worst.max(after(out, &paths));
    }

    Ok(worst)
}

/// Acquire files and folders as an AFF4-L logical image.
///
/// Follows Schatz (2019) rather than pyaff4's behaviour where the two differ.
/// Notably it writes the AFF4-L 2019 §3.6 enumeration model, so a consumer can
/// identify the acquisition roots and walk the tree, which no existing AFF4-L
/// container supports.
fn run_acquire_logical(
    out: &mut impl Write,
    roots: &[PathBuf],
    output: &std::path::Path,
    log_path: Option<&std::path::Path>,
    settings: AcquireOptions,
) -> ExitCode {
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::logical::{LogicalOptions, acquire_logical_scanned};
    use aff4tools::write::stream_writer::StreamOptions;

    // A large acquisition reports thousands of skipped paths, which scroll past
    // and are lost. The log is the record an examiner keeps.
    let (log_path, log) = match setup_log(output, log_path) {
        Ok(pair) => pair,
        Err(code) => return ExitCode::from(code),
    };
    let mut out = Tee {
        out,
        log: Some(log),
    };
    let out = &mut out;

    let mut registry = SourceRegistry::new();
    for root in roots {
        if !root.exists() {
            let _ = writeln!(out, "error: {} does not exist", root.display());
            eprintln!("error: {} does not exist", root.display());
            return ExitCode::from(3);
        }
        if let Err(e) = registry.register(root) {
            let _ = writeln!(out, "error: cannot open {}: {e}", root.display());
            eprintln!("error: cannot open {}: {e}", root.display());
            return ExitCode::from(3);
        }
    }

    let AcquireOptions {
        compression,
        chunk_size,
        chunks_per_bevy,
        deduplicate,
        verify_written_container,
        // `run_acquire` refuses `--split-file` alongside `--logical` with a
        // worded error, so it never reaches here.
        split_after: _,
        scan_first,
    } = settings;
    let options = LogicalOptions {
        stream: StreamOptions {
            chunk_size,
            chunks_per_segment: chunks_per_bevy,
            codec: compression.into(),
            block_hashes: true,
        },
        deduplicate,
    };

    let _ = writeln!(out, "Acquiring:   {} root(s)", roots.len());
    for root in roots {
        let _ = writeln!(out, "             {}", root.display());
    }
    let _ = writeln!(out, "Output:      {}", output.display());
    let _ = writeln!(out, "Log:         {}", log_path.display());
    let _ = writeln!(
        out,
        "Large files: ImageStream above {} ({} chunks, {} per bevy){}",
        human_bytes(aff4tools::write::logical::MAX_SEGMENT_RESIDENT_SIZE),
        chunk_size,
        chunks_per_bevy,
        if deduplicate { ", deduplicated" } else { "" }
    );
    let _ = writeln!(out);

    // `--scan-first` inventories the tree to completion before the container
    // is even created: an examiner who chose it wants the exact total from the
    // very first paint, not one that firms up as writing proceeds.
    let prescan = if scan_first {
        let scanner = aff4tools::write::scan::spawn(
            roots.to_vec(),
            aff4tools::write::scan::SCAN_QUEUE_CAPACITY,
        );
        let totals = std::sync::Arc::clone(&scanner.totals);
        let items: Vec<_> = scanner.items.iter().collect();
        scanner.join();
        let (files, cost, _) = totals.snapshot();
        // `cost` is a work-estimate the progress display uses internally (see
        // `cost_of` in `src/write/scan.rs`) — it adds a synthetic per-file
        // overhead and is not a byte count. Rendering it with `human_bytes`
        // would put an estimated total in the acquisition log, which the plan
        // forbids outright; the file count is the one fact from the scan
        // worth recording here.
        let _ = writeln!(out, "Scanned:     {} file(s)", files);
        let _ = writeln!(out);
        Some((items, files, cost))
    } else {
        None
    };

    let locus = aff4tools::Locus::new(output);
    let mut writer = match ContainerWriter::create_logical(output, &registry) {
        Ok(w) => w,
        Err(e) => return ExitCode::from(report_error(&e)),
    };
    let volume_arn = writer.volume_arn().as_str().to_owned();

    // Progress goes to stderr, and only to a terminal: the report above and
    // below is on stdout, and redirecting it must not capture carriage returns.
    let mut painter =
        painter::ProgressPainter::new(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    let mut progress = aff4tools::progress::LogicalProgress::new();
    let mut scan_was_complete = false;

    let acquired = if let Some((items, files, cost)) = prescan {
        // The total is exact and known before acquisition starts, so it is set
        // once, up front, and never revised.
        progress.set_estimate(files, cost, true);
        match aff4tools::write::logical::acquire_logical_prescanned(
            &mut writer,
            items,
            options,
            &locus,
            &mut |acq| {
                progress.update(acq.files, acq.bytes);
                progress.observe_cost(acq.bytes);
                progress.calibrate(acq.files, acq.bytes, painter.elapsed());
                if painter.would_paint() {
                    let line = aff4tools::progress::AcquisitionProgress::line(
                        &progress,
                        painter.elapsed(),
                    );
                    painter.paint(&line);
                }
            },
        ) {
            Ok(a) => a,
            Err(e) => {
                painter.finish();
                return ExitCode::from(report_error(&e));
            }
        }
    } else {
        match acquire_logical_scanned(&mut writer, roots, options, &locus, &mut |acq, totals| {
            progress.update(acq.files, acq.bytes);
            // `None` means the scanner failed and the denominator is
            // short, so the estimate is left untouched and the line stays
            // on its liveness form rather than reporting a percentage
            // that cannot be trusted.
            if let Some((files, cost, complete)) = totals {
                progress.set_estimate(files, cost, complete);
                progress.observe_cost(acq.bytes);
            }
            progress.calibrate(acq.files, acq.bytes, painter.elapsed());
            // The scan completing switches the display from liveness to a
            // percentage. That is worth showing at once rather than at
            // the next tick of the throttle.
            let just_completed = progress.scan_complete() && !scan_was_complete;
            scan_was_complete = progress.scan_complete();
            if just_completed || painter.would_paint() {
                let line =
                    aff4tools::progress::AcquisitionProgress::line(&progress, painter.elapsed());
                if just_completed {
                    painter.paint_now(&line);
                } else {
                    painter.paint(&line);
                }
            }
        }) {
            Ok(a) => a,
            Err(e) => {
                painter.finish();
                return ExitCode::from(report_error(&e));
            }
        }
    };
    painter.finish();
    if let Err(e) = writer.finish() {
        return ExitCode::from(report_error(&e));
    }

    let _ = writeln!(out, "Volume ARN:  {volume_arn}");
    let _ = writeln!(
        out,
        "Acquired:    {} file(s), {} folder(s), {}",
        acquired.files,
        acquired.folders,
        human_bytes(acquired.bytes)
    );
    if let Some(dedupe) = acquired.dedupe {
        let _ = writeln!(
            out,
            "Deduplicated: {} unique chunk(s), {} stored, {} not stored again",
            dedupe.unique_chunks,
            human_bytes(dedupe.stored),
            human_bytes(dedupe.saved())
        );
    }

    let mut worst = 0u8;
    // Skipped paths are a finding about the acquisition's completeness and are
    // listed in full, never summarized to a count.
    if !acquired.skipped.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "SKIPPED:     {} path(s) were NOT acquired",
            acquired.skipped.len()
        );
        for (path, reason) in &acquired.skipped {
            let _ = writeln!(out, "  {}: {reason}", path.display());
        }
        worst = worst.max(EXIT_STRICT_DEVIATION);
    }

    // Reported apart from SKIPPED, and never merged into it: these files were
    // acquired. The container holds them at their true length, with digests
    // over the bytes actually stored. What the examiner needs to know is that
    // the source changed while it was being read — which is a fact about the
    // evidence, not about the acquisition's completeness.
    if !acquired.changed.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "CHANGED:     {} path(s) changed while being read; each was \
             acquired and recorded at its actual length",
            acquired.changed.len()
        );
        for (path, expected, actual) in &acquired.changed {
            let _ = writeln!(
                out,
                "  {}: {expected} bytes expected, {actual} read",
                path.display()
            );
        }
        worst = worst.max(EXIT_STRICT_DEVIATION);
    }

    // The same split the other modes draw: every file has been read and
    // written, and what follows checks the container rather than the source.
    stamp_acquisition_complete(out);

    // Check 1: recompute from the container we just wrote. A logical
    // acquisition is evidence like any other, so it is verified like any
    // other.
    let _ = writeln!(out);
    worst = worst.max(verify_after_acquire(
        out,
        output,
        acquired.bytes,
        verify_written_container,
    ));

    // Check 2: conformance.
    match summarize(std::slice::from_ref(&output.to_path_buf())) {
        Ok(summary) => {
            if summary.deviations.is_empty() {
                // Named from the container's own generation, not a constant:
                // what aff4tools wrote decides which document governs it.
                let (spec, _) = summary.generation.governing_spec();
                let _ = writeln!(out, "Conformance: no deviations from {spec}");
            } else {
                let _ = writeln!(
                    out,
                    "Conformance: {} deviation(s) — run `aff4tools conformance`",
                    summary.deviations.len()
                );
                worst = worst.max(EXIT_STRICT_DEVIATION);
            }
        }
        Err(_) => {
            let _ = writeln!(out, "Conformance: could not summarize the container");
        }
    }

    stamp_completed(out);

    ExitCode::from(worst)
}

/// The raw counterpart of a buffered device node, when one exists.
///
/// `/dev/disk4` → `/dev/rdisk4`. Returns `None` when the path is already raw,
/// is not a `/dev/diskN` node, or the raw node does not exist.
fn raw_device_node(device: &std::path::Path) -> Option<PathBuf> {
    let name = device.file_name()?.to_str()?;
    if !name.starts_with("disk") {
        return None;
    }
    let raw = device.with_file_name(format!("r{name}"));
    raw.exists().then_some(raw)
}

/// Writes to the terminal and to a log file at once.
///
/// The terminal is what the operator watches; the log is what survives. A
/// failure to write the log is deliberately **not** fatal — losing the record of
/// an acquisition is bad, but aborting a running acquisition over it is worse.
struct Tee<'a, W: Write> {
    out: &'a mut W,
    log: Option<std::fs::File>,
}

impl<W: Write> Write for Tee<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(log) = self.log.as_mut() {
            let _ = log.write_all(buf);
        }
        self.out.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(log) = self.log.as_mut() {
            let _ = log.flush();
        }
        self.out.flush()
    }
}

/// The log path used when the operator names none: `<output>_log.txt`.
///
/// Beside the container, so the record travels with the evidence it describes.
fn default_log_path(output: &std::path::Path) -> PathBuf {
    let mut name = output.file_stem().unwrap_or_default().to_os_string();
    name.push("_log.txt");
    output.with_file_name(name)
}

/// Resolve the log path and open it, for any acquisition mode.
///
/// Extracted because the log was originally wired into `--logical` alone — the
/// mode whose noisy output prompted it — leaving `--device` and `--image`
/// silently unlogged. A device acquisition is the *longest* run and the one an
/// examiner is least able to repeat, so it is the last one that should lack a
/// record. One helper, called by all three, is what keeps them from drifting
/// apart again.
///
/// Returns the resolved path and the open file, or the exit code to fail with.
fn setup_log(
    output: &std::path::Path,
    log_path: Option<&std::path::Path>,
) -> std::result::Result<(PathBuf, std::fs::File), u8> {
    let path = log_path.map_or_else(|| default_log_path(output), std::path::Path::to_path_buf);
    match open_log(&path) {
        Ok(file) => Ok((path, file)),
        Err(e) => {
            eprintln!("error: cannot create {}: {e}", path.display());
            Err(3)
        }
    }
}

/// The current time as RFC 3339 UTC, the form the log's `Started:` line uses.
///
/// An acquisition log is a record an examiner may have to account for later,
/// so the times it reports must be readable in one format, not two.
fn now_rfc3339_utc() -> String {
    aff4tools::write::logical::format_rfc3339_utc(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

/// Close the acquisition proper: everything before this concerns reading the
/// source, everything after concerns checking what was written.
///
/// On a long acquisition the split is what tells an examiner how much of the
/// elapsed time was spent on the source medium.
fn stamp_acquisition_complete(out: &mut impl Write) {
    let _ = writeln!(out, "Acquisition Complete: {}", now_rfc3339_utc());
}

/// Close the run. Written once, after verification has had its chance.
///
/// Every mode routes its final line through here so the three stamps cannot
/// drift apart in wording or format between the paths that write them.
fn stamp_completed(out: &mut impl Write) {
    let _ = writeln!(out, "Completed: {}", now_rfc3339_utc());
}

/// Create the log, refusing to overwrite an existing file.
///
/// Same rule the container itself follows: a log that silently replaced a
/// previous acquisition's record would destroy evidence about evidence.
fn open_log(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    // The log is the binary's own output, not container content, so it does not
    // pass through `write::sink`. `create_new` refuses to overwrite, which is
    // the property that matters here.
    #[allow(clippy::disallowed_methods)]
    let mut file = std::fs::File::create_new(path)?;
    writeln!(
        file,
        "aff4tools {} — acquisition log\nStarted: {}\n",
        env!("CARGO_PKG_VERSION"),
        now_rfc3339_utc()
    )?;
    Ok(file)
}

/// Acquire a block device into a new container.
fn run_acquire_device(
    out: &mut impl Write,
    device: &std::path::Path,
    output: &std::path::Path,
    log_path: Option<&std::path::Path>,
    settings: AcquireOptions,
) -> ExitCode {
    let AcquireOptions {
        compression,
        chunk_size,
        chunks_per_bevy,
        verify_written_container,
        split_after,
        ..
    } = settings;
    use aff4tools::write::container_writer::ContainerWriter;
    use aff4tools::write::device::{DeviceOptions, DeviceReader};
    use aff4tools::write::guard::SourceRegistry;
    use aff4tools::write::stream_writer::StreamOptions;

    let mut registry = SourceRegistry::new();
    if let Err(e) = registry.register(device) {
        eprintln!("error: cannot open device {}: {e}", device.display());
        return ExitCode::from(3);
    }

    let mut file = match std::fs::File::open(device) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: cannot open device {}: {e}", device.display());
            return ExitCode::from(3);
        }
    };
    // A raw block device reports zero through `metadata`, so the size comes
    // from a seek to the end rather than from the file entry.
    let total = match aff4tools::write::device::device_size(&mut file) {
        Ok(n) => n,
        Err(e) => {
            eprintln!(
                "error: cannot determine the size of {}: {e}",
                device.display()
            );
            return ExitCode::from(6);
        }
    };

    // Opened only once the device is known good, so a failed size probe does
    // not leave a log describing an acquisition that never began.
    let (log_path, log) = match setup_log(output, log_path) {
        Ok(pair) => pair,
        Err(code) => return ExitCode::from(code),
    };
    let mut out = Tee {
        out,
        log: Some(log),
    };
    let out = &mut out;

    let _ = writeln!(out, "Device:      {}", device.display());
    let _ = writeln!(out, "Size:        {}", human_bytes(total));
    let _ = writeln!(out, "Output:      {}", output.display());
    let _ = writeln!(out, "Log:         {}", log_path.display());

    // macOS exposes each disk twice: `/dev/diskN` goes through the buffer
    // cache, `/dev/rdiskN` does not. For a linear read of a whole medium the
    // cache buys nothing and costs a copy per block. Measured on a slow USB
    // drive with `dd`: 11.8 MiB/s buffered against 15.5 MiB/s raw, a 31%
    // difference that is hours on a large device.
    //
    // Named rather than substituted: the operator chose a device, and quietly
    // acquiring a different node than the one written in their notes is not a
    // decision this tool should make for them.
    if let Some(raw) = raw_device_node(device) {
        let _ = writeln!(
            out,
            "Faster:      {} is the raw node — typically ~30% faster for a \
             whole-device read. This run uses the node you named.",
            raw.display()
        );
    }

    let options = StreamOptions {
        chunk_size,
        chunks_per_segment: chunks_per_bevy,
        codec: compression.into(),
        block_hashes: true,
    };
    let _ = writeln!(
        out,
        "Compression: {} ({chunk_size} byte chunks, {chunks_per_bevy} per bevy)",
        options.codec.name()
    );
    let _ = writeln!(out);

    if let Some(split_after) = split_after {
        let mut reader = DeviceReader::new(file, total, DeviceOptions::default());
        let algorithms = [
            aff4tools::HashAlgorithm::Sha256,
            aff4tools::HashAlgorithm::Md5,
        ];
        // A write failure (preflight or the write itself) is distinct from a
        // verification finding: it means the evidence is incomplete, and must
        // not be reported as if the acquisition finished. Return immediately,
        // without the unreadable-region report or the completion transcript
        // below — `report_error` has already told the user what went wrong.
        let code = match run_acquire_split(
            out,
            output,
            &mut reader,
            total,
            aff4tools::write::split_writer::SplitOptions {
                stream: options,
                split_after,
            },
            &algorithms,
            &registry,
            Some(&mut |out: &mut dyn Write, parts: &[PathBuf]| {
                verify_set_after_acquire(out, parts, total, verify_written_container)
            }),
        ) {
            Ok(floor) => floor,
            Err(failed) => return ExitCode::from(failed),
        };

        // Reported from the reader's accumulated state, now that the write has
        // released it. The offsets are absolute positions on the device,
        // independent of which part stores them, so they stay comparable with a
        // whole acquisition.
        let mut worst = 0u8;
        let regions = reader.unreadable();
        if regions.is_empty() {
            let _ = writeln!(out, "Read errors: none; every sector was returned");
        } else {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "UNREADABLE:  {} region(s), {} total, recorded as placeholder \
                 content and NOT recovered data",
                regions.len(),
                human_bytes(reader.unreadable_bytes())
            );
            for region in regions {
                let _ = writeln!(
                    out,
                    "  bytes {}..{} ({}): {}",
                    region.start,
                    region.start + region.length,
                    human_bytes(region.length),
                    region.reason
                );
            }
            worst = worst.max(EXIT_STRICT_DEVIATION);
        }
        stamp_completed(out);

        // `code` carries any floor the verification pass contributed; `worst`
        // carries the floor from unreadable device sectors. Neither may be
        // discarded in favor of the other — a device with both bad sectors
        // and a verification mismatch must report the mismatch, since
        // EXIT_MISMATCH outranks EXIT_STRICT_DEVIATION (see the ordering
        // documented at EXIT_UNVERIFIABLE above). Combined with `.max()` so
        // the stronger finding always wins, exactly as the single-file device
        // path does.
        return ExitCode::from(worst.max(code));
    }

    let locus = aff4tools::Locus::new(output);
    let mut writer = match ContainerWriter::create(output, &registry) {
        Ok(w) => w,
        Err(e) => return ExitCode::from(report_error(&e)),
    };
    let volume_arn = writer.volume_arn().as_str().to_owned();

    let mut reader = DeviceReader::new(file, total, DeviceOptions::default());
    let algorithms = [
        aff4tools::HashAlgorithm::Sha256,
        aff4tools::HashAlgorithm::Md5,
    ];
    // A 16 GB device is minutes of work and a multi-terabyte one is hours.
    // Without this the tool prints its header and then goes silent, which is
    // indistinguishable from a hang — the user cannot tell progress from a
    // stall, and has no basis for deciding whether to wait.
    let mut painter =
        painter::ProgressPainter::new(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    let mut reporter = aff4tools::progress::BlockProgress::new(total);
    let stream_arn = format!("{volume_arn}/data");
    let written = match aff4tools::write::stream_writer::write_image_stream_observed(
        &mut writer,
        &stream_arn,
        &mut reader,
        options,
        &algorithms,
        &mut |done, bevies| {
            reporter.update(done, bevies);
            if painter.would_paint() {
                let line =
                    aff4tools::progress::AcquisitionProgress::line(&reporter, painter.elapsed());
                painter.paint(&line);
            }
        },
        &locus,
    ) {
        Ok(w) => w,
        Err(e) => {
            painter.finish();
            return ExitCode::from(report_error(&e));
        }
    };
    painter.finish();
    let entries = [aff4tools::write::map_writer::MapEntry {
        mapped_offset: 0,
        length: written.size,
        target_offset: 0,
        target_id: 0,
    }];
    if let Err(e) = aff4tools::write::map_writer::write_map(
        &mut writer,
        &entries,
        std::slice::from_ref(&written.arn),
        written.size,
        &locus,
    ) {
        return ExitCode::from(report_error(&e));
    }

    if let Err(e) = writer.finish() {
        return ExitCode::from(report_error(&e));
    }

    let _ = writeln!(out, "Volume ARN:  {volume_arn}");
    let _ = writeln!(
        out,
        "Written:     {} in {} bevies",
        human_bytes(written.size),
        written.bevy_count
    );
    write_acquired_digests(out, &written);

    // Unreadable regions are a finding about the evidence and are reported
    // prominently, never folded into a summary line.
    let mut worst = 0u8;
    let regions = reader.unreadable();
    if regions.is_empty() {
        let _ = writeln!(out, "Read errors: none; every sector was returned");
    } else {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "UNREADABLE:  {} region(s), {} total, recorded as placeholder \
             content and NOT recovered data",
            regions.len(),
            human_bytes(reader.unreadable_bytes())
        );
        for region in regions {
            let _ = writeln!(
                out,
                "  bytes {}..{} ({}): {}",
                region.start,
                region.start + region.length,
                human_bytes(region.length),
                region.reason
            );
        }
        worst = worst.max(EXIT_STRICT_DEVIATION);
    }

    // Closes the acquisition proper: everything above concerns reading the
    // device, everything below concerns checking what was written. On a long
    // acquisition the split is what tells an examiner how much of the elapsed
    // time was spent on the medium.
    //
    // The split path stamps its own line at the same boundary, before its
    // verification hook runs, so the timestamp means the same thing in both:
    // reading the source is finished, checking the container has not begun.
    // The two transcripts still order the unreadable-region report differently
    // — the split path can only read `reader.unreadable()` after
    // `run_acquire_split` releases its mutable borrow — but that report is a
    // statement about the read, not a timestamp, so the boundary holds.
    stamp_acquisition_complete(out);

    let _ = writeln!(out);
    worst = worst.max(verify_after_acquire(
        out,
        output,
        written.size,
        verify_written_container,
    ));

    stamp_completed(out);

    ExitCode::from(worst)
}

/// Report every digest an acquisition recorded, grouped by what it covers.
///
/// Printing only the stream's two digests while verification reports "6 of 6
/// recomputed digest(s) matched" reads as a discrepancy, and leaves the missing
/// four shown nowhere. Each recorded digest is named by the object that carries
/// it, so the log accounts for what the container holds.
///
/// The `blockHashesHash` values sit under their own heading because they are a
/// different claim: each attests one whole block-hash segment, not the
/// evidence bytes.
fn write_acquired_digests(
    out: &mut impl Write,
    written: &aff4tools::write::stream_writer::WrittenStream,
) {
    /// The trailing path element of an ARN, which is how the container names
    /// the object an examiner is looking at (`data`, `blockhash.md5`).
    fn suffix(arn: &str) -> &str {
        arn.rsplit('/').next().unwrap_or(arn)
    }

    if !written.digests.is_empty() {
        let _ = writeln!(out, "ImageStream hashes:");
        let stream = suffix(&written.arn);
        for digest in &written.digests {
            let _ = writeln!(out, "  {stream} {} {}", digest.algorithm(), digest.hex());
        }
    }

    if !written.block_hash_digests.is_empty() {
        let _ = writeln!(out, "BlockHashes:");
        for digest in &written.block_hash_digests {
            // SHA-512 always: the segment digest's algorithm is fixed by the
            // format, and is not the algorithm of the per-chunk hashes inside.
            let _ = writeln!(out, "  {} SHA512 {}", suffix(&digest.arn), digest.hex);
        }
    }
}

/// Run the post-acquisition verification pass, or state that it was skipped.
///
/// Every acquisition mode calls this — `--image`, `--logical`, and `--device`
/// alike. Verification is what turns a written file into evidence, so it runs
/// by default regardless of what was acquired, and `--no-verify` is the only
/// thing that skips it.
///
/// This exists because the three modes each grew their own copy of the block
/// and then drifted: `--logical` verified nothing at all, and `--device`
/// verified unconditionally, ignoring the flag. One caller-agnostic function
/// is the only way that stays fixed.
///
/// `size` is the acquired byte count, named in the announcement so a long
/// re-read is explained while it happens.
///
/// Returns the worst exit code the pass produced.
fn verify_after_acquire(
    out: &mut impl Write,
    output: &std::path::Path,
    size: u64,
    verify: bool,
) -> u8 {
    let mut worst = 0u8;

    if !verify {
        let _ = writeln!(
            out,
            "Scope:       digests were recorded from the source as it was read, \
             but not checked against the container (--no-verify). Run \
             `aff4tools verify` to check them."
        );
        return worst;
    }

    // Named before it starts, not after it finishes: on a large container this
    // re-read runs for minutes, and an unlabeled pause reads as a hang.
    let _ = writeln!(
        out,
        "Verifying:   re-reading {} from the container just written",
        human_bytes(size)
    );
    let _ = out.flush();

    match verify_written(output) {
        Ok(report) => {
            if report.has_mismatch() {
                let _ = writeln!(
                    out,
                    "VERIFY:      MISMATCH — the container does not match its own \
                     recorded digests. This is a finding about the acquisition."
                );
                worst = worst.max(EXIT_MISMATCH);
            } else {
                let _ = writeln!(
                    out,
                    "Verify:      {} of {} recomputed digest(s) matched",
                    report.match_count(),
                    report.checked_count()
                );
            }
            // An acquisition that wrote evidence it cannot read back is a
            // finding even when everything readable matched.
            if report.has_unreadable() {
                let _ = writeln!(
                    out,
                    "VERIFY:      {} recorded digest(s) span bytes that could not be \
                     read back from the container.",
                    report.unreadable_count()
                );
                worst = worst.max(EXIT_UNVERIFIABLE);
            }
        }
        Err(e) => {
            let _ = writeln!(out, "VERIFY:      could not re-read the container: {e}");
            worst = worst.max(e.exit_code());
        }
    }

    worst
}

/// Verify a split set in place, reading its parts as the one image they form.
///
/// `verify_after_acquire` cannot serve here: it calls `verify_written`, which
/// opens a single container. A part opened alone is a partial view of the
/// evidence, so the whole set is opened together through the same path
/// `verify --split-file` uses.
fn verify_set_after_acquire(out: &mut dyn Write, parts: &[PathBuf], size: u64, verify: bool) -> u8 {
    let mut worst = 0u8;

    if !verify {
        let _ = writeln!(
            out,
            "Scope:       digests were recorded from the source as it was read, \
             but not checked against the container (--no-verify). Run \
             `aff4tools verify --split-file` to check them."
        );
        return worst;
    }

    let _ = writeln!(
        out,
        "Verifying:   re-reading {} from the {} part(s) just written",
        human_bytes(size),
        parts.len()
    );
    let _ = out.flush();

    // `self::` avoids the shadow: the `verify: bool` parameter above hides the
    // free function `verify` of the same name for the rest of this scope.
    match self::verify(parts, VerifyOptions { block_hashes: true }, None) {
        Ok((report, _summary)) => {
            if report.has_mismatch() {
                let _ = writeln!(
                    out,
                    "VERIFY:      MISMATCH — the container does not match its own \
                     recorded digests. This is a finding about the acquisition."
                );
                worst = worst.max(EXIT_MISMATCH);
            } else {
                let _ = writeln!(
                    out,
                    "Verify:      {} of {} recomputed digest(s) matched",
                    report.match_count(),
                    report.checked_count()
                );
            }
            if report.has_unreadable() {
                let _ = writeln!(
                    out,
                    "VERIFY:      {} recorded digest(s) span bytes that could not be \
                     read back from the container.",
                    report.unreadable_count()
                );
                worst = worst.max(EXIT_UNVERIFIABLE);
            }
        }
        Err(error) => worst = worst.max(error.report()),
    }

    worst
}

/// Recompute the digests of a container we just wrote.
///
/// # Why this reports progress
///
/// This re-reads and decompresses **the whole container** — on a 15 GiB device
/// acquisition it ran for one to two minutes with nothing on screen, which is
/// indistinguishable from a hang at the very moment the user is waiting to
/// learn whether their evidence is sound. It uses the same reporter as
/// `aff4tools verify`, because it is doing the same work.
fn verify_written(path: &std::path::Path) -> aff4tools::Result<VerificationReport> {
    let mut container = Container::open(path)?;
    let expected = aff4tools::estimate_work(&mut container, VerifyOptions { block_hashes: true })
        .map_or(0, |estimate| estimate.bytes_to_read);
    let mut reporter = ProgressReporter::new(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .expecting(expected)
        .across_parts(1);
    let report = verify_container_with_progress(
        &mut container,
        VerifyOptions { block_hashes: true },
        &mut reporter,
    );
    reporter.finish();
    report
}

/// Collect a container's deviations without retaining its objects.
///
/// `conformance` reads only the path and the deviation list, so
/// `Container::deviations_only` skips holding one `Aff4Object` per described
/// subject — 2.3 GB at a million objects. Same checks, same order, same
/// findings; see docs/RDF-scalability.md.
fn conformance_findings(
    paths: &[PathBuf],
) -> std::result::Result<aff4tools::ConformanceScan, OpenError> {
    let mut container = open_striped_for_summary(paths)?;
    Ok(container.deviations_only()?)
}

/// Check each path against the specification, returning the worst exit code.
///
/// The deviation listing lives here and only here. Printing it from `info` or
/// `verify` too would make a conformance finding something the examiner happens
/// across while reading a metadata dump; keeping it a command of its own means
/// asking the conformance question is a deliberate act with an answer of its
/// own.
fn run_conformance(sets: &[Vec<PathBuf>], format: Format, strict: bool) -> ExitCode {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut worst = 0u8;
    let mut reports = Vec::new();
    let mut errors = Vec::new();

    for (index, set) in sets.iter().enumerate() {
        match conformance_findings(set) {
            Ok(scan) => {
                let deviations = &scan.deviations;
                if strict && aff4tools::model::has_noteworthy_deviation(deviations) {
                    // Same rule --strict follows everywhere else: routine
                    // conditions are reported but do not set the exit code.
                    worst = worst.max(EXIT_STRICT_DEVIATION);
                }
                match format {
                    Format::Text => {
                        if index > 0 {
                            let _ = writeln!(out);
                        }
                        let _ = write_conformance(&mut out, &scan);
                    }
                    Format::Json => {
                        reports.push(ConformanceReport::from(&scan));
                    }
                }
            }
            Err(error) => match format {
                Format::Text => worst = worst.max(error.report()),
                Format::Json => {
                    let (entry, code) = error.as_json_entry(&set[0]);
                    worst = worst.max(code);
                    errors.push(entry);
                }
            },
        }
    }

    if format == Format::Json {
        // The same envelope shape `info --format json` uses, for the same
        // reason: one input or many, success or total failure, a
        // script reads `.containers` and `.errors` without branching.
        let report = ConformanceJsonReport {
            containers: reports,
            errors,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                let _ = writeln!(out, "{text}");
            }
            Err(e) => {
                eprintln!("error: cannot render JSON: {e}");
                worst = worst.max(EXIT_USAGE);
            }
        }
    }

    ExitCode::from(worst)
}

/// Write the human-readable conformance report.
///
/// Three parts, in the order the examiner asked for them: which container, what
/// it was checked against, and every way it departs from that. Nothing else —
/// no object listing, no digests. A reader who wants those runs `info`.
///
/// Every recorded deviation is printed, routine or not. `--strict` decides
/// which ones affect the exit code; it never decides which ones are shown. A
/// conformance report that silently dropped a recorded departure would be
/// exactly the lossy conversion this project refuses to make.
fn write_conformance(
    out: &mut impl Write,
    scan: &aff4tools::ConformanceScan,
) -> std::io::Result<()> {
    let deviations = &scan.deviations;
    let (base_spec, logical_spec) = scan.generation.governing_spec();

    writeln!(out, "Container: {}", scan.path.display())?;
    // The declared version and the producing tool, in the same words `info`
    // uses. The version is what selected the document named below, so a report
    // that cites a specification without showing the version leaves the
    // examiner unable to check that choice. Which implementation wrote the
    // container is then the first thing that explains a deviation, and neither
    // fact should require running a second command.
    match scan.version.as_ref() {
        Some(version) => {
            writeln!(out, "AFF4 Version: {}.{}", version.major, version.minor)?;
            if let Some(tool) = version.tool.as_ref() {
                writeln!(out, "Tool: {tool}")?;
            }
        }
        // Stated rather than omitted: absence is a fact about the container,
        // and pyaff4 fabricates Version(0,1) here.
        None => writeln!(out, "AFF4 Version: not declared (pre-standard container)")?,
    }
    match logical_spec {
        // Two documents govern a pyaff4-era AFF4-L container: v1.0a for the
        // base container, the paper for the logical layer above it. Naming
        // only one would misstate what was measured.
        Some(logical) => writeln!(
            out,
            "Checking conformance with {base_spec}, and {logical} for logical constructs"
        )?,
        None => writeln!(out, "Checking conformance with {base_spec}")?,
    }
    writeln!(out)?;

    if deviations.is_empty() {
        // Stated as what was checked, not as a clean bill of health: this
        // command reads metadata and recomputes nothing, so "conforms" here
        // must not be read as "the evidence is intact".
        writeln!(
            out,
            "No deviations. This container's metadata conforms to {base_spec}."
        )?;
        writeln!(
            out,
            "(Metadata only — no digest was recomputed. Run `aff4tools verify` \
             to check the stored bytes against their recorded hashes.)"
        )?;
        return Ok(());
    }

    writeln!(out, "Deviations ({})", deviations.len())?;
    for deviation in deviations {
        writeln!(out)?;
        writeln!(out, "  [{}] {}", deviation.kind, deviation.locus)?;
        match (
            deviation.kind.spec_section(scan.generation),
            deviation.kind.other_specification(scan.generation),
        ) {
            (Some(section), _) => writeln!(out, "      {base_spec} {section}")?,
            // AFF4-L rules are specified in the paper, not the Standard.
            // Citing that document is both true and findable; saying the
            // Standard is silent would imply nothing legislates it.
            (None, Some((document, section))) => {
                writeln!(out, "      {document} {section}")?;
            }
            // Named as unlegislated rather than left blank, so a missing
            // citation cannot read as an omission.
            (None, None) => writeln!(
                out,
                "      {base_spec} does not address this; reported as an extension"
            )?,
        }
        writeln!(out, "      {}", deviation.detail)?;
    }

    Ok(())
}

/// The `--format json` envelope for `conformance`.
///
/// Shaped like [`InfoJsonReport`] deliberately — same field names, same
/// guarantees — so a script that already reads one can read the other.
#[derive(Debug, serde::Serialize)]
struct ConformanceJsonReport {
    /// Every container checked successfully, in command-line order.
    containers: Vec<ConformanceReport>,
    /// Every path that could not be opened or read. Empty on complete success.
    errors: Vec<ContainerError>,
}

/// One container's conformance result, in machine-readable form.
#[derive(Debug, serde::Serialize)]
struct ConformanceReport {
    /// The container's path on disk.
    source_path: PathBuf,
    /// Which era wrote the container, as [`Generation`] serializes it.
    generation: aff4tools::Generation,
    /// The version declared in `version.txt`, e.g. `"1.1"`. Absent for a
    /// container that declares none.
    #[serde(skip_serializing_if = "Option::is_none")]
    aff4_version: Option<String>,
    /// The producing tool from `version.txt`, absent if it declared none.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
    /// The base specification checked against, decided by the generation.
    specification: &'static str,
    /// The additional document governing logical constructs, where one
    /// applies. Present only for pyaff4-era AFF4-L, whose logical layer is
    /// specified in a paper rather than in the Standard.
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_specification: Option<&'static str>,
    /// Whether anything at all departed from the standard. Routine conditions
    /// count here — this is [`ContainerSummary::is_conformant`], not the
    /// narrower question `--strict` asks.
    conformant: bool,
    /// Every deviation, each with its spec citation.
    deviations: Vec<ConformanceDeviation>,
}

impl ConformanceReport {
    fn from(scan: &aff4tools::ConformanceScan) -> Self {
        let (base_spec, logical_spec) = scan.generation.governing_spec();
        Self {
            source_path: scan.path.clone(),
            generation: scan.generation,
            aff4_version: scan
                .version
                .as_ref()
                .map(|v| format!("{}.{}", v.major, v.minor)),
            tool: scan.version.as_ref().and_then(|v| v.tool.clone()),
            specification: base_spec.name(),
            logical_specification: logical_spec.map(aff4tools::rules::Document::name),
            // `is_conformant` is "no deviation at all", routine ones included —
            // deliberately not the narrower question `--strict` asks.
            conformant: scan.deviations.is_empty(),
            deviations: scan
                .deviations
                .iter()
                .map(|d| ConformanceDeviation::from(d, scan.generation))
                .collect(),
        }
    }
}

/// One deviation, with the section it departs from.
#[derive(Debug, serde::Serialize)]
struct ConformanceDeviation {
    /// The machine-readable kind token, as [`DeviationKind`] serializes it.
    kind: DeviationKind,
    /// The kind rendered for a human, e.g. `"NUL-padded ZIP comment"`.
    description: String,
    /// Where the deviation was found.
    locus: String,
    /// The specifics, including the offending lexical value.
    detail: String,
    /// The v1.0a section departed from, serialized bare — e.g. `"§5.4"`. The
    /// document it belongs to is the report's `specification` field. `null`
    /// where the standard does not legislate the condition at all — an
    /// extension that no clause prohibits, reported so the examiner knows it
    /// is in use.
    spec_section: Option<&'static str>,
    /// The other normative document this cites, where the Standard is silent
    /// but another specification is not — AFF4-L is defined in a paper, so its
    /// rules have no Standard section. `null` for everything else, which keeps
    /// a consumer from confusing "no Standard clause" with "no rule at all".
    #[serde(skip_serializing_if = "Option::is_none")]
    other_specification: Option<OtherSpecification>,
}

/// A citation into a normative document that is not the AFF4 Standard.
#[derive(Debug, serde::Serialize)]
struct OtherSpecification {
    /// The document's full name, so an examiner can find it.
    document: &'static str,
    /// The section within the document named above, serialized bare — for the
    /// AFF4-L 2019 paper, e.g. `"§3.8"`.
    section: &'static str,
}

impl ConformanceDeviation {
    fn from(deviation: &Deviation, generation: aff4tools::Generation) -> Self {
        Self {
            kind: deviation.kind,
            description: deviation.kind.to_string(),
            locus: deviation.locus.to_string(),
            detail: deviation.detail.clone(),
            spec_section: deviation.kind.spec_section(generation),
            other_specification: deviation
                .kind
                .other_specification(generation)
                .map(|(document, section)| OtherSpecification { document, section }),
        }
    }
}

/// The `--format json` envelope for `info`.
///
/// A bare array of summaries (or a bare object for exactly one input) would
/// send every failure to stderr as prose and print `[]` on total failure —
/// indistinguishable, to a script reading only stdout, from "these paths
/// matched zero containers". Wrapping both outcomes in one object makes
/// success and failure both live in the
/// one machine-readable stream: `containers` holds every summary that could
/// be built, `errors` holds a structured entry for every path that could not
/// be opened or read, in the order encountered. A run over several paths
/// where some succeed and some fail — the case
/// `a_failure_in_one_container_still_reports_the_others` in `tests/cli.rs`
/// covers on the text side — reports both halves in the one document rather
/// than losing the failures to stderr.
///
/// The process exit code is unchanged (still the worst `Error::exit_code`
/// seen, still 3 for the "cannot even read the file" cases this envelope was
/// built to disambiguate) — this only makes the same fact machine-readable on
/// stdout instead of prose-only on stderr.
#[derive(Debug, serde::Serialize)]
struct InfoJsonReport {
    /// Every container summarized successfully, in the order given on the
    /// command line.
    containers: Vec<ContainerSummary>,
    /// Every path that could not be opened or read, in the order encountered.
    /// Empty on complete success.
    errors: Vec<ContainerError>,
}

/// One path that failed, in machine-readable form.
///
/// Mirrors what [`report_error`] prints to stderr for the text format, so
/// nothing disclosed there is lost in JSON: the message, the full `source()`
/// cause chain, the exit code this failure contributes, and whether it is an
/// integrity finding about the evidence itself versus a limitation of this
/// tool (`Error::is_integrity_finding`).
#[derive(Debug, serde::Serialize)]
struct ContainerError {
    /// The path given on the command line that this error is about. For a
    /// `--split-file` set, the primary (first) path.
    path: PathBuf,
    /// A stable, short token for the failure category — the same grouping
    /// [`Error::exit_code`] uses, so a script can match on it without parsing
    /// `message`. One of `"io"`, `"zip"`, `"not_aff4"`, `"malformed"`,
    /// `"unsupported"`, `"usage"` (a command-line mistake, e.g. a `--split-file`
    /// set that shares no volume, which is not a fact about the evidence at
    /// all), or `"unverifiable"` (one part of a split set was named, so bytes
    /// the recorded digests cover are not present).
    kind: &'static str,
    /// The top-level error message, exactly as the text report's first line
    /// states it (without the `error: ` prefix).
    message: String,
    /// Each wrapped cause, innermost last, exactly as the text report's
    /// `caused by:` lines state them.
    caused_by: Vec<String>,
    /// The exit code this failure contributes to the process's overall exit
    /// code (`ExitCode::from` takes the worst across every path).
    exit_code: u8,
    /// Whether this is a finding about the evidence itself (a malformed
    /// container) rather than a limitation of aff4tools (missing codec
    /// support) or a mistake on the command line. Mirrors the `note:` line
    /// [`report_error`] prints for the text format.
    is_integrity_finding: bool,
}

impl ContainerError {
    /// Build a [`ContainerError`] from a library [`Error`], for `path`.
    fn from(error: &Error, path: &std::path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
            kind: error_kind(error),
            message: error.to_string(),
            caused_by: cause_chain(error),
            exit_code: error.exit_code(),
            is_integrity_finding: error.is_integrity_finding(),
        }
    }

    /// Build a [`ContainerError`] for a command-line mistake (an
    /// [`OpenError::Usage`]) — not a fact about the evidence, so `kind` is
    /// `"usage"` and `is_integrity_finding` is always `false`.
    fn from_usage(detail: &str, path: &std::path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
            kind: "usage",
            message: detail.to_owned(),
            caused_by: Vec::new(),
            exit_code: EXIT_USAGE,
            is_integrity_finding: false,
        }
    }

    /// A failure meaning the evidence cannot be read back in full.
    ///
    /// An integrity finding: bytes the recorded digests cover are not present,
    /// which is a fact about the evidence rather than about aff4tools.
    fn from_unverifiable(detail: &str, path: &std::path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
            kind: "unverifiable",
            message: detail.to_owned(),
            caused_by: Vec::new(),
            exit_code: EXIT_UNVERIFIABLE,
            is_integrity_finding: true,
        }
    }
}

/// The stable `kind` token for a library [`Error`]. Grouped exactly the way
/// [`Error::exit_code`] groups them, so the two never disagree about what
/// counts as the same kind of failure.
fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::Io { .. } => "io",
        Error::Zip { .. } => "zip",
        Error::NotAff4 { .. } => "not_aff4",
        Error::Malformed { .. } => "malformed",
        Error::Unsupported { .. } => "unsupported",
    }
}

/// The full `source()` cause chain of an error, innermost last — the same
/// traversal [`report_error`] prints as `caused by:` lines.
fn cause_chain(error: &(impl std::error::Error + ?Sized)) -> Vec<String> {
    let mut chain = Vec::new();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        chain.push(cause.to_string());
        source = std::error::Error::source(cause);
    }
    chain
}

fn summarize(paths: &[PathBuf]) -> std::result::Result<ContainerSummary, OpenError> {
    summarize_for(paths, false)
}

/// [`summarize`], optionally keeping only what `--brief` renders.
///
/// `brief` is honored for text output only. `--format json` serializes
/// `objects`, so it must have them all — a partial list there would be a
/// silently truncated record rather than a shorter report.
fn summarize_for(
    paths: &[PathBuf],
    brief: bool,
) -> std::result::Result<ContainerSummary, OpenError> {
    // Opened without parsing the primary's graph: both summarize paths stream
    // their own, so a retained copy would never be read. `verify` still uses
    // `open_striped`, because it reads the retained graph afterwards.
    let mut container = open_striped_for_summary(paths)?;
    if brief {
        return Ok(container.summarize_brief()?);
    }
    Ok(container.summarize()?)
}

/// Bytes of `information.turtle` above which parsing is announced.
///
/// Below this the parse is imperceptible and a notice would be noise on every
/// command. The largest metadata segment in the reference corpus is 99 KB, so
/// no canonical container reaches it — this fires on the real-world case it is
/// for: an AFF4-L acquisition of millions of objects, whose turtle runs to
/// hundreds of megabytes.
///
/// 50 MiB is roughly 300,000 objects, where the parse alone is worth
/// announcing on its own merits. A lower threshold would announce work that
/// takes about a second, which trains the reader to ignore the notice.
const METADATA_NOTICE_THRESHOLD: u64 = 50 * 1024 * 1024;

/// Say that metadata is being parsed, when that will take long enough to notice.
///
/// A large logical acquisition spends real time in the Turtle parser before any
/// output appears, and silence there is indistinguishable from a hang. This is
/// the same reasoning as the verify pass announcing itself.
///
/// **On stderr, not stdout.** It is progress, not part of the report: `info >
/// summary.txt` must not capture it, and `--format json` must stay parseable.
///
/// **Printed from the binary, not the library.** `Container::open` is where the
/// parse happens, but the library returns values and never writes to a stream —
/// a future GUI or language binding cannot have text appearing on its stdout.
/// So the size is read here, from the ZIP central directory, before the
/// container is opened.
///
/// The size is the **uncompressed** one. `information.turtle` is deflated, at
/// ratios from 1.0x to 6.5x across the corpus, so the stored size predicts
/// neither parse time nor memory; a 30 MB turtle stored in 3 MB would otherwise
/// slip under the threshold, which is exactly the case worth announcing.
///
/// Silent whenever the size cannot be read. Opening the container is what
/// reports a malformed one; duplicating that here would put a diagnostic before
/// the error that explains it.
fn announce_metadata_parse(path: &std::path::Path) {
    let Ok(volume) = aff4tools::zip::ZipVolume::open(path) else {
        return;
    };
    let Some(size) = volume.uncompressed_bytes(aff4tools::container::METADATA_SEGMENT) else {
        return;
    };
    if size < METADATA_NOTICE_THRESHOLD {
        return;
    }
    eprintln!("Parsing container information ({})...", human_bytes(size));
}

/// Open a container, joining any further stripes into one volume set.
///
/// `paths[0]` is the primary. The rest are added in the order given, which is
/// the order an examiner asserted — it is not re-sorted, because for a striped
/// image that order is an input to the root digest, not a presentation detail.
///
fn open_striped(paths: &[PathBuf]) -> std::result::Result<Container, OpenError> {
    open_striped_inner(paths, true)
}

/// [`open_striped`], without parsing the primary's metadata graph.
///
/// For `info` and `conformance`, which build a summary and never read the
/// retained graph. See `Container::open_without_graph`.
fn open_striped_for_summary(paths: &[PathBuf]) -> std::result::Result<Container, OpenError> {
    open_striped_inner(paths, false)
}

fn open_striped_inner(
    paths: &[PathBuf],
    retain_graph: bool,
) -> std::result::Result<Container, OpenError> {
    announce_metadata_parse(&paths[0]);
    let mut container = if retain_graph {
        Container::open(&paths[0])?
    } else {
        Container::open_without_graph(&paths[0])?
    };

    for path in &paths[1..] {
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(path)?;
        if !container.add_volume(volume, graph, VolumeOrigin::Named) {
            eprintln!(
                "note: {} holds a volume already given; ignoring the repeat",
                path.display()
            );
        }
    }

    if container.volumes().len() > 1
        && let Err(detail) = check_stripe_set(&mut container)
    {
        return Err(OpenError::Usage(detail));
    }

    Ok(container)
}

/// Why a set of volumes could not be opened.
///
/// Separates the two kinds of failure so each gets the right exit code: a
/// library error is a fact about the container, while naming the wrong files is
/// a mistake on the command line and must not be reported as damaged evidence.
enum OpenError {
    Library(Error),
    Usage(String),
    /// The single file named is one part of a split set, so the volumes it
    /// references are not all present.
    PartOfSplitSet {
        /// The path the examiner named.
        path: PathBuf,
        /// How many volumes it references but does not hold.
        missing: usize,
    },
}

impl From<Error> for OpenError {
    fn from(error: Error) -> Self {
        Self::Library(error)
    }
}

impl OpenError {
    /// Render and map to an exit code.
    fn report(&self) -> u8 {
        match self {
            Self::Library(error) => report_error(error),
            Self::Usage(detail) => {
                eprintln!("error: {detail}");
                EXIT_USAGE
            }
            // Missing volumes mean missing data, so the recorded digests span
            // bytes that cannot be read back. That is exactly what
            // `EXIT_UNVERIFIABLE` means, and it beats a reassuring partial
            // report over whichever streams happened to be present.
            Self::PartOfSplitSet { path, missing } => {
                eprintln!(
                    "error: {} is one part of a split set; it references {missing} volume(s) \
                     it does not hold.",
                    path.display()
                );
                eprintln!(
                    "       Pass the containing folder: \
                     aff4tools verify --split-file <dir>"
                );
                EXIT_UNVERIFIABLE
            }
        }
    }

    /// The machine-readable form of this failure, and the code it contributes.
    ///
    /// `info` and `conformance` render every failure into the `errors` array of
    /// their JSON envelope, so nothing reported on stderr for text output is
    /// lost in JSON.
    fn as_json_entry(&self, path: &std::path::Path) -> (ContainerError, u8) {
        match self {
            Self::Library(e) => (ContainerError::from(e, path), e.exit_code()),
            Self::Usage(detail) => (ContainerError::from_usage(detail, path), EXIT_USAGE),
            Self::PartOfSplitSet {
                path: part,
                missing,
            } => (
                ContainerError::from_unverifiable(
                    &format!(
                        "{} is one part of a split set; it references {missing} volume(s) \
                         it does not hold. Pass the containing folder: \
                         aff4tools verify --split-file <dir>",
                        part.display()
                    ),
                    path,
                ),
                EXIT_UNVERIFIABLE,
            ),
        }
    }
}

/// Refuse a set of volumes that do not belong to one striped container.
///
/// Standard v1.0a §7.1 makes a commonly-named `aff4:DiskImage` "the point of
/// commonality unifying" the volumes of a striped set, and the corpus bears it
/// out: the shared image ARN is identical across stripes while every other
/// identifier differs per volume. Volumes sharing none are not a striped
/// container.
///
/// Checked before verifying because `--split-file` is an **assertion by the
/// examiner** that these files are one image. Verifying anyway mostly works —
/// each object resolves against whichever volume owns it — so the mistake would
/// surface only as a puzzling decline several screens below a reassuring
/// "N of N matched". Better to say so at the top.
///
/// The test is *share at least one*, not *declare exactly one*: a volume may
/// legitimately hold an unrelated image beside the striped one. And it catches
/// unrelated files, not a wrong one — two volumes from different acquisitions
/// of the same set would share the ARN and pass.
/// Returns `Err(message)` for the caller to report as a **usage** error, not a
/// library one: naming the wrong files is a mistake on the command line, and
/// classifying it as `Malformed` would claim the evidence is damaged and exit
/// with an integrity code.
fn check_stripe_set(container: &mut Container) -> std::result::Result<(), String> {
    // Through the container, not the volume set: `info` and `conformance` open
    // the primary without retaining its graph, and reading the retained copy
    // there saw "no DiskImage" for the primary of every striped set. See
    // `Container::disk_images_per_volume`.
    let per_volume = match container.disk_images_per_volume() {
        Ok(per_volume) => per_volume,
        Err(error) => return Err(format!("the set's metadata could not be read: {error}")),
    };

    let Some((_, first)) = per_volume.first() else {
        return Ok(());
    };
    let shared: Vec<&String> = first
        .iter()
        .filter(|image| {
            per_volume
                .iter()
                .all(|(_, images)| images.iter().any(|i| i == *image))
        })
        .collect();

    if !shared.is_empty() {
        return Ok(());
    }

    let mut detail = String::from(
        "the volumes given do not share an aff4:DiskImage, so they are not \
         stripes of one image. Each volume declares:",
    );
    for (path, images) in &per_volume {
        let names = if images.is_empty() {
            "no DiskImage".to_owned()
        } else {
            images.join(", ")
        };
        detail.push_str(&format!(
            "\n  {} — {names}",
            path.file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
        ));
    }
    detail.push_str(
        "\nTo verify these as separate containers, pass them as plain paths \
         rather than --split-file.",
    );

    Err(detail)
}

/// Render an error and map it to its exit code.
///
/// Returns the code rather than exiting, so several containers can be processed
/// and the most severe result reported at the end.
fn report_error(err: &Error) -> u8 {
    eprintln!("error: {err}");

    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = std::error::Error::source(cause);
    }

    if err.is_integrity_finding() {
        eprintln!(
            "note: this is a finding about the evidence itself, \
             not a limitation of aff4tools"
        );
    }

    err.exit_code()
}

/// Group a count with thousands separators: `978880` becomes `978,880`.
///
/// Digest counts reach the hundreds of thousands on a real acquisition, where
/// an ungrouped run of digits is easy to misread by an order of magnitude.
fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use aff4tools::{Feature, Locus, NotAff4Reason};

    /// Guards the distinction the taxonomy exists for: an unsupported feature
    /// must not be annotated as an evidence-integrity finding.
    #[test]
    fn only_malformed_is_annotated_as_an_integrity_finding() {
        let malformed = Error::malformed(Locus::new("/x.aff4"), "bad bevy index");
        assert!(malformed.is_integrity_finding());

        for err in [
            Error::unsupported(Feature::Encryption, "at /x.aff4"),
            Error::not_aff4("/x.zip", NotAff4Reason::EmptyArchive),
            Error::io(
                "/x.aff4",
                std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
            ),
        ] {
            assert!(
                !err.is_integrity_finding(),
                "{err} must not be reported as an integrity finding"
            );
        }
    }

    /// Exit code 1 is reserved for clap usage errors, so no library error may
    /// claim it — otherwise scripts cannot tell a bad invocation from bad
    /// evidence.
    #[test]
    fn library_errors_never_use_the_usage_exit_code() {
        let errors = [
            Error::io(
                "/x",
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            ),
            Error::not_aff4("/x", NotAff4Reason::NoMetadata),
            Error::malformed(Locus::new("/x"), "bad"),
            Error::unsupported(Feature::Encryption, "ctx"),
        ];
        for err in &errors {
            assert_ne!(err.exit_code(), EXIT_USAGE, "{err}");
            assert_ne!(err.exit_code(), 0, "{err}");
        }
    }

    /// A device split acquisition with unreadable sectors AND a failed write
    /// must report the failure, not the higher-numbered
    /// `EXIT_STRICT_DEVIATION`.
    ///
    /// Regression for the bug where `run_acquire_split`'s `u8` collapsed "the
    /// write failed" and "verification found something" into one value, so
    /// `worst.max(code)` in the device branch always preferred
    /// `EXIT_STRICT_DEVIATION` (7) over a library error code (3..=6) whenever
    /// bad sectors were present — masking a failed acquisition as a completed
    /// one with a strict-mode deviation.
    ///
    /// `FaultyReader` (`src/write/device.rs`) injects a read failure over a
    /// byte range, which `DeviceReader` converts into a recorded unreadable
    /// region rather than propagating the error — that is what puts bad
    /// sectors on the record without aborting the read. The write is then
    /// failed independently and deterministically: `ContainerWriter::create`
    /// (via `WriteSink::create`) refuses to overwrite an existing file, so
    /// pre-creating part 002's path forces part 2's creation to fail after
    /// part 1 — which covers the byte range carrying the injected read
    /// failure — has already been written and its bad sector recorded.
    #[test]
    fn split_write_failure_is_not_masked_by_unreadable_sectors() {
        use aff4tools::write::device::{DeviceOptions, DeviceReader, FaultyReader};
        use aff4tools::write::guard::SourceRegistry;
        use aff4tools::write::split_writer::{SplitOptions, part_path};
        use aff4tools::write::stream_writer::StreamOptions;

        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("evidence.aff4");

        // Bad sector inside part 1's byte range (part boundary is at
        // `split_after` = 64 KiB), so it is recorded before part 2 fails.
        let total = 192 * 1024u64;
        let data = vec![0xABu8; total as usize];
        let faulty = FaultyReader::new(data, 4096..8192);
        let mut reader = DeviceReader::new(faulty, total, DeviceOptions::default());

        // Forces part 2's `ContainerWriter::create` to fail: the sink refuses
        // to overwrite an existing file. Test fixture setup, not the writer
        // itself, so it is exempted from the read-only-guard lint the same
        // way other test fixtures are (see `tests/cli.rs`).
        #[allow(clippy::disallowed_methods)]
        std::fs::write(part_path(&output, 2), b"pre-existing").unwrap();

        let registry = SourceRegistry::new();
        let algorithms = [
            aff4tools::HashAlgorithm::Sha256,
            aff4tools::HashAlgorithm::Md5,
        ];
        let options = SplitOptions {
            stream: StreamOptions {
                chunk_size: 4096,
                chunks_per_segment: 2,
                codec: aff4tools::Codec::Stored,
                block_hashes: true,
            },
            split_after: 64 * 1024,
        };

        let mut out = Vec::new();
        let result = run_acquire_split(
            &mut out,
            &output,
            &mut reader,
            total,
            options,
            &algorithms,
            &registry,
            None,
        );

        let code = match result {
            Ok(floor) => panic!(
                "write failure must surface as Err, not a floor of {floor}; a caller \
                 combining this with EXIT_STRICT_DEVIATION via .max() would report 7 \
                 instead of the failure"
            ),
            Err(code) => code,
        };
        assert!(
            (3..=6).contains(&code),
            "expected a library error code (3..=6), got {code}"
        );
        assert_ne!(
            code, EXIT_STRICT_DEVIATION,
            "a failed write must never be reported as EXIT_STRICT_DEVIATION"
        );

        // The bad sector was in part 1's range and part 1 was written before
        // part 2 failed, so it must have been recorded — proving this test
        // actually exercises the masking scenario (bad sectors present) and
        // not merely a plain write failure.
        assert!(
            !reader.unreadable().is_empty(),
            "the injected read failure must have been recorded before the write failed"
        );

        let transcript = String::from_utf8_lossy(&out);
        assert!(
            !transcript.contains("Acquisition Complete"),
            "no completion transcript may print after a failed write: {transcript}"
        );
    }
    /// The meter must never report more than 100% on a correct estimate.
    ///
    /// The first cut of the cumulative meter read `10.3/4.1 GiB | 250%` on a
    /// nine-part set, because the estimate covered one part while the run read
    /// nine. A monotonicity test passed it — the figure climbed smoothly to
    /// 250% — so the property that actually matters is asserted here: what the
    /// accumulator produces, against the total it is measured with.
    #[test]
    fn the_meter_ends_at_the_total_it_was_given() {
        let total = 9 * 1000u64;
        let mut reporter = ProgressReporter::new(false).expecting(total);

        // Nine streams, each reporting its own cumulative `done` from zero, as
        // the library emits them.
        let mut highest = 0u64;
        for part in 0..9 {
            let arn = format!("aff4://volume/part{part}/data");
            for step in 1..=10u64 {
                highest = reporter.advance(&arn, step * 100);
            }
        }

        assert_eq!(
            highest,
            total,
            "the run delivered {highest} against a total of {total}: the meter \
             would read {}%",
            highest * 100 / total
        );
    }

    /// A subject reporting less than it did before starts a new traversal.
    ///
    /// `done` counts from its own object's start, so a drop means the object is
    /// being read again rather than un-read. Counting the drop as negative
    /// would send the meter backwards; ignoring it would lose the bytes.
    #[test]
    fn a_restarted_subject_adds_its_bytes_rather_than_subtracting() {
        let mut reporter = ProgressReporter::new(false).expecting(300);
        assert_eq!(reporter.advance("aff4://a", 100), 100);
        assert_eq!(reporter.advance("aff4://a", 200), 200);
        // A second traversal of the same subject restarts at 50.
        assert_eq!(reporter.advance("aff4://a", 50), 250);
    }
}
