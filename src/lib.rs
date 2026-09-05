//! Reading, writing, and validation of AFF4 forensic evidence containers.
//!
//! This crate is the authoritative implementation; the `aff4tools` binary is a
//! thin command-line layer over it.
//!
//! # Never alter evidence
//!
//! [`mod@write`] is the only module permitted to create files, and every write goes
//! through `write::sink`. Acquisition sources and containers being inspected are
//! never written to. See that module and `write::guard` for how it is enforced.
//!
//! # Errors are values
//!
//! Nothing here prints or terminates the process. Every fallible operation
//! returns [`Result`]; presentation is the binary's job. See [`error`] for the
//! failure taxonomy and why [`Error::Unsupported`] must never be reported as
//! damaged evidence.

// One audited exception: `write::device::block_device_size` needs two read-only
// ioctls, because `lseek` returns zero for a block device.
#![deny(unsafe_code)]
// clippy.toml disallows the std::fs mutators and zip::ZipWriter. Denied rather
// than warned so an unaudited write fails the build; `src/write/` opts out at
// each audited site.
#![deny(clippy::disallowed_methods, clippy::disallowed_types)]
// Nothing is swallowed: a discarded Result or a panic on malformed input would
// both violate this crate's contract. Test modules relax these individually.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    unused_must_use
)]
#![warn(missing_docs, clippy::pedantic)]

pub mod arn;
pub mod codec;
pub mod container;
pub mod error;
pub mod export;
pub mod hash;
pub mod image;
pub mod lexicon;
pub mod map;
/// The metadata query surface and its backends (docs/RDF-scalability.md).
pub mod metadata;

pub mod model;
pub mod parallel;
pub mod progress;
pub mod rdf;
/// The conformance rule registry.
pub mod rules;
/// Finding and ordering the parts of a split AFF4 set.
pub mod split_set;
pub mod stream;
pub mod verify;
pub mod version;
pub mod write;
pub mod zip;
pub mod zip_volume_set;

pub use arn::{Arn, ByteRange};
pub use codec::Codec;
pub use container::{ConformanceScan, Container};
pub use error::{
    AFF4_L_STANDARD_NAME, Deviation, DeviationKind, Error, Feature, Locus, NotAff4Reason, Result,
    SPEC_NAME,
};
pub use hash::{Digest, MultiHasher};
pub use image::Image;
pub use lexicon::{Generation, Lexicon};
pub use map::{
    GapFill, GapPolicy, GapSummary, Map, MapEntry, ReadAccounting, SplitLayout, StreamSource,
    Target,
};
pub use model::{
    Aff4Object, BlockHashesInfo, ContainerSummary, EdgeKind, GraphEdge, HashAlgorithm, Locality,
    ManifestDisagreement, ManifestIssue, ObjectCounts, ObjectRole, Property, SegmentSummary,
    StoredHash, VolumeInfo, block_hash_content_algorithm,
};
pub use parallel::{ThreadPlan, cpu_budget};
pub use rdf::{Graph, Statement, Value};
pub use rules::Document;
pub use stream::{ChunkLocation, ChunkReader, ImageStream};
pub use verify::{
    Coverage, Declined, HashCheck, NoProgress, Outcome, Progress, ProgressObserver,
    VerificationReport, VerifyOptions, WorkEstimate, estimate_work, verify_container,
    verify_container_with_progress,
};
pub use version::ContainerVersion;
pub use zip::{ArnSource, ParallelVolume, SegmentReader, Volume, ZipVolume};

/// The version of this crate, as declared in `Cargo.toml`.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Render a byte count with a binary-prefix approximation.
///
/// Shared by the `verify` report, the `info` report, and the progress
/// display, all in the `aff4tools` binary.
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    let mut scaled = value;
    let mut unit = 0;
    while scaled >= 1024.0 && unit < UNITS.len() - 1 {
        scaled /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{scaled:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        assert!(!version().is_empty());
    }

    /// Guards the exact rendering `verify`, `info`, and the progress display
    /// depend on: no scaling below 1024, one decimal place above it.
    #[test]
    fn human_bytes_keeps_small_values_exact() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(3_964_928), "3.8 MiB");
        assert_eq!(human_bytes(268_435_456), "256.0 MiB");
    }
}
