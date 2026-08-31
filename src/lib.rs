//! Read-only inspection and validation of AFF4 forensic evidence containers.
//!
//! This crate is the authoritative implementation of AFF4 handling in this
//! project; the `aff4tools` binary is a thin command-line layer over it.
//!
//! # Read-only
//!
//! aff4tools never modifies evidence: nothing here opens a write handle, and
//! every container is opened through a single [`std::fs::File::open`] call
//! site.
//!
//! This is enforced by the `disallowed-methods` and `disallowed-types` lists in
//! `clippy.toml` — covering the `std::fs` mutators and `zip::ZipWriter` — which
//! the crate-root lints below raise to deny. Note that the `zip` crate compiles
//! its writer unconditionally, so it cannot be excluded via Cargo features;
//! those lists are what keep write code out of this crate.
//!
//! # Errors are values
//!
//! Nothing in this crate prints to stdout or stderr, and nothing terminates the
//! process. Every fallible operation returns [`Result`]; deciding what a user
//! sees is the binary's job. See [`error`] for the failure taxonomy and for why
//! [`Error::Unsupported`] must never be reported as damaged evidence.

// Read-only enforcement. `deny`, with exactly ONE audited exception:
// `write::device::block_device_size` calls two read-only macOS ioctls to learn
// a block device's geometry. The ioctl is required because `lseek` returns
// zero for a block device, so `--device` cannot otherwise learn its size.
//
// `deny` still fails the build on any new `unsafe`, and the single `#[allow]`
// is greppable. If a second exception is ever proposed, that is the moment to
// reconsider a safe wrapper crate instead.
#![deny(unsafe_code)]
// The write-blocking lints are deny, not warn: the disallowed lists in
// clippy.toml (std::fs mutators and zip::ZipWriter) must fail the build rather
// than scroll past in a wall of output. Note the zip crate compiles its writer
// unconditionally, so this list — not Cargo features — is what keeps write
// code out of aff4tools.
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
pub use container::Container;
pub use error::{
    Deviation, DeviationKind, Error, Feature, Locus, NotAff4Reason, Result, SPEC_NAME,
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
/// The exact figure is always shown alongside; this is a reading aid, never a
/// replacement for the real number.
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
