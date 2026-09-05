//! Recalculate a container's hash digests and compare them with recorded values.
//!
//! This is README feature 1. Everything below returns a [`VerificationReport`];
//! nothing here decides an exit code, prints, or stops at the first failure —
//! a report that hid checks after a mismatch would be worse than no report.
//!
//! # A mismatch is not an error
//!
//! [`Outcome::Mismatch`] is a *successful* verification with a negative result.
//! [`Error`] is reserved for containers that could not be read at all. pyaff4's
//! listener raises on mismatch, which conflates the two; here the distinction
//! reaches the exit code, so a script can tell "the evidence does not match" (8)
//! from "the container is damaged" (5).
//!
//! # What AFF4 actually protects an image with
//!
//! Not one digest. A `DiskImage` in the corpus carries only
//! `blockMapHashSHA512`, which sits at the root of a Merkle-style tree:
//!
//! ```text
//! per-chunk MD5/SHA1  ->  .blockHash.md5 / .blockHash.sha1 segments
//!                     ->  SHA512 of each segment      (blockHashesHash)
//!         map, idx, mapPath segments
//!                     ->  SHA512 of each              (mapPointHash, …)
//!                     ->  blockMapHash = SHA512(the five digests concatenated)
//! ```
//!
//! Every construction here was derived and verified byte-for-byte against
//! `Base-Linear.aff4`. Two details a
//! plausible guess gets wrong: `mapHash` concatenates segment **bytes** while
//! `blockMapHash` concatenates raw **digests**, and `mapPathHash` is a fourth
//! input to `blockMapHash` whose omission yields a clean-looking wrong answer.
//!
//! # The linear bitstream hash
//!
//! `aff4:hash` on an `ImageStream` covers the *stored* bytes only — described
//! runs are deliberately excluded, in the AFF4 authors' own terms. So verifying
//! it is not the same as verifying the image, and the report says which is
//! which rather than letting one imply the other.

use std::path::PathBuf;

use crate::arn::Arn;
use crate::error::{Locus, Result};
use crate::hash::{Digest, MultiHasher, digest_of, is_computable};
use crate::image::Image;
use crate::lexicon::Lexicon;
use crate::map::{IDX_SEGMENT, MAP_PATH_SEGMENT, MAP_SEGMENT, ReadAccounting};
use crate::model::{HashAlgorithm, ObjectRole, StoredHash};
use crate::rdf::Graph;
use crate::stream::ImageStream;
use crate::zip::Volume;
use crate::zip_volume_set::PRIMARY;

/// The suffix of a stream's per-chunk hash segment, before the algorithm name.
pub const BLOCK_HASH_SUFFIX: &str = ".blockHash.";

/// Result of a single hash verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Outcome {
    /// Recomputed and matching the recorded hash value.
    Match,
    /// Recomputed and **not** matching the recorded hash value.
    Mismatch,
    /// Not recomputed, with the reason stated.
    NotVerifiable {
        /// Why this digest could not be recomputed.
        reason: String,
        /// Whether the evidence itself could not be read.
        ///
        /// Both kinds print the same way, but they are not the same finding.
        /// [`Declined::Unreadable`] means the container holds a digest over
        /// bytes that could not be retrieved — damage, or a truncated
        /// acquisition. [`Declined::NotSupported`] means the bytes are fine
        /// and this build cannot do the arithmetic. Only the first is a
        /// statement about the evidence, so only the first affects the exit
        /// code.
        cause: Declined,
    },
}

/// Classify a read failure as damaged evidence or an unsupported capability.
///
/// [`Error::Unsupported`] is this build's limit, never the container's fault:
/// a codec recognised but deliberately not decompressed (raw deflate, Rekall
/// snappy) leaves the evidence perfectly intact. Everything else — a failed
/// ZIP checksum, a corrupt compressed stream, an I/O error — means the bytes
/// a digest covers could not be retrieved.
fn classify_read_failure(error: &crate::error::Error) -> Declined {
    match error {
        crate::error::Error::Unsupported { .. } => Declined::NotSupported,
        _ => Declined::Unreadable,
    }
}

/// Why a recorded digest was not recomputed.
///
/// Kept separate from the human-readable reason because an exit code must not
/// be derived by matching on prose: the wording is reviewed and edited, and a
/// classification that changed when a sentence was reworded would be a defect
/// waiting to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Declined {
    /// The evidence bytes could not be retrieved: a segment that would not
    /// decompress, a stream that would not open, a ZIP member that failed its
    /// checksum. A finding about the container's *contents*.
    ///
    /// Not every error qualifies. Metadata that does not describe an image
    /// well enough to read it — a stream declaring no size, an image naming no
    /// `dataStream`, a map whose segments live in a volume that was not
    /// supplied — is a gap in the description, not damaged evidence. A single
    /// stripe of a striped set produces exactly that and is entirely normal,
    /// so those stay [`Declined::NotSupported`] and leave the exit code alone.
    Unreadable,
    /// The container is intact; this build cannot compute the digest, or the
    /// value's input is not defined well enough to recompute. A statement
    /// about the tool, never about the evidence.
    NotSupported,
}

impl Outcome {
    /// Whether this outcome is a mismatch.
    #[must_use]
    pub fn is_mismatch(&self) -> bool {
        matches!(self, Self::Mismatch)
    }

    /// Whether a digest was actually recomputed and compared.
    #[must_use]
    pub fn was_checked(&self) -> bool {
        matches!(self, Self::Match | Self::Mismatch)
    }
}

/// What a digest is a digest *of*.
///
/// The distinction an examiner needs: a matching `aff4:hash` on an `ImageStream`
/// says the stored bytes are intact, which is not the same claim as the image
/// being intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Coverage {
    /// The stored bytes of an `ImageStream`, excluding described runs.
    StoredStream,
    /// Every byte of the image as an examiner would see it, described runs included.
    WholeImage,
    /// The bytes of one segment, e.g. `map` or `idx`.
    Segment,
    /// A construction over other digests rather than over evidence bytes.
    Composite,
    /// One chunk of a stream, against its recorded per-chunk digest.
    Block,
    /// A recorded digest whose input this build has not identified.
    Unidentified,
}

impl Coverage {
    /// A short phrase for a report.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::StoredStream => "the stream's stored bytes",
            Self::WholeImage => "the whole image, stored and described",
            Self::Segment => "one segment's bytes",
            Self::Composite => "a construction over other digests",
            Self::Block => "one chunk",
            Self::Unidentified => "an input aff4tools has not identified",
        }
    }
}

/// One digest, recomputed and compared.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HashCheck {
    /// The object the digest belongs to.
    pub subject: Arn,
    /// What kind of object that is.
    pub role: ObjectRole,
    /// The predicate the digest was recorded under, e.g. `hash`, `mapHash`.
    pub predicate: String,
    /// The algorithm named by the recorded digest's datatype.
    pub algorithm: HashAlgorithm,
    /// What the digest covers.
    pub coverage: Coverage,
    /// The digest the container recorded, at full length.
    pub expected: String,
    /// The digest recomputed here, at full length, or empty if not recomputed.
    pub actual: String,
    /// The conclusion.
    pub outcome: Outcome,
    /// How many digests this one check covers, when it covers many.
    ///
    /// A [`Coverage::Block`] check compares a whole sequence of per-chunk
    /// digests — hundreds of thousands on a large container — as a single
    /// check. Carried as a number rather than left inside `expected`'s text so
    /// a summary can total the work without parsing prose. `None` for a check
    /// over one recorded value.
    pub digests_covered: Option<usize>,
}

impl HashCheck {
    /// Build a check by comparing a computed digest against a recorded one.
    fn compared(
        subject: &Arn,
        role: ObjectRole,
        stored: &StoredHash,
        coverage: Coverage,
        computed: &Digest,
    ) -> Self {
        Self {
            subject: subject.clone(),
            role,
            predicate: stored.predicate.clone(),
            algorithm: stored.algorithm.clone(),
            coverage,
            expected: stored.hex.clone(),
            actual: computed.hex().to_owned(),
            outcome: if computed.matches(stored) {
                Outcome::Match
            } else {
                Outcome::Mismatch
            },
            digests_covered: None,
        }
    }

    /// Build a check that was not run because this build cannot run it.
    ///
    /// For a digest whose input is undefined or whose algorithm is unsupported
    /// — never for evidence that could not be read. Use
    /// [`HashCheck::unreadable`] for that.
    fn declined(
        subject: &Arn,
        role: ObjectRole,
        stored: &StoredHash,
        coverage: Coverage,
        reason: impl Into<String>,
    ) -> Self {
        Self::not_recomputed(
            subject,
            role,
            stored,
            coverage,
            reason,
            Declined::NotSupported,
        )
    }

    /// Build a check that was not run because a read failed, classifying the
    /// failure by its error: unsupported capability, or unreadable evidence.
    ///
    /// Prefer this wherever the [`crate::error::Error`] is in hand — deciding
    /// from the error is what keeps a declined codec (this build's limit) from
    /// being reported as damaged evidence.
    fn from_read_error(
        subject: &Arn,
        role: ObjectRole,
        stored: &StoredHash,
        coverage: Coverage,
        reason: impl Into<String>,
        error: &crate::error::Error,
    ) -> Self {
        Self::not_recomputed(
            subject,
            role,
            stored,
            coverage,
            reason,
            classify_read_failure(error),
        )
    }

    /// Build a check that was not run because the evidence could not be read.
    ///
    /// A finding about the container, not about this build: something the
    /// container declares a digest over could not be retrieved.
    fn unreadable(
        subject: &Arn,
        role: ObjectRole,
        stored: &StoredHash,
        coverage: Coverage,
        reason: impl Into<String>,
    ) -> Self {
        Self::not_recomputed(
            subject,
            role,
            stored,
            coverage,
            reason,
            Declined::Unreadable,
        )
    }

    /// Shared construction for both not-recomputed kinds.
    fn not_recomputed(
        subject: &Arn,
        role: ObjectRole,
        stored: &StoredHash,
        coverage: Coverage,
        reason: impl Into<String>,
        cause: Declined,
    ) -> Self {
        Self {
            subject: subject.clone(),
            role,
            predicate: stored.predicate.clone(),
            algorithm: stored.algorithm.clone(),
            coverage,
            expected: stored.hex.clone(),
            actual: String::new(),
            outcome: Outcome::NotVerifiable {
                reason: reason.into(),
                cause,
            },
            digests_covered: None,
        }
    }
}

/// Everything verification concluded about one container.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationReport {
    /// The container's path.
    pub source_path: std::path::PathBuf,
    /// Every check, in the order performed.
    pub checks: Vec<HashCheck>,
    /// The composition of the bytes read, per image verified.
    pub read_accounting: Vec<ImageAccounting>,
    /// Things worth telling the examiner that are not check results — a stream
    /// whose codec is declined, an image whose map could not be resolved.
    pub notes: Vec<String>,
    /// Whether per-chunk block hashes were actually recomputed.
    ///
    /// Recorded explicitly so a report can never imply coverage it doesn't have.
    pub block_hashes_verified: bool,
}

/// How much of one image was stored against described.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImageAccounting {
    /// The image verified.
    pub image: Arn,
    /// The composition of the image's address space.
    pub accounting: ReadAccounting,
    /// Whether these figures come from an actual traversal.
    ///
    /// `false` means they were derived from the map's entries without reading
    /// the image — accurate about composition, but no claim that the bytes were
    /// produced. A report must not present the two as the same thing.
    pub traversed: bool,
}

impl VerificationReport {
    /// Whether any recomputed digest failed to match.
    #[must_use]
    pub fn has_mismatch(&self) -> bool {
        self.checks.iter().any(|c| c.outcome.is_mismatch())
    }

    /// How many digests were actually recomputed and compared.
    #[must_use]
    pub fn checked_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.outcome.was_checked())
            .count()
    }

    /// How many digests matched.
    #[must_use]
    pub fn match_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.outcome == Outcome::Match)
            .count()
    }

    /// How many were recorded but not recomputed.
    #[must_use]
    pub fn not_verifiable_count(&self) -> usize {
        self.checks.len() - self.checked_count()
    }

    /// How many single recorded digest values were recomputed and compared.
    ///
    /// The number an examiner sees in `info`: one per `aff4:hash` (and kin)
    /// recorded in the Turtle. Excludes [`Coverage::Block`] checks, which
    /// compare a sequence of per-chunk digests rather than one recorded value
    /// — counting those here is what made a report of four recorded digests
    /// look inconsistent with six checks.
    #[must_use]
    pub fn recorded_value_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.outcome.was_checked() && c.digests_covered.is_none())
            .count()
    }

    /// How many per-chunk digests were recomputed and compared in total.
    ///
    /// Summed across every [`Coverage::Block`] check, so two algorithms over
    /// the same chunks count twice: each is a digest that was computed and
    /// compared.
    #[must_use]
    pub fn chunk_digest_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.outcome.was_checked())
            .filter_map(|c| c.digests_covered)
            .sum()
    }

    /// How many were not recomputed because the evidence could not be read.
    ///
    /// A subset of [`Self::not_verifiable_count`]. The rest are digests this
    /// build cannot compute, which says nothing about the container.
    #[must_use]
    pub fn unreadable_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| {
                matches!(
                    c.outcome,
                    Outcome::NotVerifiable {
                        cause: Declined::Unreadable,
                        ..
                    }
                )
            })
            .count()
    }

    /// Whether any recorded digest covers bytes that could not be read.
    ///
    /// Distinct from [`Self::has_mismatch`]: a mismatch says the evidence does
    /// not match its digests, this says the question could not be asked. Both
    /// are findings; neither may be reported as a clean verification.
    #[must_use]
    pub fn has_unreadable(&self) -> bool {
        self.unreadable_count() > 0
    }
}

/// Progress line information.
///
/// The library doesn't print to stdout. It emits these, and the caller decides what
/// a user sees. Events are emitted **unthrottled**, once per delivered chunk
/// for [`Progress::Bytes`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Progress<'a> {
    /// Work has begun on an object.
    ObjectStarted {
        /// The object being verified.
        arn: &'a Arn,
        /// What kind of object it is.
        role: &'a ObjectRole,
        /// How many bytes will be read, where that is known in advance.
        total_bytes: Option<u64>,
    },
    /// Bytes have been read for the object in progress.
    Bytes {
        /// The object being verified.
        arn: &'a Arn,
        /// Bytes delivered so far, monotonically increasing.
        done: u64,
        /// The expected total, where known.
        total: Option<u64>,
    },
    /// A bevy has been fully delivered to the digest.
    ///
    /// Reported alongside bytes because the bevy count is a figure an examiner
    /// can check against the container's own structure: `info` states how many
    /// bevies a stream holds, and a run naming the same number has covered all
    /// of it. A byte total alone cannot be checked that way.
    BevyCompleted {
        /// The stream being read.
        arn: &'a Arn,
        /// Bevies delivered so far, in stream order.
        done: u64,
        /// How many the stream declares.
        total: u64,
    },
    /// A digest has been recomputed and compared.
    ///
    /// Emitted as it lands, so a long run can report each result rather than
    /// withholding every one until the end.
    CheckCompleted {
        /// The finished check.
        check: &'a HashCheck,
    },
    /// Work on an object is finished.
    ObjectFinished {
        /// The object just verified.
        arn: &'a Arn,
    },
}

/// Receives [`Progress`] events during verification.
///
/// Blanket-implemented for closures, so a caller can pass one directly.
pub trait ProgressObserver {
    /// Handle one event. Must not panic: it runs inside the read loop.
    fn on(&mut self, event: Progress<'_>);
}

impl<F: FnMut(Progress<'_>)> ProgressObserver for F {
    fn on(&mut self, event: Progress<'_>) {
        self(event);
    }
}

/// A [`ProgressObserver`] that discards everything.
///
/// What [`verify_container`] uses, so callers that do not want progress pay
/// nothing but an empty call.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProgress;

impl ProgressObserver for NoProgress {
    fn on(&mut self, _event: Progress<'_>) {}
}

/// What verification will have to read, computed before it starts.
///
/// Lets a caller warn that a run will take minutes rather than leaving the user
/// to guess. Every figure comes from metadata already parsed, so producing this
/// costs no I/O.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WorkEstimate {
    /// Bytes that will be decompressed and hashed.
    pub bytes_to_read: u64,
    /// Bytes that will actually come off the disk.
    ///
    /// The stored size of every bevy, which is what the I/O cost is a function
    /// of. On a barely-compressible image this is close to `bytes_to_read`; on
    /// a sparse one it can be a small fraction, and predicting a duration from
    /// the decompressed figure would then be badly wrong.
    pub bytes_on_disk: u64,
    /// How many bevies those bytes span.
    pub bevies: u64,
    /// The codecs involved, for a caller that wants to name them.
    pub codecs: Vec<String>,
    /// Whether per-chunk block hashes were requested, which adds two digests
    /// per chunk over the same data.
    pub block_hashes: bool,
    /// What will be verified, per stream, in the order the streams are read.
    pub streams: Vec<StreamPlan>,
    /// How the run will be parallelised.
    pub threads: crate::parallel::ThreadPlan,
}

/// What verification will do to one image stream.
///
/// Built before any data is read, so a caller can say up front which digests
/// will be recomputed and which recorded values will go unchecked. A run that
/// silently skips a digest is worse than one that says it will.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamPlan {
    /// The stream being read.
    pub arn: Arn,
    /// Decompressed bytes in this stream.
    pub size: u64,
    /// The codec its bevies are compressed with.
    pub codec: String,
    /// Algorithms recomputed over the whole stream, from its `aff4:hash`
    /// values. These are the acquisition hashes.
    pub linear: Vec<HashAlgorithm>,
    /// Recorded digests that will *not* be recomputed, with the reason.
    ///
    /// Named up front rather than discovered in the report, so "verified" is
    /// never read as covering more than it does.
    pub not_recomputed: Vec<(String, String)>,
    /// Per-chunk algorithms that will be checked against block-hash segments.
    ///
    /// Empty when the stream stores none, in which case block hashing adds no
    /// work and no coverage for this stream.
    pub block_hashes: Vec<HashAlgorithm>,
}

impl WorkEstimate {
    /// Whether there is enough work here to be worth warning about.
    ///
    /// One gibibyte is the threshold: below it a run finishes in seconds and a
    /// warning is noise.
    #[must_use]
    pub fn is_substantial(&self) -> bool {
        self.bytes_to_read >= 1024 * 1024 * 1024
    }
}

/// What to verify.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// Recompute every chunk's MD5 and SHA-1 against the block-hash segments.
    /// On by default.
    pub block_hashes: bool,
}

impl Default for VerifyOptions {
    /// Block hashing on; see [`VerifyOptions::block_hashes`].
    fn default() -> Self {
        Self { block_hashes: true }
    }
}

/// Report under construction, plus wherever progress is going.
///
/// Bundled so that pushing a check and announcing it cannot drift apart: every
/// completed check is emitted as it lands, which is what lets a caller show
/// results during a run rather than only at the end.
struct Session<'o> {
    report: VerificationReport,
    progress: &'o mut dyn ProgressObserver,
}

impl Session<'_> {
    /// Record a finished check and announce it.
    fn push(&mut self, check: HashCheck) {
        self.progress.on(Progress::CheckCompleted { check: &check });
        self.report.checks.push(check);
    }

    /// Record something worth saying that is not a check result.
    fn note(&mut self, note: String) {
        self.report.notes.push(note);
    }
}

/// Verify every image, stream, and map a container describes.
///
/// # Errors
///
/// [`Error::Malformed`] or [`Error::Io`] if the container cannot be read at
/// all. A digest that does not match is **not** an error — it is a
/// [`HashCheck`] with [`Outcome::Mismatch`].
pub fn verify_container(
    container: &mut crate::container::Container,
    options: VerifyOptions,
) -> Result<VerificationReport> {
    verify_container_with_progress(container, options, &mut NoProgress)
}

/// Verify a container, reporting progress as the work proceeds.
///
/// Identical to [`verify_container`] except that `progress` is told what is
/// happening. Use this for anything that might take minutes — a large
/// container is minutes of decompression, and silence is indistinguishable
/// from a hang.
///
/// # Errors
///
/// As [`verify_container`]. A digest that does not match is **not** an error.
pub fn verify_container_with_progress(
    container: &mut crate::container::Container,
    options: VerifyOptions,
    progress: &mut dyn ProgressObserver,
) -> Result<VerificationReport> {
    let path = container.volume().path().to_path_buf();
    let locus = Locus::new(&path);
    let graph = container.graph()?;
    let lexicon = container.lexicon();

    // Every volume's declarations, not just the primary's. In a striped set a
    // sibling's stream records its digests only in the volume holding the data;
    // reading the primary's view alone would skip them silently (decision 35).
    let objects = container.objects_across_volumes()?;

    let mut session = Session {
        report: VerificationReport {
            source_path: path,
            checks: Vec::new(),
            read_accounting: Vec::new(),
            notes: Vec::new(),
            // Set from the checks once the run is over — see the field's docs.
            // Nothing has been hashed yet, so the only honest value here is
            // false.
            block_hashes_verified: false,
        },
        progress,
    };

    // A striped container needs the whole set, since a stream's data and its
    // metadata may live in different files. Single-volume containers — every
    // other case — take the same path with a set of one.
    let striped = container.volumes().len() > 1;

    // Prepare the whole-image digest to ride the stream passes, where the
    // container's shape allows it. `prepare` refuses whenever image order and
    // part order might differ, leaving that image its own traversal.
    let mut fused =
        prepare_fused_image(&objects, container, lexicon, &locus, striped, &mut session);

    for object in &objects {
        let announced = matches!(object.role, ObjectRole::ImageStream) || object.role.is_image();
        if announced {
            session.progress.on(Progress::ObjectStarted {
                arn: &object.arn,
                role: &object.role,
                total_bytes: object.size,
            });
        }

        // The image the fused traversal is computing takes its result from
        // that traversal rather than driving one of its own.
        let owns_fused = fused
            .as_ref()
            .is_some_and(|f| f.arn.as_str() == object.arn.as_str());
        if owns_fused {
            let covered = fused
                .take()
                .is_some_and(|fused| fused.finish(&locus, &mut session));
            if covered {
                // The traversal reported every digest it carried. What it never
                // carries is still owed: `blockMapHash` is a construction over
                // the map's own segments rather than a pass over the address
                // space, and an algorithm this build cannot compute is declined
                // without reading. Both are what `verify_image_in_set` would
                // have done for these hashes.
                for hash in &object.hashes {
                    if hash.algorithm == HashAlgorithm::BlockMapSha512 {
                        verify_striped_block_map_hash(
                            object,
                            container.volumes_mut(),
                            hash,
                            &mut session,
                        );
                    } else if !is_computable(&hash.algorithm) {
                        session.push(HashCheck::declined(
                            &object.arn,
                            object.role.clone(),
                            hash,
                            Coverage::WholeImage,
                            format!("this build cannot compute {}", hash.algorithm),
                        ));
                    }
                }
            } else {
                // The traversal could not cover the image and reported no
                // digest from it. The ordinary path checks everything this
                // image records — including the two kinds above — so it is
                // taken whole rather than in part, which is also what keeps
                // `blockMapHash` from being checked twice.
                verify_object(
                    object,
                    container,
                    &graph,
                    lexicon,
                    &locus,
                    options,
                    striped,
                    None,
                    &mut session,
                );
            }
        } else {
            verify_object(
                object,
                container,
                &graph,
                lexicon,
                &locus,
                options,
                striped,
                fused.as_mut(),
                &mut session,
            );
        }

        if announced {
            session
                .progress
                .on(Progress::ObjectFinished { arn: &object.arn });
        }
    }

    // Derived from the work done, not from the option that asked for it. A
    // container storing no block-hash segments produces no Coverage::Block
    // check, so the closing coverage statement cannot claim the leaves were
    // checked when nothing was there to check.
    session.report.block_hashes_verified = session
        .report
        .checks
        .iter()
        .any(|check| check.coverage == Coverage::Block && check.outcome.was_checked());

    Ok(session.report)
}

/// Prepare a whole-image digest to ride the stream passes, if one can.
///
/// Returns the fused traversal for the single image whose plain digests it will
/// compute. Anything it refuses — a striped set, a map whose order does not
/// match part order, more than one image — simply gets no fused traversal, and
/// verification proceeds exactly as it did in Phase A.
///
/// Only a set is considered. A single-volume container already reads each
/// stored byte once per consumer with no cross-part coordination to gain, and
/// its images include AFF4-L logical forms whose bytes are a ZIP member rather
/// than a map.
fn prepare_fused_image(
    objects: &[crate::model::Aff4Object],
    container: &mut crate::container::Container,
    lexicon: &Lexicon,
    locus: &Locus,
    striped: bool,
    session: &mut Session,
) -> Option<FusedImage> {
    if !striped {
        return None;
    }

    // Exactly one image, or the streams cannot be attributed to a single
    // traversal without deciding which image gets them.
    let mut images = objects.iter().filter(|o| o.role.is_image());
    let object = images.next()?;
    if images.next().is_some() {
        return None;
    }

    // Only digests computed over the image's bytes ride the traversal.
    // `blockMapHash` is built from the map's own segments and keeps its own
    // path, as does anything this build cannot compute.
    let hashes: Vec<&StoredHash> = object
        .hashes
        .iter()
        .filter(|h| h.algorithm != HashAlgorithm::BlockMapSha512 && is_computable(&h.algorithm))
        .collect();
    if hashes.is_empty() {
        return None;
    }

    let image = Image::open_in_set(&object.arn, container.volumes_mut(), lexicon, locus).ok()?;
    let fused = FusedImage::prepare(object, &image, &hashes, locus)?;

    // The map's holes, which are legal but never silent: the filled bytes were
    // not recorded by the acquisition, so any digest over this image covers
    // content the spec supplied rather than content the imager measured. Said
    // here because the fused traversal replaces the call that would have said
    // it, and it costs nothing — it comes from the entries, not from reading.
    //
    // The read accounting is deliberately **not** stated here. `finish` pushes
    // the traversed figures when the pass covers the image, and the fallback
    // path states its own; emitting a third from here would list the same image
    // twice on a fallback, which is the duplicate an examiner cannot interpret.
    if let Some(deviation) = image.gap_deviation(locus, records_whole_image_digest(object)) {
        session.note(deviation.detail.clone());
    }

    Some(fused)
}

/// Verify one object, reading it from the volume that owns it.
///
/// Split out of the dispatch loop so each role's volume-selection reasoning
/// sits next to the call it governs.
#[allow(clippy::too_many_arguments)]
fn verify_object(
    object: &crate::model::Aff4Object,
    container: &mut crate::container::Container,
    graph: &Graph,
    lexicon: &Lexicon,
    locus: &Locus,
    options: VerifyOptions,
    striped: bool,
    fused: Option<&mut FusedImage>,
    session: &mut Session,
) {
    match object.role {
        ObjectRole::ImageStream => {
            // Read this stream from whichever volume holds its bevies, and
            // read its *declaration* from the same volume. The primary's
            // graph holds only a stub for a sibling's stream, so passing
            // the primary's graph here would fail on the absent `size`.
            let held = container.volumes().holding(&object.arn).cloned();
            match &held {
                Some(volume_arn) => {
                    // Split the borrow: the graph and the volume come from
                    // the same set, so take them together.
                    if let Some((volume, stream_graph)) =
                        container.volumes_mut().volume_and_graph_mut(volume_arn)
                    {
                        verify_stream(
                            object,
                            volume,
                            stream_graph,
                            lexicon,
                            locus,
                            options,
                            fused,
                            session,
                        );
                    }
                }
                None => verify_stream(
                    object,
                    container.volumes_mut().primary_mut(),
                    graph,
                    lexicon,
                    locus,
                    options,
                    fused,
                    session,
                ),
            }
        }
        ObjectRole::Map => {
            // A map's segments live beside the volume that declares it.
            let owner = container.volumes().declaring_volume(&object.arn).cloned();
            let volume = match &owner {
                Some(arn) => container.volumes_mut().get_mut(arn),
                None => Some(container.volumes_mut().primary_mut()),
            };
            if let Some(volume) = volume {
                verify_map(object, volume, session);
            }
        }
        ObjectRole::BlockHashes => {
            // Every stripe stores every stream's block-hash segments, so
            // the primary usually has them — but a set whose primary does
            // not must still find them rather than declining.
            let owner = container
                .volumes()
                .holding_block_hashes(&object.arn)
                .cloned();
            let volume = match &owner {
                Some(arn) => container.volumes_mut().get_mut(arn),
                None => Some(container.volumes_mut().primary_mut()),
            };
            if let Some(volume) = volume {
                verify_block_hash_segment(object, volume, session);
            }
        }
        _ if object.role.is_image() => {
            if striped {
                verify_image_in_set(
                    object,
                    container.volumes_mut(),
                    lexicon,
                    locus,
                    options,
                    session,
                );
            } else {
                verify_image(
                    object,
                    container.volume_mut(),
                    graph,
                    lexicon,
                    locus,
                    options,
                    session,
                );
            }
        }
        _ => {}
    }
}

/// Open a stream against the graph of the volume that declares it.
///
/// A sibling's stream is only a stub in the primary's graph — no `size` — so
/// opening it there fails, and a caller that treats failure as "nothing to
/// count" then drops it in silence. That is how eight parts of nine vanished
/// from the work estimate: the same assumption already corrected in
/// `verify_stream`.
fn open_declared_stream(
    object: &crate::model::Aff4Object,
    container: &mut crate::container::Container,
    holding: Option<&Arn>,
    graph: &Graph,
    lexicon: &Lexicon,
    locus: &Locus,
) -> Option<ImageStream> {
    match holding {
        Some(volume_arn) => container
            .volumes_mut()
            .volume_and_graph_mut(volume_arn)
            .and_then(|(_, stream_graph)| {
                ImageStream::open(&object.arn, stream_graph, lexicon, locus).ok()
            }),
        None => ImageStream::open(&object.arn, graph, lexicon, locus).ok(),
    }
}

/// Which per-chunk algorithms this stream has segments to compare against.
///
/// Without them block hashing adds neither work nor coverage, and saying so up
/// front is more useful than an unexplained absence in the report.
fn block_hash_algorithms(
    object: &crate::model::Aff4Object,
    volume: &dyn Volume,
    volume_arn: &Arn,
    options: VerifyOptions,
) -> Vec<HashAlgorithm> {
    let mut block = Vec::new();
    if options.block_hashes
        && let Some(base) = object.arn.member_name(volume_arn)
    {
        for (suffix, algorithm) in [("md5", HashAlgorithm::Md5), ("sha1", HashAlgorithm::Sha1)] {
            if !block_hash_segments(volume, &base, suffix).is_empty() {
                block.push(algorithm);
            }
        }
    }
    block
}

/// Estimate what verifying this container will require, without reading data.
///
/// Every figure comes from metadata already parsed, so this costs no I/O. Use
/// it to warn before a long run rather than leaving the user to guess.
///
/// # Errors
///
/// Propagates a failure to read or parse the container's metadata.
pub fn estimate_work(
    container: &mut crate::container::Container,
    options: VerifyOptions,
) -> Result<WorkEstimate> {
    let locus = Locus::new(container.volume().path());
    let graph = container.graph()?;
    let lexicon = container.lexicon();

    // Every volume's streams, not just the primary's. A split set's parts each
    // declare their own stream, so estimating from the primary alone described
    // one part of nine: the run then read 14.9 GiB against a 4.1 GiB total and
    // the meter reported 250%. `objects_across_volumes` short-circuits to the
    // summary for a single-volume container, so that case costs nothing new,
    // and the whole estimate remains metadata-only — no bevy is read here.
    let objects = container.objects_across_volumes()?;

    let mut estimate = WorkEstimate {
        block_hashes: options.block_hashes,
        ..WorkEstimate::default()
    };

    for object in &objects {
        let is_stream =
            matches!(object.role, ObjectRole::ImageStream) || declares_type(object, "ImageStream");
        if !is_stream {
            continue;
        }
        // A stream is read when it carries a digest OR when its block hashes
        // will be recomputed. A part of a split set records no `aff4:hash` of
        // its own — one digest describes the whole image stream and lives in
        // part 001 — so testing for a digest alone estimated
        // zero bytes for an entire split set, and the run then announced
        // nothing about what it was about to cost. Mirrors the same correction
        // made in `verify_stream`.
        let has_digest = object.hashes.iter().any(|h| h.predicate == "hash");
        if !has_digest && !options.block_hashes {
            continue;
        }
        let holding = container.volumes().holding(&object.arn).cloned();
        let Some(stream) =
            open_declared_stream(object, container, holding.as_ref(), &graph, lexicon, &locus)
        else {
            continue;
        };

        estimate.bytes_to_read = estimate.bytes_to_read.saturating_add(stream.size());
        estimate.bevies = estimate.bevies.saturating_add(stream.bevy_count());

        let codec = stream.codec().name().to_owned();
        if !estimate.codecs.contains(&codec) {
            estimate.codecs.push(codec);
        }

        // The volume that actually holds this stream's bevies, not the
        // primary. In a split set part 002's segments are not members of part
        // 001, so asking the primary about them found nothing and reported zero
        // stored bytes for eight parts of nine.
        let volume_arn = holding
            .clone()
            .unwrap_or_else(|| container.volume().arn().clone());
        let volume = match &holding {
            Some(arn) => container.volumes_mut().get_mut(arn),
            None => None,
        };
        let volume: &dyn Volume = match volume {
            Some(volume) => volume,
            None => container.volume(),
        };

        // What the bevies occupy on disk, which is what the read will cost.
        let bevy_names: Vec<String> = (0..stream.bevy_count())
            .filter_map(|index| stream.bevy_name(&volume_arn, index))
            .collect();
        estimate.bytes_on_disk = estimate
            .bytes_on_disk
            .saturating_add(volume.stored_bytes(&bevy_names));

        let block = block_hash_algorithms(object, volume, &volume_arn, options);

        let mut linear = Vec::new();
        let mut not_recomputed = Vec::new();
        for hash in &object.hashes {
            if hash.predicate == "hash" {
                if is_computable(&hash.algorithm) {
                    linear.push(hash.algorithm.clone());
                } else {
                    not_recomputed.push((
                        hash.predicate.clone(),
                        format!("{} is not implemented in this build", hash.algorithm),
                    ));
                }
            } else if hash.predicate == "imageStreamHash" {
                not_recomputed.push((
                    hash.predicate.clone(),
                    "its input has not been identified".to_owned(),
                ));
            }
        }

        estimate.streams.push(StreamPlan {
            arn: object.arn.clone(),
            size: stream.size(),
            codec: stream.codec().name().to_owned(),
            linear,
            not_recomputed,
            block_hashes: block,
        });
    }

    estimate_segment_stored(&objects, container, &mut estimate);

    // Streams are read one after another, so the run's peak cost is the widest
    // single stream rather than the sum. `MultiHasher` starts one thread per
    // algorithm once a stream records more than one, and those threads are
    // counted in this plan: a container recording five digests starts five.
    //
    // Both populations, not just streams. A traversal happens per stream AND
    // per image, and the image's digests come from its own object rather than
    // from any `StreamPlan` — sampling streams alone would report no digest
    // threads for a container whose image records several.
    let widest_stream = estimate.streams.iter().map(|s| s.linear.len()).max();
    let widest_image = objects
        .iter()
        .filter(|o| o.role.is_image())
        .map(|o| {
            o.hashes
                .iter()
                .filter(|h| {
                    h.algorithm != HashAlgorithm::BlockMapSha512
                        && crate::hash::is_computable(&h.algorithm)
                })
                .count()
        })
        .max();
    let widest = widest_stream
        .into_iter()
        .chain(widest_image)
        .max()
        .unwrap_or(0);
    estimate.threads = estimate.threads.with_digest_threads(widest);

    Ok(estimate)
}

/// Add the data stored as plain ZIP members to a work estimate.
///
/// An AFF4-L container stores a small file as one ZIP segment rather than as an
/// image stream, and `verify_zip_segment_image` reads every byte of it. Counting
/// only streams therefore described a fraction of the run: on a 4.4 GiB logical
/// container the meter announced a 3.3 GiB total and then read past it, because
/// segment-stored files were work the estimate never admitted existed. The same
/// assumption the split-set correction fixed for volumes, here for storage
/// form.
///
/// Metadata only, like the rest of the estimate: `uncompressed_bytes` reads the
/// central directory entry, never the member.
fn estimate_segment_stored(
    objects: &[crate::model::Aff4Object],
    container: &crate::container::Container,
    estimate: &mut WorkEstimate,
) {
    let volume_arn = container.volume().arn().clone();
    let volume = container.volume();

    for object in objects {
        if !object.role.is_image() || !is_zip_segment(object) {
            continue;
        }
        let Some(member) = object.arn.member_name(&volume_arn) else {
            continue;
        };
        // Both spellings, for the same reason `verify_zip_segment_image` tries
        // both: pyaff4 writes legal characters unescaped.
        let found = if volume.uncompressed_bytes(&member).is_some() {
            Some(member)
        } else {
            let unescaped = crate::arn::unescape(&member);
            volume.uncompressed_bytes(&unescaped).map(|_| unescaped)
        };
        let Some(name) = found else { continue };
        let Some(size) = volume.uncompressed_bytes(&name) else {
            continue;
        };
        estimate.bytes_to_read = estimate.bytes_to_read.saturating_add(size);
        estimate.bytes_on_disk = estimate
            .bytes_on_disk
            .saturating_add(volume.stored_bytes(std::slice::from_ref(&name)));
    }
}

/// Read a stream in full. Parallelize when possible.
fn read_stream(
    stream: &ImageStream,
    volume: &mut crate::zip::ZipVolume,
    plan: crate::parallel::ThreadPlan,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    on_bevy: &mut dyn FnMut(u64),
    locus: &Locus,
) -> Result<()> {
    if plan.is_parallel() && !crate::parallel::too_small_to_parallelise(stream.bevy_count()) {
        crate::parallel::read_all_parallel(stream, volume, plan, sink, on_bevy, locus)
    } else {
        stream.read_all_observed(volume, sink, on_bevy, locus)
    }
}

/// A hasher whose threads are inside the run's reported budget.
///
/// `MultiHasher` starts one thread per algorithm once there is more than one.
/// They are counted in `ThreadPlan`: a container recording five digests starts
/// five, and a total that omitted them would call itself a capped run while
/// exceeding the cap. Algorithms beyond the cap are
/// hashed on the calling thread rather than skipped: staying within a budget
/// must never cost a comparison.
fn budgeted_hasher(algorithms: &[HashAlgorithm]) -> (MultiHasher, crate::parallel::ThreadPlan) {
    let plan = crate::parallel::ThreadPlan::for_host().with_digest_threads(algorithms.len());
    let hasher = MultiHasher::with_thread_cap(algorithms, plan.digesters);
    (hasher, plan)
}

/// The whole-image digest, computed from the stream passes instead of its own.
///
/// Traversing a split set twice over — once per part to check that part's
/// stored bytes, then once more through the map to compute the image's digest
/// — reads the same bytes for both. The bytes are identical — only the consumer differs — so a nine-part
/// set would decompress 14.9 GiB twice to learn two things about the same data.
///
/// This rides the stream passes instead. Each part's traversal feeds its
/// decompressed chunks here as well as to that part's own consumers, and the
/// described runs between them are reconstructed from the map at the boundaries
/// where they belong.
///
/// Only eligible when image order and part order coincide — see
/// [`FusedImage::prepare`], which refuses rather than guesses.
struct FusedImage {
    /// The image being computed.
    arn: Arn,
    /// Its role, for the checks this produces.
    role: ObjectRole,
    /// The recorded digests this traversal will satisfy.
    hashes: Vec<StoredHash>,
    /// The hasher, fed in image address order.
    hasher: MultiHasher,
    /// Every run in image order, walked as the streams arrive.
    runs: Vec<crate::map::ImageRun>,
    /// The map, for reconstructing described runs.
    map: crate::map::Map,
    /// How far through `runs` the traversal has advanced.
    position: usize,
    /// What has been delivered, stored against described.
    accounting: ReadAccounting,
    /// The image's declared size, for the closing check.
    size: u64,
    /// Set when a described run could not be reconstructed; reported at finish.
    failure: Option<String>,
}

/// What a stream pass must do for the fused image, decided before it starts.
enum FusedRole {
    /// This stream contributes no bytes to the fused traversal.
    None,
    /// Feed every chunk to the image hasher as well.
    Feeding,
}

impl FusedImage {
    /// Prepare a fused traversal, or refuse if the ordering cannot be trusted.
    ///
    /// Returns `None` whenever the fused path would have to guess. Every
    /// refusal leaves the caller on the Phase A behavior — a separate image
    /// traversal — which is slower and always correct. A wrong digest is far
    /// worse than a slow one.
    fn prepare(
        object: &crate::model::Aff4Object,
        image: &Image,
        hashes: &[&StoredHash],
        locus: &Locus,
    ) -> Option<Self> {
        // Striped sets interleave streams through the address space, so part
        // order is not image order and feeding bytes as the parts arrive would
        // produce a confidently wrong digest. Out of scope by design.
        if matches!(image.map().split_layout(), crate::map::SplitLayout::Striped) {
            return None;
        }

        let runs = image.map().runs(locus).ok()?;

        // Each stored stream must appear in exactly one contiguous run of
        // entries, and that run must cover the stream from 0 to its declared
        // size in ascending order. That is what makes "the next chunk of this
        // stream" the same thing as "the next stored bytes the image wants".
        let mut seen: Vec<&Arn> = Vec::new();
        let mut expected: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        for run in &runs {
            let crate::map::ImageRun::Stored {
                stream,
                target_offset,
                length,
            } = run
            else {
                continue;
            };
            if seen.last().map(|a: &&Arn| a.as_str()) != Some(stream.as_str()) {
                // A stream reappearing after another intervened is striping the
                // layout check did not catch.
                if seen.iter().any(|a| a.as_str() == stream.as_str()) {
                    return None;
                }
                seen.push(stream);
            }
            let next = expected.entry(stream.as_str()).or_insert(0);
            if *next != *target_offset {
                return None;
            }
            *next = next.checked_add(*length)?;
        }

        // Every run must end exactly at its stream's declared size: a map
        // covering only part of a stream would leave the pass feeding bytes the
        // image never asked for.
        for stream in image.streams() {
            match expected.get(stream.arn().as_str()) {
                Some(covered) if *covered == stream.size() => {}
                // A stream the map never names contributes nothing, which is
                // fine; one it covers only partly is not.
                None => {}
                Some(_) => return None,
            }
        }

        let algorithms: Vec<HashAlgorithm> = hashes.iter().map(|h| h.algorithm.clone()).collect();
        let (image_hasher, _) = budgeted_hasher(&algorithms);

        Some(Self {
            arn: object.arn.clone(),
            role: object.role.clone(),
            hashes: hashes.iter().map(|h| (*h).clone()).collect(),
            hasher: image_hasher,
            runs,
            map: image.map().clone(),
            position: 0,
            accounting: ReadAccounting {
                gap_fill: image.map().gaps().fill.clone(),
                ..ReadAccounting::default()
            },
            size: image.size(),
            failure: None,
        })
    }

    /// What the stream about to be read owes this traversal.
    ///
    /// Reconstructs every described run standing between the last stored run
    /// and this stream's first, so the hasher receives the image in address
    /// order rather than stored-bytes-only order.
    fn before_stream(&mut self, stream: &Arn, locus: &Locus) -> FusedRole {
        if self.failure.is_some() {
            return FusedRole::None;
        }
        // Nothing may be skipped: if the next stored run is not this stream's,
        // the parts are arriving out of image order and this traversal cannot
        // be trusted. Emit the described runs up to the next stored run, then
        // check whose it is.
        self.emit_described_until_stored(locus);
        match self.runs.get(self.position) {
            Some(crate::map::ImageRun::Stored { stream: next, .. })
                if next.as_str() == stream.as_str() =>
            {
                FusedRole::Feeding
            }
            _ => FusedRole::None,
        }
    }

    /// Reconstruct described runs until the next stored run, or the end.
    fn emit_described_until_stored(&mut self, locus: &Locus) {
        while let Some(run) = self.runs.get(self.position) {
            let crate::map::ImageRun::Described { position } = run else {
                return;
            };
            let position = *position;
            // Split the borrow: `emit_described` reads the map while the sink
            // writes the hasher, and both are fields of `self`.
            let Self { map, hasher, .. } = self;
            let emitted = map.emit_described(
                position,
                &mut |bytes| {
                    hasher.update(bytes);
                    Ok(())
                },
                locus,
            );
            match emitted {
                Ok(accounting) => {
                    self.accounting.described = self
                        .accounting
                        .described
                        .saturating_add(accounting.described);
                    self.accounting.gap_filled = self
                        .accounting
                        .gap_filled
                        .saturating_add(accounting.gap_filled);
                    self.accounting.unknown_placeholder = self
                        .accounting
                        .unknown_placeholder
                        .saturating_add(accounting.unknown_placeholder);
                }
                Err(error) => {
                    self.failure =
                        Some(format!("a described region could not be produced: {error}"));
                    return;
                }
            }
            self.position += 1;
        }
    }

    /// Take this stream's decompressed bytes.
    fn feed(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.accounting.stored = self.accounting.stored.saturating_add(bytes.len() as u64);
    }

    /// Close out the stored run a finished stream pass covered.
    fn after_stream(&mut self) {
        if let Some(crate::map::ImageRun::Stored { .. }) = self.runs.get(self.position) {
            self.position += 1;
        }
    }

    /// Mark the traversal unusable, so no digest is reported from partial data.
    fn abandon(&mut self, reason: String) {
        if self.failure.is_none() {
            self.failure = Some(reason);
        }
    }

    /// Whether every run was delivered and the totals agree.
    ///
    /// A short traversal must never produce a digest: it would be a digest over
    /// less than the image and would look authoritative.
    fn finish(mut self, locus: &Locus, session: &mut Session) -> bool {
        self.emit_described_until_stored(locus);

        if let Some(reason) = self.failure {
            session.note(format!(
                "image {} was not verified in one pass: {reason}",
                self.arn
            ));
            return false;
        }
        if self.position != self.runs.len() {
            session.note(format!(
                "image {} was not verified in one pass: {} of {} runs were delivered",
                self.arn,
                self.position,
                self.runs.len()
            ));
            return false;
        }
        if self.accounting.total() != self.size {
            session.note(format!(
                "image {} was not verified in one pass: {} bytes were delivered but it declares {}",
                self.arn,
                self.accounting.total(),
                self.size
            ));
            return false;
        }

        session
            .report
            .read_accounting
            .retain(|e| e.image.as_str() != self.arn.as_str());
        session.report.read_accounting.push(ImageAccounting {
            image: self.arn.clone(),
            accounting: self.accounting,
            traversed: true,
        });

        // Matched by algorithm, never by position: `finish` may reorder or omit
        // one this build cannot compute.
        let digests = self.hasher.finish();
        for hash in &self.hashes {
            match digests.iter().find(|d| d.algorithm() == &hash.algorithm) {
                Some(computed) => session.push(HashCheck::compared(
                    &self.arn,
                    self.role.clone(),
                    hash,
                    Coverage::WholeImage,
                    computed,
                )),
                None => session.push(HashCheck::declined(
                    &self.arn,
                    self.role.clone(),
                    hash,
                    Coverage::WholeImage,
                    format!("this build cannot compute {}", hash.algorithm),
                )),
            }
        }
        true
    }
}

/// Verify an `ImageStream`'s linear bitstream hashes.
#[allow(clippy::too_many_arguments)]
fn verify_stream(
    object: &crate::model::Aff4Object,
    volume: &mut crate::zip::ZipVolume,
    graph: &Graph,
    lexicon: &Lexicon,
    locus: &Locus,
    options: VerifyOptions,
    fused: Option<&mut FusedImage>,
    session: &mut Session,
) {
    // Only `aff4:hash` is the linear bitstream digest over the stream's data.
    let recorded: Vec<&StoredHash> = object
        .hashes
        .iter()
        .filter(|h| h.predicate == "hash")
        .collect();

    let stream = match ImageStream::open(&object.arn, graph, lexicon, locus) {
        Ok(stream) => stream,
        Err(error) => {
            // The fused image traversal was counting on this stream's bytes.
            // Without them its digest would cover less than the image, so it is
            // abandoned rather than finished short.
            if let Some(fused) = fused {
                fused.abandon(format!(
                    "stream {} could not be opened: {error}",
                    object.arn
                ));
            }
            for hash in &object.hashes {
                session.push(HashCheck::from_read_error(
                    &object.arn,
                    object.role.clone(),
                    hash,
                    Coverage::StoredStream,
                    format!("the stream could not be opened: {error}"),
                    &error,
                ));
            }
            return;
        }
    };

    verify_stream_index_hashes(object, &stream, volume, session);

    let mut blocks = wanted_block_digests(object, volume, options);

    // A stream's own digest and its per-chunk block hashes are separate claims:
    // the first attests the stored bytes as a whole, the second attests each
    // chunk. Only when there is neither is there nothing to do.
    //
    // This decision sits below the `blocks` binding for a reason. A part of a
    // split set records no `aff4:hash` of its own — one digest describes the
    // whole image stream and lives in part 001 — so
    // returning on `recorded.is_empty()` alone skipped every leaf in the set,
    // while the identical evidence in one file was checked in full.
    //
    // A fused image traversal is a third claim on these bytes: a part carrying
    // neither its own digest nor block-hash segments still owes the image its
    // stored run, so the pass runs when one is waiting on this stream.
    let mut fused = fused;
    let feeding = match fused.as_deref_mut() {
        Some(fused) => matches!(fused.before_stream(&object.arn, locus), FusedRole::Feeding),
        None => false,
    };
    if recorded.is_empty() && blocks.is_none() && !feeding {
        return;
    }

    let algorithms: Vec<HashAlgorithm> = recorded.iter().map(|h| h.algorithm.clone()).collect();
    // ONE plan governs the whole object: the digest threads are taken out of the
    // worker share, and the reader pipeline is then built from what remains.
    // Deriving a second plan here would hand the pipeline its full worker count
    // while the digest threads were already running, so the process would hold
    // far more threads than the run reported.
    let (mut hasher, plan) = budgeted_hasher(&algorithms);
    let chunk_size = stream.chunk_size();
    let mut carry: Vec<u8> = Vec::new();

    // This is where a large container spends its minutes: 256 GiB of LZ4 to
    // decompress and hash. Emitting per chunk keeps a caller's display honest
    // without the library deciding how often to repaint.
    let progress = std::cell::RefCell::new(&mut *session.progress);
    let arn = object.arn.clone();
    let total = Some(stream.size());
    let bevy_total = stream.bevy_count();
    let mut done: u64 = 0;

    // One read, many consumers: this stream's own digest, its
    // per-chunk block hashes, and — when the parts arrive in image order — the
    // whole-image digest, all from the same decompressed chunk.
    let mut image = if feeding { fused.as_deref_mut() } else { None };
    let mut sink = |bytes: &[u8]| {
        hasher.update(bytes);
        if let Some(blocks) = blocks.as_mut() {
            blocks.feed(bytes, chunk_size, &mut carry);
        }
        if let Some(image) = image.as_deref_mut() {
            image.feed(bytes);
        }
        done += bytes.len() as u64;
        progress.borrow_mut().on(Progress::Bytes {
            arn: &arn,
            done,
            total,
        });
        Ok(())
    };
    let mut on_bevy = |bevies_done: u64| {
        progress.borrow_mut().on(Progress::BevyCompleted {
            arn: &arn,
            done: bevies_done,
            total: bevy_total,
        });
    };

    let read = read_stream(&stream, volume, plan, &mut sink, &mut on_bevy, locus);
    // `sink` held a reborrow of `fused`; ending it here frees `fused` for the
    // completion paths below.
    let _ = image;

    if let Err(error) = read {
        if let Some(fused) = fused.as_deref_mut() {
            fused.abandon(format!("stream {} could not be read: {error}", object.arn));
        }
        for hash in &recorded {
            session.push(HashCheck::from_read_error(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::StoredStream,
                format!("the stream could not be read: {error}"),
                &error,
            ));
        }
        return;
    }

    if feeding && let Some(fused) = fused {
        fused.after_stream();
    }

    compare_stream_digests(object, &recorded, &hasher.finish(), session);

    if let Some(mut blocks) = blocks {
        blocks.finish(&mut carry);
        verify_block_hashes(&object.arn, &stream, &blocks, volume, session);
    }
}

/// The per-chunk digests this stream's pass should gather, if any.
///
/// Decided before the read: a stream that records no block-hash segments gets
/// no per-chunk hashing at all, rather than computing digests that
/// `verify_block_hashes` would find nothing to compare against. Gathering them
/// in the same pass is what keeps a terabyte container from being read twice.
fn wanted_block_digests(
    object: &crate::model::Aff4Object,
    volume: &mut crate::zip::ZipVolume,
    options: VerifyOptions,
) -> Option<BlockDigests> {
    options.block_hashes.then(|| {
        object
            .arn
            .member_name(&volume.arn().clone())
            .and_then(|base| BlockDigests::wanted(volume, &base))
    })?
}

/// Compare a stream's recorded digests against what the pass computed.
///
/// Matched by algorithm, never by position: `finish` may reorder its results or
/// omit one this build cannot compute, and a digest compared against the wrong
/// algorithm's value would report a mismatch on intact evidence.
fn compare_stream_digests(
    object: &crate::model::Aff4Object,
    recorded: &[&StoredHash],
    digests: &[Digest],
    session: &mut Session,
) {
    for hash in recorded {
        match digests.iter().find(|d| d.algorithm() == &hash.algorithm) {
            Some(computed) => session.push(HashCheck::compared(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::StoredStream,
                computed,
            )),
            None => session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::StoredStream,
                format!("this build cannot compute {}", hash.algorithm),
            )),
        }
    }
}

/// Verify the two digests a stream records besides its `aff4:hash`.
///
/// `imageStreamIndexHash` **is** SHA-512 over the bevy index segment's bytes —
/// measured against `Base-Linear.aff4`, where the recorded value reproduces
/// exactly. Neither reference implementation reads it, so this is aff4tools
/// checking something pyaff4 does not.
///
/// `imageStreamHash` remains unidentified, and is now known not to be a digest
/// over the stream's stored bytes at all: `Base-Linear.aff4` and
/// `Base-Linear-AllHashes.aff4` carry byte-identical bevy, index, and
/// block-hash segments yet record different values, so no arrangement of those
/// bytes can be the input. Rather than guess at a digest's input, it is
/// reported as not recomputed with its recorded value shown.
fn verify_stream_index_hashes(
    object: &crate::model::Aff4Object,
    stream: &ImageStream,
    volume: &mut dyn Volume,
    session: &mut Session,
) {
    let volume_arn = volume.arn().clone();

    for hash in &object.hashes {
        match hash.predicate.as_str() {
            "hash" => {}
            "imageStreamIndexHash" => {
                let Some(base) = stream.arn().member_name(&volume_arn) else {
                    continue;
                };

                // One index segment per bevy, concatenated in bevy order.
                let mut bytes = Vec::new();
                let mut failed = None;
                for bevy in 0..stream.bevy_count() {
                    let name = format!("{base}/{bevy:08}{}", crate::stream::INDEX_SUFFIX);
                    if !volume.has_segment(&name) {
                        continue;
                    }
                    match volume.read_segment(&name) {
                        Ok(segment) => bytes.extend_from_slice(&segment),
                        Err(error) => {
                            failed = Some(format!("{name} could not be read: {error}"));
                            break;
                        }
                    }
                }

                match failed {
                    Some(reason) => session.push(HashCheck::declined(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        Coverage::Segment,
                        reason,
                    )),
                    None => push_digest_check(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        Coverage::Segment,
                        &bytes,
                        session,
                    ),
                }
            }
            other => session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::Unidentified,
                format!("unknown digest {other}; not found in reference implementation"),
            )),
        }
    }
}

/// The block-hash segments a stream actually has, for one algorithm suffix.
///
/// Resolved by asking which names exist under the stream's prefix, rather than
/// generating a candidate name per bevy and probing for each. On a container
/// with 8215 bevies the probing form cost tens of thousands of lookups per
/// algorithm — and on a container with no block hashes at all, every one of
/// them was a miss.
///
/// Returned in bevy order, which is name order: bevy numbers are zero-padded
/// to eight digits precisely so they sort correctly.
/// Whether this volume holds the stream's **bevy data**, not merely metadata
/// or block-hash segments about it.
///
/// This is the discriminator for which streams contribute to a map's
/// `blockMapHash`, and it is deliberately *not* "can the stream's segments be
/// named in this volume".
///
/// In the striped corpus fixture each volume stores **both** streams'
/// block-hash segments while holding only **one** stream's bevies, and each
/// stripe's recorded `blockMapHash` covers only the stream whose bevies are
/// local. Verified by recomputation against
/// `AFF4Std/Striped/Base-Linear_{1,2}.aff4`:
///
/// | inputs | stripe 1 | stripe 2 |
/// |---|---|---|
/// | local stream only | matches `904c68e4…` | matches `1a9618d0…` |
/// | local + foreign | no match | no match |
/// | foreign + local | no match | no match |
///
/// So presence of a `.blockHash.*` segment does **not** mean the stream counts,
/// and a resolver that later makes foreign segments readable must not start
/// including them. Bevy presence is the test that survives that change.
fn volume_holds_stream_data(volume: &dyn Volume, stream: &Arn) -> bool {
    let Some(base) = stream.member_name(volume.arn()) else {
        return false;
    };
    // A bevy is a plain zero-padded number with no extension; `.index` and
    // `.blockHash.*` siblings share the prefix and must not count.
    volume
        .segments_with_prefix(&format!("{base}/"))
        .into_iter()
        .any(|name| {
            name.rsplit_once('/')
                .is_some_and(|(_, leaf)| crate::zip::is_bevy_number(leaf))
        })
}

fn block_hash_segments(volume: &dyn Volume, base: &str, suffix: &str) -> Vec<String> {
    let tail = format!("{BLOCK_HASH_SUFFIX}{suffix}");
    let mut found: Vec<String> = volume
        .segments_with_prefix(&format!("{base}/"))
        .into_iter()
        .filter(|name| name.ends_with(&tail))
        .collect();
    found.sort();
    found
}

/// Per-chunk digests, accumulated while a stream is read.
///
/// Only the algorithms whose block-hash segments are actually present are
/// computed. A digest with nothing to compare against is pure cost: on a
/// 256 GiB container with no block-hash segments at all, hashing every chunk
/// with MD5 and SHA-1 and then discarding both accounted for the majority of
/// `verify`'s runtime. `wanted` is decided once, before the read begins.
#[derive(Default)]
struct BlockDigests {
    md5: Option<Vec<u8>>,
    sha1: Option<Vec<u8>>,
}

impl BlockDigests {
    /// Both algorithms enabled, for tests that exercise chunking itself.
    #[cfg(test)]
    fn all() -> Self {
        Self {
            md5: Some(Vec::new()),
            sha1: Some(Vec::new()),
        }
    }

    /// Enable only the algorithms this stream records block hashes for.
    ///
    /// Returns [`None`] when the stream records none, so the caller can skip
    /// per-chunk hashing entirely rather than run it into a void.
    fn wanted(volume: &dyn Volume, base: &str) -> Option<Self> {
        let md5 = !block_hash_segments(volume, base, "md5").is_empty();
        let sha1 = !block_hash_segments(volume, base, "sha1").is_empty();
        if !md5 && !sha1 {
            return None;
        }
        Some(Self {
            md5: md5.then(Vec::new),
            sha1: sha1.then(Vec::new),
        })
    }
}

impl BlockDigests {
    /// Absorb the next slice, emitting a digest per completed chunk.
    ///
    /// `read_all` delivers chunk-sized slices today, but nothing in its
    /// contract promises that, so slices are re-cut to chunk boundaries here.
    /// A block hasher that assumed one slice per chunk would silently compute
    /// the wrong digests if that ever changed.
    fn feed(&mut self, bytes: &[u8], chunk_size: usize, carry: &mut Vec<u8>) {
        let mut rest = bytes;
        while !rest.is_empty() {
            let want = chunk_size.saturating_sub(carry.len());
            let take = want.min(rest.len());
            carry.extend_from_slice(&rest[..take]);
            rest = &rest[take..];

            if carry.len() == chunk_size {
                self.emit(carry);
                carry.clear();
            }
        }
    }

    /// Emit the final, short chunk if there is one.
    fn finish(&mut self, carry: &mut Vec<u8>) {
        if !carry.is_empty() {
            self.emit(carry);
            carry.clear();
        }
    }

    fn emit(&mut self, chunk: &[u8]) {
        if let Some(acc) = self.md5.as_mut()
            && let Some(digest) = digest_of(&HashAlgorithm::Md5, chunk)
        {
            acc.extend_from_slice(&hex_to_bytes(digest.hex()));
        }
        if let Some(acc) = self.sha1.as_mut()
            && let Some(digest) = digest_of(&HashAlgorithm::Sha1, chunk)
        {
            acc.extend_from_slice(&hex_to_bytes(digest.hex()));
        }
    }
}

/// Compare recomputed per-chunk digests against the stream's block-hash
/// segments.
///
/// This is the leaf level of the tree. The composite digests establish that a
/// block-hash segment is itself intact; only this establishes that it describes
/// the data.
fn verify_block_hashes(
    stream_arn: &Arn,
    stream: &ImageStream,
    blocks: &BlockDigests,
    volume: &mut dyn Volume,
    session: &mut Session,
) {
    let volume_arn = volume.arn().clone();
    let Some(base) = stream_arn.member_name(&volume_arn) else {
        return;
    };

    for (algorithm, computed) in [
        (HashAlgorithm::Md5, blocks.md5.as_ref()),
        (HashAlgorithm::Sha1, blocks.sha1.as_ref()),
    ] {
        // Not computed, because no segment of this algorithm exists to compare
        // against. `block_hash_segments` below agrees, but skipping here keeps
        // the two decisions from drifting apart.
        let Some(computed) = computed else {
            continue;
        };
        let suffix = match algorithm {
            HashAlgorithm::Md5 => "md5",
            _ => "sha1",
        };

        // Block hashes are per bevy: one segment per bevy, each holding that
        // bevy's chunk digests back to back. Ask which exist rather than
        // probing for one name per bevy.
        let names = block_hash_segments(volume, &base, suffix);
        if names.is_empty() {
            continue;
        }

        let mut recorded = Vec::new();
        for name in &names {
            match volume.read_segment(name) {
                Ok(bytes) => recorded.extend_from_slice(&bytes),
                Err(error) => {
                    session.note(format!(
                        "block hashes for stream {stream_arn} could not be read \
                         from {name}: {error}"
                    ));
                    return;
                }
            }
        }

        let width = if algorithm == HashAlgorithm::Md5 {
            16
        } else {
            20
        };
        let stored_hash = StoredHash {
            algorithm: algorithm.clone(),
            hex: to_hex(&recorded),
            predicate: format!("blockHash.{suffix}"),
        };

        let outcome = if recorded == *computed {
            Outcome::Match
        } else {
            Outcome::Mismatch
        };

        // Every recorded chunk digest is compared, not a sample: the equality
        // above is over the whole concatenated sequence. The count is what the
        // summary totals, so it is carried as a number beside the text.
        let chunk_count = recorded.len() / width;

        session.push(HashCheck {
            subject: stream_arn.clone(),
            role: ObjectRole::BlockHashes,
            predicate: format!("blockHash.{suffix}"),
            algorithm,
            coverage: Coverage::Block,
            expected: format!("{chunk_count} chunk digests"),
            actual: format!("{} chunk digests", computed.len() / width),
            outcome,
            digests_covered: Some(chunk_count),
        });

        // Naming the first differing chunk is what makes a mismatch actionable:
        // "chunk 47 of 121" localises the damage, "the digests differ" does not.
        if let Some(index) = first_difference(&recorded, computed, width) {
            session.note(format!(
                "the first block-hash difference for stream {stream_arn} is at \
                 chunk {index} ({}); bytes {}..{} of the stream do not match the \
                 digest recorded for them",
                stored_hash.predicate,
                index as u64 * stream.chunk_size() as u64,
                (index as u64 + 1) * stream.chunk_size() as u64
            ));
        }
    }
}

/// The index of the first differing digest, comparing digest by digest.
fn first_difference(recorded: &[u8], computed: &[u8], width: usize) -> Option<usize> {
    let count = (recorded.len() / width).min(computed.len() / width);
    for index in 0..count {
        let range = index * width..(index + 1) * width;
        if recorded.get(range.clone()) != computed.get(range) {
            return Some(index);
        }
    }
    // Equal as far as both go, but of different lengths: the first missing one.
    (recorded.len() != computed.len()).then_some(count)
}

/// Verify a `Map`'s segment digests and its composite `mapHash`.
fn verify_map(object: &crate::model::Aff4Object, volume: &mut dyn Volume, session: &mut Session) {
    let volume_arn = volume.arn().clone();

    let Some(base) = object.arn.member_name(&volume_arn) else {
        for hash in &object.hashes {
            session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::Segment,
                "the map's segments are stored in another volume".to_owned(),
            ));
        }
        return;
    };

    let segments = match read_map_segments(&base, volume) {
        Ok(segments) => segments,
        Err(error) => {
            for hash in &object.hashes {
                session.push(HashCheck::from_read_error(
                    &object.arn,
                    object.role.clone(),
                    hash,
                    Coverage::Segment,
                    format!("the map's segments could not be read: {error}"),
                    &error,
                ));
            }
            return;
        }
    };

    // The map's target index names every stream it draws on. Keep those whose
    // bevy data lives in this volume — a stripe also stores its sibling's
    // block-hash segments, and those must not contribute.
    let local_streams: Vec<Arn> = String::from_utf8_lossy(&segments.idx)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| Arn::parse(line, &Locus::new(session.report.source_path.clone())).ok())
        .filter(|arn| volume_holds_stream_data(volume, arn))
        .collect();

    for hash in &object.hashes {
        // Each of the four is SHA512 over bytes already read. `mapHash` is over
        // the three segments concatenated — bytes, not digests.
        let (input, coverage): (Option<Vec<u8>>, Coverage) = match hash.predicate.as_str() {
            "mapPointHash" => (Some(segments.map.clone()), Coverage::Segment),
            "mapIdxHash" => (Some(segments.idx.clone()), Coverage::Segment),
            "mapPathHash" => (Some(segments.path.clone()), Coverage::Segment),
            "mapHash" => (Some(segments.concatenated()), Coverage::Composite),
            _ => (None, Coverage::Composite),
        };

        match input {
            Some(bytes) => push_digest_check(
                &object.arn,
                object.role.clone(),
                hash,
                coverage,
                &bytes,
                session,
            ),
            // `blockMapHash` is recorded on the map as well as on the image.
            //
            // Not dropped in favour of the image-side check, which covers the
            // same value only while the image can be opened. A stripe whose
            // sibling is absent has a foreign stream stubbed with no `size`, so
            // `Image::open` fails and neither copy would be checked — the
            // container reporting "N of N matched" while a digest it records
            // goes unverified. The map's copy is recomputable on its own, so
            // recompute it here rather than depending on the image path.
            None if hash.predicate == "blockMapHash" => {
                match block_map_hash_input(volume, &local_streams, &segments) {
                    Ok(input) => push_block_map_check(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        &input,
                        session,
                    ),
                    Err(reason) => session.push(HashCheck::unreadable(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        Coverage::Composite,
                        format!("block-hash segment {reason}"),
                    )),
                }
            }
            None => session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::Composite,
                format!(
                    "aff4tools has not identified what {} is computed over",
                    hash.predicate
                ),
            )),
        }
    }
}

/// A map's three segments.
struct MapSegments {
    map: Vec<u8>,
    idx: Vec<u8>,
    path: Vec<u8>,
}

impl MapSegments {
    /// `map ‖ idx ‖ mapPath` — the input to `mapHash`, in that order.
    fn concatenated(&self) -> Vec<u8> {
        let mut all = Vec::with_capacity(self.map.len() + self.idx.len() + self.path.len());
        all.extend_from_slice(&self.map);
        all.extend_from_slice(&self.idx);
        all.extend_from_slice(&self.path);
        all
    }
}

/// Read `map`, `idx`, and the optional `mapPath`.
fn read_map_segments(base: &str, volume: &mut dyn Volume) -> Result<MapSegments> {
    let map = volume.read_segment(&format!("{base}/{MAP_SEGMENT}"))?;
    let idx = volume.read_segment(&format!("{base}/{IDX_SEGMENT}"))?;

    // Absent in broken-dedupe.aff4. An absent segment hashes as empty, which is
    // what its recorded digest would have been computed over.
    let path_name = format!("{base}/{MAP_PATH_SEGMENT}");
    let path = if volume.has_segment(&path_name) {
        volume.read_segment(&path_name)?
    } else {
        Vec::new()
    };

    Ok(MapSegments { map, idx, path })
}

/// Verify a `BlockHashes` object: the SHA512 over one block-hash segment.
fn verify_block_hash_segment(
    object: &crate::model::Aff4Object,
    volume: &mut dyn Volume,
    session: &mut Session,
) {
    let volume_arn = volume.arn().clone();

    // The object is named `…/blockhash.md5`; the segment is
    // `…/00000000.blockHash.md5`. The mapping is by algorithm suffix, since a
    // multi-bevy stream has one segment per bevy under one object.
    // Split the ARN, not its escaped member name. The object is
    // `<stream>/blockhash.<alg>`, and `<stream>` is a volume-relative ARN whose
    // own `member_name` gives the directory the segments live under. Splitting
    // the escaped string instead yields `…%2Fblockhash`, which prefix-matches
    // nothing — the bug that left every `blockHashesHash` unverified while the
    // silent `return` here hid it.
    let Some((stream_iri, suffix)) = object.arn.as_str().rsplit_once("/blockhash.") else {
        for hash in &object.hashes {
            session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::Segment,
                format!(
                    "{} does not name a stream and algorithm, so the segments \
                     it covers cannot be identified",
                    object.arn
                ),
            ));
        }
        return;
    };

    let locus = Locus::new(session.report.source_path.clone());
    let Some(stream_base) = Arn::parse(stream_iri, &locus)
        .ok()
        .and_then(|stream| stream.member_name(&volume_arn))
    else {
        for hash in &object.hashes {
            session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::Segment,
                "the block-hash segments are stored in another volume".to_owned(),
            ));
        }
        return;
    };

    let mut bytes = Vec::new();
    let mut found = false;
    // Already sorted into bevy order, so a multi-bevy stream concatenates in
    // address order.
    let matching = block_hash_segments(volume, &stream_base, suffix);

    for name in &matching {
        found = true;
        match volume.read_segment(name) {
            Ok(segment) => bytes.extend_from_slice(&segment),
            Err(error) => {
                let reason = format!("block-hash segment {name} could not be read: {error}");
                session.note(reason.clone());
                for hash in &object.hashes {
                    session.push(HashCheck::declined(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        Coverage::Segment,
                        reason.clone(),
                    ));
                }
                return;
            }
        }
    }

    if !found {
        for hash in &object.hashes {
            session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::Segment,
                format!("no {suffix} block-hash segments are stored under {stream_base}"),
            ));
        }
        return;
    }

    for hash in &object.hashes {
        push_digest_check(
            &object.arn,
            object.role.clone(),
            hash,
            Coverage::Segment,
            &bytes,
            session,
        );
    }
}

/// Verify an image's `blockMapHash`, the root of the tree.
fn verify_image(
    object: &crate::model::Aff4Object,
    volume: &mut crate::zip::ZipVolume,
    graph: &Graph,
    lexicon: &Lexicon,
    locus: &Locus,
    options: VerifyOptions,
    session: &mut Session,
) {
    // An AFF4-L logical image is often a `zip_segment`: its bytes are one ZIP
    // member, with no map and no ImageStream. `dream.aff4` is the simple case —
    // an 8688-byte file whose recorded MD5 and SHA-1 are digests over the
    // member exactly. Checking for this first avoids reporting "names no data
    // stream" about a container that is perfectly well formed.
    if is_zip_segment(object) && verify_zip_segment_image(object, volume, session) {
        return;
    }

    // An AFF4-L image can also declare itself an `ImageStream` on the same
    // subject: it *is* its own data stream, with no separate map. `unicode.aff4`
    // stores fourteen images this way, each `FileImage` + `Image` +
    // `ImageStream` with its own chunkSize and bevy. `ObjectRole` reports the
    // most specific type, which is `FileImage`, so without this they would fall
    // to the map path and be declined for naming no data stream.
    if declares_type(object, "ImageStream") {
        verify_stream(
            object, volume, graph, lexicon, locus, options, None, session,
        );
        return;
    }

    // A folder holds no bytes. `ObjectRole::is_image` counts `FolderImage`
    // among the images — right for the listing, which reports folders — but a
    // folder has no map, no stream, and nothing to hash, so asking it for a
    // data stream is a category error. Every AFF4-L container with a folder
    // reported one "names no data stream" note per folder, on containers that
    // were perfectly well formed. Nothing is declined by returning: a folder
    // carries no `aff4:hash` to check.
    if matches!(object.role, crate::model::ObjectRole::FolderImage) {
        return;
    }

    // A file whose bytes are a plain member but which never declared
    // `aff4:zip_segment`. AFF4-L 2019 §3.8 requires the type; pyaff4's own
    // `unicode.aff4` omits it on `README.txt`, and without this fallback that
    // file's two recorded digests were declined although its bytes were
    // present and matched. The departure is reported by `conformance` as
    // `MissingZipSegmentType` — the leniency rule: verify the bytes anyway,
    // and record the deviation rather than ignoring it.
    if verify_zip_segment_image(object, volume, session) {
        return;
    }

    let image = match Image::open(&object.arn, volume, graph, lexicon, locus) {
        Ok(image) => image,
        Err(error) => {
            for hash in &object.hashes {
                session.push(HashCheck::declined(
                    &object.arn,
                    object.role.clone(),
                    hash,
                    Coverage::WholeImage,
                    format!("the image's map could not be resolved: {error}"),
                ));
            }
            session.note(format!(
                "image {} could not be resolved to a map: {error}",
                object.arn
            ));
            return;
        }
    };

    // A discontiguous map's holes are legal but never silent: the filled bytes
    // were not recorded by the acquisition, so any digest over this image
    // covers content the spec supplied rather than content the imager measured.
    //
    // Whether one does is settled here rather than inside the note, so the note
    // can say which of the two situations this container is in.
    if let Some(deviation) = image.gap_deviation(locus, records_whole_image_digest(object)) {
        session.note(deviation.detail.clone());
    }

    // The map's own composition, which costs nothing to state: it comes from
    // the entries, not from reading the image. Stated even when no digest
    // required a traversal, because "3.8 MB stored, 252 MB described" is what
    // tells an examiner what a matching digest is a digest *of*.
    session.report.read_accounting.push(ImageAccounting {
        image: object.arn.clone(),
        accounting: ReadAccounting {
            stored: image.map().stored_bytes(),
            described: image.map().described_bytes(),
            unknown_placeholder: 0,
            gap_filled: image.map().gaps().bytes,
            gap_fill: image.map().gaps().fill.clone(),
        },
        traversed: false,
    });

    // One read, many consumers: every computable digest shares one traversal.
    //
    // No corpus container reaches this arm — each canonical image records its
    // `aff4:hash` as `^^aff4:blockMapHashSHA512`, which is built from the map's
    // own segments and takes the branch above. Containers this tool writes do
    // record plain digests over the image's bytes, so this is the path that
    // once re-read the whole image once per algorithm.
    let mut whole: Vec<&StoredHash> = Vec::new();
    for hash in &object.hashes {
        match &hash.algorithm {
            HashAlgorithm::BlockMapSha512 => {
                verify_block_map_hash(object, &image, volume, hash, session);
            }
            algorithm if is_computable(algorithm) => whole.push(hash),
            algorithm => session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::WholeImage,
                format!("this build cannot compute {algorithm}"),
            )),
        }
    }
    if !whole.is_empty() {
        verify_whole_image_digests(object, &image, volume, &whole, locus, session);
    }
}

/// Whether this object records a digest computed over the whole image.
///
/// Mirrors the dispatch in [`verify_image`]: `blockMapHash` is a construction
/// over other digests rather than a pass over the address space, so it does not
/// count — a container recording only that one has nothing covering its filled
/// gaps. An algorithm this build cannot compute does not count either: the
/// digest exists, but nothing here recomputes it, so no claim about the gap
/// bytes rests on it.
fn records_whole_image_digest(object: &crate::model::Aff4Object) -> bool {
    object
        .hashes
        .iter()
        .any(|h| h.algorithm != HashAlgorithm::BlockMapSha512 && is_computable(&h.algorithm))
}

/// Verify an image whose streams are spread across a set of volumes.
///
/// The single-volume path cannot open a striped image at all: the sibling's
/// stream is a stub with no `size`, so `Image::open` fails before any digest is
/// reached. Here each stream is resolved against the volume describing it.
///
/// `blockMapHash` is deliberately **not** recomputed here. Its per-stripe form
/// is verified on each Map, against that volume's own local stream (decision
/// 36); the image-level value in a striped set is a different construction over
/// the stripes' digests, which Stage 6 of the striping work covers. Recomputing
/// the single-volume form against a set would produce a mismatch on a container
/// that is intact.
fn verify_image_in_set(
    object: &crate::model::Aff4Object,
    volumes: &mut crate::zip_volume_set::ZipVolumeSet,
    lexicon: &Lexicon,
    locus: &Locus,
    _options: VerifyOptions,
    session: &mut Session,
) {
    let image = match Image::open_in_set(&object.arn, volumes, lexicon, locus) {
        Ok(image) => image,
        Err(error) => {
            for hash in &object.hashes {
                session.push(HashCheck::declined(
                    &object.arn,
                    object.role.clone(),
                    hash,
                    Coverage::WholeImage,
                    format!("the image's map could not be resolved: {error}"),
                ));
            }
            session.note(format!(
                "image {} could not be resolved to a map: {error}",
                object.arn
            ));
            return;
        }
    };

    if let Some(deviation) = image.gap_deviation(locus, records_whole_image_digest(object)) {
        session.note(deviation.detail.clone());
    }

    session.report.read_accounting.push(ImageAccounting {
        image: object.arn.clone(),
        accounting: ReadAccounting {
            stored: image.map().stored_bytes(),
            described: image.map().described_bytes(),
            unknown_placeholder: 0,
            gap_filled: image.map().gaps().bytes,
            gap_fill: image.map().gaps().fill.clone(),
        },
        traversed: false,
    });

    // One read, many consumers. `BlockMapSha512` is not a digest over the
    // image's bytes — it is built from the map's own segments — so it keeps its
    // own path. Everything computable rides a single traversal; anything this
    // build cannot compute is declined without reading at all.
    //
    // One traversal per digest would mean a 14.9 GiB set recording SHA-256 and
    // MD5 reads all of it twice at the image level.
    let mut whole: Vec<&StoredHash> = Vec::new();
    for hash in &object.hashes {
        match &hash.algorithm {
            HashAlgorithm::BlockMapSha512 => {
                verify_striped_block_map_hash(object, volumes, hash, session);
            }
            algorithm if is_computable(algorithm) => whole.push(hash),
            algorithm => session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::WholeImage,
                format!("this build cannot compute {algorithm}"),
            )),
        }
    }
    if !whole.is_empty() {
        verify_whole_image_digests_in_set(object, &image, volumes, &whole, locus, session);
    }
}

/// `aff4:dataStream`, the predicate that says a volume declares an image.
const DATA_STREAM_IRI: &str = "http://aff4.org/Schema#dataStream";

/// An image held wholly in one volume of a set: its root is the plain
/// `blockMapHash`, not a digest over several stripes.
///
/// A volume in a set may carry an image of its own. Verifying it as though it
/// were striped is wrong in both directions — it would decline a digest that is
/// perfectly checkable, and the construction differs (pass-through rather than
/// a concatenation over stripe digests).
fn verify_single_volume_block_map_hash(
    object: &crate::model::Aff4Object,
    volumes: &mut crate::zip_volume_set::ZipVolumeSet,
    index: usize,
    hash: &StoredHash,
    session: &mut Session,
) {
    match recompute_stripe_digests(volumes, &[index]) {
        Ok(stripes) => match stripes.first() {
            // The recorded value is the stripe's own blockMapHash directly.
            Some(stripe) => {
                let computed = to_hex(&stripe.digest);
                let outcome = if computed.eq_ignore_ascii_case(&hash.hex) {
                    Outcome::Match
                } else {
                    Outcome::Mismatch
                };
                session.push(HashCheck {
                    subject: object.arn.clone(),
                    role: object.role.clone(),
                    predicate: hash.predicate.clone(),
                    algorithm: hash.algorithm.clone(),
                    coverage: Coverage::WholeImage,
                    expected: hash.hex.clone(),
                    actual: computed,
                    outcome,
                    digests_covered: None,
                });
            }
            None => session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::WholeImage,
                "no volume in the set declares this image's map".to_owned(),
            )),
        },
        Err(reason) => session.push(HashCheck::declined(
            &object.arn,
            object.role.clone(),
            hash,
            Coverage::WholeImage,
            reason,
        )),
    }
}

/// Find the stripe order that reproduces `expected`, trying each key in turn.
///
/// Returns the matching key with its ordering and digest, plus the keys tried.
/// Separated from the reporting so the search reads as one idea: no candidate is
/// privileged, and the first that matches is the one named.
type OrderMatch<'s> = (StripeOrderKey, Vec<&'s Stripe>, String);

fn search_stripe_order<'s>(
    stripes: &'s [Stripe],
    expected: &str,
) -> (Option<OrderMatch<'s>>, Vec<&'static str>) {
    let mut tried = Vec::new();

    for key in [
        StripeOrderKey::Filename,
        StripeOrderKey::MapArn,
        StripeOrderKey::StreamArn,
    ] {
        let mut ordered: Vec<&Stripe> = stripes.iter().collect();
        ordered.sort_by_key(|s| s.key(key));

        let input: Vec<u8> = ordered.iter().flat_map(|s| s.digest.clone()).collect();
        let Some(computed) = digest_of(&HashAlgorithm::Sha512, &input) else {
            break;
        };

        if computed.hex().eq_ignore_ascii_case(expected) {
            let hex = computed.hex().to_owned();
            return (Some((key, ordered, hex)), tried);
        }
        tried.push(key.describe());
    }

    (None, tried)
}

/// One stripe's recomputed `blockMapHash`, with the keys it can be ordered by.
struct Stripe {
    path: PathBuf,
    map: Arn,
    stream: Arn,
    /// The recomputed digest, raw bytes. Never the recorded value.
    digest: Vec<u8>,
}

impl Stripe {
    /// The sort key for one candidate ordering rule.
    fn key(&self, by: StripeOrderKey) -> String {
        match by {
            StripeOrderKey::Filename => self
                .path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
            StripeOrderKey::MapArn => self.map.as_str().to_owned(),
            StripeOrderKey::StreamArn => self.stream.as_str().to_owned(),
        }
    }
}

/// Recompute every stripe's own `blockMapHash`, in volume order.
///
/// Returns `Err` with a reason when any stripe cannot be recomputed: a root
/// built from a partial set would be meaningless.
fn recompute_stripe_digests(
    volumes: &mut crate::zip_volume_set::ZipVolumeSet,
    members: &[usize],
) -> std::result::Result<Vec<Stripe>, String> {
    let mut stripes = Vec::new();

    for &index in members {
        let path = volumes.path_at(index).to_path_buf();
        let volume_arn = volumes.arn_at(index).clone();

        let Some((map_arn, map_base)) = volumes.local_map(&volume_arn) else {
            return Err(format!("volume {volume_arn} declares no map of its own"));
        };
        let Some(volume) = volumes.get_mut(&volume_arn) else {
            return Err(format!("volume {volume_arn} is no longer available"));
        };

        let segments = read_map_segments(&map_base, volume)
            .map_err(|e| format!("volume {volume_arn}'s map segments could not be read: {e}"))?;

        // This stripe's own streams only — the locality rule of decision 36.
        let local: Vec<Arn> = String::from_utf8_lossy(&segments.idx)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(|l| Arn::parse(l, &Locus::new(path.clone())).ok())
            .filter(|arn| volume_holds_stream_data(volume, arn))
            .collect();

        let stream = local.first().cloned().unwrap_or_else(|| map_arn.clone());
        let input = block_map_hash_input(volume, &local, &segments)
            .map_err(|reason| format!("volume {volume_arn}: block-hash segment {reason}"))?;

        // Raw digest bytes, never hex — the rule throughout the AFF4 tree.
        let digest = sha512_raw(&input);
        if digest.is_empty() {
            return Err("SHA512 is unavailable in this build".to_owned());
        }

        stripes.push(Stripe {
            path,
            map: map_arn,
            stream,
            digest,
        });
    }

    Ok(stripes)
}

/// Which key produced the stripe order that matched.
///
/// Reported, never inferred silently: an order the tool guessed is part of the
/// finding, and an examiner reading "MATCH" must be able to see what was
/// assumed to get there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StripeOrderKey {
    Filename,
    MapArn,
    StreamArn,
}

impl StripeOrderKey {
    fn describe(self) -> &'static str {
        match self {
            Self::Filename => "filename order",
            Self::MapArn => "map ARN order",
            Self::StreamArn => "stream ARN order",
        }
    }
}

/// Recompute a striped image's root digest.
///
/// The construction, identified against `AFF4Std/Striped/` and documented
/// nowhere else:
///
/// ```text
/// root = SHA-512( blockMapHash₁ ‖ blockMapHash₂ ‖ … )   raw bytes
/// ```
///
/// Two properties make this delicate.
///
/// **The inputs are recomputed, never the recorded values.** Feeding the
/// recorded per-stripe digests would make the root match even when a stripe's
/// data is damaged — the one failure this digest exists to catch. If any
/// stripe's `blockMapHash` cannot be recomputed, the root is `NotVerifiable`.
///
/// **It is order-sensitive, and the order is not recorded anywhere.** No ARN
/// sort determines it: on the reference fixture, sorting by volume ARN or
/// stream ARN gives the wrong order while filename and map ARN happen to agree.
/// That agreement is a coincidence of two samples. So the order is *inferred*
/// by trying candidate keys in turn — filename, then map ARN, then stream ARN —
/// and the key that matched is reported. When none matches, the digest is
/// declined with that stated, rather than reported as a mismatch: "we could not
/// determine the order" is not "the evidence is wrong".
fn verify_striped_block_map_hash(
    object: &crate::model::Aff4Object,
    volumes: &mut crate::zip_volume_set::ZipVolumeSet,
    hash: &StoredHash,
    session: &mut Session,
) {
    // Only the volumes that actually declare this image are its stripes.
    //
    // A set may hold a volume carrying an image of its own alongside the shared
    // one — and an image declared by a single volume is not striped at all: its
    // root is the ordinary single-volume `blockMapHash`, not a digest over
    // several. Treating every volume as a stripe of every image produced a
    // spurious "the stripe order is not recorded" decline on a container that
    // verifies cleanly when opened alone.
    let declaring: Vec<usize> = (0..volumes.len())
        .filter(|&i| {
            volumes
                .graph_at(i)
                .object(object.arn.as_str(), DATA_STREAM_IRI)
                .is_some()
        })
        .collect();

    if declaring.len() <= 1 {
        // Not striped. The single-volume path already knows this construction,
        // and it is a different one — pass-through, not a concatenation.
        let index = declaring.first().copied().unwrap_or(PRIMARY);
        verify_single_volume_block_map_hash(object, volumes, index, hash, session);
        return;
    }

    // Recompute each stripe's blockMapHash from its own segments.
    let stripes = match recompute_stripe_digests(volumes, &declaring) {
        Ok(stripes) => stripes,
        Err(reason) => {
            session.push(HashCheck::declined(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::WholeImage,
                reason,
            ));
            return;
        }
    };

    // Try each ordering key in turn. The first that matches wins, and is named.
    let (matched, tried) = search_stripe_order(&stripes, &hash.hex);
    if let Some((key, ordered, computed)) = matched {
        session.note(format!(
            "the striped image's blockMapHash matched with the stripes in \
             {} ({}); this order is inferred, not recorded in the container",
            key.describe(),
            ordered
                .iter()
                .filter_map(|s| s.path.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        session.push(HashCheck {
            subject: object.arn.clone(),
            role: object.role.clone(),
            predicate: hash.predicate.clone(),
            algorithm: hash.algorithm.clone(),
            coverage: Coverage::WholeImage,
            expected: hash.hex.clone(),
            actual: computed,
            outcome: Outcome::Match,
            digests_covered: None,
        });
        return;
    }

    // No ordering matched — which has two very different causes, and reporting
    // the wrong one would be a false statement about the evidence either way.
    //
    // If every stripe's own `blockMapHash` matched its recorded value, the
    // stripes are individually intact and only their *order* is in question.
    // That is a limitation of this build, not a finding: decline it.
    //
    // If some stripe's `blockMapHash` did **not** match, the inputs to the root
    // are known-bad, so no permutation of them could ever reproduce it. Calling
    // that "order undeterminable" would bury a real integrity failure behind a
    // tooling caveat. Report the mismatch, under the order named.
    let stripes_intact = session
        .report
        .checks
        .iter()
        .filter(|c| c.predicate == "blockMapHash")
        .all(|c| c.outcome == Outcome::Match);

    if stripes_intact {
        session.push(HashCheck::declined(
            &object.arn,
            object.role.clone(),
            hash,
            Coverage::WholeImage,
            format!(
                "every stripe verified individually, but the order they combine \
                 in is not recorded in the container and none of the orders \
                 tried ({}) reproduced this digest. Pass the folder holding \
                 them with --split-file, named in acquisition order",
                tried.join(", ")
            ),
        ));
        return;
    }

    let input: Vec<u8> = stripes.iter().flat_map(|s| s.digest.clone()).collect();
    let computed = digest_of(&HashAlgorithm::Sha512, &input);

    session.note(
        "the striped image's blockMapHash could not match: at least one \
         stripe's own blockMapHash did not match its recorded value, so the \
         inputs to this digest are already known to differ"
            .to_owned(),
    );
    session.push(HashCheck {
        subject: object.arn.clone(),
        role: object.role.clone(),
        predicate: hash.predicate.clone(),
        algorithm: hash.algorithm.clone(),
        coverage: Coverage::WholeImage,
        expected: hash.hex.clone(),
        actual: computed.map_or_else(String::new, |d| d.hex().to_owned()),
        outcome: Outcome::Mismatch,
        digests_covered: None,
    });
}

/// Every plain digest over a striped image's bytes, in one traversal.
///
/// One read, many consumers: decompressing the image is what this costs, and
/// the algorithms riding along are nearly free. Each digest once drove its own
/// full pass, so a 14.9 GiB set recording SHA-256 and MD5 read all of it twice.
fn verify_whole_image_digests_in_set(
    object: &crate::model::Aff4Object,
    image: &Image,
    volumes: &mut crate::zip_volume_set::ZipVolumeSet,
    hashes: &[&StoredHash],
    locus: &Locus,
    session: &mut Session,
) {
    let algorithms: Vec<HashAlgorithm> = hashes.iter().map(|h| h.algorithm.clone()).collect();
    let (mut digest_hasher, _plan) = budgeted_hasher(&algorithms);

    let progress = &mut *session.progress;
    let arn = object.arn.clone();
    let total = Some(image.size());
    let mut done: u64 = 0;

    let read = image.read_from_set(
        volumes,
        &mut |bytes| {
            digest_hasher.update(bytes);
            done += bytes.len() as u64;
            progress.on(Progress::Bytes {
                arn: &arn,
                done,
                total,
            });
            Ok(())
        },
        locus,
    );

    match read {
        Ok(accounting) => {
            // One entry per image, not one per algorithm. This runs once for
            // each recorded digest, so without the retain a two-digest image
            // reported its accounting twice — three times beside the
            // map-derived line — and an examiner saw the same ARN listed
            // repeatedly with nothing to distinguish the copies. Mirrors the
            // single-volume path, which has always deduplicated this way.
            session
                .report
                .read_accounting
                .retain(|e| e.image.as_str() != object.arn.as_str());
            session.report.read_accounting.push(ImageAccounting {
                image: object.arn.clone(),
                accounting,
                traversed: true,
            });
            // Matched by algorithm, never by position: `finish` may reorder
            // or omit one this build cannot compute.
            let digests = digest_hasher.finish();
            for hash in hashes {
                match digests.iter().find(|d| d.algorithm() == &hash.algorithm) {
                    Some(computed) => session.push(HashCheck::compared(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        Coverage::WholeImage,
                        computed,
                    )),
                    None => session.push(HashCheck::declined(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        Coverage::WholeImage,
                        format!("this build cannot compute {}", hash.algorithm),
                    )),
                }
            }
        }
        // One failed read now covers every digest that traversal served, so it
        // fans out to a finding for each. Collapsing them into one would report
        // fewer problems than the container actually has.
        Err(error) => {
            for hash in hashes {
                session.push(HashCheck::from_read_error(
                    &object.arn,
                    object.role.clone(),
                    hash,
                    Coverage::WholeImage,
                    format!("the image could not be read: {error}"),
                    &error,
                ));
            }
        }
    }
}

/// Whether an object declares the given type, by local name.
///
/// v1.0a §2.1 requires multiple `rdf:type` values, and [`ObjectRole`] reports
/// only the most specific — so a `FileImage` that is also an `ImageStream` needs
/// the full list to be read, not the role.
fn declares_type(object: &crate::model::Aff4Object, name: &str) -> bool {
    object.types.iter().any(|iri| {
        let iri: &str = iri;
        let local = iri.rsplit_once(['#', '/']).map_or(iri, |(_, n)| n);
        local == name
    })
}

/// Whether an object declares itself a ZIP segment (AFF4-L).
fn is_zip_segment(object: &crate::model::Aff4Object) -> bool {
    declares_type(object, "zip_segment") || declares_type(object, "ZipSegment")
}

/// Verify a logical image whose bytes are one ZIP member.
///
/// Returns whether the member was found. A `false` return means the object
/// declares itself a ZIP segment but names no member of this volume, so the
/// caller falls through to the map path rather than reporting a failure here.
fn verify_zip_segment_image(
    object: &crate::model::Aff4Object,
    volume: &mut dyn Volume,
    session: &mut Session,
) -> bool {
    let volume_arn = volume.arn().clone();
    let Some(member) = object.arn.member_name(&volume_arn) else {
        return false;
    };

    // `member_name` escapes the path per v1.0a §5.1, but pyaff4 writes logical
    // segment names unescaped where the characters are already legal —
    // `dream.aff4` stores `/test_images/AFF4-L/dream.txt` verbatim. Both
    // spellings are tried rather than assuming one, since either produces a
    // container the corpus contains.
    let name = if volume.has_segment(&member) {
        member
    } else {
        let unescaped = crate::arn::unescape(&member);
        if volume.has_segment(&unescaped) {
            unescaped
        } else {
            return false;
        }
    };

    let bytes = match volume.read_segment(&name) {
        Ok(bytes) => bytes,
        Err(error) => {
            for hash in &object.hashes {
                session.push(HashCheck::from_read_error(
                    &object.arn,
                    object.role.clone(),
                    hash,
                    Coverage::WholeImage,
                    format!("segment {name} could not be read: {error}"),
                    &error,
                ));
            }
            return true;
        }
    };

    // A logical image is stored whole: every byte comes off the member, none is
    // described.
    session.report.read_accounting.push(ImageAccounting {
        image: object.arn.clone(),
        accounting: ReadAccounting {
            stored: bytes.len() as u64,
            described: 0,
            unknown_placeholder: 0,
            gap_filled: 0,
            gap_fill: None,
        },
        traversed: true,
    });

    for hash in &object.hashes {
        push_digest_check(
            &object.arn,
            object.role.clone(),
            hash,
            Coverage::WholeImage,
            &bytes,
            session,
        );
    }

    true
}

/// Recompute a digest over every byte of the image.
fn verify_whole_image_digests(
    object: &crate::model::Aff4Object,
    image: &Image,
    volume: &mut dyn Volume,
    hashes: &[&StoredHash],
    locus: &Locus,
    session: &mut Session,
) {
    let algorithms: Vec<HashAlgorithm> = hashes.iter().map(|h| h.algorithm.clone()).collect();
    let (mut digest_hasher, _plan) = budgeted_hasher(&algorithms);

    let progress = &mut *session.progress;
    let arn = object.arn.clone();
    let total = Some(image.size());
    let mut done: u64 = 0;

    let read = image.read(
        volume,
        &mut |bytes| {
            digest_hasher.update(bytes);
            done += bytes.len() as u64;
            progress.on(Progress::Bytes {
                arn: &arn,
                done,
                total,
            });
            Ok(())
        },
        locus,
    );

    match read {
        Ok(accounting) => {
            // Replaces the map-derived figures with measured ones.
            session
                .report
                .read_accounting
                .retain(|e| e.image.as_str() != object.arn.as_str());
            session.report.read_accounting.push(ImageAccounting {
                image: object.arn.clone(),
                accounting,
                traversed: true,
            });
            let digests = digest_hasher.finish();
            for hash in hashes {
                match digests.iter().find(|d| d.algorithm() == &hash.algorithm) {
                    Some(computed) => session.push(HashCheck::compared(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        Coverage::WholeImage,
                        computed,
                    )),
                    None => session.push(HashCheck::declined(
                        &object.arn,
                        object.role.clone(),
                        hash,
                        Coverage::WholeImage,
                        format!("this build cannot compute {}", hash.algorithm),
                    )),
                }
            }
        }
        // One failed read covers every digest that traversal served.
        Err(error) => {
            for hash in hashes {
                session.push(HashCheck::from_read_error(
                    &object.arn,
                    object.role.clone(),
                    hash,
                    Coverage::WholeImage,
                    format!("the image could not be read: {error}"),
                    &error,
                ));
            }
        }
    }
}

/// The `blockMapHash` input: block-hash digests, then the three map digests.
///
/// One function so the map-side and image-side checks cannot drift apart.
/// `streams` must already be filtered to those whose bevy data this volume
/// holds — see [`volume_holds_stream_data`]; passing a foreign stream here
/// produces a digest that will not match anything.
///
/// Returns `Err(name)` naming the segment that could not be read.
fn block_map_hash_input(
    volume: &mut dyn Volume,
    streams: &[Arn],
    segments: &MapSegments,
) -> std::result::Result<Vec<u8>, String> {
    let volume_arn = volume.arn().clone();
    let mut input: Vec<u8> = Vec::new();

    for stream in streams {
        let Some(base) = stream.member_name(&volume_arn) else {
            continue;
        };
        for suffix in BLOCK_HASH_ORDER {
            let names = block_hash_segments(volume, &base, suffix);
            if names.is_empty() {
                continue;
            }
            let mut bytes = Vec::new();
            for name in &names {
                match volume.read_segment(name) {
                    Ok(segment) => bytes.extend_from_slice(&segment),
                    Err(error) => return Err(format!("{name} could not be read: {error}")),
                }
            }
            input.extend_from_slice(&sha512_raw(&bytes));
        }
    }

    input.extend_from_slice(&sha512_raw(&segments.map));
    input.extend_from_slice(&sha512_raw(&segments.idx));
    input.extend_from_slice(&sha512_raw(&segments.path));
    Ok(input)
}

/// Recompute `blockMapHash`: SHA512 over raw digests concatenated.
///
/// The order is `hashOrderingMap` — MD5, SHA1, SHA256, SHA512, Blake2b — for
/// the block-hash segments, then `mapPointHash`, `mapIdxHash`, `mapPathHash`.
/// Metadata order is not the order; nor is alphabetical.
///
/// The count is one digest per block-hash segment *present for a local
/// stream*, plus the three map digests — not a fixed five. A container
/// recording all five algorithms contributes eight inputs.
fn verify_block_map_hash(
    object: &crate::model::Aff4Object,
    image: &Image,
    volume: &mut dyn Volume,
    hash: &StoredHash,
    session: &mut Session,
) {
    let volume_arn = volume.arn().clone();

    let Some(map_base) = image.map().arn().member_name(&volume_arn) else {
        session.push(HashCheck::declined(
            &object.arn,
            object.role.clone(),
            hash,
            Coverage::Composite,
            "the map's segments are stored in another volume".to_owned(),
        ));
        return;
    };

    let segments = match read_map_segments(&map_base, volume) {
        Ok(segments) => segments,
        Err(error) => {
            session.push(HashCheck::from_read_error(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::Composite,
                format!("the map's segments could not be read: {error}"),
                &error,
            ));
            return;
        }
    };

    // Only streams whose bevy data this volume holds. A stripe stores its
    // sibling's block-hash segments too, and including those does not match.
    let local: Vec<Arn> = image
        .streams()
        .iter()
        .filter(|s| volume_holds_stream_data(volume, s.arn()))
        .map(|s| s.arn().clone())
        .collect();

    let input = match block_map_hash_input(volume, &local, &segments) {
        Ok(input) => input,
        Err(reason) => {
            session.push(HashCheck::unreadable(
                &object.arn,
                object.role.clone(),
                hash,
                Coverage::Composite,
                format!("block-hash segment {reason}"),
            ));
            return;
        }
    };

    push_block_map_check(&object.arn, object.role.clone(), hash, &input, session);
}

/// Compare a recomputed `blockMapHash` against its recorded value.
///
/// The recorded datatype is `blockMapHashSHA512` while the value itself is a
/// SHA512. Comparing hex directly rather than through `Digest::matches` keeps
/// that datatype distinction intact instead of relabelling the computed digest
/// to make it pass.
fn push_block_map_check(
    subject: &Arn,
    role: ObjectRole,
    hash: &StoredHash,
    input: &[u8],
    session: &mut Session,
) {
    match digest_of(&HashAlgorithm::Sha512, input) {
        Some(computed) => {
            let outcome = if computed.hex().eq_ignore_ascii_case(&hash.hex) {
                Outcome::Match
            } else {
                Outcome::Mismatch
            };
            session.push(HashCheck {
                subject: subject.clone(),
                role,
                predicate: hash.predicate.clone(),
                algorithm: hash.algorithm.clone(),
                coverage: Coverage::Composite,
                expected: hash.hex.clone(),
                actual: computed.hex().to_owned(),
                outcome,
                digests_covered: None,
            });
        }
        None => session.push(HashCheck::declined(
            subject,
            role,
            hash,
            Coverage::Composite,
            "SHA512 is unavailable in this build".to_owned(),
        )),
    }
}

/// Block-hash algorithm suffixes in `hashOrderingMap` order.
const BLOCK_HASH_ORDER: [&str; 5] = ["md5", "sha1", "sha256", "sha512", "blake2b"];

/// Compute a digest over `bytes` and compare it against a recorded hash.
fn push_digest_check(
    subject: &Arn,
    role: ObjectRole,
    hash: &StoredHash,
    coverage: Coverage,
    bytes: &[u8],
    session: &mut Session,
) {
    match digest_of(&hash.algorithm, bytes) {
        Some(computed) => {
            session.push(HashCheck::compared(
                subject, role, hash, coverage, &computed,
            ));
        }
        None => session.push(HashCheck::declined(
            subject,
            role,
            hash,
            coverage,
            format!("this build cannot compute {}", hash.algorithm),
        )),
    }
}

/// SHA-512 of `bytes`, as raw digest bytes.
fn sha512_raw(bytes: &[u8]) -> Vec<u8> {
    digest_of(&HashAlgorithm::Sha512, bytes)
        .map(|d| hex_to_bytes(d.hex()))
        .unwrap_or_default()
}

/// Decode a lowercase hex string back to bytes.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

/// Render bytes as lowercase hex.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn arn(text: &str) -> Arn {
        Arn::parse(text, &Locus::new("/x.aff4")).unwrap()
    }

    fn stored(predicate: &str, algorithm: HashAlgorithm, hex: &str) -> StoredHash {
        StoredHash {
            algorithm,
            hex: hex.to_owned(),
            predicate: predicate.to_owned(),
        }
    }

    #[test]
    fn hex_round_trips_through_bytes() {
        assert_eq!(hex_to_bytes("000fffa5"), vec![0x00, 0x0f, 0xff, 0xa5]);
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(hex_to_bytes(""), Vec::<u8>::new());
    }

    /// The empty input's SHA-512, as raw bytes — the value `sha512_raw` must
    /// produce for an absent `mapPath`.
    #[test]
    fn sha512_raw_is_the_digest_not_its_hex() {
        let raw = sha512_raw(b"");
        assert_eq!(
            raw.len(),
            64,
            "a raw SHA-512 is 64 bytes, not 128 characters"
        );
        assert_eq!(to_hex(&raw)[..16], *"cf83e1357eefb8bd");
    }

    /// `blockMapHash` concatenates raw digests; `mapHash` concatenates segment
    /// bytes. Conflating them yields a clean-looking wrong answer.
    #[test]
    fn map_hash_concatenates_bytes_not_digests() {
        let segments = MapSegments {
            map: b"MMM".to_vec(),
            idx: b"II".to_vec(),
            path: b"P".to_vec(),
        };
        assert_eq!(segments.concatenated(), b"MMMIIP".to_vec());

        // The digest-concatenation form is 3 x 64 bytes, and differs.
        let digests = [
            sha512_raw(&segments.map),
            sha512_raw(&segments.idx),
            sha512_raw(&segments.path),
        ]
        .concat();
        assert_eq!(digests.len(), 192);
        assert_ne!(
            digest_of(&HashAlgorithm::Sha512, &segments.concatenated()),
            digest_of(&HashAlgorithm::Sha512, &digests)
        );
    }

    /// hashOrderingMap order, not alphabetical and not metadata order.
    #[test]
    fn block_hash_order_is_the_reference_ordering() {
        assert_eq!(
            BLOCK_HASH_ORDER,
            ["md5", "sha1", "sha256", "sha512", "blake2b"]
        );

        let mut alphabetical = BLOCK_HASH_ORDER;
        alphabetical.sort_unstable();
        assert_ne!(
            BLOCK_HASH_ORDER, alphabetical,
            "the ordering is defined by the reference implementation, not by \
             sorting; a sorted guess would put blake2b first"
        );
    }

    /// A check that did not run must never read as a pass.
    #[test]
    fn a_declined_check_is_not_a_match() {
        let hash = stored("hash", HashAlgorithm::Sha1, "abc");
        let check = HashCheck::declined(
            &arn("aff4://s"),
            ObjectRole::ImageStream,
            &hash,
            Coverage::StoredStream,
            "no reason",
        );

        assert!(!check.outcome.was_checked());
        assert!(!check.outcome.is_mismatch());
        assert_ne!(check.outcome, Outcome::Match);
        assert!(
            check.actual.is_empty(),
            "nothing was computed, so nothing is shown"
        );
    }

    /// Comparison must require the algorithm to agree, not just the value.
    #[test]
    fn a_comparison_respects_the_algorithm() {
        let computed = digest_of(&HashAlgorithm::Sha1, b"abc").unwrap();

        let right = stored(
            "hash",
            HashAlgorithm::Sha1,
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        );
        let check = HashCheck::compared(
            &arn("aff4://s"),
            ObjectRole::ImageStream,
            &right,
            Coverage::StoredStream,
            &computed,
        );
        assert_eq!(check.outcome, Outcome::Match);

        let wrong_algorithm = StoredHash {
            algorithm: HashAlgorithm::Md5,
            ..right
        };
        let check = HashCheck::compared(
            &arn("aff4://s"),
            ObjectRole::ImageStream,
            &wrong_algorithm,
            Coverage::StoredStream,
            &computed,
        );
        assert_eq!(check.outcome, Outcome::Mismatch);
    }

    #[test]
    fn a_report_counts_matches_mismatches_and_declines_separately() {
        let hash = stored("hash", HashAlgorithm::Sha1, "abc");
        let computed = digest_of(&HashAlgorithm::Sha1, b"abc").unwrap();

        let report = VerificationReport {
            source_path: "/x.aff4".into(),
            checks: vec![
                HashCheck::compared(
                    &arn("aff4://s"),
                    ObjectRole::ImageStream,
                    &stored(
                        "hash",
                        HashAlgorithm::Sha1,
                        "a9993e364706816aba3e25717850c26c9cd0d89d",
                    ),
                    Coverage::StoredStream,
                    &computed,
                ),
                HashCheck::compared(
                    &arn("aff4://s"),
                    ObjectRole::ImageStream,
                    &hash,
                    Coverage::StoredStream,
                    &computed,
                ),
                HashCheck::declined(
                    &arn("aff4://s"),
                    ObjectRole::ImageStream,
                    &hash,
                    Coverage::StoredStream,
                    "unknown input",
                ),
            ],
            read_accounting: Vec::new(),
            notes: Vec::new(),
            block_hashes_verified: false,
        };

        assert_eq!(report.checked_count(), 2);
        assert_eq!(report.match_count(), 1);
        assert_eq!(report.not_verifiable_count(), 1);
        assert!(report.has_mismatch());
    }

    /// Block digests must be cut at chunk boundaries regardless of how the
    /// stream delivers its slices.
    #[test]
    fn block_digests_are_cut_at_chunk_boundaries() {
        let chunk_size = 100usize;
        let data: Vec<u8> = (0..250u32).map(|i| (i % 251) as u8).collect();

        // Delivered as one slice.
        let mut whole = BlockDigests::all();
        let mut carry = Vec::new();
        whole.feed(&data, chunk_size, &mut carry);
        whole.finish(&mut carry);

        // Delivered in awkward pieces that cross boundaries.
        let mut pieces = BlockDigests::all();
        let mut carry = Vec::new();
        for piece in data.chunks(37) {
            pieces.feed(piece, chunk_size, &mut carry);
        }
        pieces.finish(&mut carry);

        assert_eq!(whole.md5, pieces.md5);
        assert_eq!(whole.sha1, pieces.sha1);

        // Three chunks: 100, 100, and a short 50.
        assert_eq!(whole.md5.as_ref().unwrap().len(), 3 * 16);
        assert_eq!(whole.sha1.as_ref().unwrap().len(), 3 * 20);

        // The last one is the short chunk's digest, not a padded one.
        let expected = digest_of(&HashAlgorithm::Md5, &data[200..250]).unwrap();
        assert_eq!(to_hex(&whole.md5.as_ref().unwrap()[32..48]), expected.hex());
    }

    /// A mismatch must localise itself: "chunk 47" is actionable, "the digests
    /// differ" is not.
    #[test]
    fn the_first_differing_block_is_identified() {
        let a = vec![0u8; 16 * 5];
        let mut b = a.clone();
        assert_eq!(first_difference(&a, &b, 16), None);

        // A change inside the third digest.
        b[16 * 2 + 3] = 0xFF;
        assert_eq!(first_difference(&a, &b, 16), Some(2));

        // Differing counts: the first one that is missing.
        let short = vec![0u8; 16 * 3];
        assert_eq!(first_difference(&a, &short, 16), Some(3));
    }

    #[test]
    fn coverage_distinguishes_a_stream_from_an_image() {
        assert!(Coverage::StoredStream.describe().contains("stored"));
        assert!(Coverage::WholeImage.describe().contains("described"));
        assert_ne!(
            Coverage::StoredStream.describe(),
            Coverage::WholeImage.describe(),
            "a stream digest must not read as an image digest"
        );
    }
}
