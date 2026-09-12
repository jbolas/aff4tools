//! Deciding whether a ZIP segment's bytes are stored compressed or verbatim.
//!
//! A ZIP member is stored with one of two methods: Stored (verbatim) or
//! Deflate. AFF4-L v1.0-ALPHA §6.1 permits either for a file segment. Deflating
//! a high-entropy file (already-compressed media, encrypted data) spends CPU to
//! produce output no smaller than the input, and often larger, so this module
//! chooses Stored for such files and Deflate for genuinely compressible ones.

use std::io::Write;

use flate2::Compression;
use flate2::write::DeflateEncoder;

/// The deflate level used for every ZIP segment this crate writes.
pub const SEGMENT_DEFLATE_LEVEL: u32 = 1;

/// The compression level every deflate in this crate's ZIP path uses.
#[must_use]
pub fn segment_compression() -> Compression {
    Compression::new(SEGMENT_DEFLATE_LEVEL)
}

/// How a segment's bytes should be stored in the ZIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentPlacement {
    /// ZIP method Stored: the bytes verbatim.
    Stored,
    /// ZIP method Deflate: the bytes compressed.
    Deflate,
}

/// A decided placement, carrying the compressed bytes when there are any.
///
/// The `Deflate` variant owns the output of the one deflate that ran, so the
/// writer never repeats it. See the module comment.
#[derive(Debug)]
pub enum SegmentPlan {
    /// Write the input verbatim, as ZIP method Stored.
    Stored,
    /// Write these bytes as ZIP method Deflate.
    ///
    /// Guaranteed shorter than the input: [`plan_segment`] falls back to
    /// [`SegmentPlan::Stored`] otherwise, so a compression attempt can never
    /// enlarge the container.
    Deflate(Vec<u8>),
}

impl SegmentPlan {
    /// Which ZIP method this plan calls for.
    #[must_use]
    pub fn placement(&self) -> SegmentPlacement {
        match self {
            Self::Stored => SegmentPlacement::Stored,
            Self::Deflate(_) => SegmentPlacement::Deflate,
        }
    }
}

/// A caller's explicit choice, from `--compression`.
///
/// A ZIP member has only two methods, so any non-stored codec (`zlib`, `lz4`,
/// `snappy`) maps to `Deflate` here: those codecs frame `ImageStream` *chunks*,
/// not ZIP members, and a segment written with a non-stored `--compression`
/// value is Deflate-compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentCodec {
    /// Force Stored, whatever the probe would say.
    Stored,
    /// Force Deflate, whatever the probe would say.
    Deflate,
}

/// Above this size the compressibility probe runs; at or below it, deflating
/// the whole segment is cheaper than sampling it.
const PROBE_FLOOR_BYTES: usize = PROBE_TOTAL_BYTES;

/// How many bytes of a large file the probe samples in total.
///
/// Enough to characterize compressibility, small enough that the probe costs a
/// few milliseconds rather than the hundreds a full deflate of a 16 MiB file
/// costs. Measured: a 256 KiB level-1 deflate is ~6 ms; a full 16 MiB deflate
/// of incompressible data is ~433 ms.
const PROBE_TOTAL_BYTES: usize = 256 * 1024;

/// The number of windows the probe spreads across the file.
///
/// Sampling across the file rather than from its head alone catches a file
/// whose entropy varies by region — a header that looks random above a
/// compressible body, or the reverse.
const PROBE_WINDOWS: usize = 4;

/// The fraction below which deflating is judged worthwhile, as an exact
/// integer ratio [`PROBE_RATIO_NUM`]/[`PROBE_RATIO_DEN`] = 9/10 = 90%.
///
/// A probe compressing to 90% or less of its size predicts a real saving. A
/// file that barely compresses is not worth the CPU or the slight risk of the
/// full deflate expanding it. Expressed as an integer ratio so the comparison
/// needs no `usize`-to-`f64` cast (which would lose precision above 2^52).
const PROBE_RATIO_NUM: usize = 9;
const PROBE_RATIO_DEN: usize = 10;

/// Deflate `data` in full at [`SEGMENT_DEFLATE_LEVEL`].
///
/// Returns `None` only if the encoder itself fails, which would be a bug here
/// rather than bad input; the caller then stores the bytes verbatim, which is
/// always a valid way to write a segment.
fn deflate_all(data: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), segment_compression());
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

/// Whether deflating `data` is likely to shrink it, judged from a small sample.
///
/// Trial-compresses up to [`PROBE_TOTAL_BYTES`] drawn as [`PROBE_WINDOWS`]
/// evenly spaced windows, and returns whether the sample compressed past the
/// [`PROBE_RATIO_NUM`]/[`PROBE_RATIO_DEN`] ceiling.
///
/// **Only meaningful above [`PROBE_FLOOR_BYTES`].** At or below that size the
/// sample is the whole file, so this costs exactly what it is trying to avoid;
/// [`plan_segment`] does not call it there.
#[must_use]
pub fn deflate_helps(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    let sample = strided_sample(data);
    if sample.is_empty() {
        return false;
    }

    // The probe runs at the same level as the real write, so its ratio is the
    // ratio the write will achieve rather than an estimate from a different
    // level. The never-grow guard still has the final say on the real output.
    let Some(compressed) = deflate_all(&sample) else {
        return false;
    };

    // `compressed < sample * 9/10`, done in integers to avoid a lossy
    // `usize`-to-`f64` cast. Multiply first: sample lengths are bounded by
    // `PROBE_TOTAL_BYTES` (256 KiB), so `sample.len() * 9` cannot overflow.
    compressed.len() * PROBE_RATIO_DEN < sample.len() * PROBE_RATIO_NUM
}

/// Draw up to [`PROBE_TOTAL_BYTES`] from `data` as evenly spaced windows.
fn strided_sample(data: &[u8]) -> Vec<u8> {
    if data.len() <= PROBE_TOTAL_BYTES {
        return data.to_vec();
    }
    let window = PROBE_TOTAL_BYTES / PROBE_WINDOWS;
    let mut out = Vec::with_capacity(PROBE_TOTAL_BYTES);
    // Space the window starts across the file, leaving room for the last window
    // to fit entirely within `data`.
    let span = data.len() - window;
    for i in 0..PROBE_WINDOWS {
        let start = span * i / (PROBE_WINDOWS - 1);
        out.extend_from_slice(&data[start..start + window]);
    }
    out
}

/// Decide how a segment's bytes are stored, and compress them if that is how.
///
/// The returned plan carries the compressed bytes when Deflate wins, so the
/// writer performs no deflate of its own — see the module comment on why that
/// matters.
///
/// # The never-grow guard
///
/// Deflate is chosen only when its real output is strictly shorter than the
/// input, whatever the probe or a forced codec said. A segment is therefore
/// never stored in a form larger than verbatim, and honoring a forced
/// "compress this" never means "store it larger".
///
/// # Which files are probed
///
/// A segment larger than [`PROBE_FLOOR_BYTES`] is sampled first, so an
/// incompressible large file costs a 256 KiB probe rather than a full deflate.
/// At or below that size the full deflate runs directly: the probe would cost
/// as much as the answer it predicts.
#[must_use]
pub fn plan_segment(data: &[u8], forced: Option<SegmentCodec>) -> SegmentPlan {
    if data.is_empty() {
        return SegmentPlan::Stored;
    }

    match forced {
        // Nothing to weigh: the examiner asked for verbatim bytes.
        Some(SegmentCodec::Stored) => return SegmentPlan::Stored,
        // Forced Deflate skips the probe but not the guard below.
        Some(SegmentCodec::Deflate) => {}
        // Large and unpromising by sample: decline without a full deflate.
        None => {
            if data.len() > PROBE_FLOOR_BYTES && !deflate_helps(data) {
                return SegmentPlan::Stored;
            }
        }
    }

    match deflate_all(data) {
        // The guard, measured on the bytes that would actually be written.
        Some(compressed) if compressed.len() < data.len() => SegmentPlan::Deflate(compressed),
        _ => SegmentPlan::Stored,
    }
}

/// Decide how a segment's bytes are stored.
///
/// Retained for callers that need only the decision. Prefer [`plan_segment`],
/// which yields the compressed bytes alongside it and so costs one deflate
/// rather than two.
#[must_use]
pub fn decide_segment_placement(data: &[u8], forced: Option<SegmentCodec>) -> SegmentPlacement {
    plan_segment(data, forced).placement()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random fill: a linear congruential sequence, so a
    /// test needs no rng dependency and reproduces exactly. The top byte of
    /// each state word is taken via `to_le_bytes`, which needs no truncating
    /// cast.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut data = vec![0u8; len];
        for b in &mut data {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = (state >> 56).to_le_bytes()[0];
        }
        data
    }

    /// A run of one byte is maximally compressible; the probe must say so.
    #[test]
    fn probe_says_yes_on_compressible() {
        let data = vec![b'A'; 4 * 1024 * 1024];
        assert!(deflate_helps(&data));
    }

    /// Random bytes do not compress; the probe must say so, and cheaply — this
    /// is the case the whole change exists to speed up.
    #[test]
    fn probe_says_no_on_incompressible() {
        let data = pseudo_random(4 * 1024 * 1024, 0x9e37_79b9_7f4a_7c15);
        assert!(!deflate_helps(&data));
    }

    /// The probe samples across the file, not just the head: a file whose first
    /// window is random but whose bulk is compressible must still be seen as
    /// compressible.
    #[test]
    fn probe_samples_across_not_just_head() {
        let mut data = vec![0u8; 4 * 1024 * 1024];
        // First 512 KiB random-ish, rest highly compressible zeros.
        data[..512 * 1024].copy_from_slice(&pseudo_random(512 * 1024, 1));
        assert!(deflate_helps(&data), "probe missed the compressible tail");
    }

    /// With no forced codec, the decision follows the probe.
    #[test]
    fn decision_follows_probe_when_not_forced() {
        let compressible = vec![b'Z'; 2 * 1024 * 1024];
        assert_eq!(
            decide_segment_placement(&compressible, None),
            SegmentPlacement::Deflate
        );
        let incompressible = pseudo_random(2 * 1024 * 1024, 42);
        assert_eq!(
            decide_segment_placement(&incompressible, None),
            SegmentPlacement::Stored
        );
    }

    /// A forced codec overrides the *probe*, but not the never-grow guard.
    ///
    /// Forced Stored is absolute: compressible content stays verbatim. Forced
    /// Deflate skips the probe, so content the probe would have declined is
    /// still deflated and measured — but content that does not actually shrink
    /// resolves to Stored, because honoring "compress this" must never mean
    /// "store it larger". A forced Deflate that *does* shrink is honored, which
    /// is what distinguishes this from ignoring the flag.
    #[test]
    fn forced_codec_overrides_probe_but_not_the_guard() {
        let compressible = vec![b'Z'; 1024 * 1024];
        assert_eq!(
            decide_segment_placement(&compressible, Some(SegmentCodec::Stored)),
            SegmentPlacement::Stored,
            "forced Stored must not be overridden by a compressible probe"
        );
        assert_eq!(
            decide_segment_placement(&compressible, Some(SegmentCodec::Deflate)),
            SegmentPlacement::Deflate,
            "forced Deflate must be honored when it does shrink the segment"
        );
        let incompressible = pseudo_random(1024 * 1024, 7);
        assert_eq!(
            decide_segment_placement(&incompressible, Some(SegmentCodec::Deflate)),
            SegmentPlacement::Stored,
            "the never-grow guard outranks a forced Deflate that would not shrink"
        );
    }

    /// Empty input is Stored: there is nothing to compress and a Deflate stream
    /// of empty input is larger than empty.
    #[test]
    fn empty_is_stored() {
        assert_eq!(
            decide_segment_placement(&[], None),
            SegmentPlacement::Stored
        );
        assert!(!deflate_helps(&[]));
    }

    /// Level 1, and never the library default: the whole point of pinning it.
    /// A regression here silently costs 2.6x the CPU on every logical
    /// acquisition, which is invisible in output and only shows up as time.
    #[test]
    fn the_segment_level_is_one() {
        assert_eq!(SEGMENT_DEFLATE_LEVEL, 1);
        assert_eq!(segment_compression().level(), 1);
    }

    /// A small compressible segment is planned as Deflate and the plan carries
    /// the compressed bytes, so the writer needs no deflate of its own.
    #[test]
    fn a_plan_carries_the_compressed_bytes() {
        let data = vec![b'Q'; 64 * 1024];
        match plan_segment(&data, None) {
            SegmentPlan::Deflate(compressed) => {
                assert!(
                    compressed.len() < data.len(),
                    "a Deflate plan must be shorter than its input"
                );
                // The bytes are the real deflate output, so they must inflate
                // back to the input exactly. This is the property the writer
                // relies on when it skips compressing again.
                let mut d = flate2::write::DeflateDecoder::new(Vec::new());
                d.write_all(&compressed).unwrap();
                assert_eq!(d.finish().unwrap(), data, "plan bytes must round-trip");
            }
            SegmentPlan::Stored => panic!("compressible data must plan as Deflate"),
        }
    }

    /// The never-grow guard, now the only thing that decides for small files:
    /// incompressible input plans as Stored even though the probe never ran.
    #[test]
    fn small_incompressible_falls_back_to_stored() {
        let data = pseudo_random(64 * 1024, 99);
        assert!(
            data.len() <= PROBE_FLOOR_BYTES,
            "this test needs a small file"
        );
        assert!(
            matches!(plan_segment(&data, None), SegmentPlan::Stored),
            "incompressible bytes must not be stored as Deflate"
        );
    }

    /// A large incompressible file is declined by the probe, which is the case
    /// the probe still exists for: it avoids a full deflate of many megabytes.
    #[test]
    fn large_incompressible_is_declined_by_the_probe() {
        let data = pseudo_random(4 * 1024 * 1024, 0x5151);
        assert!(data.len() > PROBE_FLOOR_BYTES);
        assert!(!deflate_helps(&data));
        assert!(matches!(plan_segment(&data, None), SegmentPlan::Stored));
    }

    /// Forced Deflate is still guarded: honoring "compress this" must never
    /// mean "store it larger".
    #[test]
    fn forced_deflate_that_would_grow_is_stored() {
        let data = pseudo_random(32 * 1024, 7);
        assert!(
            matches!(
                plan_segment(&data, Some(SegmentCodec::Deflate)),
                SegmentPlan::Stored
            ),
            "the guard must override a forced Deflate that would not shrink"
        );
    }

    /// Forced Stored never deflates, whatever the content would allow.
    #[test]
    fn forced_stored_never_deflates() {
        let data = vec![b'Z'; 128 * 1024];
        assert!(matches!(
            plan_segment(&data, Some(SegmentCodec::Stored)),
            SegmentPlan::Stored
        ));
    }

    /// Empty input is Stored: there is nothing to compress and a Deflate
    /// stream of empty input is larger than empty.
    #[test]
    fn empty_plans_as_stored() {
        assert!(matches!(plan_segment(&[], None), SegmentPlan::Stored));
    }
}
