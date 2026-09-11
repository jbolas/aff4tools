//! Deciding whether a ZIP segment's bytes are stored compressed or verbatim.
//!
//! A ZIP member is stored with one of two methods: Stored (verbatim) or
//! Deflate. AFF4-L v1.0-ALPHA §6.1 permits either for a file segment. Deflating
//! a high-entropy file (already-compressed media, encrypted data) spends CPU to
//! produce output no smaller than the input, and often larger, so this module
//! chooses Stored for such files and Deflate for genuinely compressible ones.
//!
//! The choice never affects the bytes a reader reconstructs — only the ZIP
//! method recorded for the member — so it breaks no conformance rule.

use std::io::Write;

use flate2::Compression;
use flate2::write::DeflateEncoder;

/// How a segment's bytes should be stored in the ZIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentPlacement {
    /// ZIP method Stored: the bytes verbatim.
    Stored,
    /// ZIP method Deflate: the bytes compressed.
    Deflate,
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

/// Whether deflating `data` is likely to shrink it, judged from a small sample.
///
/// Trial-compresses up to [`PROBE_TOTAL_BYTES`] drawn as [`PROBE_WINDOWS`]
/// evenly spaced windows, and returns whether the sample compressed past the
/// [`PROBE_RATIO_NUM`]/[`PROBE_RATIO_DEN`] ceiling. A file smaller than the
/// sample budget is probed whole.
#[must_use]
pub fn deflate_helps(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    let sample = strided_sample(data);
    if sample.is_empty() {
        return false;
    }

    // `Compression::fast()` for the probe: it is a heuristic on a small sample,
    // so speed matters and a slightly conservative estimate is safe — a false
    // "no" merely stores a file that would have compressed a little, never
    // corrupts anything. The never-grow guard in the writer uses the real
    // write level (`Compression::default()`, matching `add_deflated_member` in
    // src/write/zip_writer.rs) so the final Stored-vs-Deflate outcome is never
    // wrong about which is actually smaller.
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    if encoder.write_all(&sample).is_err() {
        return false;
    }
    let Ok(compressed) = encoder.finish() else {
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

/// Decide how a segment's bytes are stored.
///
/// A `forced` codec wins outright. With no forced codec, [`deflate_helps`]
/// decides. This never runs a full deflate — the writer that acts on a
/// [`SegmentPlacement::Deflate`] result must still apply the never-grow guard
/// (a completed deflate that is not smaller than the input is discarded for
/// Stored), which is the writer's responsibility, not this function's.
#[must_use]
pub fn decide_segment_placement(data: &[u8], forced: Option<SegmentCodec>) -> SegmentPlacement {
    match forced {
        Some(SegmentCodec::Stored) => SegmentPlacement::Stored,
        Some(SegmentCodec::Deflate) => SegmentPlacement::Deflate,
        None => {
            if deflate_helps(data) {
                SegmentPlacement::Deflate
            } else {
                SegmentPlacement::Stored
            }
        }
    }
}

#[cfg(test)]
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

    /// A forced codec wins over the probe in both directions.
    #[test]
    fn forced_codec_overrides_probe() {
        let compressible = vec![b'Z'; 1024 * 1024];
        assert_eq!(
            decide_segment_placement(&compressible, Some(SegmentCodec::Stored)),
            SegmentPlacement::Stored,
            "forced Stored must not be overridden by a compressible probe"
        );
        let incompressible = pseudo_random(1024 * 1024, 7);
        assert_eq!(
            decide_segment_placement(&incompressible, Some(SegmentCodec::Deflate)),
            SegmentPlacement::Deflate,
            "forced Deflate must be honored even when it will not help"
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
}
