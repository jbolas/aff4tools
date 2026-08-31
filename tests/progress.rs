//! The shared progress rendering: the 80-column rule and percentage reporting.
//!
//! `ProgressPainter`'s throttle and disabled-gate behavior are covered in
//! `src/painter.rs`'s own unit tests instead of here: that type prints to
//! stderr, so it is binary-only code and unreachable from an integration test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use aff4tools::progress::{AcquisitionProgress, BlockProgress, LogicalProgress};

/// Every rendered line stays inside 80 columns.
///
/// A wrapped line cannot be overwritten by a carriage return, so each repaint
/// would leave the previous one behind.
#[test]
fn a_block_progress_line_fits_in_eighty_columns() {
    // A large total, a large done count, and a wide rate: the widest realistic
    // line this renders.
    let mut progress = BlockProgress::new(18_000_000_000_000);
    progress.update(17_999_000_000_000, 999_999);
    let line = progress.line(Duration::from_secs(35_999));
    assert!(
        line.chars().count() <= 80,
        "progress must fit 80 columns, got {}: {line}",
        line.chars().count()
    );
}

/// The block form reports its percentage against a known total.
#[test]
fn a_block_progress_line_reports_a_percentage() {
    let mut progress = BlockProgress::new(1000);
    progress.update(380, 4);
    let line = progress.line(Duration::from_secs(10));
    assert!(line.contains("38%"), "expected a percentage in: {line}");
}

/// Before the scan completes, the line reports liveness and no percentage.
///
/// A percentage against a denominator that is still growing can fall as new
/// directories are found, which reads as a malfunction.
#[test]
fn logical_progress_shows_no_percentage_while_scanning() {
    let mut progress = LogicalProgress::new();
    progress.update(1_284, 4_200_000_000);
    progress.set_estimate(2_000, 9_000_000_000, false);

    let line = progress.line(Duration::from_secs(38));
    assert!(
        !line.contains('%'),
        "no percentage belongs on a growing denominator: {line}"
    );
    assert!(line.contains("1,284"), "expected a file count in: {line}");
    assert!(
        line.contains("scanning"),
        "the operator must be told the total is still being found: {line}"
    );
}

/// Once the scan completes, the line reports a percentage and an ETA.
#[test]
fn logical_progress_shows_a_percentage_once_scanned() {
    let mut progress = LogicalProgress::new();
    progress.set_estimate(10_000, 1_000, true);
    progress.update(3_800, 380);
    progress.observe_cost(380);

    let line = progress.line(Duration::from_secs(10));
    assert!(line.contains('%'), "expected a percentage in: {line}");
    assert!(
        !line.contains("scanning"),
        "the scanning marker must clear once the total is known: {line}"
    );
}

/// The logical line also fits 80 columns at its widest.
#[test]
fn a_logical_progress_line_fits_in_eighty_columns() {
    let mut progress = LogicalProgress::new();
    progress.set_estimate(9_999_999, 18_000_000_000_000, true);
    progress.update(9_999_999, 17_999_000_000_000);
    progress.observe_cost(17_999_000_000_000);

    let line = progress.line(Duration::from_secs(35_999));
    assert!(
        line.chars().count() <= 80,
        "progress must fit 80 columns, got {}: {line}",
        line.chars().count()
    );
}

/// A percentage is never reported above 100, even if the estimate ran low.
///
/// The cost model is calibrated live, so a tree can finish slightly over its
/// estimate. Showing 118% would read as a fault.
#[test]
fn logical_progress_clamps_at_one_hundred_percent() {
    let mut progress = LogicalProgress::new();
    progress.set_estimate(100, 1_000, true);
    progress.update(100, 2_000);
    progress.observe_cost(2_000);

    let line = progress.line(Duration::from_secs(5));
    assert!(
        line.contains("100%"),
        "an overrun estimate must clamp to 100%: {line}"
    );
}

/// Calibration raises the estimate when small files cost more than assumed.
///
/// A tree of tiny files spends its time on per-entry work, not on bytes. If
/// the ETA were computed from bytes alone it would report almost no time
/// remaining while most of the work was still ahead.
#[test]
fn calibration_accounts_for_per_file_cost() {
    let mut progress = LogicalProgress::new();
    // 10,000 files found, almost no bytes: a small-file tree.
    progress.set_estimate(10_000, 10_000 * 4_096, true);

    // 1,000 files done in 10 seconds, carrying very few bytes.
    progress.update(1_000, 8_000);
    progress.observe_cost(1_000 * 4_096);
    progress.calibrate(1_000, 8_000, Duration::from_secs(10));

    let line = progress.line(Duration::from_secs(10));
    // A tenth done in ten seconds implies roughly ninety seconds remain.
    assert!(
        line.contains("0:01:") || line.contains("0:00:5") || line.contains("0:01"),
        "the ETA must reflect per-file cost, not bytes: {line}"
    );
    assert!(line.contains("10%"), "expected ten percent in: {line}");
}
