//! Progress display shared by every acquisition mode.
//!
//! What to *say* about progress lives here, behind [`AcquisitionProgress`]: a
//! device knows how many bytes it will read, and a logical walk does not, so
//! presenting both the same way would mean inventing a denominator for one of
//! them. This module returns rendered lines as `String`s and performs no I/O
//! of its own — the library never prints (see the CLAUDE.md layout note) — so
//! it stays reachable from tests as ordinary library code. The mechanics of
//! *when* to repaint a line on stderr belong to the binary and live in
//! `src/painter.rs`.

use std::time::Duration;

/// What one acquisition mode says about its own progress.
pub trait AcquisitionProgress {
    /// The line to paint, given how long the acquisition has run.
    ///
    /// Must fit within 80 columns: a wrapped line cannot be overwritten by a
    /// carriage return, so every repaint would leave the previous behind.
    fn line(&self, elapsed: Duration) -> String;
}

/// Progress for a source whose size is known: a device, an image, a split set.
pub struct BlockProgress {
    total: u64,
    done: u64,
    bevies: u64,
}

impl BlockProgress {
    /// Create a tracker for a source of `total` bytes.
    #[must_use]
    pub fn new(total: u64) -> Self {
        Self {
            total,
            done: 0,
            bevies: 0,
        }
    }

    /// Record `done` bytes read and `bevies` written.
    pub fn update(&mut self, done: u64, bevies: u64) {
        self.done = done;
        self.bevies = bevies;
    }
}

impl AcquisitionProgress for BlockProgress {
    fn line(&self, elapsed: Duration) -> String {
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        let secs = elapsed.as_secs_f64().max(0.001);
        #[allow(clippy::cast_precision_loss)]
        let rate = self.done as f64 / secs;
        #[allow(clippy::cast_precision_loss)]
        let done_gib = self.done as f64 / GIB;
        #[allow(clippy::cast_precision_loss)]
        let total_f = self.total as f64;
        // Computed via `done_gib` (rather than straight from `self.done`) to
        // match, bit for bit, the rounding the original `AcquireProgress`
        // produced — this task moves that display, not redefines it.
        let percent = if total_f == 0.0 {
            0.0
        } else {
            (done_gib * GIB / total_f) * 100.0
        };

        #[allow(clippy::cast_precision_loss)]
        let left = self.total.saturating_sub(self.done) as f64;
        let remaining = if rate > 0.0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let seconds = (left / rate).min(359_999.0) as u64;
            format!(
                " | {:01}:{:02}:{:02} left",
                seconds / 3600,
                (seconds % 3600) / 60,
                seconds % 60
            )
        } else {
            String::new()
        };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rate_bytes = rate as u64;
        format!(
            "{done_gib:.1}/{:.1} GiB | {percent:.0}% | {}/s | {} bevies{remaining}",
            total_f / GIB,
            crate::human_bytes(rate_bytes),
            self.bevies,
        )
    }
}

/// Progress for a logical acquisition, whose total is discovered while it runs.
///
/// Two display states. Until the scanner finishes, the total is still growing,
/// so the line reports what has been done and says the scan is running — a
/// percentage against a moving denominator can fall, which reads as a fault.
/// Once the scan completes the total is fixed and the line reports a
/// percentage and an estimated time remaining.
pub struct LogicalProgress {
    files_done: u64,
    bytes_done: u64,
    cost_done: u64,
    files_found: u64,
    cost_found: u64,
    scan_complete: bool,
    cost_rate: Option<f64>,
}

impl Default for LogicalProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl LogicalProgress {
    /// Create a tracker with nothing done and nothing found yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            files_done: 0,
            bytes_done: 0,
            cost_done: 0,
            files_found: 0,
            cost_found: 0,
            scan_complete: false,
            cost_rate: None,
        }
    }

    /// Record acquisition progress: files finished and bytes stored.
    pub fn update(&mut self, files: u64, bytes: u64) {
        self.files_done = files;
        self.bytes_done = bytes;
    }

    /// Record cost units completed, in the same units as [`Self::set_estimate`].
    pub fn observe_cost(&mut self, cost_done: u64) {
        self.cost_done = cost_done;
    }

    /// Record what the scanner has found so far, and whether it has finished.
    pub fn set_estimate(&mut self, files: u64, cost: u64, complete: bool) {
        self.files_found = files;
        self.cost_found = cost;
        self.scan_complete = complete;
    }

    /// Whether the scan has finished and the denominator is fixed.
    #[must_use]
    pub fn scan_complete(&self) -> bool {
        self.scan_complete
    }

    /// Refine the ETA from observed throughput.
    ///
    /// The denominator is in cost units, and the writer knows how many it has
    /// completed and how long that took. The rate that matters is therefore
    /// cost-per-second, measured rather than assumed — which is what makes the
    /// estimate hold on a tree of many small files as well as on a few large
    /// ones.
    pub fn calibrate(&mut self, _files_done: u64, _bytes_done: u64, elapsed: Duration) {
        let secs = elapsed.as_secs_f64().max(0.001);
        #[allow(clippy::cast_precision_loss)]
        let rate = self.cost_done as f64 / secs;
        self.cost_rate = if rate > 0.0 { Some(rate) } else { None };
    }
}

/// Group a count with commas: `1284` renders as `1,284`.
fn with_commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    let first = digits.len() % 3;
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && index % 3 == first {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

impl AcquisitionProgress for LogicalProgress {
    fn line(&self, elapsed: Duration) -> String {
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        let secs = elapsed.as_secs_f64().max(0.001);
        #[allow(clippy::cast_precision_loss)]
        let rate = self.bytes_done as f64 / secs;
        #[allow(clippy::cast_precision_loss)]
        let done_gib = self.bytes_done as f64 / GIB;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rate_bytes = rate as u64;
        let files = with_commas(self.files_done);

        if !self.scan_complete {
            return format!(
                "{files} files | {done_gib:.1} GiB | {}/s | scanning...",
                crate::human_bytes(rate_bytes),
            );
        }

        // Clamped: the cost model is calibrated live, so a tree can finish
        // slightly over its estimate, and a figure above 100% reads as a fault.
        #[allow(clippy::cast_precision_loss)]
        let percent = if self.cost_found == 0 {
            100.0_f64
        } else {
            ((self.cost_done as f64 / self.cost_found as f64) * 100.0).min(100.0)
        };

        let cost_rate = self.cost_rate.unwrap_or_else(|| {
            #[allow(clippy::cast_precision_loss)]
            let fallback = self.cost_done as f64 / secs;
            fallback
        });
        #[allow(clippy::cast_precision_loss)]
        let left = self.cost_found.saturating_sub(self.cost_done) as f64;
        let remaining = if cost_rate > 0.0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let seconds = (left / cost_rate).min(359_999.0) as u64;
            format!(
                " | ~{:01}:{:02}:{:02} left",
                seconds / 3600,
                (seconds % 3600) / 60,
                seconds % 60
            )
        } else {
            String::new()
        };

        format!(
            "{percent:.0}% | {files} files | {done_gib:.1} GiB | {}/s{remaining}",
            crate::human_bytes(rate_bytes),
        )
    }
}
