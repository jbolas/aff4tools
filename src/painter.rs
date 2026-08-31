//! Repainting the acquisition progress line on stderr.
//!
//! This is binary-only, not library code: the library returns errors and
//! formatted lines as values and never prints or exits (see the CLAUDE.md
//! layout note), so anything that calls `eprint!` lives here instead of in
//! `src/progress.rs`.

use std::time::{Duration, Instant};

/// Repaints a one-line progress display on stderr.
///
/// On stderr rather than stdout so redirecting the report to a file does not
/// capture carriage returns, and suppressed entirely when stderr is not a
/// terminal.
pub(crate) struct ProgressPainter {
    enabled: bool,
    started: Instant,
    last_paint: Instant,
    painted: bool,
}

impl ProgressPainter {
    /// How often the line may repaint. Four times a second reads as smooth
    /// without flooding a slow terminal.
    const INTERVAL: Duration = Duration::from_millis(250);

    /// Create a painter. When `enabled` is false, every method becomes a
    /// no-op — used when stderr is not a terminal.
    pub(crate) fn new(enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            enabled,
            started: now,
            last_paint: now.checked_sub(Self::INTERVAL).unwrap_or(now),
            painted: false,
        }
    }

    /// How long this display has been running, for rate and ETA arithmetic.
    pub(crate) fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Whether anything has been painted and not yet cleared.
    #[cfg(test)]
    pub(crate) fn painted(&self) -> bool {
        self.painted
    }

    /// Whether a paint right now would be admitted by the throttle.
    pub(crate) fn would_paint(&self) -> bool {
        self.enabled && self.last_paint.elapsed() >= Self::INTERVAL
    }

    /// Repaint, if enabled and the throttle allows it.
    pub(crate) fn paint(&mut self, line: &str) {
        if !self.would_paint() {
            return;
        }
        self.paint_now(line);
    }

    /// Repaint regardless of the throttle.
    ///
    /// Used by [`Self::paint`] once the throttle admits a repaint, and
    /// available for a state change the operator should see at once — the
    /// scanner completing, which switches the logical display from liveness
    /// to a percentage.
    pub(crate) fn paint_now(&mut self, line: &str) {
        if !self.enabled {
            return;
        }
        self.last_paint = Instant::now();
        self.painted = true;
        eprint!("\r\x1b[2K{line}");
    }

    /// Clear the line so the report that follows starts clean.
    pub(crate) fn finish(&mut self) {
        if self.painted {
            eprint!("\r\x1b[2K");
            self.painted = false;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::ProgressPainter;

    /// A disabled painter emits nothing, whatever it is asked to paint.
    ///
    /// Progress goes to stderr only when stderr is a terminal; redirecting
    /// the report to a file must not capture carriage returns.
    #[test]
    fn a_disabled_painter_paints_nothing() {
        let mut painter = ProgressPainter::new(false);
        painter.paint("anything at all");
        painter.finish();
        assert!(!painter.painted(), "a disabled painter must never paint");
    }

    /// The throttle admits the first paint and suppresses an immediate second.
    #[test]
    fn the_throttle_suppresses_a_rapid_repaint() {
        let mut painter = ProgressPainter::new(true);
        assert!(painter.would_paint(), "the first paint is always admitted");
        painter.paint("first");
        assert!(
            !painter.would_paint(),
            "a paint 250ms early must be suppressed"
        );
    }
}
