//! A metadata-only scanner that inventories a tree ahead of acquisition.
//!
//! # Why a thread
//!
//! A logical acquisition has no denominator until the tree has been walked.
//! Walking it inline, one directory at a time, does not help: discovery and
//! acquisition then advance at the same rate, so the running total tracks the
//! work already done and the display reads "nearly finished" throughout.
//!
//! A separate thread decouples the two rates. The scanner reads metadata only
//! — no file contents, no hashing, no compression — so it runs one to two
//! orders of magnitude faster than acquisition and finishes while the writer
//! is still in the first few percent. The denominator is exact from then on.
//!
//! # Read-only
//!
//! The scanner calls `symlink_metadata` and `read_dir` and nothing else. It
//! never opens a file for its contents and never obtains a write handle.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;

use super::logical::MAX_SEGMENT_RESIDENT_SIZE;

/// How many entries may sit in the queue at once.
///
/// This is the **only** bound on how far the scanner may run ahead. Never add
/// a second: two independent limits on what is in flight is the shape that
/// produced three deadlocks in the parallel read pipeline.
pub const SCAN_QUEUE_CAPACITY: usize = 4096;

/// What a small file costs beyond its bytes.
///
/// A file at or below `MAX_SEGMENT_RESIDENT_SIZE` is stored as a ZIP segment,
/// which carries per-entry work the byte count does not show. A tree of
/// 500,000 tiny files has a trivial byte total and a substantial cost, and a
/// bytes-only denominator would be badly optimistic there. Calibrated live by
/// the writer; this is the starting figure.
const SEGMENT_OVERHEAD: u64 = 4096;

/// One item the scanner found.
#[derive(Debug, Clone)]
pub enum ScanItem {
    /// A regular file, with its size in bytes.
    File {
        /// Where the file is.
        path: PathBuf,
        /// Its size in bytes, from its metadata.
        size: u64,
    },
    /// A directory is being entered. Matched by exactly one [`ScanItem::DirEnd`].
    Dir {
        /// Where the directory is.
        path: PathBuf,
    },
    /// The directory most recently opened is finished.
    DirEnd,
    /// A path that could not be inventoried, with the reason.
    Skipped {
        /// The path that was not inventoried.
        path: PathBuf,
        /// Why it was passed over.
        reason: String,
    },
}

/// What the scanner has found so far.
pub struct ScanTotals {
    files: AtomicU64,
    cost: AtomicU64,
    complete: AtomicBool,
}

impl ScanTotals {
    fn new() -> Self {
        Self {
            files: AtomicU64::new(0),
            cost: AtomicU64::new(0),
            complete: AtomicBool::new(false),
        }
    }

    /// Files found, cost found, and whether the walk has finished.
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64, bool) {
        (
            self.files.load(Ordering::Relaxed),
            self.cost.load(Ordering::Relaxed),
            self.complete.load(Ordering::Relaxed),
        )
    }
}

/// What one file is expected to cost, in the units the denominator uses.
#[must_use]
pub fn cost_of(size: u64) -> u64 {
    if size <= MAX_SEGMENT_RESIDENT_SIZE {
        size.saturating_add(SEGMENT_OVERHEAD)
    } else {
        size
    }
}

/// A running scanner: its output queue, its totals, and its thread.
pub struct Scanner {
    /// Items found, in walk order.
    pub items: Receiver<ScanItem>,
    /// Live counts, readable while the walk runs.
    pub totals: Arc<ScanTotals>,
    handle: JoinHandle<()>,
}

impl Scanner {
    /// Wait for the scanner thread to finish.
    ///
    /// Nothing in the walk can panic and unwind, so the join's result carries
    /// no information: it is dropped rather than inspected.
    pub fn join(self) {
        drop(self.handle.join());
    }

    /// Split into the queue and a handle that can still report a panic.
    ///
    /// [`Scanner::join`] takes `self`, so a caller that wants to consume the
    /// queue lazily — acquiring each item as it arrives, rather than draining
    /// the queue into memory first — cannot also keep the scanner joinable.
    /// This hands back the two halves so discovery and acquisition can overlap,
    /// which is the entire reason the scan runs on its own thread.
    ///
    /// The [`ScanRun`] should be joined once the queue is exhausted, so the
    /// scanner's lifetime ends inside the call that started it.
    #[must_use]
    pub fn split(self) -> (Receiver<ScanItem>, ScanRun) {
        (
            self.items,
            ScanRun {
                totals: self.totals,
                handle: self.handle,
            },
        )
    }

    /// Drop the queue, then wait for the thread.
    ///
    /// Hanging up the receiver is what makes a blocked `send` return `Err`, so
    /// this is the order that proves the scanner exits on a gone consumer
    /// instead of parking forever on a full queue. `items` is private to this
    /// call because dropping it separately would partially move the `Scanner`
    /// and leave the handle unreachable.
    ///
    /// The join's result is dropped, exactly as in [`Scanner::join`]: the walk
    /// has no operation that can panic and unwind.
    pub fn drop_queue_and_join(self) {
        drop(self.items);
        drop(self.handle.join());
    }
}

/// The half of a split [`Scanner`] that outlives its queue.
///
/// Holds the totals the display reads and the thread handle the caller joins
/// once the queue is exhausted.
pub struct ScanRun {
    totals: Arc<ScanTotals>,
    handle: JoinHandle<()>,
}

impl ScanRun {
    /// The live counts, shareable with a progress display.
    #[must_use]
    pub fn totals(&self) -> Arc<ScanTotals> {
        Arc::clone(&self.totals)
    }

    /// Wait for the thread.
    ///
    /// The join's result is dropped, exactly as in [`Scanner::join`]: nothing
    /// in the walk can panic and unwind, so there is nothing to report.
    pub fn join(self) {
        drop(self.handle.join());
    }
}

/// Start scanning `roots` on a new thread.
#[must_use]
pub fn spawn(roots: Vec<PathBuf>, capacity: usize) -> Scanner {
    let (tx, rx) = sync_channel(capacity);
    let totals = Arc::new(ScanTotals::new());
    let thread_totals = Arc::clone(&totals);

    let handle = std::thread::spawn(move || {
        for root in &roots {
            // A send failure means the consumer is gone; stop walking.
            if !scan_path(root, &tx, &thread_totals) {
                break;
            }
        }
        thread_totals.complete.store(true, Ordering::Relaxed);
    });

    Scanner {
        items: rx,
        totals,
        handle,
    }
}

/// Walk one path. Returns false when the consumer has hung up.
fn scan_path(path: &std::path::Path, tx: &SyncSender<ScanItem>, totals: &ScanTotals) -> bool {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return tx
                .send(ScanItem::Skipped {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                })
                .is_ok();
        }
    };

    // Symlinks and special files are not acquired, so they are not counted.
    // The acquisition path reports them; the scanner only needs its total to
    // match what will actually be written.
    if metadata.is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return tx
            .send(ScanItem::Skipped {
                path: path.to_path_buf(),
                reason: "not a regular file".to_owned(),
            })
            .is_ok();
    }

    if metadata.is_file() {
        let size = metadata.len();
        totals.files.fetch_add(1, Ordering::Relaxed);
        totals.cost.fetch_add(cost_of(size), Ordering::Relaxed);
        return tx
            .send(ScanItem::File {
                path: path.to_path_buf(),
                size,
            })
            .is_ok();
    }

    if tx
        .send(ScanItem::Dir {
            path: path.to_path_buf(),
        })
        .is_err()
    {
        return false;
    }

    match std::fs::read_dir(path) {
        Ok(entries) => {
            let mut failures = Vec::new();
            let children =
                children_from_entries(path, entries.map(|e| e.map(|e| e.path())), &mut failures);
            // Emitted before recursing into the readable children, so the
            // inline walk in `logical.rs` can place them identically and the
            // two walkers stay item-for-item equal.
            for (failed, reason) in failures {
                if tx
                    .send(ScanItem::Skipped {
                        path: failed,
                        reason,
                    })
                    .is_err()
                {
                    return false;
                }
            }
            for child in children {
                if !scan_path(&child, tx, totals) {
                    return false;
                }
            }
        }
        Err(e) => {
            if tx
                .send(ScanItem::Skipped {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                })
                .is_err()
            {
                return false;
            }
        }
    }

    tx.send(ScanItem::DirEnd).is_ok()
}

/// Sort the readable children of a directory, recording the ones that failed.
///
/// `read_dir`'s per-entry iterator can yield `Err`: the OS failed partway
/// through enumerating, so an entry exists but cannot be materialized — a
/// network mount dropping, a device disappearing, filesystem corruption. The
/// walkers used to `flatten()` those away, which dropped the entry with
/// nothing recorded anywhere. An acquisition may skip what it cannot read; it
/// may not omit it silently.
///
/// A failure is attributed to `dir`, the directory being listed, because a
/// failed entry has no path of its own — the path is exactly what the OS could
/// not produce.
///
/// Shared by both walkers so they cannot drift: they must emit the same items
/// in the same order for the same tree, and `scanned_and_inline_acquisitions_agree`
/// is the guard. Each caller reports the failures its own way — the scanner
/// sends them, the inline walk pushes them — so this only collects.
///
/// Reads nothing: no path here is opened.
pub(super) fn children_from_entries(
    dir: &std::path::Path,
    entries: impl Iterator<Item = std::io::Result<PathBuf>>,
    failures: &mut Vec<(PathBuf, String)>,
) -> Vec<PathBuf> {
    let mut children = Vec::new();
    for entry in entries {
        match entry {
            Ok(path) => children.push(path),
            Err(e) => failures.push((dir.to_path_buf(), super::logical::explain_io_error(&e))),
        }
    }
    children.sort();
    children
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A directory entry the OS cannot materialize is recorded, not dropped.
    ///
    /// `read_dir`'s per-entry iterator can yield `Err` — a network mount
    /// dropping, a device disappearing, filesystem corruption. `flatten()`
    /// discarded those, so an entry vanished with nothing in the transcript to
    /// say it had ever been seen. A silent omission in the discovery path is
    /// the one thing an acquisition must not do.
    #[test]
    fn an_unreadable_directory_entry_is_recorded() {
        let entries = vec![
            Ok(PathBuf::from("/tree/good.txt")),
            Err(std::io::Error::other("device not configured")),
        ];

        let mut failures = Vec::new();
        let children = children_from_entries(
            std::path::Path::new("/tree"),
            entries.into_iter(),
            &mut failures,
        );

        assert_eq!(children.len(), 1, "the readable entry is kept");
        assert_eq!(children[0], PathBuf::from("/tree/good.txt"));
        assert_eq!(failures.len(), 1, "the failed entry is recorded");
        assert!(
            failures[0].1.contains("device not configured"),
            "the reason must survive: {:?}",
            failures[0]
        );
    }

    /// The failure is attributed to the directory being listed.
    ///
    /// A per-entry `Err` carries no path — the entry is precisely what the OS
    /// could not produce — so the directory that was being enumerated is the
    /// only identifier there is, and reporting it is better than reporting
    /// nothing.
    #[test]
    fn a_failed_entry_is_attributed_to_its_directory() {
        let entries = vec![Err(std::io::Error::other("input/output error"))];

        let mut failures = Vec::new();
        let children = children_from_entries(
            std::path::Path::new("/tree"),
            entries.into_iter(),
            &mut failures,
        );

        assert!(children.is_empty());
        assert_eq!(failures[0].0, PathBuf::from("/tree"));
    }

    /// Readable children come back sorted in whatever order the OS listed them.
    #[test]
    fn readable_children_are_sorted() {
        let entries = vec![
            Ok(PathBuf::from("/tree/c")),
            Ok(PathBuf::from("/tree/a")),
            Ok(PathBuf::from("/tree/b")),
        ];

        let mut failures = Vec::new();
        let children = children_from_entries(
            std::path::Path::new("/tree"),
            entries.into_iter(),
            &mut failures,
        );

        assert_eq!(
            children,
            vec![
                PathBuf::from("/tree/a"),
                PathBuf::from("/tree/b"),
                PathBuf::from("/tree/c"),
            ]
        );
        assert!(failures.is_empty());
    }
}
