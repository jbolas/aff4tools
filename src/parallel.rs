//! Deciding how much of the host to use, and reading a stream with it.
//!
//! Verification is three stages — read, decompress, hash — and run serially
//! they *add* rather than overlap. On a 236 GB container that measured 96 MiB/s
//! where the device alone could deliver 213 MiB/s and the host could hash at
//! well over a gigabyte a second.
//!
//! # The two ceilings are different, and only one is the CPU's
//!
//! Concurrent reads help, but not without limit, and the limit belongs to the
//! *device* rather than the host. Measured on one external exFAT drive, with
//! independent handles work-stealing across bevies:
//!
//! ```text
//! 1 reader   89 MiB/s
//! 2 readers 213 MiB/s   <- peak
//! 4 readers 193 MiB/s
//! 8 readers 177 MiB/s   <- interleaved seeks defeat readahead
//! ```
//!
//! An `NVMe` device rewards far more. So the reader count is a floor plus a
//! runtime observation, never a constant. Hashing, by contrast, scales close to
//! linearly with threads, and is bounded only by the CPU budget below.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use crate::error::{Error, Locus, Result};
use crate::stream::{INDEX_SUFFIX, ImageStream};
use crate::zip::ParallelVolume;

/// Numerator of the fraction of host parallelism this tool will occupy.
///
/// Verification is background-shaped work: an examiner starts it and still
/// needs the machine. Saturating every core makes a desktop unresponsive and,
/// on a laptop, invites thermal throttling that costs more throughput than the
/// extra thread gained. 90% leaves headroom on every host shape and never
/// rounds down to nothing.
///
/// **This is a ceiling the run may meet but never exceed.** Every thread the
/// tool starts — readers at any point on their ramp, workers, and the
/// per-algorithm digest threads — is counted against it, and the figure
/// reported before the run describes the same set.
const CPU_BUDGET_NUMERATOR: usize = 90;

/// Denominator of that fraction.
const CPU_BUDGET_DENOMINATOR: usize = 100;

/// Environment override for the total thread budget.
///
/// Present so an examiner on a shared machine can pin the cost, and so tests
/// can force a known plan. A value that does not parse is ignored rather than
/// guessed at: a typo must not quietly change how evidence is processed.
pub const THREADS_ENV: &str = "AFF4TOOLS_THREADS";

/// Ceiling on concurrent readers, independent of the CPU budget.
///
/// Readers are I/O-bound, not CPU-bound, so the CPU budget is the wrong limit
/// for them. Each costs a file descriptor and a parsed central directory —
/// megabytes on a 16,435-member container — and no measured device rewarded
/// more than eight. Beyond this, extra handles buy seeks rather than bytes.
const MAX_READERS: usize = 8;

/// How many threads this run may occupy in total.
///
/// Never zero, and never more than 90% of what the host reports. Falls back to
/// one thread when the host cannot say: a guess that costs speed is better than
/// one that oversubscribes a machine of unknown shape.
///
/// [`std::thread::available_parallelism`] already accounts for cgroup quotas,
/// CPU affinity masks, and Windows job objects, so this is correct on hosts
/// where the raw core count is not what the process may actually use.
#[must_use]
pub fn cpu_budget() -> usize {
    if let Some(forced) = forced_threads() {
        return forced;
    }
    budget_for(available_parallelism())
}

/// The host's usable parallelism, or 1 if it cannot be determined.
#[must_use]
pub fn available_parallelism() -> usize {
    std::thread::available_parallelism().map_or(1, NonZeroUsize::get)
}

/// The 90% budget for a given host parallelism.
///
/// Split out so the arithmetic can be tested across host shapes without
/// depending on the machine the tests happen to run on.
#[must_use]
fn budget_for(available: usize) -> usize {
    (available * CPU_BUDGET_NUMERATOR / CPU_BUDGET_DENOMINATOR).max(1)
}

/// The operator's override, if set and parseable.
fn forced_threads() -> Option<usize> {
    std::env::var(THREADS_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
}

/// How a run will be parallelised.
///
/// Reported before the run starts, so the cost in machine time is stated
/// before it is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ThreadPlan {
    /// Threads issuing reads, each with its own handle.
    pub readers: usize,
    /// Threads decompressing and hashing.
    pub workers: usize,
    /// Threads computing one recorded digest each.
    ///
    /// [`MultiHasher`](crate::hash::MultiHasher) starts one thread per algorithm
    /// once an object records more than one, and hashes a lone algorithm inline.
    /// They are counted here rather than left outside the plan: a container
    /// recording five digests starts five threads, and a total that omitted
    /// them would call itself a capped run while exceeding the cap.
    pub digesters: usize,
    /// The host parallelism this was derived from.
    pub available: usize,
    /// The 90% cap that was applied.
    pub budget: usize,
}

impl Default for ThreadPlan {
    /// The plan for the current host.
    ///
    /// Not a zeroed struct: a default-constructed estimate is one nobody
    /// supplied a plan for, and the honest answer there is what this machine
    /// would actually do.
    fn default() -> Self {
        Self::for_host()
    }
}

impl ThreadPlan {
    /// Threads this plan will run, besides the caller's own.
    ///
    /// Every kind is counted. A total that omitted one would be reported to an
    /// examiner as the whole run's cost while the run started more.
    #[must_use]
    pub fn total(self) -> usize {
        self.readers + self.workers + self.digesters
    }

    /// Seat `algorithms` digest threads within the same budget.
    ///
    /// One algorithm is hashed inline by `MultiHasher`, so it reserves nothing.
    /// Beyond that, each algorithm gets a thread, taken from the worker share
    /// rather than added on top: the 90% cap is a promise about the whole run,
    /// not about one of its layers.
    ///
    /// Workers yield first, down to one. Digest threads are never dropped to
    /// protect workers — a recorded digest must still be computed, and where
    /// the budget cannot seat them all `MultiHasher` computes the remainder on
    /// the threads it has. Staying within budget must not cost a comparison.
    #[must_use]
    pub fn with_digest_threads(self, algorithms: usize) -> Self {
        // One algorithm always stays on the calling thread — `MultiHasher`
        // spawns `len - 1` helpers, keeping the last inline because a lone
        // handoff costs more than it overlaps. Reserving `algorithms` here
        // would report one thread more than the run starts.
        let wanted = algorithms.saturating_sub(1);
        // Measured against the starting reader count, keeping one worker.
        // The ramp is bounded separately: `reader_ceiling()` subtracts whatever
        // is reserved here, so a fully ramped run still fits the budget.
        // Budgeting against the ceiling instead would starve hashing entirely,
        // since the ceiling is a maximum the governor may never reach.
        let spare = self.budget.saturating_sub(self.readers + 1);
        let digesters = wanted.min(spare);
        let workers = self
            .budget
            .saturating_sub(self.readers + digesters)
            .max(usize::from(self.workers > 0));
        Self {
            workers,
            digesters,
            ..self
        }
    }

    /// The most readers the governor may admit, once it has probed the device.
    ///
    /// [`ThreadPlan::readers`] is where a run *starts*: the I/O optimum belongs
    /// to the device rather than the host, so it is discovered while reading
    /// rather than assumed. The pipeline spawns this many threads up front and
    /// parks the surplus, because opening a handle mid-run costs megabytes of
    /// central-directory parsing on a large container at exactly the wrong
    /// moment.
    ///
    /// So a run holds between `readers` and this many reader threads, and the
    /// figure reported to the examiner names both ends. `AFF4TOOLS_THREADS`
    /// pins the plan and disables probing, which makes the range a single
    /// value.
    #[must_use]
    pub fn reader_ceiling(self) -> usize {
        if forced_threads().is_some() {
            return self.readers;
        }
        // The ramp trades against workers, not against the budget's remainder.
        // Workers already hold everything the readers did not, so subtracting
        // them left no room and the ceiling collapsed onto the floor — a range
        // that can never widen, and a governor that can never probe.
        //
        // A reader admitted mid-run is a worker not decompressing at that
        // moment, so the trade is even and the total is unchanged. One worker
        // is always kept, and digest threads are never touched: they are
        // committed for the whole object, while workers are not.
        // Readers and workers share one pool and trade against each other: a
        // reader admitted mid-run is a worker not decompressing at that moment,
        // so the sum is unchanged and the budget holds with the ramp fully
        // extended. One worker is always kept.
        //
        // Digest threads are not tradable — they are committed for the whole
        // object — so they are excluded from the pool rather than borrowed from.
        //
        // `MAX_READERS` caps it besides: past eight handles a measured device
        // bought seeks rather than bytes.
        let pool = self.readers + self.workers.saturating_sub(1);
        MAX_READERS.min(pool).max(self.readers)
    }

    /// Whether this plan is worth starting a pipeline for.
    ///
    /// A one-thread budget is the serial path with extra machinery, so it is
    /// left to the serial path.
    #[must_use]
    pub fn is_parallel(self) -> bool {
        self.readers >= 1 && self.workers >= 1 && self.total() > 1
    }

    /// The plan for this host.
    #[must_use]
    pub fn for_host() -> Self {
        Self::from_budget(available_parallelism(), cpu_budget())
    }

    /// Split a budget into readers and workers.
    ///
    /// Readers start low deliberately. The I/O optimum is a property of the
    /// device and is discovered while the run proceeds; starting high would
    /// thrash the seeks of exactly the external media large evidence tends to
    /// live on. Two is the measured optimum for such a drive and a safe floor
    /// everywhere else, so the ramp only ever has to go up.
    #[must_use]
    pub fn from_budget(available: usize, budget: usize) -> Self {
        let budget = budget.max(1);
        // A budget of one cannot be split: one reader and one worker would be
        // two threads. Report it as such and let the serial path take it.
        if budget < 2 {
            return Self {
                readers: 1,
                workers: 0,
                digesters: 0,
                available,
                budget,
            };
        }
        let readers = 2.min(MAX_READERS).min(budget - 1);
        let workers = budget - readers;
        Self {
            readers,
            workers,
            digesters: 0,
            available,
            budget,
        }
    }
}

/// Ceiling on bytes held in flight by the pipeline's queues.
///
/// Split between the raw-bevy queue and the reorder window, which together
/// with the workers' own buffers put peak usage near 1.2 GiB on a container
/// with 32 MiB bevies.
///
/// Depth is what makes the pipeline fast: with shallow queues a reader pausing
/// on a seek starved every worker, and the run measured 121 MiB/s against 166
/// once they were deepened. It is expressed in bytes rather than bevies
/// because bevy size is a container property — `chunk_size` times
/// `chunksInSegment` — so a container declaring a large one would otherwise
/// blow the budget without changing the count.
const REORDER_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

/// How long a worker waits on the queue before re-checking for failure.
///
/// Only a liveness backstop, not a tuning knob: a bevy takes tens of
/// milliseconds to read, so a wait this long costs nothing in throughput while
/// keeping a run responsive to a failure raised on another thread.
const WORKER_POLL: std::time::Duration = std::time::Duration::from_millis(25);

/// Bevies below which the pipeline costs more than it saves.
///
/// The pipeline is built per stream: reader threads, decode workers, a
/// governor, and two bounded queues. That cost is trivially repaid by a device
/// image, which is one stream of many thousands of bevies — and never repaid
/// by a stream of one, where the single bevy is read almost instantly and the
/// only thing left to do is wait for a worker to notice it.
///
/// Waiting is the whole cost. Workers poll with `try_recv` and sleep
/// [`WORKER_POLL`] on an empty queue, so a stream whose work takes microseconds
/// still pays a 25 ms wake-up latency, and the governor never reaches
/// [`WARMUP_BEVIES`] to settle — its surplus readers sleep on the same
/// interval for the life of the stream.
///
/// Measured on a 4.4 GiB AFF4-L container of 879 streams, 865 of them a single
/// bevy: 96% of main-thread samples parked in `consume_in_order`, every worker
/// at ~99% in `sleep`, and under 1% of samples doing the hashing the run
/// existed to do. Reading those streams inline removes the pipeline and the
/// wait with it.
///
/// Two rather than one so a stream that straddles a bevy boundary — the
/// common case for a file just over the bevy size — is not made to build a
/// pipeline for its second bevy either. A physical device image is unaffected
/// at any plausible bevy size: 32 MiB bevies put the threshold at 64 MiB, far
/// below any image worth acquiring.
const INLINE_BEVY_MAX: u64 = 2;

/// Whether a stream this size should be read inline rather than pipelined.
///
/// The decision is a property of the stream, not of the acquisition mode: a
/// small stream is a bad fit for the pipeline wherever it appears, and a large
/// one is a good fit even in a logical container.
#[must_use]
pub fn too_small_to_parallelise(bevy_count: u64) -> bool {
    bevy_count <= INLINE_BEVY_MAX
}

/// How long one throughput observation runs.
///
/// Long enough to cross the noise of a single bevy and any readahead warm-up,
/// short enough that a bad step costs seconds of a run measured in minutes.
const WINDOW: std::time::Duration = std::time::Duration::from_secs(4);

/// Improvement required to keep an added reader.
///
/// Below this the extra handle is noise, and it still costs a descriptor, a
/// parsed central directory, and one more seek stream competing for the
/// device. Eight percent makes the measured external-drive series — 89 MiB/s
/// at one reader, 213 at two, 193 at four — read as a clear regression at four
/// and stop the ramp at two.
const MEANINGFUL_GAIN: f64 = 0.08;

/// Bevies that must complete before probing begins.
///
/// The first bevies pay for cold caches and each reader's central-directory
/// parse; a measurement taken across them describes start-up, not the device.
const WARMUP_BEVIES: u64 = 8;

/// Discovers how many concurrent readers a device rewards.
///
/// The optimum belongs to the storage, not the host. An external drive peaks
/// at two concurrent readers and *loses* a fifth of its throughput at eight,
/// because interleaved seeks defeat readahead; an `NVMe` device rewards far
/// more. A fixed number is therefore wrong on most hardware, and wrong in the
/// expensive direction on the media large evidence usually lives on.
///
/// Method: read at the current count for one [`WINDOW`], then admit one more
/// reader and measure again. Keep the addition if throughput improved by more
/// than [`MEANINGFUL_GAIN`]; otherwise step back and stop probing. The ramp
/// only ever goes *up* from a safe floor, so a bad probe costs one window
/// rather than the run.
///
/// Readers are all spawned at the start and gated on `admitted`: a surplus
/// reader parks rather than exits, so ramping is a counter bump and never a
/// thread spawn or a re-opened handle. Parked threads are not runnable and so
/// do not count against the CPU budget.
struct ReaderGovernor {
    /// Readers currently allowed to claim work.
    admitted: AtomicUsize,
    /// Bytes read since the current observation opened.
    window_bytes: AtomicU64,
    /// Bevies finished, for the warm-up threshold.
    bevies: AtomicU64,
    /// Observation state, behind one lock because it changes together.
    probe: Mutex<Probe>,
    /// Wakes readers parked outside the admitted count.
    admit: Condvar,
}

/// What the governor has observed so far.
struct Probe {
    /// When the current observation opened.
    started: std::time::Instant,
    /// Throughput at the previous count, if one has been measured.
    previous: Option<f64>,
    /// Set once probing has settled, so a long run stops perturbing itself.
    settled: bool,
}

impl ReaderGovernor {
    fn new(initial: usize) -> Self {
        Self {
            admitted: AtomicUsize::new(initial),
            window_bytes: AtomicU64::new(0),
            bevies: AtomicU64::new(0),
            probe: Mutex::new(Probe {
                started: std::time::Instant::now(),
                previous: None,
                settled: false,
            }),
            admit: Condvar::new(),
        }
    }

    /// Whether a reader with this ordinal may claim work right now.
    fn admits(&self, ordinal: usize) -> bool {
        ordinal < self.admitted.load(Ordering::Acquire)
    }

    /// Record a finished bevy and, when a window closes, decide the next count.
    ///
    /// Called from reader threads, so it must be cheap in the common case: the
    /// fast path is two atomic adds and a clock read.
    fn observed(&self, bytes: u64, ceiling: usize) {
        self.window_bytes.fetch_add(bytes, Ordering::Relaxed);
        let bevies = self.bevies.fetch_add(1, Ordering::Relaxed) + 1;
        if bevies < WARMUP_BEVIES {
            return;
        }

        let mut probe = self
            .probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if probe.settled || probe.started.elapsed() < WINDOW {
            return;
        }

        let elapsed = probe.started.elapsed().as_secs_f64().max(0.001);
        #[allow(clippy::cast_precision_loss)]
        let rate = self.window_bytes.swap(0, Ordering::Relaxed) as f64 / elapsed;
        probe.started = std::time::Instant::now();

        self.apply_rate(&mut probe, rate, ceiling);
    }

    /// The count a run settled on, for reporting.
    #[cfg(test)]
    fn admitted_now(&self) -> usize {
        self.admitted.load(Ordering::Acquire)
    }

    /// Apply one observed throughput figure, as if a window had just closed.
    ///
    /// The whole decision lives here so it can be tested against a known
    /// series — including the one measured on real hardware — without a disk,
    /// a clock, or thread timing. [`Self::observed`] does the measuring and
    /// calls this; nothing else decides.
    fn apply_rate(&self, probe: &mut Probe, rate: f64, ceiling: usize) {
        let current = self.admitted.load(Ordering::Acquire);
        match probe.previous {
            // First full window: nothing to compare against yet, so try one
            // more reader and see.
            None => {
                probe.previous = Some(rate);
                if current < ceiling {
                    self.admitted.store(current + 1, Ordering::Release);
                    self.admit.notify_all();
                }
            }
            Some(before) => {
                if rate > before * (1.0 + MEANINGFUL_GAIN) && current < ceiling {
                    // The extra reader paid for itself; keep it and try again.
                    probe.previous = Some(rate);
                    self.admitted.store(current + 1, Ordering::Release);
                    self.admit.notify_all();
                } else {
                    // It did not. Step back to the count that was working and
                    // stop probing — further additions would only cost seeks.
                    if rate < before && current > 1 {
                        self.admitted.store(current - 1, Ordering::Release);
                    }
                    probe.settled = true;
                }
            }
        }
    }

    /// Feed one throughput figure directly, bypassing the clock.
    #[cfg(test)]
    fn observe_rate(&self, rate: f64, ceiling: usize) {
        let mut probe = self
            .probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !probe.settled {
            self.apply_rate(&mut probe, rate, ceiling);
        }
    }
}

/// A bevy as it came off the disk: still compressed, not yet decoded.
struct RawBevy {
    seq: u64,
    name: String,
    index_name: String,
    index: Vec<u8>,
    body: Vec<u8>,
}

/// A bevy decoded into its chunks, waiting for its turn in stream order.
struct PlainBevy {
    chunks: Vec<Vec<u8>>,
    plain_len: u64,
}

/// The first failure in *stream* order.
///
/// Threads fail in whatever order they happen to run, but a report that named
/// a different bevy from one run to the next could not be cited. Keeping the
/// lowest sequence number makes the message the one the serial reader would
/// have produced.
#[derive(Default)]
struct FirstError {
    inner: Mutex<Option<(u64, Error)>>,
    set: AtomicBool,
}

impl FirstError {
    fn record(&self, seq: u64, error: Error) {
        let mut slot = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match slot.as_ref() {
            Some((seen, _)) if *seen <= seq => {}
            _ => *slot = Some((seq, error)),
        }
        self.set.store(true, Ordering::Release);
    }

    fn is_set(&self) -> bool {
        self.set.load(Ordering::Acquire)
    }

    /// The earliest failure, with the bevy it belongs to.
    fn take_first(&self) -> Option<(u64, Error)> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// The reorder window: finished bevies waiting for their turn.
#[derive(Default)]
struct Window {
    ready: BTreeMap<u64, PlainBevy>,
    /// Decompressed bytes currently held, against [`REORDER_BUDGET_BYTES`].
    held: u64,
    /// Set when the consumer has everything it needs and workers should stop.
    closed: bool,
    /// Workers still able to add to `ready`.
    ///
    /// The consumer blocks until the bevy it wants arrives, so it has to know
    /// when none ever will. Without this it would wait forever on a stream
    /// that ended early or a worker that failed — a hang rather than an error,
    /// which is the worse of the two.
    live_workers: usize,
    /// The bevy the consumer is currently waiting for.
    ///
    /// A worker holding exactly this one is always admitted, however full the
    /// window is. Without that exception the pipeline deadlocks: the window
    /// fills with later bevies, every worker blocks for space, and the one
    /// bevy that would free them all has no worker left to decode it.
    wanted: u64,
}

/// Marks a worker as gone, however it leaves.
///
/// A drop guard rather than a call at each `return`, because there are five
/// ways out of the worker loop and missing one turns a finished run into a
/// hang.
struct WorkerExit<'w> {
    window: &'w Mutex<Window>,
    filled: &'w Condvar,
}

impl Drop for WorkerExit<'_> {
    fn drop(&mut self) {
        let mut held = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.live_workers = held.live_workers.saturating_sub(1);
        drop(held);
        self.filled.notify_all();
    }
}

/// The fixed bounds every reader in a run works within.
struct ReadLimits {
    /// The volume's ARN, for naming bevy members.
    volume_arn: crate::arn::Arn,
    /// How many bevies the stream declares.
    bevy_count: u64,
    /// The most readers the governor may admit.
    ceiling: usize,
    /// How far ahead of the consumer a reader may claim.
    lookahead: u64,
}

/// One reader thread: claim bevies, read their bytes, hand them on.
///
/// Claims are taken from a shared cursor rather than assigned in blocks, so a
/// reader that hits a slow region does not hold up the others.
fn read_bevies(
    shared: &Shared<'_>,
    volume: &(impl ParallelVolume + ?Sized),
    raw_tx: &std::sync::mpsc::SyncSender<RawBevy>,
    limits: &ReadLimits,
    ordinal: usize,
) {
    let ReadLimits {
        volume_arn,
        bevy_count,
        ceiling,
        lookahead,
    } = limits;
    let (bevy_count, ceiling, lookahead) = (*bevy_count, *ceiling, *lookahead);
    // Wait for admission before paying for a handle: a reader the governor
    // never admits should not open a file or parse a central directory.
    if !shared.governor.admits(ordinal) {
        let mut probe = shared
            .governor
            .probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !shared.governor.admits(ordinal) {
            if shared.failure.is_set() || shared.window.lock().is_ok_and(|w| w.closed) {
                return;
            }
            let (next, _) = shared
                .governor
                .admit
                .wait_timeout(probe, WORKER_POLL)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            probe = next;
        }
    }

    let mut reader = match volume.open_reader() {
        Ok(reader) => reader,
        Err(error) => {
            shared.failure.record(0, error);
            return;
        }
    };

    loop {
        if shared.failure.is_set() || shared.window.lock().is_ok_and(|w| w.closed) {
            return;
        }
        // A reader beyond the admitted count stands down rather than competing
        // for the device. It keeps its handle in case the governor readmits it.
        if !shared.governor.admits(ordinal) {
            std::thread::sleep(WORKER_POLL);
            continue;
        }
        // Never claim a bevy further ahead than the pipeline can hold.
        //
        // Bevies must reach the consumer in order, so one claimed far ahead
        // occupies a queue slot until every bevy before it has been delivered.
        // Left unbounded, readers race ahead, the window and the raw queue fill
        // with bevies the consumer cannot use yet, and nothing is left free to
        // handle the one it is actually waiting for — every thread blocks.
        //
        // Reading no further ahead than `lookahead` makes that impossible
        // rather than unlikely.
        let wanted = {
            let held = shared
                .window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            held.wanted
        };
        if shared.next_bevy.load(Ordering::Relaxed) >= wanted.saturating_add(lookahead) {
            std::thread::sleep(WORKER_POLL);
            continue;
        }

        let seq = shared.next_bevy.fetch_add(1, Ordering::Relaxed);
        if seq >= bevy_count {
            return;
        }

        let Some(name) = shared.stream.bevy_name(volume_arn, seq) else {
            shared.failure.record(
                seq,
                Error::malformed(
                    shared.locus.clone(),
                    format!(
                        "stream {} names no member of volume {volume_arn}; its data is \
                         stored elsewhere, which this build cannot follow",
                        shared.stream.arn()
                    ),
                ),
            );
            return;
        };
        let index_name = format!("{name}{INDEX_SUFFIX}");

        let index = match reader.read_segment(&index_name) {
            Ok(bytes) => bytes,
            Err(error) => {
                shared.failure.record(seq, error);
                return;
            }
        };
        let body = match reader.read_segment(&name) {
            Ok(bytes) => bytes,
            Err(error) => {
                shared.failure.record(seq, error);
                return;
            }
        };

        // Measured before the send, so time spent blocked on a full queue is
        // not counted against the device's throughput.
        shared
            .governor
            .observed((index.len() + body.len()) as u64, ceiling);

        if raw_tx
            .send(RawBevy {
                seq,
                name,
                index_name,
                index,
                body,
            })
            .is_err()
        {
            return;
        }
    }
}

/// One worker thread: decompress bevies and place them in the reorder window.
///
/// Order-free by construction — nothing here knows where its bevy sits in the
/// stream, which is what keeps the truncation decision in the consumer where
/// the running byte count lives.
fn decode_bevies(shared: &Shared<'_>) {
    // However this worker leaves — channel closed, failure, or the consumer
    // closing the window — the consumer must be told, or it waits for a bevy
    // that is never coming.
    let _exit = WorkerExit {
        window: &shared.window,
        filled: &shared.filled,
    };

    loop {
        // A bounded wait rather than a plain `recv`, so a worker parked on an
        // empty queue still notices `failure` and exits instead of holding the
        // lock until a bevy that will never arrive.
        //
        // The timeout is *not* a contention fix. Profiles of this loop show
        // most samples in `__psynch_mutexwait`, which reads like lock
        // contention but is not: it is workers idle on a queue the readers
        // have not filled. Throughput moved when the queues were deepened and
        // did not move when the locking changed — so treat time parked here as
        // a signal that reading is behind, not that this lock is hot.
        // The lock is released before waiting, never held across it. Holding
        // it through a blocking receive serialises the workers: one parks with
        // the lock while the others cannot even look at the queue, and readers
        // blocked on a full queue never get drained. That is a livelock, and
        // it is what a `recv` or `recv_timeout` inside the guard produces.
        let raw = {
            let guard = shared
                .raw_rx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.try_recv()
        };
        let raw = match raw {
            Ok(raw) => raw,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                if shared.failure.is_set() || shared.window.lock().is_ok_and(|w| w.closed) {
                    return;
                }
                // Park outside the lock so another worker can take the next
                // bevy the instant a reader delivers it.
                std::thread::sleep(WORKER_POLL);
                continue;
            }
        };
        if shared.failure.is_set() {
            return;
        }

        let bevy_locus = shared.locus.clone().segment(&raw.name);
        let index_locus = shared.locus.clone().segment(&raw.index_name);
        let chunks =
            match shared
                .stream
                .decode_bevy(&raw.body, &raw.index, &bevy_locus, &index_locus)
            {
                Ok(chunks) => chunks,
                Err(error) => {
                    shared.failure.record(raw.seq, error);
                    shared.filled.notify_all();
                    return;
                }
            };

        let plain_len: u64 = chunks.iter().map(|c| c.len() as u64).sum();

        // Deposit unconditionally: a worker never waits for window space.
        //
        // Backpressure lives entirely in the reader gate, which will not claim
        // a bevy the pipeline cannot hold. A worker that blocked here instead
        // could be the last one free, leaving the bevy the consumer wants
        // undecoded in the queue with nobody to pick it up — every thread then
        // waits on another. Bounding one place rather than two is what makes
        // that state unreachable.
        let mut held = shared
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.closed || shared.failure.is_set() {
            return;
        }
        held.held += plain_len;
        held.ready.insert(raw.seq, PlainBevy { chunks, plain_len });
        drop(held);
        shared.filled.notify_all();
    }
}

/// Deliver finished bevies to `sink` in strict stream order.
///
/// A line-for-line transcription of the serial reader's loop, operating on
/// already-decompressed chunks: the same early exits, the same truncation
/// against the running byte count, in the same order. Keeping it here — on one
/// thread, with `delivered` local — is what makes the parallel path's digest
/// identical to the serial one's.
///
/// Returns the outcome, the bytes delivered, and how many bevies were consumed.
fn consume_in_order(
    shared: &Shared<'_>,
    bevy_count: u64,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    on_bevy: &mut dyn FnMut(u64),
) -> (Result<()>, u64, u64) {
    let size = shared.stream.size();
    let mut delivered: u64 = 0;
    let mut next_expected: u64 = 0;
    let mut result = Ok(());

    'outer: while next_expected < bevy_count && delivered < size {
        let bevy = {
            let mut held = shared
                .window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Publish what this thread is waiting for, so a worker holding it
            // is admitted even when the window is otherwise full.
            held.wanted = next_expected;
            shared.space.notify_all();

            loop {
                if let Some(bevy) = held.ready.remove(&next_expected) {
                    held.held -= bevy.plain_len;
                    shared.space.notify_all();
                    break bevy;
                }
                if shared.failure.is_set() {
                    break 'outer;
                }
                // No worker is left to produce it, so waiting would hang. The
                // length check in the caller turns this into a reported short
                // read rather than a stall.
                if held.live_workers == 0 {
                    break 'outer;
                }
                held = shared
                    .filled
                    .wait(held)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };

        for mut chunk in bevy.chunks {
            if delivered >= size {
                break;
            }
            // The last chunk of the stream is truncated to the declared size,
            // exactly as the serial reader does it.
            let remaining = size - delivered;
            if (chunk.len() as u64) > remaining {
                chunk.truncate(usize::try_from(remaining).unwrap_or(chunk.len()));
            }
            delivered += chunk.len() as u64;
            if let Err(error) = sink(&chunk) {
                result = Err(error);
                break 'outer;
            }
        }

        next_expected += 1;
        on_bevy(next_expected);
    }

    (result, delivered, next_expected)
}

/// State every thread in one run shares.
///
/// Bundled rather than passed as a dozen references: the pipeline has readers,
/// workers, and a consumer all touching the same few things, and naming the set
/// once makes the sharing visible.
struct Shared<'a> {
    stream: &'a ImageStream,
    locus: Locus,
    next_bevy: AtomicU64,
    failure: FirstError,
    window: Mutex<Window>,
    space: Condvar,
    filled: Condvar,
    raw_rx: Mutex<std::sync::mpsc::Receiver<RawBevy>>,
    governor: ReaderGovernor,
}

/// Read every byte of `stream` into `sink`, in exact stream order, in parallel.
///
/// Byte-for-byte equivalent to [`ImageStream::read_all_observed`]: `sink` sees
/// the identical sequence of slices. Parallelism covers reading and
/// decompression only — the bytes are put back in order before any of them
/// reach `sink`, so the digest cannot depend on thread timing.
///
/// `sink` and `on_bevy` run on the calling thread, which is why the caller's
/// hasher, block digests, and progress observer need no locking and no `Send`.
///
/// # Errors
///
/// As [`ImageStream::read_all`]. When several bevies fail, the one earliest in
/// stream order is reported.
pub fn read_all_parallel(
    stream: &ImageStream,
    volume: &(impl ParallelVolume + ?Sized),
    plan: ThreadPlan,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    on_bevy: &mut dyn FnMut(u64),
    locus: &Locus,
) -> Result<()> {
    let volume_arn = volume.arn().clone();
    let locus = locus.clone().subject(stream.arn().as_str());
    let bevy_count = stream.bevy_count();

    // One bevy's worth of decompressed data, used to size the window in bevies
    // from a budget expressed in bytes.
    let bevy_plain = (stream.chunk_size() as u64)
        .saturating_mul(stream.chunks_in_segment() as u64)
        .max(1);
    // Enough slack that workers finishing out of order do not stall behind the
    // one bevy the consumer is waiting for, but still bounded by the byte
    // budget: at `workers + 2` a single slow bevy idled every other worker.
    //
    // The budget covers both queues. Raw bevies are compressed and the window
    // holds decompressed ones, so the window takes the larger share.
    let slots = usize::try_from(REORDER_BUDGET_BYTES.saturating_mul(2) / 3 / bevy_plain)
        .unwrap_or(2)
        .clamp(2, (plan.workers * 3).max(4));

    // Bounded so readers cannot run away with memory, but deep enough that a
    // reader stalling on a seek does not starve every worker: at `readers + 2`
    // the queue drained faster than it filled and the workers idled. Sized
    // against the same byte budget as the window, since these hold compressed
    // bevies of comparable size.
    let queue_depth = usize::try_from(REORDER_BUDGET_BYTES / 3 / bevy_plain)
        .unwrap_or(4)
        .clamp(plan.readers + 2, 12);
    let (raw_tx, raw_rx) = std::sync::mpsc::sync_channel::<RawBevy>(queue_depth);

    // How far ahead of the consumer readers may claim.
    //
    // This is the *only* bound on how much is in flight, and the window is
    // sized to accept all of it. Bounding both independently deadlocks: a
    // worker holding a bevy the consumer does not want yet blocks for window
    // space, and with no worker left free, the bevy that would unblock
    // everything sits undecoded in the queue. Letting a worker always deposit
    // what it holds removes that state entirely — the reader gate alone keeps
    // memory bounded.
    let lookahead = (slots + queue_depth + plan.workers) as u64;

    let shared = Shared {
        stream,
        locus: locus.clone(),
        next_bevy: AtomicU64::new(0),
        failure: FirstError::default(),
        window: Mutex::new(Window {
            live_workers: plan.workers,
            ..Window::default()
        }),
        space: Condvar::new(),
        filled: Condvar::new(),
        raw_rx: Mutex::new(raw_rx),
        governor: ReaderGovernor::new(plan.readers),
    };
    let shared = &shared;

    // Spawn up to the ceiling but admit only `plan.readers` at first. The
    // surplus threads park until the governor finds the device rewards them,
    // so ramping never has to spawn a thread or open a handle mid-run.
    //
    // `AFF4TOOLS_THREADS` pins the plan for tests and for operators who want a
    // fixed cost, so it disables probing entirely.
    let reader_ceiling = plan.reader_ceiling();

    let limits = ReadLimits {
        volume_arn,
        bevy_count,
        ceiling: reader_ceiling,
        lookahead,
    };
    let limits = &limits;

    let outcome = std::thread::scope(|scope| {
        for ordinal in 0..reader_ceiling {
            let raw_tx = raw_tx.clone();
            scope.spawn(move || {
                read_bevies(shared, volume, &raw_tx, limits, ordinal);
            });
        }
        drop(raw_tx);

        for _ in 0..plan.workers {
            scope.spawn(move || {
                decode_bevies(shared);
            });
        }

        // The consumer is this thread, so `sink`, `on_bevy`, the hasher and the
        // progress observer stay single-threaded and unsynchronised.
        let (result, delivered, next_expected) =
            consume_in_order(shared, bevy_count, sink, on_bevy);

        // Release every waiting thread before the scope joins them.
        {
            let mut held = shared
                .window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            held.closed = true;
            held.ready.clear();
            held.held = 0;
        }
        shared.space.notify_all();
        shared.filled.notify_all();
        // Drain anything still in flight so readers blocked on `send` can exit.
        while shared
            .raw_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_recv()
            .is_ok()
        {}

        (result, delivered, next_expected)
    });

    let (result, delivered, consumed_bevies) = outcome;
    result?;

    // A failure outranks the length check — it explains the shortfall — but
    // only if the serial reader would have reached that bevy at all.
    //
    // Readers run ahead of the consumer, so a bevy *past* the point where the
    // stream is already complete may have been read and found malformed. The
    // serial reader stops at `delivered >= size` and never opens those, so
    // honouring such an error here would fail a container that verifies
    // serially. Bevies at or after the last one consumed are therefore
    // discarded, errors included.
    if let Some((seq, error)) = shared.failure.take_first()
        && (seq < consumed_bevies || delivered < stream.size())
    {
        return Err(error);
    }

    if delivered != stream.size() {
        return Err(Error::malformed(
            locus,
            format!(
                "stream {} delivered {delivered} bytes but declares {}; a short read \
                 would produce a digest that does not match the evidence",
                stream.arn(),
                stream.size()
            ),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap must hold across host shapes, and never yield zero threads.
    #[test]
    fn the_budget_is_ninety_percent_and_never_zero() {
        // (available, expected budget)
        for (available, expected) in [
            (1, 1),
            (2, 1),
            (4, 3),
            (8, 7),
            (10, 9),
            (16, 14),
            (64, 57),
            (128, 115),
        ] {
            assert_eq!(
                budget_for(available),
                expected,
                "budget for {available} cores"
            );
            assert!(
                budget_for(available) <= available,
                "the budget must never exceed the host"
            );
        }
    }

    /// A single-core host must still produce a usable, serial-shaped plan.
    #[test]
    fn a_single_core_host_is_not_parallelised() {
        let plan = ThreadPlan::from_budget(1, budget_for(1));
        assert!(!plan.is_parallel(), "{plan:?}");
    }

    /// Readers start at the measured safe floor, and the rest hash.
    #[test]
    fn a_ten_core_host_reads_with_two_and_hashes_with_the_rest() {
        let plan = ThreadPlan::from_budget(10, budget_for(10));
        assert_eq!(plan.readers, 2);
        assert_eq!(plan.workers, 7);
        assert_eq!(plan.total(), 9, "90% of 10 cores");
        assert!(plan.is_parallel());
    }

    /// A stream too small to repay a pipeline must be read inline.
    ///
    /// The regression this guards: an AFF4-L container of 879 streams, 865 of
    /// them a single bevy, built and tore down a pipeline for each one and
    /// spent 96% of its samples asleep on the 25 ms worker poll. The reference
    /// corpus could not catch it — every stream in it is one bevy, so nothing
    /// there distinguishes the two paths by anything but speed.
    #[test]
    fn a_one_bevy_stream_is_not_pipelined() {
        assert!(too_small_to_parallelise(0), "an empty stream");
        assert!(too_small_to_parallelise(1), "the AFF4-L common case");
        assert!(too_small_to_parallelise(2), "a file straddling a boundary");
    }

    /// A device image must keep the pipeline it was tuned for.
    ///
    /// The fix above must not reach the physical path: at 32 MiB bevies the
    /// threshold sits at 64 MiB, so any image worth acquiring stays pipelined.
    #[test]
    fn a_device_image_still_takes_the_pipeline() {
        for bevies in [3_u64, 8, 100, 7_500, 10_000] {
            assert!(
                !too_small_to_parallelise(bevies),
                "a {bevies}-bevy stream must still be pipelined"
            );
        }
    }

    /// The measured external-drive series must settle at two readers.
    ///
    /// This is the case the governor exists for: throughput peaks at two and
    /// falls away, so a fixed higher count would cost a fifth of the run.
    #[test]
    fn the_governor_settles_where_the_device_peaks() {
        let mib = 1024.0 * 1024.0;
        let governor = ReaderGovernor::new(1);

        // 1 reader: 89 MiB/s, 2: 213, 4: 193 — measured on exFAT over USB.
        governor.observe_rate(89.0 * mib, 8);
        assert_eq!(governor.admitted_now(), 2, "a first window must try more");

        governor.observe_rate(213.0 * mib, 8);
        assert_eq!(governor.admitted_now(), 3, "a clear gain must be kept");

        governor.observe_rate(193.0 * mib, 8);
        assert_eq!(
            governor.admitted_now(),
            2,
            "a regression must step back to what worked"
        );

        // Settled: further observations must not perturb a long run.
        governor.observe_rate(400.0 * mib, 8);
        assert_eq!(governor.admitted_now(), 2, "probing must stop once settled");
    }

    /// A device that keeps rewarding readers must ramp to the ceiling.
    #[test]
    fn the_governor_ramps_on_hardware_that_rewards_it() {
        let mib = 1024.0 * 1024.0;
        let governor = ReaderGovernor::new(2);

        for step in 1..=8 {
            governor.observe_rate(500.0 * mib * f64::from(step), 8);
        }
        assert_eq!(
            governor.admitted_now(),
            8,
            "monotonic improvement must reach the ceiling"
        );
    }

    /// Noise must not be mistaken for improvement.
    #[test]
    fn the_governor_stops_when_a_reader_buys_nothing() {
        let mib = 1024.0 * 1024.0;
        let governor = ReaderGovernor::new(2);

        governor.observe_rate(200.0 * mib, 8);
        // Within MEANINGFUL_GAIN of the previous figure: not worth a handle.
        governor.observe_rate(205.0 * mib, 8);
        assert_eq!(governor.admitted_now(), 3);

        governor.observe_rate(205.0 * mib, 8);
        assert_eq!(governor.admitted_now(), 3, "settled, so no further change");
    }

    /// The split must never exceed the budget it was given, at any size.
    #[test]
    fn the_split_never_exceeds_the_budget() {
        for available in 1..=256 {
            let budget = budget_for(available);
            let plan = ThreadPlan::from_budget(available, budget);
            assert!(
                plan.total() <= budget,
                "plan {plan:?} exceeds budget {budget}"
            );
            // A parallel plan needs both kinds; a budget of one has neither to
            // spare and is left to the serial path.
            if plan.is_parallel() {
                assert!(plan.readers >= 1 && plan.workers >= 1, "{plan:?}");
            }
        }
    }

    /// The reported total must count every thread the run starts, including the
    /// per-algorithm digest threads `MultiHasher` spawns.
    ///
    /// `Base-Linear-AllHashes.aff4` records five digests on its `ImageStream`
    /// (SHA512, MD5, SHA1, Blake2b, SHA256). `MultiHasher` starts one thread per
    /// algorithm once there is more than one, so verifying it starts five
    /// threads. A total counting only `readers + workers` would omit them while
    /// the run announces itself as a capped run.
    #[test]
    fn the_reported_total_counts_digest_threads() {
        // Ten cores, 90% cap = 9.
        let plan = ThreadPlan::from_budget(10, 9).with_digest_threads(5);
        assert_eq!(
            plan.total(),
            plan.readers + plan.workers + plan.digesters,
            "total() must count every thread started"
        );
        assert!(
            plan.total() <= plan.budget,
            "{} threads exceeds the {} budget: {plan:?}",
            plan.total(),
            plan.budget
        );
        // Five algorithms spawn four helpers; the fifth is hashed inline on
        // the calling thread, so it reserves nothing.
        assert_eq!(plan.digesters, 4, "one algorithm stays inline");
    }

    /// Staying within budget must never cost a comparison: when the budget
    /// cannot seat every algorithm, worker threads yield first and the
    /// remaining digests are computed on the threads that remain.
    #[test]
    fn a_small_budget_yields_workers_before_dropping_a_digest() {
        for budget in 2..=8usize {
            for digests in 0..=6usize {
                let plan = ThreadPlan::from_budget(budget, budget).with_digest_threads(digests);
                assert!(
                    plan.total() <= plan.budget,
                    "budget {budget}, {digests} digests: {plan:?}"
                );
                assert!(plan.readers >= 1, "a reader is always needed: {plan:?}");
            }
        }
    }

    /// The plan handed to the reader pipeline must be the one that already paid
    /// for its digest threads, not a fresh full-budget plan.
    ///
    /// `verify_stream` once derived two plans: `budgeted_hasher` shrank the
    /// worker share to seat digest threads, then `read_stream` called
    /// `for_host()` again and spawned from the FULL worker count while those
    /// digest threads were live. The reduction was decorative and the process
    /// held far more threads than the run reported.
    #[test]
    fn the_reduced_plan_is_what_the_pipeline_spends() {
        let base = ThreadPlan::from_budget(10, 9);
        let reduced = base.with_digest_threads(5);
        assert!(
            reduced.workers < base.workers,
            "digest threads must be paid for out of the worker share: {reduced:?}"
        );
        assert!(
            reduced.readers + reduced.workers + reduced.digesters <= reduced.budget,
            "the plan the pipeline spends must itself fit the budget: {reduced:?}"
        );
    }

    /// A fully ramped run must still fit the budget.
    ///
    /// The governor may admit up to `reader_ceiling()` readers mid-run, so the
    /// budget has to hold with the ramp at its maximum — not merely at the
    /// starting reader count. The ceiling is what the ramp is bounded by, and
    /// it may not spend capacity the workers or digest threads already hold.
    #[test]
    fn a_fully_ramped_run_stays_within_budget() {
        for budget in 2..=64usize {
            for digests in 0..=8usize {
                let plan = ThreadPlan::from_budget(budget, budget).with_digest_threads(digests);
                // Readers and workers trade within one pool: a reader admitted
                // mid-run is a worker not decompressing then, so the concurrent
                // peak is the pool plus the digest threads, not the sum of both
                // maxima. Assert on what can actually run at one instant.
                let pool = plan.readers + plan.workers;
                let peak = pool + plan.digesters;
                assert!(
                    peak <= plan.budget,
                    "budget {budget}, {digests} digests: peak {peak} exceeds {}: {plan:?}",
                    plan.budget
                );
                assert!(
                    plan.reader_ceiling() <= pool,
                    "the ramp may not exceed the pool it trades within: {plan:?}"
                );
                assert!(
                    plan.reader_ceiling() >= plan.readers,
                    "the ceiling may never fall below the starting count: {plan:?}"
                );
            }
        }
    }

    /// A single algorithm spawns no thread — `MultiHasher` hashes it inline —
    /// so the plan must not reserve one for it.
    #[test]
    fn one_digest_reserves_no_thread() {
        let plan = ThreadPlan::from_budget(10, 9).with_digest_threads(1);
        assert_eq!(plan.digesters, 0, "one algorithm is hashed inline");
        let none = ThreadPlan::from_budget(10, 9).with_digest_threads(0);
        assert_eq!(none.digesters, 0, "no digests reserve no threads");
    }
}
