//! Computing digests over stream data.
//!
//! Feature 2 reports the digests a container *recorded*. This module computes
//! them from the bytes, which is what makes verification possible.
//!
//! # One pass, several algorithms
//!
//! `Base-Linear-AllHashes.aff4` records five digests on one stream. Reading it
//! five times would be five passes over gigabytes of evidence, so
//! [`MultiHasher`] feeds every enabled algorithm from a single pass — the same
//! idea as pyaff4's `StreamHasher`, without its coupling to a stream type.
//!
//! # Algorithms are part of the value
//!
//! A digest is never a bare string here. [`Digest`] carries its
//! [`HashAlgorithm`], and comparison checks both, so a hex string that happens
//! to match under a different algorithm cannot pass. pyaff4 does the same in
//! `BlockHashesHash.__eq__`; getting it wrong would let an MD5 satisfy a SHA-1
//! claim.
//!
//! # Weak algorithms are computed anyway
//!
//! MD5 and SHA-1 are cryptographically broken. They are also what acquisition
//! tools recorded, often years ago, and verification must recompute *the
//! algorithm the container names* rather than a better one. A stronger digest
//! computed here would answer a question nobody asked.
//!
//! # What this module does not do
//!
//! It computes digests; it does not decide what they mean. Comparison against
//! recorded values, and the reporting of matches and mismatches, belong to the
//! verification layer.

use blake2::Blake2b512;
use md5::Md5;
use sha1::Sha1;
// The `Digest` trait is re-exported identically by every RustCrypto hash
// crate; taking it from one keeps `digest` out of the direct dependencies.
use sha2::{Digest as _, Sha256, Sha512};

use crate::model::{HashAlgorithm, StoredHash};

/// A computed digest, carrying the algorithm that produced it.
///
/// Distinct from [`StoredHash`], which is a digest *read from a container*.
/// Keeping the two types apart is deliberate: a summary must never present a
/// computed value as an acquisition hash, or the reverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    algorithm: HashAlgorithm,
    hex: String,
}

impl Digest {
    /// The algorithm that produced this digest.
    #[must_use]
    pub fn algorithm(&self) -> &HashAlgorithm {
        &self.algorithm
    }

    /// The digest in lowercase hex, at full length. Never truncated.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Whether this digest matches one recorded in a container.
    ///
    /// Both the algorithm and the value must agree. Comparison of the hex is
    /// ASCII-case-insensitive, since the case a container used is a writer's
    /// choice and not a property of the digest — but the stored form is never
    /// rewritten, only compared.
    #[must_use]
    pub fn matches(&self, stored: &StoredHash) -> bool {
        self.algorithm == stored.algorithm && self.hex.eq_ignore_ascii_case(&stored.hex)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex)
    }
}

/// Whether this build can compute a given algorithm.
///
/// The block-map variants (v1.0a §6.2) are composite constructions over block
/// hashes, not digests over a byte stream, so they are **not** computable here
/// — see [`HashAlgorithm::BlockMapSha512`]. `Other` names a datatype this
/// build does not recognise.
#[must_use]
pub fn is_computable(algorithm: &HashAlgorithm) -> bool {
    matches!(
        algorithm,
        HashAlgorithm::Md5
            | HashAlgorithm::Sha1
            | HashAlgorithm::Sha256
            | HashAlgorithm::Sha512
            | HashAlgorithm::Blake2b
    )
}

/// One algorithm's running state.
enum Running {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
    Blake2b(Box<Blake2b512>),
}

impl Running {
    fn start(algorithm: &HashAlgorithm) -> Option<Self> {
        match algorithm {
            HashAlgorithm::Md5 => Some(Self::Md5(Md5::new())),
            HashAlgorithm::Sha1 => Some(Self::Sha1(Sha1::new())),
            HashAlgorithm::Sha256 => Some(Self::Sha256(Sha256::new())),
            HashAlgorithm::Sha512 => Some(Self::Sha512(Sha512::new())),
            HashAlgorithm::Blake2b => Some(Self::Blake2b(Box::new(Blake2b512::new()))),
            _ => None,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Md5(h) => h.update(bytes),
            Self::Sha1(h) => h.update(bytes),
            Self::Sha256(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
            Self::Blake2b(h) => h.update(bytes),
        }
    }

    fn finish(self) -> Digest {
        let (algorithm, bytes) = match self {
            Self::Md5(h) => (HashAlgorithm::Md5, h.finalize().to_vec()),
            Self::Sha1(h) => (HashAlgorithm::Sha1, h.finalize().to_vec()),
            Self::Sha256(h) => (HashAlgorithm::Sha256, h.finalize().to_vec()),
            Self::Sha512(h) => (HashAlgorithm::Sha512, h.finalize().to_vec()),
            Self::Blake2b(h) => (HashAlgorithm::Blake2b, h.finalize().to_vec()),
        };

        Digest {
            algorithm,
            hex: to_hex(&bytes),
        }
    }

    fn algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Md5(_) => HashAlgorithm::Md5,
            Self::Sha1(_) => HashAlgorithm::Sha1,
            Self::Sha256(_) => HashAlgorithm::Sha256,
            Self::Sha512(_) => HashAlgorithm::Sha512,
            Self::Blake2b(_) => HashAlgorithm::Blake2b,
        }
    }
}

/// Computes several digests over one pass of the data.
///
/// # Why the algorithms run concurrently
///
/// Two digests over the same bytes cost the *sum* of their rates when run in
/// lockstep, not the slower of the two. Measured on Apple silicon: SHA-256
/// reaches 1485 MiB/s using the hardware digest instructions, MD5 only
/// 436 MiB/s — it has no SIMD form, because each round depends on the one
/// before — and the pair together manage 339 MiB/s, which is `1/(1/1485 +
/// 1/436)`. Giving each algorithm its own thread makes the pair cost what the
/// slowest one costs, about 436 MiB/s.
///
/// **Only the algorithms are parallel; the byte stream never is.** Each
/// algorithm still sees every byte in stream order. Splitting the stream
/// itself would require a tree hash, which computes a different digest and
/// would not be the value the container recorded.
///
/// A single algorithm stays on the calling thread, where the handoff would
/// cost more than it saves.
pub struct MultiHasher {
    /// Algorithms running here, on the caller's thread.
    running: Vec<Running>,
    /// Algorithms running on their own threads, when there are several.
    workers: Vec<HashWorker>,
    declined: Vec<HashAlgorithm>,
    bytes_hashed: u64,
}

/// One algorithm on its own thread, fed slices in order.
struct HashWorker {
    /// Slices to absorb. Bounded so a slow algorithm applies backpressure
    /// rather than letting the queue grow without limit.
    tx: Option<std::sync::mpsc::SyncSender<std::sync::Arc<[u8]>>>,
    handle: Option<std::thread::JoinHandle<Digest>>,
}

impl HashWorker {
    /// How many slices may be queued for one algorithm.
    ///
    /// Deep enough to absorb the jitter between a fast algorithm and a slow
    /// one, shallow enough that the queue cannot become a second buffer of the
    /// stream: at 32 KiB a chunk this is a couple of megabytes.
    const DEPTH: usize = 64;

    fn start(mut state: Running) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<std::sync::Arc<[u8]>>(Self::DEPTH);
        let handle = std::thread::spawn(move || {
            while let Ok(slice) = rx.recv() {
                state.update(&slice);
            }
            state.finish()
        });
        Self {
            tx: Some(tx),
            handle: Some(handle),
        }
    }

    fn update(&mut self, slice: &std::sync::Arc<[u8]>) {
        if let Some(tx) = self.tx.as_ref() {
            // A send only fails if the thread died, which it cannot do before
            // its channel closes. Nothing to recover, and the digest it would
            // have produced is never read.
            let _ = tx.send(std::sync::Arc::clone(slice));
        }
    }

    /// Close the channel and collect the digest.
    fn finish(mut self) -> Option<Digest> {
        drop(self.tx.take());
        self.handle.take().and_then(|h| h.join().ok())
    }
}

impl MultiHasher {
    /// Start hashing for each algorithm, skipping duplicates.
    ///
    /// Algorithms this build cannot compute are recorded rather than dropped;
    /// [`MultiHasher::declined`] reports them so a caller can say what was not
    /// checked instead of silently omitting it.
    #[must_use]
    pub fn for_algorithms(algorithms: &[HashAlgorithm]) -> Self {
        Self::with_thread_cap(algorithms, usize::MAX)
    }

    /// Start hashing, spawning at most `max_threads` helper threads.
    ///
    /// Every algorithm is still computed. The cap bounds only how many get a
    /// thread of their own; the remainder are hashed on the caller's thread
    /// alongside it. Staying within a thread budget must never cost a
    /// comparison — a digest recorded in a container is always recomputed.
    ///
    /// This is what keeps the figure reported to the examiner true. The 90% cap
    /// is a promise about the whole run, and these threads were once outside it
    /// entirely: a container recording five digests started five threads that
    /// `ThreadPlan` never counted. See [`ThreadPlan::with_digest_threads`].
    ///
    /// [`ThreadPlan::with_digest_threads`]: crate::parallel::ThreadPlan::with_digest_threads
    #[must_use]
    pub fn with_thread_cap(algorithms: &[HashAlgorithm], max_threads: usize) -> Self {
        let mut running: Vec<Running> = Vec::new();
        let mut declined = Vec::new();

        for algorithm in algorithms {
            if running.iter().any(|r| &r.algorithm() == algorithm) || declined.contains(algorithm) {
                continue;
            }
            match Running::start(algorithm) {
                Some(state) => running.push(state),
                None => declined.push(algorithm.clone()),
            }
        }

        // One algorithm stays here: a thread handoff would cost more than the
        // overlap saves, and the common single-digest case should not pay for
        // machinery it cannot use.
        // At least one algorithm stays here whatever the cap: a lone algorithm
        // would pay for a handoff it cannot overlap, and keeping one inline
        // means a cap of zero still hashes everything.
        let spawnable = running.len().saturating_sub(1).min(max_threads);
        let workers = if spawnable > 0 {
            running.drain(..spawnable).map(HashWorker::start).collect()
        } else {
            Vec::new()
        };

        Self {
            running,
            workers,
            declined,
            bytes_hashed: 0,
        }
    }

    /// Feed the next slice of data to every enabled algorithm.
    pub fn update(&mut self, bytes: &[u8]) {
        for state in &mut self.running {
            state.update(bytes);
        }

        if !self.workers.is_empty() {
            // One allocation per slice, shared by every algorithm rather than
            // copied per thread.
            let shared: std::sync::Arc<[u8]> = std::sync::Arc::from(bytes);
            for worker in &mut self.workers {
                worker.update(&shared);
            }
        }

        self.bytes_hashed += bytes.len() as u64;
    }

    /// How many bytes have been hashed.
    ///
    /// Worth asserting against a stream's declared size: digests over a short
    /// read are wrong in a way that looks authoritative.
    #[must_use]
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes_hashed
    }

    /// Whether any algorithm is being computed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.running.is_empty() && self.workers.is_empty()
    }

    /// Algorithms this build could not compute.
    #[must_use]
    pub fn declined(&self) -> &[HashAlgorithm] {
        &self.declined
    }

    /// Finish, returning one digest per enabled algorithm.
    ///
    /// Order matches the algorithms given to [`MultiHasher::for_algorithms`],
    /// whether they ran here or on their own threads.
    #[must_use]
    pub fn finish(self) -> Vec<Digest> {
        let mut digests: Vec<Digest> = self.running.into_iter().map(Running::finish).collect();
        digests.extend(self.workers.into_iter().filter_map(HashWorker::finish));
        digests
    }
}

/// Compute a single digest over a slice, for tests and small segments.
///
/// Returns `None` for an algorithm this build cannot compute.
#[must_use]
pub fn digest_of(algorithm: &HashAlgorithm, bytes: &[u8]) -> Option<Digest> {
    let mut hasher = MultiHasher::for_algorithms(std::slice::from_ref(algorithm));
    hasher.update(bytes);
    hasher.finish().into_iter().next()
}

/// Render bytes as lowercase hex.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    // Writing into a String is infallible; nothing is being swallowed.
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

    /// Known answers for the empty input, from each algorithm's specification.
    /// If a dependency is ever swapped, these catch a changed implementation.
    #[test]
    fn known_answers_for_the_empty_input() {
        let cases = [
            (HashAlgorithm::Md5, "d41d8cd98f00b204e9800998ecf8427e"),
            (
                HashAlgorithm::Sha1,
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ),
            (
                HashAlgorithm::Sha256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                HashAlgorithm::Sha512,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
        ];

        for (algorithm, expected) in cases {
            let digest = digest_of(&algorithm, b"").unwrap();
            assert_eq!(digest.hex(), expected, "{algorithm:?}");
            assert_eq!(digest.algorithm(), &algorithm);
        }
    }

    /// The classic `abc` vectors.
    #[test]
    fn known_answers_for_abc() {
        assert_eq!(
            digest_of(&HashAlgorithm::Md5, b"abc").unwrap().hex(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            digest_of(&HashAlgorithm::Sha1, b"abc").unwrap().hex(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            digest_of(&HashAlgorithm::Sha256, b"abc").unwrap().hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Blake2b512 must be the 512-bit variant: a 128-character digest.
    #[test]
    fn blake2b_is_the_512_bit_variant() {
        let digest = digest_of(&HashAlgorithm::Blake2b, b"abc").unwrap();
        assert_eq!(digest.hex().len(), 128, "{}", digest.hex());
        assert!(digest.hex().starts_with("ba80a53f981c4d0d6a2797b69f12f6e9"));
    }

    /// Digest lengths must match what the model declares, or a container's
    /// consistency check would compare against the wrong expectation.
    #[test]
    fn digest_lengths_match_the_declared_algorithm() {
        for algorithm in [
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Blake2b,
        ] {
            let digest = digest_of(&algorithm, b"some evidence").unwrap();
            if let Some(expected) = algorithm.hex_length() {
                assert_eq!(
                    digest.hex().len(),
                    expected,
                    "{algorithm:?} produced {} characters",
                    digest.hex().len()
                );
            }
        }
    }

    /// Feeding data in pieces must equal feeding it whole — the property the
    /// whole streaming design depends on.
    #[test]
    fn chunked_input_equals_whole_input() {
        let data: Vec<u8> = (0..10_000u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();

        let whole = digest_of(&HashAlgorithm::Sha256, &data).unwrap();

        let mut hasher = MultiHasher::for_algorithms(&[HashAlgorithm::Sha256]);
        for piece in data.chunks(37) {
            hasher.update(piece);
        }
        let chunked = hasher.finish().into_iter().next().unwrap();

        assert_eq!(whole, chunked);
    }

    /// One pass must produce the same values as separate passes.
    #[test]
    fn one_pass_equals_separate_passes() {
        let data = b"AFF4 evidence chunk. ".repeat(500);
        let algorithms = [
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Blake2b,
        ];

        let mut multi = MultiHasher::for_algorithms(&algorithms);
        multi.update(&data);
        let together = multi.finish();

        assert_eq!(together.len(), 5);
        for digest in &together {
            let alone = digest_of(digest.algorithm(), &data).unwrap();
            assert_eq!(
                *digest,
                alone,
                "{:?} differs between passes",
                digest.algorithm()
            );
        }
    }

    #[test]
    fn bytes_hashed_counts_every_update() {
        let mut hasher = MultiHasher::for_algorithms(&[HashAlgorithm::Md5]);
        assert_eq!(hasher.bytes_hashed(), 0);
        hasher.update(&[0u8; 100]);
        hasher.update(&[0u8; 55]);
        assert_eq!(hasher.bytes_hashed(), 155);
    }

    /// Repeated algorithms must not be computed twice.
    #[test]
    fn duplicate_algorithms_are_collapsed() {
        let hasher = MultiHasher::for_algorithms(&[
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha1,
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
        ]);
        assert_eq!(hasher.finish().len(), 2);
    }

    /// Block-map hashes are composite constructions, not stream digests. They
    /// must be declined by name rather than computed wrongly.
    #[test]
    fn block_map_hashes_are_declined_not_computed() {
        for algorithm in [
            HashAlgorithm::BlockMapSha512,
            HashAlgorithm::BlockMapSha256,
            HashAlgorithm::Other("aff4:Whirlpool".to_owned()),
        ] {
            assert!(!is_computable(&algorithm), "{algorithm:?}");
            assert!(digest_of(&algorithm, b"data").is_none(), "{algorithm:?}");

            let hasher = MultiHasher::for_algorithms(std::slice::from_ref(&algorithm));
            assert!(hasher.is_empty());
            assert_eq!(hasher.declined(), &[algorithm]);
        }
    }

    /// A declined algorithm alongside a computable one must not suppress the
    /// one that works, nor be silently forgotten.
    #[test]
    fn declining_one_algorithm_does_not_suppress_the_others() {
        let mut hasher = MultiHasher::for_algorithms(&[
            HashAlgorithm::Sha1,
            HashAlgorithm::BlockMapSha512,
            HashAlgorithm::Md5,
        ]);
        hasher.update(b"abc");

        assert_eq!(hasher.declined(), &[HashAlgorithm::BlockMapSha512]);
        let digests = hasher.finish();
        assert_eq!(digests.len(), 2);
    }

    /// The comparison that must not be loosened: a value matching under a
    /// different algorithm is not a match.
    #[test]
    fn matching_requires_the_algorithm_to_agree() {
        let digest = digest_of(&HashAlgorithm::Sha1, b"abc").unwrap();

        let right = StoredHash {
            algorithm: HashAlgorithm::Sha1,
            hex: "a9993e364706816aba3e25717850c26c9cd0d89d".to_owned(),
            predicate: "hash".to_owned(),
        };
        assert!(digest.matches(&right));

        // Same digest string, wrong algorithm.
        let wrong_algorithm = StoredHash {
            algorithm: HashAlgorithm::Md5,
            ..right.clone()
        };
        assert!(!digest.matches(&wrong_algorithm));

        // Right algorithm, one character different.
        let wrong_value = StoredHash {
            hex: "a9993e364706816aba3e25717850c26c9cd0d89e".to_owned(),
            ..right.clone()
        };
        assert!(!digest.matches(&wrong_value));
    }

    /// Containers differ in digest case; that is a writer's choice, not a
    /// property of the digest.
    #[test]
    fn comparison_ignores_case_but_never_rewrites_the_stored_value() {
        let digest = digest_of(&HashAlgorithm::Sha1, b"abc").unwrap();
        let upper = StoredHash {
            algorithm: HashAlgorithm::Sha1,
            hex: "A9993E364706816ABA3E25717850C26C9CD0D89D".to_owned(),
            predicate: "hash".to_owned(),
        };

        assert!(digest.matches(&upper));
        // The stored form is untouched, and ours stays lowercase.
        assert_eq!(upper.hex, "A9993E364706816ABA3E25717850C26C9CD0D89D");
        assert_eq!(digest.hex(), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    /// Digests are rendered at full length. Truncation is what a summary must
    /// never do, and it starts here.
    #[test]
    fn digests_render_in_full() {
        let digest = digest_of(&HashAlgorithm::Sha512, b"evidence").unwrap();
        assert_eq!(digest.to_string().len(), 128);
        assert_eq!(digest.to_string(), digest.hex());
        assert!(!digest.to_string().contains('…'));
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(to_hex(&[]), "");
    }

    /// An empty request hashes nothing and yields nothing — no accidental
    /// "verified" from a container that recorded no digests.
    #[test]
    fn no_algorithms_yields_no_digests() {
        let mut hasher = MultiHasher::for_algorithms(&[]);
        hasher.update(b"data");
        assert!(hasher.is_empty());
        assert!(hasher.declined().is_empty());
        assert!(hasher.finish().is_empty());
    }

    /// Threaded hashing must produce exactly the digests single-threaded
    /// hashing produces.
    ///
    /// The parallelism is per *algorithm*: each still sees every byte in
    /// stream order. If that ever stopped being true the digests would differ
    /// here, which is the whole point of comparing against `digest_of` — an
    /// independent one-shot over the same bytes.
    #[test]
    fn threaded_algorithms_match_single_threaded_digests() {
        let algorithms = [
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Blake2b,
        ];

        // Awkward, uneven slice boundaries: a threaded hasher that reordered
        // or dropped a slice would survive uniform ones.
        let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        for cut in [1usize, 7, 64, 1000, 4096, 39_999] {
            let mut multi = MultiHasher::for_algorithms(&algorithms);
            for slice in data.chunks(cut) {
                multi.update(slice);
            }
            let digests = multi.finish();
            assert_eq!(digests.len(), algorithms.len(), "cut {cut}");
            assert_eq!(multi_bytes(&data, cut), data.len() as u64);

            for algorithm in &algorithms {
                let expected = digest_of(algorithm, &data).unwrap();
                let actual = digests
                    .iter()
                    .find(|d| d.algorithm() == algorithm)
                    .unwrap_or_else(|| panic!("{algorithm} missing at cut {cut}"));
                assert_eq!(
                    actual.hex(),
                    expected.hex(),
                    "{algorithm} differs from the single-threaded digest at cut {cut}"
                );
            }
        }
    }

    /// Bytes hashed must be counted once, not once per algorithm.
    fn multi_bytes(data: &[u8], cut: usize) -> u64 {
        let mut multi = MultiHasher::for_algorithms(&[HashAlgorithm::Md5, HashAlgorithm::Sha256]);
        for slice in data.chunks(cut) {
            multi.update(slice);
        }
        multi.bytes_hashed()
    }

    /// A single algorithm must still work, and stays off the thread path.
    #[test]
    fn one_algorithm_needs_no_threads() {
        let data = b"the quick brown fox";
        let mut multi = MultiHasher::for_algorithms(&[HashAlgorithm::Sha256]);
        multi.update(data);
        let digests = multi.finish();
        assert_eq!(digests.len(), 1);
        assert_eq!(
            digests[0].hex(),
            digest_of(&HashAlgorithm::Sha256, data).unwrap().hex()
        );
    }
}
