//! Reading a block device, and surviving the sectors that will not read.
//!
//! # Read errors are recorded, never fabricated
//!
//! Failing media is often exactly the evidence being acquired, so an
//! unrecoverable read cannot abort the acquisition — but it must not be
//! silently zero-filled either. A zero-filled region produces a clean-looking
//! image whose digest covers bytes the medium never returned.
//!
//! This module retries at finer granularity, then reports the failed extent so
//! the caller can map it to `aff4:UnreadableData` — the symbolic stream the
//! specification defines for exactly this, with fixed placeholder content so
//! the region hashes reproducibly while remaining attributable.
//!
//! **Neither reference implementation does this.** `UnreadableData` appears
//! nowhere in c-aff4, and pyaff4's own `Base-Linear-ReadError.aff4` declares
//! `mapGapDefaultStream aff4:Zero`. There is no corpus fixture to copy, which
//! is why [`FaultyReader`] exists: it injects failures so the path is exercised.
//!
//! # Testability without privilege
//!
//! Everything here works against any [`Read`] + [`Seek`] source, so a file
//! stands in for a device. Opening a real `/dev/rdiskN` needs privilege.

use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;

/// A region the medium refused to return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableRegion {
    /// Byte offset where the failure starts.
    pub start: u64,
    /// How many bytes could not be read.
    pub length: u64,
    /// What the OS said, for the report.
    pub reason: String,
}

impl UnreadableRegion {
    /// The half-open byte range this region covers.
    #[must_use]
    pub fn range(&self) -> Range<u64> {
        self.start..self.start + self.length
    }
}

/// How a device should be read.
#[derive(Debug, Clone, Copy)]
pub struct DeviceOptions {
    /// Bytes per read attempt when all is well.
    pub read_size: usize,
    /// The granularity a failed read retries at — normally the sector size.
    ///
    /// A single bad sector should cost one sector, not one whole read block,
    /// so the retry narrows to this before giving up on a range.
    pub sector_size: usize,
}

impl Default for DeviceOptions {
    fn default() -> Self {
        Self {
            read_size: 1 << 20,
            sector_size: 512,
        }
    }
}

/// Reads a device, substituting placeholder content for unreadable sectors and
/// recording where they were.
///
/// The placeholder is the specification's `UnreadableData` repeated string, so
/// the bytes fed to the digest are the ones the standard defines for a region
/// whose true content is unknown — reproducible by any other implementation,
/// and never mistaken for recovered data.
#[derive(Debug)]
pub struct DeviceReader<S> {
    source: S,
    options: DeviceOptions,
    position: u64,
    total: u64,
    unreadable: Vec<UnreadableRegion>,
    /// Bytes read from the device but not yet handed to the caller.
    ///
    /// **This is what keeps acquisition off the syscall floor.** The stream
    /// writer asks for one `chunk_size` at a time — 32 KiB by default — and a
    /// device answers a 32 KiB request no faster than a 1 MiB one, because the
    /// cost is per-request latency rather than bandwidth. Reading `read_size`
    /// at a time and serving chunks from here turns 488,000 requests into
    /// 15,000 for a 15 GiB device.
    ///
    /// Measured on a USB flash drive: 11.2 MiB/s before, and the per-read wall
    /// time of 2.79 ms showed the drive was idle between requests rather than
    /// saturated.
    buffer: Vec<u8>,
    /// How much of `buffer` has been handed out.
    buffer_used: usize,
    /// How much of `buffer` holds device bytes.
    buffer_filled: usize,
    /// Where the underlying descriptor is positioned.
    ///
    /// Lets a sequential read skip the seek: after a successful read the
    /// descriptor already sits at `position`, so re-seeking there is a syscall
    /// that buys nothing. Any retry or fill resets this.
    sought: u64,
}

/// The repeated string `aff4:UnreadableData` is defined to hold.
const UNREADABLE_PATTERN: &[u8] = b"UNREADABLEDATA";

impl<S: Read + Seek> DeviceReader<S> {
    /// Wrap `source`, which reports `total` bytes.
    pub fn new(source: S, total: u64, options: DeviceOptions) -> Self {
        Self {
            source,
            options,
            position: 0,
            total,
            unreadable: Vec::new(),
            buffer: vec![0u8; options.read_size.max(1)],
            buffer_used: 0,
            buffer_filled: 0,
            sought: 0,
        }
    }

    /// Every region that could not be read, in order.
    #[must_use]
    pub fn unreadable(&self) -> &[UnreadableRegion] {
        &self.unreadable
    }

    /// Total bytes that could not be read.
    #[must_use]
    pub fn unreadable_bytes(&self) -> u64 {
        self.unreadable.iter().map(|r| r.length).sum()
    }

    /// Fill `buf` from the device, tolerating unreadable sectors.
    ///
    /// Returns how many bytes were produced — placeholder bytes included, since
    /// the image must stay the size the medium claims. Where they came from is
    /// in [`DeviceReader::unreadable`].
    fn read_tolerantly(&mut self, buf: &mut [u8]) -> usize {
        if self.position >= self.total {
            return 0;
        }
        let want = buf
            .len()
            .min(usize::try_from(self.total - self.position).unwrap_or(usize::MAX));
        let buf = &mut buf[..want];

        // Sequential reads need no seek: the descriptor is already positioned
        // where the last read left it. Seeking anyway costs a syscall per block
        // and, on some drivers, discards readahead. The seek stays on the retry
        // path below, which is genuinely random access.
        let sequential = self.position == self.sought;
        let outcome = if sequential {
            read_exact_here(&mut self.source, buf)
        } else {
            read_at(&mut self.source, self.position, buf)
        };

        match outcome {
            Ok(n) if n == buf.len() => {
                self.position += n as u64;
                self.sought = self.position;
                return n;
            }
            Ok(n) => {
                // A short read that is not the end: treat the remainder as
                // suspect and narrow to sector granularity below.
                self.sought = self.position + n as u64;
                if self.position + n as u64 >= self.total {
                    self.position += n as u64;
                    return n;
                }
            }
            Err(_) => self.sought = u64::MAX, // position unknown; force a seek
        }

        // Something failed. Narrow to sector granularity so one bad sector
        // costs one sector, not the whole block.
        let sector = self.options.sector_size;
        let mut produced = 0;
        while produced < buf.len() {
            let end = (produced + sector).min(buf.len());
            let slice = &mut buf[produced..end];
            let offset = self.position + produced as u64;

            match read_at(&mut self.source, offset, slice) {
                Ok(n) if n == slice.len() => {}
                Ok(_) | Err(_) => {
                    let reason = match read_at(&mut self.source, offset, slice) {
                        Err(e) => e.to_string(),
                        Ok(_) => "short read".to_owned(),
                    };
                    fill_unreadable(slice, offset);
                    self.note_unreadable(offset, slice.len() as u64, reason);
                }
            }
            produced = end;
        }

        self.position += produced as u64;
        // The retry loop seeks per sector, so the descriptor is wherever the
        // last one left it.
        self.sought = self.position;
        produced
    }

    /// Record an unreadable extent, merging with the previous one when
    /// adjacent so a long bad run reports as one region rather than thousands.
    fn note_unreadable(&mut self, start: u64, length: u64, reason: String) {
        if let Some(last) = self.unreadable.last_mut()
            && last.start + last.length == start
        {
            last.length += length;
            return;
        }
        self.unreadable.push(UnreadableRegion {
            start,
            length,
            reason,
        });
    }
}

impl<S: Read + Seek> Read for DeviceReader<S> {
    /// Serve `buf` from the internal buffer, refilling from the device in
    /// `read_size` blocks.
    ///
    /// The caller's buffer size is an AFF4 concern (`chunk_size`); the device's
    /// is a hardware one. Reading at the caller's granularity conflated the two
    /// and left a USB drive idle between requests.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.buffer_used == self.buffer_filled {
            // Buffer exhausted: pull another block from the device. A caller
            // asking for more than `read_size` is served directly, so a large
            // request never costs an extra copy.
            if buf.len() >= self.buffer.len() {
                return Ok(self.read_tolerantly(buf));
            }
            let filled = {
                let mut block = std::mem::take(&mut self.buffer);
                let filled = self.read_tolerantly(&mut block);
                self.buffer = block;
                filled
            };
            self.buffer_used = 0;
            self.buffer_filled = filled;
            if filled == 0 {
                return Ok(0);
            }
        }

        let take = buf.len().min(self.buffer_filled - self.buffer_used);
        buf[..take].copy_from_slice(&self.buffer[self.buffer_used..self.buffer_used + take]);
        self.buffer_used += take;
        Ok(take)
    }
}

/// Fill `buf` from wherever the descriptor is, looping over short reads.
fn read_exact_here<S: Read>(source: &mut S, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Read `buf`-many bytes at `offset`, looping over short reads.
fn read_at<S: Read + Seek>(source: &mut S, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    source.seek(SeekFrom::Start(offset))?;
    let mut filled = 0;
    while filled < buf.len() {
        match source.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Fill `buf` with `aff4:UnreadableData`'s defined content.
///
/// The pattern repeats from the region's absolute offset so the same byte range
/// yields the same placeholder however it is read — a digest over an image with
/// unreadable regions must be reproducible.
fn fill_unreadable(buf: &mut [u8], offset: u64) {
    let phase = usize::try_from(offset % UNREADABLE_PATTERN.len() as u64).unwrap_or(0);
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = UNREADABLE_PATTERN[(phase + i) % UNREADABLE_PATTERN.len()];
    }
}

/// Determine a device's size in bytes.
///
/// Two sources, in order:
///
/// 1. **`lseek` to the end.** A regular file answers immediately, so a
///    file-backed source needs nothing further.
/// 2. **`DKIOCGETBLOCKCOUNT` × `DKIOCGETBLOCKSIZE`** (macOS). A block device
///    returns **zero** from `lseek`, so the seek alone cannot acquire one.
///
/// Verified against a real 16 GB volume: the ioctl answers 31,324,160 blocks
/// × 512 bytes, matching `diskutil` exactly, where `lseek` answers zero for
/// both `/dev/diskN` and `/dev/rdiskN`.
///
/// Deliberately **not** a read-until-EOF fallback: guessing a device's length
/// by reading it would silently truncate an acquisition whenever the guess ran
/// short, which is the failure this project treats as unacceptable. If neither
/// source answers, the caller is told rather than given a number.
///
/// # Errors
///
/// [`std::io::Error`] if the handle cannot be seeked, or `InvalidData` when no
/// source reports a usable length.
pub fn device_size(file: &mut std::fs::File) -> std::io::Result<u64> {
    let end = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;
    if end > 0 {
        return Ok(end);
    }

    // A block device seeks to zero; ask the driver for its geometry instead.
    if let Some(size) = block_device_size(file) {
        return Ok(size);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "the device reports a length of zero",
    ))
}

/// The device's size, asked of the driver, or `None`.
///
/// macOS and Linux; every other platform falls through to the seek result.
///
/// macOS has no single "size in bytes" request, so it multiplies the block
/// count by the block size. Linux's `BLKGETSIZE64` answers in bytes directly,
/// which is why the two arms differ in shape.
///
/// # The crate's only `unsafe`
///
/// Every ioctl reached from here is **read-only**: each reports the disk's
/// geometry and cannot modify the device, so this cannot violate the project's
/// write-blocking guarantee. Each writes exactly the width its header declares
/// into a local of that type, and a failure returns `None` rather than a guess.
/// `src/lib.rs` denies `unsafe_code` crate-wide; this is the single audited
/// exception. The per-target arms live inside one function so that stays
/// literally true — `tests/read_only_guard.rs` counts the `#[allow]`
/// annotations as text, not per target.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(unsafe_code)]
fn block_device_size(file: &std::fs::File) -> Option<u64> {
    use std::os::fd::AsRawFd as _;

    #[allow(non_camel_case_types)]
    type libc_ulong = std::ffi::c_ulong;

    // glibc, musl, and macOS all declare the request as `unsigned long`.
    unsafe extern "C" {
        fn ioctl(fd: std::ffi::c_int, request: libc_ulong, ...) -> std::ffi::c_int;
    }

    let fd = file.as_raw_fd();

    #[cfg(target_os = "macos")]
    {
        // <sys/disk.h>: _IOR('d', 25, uint64_t) and _IOR('d', 24, uint32_t).
        const DKIOCGETBLOCKCOUNT: libc_ulong = 0x4008_6419;
        const DKIOCGETBLOCKSIZE: libc_ulong = 0x4004_6418;

        let mut blocks: u64 = 0;
        let mut block_size: u32 = 0;

        // SAFETY: `fd` is a live descriptor owned by `file`, and each request
        // writes exactly the width its <sys/disk.h> definition declares.
        let ok = unsafe {
            ioctl(fd, DKIOCGETBLOCKCOUNT, &raw mut blocks) == 0
                && ioctl(fd, DKIOCGETBLOCKSIZE, &raw mut block_size) == 0
        };

        if !ok || blocks == 0 || block_size == 0 {
            return None;
        }
        blocks.checked_mul(u64::from(block_size))
    }

    #[cfg(target_os = "linux")]
    {
        // <linux/fs.h>: _IOR(0x12, 114, size_t). Linux encodes the argument's
        // width into the request, so the constant differs between 32- and
        // 64-bit targets; a 64-bit value sent from a 32-bit build is rejected
        // with EINVAL rather than answered wrongly, but it is still wrong.
        const BLKGETSIZE64: libc_ulong = if size_of::<usize>() == 8 {
            0x8008_1272
        } else {
            0x8004_1272
        };

        // The kernel writes a `size_t`, so receive one and widen afterwards.
        let mut bytes: usize = 0;

        // SAFETY: `fd` is a live descriptor owned by `file`. BLKGETSIZE64
        // writes exactly one `size_t`, the width <linux/fs.h> declares, into a
        // local of that type, and reports geometry without modifying it.
        let ok = unsafe { ioctl(fd, BLKGETSIZE64, &raw mut bytes) == 0 };

        if !ok || bytes == 0 {
            return None;
        }
        Some(bytes as u64)
    }
}

/// Platforms with no geometry request wired up yet.
///
/// FreeBSD's `DIOCGMEDIASIZE` is the counterpart and would slot in as another
/// arm above; until it is tested against a real device, reporting no answer is
/// better than reporting a wrong one.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn block_device_size(_file: &std::fs::File) -> Option<u64> {
    None
}

/// A source that fails on a chosen byte range, for exercising the error path.
///
/// No corpus container demonstrates `UnreadableData`, so the only way to test
/// this path is to inject the failure.
#[derive(Debug)]
pub struct FaultyReader {
    data: Vec<u8>,
    bad: Range<u64>,
    position: u64,
}

impl FaultyReader {
    /// Wrap `data`, failing every read that touches `bad`.
    #[must_use]
    pub fn new(data: Vec<u8>, bad: Range<u64>) -> Self {
        Self {
            data,
            bad,
            position: 0,
        }
    }
}

impl Read for FaultyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = self.position;
        let end = start + buf.len() as u64;
        if start < self.bad.end && end > self.bad.start {
            return Err(std::io::Error::other("simulated media read error"));
        }
        let available = self.data.len() as u64 - start.min(self.data.len() as u64);
        let n = buf.len().min(usize::try_from(available).unwrap_or(0));
        let from = usize::try_from(start).unwrap_or(0);
        buf[..n].copy_from_slice(&self.data[from..from + n]);
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for FaultyReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        // Saturating and sign-correct: a negative seek past the start clamps
        // to zero rather than wrapping to an enormous offset.
        self.position = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => offset_from(self.data.len() as u64, n),
            SeekFrom::Current(n) => offset_from(self.position, n),
        };
        Ok(self.position)
    }
}

/// Apply a signed delta to a base offset, clamping at zero.
fn offset_from(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta.unsigned_abs())
    } else {
        base.saturating_sub(delta.unsigned_abs())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn options() -> DeviceOptions {
        DeviceOptions {
            read_size: 4096,
            sector_size: 512,
        }
    }

    /// A healthy device reads through unchanged.
    #[test]
    fn a_clean_device_reads_identically() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut reader = DeviceReader::new(Cursor::new(data.clone()), 10_000, options());

        let mut back = Vec::new();
        reader.read_to_end(&mut back).unwrap();

        assert_eq!(back, data);
        assert!(
            reader.unreadable().is_empty(),
            "nothing should be unreadable"
        );
    }

    /// A bad sector is recorded, not zero-filled, and the image keeps its size.
    #[test]
    fn a_bad_sector_is_recorded_and_filled_with_placeholder() {
        let data = vec![0xAAu8; 8192];
        // One sector at 2048 fails.
        let faulty = FaultyReader::new(data, 2048..2560);
        let mut reader = DeviceReader::new(faulty, 8192, options());

        let mut back = Vec::new();
        reader.read_to_end(&mut back).unwrap();

        assert_eq!(back.len(), 8192, "the image must keep the medium's size");
        assert_eq!(reader.unreadable().len(), 1, "one region");
        let region = &reader.unreadable()[0];
        assert_eq!(region.start, 2048);
        assert_eq!(region.length, 512);
        assert_eq!(reader.unreadable_bytes(), 512);

        // Good data survives on both sides.
        assert!(back[..2048].iter().all(|&b| b == 0xAA));
        assert!(back[2560..].iter().all(|&b| b == 0xAA));

        // The gap is the specification's placeholder, NOT zeroes.
        let gap = &back[2048..2560];
        assert!(
            !gap.iter().all(|&b| b == 0),
            "unreadable regions must never be zero-filled: a zeroed gap is \
             indistinguishable from genuinely zeroed evidence"
        );
        assert!(
            gap.windows(UNREADABLE_PATTERN.len())
                .any(|w| w == UNREADABLE_PATTERN),
            "the gap must carry the UnreadableData pattern, got {:?}",
            &gap[..32]
        );
    }

    /// Adjacent bad sectors merge into one reported region.
    #[test]
    fn adjacent_bad_sectors_merge() {
        let data = vec![0x55u8; 8192];
        let faulty = FaultyReader::new(data, 1024..3072);
        let mut reader = DeviceReader::new(faulty, 8192, options());

        let mut back = Vec::new();
        reader.read_to_end(&mut back).unwrap();

        assert_eq!(back.len(), 8192);
        assert_eq!(
            reader.unreadable().len(),
            1,
            "a contiguous bad run must report as one region, not {} \
             sector-sized ones",
            reader.unreadable().len()
        );
        assert_eq!(reader.unreadable()[0].length, 2048);
    }

    /// A regular file's size is answered by the seek, so the device path works
    /// against file-backed sources without privilege.
    #[test]
    fn device_size_answers_for_a_regular_file() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img.dd");
        #[allow(clippy::disallowed_methods)]
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&vec![0u8; 4096]).unwrap();
        drop(f);

        let mut file = std::fs::File::open(&path).unwrap();
        assert_eq!(device_size(&mut file).unwrap(), 4096);
        // And the handle is rewound, so the caller reads from zero.
        assert_eq!(file.stream_position().unwrap(), 0);
    }

    /// **Performance regression.** Small caller reads must not become small
    /// device reads.
    ///
    /// The stream writer asks for one `chunk_size` at a time — 32 KiB. Turning
    /// each of those into its own seek-and-read against the device measured
    /// 11.2 MiB/s at 2.79 ms per read on a USB drive: idle between requests,
    /// not saturated. A 15 GiB acquisition would cost 488,000 request pairs
    /// instead of 15,000.
    ///
    /// Asserted by counting what reaches the device, which is deterministic —
    /// unlike a throughput threshold, which would be flaky on shared hardware.
    #[test]
    fn small_caller_reads_do_not_become_small_device_reads() {
        /// Counts reads and seeks reaching the "device".
        struct Counting {
            data: std::io::Cursor<Vec<u8>>,
            reads: usize,
            seeks: usize,
        }
        impl Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                self.data.read(buf)
            }
        }
        impl Seek for Counting {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.seeks += 1;
                self.data.seek(pos)
            }
        }

        let total = 4 * 1024 * 1024;
        let source = Counting {
            data: std::io::Cursor::new(vec![0x5Au8; total]),
            reads: 0,
            seeks: 0,
        };
        let mut reader = DeviceReader::new(
            source,
            total as u64,
            DeviceOptions {
                read_size: 1 << 20,
                sector_size: 512,
            },
        );

        // Read the whole device the way the stream writer does: 32 KiB at a
        // time. That is 128 caller reads.
        let mut chunk = vec![0u8; 32 * 1024];
        let mut got = 0usize;
        while got < total {
            let n = reader.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        assert_eq!(got, total, "the whole device must be delivered");

        let source = reader.source;
        // 4 MiB at 1 MiB per fill is 4 device reads (plus a trailing empty
        // one). Without buffering this was 128 — one per caller read.
        assert!(
            source.reads <= 8,
            "expected ~4 device reads for 4 MiB at 1 MiB blocks, got {} — the \
             caller's 32 KiB granularity is reaching the device",
            source.reads
        );
        // And a sequential read needs no seek at all.
        assert_eq!(
            source.seeks, 0,
            "sequential reading must not seek; {} seeks issued",
            source.seeks
        );
    }

    /// A zero-length source is refused rather than guessed at.
    ///
    /// An empty *regular file* seeks to zero and has no block geometry, so both
    /// sources decline and the caller is told — never handed a number read off
    /// the end of the data.
    #[test]
    fn a_zero_length_device_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.dd");
        #[allow(clippy::disallowed_methods)]
        std::fs::File::create(&path).unwrap();

        let mut file = std::fs::File::open(&path).unwrap();
        let err = device_size(&mut file).unwrap_err();
        assert!(
            err.to_string().contains("length of zero"),
            "the refusal must say the length was zero: {err}"
        );
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidData,
            "a zero length is a finding about the source, not an I/O failure"
        );
    }

    /// The placeholder is reproducible: the same range yields the same bytes.
    #[test]
    fn placeholder_content_is_reproducible() {
        let mut a = vec![0u8; 512];
        let mut b = vec![0u8; 512];
        fill_unreadable(&mut a, 4096);
        fill_unreadable(&mut b, 4096);
        assert_eq!(a, b, "a digest over an unreadable region must be stable");

        let mut c = vec![0u8; 512];
        fill_unreadable(&mut c, 4097);
        assert_ne!(a, c, "the pattern is offset-phased");
    }
}
