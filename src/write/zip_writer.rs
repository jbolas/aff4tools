//! A streaming ZIP writer for AFF4 volumes.
//!
//! # Why not the `zip` crate's writer
//!
//! Three AFF4 requirements a general-purpose library fights:
//!
//! 1. **§5.4 member ordering.** `container.description` MUST be the first file
//!    *stored* in the volume — a physical-layout constraint. Three of the four
//!    corpus writers violate it, pyaff4 because it flushes segments from an
//!    object cache in eviction order rather than creation order.
//! 2. **§5.4 requires ZIP64 unconditionally**, regardless of size. Libraries
//!    emit it only when a field overflows.
//! 3. **No member may be buffered whole in memory.** Evidence reaches
//!    terabytes.
//!
//! Every structure written here is parsed by `crate::zip`, so the formats are
//! known-good from the reading side.

use std::io::Write as _;

use crate::error::{Error, Locus, Result};
use crate::write::sink::WriteSink;

/// ZIP's stored (uncompressed) method.
pub const METHOD_STORED: u16 = 0;

/// ZIP's deflate method.
pub const METHOD_DEFLATE: u16 = 8;

/// Local file header signature, `PK\x03\x04`.
const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;

/// Central directory file header signature, `PK\x01\x02`.
const CD_HEADER_SIGNATURE: u32 = 0x0201_4b50;

/// ZIP64 end of central directory signature, `PK\x06\x06`.
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;

/// ZIP64 end of central directory locator signature, `PK\x06\x07`.
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;

/// End of central directory signature, `PK\x05\x06`.
const EOCD_SIGNATURE: u32 = 0x0605_4b50;

/// Version needed to extract, 4.5 — the ZIP64 minimum.
const VERSION_ZIP64: u16 = 45;

/// Version made by: 4.5 (`0x2d`) in the low byte, UNIX (3) in the high byte.
const VERSION_MADE_BY: u16 = 0x032d;

/// UTF-8 filename flag (EFS, bit 11).
///
/// AFF4-L §3.4 keeps Unicode filenames readable in ordinary ZIP browsers, which
/// requires declaring the encoding rather than leaving it to be guessed.
const FLAG_UTF8: u16 = 1 << 11;

/// What the central directory needs to record about one written member.
#[derive(Debug, Clone)]
pub struct MemberRecord {
    /// The member's name, as stored.
    pub name: String,
    /// Byte offset of its local file header.
    pub local_header_offset: u64,
    /// Uncompressed size.
    pub uncompressed_size: u64,
    /// Compressed size; equal to `uncompressed_size` for a stored member.
    pub compressed_size: u64,
    /// CRC-32 of the uncompressed bytes.
    pub crc32: u32,
    /// The compression method used.
    pub method: u16,
}

/// Writes ZIP members to a [`WriteSink`] in the order they are added.
///
/// Physical order is exactly call order, which is what lets the caller satisfy
/// §5.4 by adding `container.description` first.
#[derive(Debug)]
pub struct ZipWriter {
    members: Vec<MemberRecord>,
}

impl Default for ZipWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ZipWriter {
    /// Start a new archive.
    ///
    /// The sink is passed to each call rather than borrowed for the writer's
    /// lifetime, so a caller can hold both without fighting the borrow checker
    /// — which is what lets `ContainerWriter` stream members as they arrive
    /// instead of buffering them all to the end.
    #[must_use]
    pub fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// Every member written so far, in physical order.
    #[must_use]
    pub fn members(&self) -> &[MemberRecord] {
        &self.members
    }

    /// Append a stored (uncompressed) member.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a write fails.
    pub fn add_stored_member(
        &mut self,
        sink: &mut WriteSink,
        name: &str,
        data: &[u8],
    ) -> Result<()> {
        let crc = crc32fast::hash(data);
        self.add_member(sink, name, data, data, METHOD_STORED, crc)
    }

    /// Append a deflate-compressed member.
    ///
    /// Used for `information.turtle`, which is highly repetitive RDF and
    /// compresses well — and which pyaff4 also stores deflated.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a write fails, [`Error::Malformed`] if compression
    /// fails (which would mean a bug here, not bad input).
    pub fn add_deflated_member(
        &mut self,
        sink: &mut WriteSink,
        name: &str,
        data: &[u8],
    ) -> Result<()> {
        let crc = crc32fast::hash(data);
        // Raw deflate (-15 window), which is what ZIP method 8 carries — not
        // zlib-wrapped. Getting this wrong produces an archive that every
        // reader rejects.
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(data)
            .map_err(|source| Error::io(sink.path().to_path_buf(), source))?;
        let compressed = encoder
            .finish()
            .map_err(|source| Error::io(sink.path().to_path_buf(), source))?;

        self.add_member(sink, name, data, &compressed, METHOD_DEFLATE, crc)
    }

    /// Write one member's local header and body.
    fn add_member(
        &mut self,
        sink: &mut WriteSink,
        name: &str,
        uncompressed: &[u8],
        stored: &[u8],
        method: u16,
        crc: u32,
    ) -> Result<()> {
        let offset = sink.position();
        let name_bytes = name.as_bytes();

        if name_bytes.len() > u16::MAX as usize {
            return Err(Error::malformed(
                Locus::new(sink.path()),
                format!(
                    "member name is {} bytes, too long for ZIP",
                    name_bytes.len()
                ),
            ));
        }

        let uncompressed_size = uncompressed.len() as u64;
        let compressed_size = stored.len() as u64;

        let mut header = Vec::with_capacity(30 + name_bytes.len() + 20);
        header.extend_from_slice(&LOCAL_HEADER_SIGNATURE.to_le_bytes());
        header.extend_from_slice(&VERSION_ZIP64.to_le_bytes());
        header.extend_from_slice(&FLAG_UTF8.to_le_bytes());
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes()); // mod time
        header.extend_from_slice(&0u16.to_le_bytes()); // mod date
        header.extend_from_slice(&crc.to_le_bytes());
        // 32-bit size fields carry the ZIP64 sentinel; the extra field holds
        // the real values. §5.4 requires zip64 headers unconditionally.
        header.extend_from_slice(&u32::MAX.to_le_bytes());
        header.extend_from_slice(&u32::MAX.to_le_bytes());
        // Bounds-checked above, so this cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        let name_len = name_bytes.len() as u16;
        header.extend_from_slice(&name_len.to_le_bytes());
        header.extend_from_slice(&20u16.to_le_bytes()); // extra field length
        header.extend_from_slice(name_bytes);

        // ZIP64 extended information: tag 0x0001, 16 bytes of payload.
        header.extend_from_slice(&0x0001u16.to_le_bytes());
        header.extend_from_slice(&16u16.to_le_bytes());
        header.extend_from_slice(&uncompressed_size.to_le_bytes());
        header.extend_from_slice(&compressed_size.to_le_bytes());

        sink.write_all(&header)?;
        sink.write_all(stored)?;

        self.members.push(MemberRecord {
            name: name.to_owned(),
            local_header_offset: offset,
            uncompressed_size,
            compressed_size,
            crc32: crc,
            method,
        });

        Ok(())
    }

    /// Write the central directory and close the archive.
    ///
    /// `comment` becomes the ZIP comment, which AFF4 §5.4 uses to carry the
    /// volume ARN. It is written with **no NUL padding** — one corpus writer
    /// pads it, which this crate records as a deviation on read and must never
    /// reproduce on write.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if a write fails.
    pub fn finish(self, sink: &mut WriteSink, comment: &str) -> Result<()> {
        let cd_offset = sink.position();

        for member in &self.members {
            let name = member.name.as_bytes();
            let mut entry = Vec::with_capacity(46 + name.len() + 28);
            entry.extend_from_slice(&CD_HEADER_SIGNATURE.to_le_bytes());
            entry.extend_from_slice(&VERSION_MADE_BY.to_le_bytes());
            entry.extend_from_slice(&VERSION_ZIP64.to_le_bytes());
            entry.extend_from_slice(&FLAG_UTF8.to_le_bytes());
            entry.extend_from_slice(&member.method.to_le_bytes());
            entry.extend_from_slice(&0u16.to_le_bytes()); // mod time
            entry.extend_from_slice(&0u16.to_le_bytes()); // mod date
            entry.extend_from_slice(&member.crc32.to_le_bytes());
            entry.extend_from_slice(&u32::MAX.to_le_bytes()); // compressed
            entry.extend_from_slice(&u32::MAX.to_le_bytes()); // uncompressed
            // Bounds-checked in `add_member`, so this cannot truncate.
            #[allow(clippy::cast_possible_truncation)]
            let name_len = name.len() as u16;
            entry.extend_from_slice(&name_len.to_le_bytes());
            entry.extend_from_slice(&28u16.to_le_bytes()); // extra length
            entry.extend_from_slice(&0u16.to_le_bytes()); // comment length
            entry.extend_from_slice(&0u16.to_le_bytes()); // disk number
            entry.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            entry.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            entry.extend_from_slice(&u32::MAX.to_le_bytes()); // local offset
            entry.extend_from_slice(name);

            // ZIP64 extra: uncompressed, compressed, local header offset.
            entry.extend_from_slice(&0x0001u16.to_le_bytes());
            entry.extend_from_slice(&24u16.to_le_bytes());
            entry.extend_from_slice(&member.uncompressed_size.to_le_bytes());
            entry.extend_from_slice(&member.compressed_size.to_le_bytes());
            entry.extend_from_slice(&member.local_header_offset.to_le_bytes());

            sink.write_all(&entry)?;
        }

        let cd_size = sink.position() - cd_offset;
        let eocd64_offset = sink.position();
        let count = self.members.len() as u64;

        // ZIP64 end of central directory record.
        let mut eocd64 = Vec::with_capacity(56);
        eocd64.extend_from_slice(&ZIP64_EOCD_SIGNATURE.to_le_bytes());
        eocd64.extend_from_slice(&44u64.to_le_bytes()); // size of remainder
        eocd64.extend_from_slice(&VERSION_MADE_BY.to_le_bytes());
        eocd64.extend_from_slice(&VERSION_ZIP64.to_le_bytes());
        eocd64.extend_from_slice(&0u32.to_le_bytes()); // this disk
        eocd64.extend_from_slice(&0u32.to_le_bytes()); // disk with CD start
        eocd64.extend_from_slice(&count.to_le_bytes());
        eocd64.extend_from_slice(&count.to_le_bytes());
        eocd64.extend_from_slice(&cd_size.to_le_bytes());
        eocd64.extend_from_slice(&cd_offset.to_le_bytes());
        sink.write_all(&eocd64)?;

        // ZIP64 locator.
        let mut locator = Vec::with_capacity(20);
        locator.extend_from_slice(&ZIP64_LOCATOR_SIGNATURE.to_le_bytes());
        locator.extend_from_slice(&0u32.to_le_bytes());
        locator.extend_from_slice(&eocd64_offset.to_le_bytes());
        locator.extend_from_slice(&1u32.to_le_bytes()); // total disks
        sink.write_all(&locator)?;

        // Classic EOCD, with ZIP64 sentinels.
        let comment_bytes = comment.as_bytes();
        if comment_bytes.len() > u16::MAX as usize {
            return Err(Error::malformed(
                Locus::new(sink.path()),
                format!(
                    "ZIP comment is {} bytes, too long to record the volume ARN",
                    comment_bytes.len()
                ),
            ));
        }
        let mut eocd = Vec::with_capacity(22 + comment_bytes.len());
        eocd.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // this disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk with CD start
        eocd.extend_from_slice(&u16::MAX.to_le_bytes());
        eocd.extend_from_slice(&u16::MAX.to_le_bytes());
        eocd.extend_from_slice(&u32::MAX.to_le_bytes());
        eocd.extend_from_slice(&u32::MAX.to_le_bytes());
        // Bounds-checked immediately above.
        #[allow(clippy::cast_possible_truncation)]
        let comment_len = comment_bytes.len() as u16;
        eocd.extend_from_slice(&comment_len.to_le_bytes());
        eocd.extend_from_slice(comment_bytes);
        sink.write_all(&eocd)?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::write::guard::SourceRegistry;

    /// The `zip` crate — an independent implementation — must open what we
    /// wrote and read every member back byte-for-byte. Our own reader sharing a
    /// bug with our writer would pass a self-consistency check; this cannot.
    #[test]
    fn an_archive_opens_in_an_independent_reader() {
        use std::io::Read as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.zip");
        let registry = SourceRegistry::new();

        let big = vec![b'x'; 100_000];
        let mut sink = WriteSink::create(&path, &registry).unwrap();
        {
            let mut zip = ZipWriter::new();
            zip.add_stored_member(&mut sink, "container.description", b"aff4://vol")
                .unwrap();
            zip.add_stored_member(&mut sink, "version.txt", b"major=1\nminor=1\n")
                .unwrap();
            zip.add_deflated_member(&mut sink, "information.turtle", &big)
                .unwrap();
            assert_eq!(zip.members().len(), 3);
            assert_eq!(zip.members()[0].local_header_offset, 0);
            zip.finish(&mut sink, "aff4://vol").unwrap();
        }
        sink.finish().unwrap();

        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        assert_eq!(archive.len(), 3);

        // Physical order must match call order: container.description first.
        let names: Vec<String> = archive.file_names().map(str::to_owned).collect();
        assert_eq!(names[0], "container.description", "§5.4: must be first");

        let mut body = String::new();
        archive
            .by_name("version.txt")
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        assert_eq!(body, "major=1\nminor=1\n");

        // The deflated member must round-trip too.
        let mut back = Vec::new();
        archive
            .by_name("information.turtle")
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, big, "deflated member must round-trip");

        assert_eq!(archive.comment(), b"aff4://vol");
    }

    /// The comment carries the volume ARN with no NUL padding — the deviation
    /// this crate records on read and must never write.
    #[test]
    fn the_comment_is_not_nul_padded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.zip");
        let registry = SourceRegistry::new();

        let mut sink = WriteSink::create(&path, &registry).unwrap();
        {
            let mut zip = ZipWriter::new();
            zip.add_stored_member(&mut sink, "container.description", b"aff4://vol")
                .unwrap();
            zip.finish(&mut sink, "aff4://vol").unwrap();
        }
        sink.finish().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.ends_with(b"\0"), "comment must carry no NUL padding");
    }
}
