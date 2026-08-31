//! Reading an existing AFF4 container as an acquisition source.
//!
//! Converting a
//! container — single-file to split set, or one codec to another — needs no
//! mount, no block device, and no operating-system cooperation. It needs the
//! random-access seam and a `Read` adapter over it, which is what this is.
//!
//! # Why this is the strongest test of `read_at`
//!
//! The output container's whole-image digest must equal the source's. If
//! [`Image::read_at`] is wrong at any offset — an off-by-one at an entry
//! boundary, a stale bevy after a stream change, a described run served with
//! the wrong filler — the digests differ and the test fails. Nothing else
//! exercises the seam against so precise an expectation.
//!
//! # The source is never written
//!
//! Every part of the source container is registered with
//! [`SourceRegistry`](crate::write::guard::SourceRegistry), so no write handle
//! can later target one. The container is opened through the ordinary read
//! path, which cannot write.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::container::Container;
use crate::error::{Error, Locus, Result};
use crate::image::Image;
use crate::model::ObjectRole;
use crate::zip_volume_set::{VolumeOrigin, open_with_graph};

/// Whether `path` is an AFF4 container, by its bytes rather than its name.
///
/// A `.aff4` extension is a claim; the ZIP local-file signature plus a
/// readable `version.txt` is the fact. TSK's own AFF4 shim sniffs the same four
/// bytes. Returns false for anything unreadable, so a caller falls back to
/// treating the path as raw evidence rather than failing here.
#[must_use]
pub fn looks_like_aff4(path: &Path) -> bool {
    use std::io::Read as _;

    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut signature = [0u8; 4];
    if file.read_exact(&mut signature).is_err() {
        return false;
    }
    // "PK\x03\x04": a ZIP local file header. Every AFF4 container is a ZIP.
    if signature != [0x50, 0x4B, 0x03, 0x04] {
        return false;
    }
    // A ZIP is not necessarily an AFF4. Opening it is the only honest check,
    // and it is cheap: the container reads its central directory and
    // `version.txt`, not its image data.
    Container::open(path).is_ok()
}

/// An AFF4 container opened as a source of image bytes.
///
/// Holds the container and the resolved image. [`Aff4Source::reader`] borrows
/// both to produce a [`Read`] over the image's address space.
pub struct Aff4Source {
    container: Container,
    image: Image,
    /// Every file the source spans: the container, plus any sibling stripes.
    parts: Vec<PathBuf>,
}

impl Aff4Source {
    /// Open `path` and resolve the `DiskImage` it stores.
    ///
    /// `siblings` names the other volumes of a striped set. Each is registered
    /// as a source alongside the primary.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the container holds no `DiskImage`, if it holds
    /// more than one and none was named, or if the image cannot be resolved
    /// against the volumes given. [`Error::Io`] if a file cannot be opened or
    /// registered.
    pub fn open(
        path: &Path,
        siblings: &[PathBuf],
        registry: &mut crate::write::guard::SourceRegistry,
    ) -> Result<Self> {
        let locus = Locus::new(path);

        registry
            .register(path)
            .map_err(|e| Error::io(path.to_path_buf(), e))?;
        let mut parts = vec![path.to_path_buf()];

        let mut container = Container::open(path)?;
        for sibling in siblings {
            registry
                .register(sibling)
                .map_err(|e| Error::io(sibling.clone(), e))?;
            let (volume, graph) = open_with_graph(sibling)?;
            container.add_volume(volume, graph, VolumeOrigin::Named);
            parts.push(sibling.clone());
        }

        let summary = container.summarize()?;
        let images: Vec<_> = summary
            .images()
            .iter()
            .filter(|o| o.role == ObjectRole::DiskImage)
            .map(|o| o.arn.clone())
            .collect();

        let arn = match images.as_slice() {
            [one] => one.clone(),
            [] => {
                return Err(Error::malformed(
                    locus,
                    "the container stores no aff4:DiskImage, so there is no disk \
                     image to re-acquire; a logical container (AFF4-L) is not a \
                     source for --image",
                ));
            }
            many => {
                let names: Vec<&str> = many.iter().map(crate::arn::Arn::as_str).collect();
                return Err(Error::malformed(
                    locus,
                    format!(
                        "the container stores {} disk images ({}), and re-acquiring \
                         without saying which would silently pick one",
                        many.len(),
                        names.join(", ")
                    ),
                ));
            }
        };

        let lexicon = container.lexicon();
        let image = Image::open_in_set(&arn, container.volumes_mut(), lexicon, &locus)?;

        Ok(Self {
            container,
            image,
            parts,
        })
    }

    /// The image's size, as its map declares and covers it.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.image.size()
    }

    /// The files this source spans, in the order they were opened.
    #[must_use]
    pub fn parts(&self) -> &[PathBuf] {
        &self.parts
    }

    /// The image's ARN.
    #[must_use]
    pub fn arn(&self) -> &crate::arn::Arn {
        self.image.arn()
    }

    /// A [`Read`] over the image's address space, from byte zero.
    ///
    /// Reads through [`Image::reader_in_set`], so the decompressed bevy stays
    /// resident across calls. Acquisition reads strictly forward, which is the
    /// pattern that benefits most.
    pub fn reader(&mut self) -> Aff4ImageReader<'_> {
        let locus = Locus::new(
            self.parts
                .first()
                .map_or(Path::new("<aff4>"), |p| p.as_path()),
        );
        Aff4ImageReader {
            inner: self.image.reader_in_set(self.container.volumes_mut()),
            position: 0,
            locus,
        }
    }
}

/// A forward [`Read`] over an AFF4 image.
///
/// Created by [`Aff4Source::reader`].
pub struct Aff4ImageReader<'s> {
    inner: crate::image::ImageReader<'s, 's>,
    position: u64,
    locus: Locus,
}

impl Read for Aff4ImageReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let written = self
            .inner
            .read_at(self.position, buf, &self.locus)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.position = self.position.saturating_add(written as u64);
        Ok(written)
    }
}
