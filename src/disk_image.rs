//! Opening the disk image in a container or a multi-part set.
//!
//! One place decides which files make up a set and which image in it is the
//! disk, so the command line, the C ABI, and library consumers can never
//! disagree about what an image is.

use std::path::{Path, PathBuf};

use crate::multi_part::{self, PartKind};
use crate::zip_volume_set::{self, VolumeOrigin};
use crate::{Arn, Container, Error, Image, Locus, ObjectRole, Result};

/// An opened disk image, with the container it reads through.
///
/// Reads need `&mut` access to the container's volume set and `&` access to
/// the image, so both are public fields: a caller borrows them separately.
#[derive(Debug)]
pub struct DiskImageHandle {
    /// Every part of the set, opened.
    pub container: Container,
    /// The disk image.
    pub image: Image,
    /// The part the set was opened from: part 1, whichever part was named.
    pub primary: PathBuf,
}

/// Which image to open.
#[derive(Debug, Clone, Copy)]
enum Choice<'a> {
    /// The only candidate; a second is an error.
    Only,
    /// The first candidate, as c-aff4 does.
    First,
    /// The image with this ARN.
    Named(&'a Arn),
}

/// Open the one disk image in the container or multi-part set that `path`
/// belongs to.
///
/// Any part of a set may be named. The candidates are the `aff4:DiskImage`
/// objects; with none, the `aff4:DiscontiguousImage` objects, then the
/// `aff4:ContiguousImage` ones, since some imagers declare a disk only that
/// way: one APFS acquisition tool types its image `aff4:DiscontiguousImage`
/// with no `aff4:DiskImage` at all.
///
/// # Errors
///
/// [`Error::NoDiskImage`] if there is no candidate; [`Error::AmbiguousImage`]
/// if there are several of the first kind found; otherwise whatever opening
/// the container or the image returns. A part of the set that cannot be opened
/// is an error, never skipped.
pub fn open(path: &Path) -> Result<DiskImageHandle> {
    open_with(path, Choice::Only)
}

/// [`open`], but taking the first candidate when there are several, as c-aff4
/// does. The C ABI keeps that behavior because TSK was written against it.
///
/// # Errors
///
/// As [`open`], except never [`Error::AmbiguousImage`].
pub fn open_first(path: &Path) -> Result<DiskImageHandle> {
    open_with(path, Choice::First)
}

/// Open the image named `arn` in the container or set that `path` belongs to.
///
/// # Errors
///
/// As [`open`], except never [`Error::NoDiskImage`] or
/// [`Error::AmbiguousImage`]. An `arn` that names no image fails when the
/// image is opened.
pub fn open_arn(path: &Path, arn: &Arn) -> Result<DiskImageHandle> {
    open_with(path, Choice::Named(arn))
}

fn open_with(path: &Path, choice: Choice<'_>) -> Result<DiskImageHandle> {
    let parts = parts_of(path);
    // In a multi-part set only part 1 carries the Map, so it is the primary
    // whichever part was named.
    let primary = parts.first().cloned().unwrap_or_else(|| path.to_path_buf());
    let locus = Locus::new(&primary);

    let mut container = Container::open(&primary)?;
    for sibling in parts.iter().skip(1) {
        let (volume, graph) = zip_volume_set::open_with_graph(sibling)?;
        container.add_volume(volume, graph, VolumeOrigin::Named);
    }

    let arn = choose(&mut container, &primary, choice)?;
    let lexicon = container.lexicon();
    let mapping = container.name_mapping();
    let image = Image::open_in_set(&arn, container.volumes_mut(), lexicon, mapping, &locus)?;

    Ok(DiskImageHandle {
        container,
        image,
        primary,
    })
}

/// Choose the image to open.
fn choose(container: &mut Container, primary: &Path, choice: Choice<'_>) -> Result<Arn> {
    if let Choice::Named(arn) = choice {
        return Ok(arn.clone());
    }
    let summary = container.summarize()?;
    let images = summary.images();
    for role in [
        ObjectRole::DiskImage,
        ObjectRole::DiscontiguousImage,
        ObjectRole::ContiguousImage,
    ] {
        let found: Vec<&Arn> = images
            .iter()
            .filter(|o| o.role == role)
            .map(|o| &o.arn)
            .collect();
        match (found.as_slice(), choice) {
            ([], _) => {}
            ([one], _) | ([one, ..], Choice::First) => return Ok((*one).clone()),
            (many, _) => {
                return Err(Error::AmbiguousImage {
                    path: primary.to_path_buf(),
                    candidates: many.iter().map(|a| a.as_str().to_owned()).collect(),
                });
            }
        }
    }
    let logical = summary
        .objects
        .iter()
        .any(|o| matches!(o.role, ObjectRole::FileImage | ObjectRole::FolderImage));
    Err(Error::NoDiskImage {
        path: primary.to_path_buf(),
        logical,
    })
}

/// Every part of the multi-part set `path` belongs to, in order, or just
/// `path`.
///
/// Deliberately **not** gated on the name carrying an ordinal. Under AFF4-L
/// v1.0-ALPHA §8 the first part of a set is named with no ordinal at all,
/// indistinguishable by name from a lone container. So a name without a number
/// must still look for siblings, and [`multi_part::discover`] settles which it
/// is. That costs one directory listing per open.
///
/// A folder holding no coherent AFF4 set falls back to the named file alone
/// rather than guessing. If that file really was one part of a broken set,
/// opening or reading it fails on its own terms.
fn parts_of(path: &Path) -> Vec<PathBuf> {
    let alone = || vec![path.to_path_buf()];
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    match multi_part::discover(dir) {
        // `discover` refuses a set with a gap in its numbering, so reaching
        // here means the set is complete.
        Ok(set) if set.kind == PartKind::Aff4 && set.parts.iter().any(|p| p == path) => set.parts,
        _ => alone(),
    }
}
