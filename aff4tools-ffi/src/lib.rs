//! The `libaff4` C ABI, implemented over aff4tools.
//!
//! Exports the functions c-aff4 publishes in `aff4/libaff4-c.h`, so consumers
//! that already call them — The Sleuth Kit built with `HAVE_LIBAFF4`, Arsenal
//! Image Mounter loading `libaff4.dll` — read AFF4 containers through this
//! implementation without changing a line.
//!
//! The signatures are inherited, not designed. What this crate decides is the
//! handle model, how errors cross the boundary, and what to do about container
//! shapes the ABI has no vocabulary for.
//!
//! # Why this is a separate crate
//!
//! `aff4tools` sets `#![deny(unsafe_code)]`, and its crate-root comment says a
//! second proposed exception is the moment to reconsider a safe wrapper crate
//! instead. A C ABI needs `extern "C"` and raw pointers, so it lives here and
//! depends on `aff4tools` through its safe public API only. The library's deny
//! is untouched, and `tests/read_only_guard.rs` asserts that.
//!
//! # The shape of a container is not the consumer's problem
//!
//! [`AFF4_open`] on **any** part of a split set discovers its siblings and
//! presents the whole image. A caller cannot tell, and must not need to know,
//! whether a container is one file or twenty. A gap in the numbering is an
//! error rather than a silently short image.
//!
//! # Nothing here can write
//!
//! Every entry point is a read. The crate opens containers through the sealed
//! read path, and there is no `AFF4_write` to implement.

// This crate exists to expose a C ABI; unsafe is inherent to that. It is
// confined here so `aff4tools` itself stays free of it.
#![allow(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
// The ABI's names are inherited from libaff4-c.h and must match it exactly:
// a consumer's header declares `AFF4_Handle`, not `Aff4Handle`.
#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aff4tools::arn::Arn;
use aff4tools::image::Image;
use aff4tools::model::ObjectRole;
use aff4tools::stream::Residency;
use aff4tools::{Container, Locus};

/// Log severity, matching `AFF4_LOG_LEVEL` in `libaff4-c.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AFF4_LOG_LEVEL {
    /// Finest detail.
    TRACE = 0,
    /// Debugging detail.
    DEBUG = 1,
    /// Informational.
    INFO = 2,
    /// A concern that did not stop the operation.
    WARNING = 3,
    /// The operation failed.
    ERROR = 4,
    /// The operation failed unrecoverably.
    CRITICAL = 5,
    /// Nothing is reported.
    OFF = 6,
}

/// A run of bytes handed to the caller.
///
/// Mirrors c-aff4's struct of the same name. `data` is owned by the caller and
/// must be released with [`AFF4_free_property`]; `length` is the byte count.
/// On failure both are left null and zero, so a caller that releases
/// unconditionally is safe.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct AFF4_Binary_Result {
    /// Pointer to the bytes. Released with [`AFF4_free_property`].
    pub data: *mut c_void,
    /// Number of bytes at `data`.
    pub length: usize,
}

/// One message in a linked list, matching `AFF4_Message` in `libaff4-c.h`.
///
/// Every list this ABI produces must be freed with [`AFF4_free_messages`].
#[repr(C)]
pub struct AFF4_Message {
    /// Severity.
    pub level: AFF4_LOG_LEVEL,
    /// NUL-terminated message text, owned by this crate.
    pub message: *mut c_char,
    /// The next message, or null.
    pub next: *mut AFF4_Message,
}

/// An opaque handle to an open image.
///
/// The state behind the pointer callers hold. Guarded by a mutex because the
/// ABI must not depend on callers serializing their own reads: TSK wraps every
/// call in a lock, but a consumer that does not would otherwise race.
pub struct AFF4_Handle {
    inner: Mutex<Open>,
    size: u64,
}

/// The container and image behind a handle.
struct Open {
    container: Container,
    image: Image,
    locus: Locus,
    /// The decompressed bevy carried between reads.
    ///
    /// `Image::read_at_in_set` drops its source per call, so without this every
    /// read -- including a re-read of bytes just returned -- decompresses a
    /// whole bevy afresh. A consumer like `mac_apt`, which walks APFS B-trees
    /// with hundreds of thousands of 4 KiB reads, pays that cost per read and
    /// spends minutes where it should spend seconds.
    ///
    /// Held here rather than as an `ImageReader` because that borrows the
    /// `Image` and the `Container` at once, which would make this struct
    /// self-referential.
    resident: Option<(Arn, Residency)>,
    /// The ARN of the image this handle was opened on.
    ///
    /// Kept because the property accessors answer about *this* object, the way
    /// c-aff4's do: it queries `handle->urn` rather than an arbitrary subject.
    arn: Arn,
}

/// Build a single-entry message list.
fn message(level: AFF4_LOG_LEVEL, text: &str) -> *mut AFF4_Message {
    // A NUL inside an error string would truncate it silently; replace rather
    // than lose the rest of what the error said.
    let owned = text.replace('\0', "\\0");
    let Ok(c) = CString::new(owned) else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(AFF4_Message {
        level,
        message: c.into_raw(),
        next: std::ptr::null_mut(),
    }))
}

/// Store `text` in `out` when the caller asked for messages.
fn report(out: *mut *mut AFF4_Message, level: AFF4_LOG_LEVEL, text: &str) {
    if out.is_null() {
        return;
    }
    let node = message(level, text);
    // SAFETY: `out` is non-null and, per the ABI, points to a writable
    // `AFF4_Message*` the caller owns.
    unsafe { *out = node };
}

/// Every part of a split set the named path belongs to, in read order.
///
/// A consumer names one file; a container may be many. Scanning the directory
/// is what makes the shape invisible, which is the point — see the module
/// documentation.
///
/// Returns just `path` when it is not part of a numbered set, so a single-file
/// container costs nothing and a lone part that legitimately is the whole
/// container still opens.
fn parts_of(path: &Path) -> Vec<PathBuf> {
    let Some(dir) = path.parent() else {
        return vec![path.to_path_buf()];
    };
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return vec![path.to_path_buf()];
    };
    if aff4tools::split_set::part_number(name).is_none() {
        // Not a numbered part, so it stands alone.
        return vec![path.to_path_buf()];
    }

    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };

    match aff4tools::split_set::discover(dir) {
        Ok(set) if set.kind == aff4tools::split_set::SplitKind::Aff4 => {
            // `discover` refuses a set with a gap in its numbering, so reaching
            // here means the set is complete. A short image would be worse than
            // an error: it verifies clean and describes evidence that was never
            // read.
            if set.parts.iter().any(|p| p == path) {
                set.parts
            } else {
                vec![path.to_path_buf()]
            }
        }
        // A folder that holds no coherent AFF4 set, or a gap: fall back to the
        // named file alone rather than guessing. If it really was one part of a
        // broken set, opening it will fail on its own terms with a better
        // message than this function could give.
        _ => vec![path.to_path_buf()],
    }
}

/// Open a container and resolve the image the ABI should expose.
fn open_image(path: &Path) -> Result<(Container, Image, Locus, u64, Arn), String> {
    let parts = parts_of(path);

    // The **first** part is the primary, whatever part the caller named.
    //
    // In a split set only part 001 carries the Map and the full metadata; the
    // rest declare their own streams and little else. Opening the named part as
    // primary therefore worked for part 001 and failed for every other part
    // with "image names no data stream" — the map was simply not in that file.
    // Since the whole point of this ABI is that the container's shape is
    // invisible, naming any part must behave identically.
    let primary = parts.first().map_or(path, PathBuf::as_path);
    let locus = Locus::new(primary);

    let mut container =
        Container::open(primary).map_err(|e| format!("opening {}: {e}", primary.display()))?;

    for sibling in &parts {
        if sibling == primary {
            continue;
        }
        let (volume, graph) = aff4tools::zip_volume_set::open_with_graph(sibling)
            .map_err(|e| format!("opening part {}: {e}", sibling.display()))?;
        container.add_volume(
            volume,
            graph,
            aff4tools::zip_volume_set::VolumeOrigin::Named,
        );
    }

    let summary = container
        .summarize()
        .map_err(|e| format!("reading metadata from {}: {e}", primary.display()))?;

    // c-aff4 keys on aff4:DiskImage, but that type is not the only way a disk
    // image is declared in the wild. An APFS acquisition written by
    // MacQuisition/BlackBag types its image `aff4:DiscontiguousImage,
    // aff4:Image` with no `aff4:DiskImage` at all, and `ObjectRole` classifies
    // most-specific-first, so such an image lands on `DiscontiguousImage` and a
    // DiskImage-only filter finds nothing in a container that plainly holds a
    // disk. `Image::open_in_set` reads all three the same way -- the gap was in
    // discovery, not in the read path.
    //
    // DiskImage still wins when present: the roles are collected in preference
    // order rather than by first appearance, so a container declaring both is
    // opened on its DiskImage exactly as before.
    let images = summary.images();
    let disk_images: Vec<_> = [
        ObjectRole::DiskImage,
        ObjectRole::DiscontiguousImage,
        ObjectRole::ContiguousImage,
    ]
    .iter()
    .flat_map(|role| {
        images
            .iter()
            .filter(move |o| o.role == *role)
            .map(|o| o.arn.clone())
    })
    .collect();

    // c-aff4's header says "access the first aff4:Image in the container", and
    // TSK was written against that. Following it matters more than being
    // stricter.
    let arn = if let Some(first) = disk_images.first() {
        first.clone()
    } else {
        {
            // An AFF4-L is not a damaged container, and saying so is more
            // useful than "no image found". A caller pointed at the wrong kind
            // of evidence should be told which kind they have.
            let logical = summary
                .objects
                .iter()
                .any(|o| matches!(o.role, ObjectRole::FileImage | ObjectRole::FolderImage));
            return Err(if logical {
                "No disk image found; this appears to be an AFF4-L logical image.".to_owned()
            } else {
                format!("No disk image found in {}", primary.display())
            });
        }
    };

    let lexicon = container.lexicon();
    let image = Image::open_in_set(&arn, container.volumes_mut(), lexicon, &locus)
        .map_err(|e| format!("opening image {arn}: {e}"))?;
    let size = image.size();

    Ok((container, image, locus, size, arn))
}

/// The library's version string.
///
/// # Safety
///
/// The returned pointer is static and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn AFF4_version() -> *const c_char {
    concat!("aff4tools ", env!("CARGO_PKG_VERSION"), "\0")
        .as_ptr()
        .cast()
}

/// Set the verbosity of reported messages.
///
/// Accepted and ignored: this implementation reports errors through the
/// `AFF4_Message` out-parameters and never logs on its own, so there is no
/// global stream to quiet. Present because the ABI declares it and a consumer
/// may call it.
#[unsafe(no_mangle)]
pub extern "C" fn AFF4_set_verbosity(_level: AFF4_LOG_LEVEL) {}

/// Free a message list produced by this ABI.
///
/// # Safety
///
/// `msg` must be null, or a list this ABI produced and has not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_free_messages(msg: *mut AFF4_Message) {
    let mut current = msg;
    while !current.is_null() {
        // SAFETY: every node in the list was produced by `message`, which
        // allocates a Box and a CString.
        let node = unsafe { Box::from_raw(current) };
        if !node.message.is_null() {
            drop(unsafe { CString::from_raw(node.message) });
        }
        current = node.next;
    }
}

/// Open a container and access the first disk image it holds.
///
/// Any part of a split set opens the whole set: the consumer never learns the
/// container's shape.
///
/// Returns null on failure, with `msg` populated when it is non-null.
///
/// # Safety
///
/// `filename` must be a valid NUL-terminated string. `msg`, if non-null, must
/// point to a writable `AFF4_Message*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_open(
    filename: *const c_char,
    msg: *mut *mut AFF4_Message,
) -> *mut AFF4_Handle {
    if !msg.is_null() {
        // SAFETY: the caller guarantees `msg` is writable.
        unsafe { *msg = std::ptr::null_mut() };
    }
    if filename.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "filename is null");
        return std::ptr::null_mut();
    }

    // SAFETY: the caller guarantees a NUL-terminated string.
    let raw = unsafe { CStr::from_ptr(filename) };
    let Ok(text) = raw.to_str() else {
        report(msg, AFF4_LOG_LEVEL::ERROR, "filename is not valid UTF-8");
        return std::ptr::null_mut();
    };
    let path = PathBuf::from(text);

    // A panic must not unwind into C: that is undefined behavior. Any panic
    // here is a bug in this crate, and the caller gets an error instead.
    let opened = catch_unwind(AssertUnwindSafe(|| open_image(&path)));

    match opened {
        Ok(Ok((container, image, locus, size, arn))) => Box::into_raw(Box::new(AFF4_Handle {
            inner: Mutex::new(Open {
                container,
                image,
                locus,
                arn,
                resident: None,
            }),
            size,
        })),
        Ok(Err(text)) => {
            report(msg, AFF4_LOG_LEVEL::ERROR, &text);
            std::ptr::null_mut()
        }
        Err(_) => {
            report(
                msg,
                AFF4_LOG_LEVEL::CRITICAL,
                "internal error while opening",
            );
            std::ptr::null_mut()
        }
    }
}

/// The size in bytes of the image the handle was opened on.
///
/// # Safety
///
/// `handle` must be a live handle from [`AFF4_open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_object_size(
    handle: *mut AFF4_Handle,
    msg: *mut *mut AFF4_Message,
) -> u64 {
    if handle.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "handle is null");
        return 0;
    }
    // SAFETY: the caller guarantees a live handle.
    unsafe { &*handle }.size
}

/// Read `length` bytes at `offset` into `buffer`.
///
/// Returns the number of bytes placed in the buffer, `0` at or past the end of
/// the image, or `-1` on error with `msg` populated.
///
/// # Safety
///
/// `handle` must be live, and `buffer` must be writable for `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_read(
    handle: *mut AFF4_Handle,
    offset: u64,
    buffer: *mut c_void,
    length: usize,
    msg: *mut *mut AFF4_Message,
) -> isize {
    if handle.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "handle is null");
        return -1;
    }
    if length == 0 {
        return 0;
    }
    if buffer.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "buffer is null");
        return -1;
    }

    // SAFETY: the caller guarantees `buffer` is writable for `length` bytes.
    let out = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) };
    // SAFETY: the caller guarantees a live handle.
    let state = unsafe { &*handle };

    let Ok(mut open) = state.inner.lock() else {
        report(
            msg,
            AFF4_LOG_LEVEL::CRITICAL,
            "handle is poisoned by an earlier failure and cannot be read",
        );
        return -1;
    };

    let read = catch_unwind(AssertUnwindSafe(|| {
        let Open {
            container,
            image,
            locus,
            resident,
            ..
        } = &mut *open;
        image.read_at_in_set_cached(container.volumes_mut(), offset, out, locus, resident)
    }));

    match read {
        Ok(Ok(n)) => isize::try_from(n).unwrap_or(isize::MAX),
        Ok(Err(e)) => {
            // The whole point of the message channel: the locus and the reason
            // survive, where a FUSE mount would have only EIO.
            report(msg, AFF4_LOG_LEVEL::ERROR, &format!("{e}"));
            -1
        }
        Err(_) => {
            report(
                msg,
                AFF4_LOG_LEVEL::CRITICAL,
                "internal error while reading",
            );
            -1
        }
    }
}

/// Close a handle.
///
/// Returns 0, or -1 if the handle is null.
///
/// # Safety
///
/// `handle` must be a live handle from [`AFF4_open`], not already closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_close(
    handle: *mut AFF4_Handle,
    msg: *mut *mut AFF4_Message,
) -> c_int {
    if handle.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "handle is null");
        return -1;
    }
    // SAFETY: the caller guarantees a live handle produced by AFF4_open.
    drop(unsafe { Box::from_raw(handle) });
    0
}

/// Look up a property on the object this handle was opened on.
///
/// Mirrors c-aff4, whose accessors query `handle->urn` rather than an
/// arbitrary subject: the answer is always about *this* image.
///
/// `property` may be a full IRI (`http://aff4.org/Schema#size`) or a bare
/// local name (`size`); both are accepted, since a caller holding a lexicon
/// constant and a caller typing a short name both have a reasonable claim.
/// Returns the lexical form exactly as the container wrote it — no
/// normalization, because the recorded form is what an examiner must be able
/// to reproduce.
fn property_value(open: &mut Open, property: &str) -> Option<String> {
    let wanted = property.rsplit(['#', '/']).next().unwrap_or(property);

    let summary = open.container.summarize().ok()?;
    let object = summary.objects.iter().find(|o| o.arn == open.arn)?;

    // `aff4:size` is modelled rather than left in `properties`, so it would be
    // missed by the generic scan below.
    if wanted == "size" {
        if let Some(size) = object.size {
            return Some(size.to_string());
        }
    }

    // Digests are modelled too, and are the values a binary accessor is for.
    if let Some(hash) = object.hashes.iter().find(|h| h.predicate == wanted) {
        return Some(hash.hex.clone());
    }

    object
        .properties
        .iter()
        .find(|p| &*p.name == wanted || &*p.iri == property)
        .map(|p| p.value.lexical().to_owned())
}

/// Read `property` from the handle, or report why it could not be read.
///
/// # Safety
///
/// `handle` must be live and `property` NUL-terminated.
unsafe fn lookup(
    handle: *mut AFF4_Handle,
    property: *const c_char,
    msg: *mut *mut AFF4_Message,
) -> Option<String> {
    if handle.is_null() || property.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "null argument");
        return None;
    }
    // SAFETY: the caller guarantees a NUL-terminated string.
    let name = unsafe { CStr::from_ptr(property) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: the caller guarantees a live handle from AFF4_open.
    let Ok(mut open) = unsafe { &*handle }.inner.lock() else {
        report(msg, AFF4_LOG_LEVEL::ERROR, "handle is poisoned");
        return None;
    };
    let found = property_value(&mut open, &name);
    if found.is_none() {
        report(
            msg,
            AFF4_LOG_LEVEL::WARNING,
            &format!("no property {name} on {}", open.arn),
        );
    }
    found
}

/// The value of a boolean property.
///
/// Accepts the XSD spellings: `true`/`false` and `1`/`0`. A property that
/// exists but is not a boolean is an error rather than a guess.
///
/// # Safety
///
/// `handle` must be live, `property` NUL-terminated, `result` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_get_boolean_property(
    handle: *mut AFF4_Handle,
    property: *const c_char,
    result: *mut c_int,
    msg: *mut *mut AFF4_Message,
) -> c_int {
    if result.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "null argument");
        return -1;
    }
    // SAFETY: forwarded to the caller's guarantees.
    let Some(text) = (unsafe { lookup(handle, property, msg) }) else {
        return -1;
    };
    let value = match text.trim() {
        "true" | "1" => 1,
        "false" | "0" => 0,
        other => {
            report(
                msg,
                AFF4_LOG_LEVEL::WARNING,
                &format!("value {other:?} is not a boolean"),
            );
            return -1;
        }
    };
    // SAFETY: checked non-null above.
    unsafe { *result = value };
    0
}

/// The value of an integer property, currently `aff4:size` only.
///
/// # Safety
///
/// `handle` must be live, `property` NUL-terminated, `result` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_get_integer_property(
    handle: *mut AFF4_Handle,
    property: *const c_char,
    result: *mut i64,
    msg: *mut *mut AFF4_Message,
) -> c_int {
    if handle.is_null() || property.is_null() || result.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "null argument");
        return -1;
    }
    // SAFETY: the caller guarantees a NUL-terminated string.
    let name = unsafe { CStr::from_ptr(property) }.to_string_lossy();
    if name.ends_with("size") {
        // SAFETY: the caller guarantees a live handle and writable result.
        let size = unsafe { &*handle }.size;
        unsafe { *result = i64::try_from(size).unwrap_or(i64::MAX) };
        return 0;
    }
    // Any other integer-valued property, read from the metadata.
    // SAFETY: forwarded to the caller's guarantees.
    let Some(text) = (unsafe { lookup(handle, property, msg) }) else {
        return -1;
    };
    match text.trim().parse::<i64>() {
        Ok(value) => {
            // SAFETY: checked non-null above.
            unsafe { *result = value };
            0
        }
        Err(_) => {
            report(
                msg,
                AFF4_LOG_LEVEL::WARNING,
                &format!("value {text:?} is not an integer"),
            );
            -1
        }
    }
}

/// The value of a string property, as the container wrote it.
///
/// `*result` is a NUL-terminated copy the caller owns.
///
/// # Safety
///
/// `handle` must be live, `property` NUL-terminated, `result` writable. The
/// returned pointer must be released with [`AFF4_free_property`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_get_string_property(
    handle: *mut AFF4_Handle,
    property: *const c_char,
    result: *mut *mut c_char,
    msg: *mut *mut AFF4_Message,
) -> c_int {
    if result.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "null argument");
        return -1;
    }
    // SAFETY: forwarded to the caller's guarantees.
    let Some(text) = (unsafe { lookup(handle, property, msg) }) else {
        return -1;
    };
    let Ok(owned) = CString::new(text) else {
        report(msg, AFF4_LOG_LEVEL::ERROR, "value contains a NUL byte");
        return -1;
    };
    let bytes = owned.as_bytes_with_nul();
    // Allocated with libc so the caller's `free` matches, exactly as c-aff4
    // does. A Rust-allocated buffer freed by C would be undefined behavior.
    let Some(buffer) = alloc_c(bytes.len()) else {
        report(msg, AFF4_LOG_LEVEL::ERROR, "out of memory");
        return -1;
    };
    // SAFETY: `buffer` is a fresh allocation of exactly `bytes.len()` bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), bytes.len()) };
    // SAFETY: checked non-null above.
    unsafe { *result = buffer.cast::<c_char>() };
    0
}

/// The value of a binary property, decoded from its hex lexical form.
///
/// This is the accessor c-aff4 exposes for `RDFBytes` values, which the
/// Turtle stores as hex and which the reader decodes to raw bytes. A digest
/// is the case that matters: `aff4:hash` is written as 64 hex characters, and
/// a caller wanting the 32 raw bytes of a SHA-256 asks for it here rather
/// than through the string accessor.
///
/// `result->data` is allocated for the caller, who owns it.
///
/// Values decoding to more than [`MAX_BINARY_PROPERTY_BYTES`] are refused
/// before anything is allocated: the lexical form comes from container
/// metadata, which is untrusted input.
///
/// # Safety
///
/// `handle` must be live, `property` NUL-terminated, `result` writable. The
/// returned `data` pointer must be released with [`AFF4_free_property`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_get_binary_property(
    handle: *mut AFF4_Handle,
    property: *const c_char,
    result: *mut AFF4_Binary_Result,
    msg: *mut *mut AFF4_Message,
) -> c_int {
    if result.is_null() {
        report(msg, AFF4_LOG_LEVEL::ERROR, "null argument");
        return -1;
    }
    // Clear first, as c-aff4 does: a caller that ignores the return value must
    // not be handed a dangling pointer from an earlier call.
    // SAFETY: checked non-null above.
    unsafe {
        (*result).data = std::ptr::null_mut();
        (*result).length = 0;
    }

    // SAFETY: forwarded to the caller's guarantees.
    let Some(text) = (unsafe { lookup(handle, property, msg) }) else {
        return -1;
    };

    let trimmed = text.trim();

    // Distinguished from "not hex": an oversized value may be perfectly valid
    // hex, and saying it is malformed would be a false finding about the
    // evidence. The message states the limit rather than echoing a value that
    // could be megabytes long.
    if trimmed.len() / 2 > MAX_BINARY_PROPERTY_BYTES {
        report(
            msg,
            AFF4_LOG_LEVEL::WARNING,
            &format!(
                "binary property is {} bytes, above this ABI's {MAX_BINARY_PROPERTY_BYTES}-byte \
                 limit; read it through the aff4tools library instead",
                trimmed.len() / 2
            ),
        );
        return -1;
    }

    let Some(bytes) = decode_hex(trimmed) else {
        report(
            msg,
            AFF4_LOG_LEVEL::WARNING,
            &format!("value {text:?} is not hex-encoded binary"),
        );
        return -1;
    };

    // A zero-length value is a real answer, not an error; report it without
    // allocating, since `malloc(0)` may or may not return null.
    if bytes.is_empty() {
        return 0;
    }

    let Some(buffer) = alloc_c(bytes.len()) else {
        report(msg, AFF4_LOG_LEVEL::ERROR, "out of memory");
        return -1;
    };
    // SAFETY: `buffer` is a fresh allocation of exactly `bytes.len()` bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), bytes.len()) };
    // SAFETY: checked non-null above.
    unsafe {
        (*result).data = buffer;
        (*result).length = bytes.len();
    }
    0
}

/// Allocate `len` bytes with the C allocator.
///
/// The property accessors hand ownership to the caller. A buffer from Rust's
/// allocator released by C's `free` is undefined behavior, so these must come
/// from `malloc` even though nothing else in this crate does.
///
/// Callers should release these through [`AFF4_free_property`] rather than
/// `free` — see that function for why it exists.
///
/// Declared directly rather than via the `libc` crate: two symbols do not
/// justify a dependency, and the ABI of `malloc` is fixed.
fn alloc_c(len: usize) -> Option<*mut c_void> {
    unsafe extern "C" {
        fn malloc(size: usize) -> *mut c_void;
    }
    // SAFETY: `malloc` is always safe to call; a null return is handled.
    let p = unsafe { malloc(len) };
    if p.is_null() { None } else { Some(p) }
}

/// Release a buffer returned by `AFF4_get_string_property` or
/// `AFF4_get_binary_property`.
///
/// **This is an addition to c-aff4's ABI, not a part of it.** c-aff4 tells the
/// caller to use `free`, which is safe only when the library and the consumer
/// share one heap. On Windows they frequently do not: each C runtime carries
/// its own, so a buffer allocated inside `libaff4.dll` linked against one CRT
/// and released by a consumer linked against another is undefined behavior —
/// heap corruption rather than a clean failure. Arsenal Image Mounter is
/// exactly that shape of consumer.
///
/// Freeing in the module that allocated removes the question. Passing null is
/// a no-op, so a caller need not check first.
///
/// A consumer written against c-aff4 that calls `free` directly still works
/// wherever one heap is shared, which is every Unix; nothing is broken by
/// adding this.
///
/// # Safety
///
/// `ptr` must be null, or a pointer this library returned from a property
/// accessor and that has not already been released. Passing anything else —
/// including a pointer already freed — is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AFF4_free_property(ptr: *mut c_void) {
    unsafe extern "C" {
        fn free(p: *mut c_void);
    }
    if ptr.is_null() {
        return;
    }
    // SAFETY: the caller guarantees this came from `alloc_c` and is live.
    unsafe { free(ptr) };
}

/// The largest binary property this ABI will decode, in decoded bytes.
///
/// A property's lexical form comes from the container's metadata, which is
/// **untrusted input**: a hostile or damaged `information.turtle` can declare
/// a hex literal of any length, and decoding it allocates. Ten mebibytes is
/// far beyond any real use — the values this accessor exists for are digests,
/// where a SHA-512 is 64 bytes — while leaving room for a writer that records
/// something larger without inviting an unbounded allocation.
///
/// Refusing is safe here in a way it would not be on the read path: this
/// declines to *hand over* a property, and never affects image data.
pub const MAX_BINARY_PROPERTY_BYTES: usize = 10 * 1024 * 1024;

/// Decode a hex string to bytes, rejecting odd lengths and non-hex digits.
///
/// c-aff4's `RDFBytes::UnSerializeFromString` rejects an odd length outright;
/// this matches, because a truncated digest silently accepted is worse than a
/// refusal. Values decoding to more than [`MAX_BINARY_PROPERTY_BYTES`] are
/// refused before anything is allocated.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    // Checked before allocating, so an absurd literal costs nothing.
    if text.len() / 2 > MAX_BINARY_PROPERTY_BYTES {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

/// Accepted and ignored: this implementation caches no handles.
#[unsafe(no_mangle)]
pub extern "C" fn AFF4_set_handle_cache_size(_n: c_uint) {}

/// Accepted and ignored: this implementation caches no handles.
#[unsafe(no_mangle)]
pub extern "C" fn AFF4_clear_handle_cache() {}

#[cfg(test)]
mod tests {
    use super::{MAX_BINARY_PROPERTY_BYTES, decode_hex};

    /// A digest decodes to its byte form.
    #[test]
    fn hex_decodes_to_bytes() {
        assert_eq!(decode_hex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(decode_hex(""), Some(vec![]));
    }

    /// Odd lengths and non-hex digits are refused, matching c-aff4.
    #[test]
    fn malformed_hex_is_refused() {
        assert_eq!(decode_hex("abc"), None, "odd length");
        assert_eq!(decode_hex("zz"), None, "not hex");
        assert_eq!(decode_hex("00 ff"), None, "embedded space");
    }

    /// The cap is enforced before allocating, and one byte under it is fine.
    ///
    /// The container's metadata is untrusted input: a hostile or damaged
    /// `information.turtle` can declare a hex literal of any length, and
    /// decoding it allocates. This bounds that.
    #[test]
    fn an_oversized_literal_is_refused_without_allocating() {
        let over = "a".repeat((MAX_BINARY_PROPERTY_BYTES + 1) * 2);
        assert_eq!(decode_hex(&over), None, "above the cap must be refused");

        let at = "a".repeat(MAX_BINARY_PROPERTY_BYTES * 2);
        assert_eq!(
            decode_hex(&at).map(|v| v.len()),
            Some(MAX_BINARY_PROPERTY_BYTES),
            "exactly at the cap must still decode"
        );
    }

    /// The cap is generous relative to what this accessor is for.
    #[test]
    fn the_cap_leaves_room_for_real_values() {
        // A SHA-512 is 64 bytes; the cap is five orders of magnitude above it.
        assert!(MAX_BINARY_PROPERTY_BYTES > 64 * 100_000);
        assert_eq!(MAX_BINARY_PROPERTY_BYTES, 10 * 1024 * 1024);
    }
}
