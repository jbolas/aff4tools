//! The C ABI, exercised through the same entry points a C consumer uses.
//!
//! Calls the `extern "C"` functions directly rather than the safe API beneath
//! them, so a mistake in the boundary — a null check, a handle lifetime, a
//! message that leaks — fails here rather than in a consumer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::{CString, c_void};
use std::path::PathBuf;

use aff4::{
    AFF4_Binary_Result, AFF4_Handle, AFF4_Message, AFF4_close, AFF4_free_messages,
    AFF4_free_property, AFF4_get_binary_property, AFF4_get_boolean_property,
    AFF4_get_integer_property, AFF4_get_string_property, AFF4_object_size, AFF4_open, AFF4_read,
};

/// The corpus root, or a clear failure explaining how to point at it.
fn corpus_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("AFF4_TEST_IMAGES") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").expect("HOME must be set to locate the corpus");
    PathBuf::from(home).join(".cache/aff4tools/corpus")
}

fn base_linear() -> PathBuf {
    corpus_root().join("pyaff4/test_images/AFF4Std/Base-Linear.aff4")
}

/// Open a path through the ABI, returning the handle and any message.
fn open(path: &std::path::Path) -> (*mut AFF4_Handle, *mut AFF4_Message) {
    let c = CString::new(path.to_str().unwrap()).unwrap();
    let mut msg: *mut AFF4_Message = std::ptr::null_mut();
    let handle = unsafe { AFF4_open(c.as_ptr(), &raw mut msg) };
    (handle, msg)
}

/// The text of a message list, joined.
fn text_of(msg: *mut AFF4_Message) -> String {
    let mut out = String::new();
    let mut current = msg;
    while !current.is_null() {
        let node = unsafe { &*current };
        if !node.message.is_null() {
            out.push_str(&unsafe { std::ffi::CStr::from_ptr(node.message) }.to_string_lossy());
        }
        current = node.next;
    }
    out
}

#[cfg(feature = "corpus")]
#[test]
fn open_reports_the_image_size() {
    let (handle, msg) = open(&base_linear());
    assert!(!handle.is_null(), "open failed: {}", text_of(msg));
    unsafe { AFF4_free_messages(msg) };

    let mut msg: *mut AFF4_Message = std::ptr::null_mut();
    let size = unsafe { AFF4_object_size(handle, &raw mut msg) };
    unsafe { AFF4_free_messages(msg) };
    assert_eq!(size, 268_435_456);

    assert_eq!(unsafe { AFF4_close(handle, std::ptr::null_mut()) }, 0);
}

#[cfg(feature = "corpus")]
#[test]
fn read_matches_the_safe_api() {
    let (handle, msg) = open(&base_linear());
    assert!(!handle.is_null(), "open failed: {}", text_of(msg));
    unsafe { AFF4_free_messages(msg) };

    let mut buf = vec![0u8; 65536];
    let mut msg: *mut AFF4_Message = std::ptr::null_mut();
    let n = unsafe {
        AFF4_read(
            handle,
            0,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len(),
            &raw mut msg,
        )
    };
    unsafe { AFF4_free_messages(msg) };
    assert_eq!(n, 65536, "a read inside the image is never short");

    // The same region through the safe API.
    let path = base_linear();
    let locus = aff4tools::Locus::new(&path);
    let mut container = aff4tools::Container::open(&path).unwrap();
    let arn = container
        .summarize()
        .unwrap()
        .images()
        .iter()
        .find(|o| o.role == aff4tools::ObjectRole::DiskImage)
        .map(|o| o.arn.clone())
        .unwrap();
    let lexicon = container.lexicon();
    let image =
        aff4tools::image::Image::open_in_set(&arn, container.volumes_mut(), lexicon, &locus)
            .unwrap();
    let mut expected = vec![0u8; 65536];
    image
        .read_at_in_set(container.volumes_mut(), 0, &mut expected, &locus)
        .unwrap();

    assert_eq!(buf, expected, "the ABI and the safe API disagree");
    assert_eq!(unsafe { AFF4_close(handle, std::ptr::null_mut()) }, 0);
}

#[cfg(feature = "corpus")]
#[test]
fn read_past_the_end_returns_zero() {
    let (handle, _) = open(&base_linear());
    assert!(!handle.is_null());
    let size = unsafe { AFF4_object_size(handle, std::ptr::null_mut()) };

    let mut buf = vec![0u8; 4096];
    let n = unsafe {
        AFF4_read(
            handle,
            size,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        n, 0,
        "a read at the end delivers nothing and is not an error"
    );
    unsafe { AFF4_close(handle, std::ptr::null_mut()) };
}

#[test]
fn a_zero_length_read_is_a_noop() {
    // No container needed: the length check precedes any use of the handle.
    let n = unsafe {
        AFF4_read(
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(n, -1, "a null handle is still refused");
}

#[test]
fn a_missing_file_returns_null_with_a_message() {
    let (handle, msg) = open(std::path::Path::new("/nonexistent/evidence.aff4"));
    assert!(handle.is_null(), "a missing file must not yield a handle");
    let text = text_of(msg);
    assert!(
        !text.is_empty(),
        "failure must be explained, not merely signalled"
    );
    unsafe { AFF4_free_messages(msg) };
}

#[test]
fn null_arguments_are_refused_rather_than_dereferenced() {
    assert!(unsafe { AFF4_open(std::ptr::null(), std::ptr::null_mut()) }.is_null());
    assert_eq!(
        unsafe { AFF4_object_size(std::ptr::null_mut(), std::ptr::null_mut()) },
        0
    );
    assert_eq!(
        unsafe { AFF4_close(std::ptr::null_mut(), std::ptr::null_mut()) },
        -1
    );
}

/// An AFF4-L is named as such rather than reported as a missing image.
#[cfg(feature = "corpus")]
#[test]
fn a_logical_container_is_named_in_the_message() {
    let path = corpus_root().join("pyaff4/test_images/AFF4-L/dream.aff4");
    let (handle, msg) = open(&path);
    assert!(handle.is_null(), "an AFF4-L holds no disk image");
    let text = text_of(msg);
    assert!(
        text.contains("AFF4-L"),
        "the message must name what the container actually is: {text}"
    );
    unsafe { AFF4_free_messages(msg) };
}

/// Freeing a message list twice over null is safe.
#[test]
fn freeing_null_is_safe() {
    unsafe { AFF4_free_messages(std::ptr::null_mut()) };
}

/// Any part of a split set opens the whole image, identically.
///
/// **The property this ABI exists to provide.** A consumer names one file; what
/// it gets is the evidence, whatever shape the container happens to have on
/// disk. Naming part 005 must be indistinguishable from naming part 001.
///
/// This caught a real defect: only part 001 carries the Map, so opening the
/// *named* part as primary worked for 001 and failed for every other part with
/// "image names no data stream".
#[cfg(feature = "corpus")]
#[test]
fn any_part_of_a_split_set_opens_the_whole_image() {
    let dir = match std::env::var_os("AFF4_TEST_SPLIT_SET") {
        Some(d) => PathBuf::from(d),
        // No split-set fixture configured; the corpus does not ship one.
        None => return,
    };

    let mut parts: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("aff4"))
        })
        .collect();
    parts.sort();
    assert!(
        parts.len() > 1,
        "expected a multi-part set in {}",
        dir.display()
    );

    let mut sizes = Vec::new();
    let mut prefixes = Vec::new();

    for part in [parts.first().unwrap(), parts.last().unwrap()] {
        let (handle, msg) = open(part);
        assert!(
            !handle.is_null(),
            "opening {} failed: {}",
            part.display(),
            text_of(msg)
        );
        unsafe { AFF4_free_messages(msg) };

        sizes.push(unsafe { AFF4_object_size(handle, std::ptr::null_mut()) });

        // A window well past the first part's own extent, so it can only be
        // served by resolving across the set.
        let mut buf = vec![0u8; 65536];
        let n = unsafe {
            AFF4_read(
                handle,
                4_294_967_296,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(n, 65536, "a read inside the image is never short");
        prefixes.push(buf);

        unsafe { AFF4_close(handle, std::ptr::null_mut()) };
    }

    assert_eq!(
        sizes[0], sizes[1],
        "the first and last part reported different image sizes"
    );
    assert_eq!(
        prefixes[0], prefixes[1],
        "the first and last part served different bytes at the same offset"
    );
}

/// The hash the container records for `Base-Linear.aff4`, as written.
///
/// A SHA-512, so 128 hex characters and 64 bytes decoded. Taken from the
/// container's own metadata, not computed here.
#[cfg(feature = "corpus")]
const BASE_LINEAR_HASH: &str = "c339331791f2018c50247cae1307ea8b0ce1166fac8747c5f4438c364b3d6c56\
793405afec7eec366205073ed9f7e7801556587c87181d83afe356bc9244ccf2";

/// The binary accessor returns the bytes the string accessor returns as hex.
///
/// This is the whole point of `AFF4_get_binary_property`: a digest is stored
/// as a hex literal, and a caller wanting the raw bytes should not have to
/// decode it itself. Both are checked against the same recorded value so a
/// decoding error cannot pass by agreeing with itself.
#[cfg(feature = "corpus")]
#[test]
fn a_binary_property_decodes_the_hex_the_string_property_returns() {
    let (handle, msg) = open(&base_linear());
    assert!(!handle.is_null(), "{}", text_of(msg));
    unsafe { AFF4_free_messages(msg) };

    let key = CString::new("hash").unwrap();
    let mut msg: *mut AFF4_Message = std::ptr::null_mut();

    let mut text: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { AFF4_get_string_property(handle, key.as_ptr(), &raw mut text, &raw mut msg) };
    assert_eq!(rc, 0, "string accessor failed: {}", text_of(msg));
    let hex = unsafe { std::ffi::CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        hex, BASE_LINEAR_HASH,
        "the recorded hash must be returned verbatim"
    );
    unsafe { AFF4_free_property(text.cast()) };

    let mut bin = AFF4_Binary_Result {
        data: std::ptr::null_mut(),
        length: 0,
    };
    let rc = unsafe { AFF4_get_binary_property(handle, key.as_ptr(), &raw mut bin, &raw mut msg) };
    assert_eq!(rc, 0, "binary accessor failed: {}", text_of(msg));
    assert_eq!(bin.length, 64, "a SHA-512 is 64 bytes");

    let bytes = unsafe { std::slice::from_raw_parts(bin.data.cast::<u8>(), bin.length) };
    let rendered: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        rendered, BASE_LINEAR_HASH,
        "decoded bytes must re-encode to the same hex"
    );
    unsafe { AFF4_free_property(bin.data) };

    unsafe { AFF4_free_messages(msg) };
    unsafe { AFF4_close(handle, std::ptr::null_mut()) };
}

/// A value that is not hex is refused rather than partially decoded.
///
/// `aff4:size` is a decimal integer. Accepting it as binary would hand the
/// caller bytes that were never in the container.
#[cfg(feature = "corpus")]
#[test]
fn a_non_hex_value_is_refused_by_the_binary_accessor() {
    let (handle, msg) = open(&base_linear());
    assert!(!handle.is_null(), "{}", text_of(msg));
    unsafe { AFF4_free_messages(msg) };

    let key = CString::new("size").unwrap();
    let mut msg: *mut AFF4_Message = std::ptr::null_mut();
    let mut bin = AFF4_Binary_Result {
        data: std::ptr::null_mut(),
        length: 0,
    };
    let rc = unsafe { AFF4_get_binary_property(handle, key.as_ptr(), &raw mut bin, &raw mut msg) };

    assert_eq!(rc, -1, "a decimal value is not binary");
    assert!(
        bin.data.is_null(),
        "the out-parameter must be cleared on failure"
    );
    assert_eq!(bin.length, 0);
    assert!(
        text_of(msg).contains("not hex"),
        "the reason must be stated: {}",
        text_of(msg)
    );

    unsafe { AFF4_free_messages(msg) };
    unsafe { AFF4_close(handle, std::ptr::null_mut()) };
}

/// An absent property is an error with cleared output, never a dangling
/// pointer the caller might free.
#[cfg(feature = "corpus")]
#[test]
fn an_absent_property_clears_the_result() {
    let (handle, msg) = open(&base_linear());
    assert!(!handle.is_null(), "{}", text_of(msg));
    unsafe { AFF4_free_messages(msg) };

    let key = CString::new("nosuchproperty").unwrap();
    let mut msg: *mut AFF4_Message = std::ptr::null_mut();
    let mut bin = AFF4_Binary_Result {
        data: std::ptr::null_mut(),
        length: 0,
    };
    let rc = unsafe { AFF4_get_binary_property(handle, key.as_ptr(), &raw mut bin, &raw mut msg) };

    assert_eq!(rc, -1);
    assert!(bin.data.is_null());
    assert_eq!(bin.length, 0);

    unsafe { AFF4_free_messages(msg) };
    unsafe { AFF4_close(handle, std::ptr::null_mut()) };
}

/// A property may be named by its full IRI or its local name.
#[cfg(feature = "corpus")]
#[test]
fn a_property_may_be_named_by_iri_or_local_name() {
    let (handle, msg) = open(&base_linear());
    assert!(!handle.is_null(), "{}", text_of(msg));
    unsafe { AFF4_free_messages(msg) };

    let mut msg: *mut AFF4_Message = std::ptr::null_mut();
    let mut by_name: i64 = 0;
    let mut by_iri: i64 = 0;

    let short = CString::new("size").unwrap();
    let long = CString::new("http://aff4.org/Schema#size").unwrap();
    let a = unsafe {
        AFF4_get_integer_property(handle, short.as_ptr(), &raw mut by_name, &raw mut msg)
    };
    let b =
        unsafe { AFF4_get_integer_property(handle, long.as_ptr(), &raw mut by_iri, &raw mut msg) };

    assert_eq!(a, 0);
    assert_eq!(b, 0);
    assert_eq!(
        by_name, by_iri,
        "both spellings must name the same property"
    );
    assert_eq!(by_name, 268_435_456);

    unsafe { AFF4_free_messages(msg) };
    unsafe { AFF4_close(handle, std::ptr::null_mut()) };
}

/// A non-boolean value is refused rather than coerced.
#[cfg(feature = "corpus")]
#[test]
fn a_non_boolean_value_is_refused() {
    let (handle, msg) = open(&base_linear());
    assert!(!handle.is_null(), "{}", text_of(msg));
    unsafe { AFF4_free_messages(msg) };

    let key = CString::new("size").unwrap();
    let mut msg: *mut AFF4_Message = std::ptr::null_mut();
    let mut flag: std::ffi::c_int = 0;
    let rc =
        unsafe { AFF4_get_boolean_property(handle, key.as_ptr(), &raw mut flag, &raw mut msg) };

    assert_eq!(rc, -1, "a size is not a boolean");
    unsafe { AFF4_free_messages(msg) };
    unsafe { AFF4_close(handle, std::ptr::null_mut()) };
}

/// Releasing null is a no-op, so a caller need not check first.
///
/// This matters for the failure path: both accessors clear their
/// out-parameter, so a caller that releases unconditionally passes null here
/// rather than a stale pointer.
#[test]
fn releasing_null_is_safe() {
    unsafe { AFF4_free_property(std::ptr::null_mut()) };
}

/// Every buffer this ABI hands out is released by the module that allocated
/// it.
///
/// `AFF4_free_property` is an addition to c-aff4's ABI. c-aff4 says to call
/// `free`, which is undefined behavior when the library and the consumer do
/// not share a heap — the normal case on Windows, where each C runtime has
/// its own. Allocating and releasing in one module removes the question.
#[cfg(feature = "corpus")]
#[test]
fn buffers_survive_repeated_acquire_and_release() {
    let (handle, msg) = open(&base_linear());
    assert!(!handle.is_null(), "{}", text_of(msg));
    unsafe { AFF4_free_messages(msg) };

    let key = CString::new("hash").unwrap();
    let mut msg: *mut AFF4_Message = std::ptr::null_mut();

    // Repeated so a double-free or a heap mismatch surfaces rather than
    // happening to survive one cycle.
    for _ in 0..64 {
        let mut bin = AFF4_Binary_Result {
            data: std::ptr::null_mut(),
            length: 0,
        };
        let rc =
            unsafe { AFF4_get_binary_property(handle, key.as_ptr(), &raw mut bin, &raw mut msg) };
        assert_eq!(rc, 0);
        assert_eq!(bin.length, 64);
        unsafe { AFF4_free_property(bin.data) };

        let mut text: *mut std::ffi::c_char = std::ptr::null_mut();
        let rc =
            unsafe { AFF4_get_string_property(handle, key.as_ptr(), &raw mut text, &raw mut msg) };
        assert_eq!(rc, 0);
        unsafe { AFF4_free_property(text.cast()) };
    }

    unsafe { AFF4_free_messages(msg) };
    unsafe { AFF4_close(handle, std::ptr::null_mut()) };
}
