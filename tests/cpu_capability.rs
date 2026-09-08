//! Hardware hash acceleration: what the CPU offers, and what this build uses.

// Integration tests build fixture trees in temp dirs, which needs the
// directory constructors the library is denied. `tests/read_only_guard.rs`
// scans `src/` only, so this relaxation cannot reach library code.
#![allow(clippy::disallowed_methods)]

/// The capability probe answers, and its two halves are independent.
///
/// `compiled_in` is a property of this build; `available` is a property of the
/// CPU. A build without the hardware path running on a CPU that has the
/// instructions is the case worth reporting, and it must be representable.
#[test]
fn the_cpu_probe_reports_both_halves() {
    let acc = aff4tools::cpu::hash_acceleration();

    // The compiled-in half is always knowable, whatever the platform.
    let _: bool = acc.compiled_in;

    // The CPU half is None where detection is unavailable — Windows on ARM —
    // and that is reported as unknown rather than guessed as false.
    assert!(matches!(acc.available, Some(true) | Some(false) | None));

    // A missed opportunity is exactly "the CPU has it and this build does not".
    assert_eq!(
        acc.is_opportunity_missed(),
        acc.available == Some(true) && !acc.compiled_in
    );
}

/// On a default build for a platform with a hardware path, that path is
/// compiled in.
///
/// This is what would catch the feature being silently dropped from
/// `[features] default`, which no other test would notice: every digest would
/// still be correct, just slower.
#[test]
#[cfg(all(
    feature = "hash-asm",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        all(
            target_arch = "aarch64",
            any(target_vendor = "apple", target_os = "linux", target_os = "android")
        )
    )
))]
fn a_default_build_carries_the_hardware_path() {
    let acc = aff4tools::cpu::hash_acceleration();
    assert!(
        acc.compiled_in,
        "the hash-asm feature is on, so the hardware path must be compiled in"
    );
    assert!(
        !acc.is_opportunity_missed(),
        "a default build on a supported target misses nothing"
    );
}

/// `acquire` tells the examiner when the machine could hash faster than this
/// build can — and stays quiet otherwise.
///
/// Both halves matter. A note that never appears is dead code; a note that
/// always appears is noise. This asserts it tracks the actual condition.
#[test]
fn a_missed_acceleration_opportunity_is_reported() {
    let expected = aff4tools::cpu::hash_acceleration().is_opportunity_missed();

    let dir = tempfile::tempdir().expect("a temp dir");
    let source = dir.path().join("evidence");
    std::fs::create_dir_all(&source).expect("the tree");
    std::fs::write(source.join("a.txt"), b"content\n").expect("a file");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_aff4tools"))
        .args(["acquire", "--logical"])
        .arg(&source)
        .arg("--output")
        .arg(dir.path().join("out.aff4"))
        .output()
        .expect("aff4tools ran");
    assert!(out.status.success());

    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        text.contains("hash acceleration this build does not use"),
        expected,
        "the note must appear exactly when the opportunity is missed:\n{text}"
    );
}
