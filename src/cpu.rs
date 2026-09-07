//! What the CPU offers for hashing, and what this build can use.
//!
//! Whether the binary carries hardware code paths is
//! decided at compile time by the `hash-asm` feature. Whether the CPU has the
//! instructions is checked at runtime.
//!
//! **Nothing here changes a digest.** The hardware and software paths compute
//! the same functions, so a container verifies identically whichever ran.

/// Whether hardware-accelerated SHA-2 is compiled in, and whether the CPU has
/// the instructions it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct HashAcceleration {
    /// Whether the CPU has the instructions.
    ///
    /// [`None`] where this build cannot tell. `cpufeatures` has no detection
    /// path for Windows on ARM, so the honest answer there is "unknown".
    pub available: Option<bool>,
    /// Whether this binary carries the hardware code paths.
    pub compiled_in: bool,
}

impl HashAcceleration {
    /// Whether the machine could hash faster than this build is able to.
    ///
    /// True only when the CPU is known to have the instructions and the
    /// binary cannot use them.
    #[must_use]
    pub fn is_opportunity_missed(&self) -> bool {
        self.available == Some(true) && !self.compiled_in
    }
}

/// Whether `sha2` was built with its hardware paths.
///
/// On x86 the SHA-NI path compiles in whatever the feature says, so the answer
/// there is always true; the feature only selects which *software* fallback
/// accompanies it. On aarch64 the feature is the only route to the hardware.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const COMPILED_IN: bool = true;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
const COMPILED_IN: bool = cfg!(feature = "hash-asm");

/// Detect on the platforms where `cpufeatures` can.
///
/// macOS queries `sysctlbyname`; Linux and Android read `getauxval(AT_HWCAP)`.
///
/// Returns `Option` even though this arm always answers, because the type is
/// the same across every platform and one of them genuinely cannot tell. A
/// per-platform return type would push that distinction onto every caller.
#[allow(clippy::unnecessary_wraps)]
#[cfg(all(
    target_arch = "aarch64",
    any(target_vendor = "apple", target_os = "linux", target_os = "android")
))]
fn detect() -> Option<bool> {
    cpufeatures::new!(sha2_cap, "sha2");
    Some(sha2_cap::get())
}

/// Detect on x86, where `CPUID` needs no operating-system involvement.
///
/// SHA-NI needs the SSE baseline alongside it, which is why four features are
/// named rather than one.
///
/// Returns `Option` for the same reason as the aarch64 arm above.
#[allow(clippy::unnecessary_wraps)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect() -> Option<bool> {
    cpufeatures::new!(shani_cap, "sha", "sse2", "ssse3", "sse4.1");
    Some(shani_cap::get())
}

/// No detection path here — report unknown rather than guess.
///
/// Windows on ARM is the case that matters: the CPU may well have the
/// instructions, but nothing in this dependency can ask it.
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    all(
        target_arch = "aarch64",
        any(target_vendor = "apple", target_os = "linux", target_os = "android")
    )
)))]
fn detect() -> Option<bool> {
    None
}

/// What this build can do about hardware hashing on this machine.
#[must_use]
pub fn hash_acceleration() -> HashAcceleration {
    HashAcceleration {
        available: detect(),
        compiled_in: COMPILED_IN,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A missed opportunity needs both halves: a CPU known to have the
    /// instructions, and a build that cannot use them.
    #[test]
    fn a_missed_opportunity_needs_both_halves() {
        let missed = HashAcceleration {
            available: Some(true),
            compiled_in: false,
        };
        assert!(missed.is_opportunity_missed());

        for settled in [
            // Using them already.
            HashAcceleration {
                available: Some(true),
                compiled_in: true,
            },
            // The CPU does not have them, so nothing is being missed.
            HashAcceleration {
                available: Some(false),
                compiled_in: false,
            },
            // Unknown is not evidence of absence.
            HashAcceleration {
                available: None,
                compiled_in: false,
            },
        ] {
            assert!(
                !settled.is_opportunity_missed(),
                "{settled:?} is not a missed opportunity"
            );
        }
    }
}
