//! Parsing the `--hash` flag into a list of algorithms.
//!
//! Kept apart from [`crate::hash`], which computes digests, because this is a
//! command-line concern: the names here are what an examiner types, not what
//! any specification calls an algorithm.

use crate::model::HashAlgorithm;

/// The algorithms recorded when `--hash` is not given.
///
/// SHA-512 because AFF4-L v1.0-ALPHA §10.1 requires SHA-256 or stronger for the
/// metadata integrity hash, and SHA-512 is the strongest algorithm the base
/// standard defines. BLAKE3 because it is stronger still by output length and
/// materially faster; see `docs/working/hash-speed-comparison.md`.
///
/// This replaces MD5 and SHA-1, which were what the logical writer recorded
/// until now. Both are broken for collision resistance and neither satisfies
/// that clause.
pub const DEFAULT: [HashAlgorithm; 2] = [HashAlgorithm::Sha512, HashAlgorithm::Blake3];

/// Every accepted spelling, paired with the algorithm it names.
///
/// The order here is the order [`names`] lists them in an error message, so it
/// runs weakest to strongest rather than alphabetically: an examiner reading
/// the list is choosing a strength, not looking a word up.
const ACCEPTED: &[(&str, HashAlgorithm)] = &[
    ("md5", HashAlgorithm::Md5),
    ("sha1", HashAlgorithm::Sha1),
    ("sha256", HashAlgorithm::Sha256),
    ("sha512", HashAlgorithm::Sha512),
    ("blake2b", HashAlgorithm::Blake2b),
    ("sha3-256", HashAlgorithm::Sha3_256),
    ("sha3-384", HashAlgorithm::Sha3_384),
    ("sha3-512", HashAlgorithm::Sha3_512),
    ("shake128", HashAlgorithm::Shake128),
    ("shake256", HashAlgorithm::Shake256),
    ("blake3", HashAlgorithm::Blake3),
];

/// The accepted names, for help text and error messages.
#[must_use]
pub fn names() -> Vec<&'static str> {
    ACCEPTED.iter().map(|(name, _)| *name).collect()
}

/// Whether an algorithm satisfies AFF4-L v1.0-ALPHA §10.1's strength floor.
///
/// That clause requires SHA-256, SHA-512, or a stronger hash the standard
/// supports. Everything this build computes clears that bar except MD5 and
/// SHA-1, both of which have practical collision attacks.
///
/// Written as an exclusion rather than an inclusion list deliberately: a future
/// algorithm added to `ACCEPTED` qualifies by default, which is the safe way
/// round. Adding a *broken* algorithm is the case needing a deliberate edit
/// here, and that is a decision worth forcing.
#[must_use]
pub fn satisfies_integrity_clause(algorithm: &HashAlgorithm) -> bool {
    !matches!(algorithm, HashAlgorithm::Md5 | HashAlgorithm::Sha1)
}

/// Parse `--hash` arguments into the algorithms to record.
///
/// Accepts both forms: repeated occurrences, and comma-separated lists within
/// one occurrence. Names are matched case-insensitively, and a repeat is
/// collapsed rather than recorded twice.
///
/// # Errors
///
/// Returns a message naming the offending input when a name is unrecognized,
/// when the selection is empty, or when nothing selected satisfies
/// [`satisfies_integrity_clause`]. All three are refused rather than defaulted:
/// an examiner who names an algorithm has stated an intent, and silently
/// recording something else would misrepresent what the container holds.
pub fn parse(args: &[String]) -> Result<Vec<HashAlgorithm>, String> {
    let mut chosen: Vec<HashAlgorithm> = Vec::new();

    for arg in args {
        for token in arg.split(',') {
            let name = token.trim();
            if name.is_empty() {
                continue;
            }
            let lowered = name.to_ascii_lowercase();
            let found = ACCEPTED
                .iter()
                .find(|(accepted, _)| *accepted == lowered)
                .map(|(_, algorithm)| algorithm.clone());

            match found {
                // De-duplicated, keeping first-seen order: two identical
                // digests on one object carry no more information than one.
                Some(algorithm) if chosen.contains(&algorithm) => {}
                Some(algorithm) => chosen.push(algorithm),
                None => {
                    return Err(format!(
                        "unknown hash algorithm '{name}'; valid names are: {}",
                        names().join(", ")
                    ));
                }
            }
        }
    }

    if chosen.is_empty() {
        return Err(format!(
            "no hash algorithm selected; valid names are: {}",
            names().join(", ")
        ));
    }

    // AFF4-L v1.0-ALPHA §10.1 requires the metadata integrity hash be SHA-256
    // or stronger, and this same selection computes it. A selection with
    // nothing qualifying could only produce a container that departs from that
    // clause, so it is refused here rather than written and reported after the
    // fact: an acquisition may not be repeatable.
    if !chosen.iter().any(satisfies_integrity_clause) {
        return Err(
            "please select at least one hash algorithm that isn't MD5 or SHA-1. \
             AFF4-L v1.0-ALPHA §10.1 requires the metadata integrity hash to be \
             SHA-256 or stronger, and the acquisition digests compute it"
                .to_owned(),
        );
    }

    Ok(chosen)
}
